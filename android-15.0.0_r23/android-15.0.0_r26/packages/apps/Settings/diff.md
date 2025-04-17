```diff
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 59ab9b26dae..5fb433329ef 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Stuur en ontvang teksboodskappe via satelliet. Nie by jou rekening ingesluit nie."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satellietboodskappe, satellietkonnektiwiteit"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Meer oor <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Jy kan as deel van ’n kwalifiserende <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-rekening teksboodskappe via satelliet stuur en ontvang."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Jou <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-pakket"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Boodskappe is by jou rekening ingesluit"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Jy kan teksboodskappe via satelliet stuur en ontvang met ’n geldige <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-rekening"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Jou <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-rekening"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satellietboodskappe is by jou rekening ingesluit"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satellietboodskappe is nie by jou rekening ingesluit nie"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Kry meer inligting"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Hoe dit werk"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"As jy nie ’n selnetwerk het nie"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Stuur ’n teksboodskap na ’n foonnommer"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Jou foon sal outomaties aan ’n satelliet verbind. Vir die beste verbinding, maak seker jy kan die lug duidelik sien."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"As jy nie ’n selnetwerk het nie, sal jy ’n opsie sien om satellietboodskappe te gebruik."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Nadat jou foon aan ’n satelliet verbind"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Volg die stappe om aan die satelliet te koppel"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Jy kan ’n teksboodskap na enigiemand stuur, insluitend nooddienste. Jou foon sal weer aan ’n selnetwerk verbind wanneer dit beskikbaar is."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> kan langer neem en is net in sekere gebiede beskikbaar. Die weer en sekere strukture kan jou satellietverbinding affekteer. Satellietoproepe is nie beskikbaar nie. Noodfoonoproepe kan dalk steeds koppel.\n\nDit kan ’n rukkie neem vir rekeningveranderinge om in Instellings te wys. Kontak <xliff:g id="CARRIER_NAME">%1$s</xliff:g> vir besonderhede."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Jy kan vir enige iemand ’n teksboodskap stuur nadat jou foon gekoppel is, insluitend nooddienste."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"’n Satellietverbinding kan stadiger wees en is net in sommige gebiede beskikbaar. Die weer en sekere strukture kan die verbinding affekteer. Satellietoproepe is nie beskikbaar nie. Noodoproepe kan steeds verbind.\n\nDit kan ’n tyd neem vir rekeningveranderinge om in Instellings te wys. Kontak <xliff:g id="CARRIER_NAME">%1$s</xliff:g> vir besonderhede."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Meer oor <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Kan nie <xliff:g id="FUNCTION">%1$s</xliff:g> aanskakel nie"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Beëindig eers die satellietverbinding om <xliff:g id="FUNCTION">%1$s</xliff:g> aan te skakel."</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 83e4793b86b..bc06777f5f5 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"ኤስኤምኤሶችን በሳተላይት ይላኩ እና ይቀበሉ። በመለያዎ ውስጥ አልተካተተም።"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"የሳተላይት መልዕክት፣ የሳተላይት ግንኙነት"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"ስለ <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"የብቁ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> መለያ አካል እንደመሆንዎ ኤስኤምኤሶችን በሳተላይት መላክ እና መቀበል ይችላሉ"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"የእርስዎ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> እቅድ"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"መልዕክት መላላክ ከመለያዎ ጋር ተካትቷል"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"ብቁ በሆነ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> መለያ በሳተላይት ኤስኤምኤስዎችን መላክ እና መቀበል ይችላሉ"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"የእርስዎ የ<xliff:g id="CARRIER_NAME">%1$s</xliff:g> መለያ"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"በሳተላይት መልዕክት መላላክ ከመለያዎ ጋር ተካትቷል"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"በሳተላይት መልዕክት መላላክ ከመለያዎ ጋር አልተካተተም"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"የበለጠ ለመረዳት"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"እንዴት እንደሚሠራ"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"የተንቀሳቃሽ ስልክ አውታረ መረብ ሳይኖርዎት ሲቀር"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ለስልክ ቁጥር የጽሑፍ መልዕክት ይላኩ"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"ስልክዎ ከሳተላይት ጋር በራስ-ሰር ይገናኛል። ለምርጥ ግንኙነት፣ የሰማይ ጥርት ያለ ዕይታ ይኑርዎት።"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"የተንቀሳቃሽ ስልክ አውታረ መረብ ከሌለዎት የሳተላይት መልዕክት የመጠቀም አማራጭ ይመለከታሉ።"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"ስልክዎ ከሳተላይት ጋር ከተገናኘ በኋላ"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"ከሳተላይቱ ጋር ለመገናኘት ያሉትን እርምጃዎች ይከተሉ"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"ድንገተኛ አደጋ አገልግሎቶችን ጨምሮ ለማንም ሰው መላክ ይችላሉ። የተንቀሳቃሽ ስልክ አውታረ መረብ ሲገኝ ከስልክዎ ጋር እንደገና ይገናኛል።"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> ረዘም ያለ ጊዜ ሊወስድ ይችላል እና በአንዳንድ አካባቢዎች ብቻ ሊገኝ ይችላል። የአየር ሁኔታ እና አንዳንድ አወቃቀሮች በሳተላይት ግንኙነትዎ ላይ ተጽዕኖ ሊያሳድሩ ይችላሉ። በሳተላይት መደወል አይገኝም። የአደጋ ጥሪዎች አሁንም ሊገናኙ ይችላሉ።\n\nየመለያ ለውጦች በቅንብሮች ውስጥ እስከሚታዩ ድረስ የተወሰነ ጊዜ ሊወስድ ይችላል። ለዝርዝሮች <xliff:g id="CARRIER_NAME">%1$s</xliff:g>ን ያነጋግሩ።"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"ስልክዎ ከተገናኘ በኋላ ድንገተኛ አደጋ አገልግሎቶችን ጨምሮ ለማንኛውም ሰው የጽሑፍ መልዕክት መላክ ይችላሉ።"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"የሳተላይት ግንኙነት የዘገየ ሊሆን ይችላል እና በአንዳንድ አካባቢዎች ውስጥ ብቻ ይገኛል። የአየር ሁኔታ እና አንዳንድ መዋቅሮች ግንኙነቱ ላይ ተጽዕኖ ሊያደርሱ ይችላሉ። በሳተላይት መደወል አይገኝም። የአደጋ ጥሪዎች አሁንም ሊገናኙ ይችላሉ።\n\nየመለያ ለውጦች በቅንብሮች ውስጥ እስከሚታዩ ድረስ የተወሰነ ጊዜ ሊወስድ ይችላል። ለዝርዝሮች <xliff:g id="CARRIER_NAME">%1$s</xliff:g> የሚለውን ያነጋግሩ።"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"ስለ <xliff:g id="SUBJECT">%1$s</xliff:g> ተጨማሪ"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> ማብራት አልተቻለም"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> ለማብራት መጀመሪያ የሳተላይት ግንኙነቱን ያጠናቅቁ"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index fbdc6f7a70d..c3ffc223830 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"يمكن إرسال رسائل نصية واستلامها باستخدام القمر الصناعي، ولكن هذه الميزة غير متوفّرة على حسابك."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"المراسلة عبر القمر الصناعي، إمكانية الاتصال بالقمر الصناعي"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"لمحة عن \"<xliff:g id="SUBJECT">%1$s</xliff:g>\""</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"يمكنك إرسال الرسائل النصية واستلامها عبر الأقمار الصناعية كجزء من حساب <xliff:g id="CARRIER_NAME">%1$s</xliff:g> مؤهَّل."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"خطّتك من <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"يتيح لك حسابك استخدام ميزة المراسلة"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"يمكنك إرسال الرسائل النصيّة وتلقّيها عبر القمر الصناعي باستخدام حساب مؤهَّل على <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"حسابك على <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"ميزة المراسلة باستخدام القمر الصناعي مدرجة ضمن حسابك"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"ميزة المراسلة باستخدام القمر الصناعي غير مدرجة ضمن حسابك"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"مزيد من المعلومات"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"طريقة العمل"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"في حال عدم وجود تغطية شبكة جوّال"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"إرسال رسالة نصية إلى رقم هاتف"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"سيتصل هاتفك تلقائيًا بالقمر الصناعي. للحصول على أفضل تجربة اتصال، يُرجى البقاء في مكان مفتوح بدون عوائق بين الجهاز والسماء."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"في حال عدم توفّر شبكة جوّال، سيظهر لك خيار لاستخدام ميزة \"المراسلة عبر القمر الاصطناعي\"."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"بعد اتصال الهاتف بالقمر الصناعي"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"يُرجى اتّباع التعليمات للاتصال بالقمر الصناعي"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"يمكنك إرسال رسائل نصية إلى أي شخص، وكذلك الاستفادة من خدمات الطوارئ. سيحاول هاتفك الاتصال بشبكة جوّال مجددًا عند توفُّرها."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"قد تستغرق ميزة \"<xliff:g id="SUBJECT">%1$s</xliff:g>\" وقتًا أطول ولا تتوفّر إلا في بعض المناطق. وقد يؤثّر الطقس وبعض المباني في اتصالك بالقمر الصناعي. ولا تتوفّر إمكانية الاتصال باستخدام القمر الصناعي. قد تظل مكالمات الطوارئ مفعَّلة.\n\nقد يستغرق ظهور التغييرات في حسابك ضِمن \"الإعدادات\" بعض الوقت. يُرجى التواصل مع <xliff:g id="CARRIER_NAME">%1$s</xliff:g> لمعرفة التفاصيل."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"بعد اتصال هاتفك، يمكنك إرسال رسائل نصية إلى أي شخص، وكذلك الاستفادة من خدمات الطوارئ."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"قد يكون الاتصال بالقمر الصناعي أبطأ ولا يتوفّر إلا في بعض المناطق، وقد يتأثر بالطقس وبعض المباني. لا تتوفّر إمكانية الاتصال باستخدام القمر الصناعي. قد تظل مكالمات الطوارئ مفعَّلة.\n\nقد يستغرق ظهور التغييرات في حسابك ضمن \"الإعدادات\" بعض الوقت. لمعرفة التفاصيل، يُرجى التواصل مع \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\"."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"المزيد حول \"<xliff:g id="SUBJECT">%1$s</xliff:g>\""</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"يتعذّر تفعيل <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"لتفعيل <xliff:g id="FUNCTION">%1$s</xliff:g>، عليك أولاً إنهاء الاتصال بالقمر الصناعي"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index cf47c8504e2..efdec429f7a 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"উপগ্ৰহৰ জৰিয়তে পাঠ বাৰ্তা পঠিয়াওক আৰু লাভ কৰক। আপোনাৰ একাউণ্টৰ সৈতে অন্তৰ্ভুক্ত নহয়।"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"উপগ্ৰহৰ দ্বাৰা বাৰ্তা বিনিময়, উপগ্ৰহৰ সংযোগ"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g>ৰ বিষয়ে"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"এটা যোগ্য <xliff:g id="CARRIER_NAME">%1$s</xliff:g> একাউণ্টৰ অংশ হিচাপে আপুনি উপগ্ৰহৰ জৰিয়তে পাঠ বাৰ্তা পঠিয়াব বা লাভ কৰিব পাৰে"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"আপোনাৰ <xliff:g id="CARRIER_NAME">%1$s</xliff:g>ৰ আঁচনি"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"আপোনাৰ একাউণ্টত বাৰ্তা বিনিময় কৰাটো অন্তর্ভুক্ত"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"এটা যোগ্য <xliff:g id="CARRIER_NAME">%1$s</xliff:g> একাউণ্টৰ জৰিয়তে আপুনি বাৰ্তা পঠিয়াব আৰু গ্ৰহণ কৰিব পাৰে"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"আপোনাৰ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> একাউণ্ট"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"উপগ্ৰহৰ জৰিয়তে বাৰ্তা বিনিময় কৰাটো আপোনাৰ একাউণ্টত অন্তৰ্ভুক্ত কৰা হয়"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"উপগ্ৰহৰ জৰিয়তে বাৰ্তা বিনিময় কৰাটো আপোনাৰ একাউণ্টত অন্তৰ্ভুক্ত কৰা নহয়"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"অধিক জানক"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"ই কেনেকৈ কাম কৰে"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"যেতিয়া আপোনাৰ কোনো ম’বাইল নেটৱৰ্ক নাথাকে"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"এটা ফ’ন নম্বৰ পাঠ বাৰ্তা হিচাপে পঠিয়াওক"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"আপোনাৰ ফ’নটো এটা উপগ্ৰহৰ সৈতে স্বয়ংক্ৰিয়ভাৱে সংযুক্ত হ’ব। আটাইতকৈ ভাল সংযোগৰ বাবে, আকাশখন ভালকৈ দেখাকৈ ৰাখক।"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"যদি আপোনাৰ ম’বাইল নেটৱৰ্ক নাই, তেন্তে আপুনি উপগ্ৰহৰ দ্বাৰা বাৰ্তা বিনিময় ব্যৱহাৰ কৰাৰ বিকল্প দেখা পাব।"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"আপোনাৰ ফ’নটো এটা উপগ্ৰহৰ সৈতে সংযুক্ত হোৱাৰ পাছত"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"উপগ্ৰহৰ সৈতে সংযোগ কৰিবলৈ পদক্ষেপসমূহ অনুসৰণ কৰক"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"আপুনি জৰুৰীকালীন সেৱাকে ধৰি যিকোনো ব্যক্তিকে পাঠ বাৰ্তা পঠিয়াব পাৰে। আপোনাৰ ফ’নটোৱে উপলব্ধ হ’লে কোনো ম’বাইল নেটৱৰ্কৰ সৈতে পুনৰ সংযোগ কৰিব।"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g>এ অধিক সময় ল\'ব পাৰে আৰু ই কেৱল কিছুমান অঞ্চলতহে উপলব্ধ। বতৰ আৰু নিৰ্দিষ্ট কিছুমান গাঁথনিয়ে আপোনাৰ উপগ্ৰহৰ সংযোগত প্ৰভাৱ পেলাব পাৰে। উপগ্ৰহৰ জৰিয়তে কল কৰাৰ সুবিধাটো উপলব্ধ নহয়। জৰুৰীকালীন কলসমূহ তথাপি সংযোগ হ\'ব পাৰে।\n\nএকাউণ্টৰ সালসলনিসমূহ ছেটিঙত দেখুৱাবলৈ কিছু সময় লাগিব পাৰে। সবিশেষৰ বাবে <xliff:g id="CARRIER_NAME">%1$s</xliff:g>ৰ সৈতে যোগাযোগ কৰক।"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"আপোনাৰ ফ’নটো সংযুক্ত হোৱাৰ পাছত আপুনি জৰুৰীকালীন সেৱাকে ধৰি যিকোনো ব্যক্তিলৈ পাঠ বাৰ্তা পঠিয়াব পাৰিব।"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"উপগ্ৰহৰ সংযোগ লেহেমীয়া আৰু কেৱল কিছুমান অঞ্চলত উপলব্ধ হ’ব পাৰে। বতৰ আৰু নিৰ্দিষ্ট কিছুমান গাঁথনিয়ে সংযোগত প্ৰভাৱ পেলাব পাৰে। উপগ্ৰহৰ জৰিয়তে কল কৰাৰ সুবিধাটো উপলব্ধ নহয়। জৰুৰীকালীন কলসমূহ তথাপি সংযোগ হ’ব পাৰে।\n\nএকাউণ্টত কৰা সালসলনিসমূহ ছেটিঙত প্ৰদৰ্শিত হ’বলৈ কিছু সময় লাগিব পাৰে। সবিশেষৰ বাবে <xliff:g id="CARRIER_NAME">%1$s</xliff:g>ৰ সৈতে যোগাযোগ কৰক।"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g>ৰ বিষয়ে অধিক"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> অন কৰিব নোৱাৰি"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> অন কৰিবলৈ, প্ৰথমে উপগ্ৰহৰ সংযোগ সমাপ্ত কৰক"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index ac7eb212568..e3167e774a7 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Peyk vasitəsilə mətn mesajları göndərin və qəbul edin. Hesabınıza daxil deyil."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Peyk mesajlaşması, peyk bağlantısı"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> haqqında"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Uyğun <xliff:g id="CARRIER_NAME">%1$s</xliff:g> hesabında peyk vasitəsilə mətn mesajları göndərə və qəbul edə bilərsiniz"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> planınız"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Mesajlaşma hesabınıza daxildir"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Uyğun <xliff:g id="CARRIER_NAME">%1$s</xliff:g> hesabı ilə peyk vasitəsilə mətn mesajları göndərə və qəbul edə bilərsiniz"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> hesabınız"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Peyk vasitəsilə mesajlaşma hesaba daxil edilib"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Peyk vasitəsilə mesajlaşma hesaba daxil edilməyib"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Ətraflı Məlumat"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Haqqında"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Mobil şəbəkə olmadıqda"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Telefon nömrəsinə mesaj yazın"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefon peykə avtomatik qoşulacaq. Yaxşı bağlantı üçün səma aydın görünməlidir."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Mobil şəbəkə yoxdursa, peyk mesajlaşmasından istifadə etmək seçimini görəcəksiniz."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Telefon peykə qoşulduqdan sonra"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Peykə qoşulmaq üçün addımlara əməl edin"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Təcili xidmətlər daxil olmaqla istədiyiniz şəxsə mesaj yaza bilərsiniz. Əlçatan olduqda telefon mobil şəbəkəyə yenidən qoşulacaq."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> uzun çəkə bilər və yalnız bəzi ərazilərdə əlçatandır. Hava və müəyyən strukturlar peyk bağlantısına təsir edə bilər. Peyk vasitəsilə zəng hələ əlçatan deyil. Təcili zənglər yenə qoşula bilər.\n\nHesab dəyişikliklərinin Ayarlarda görünməsi uzun çəkə bilər. Ətraflı məlumat üçün <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ilə əlaqə saxlayın."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Telefonunuz qoşulduqdan sonra təcili xidmətlər də daxil olmaqla hər kəsə mesaj göndərə bilərsiniz."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Peyk bağlantısı daha asta ola bilər və yalnız bəzi ərazilərdə əlçatandır. Hava və müəyyən strukturlar bağlantıya təsir edə bilər. Peyk vasitəsilə zəng etmək əlçatan deyil. Təcili zənglər yenə qoşula bilər.\n\nHesab dəyişikliklərinin Ayarlarda görünməsi bir müddət çəkə bilər. Ətraflı məlumat üçün <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ilə əlaqə saxlayın."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> haqqında daha ətraflı"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> funksiyasını yandırmaq olmur"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> funksiyasını yandırmaq üçün əvvəlcə peyk bağlantısını sonlandırın"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 75af19fd64e..f38f7ec3b1b 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Šaljite i primajte tekstualne poruke preko satelita. Nije obuhvaćeno nalogom."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"razmena poruka preko satelita, satelitska veza"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Više informacija o: <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Ako kod mobilnog operatera <xliff:g id="CARRIER_NAME">%1$s</xliff:g> imate nalog koji ispunjava uslove, možete da šaljete i primate tekstualne poruke preko satelita."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Paket kod mobilnog operatera <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Razmena poruka je obuhvaćena nalogom"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Možete da šaljete i primate poruke preko satelita ako imate <xliff:g id="CARRIER_NAME">%1$s</xliff:g> nalog koji ispunjava uslove"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> nalog"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satelitska razmena poruka je obuhvaćena nalogom"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satelitska razmena poruka nije obuhvaćena nalogom"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Saznajte više"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Princip rada"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Kad nemate pristup mobilnoj mreži"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Pošaljite poruku na broj telefona"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefon će se automatski povezati na satelit. Za najbolji kvalitet veze, uverite se da vam ništa ne zaklanja pogled na nebo."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ako nemate mobilnu mrežu, videćete opciju da koristite razmenu poruka preko satelita."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Kad se telefon poveže na satelit"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Pratite korake da biste se povezali sa satelitom"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Možete da šaljete poruke bilo kome, uključujući hitne službe. Telefon će se ponovo povezati na mobilnu mrežu kada bude dostupna."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> može da traje duže i dostupna je samo u određenim oblastima. Vremenski uslovi i određene strukture mogu da utiču na satelitsku vezu. Pozivanje putem satelita nije dostupno. Hitni pozivi i dalje mogu da se obave.\n\nMože da prođe neko vreme pre nego što se promene naloga prikažu u Podešavanjima. Obratite se mobilnom operateru <xliff:g id="CARRIER_NAME">%1$s</xliff:g> za više detalja."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Kada se telefon poveže, možete da šaljete poruke bilo kome, uključujući hitne službe."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Satelitska veza može da bude sporija i dostupna je samo u nekim oblastima. Vremenski uslovi i određene strukture mogu da utiču na vezu. Pozivanje putem satelita nije dostupno. Hitni pozivi i dalje mogu da se obave.\n\nMože da prođe neko vreme pre nego što se promene naloga prikažu u Podešavanjima. Obratite se mobilnom operateru <xliff:g id="CARRIER_NAME">%1$s</xliff:g> za više detalja."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Više o: <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Ne može da se uključi <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Da biste uključili <xliff:g id="FUNCTION">%1$s</xliff:g>, prvo završite satelitsku vezu"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index cc1e6d4580d..41dc76deff8 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Адпраўляйце і атрымлівайце тэкставыя паведамленні па спадарожнікавай сувязі. Паслуга не ўключана ва ўліковы запіс."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Абмен паведамленнямі па спадарожнікавай сувязі, спадарожнікавае падключэнне"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Інфармацыя пра \"<xliff:g id="SUBJECT">%1$s</xliff:g>\""</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Ваш уліковы запіс ад аператара \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\" дазваляе вам адпраўляць і атрымліваць тэкставыя паведамленні па спадарожнікавай сувязі"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Ваш тарыфны план ад аператара \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\""</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Ваш уліковы запіс дазваляе выкарыстоўваць абмен паведамленнямі"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Вы можаце адпраўляць і атрымліваць паведамленні з дапамогай спадарожнікавай сувязі праз прыдатны ўліковы запіс <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Ваш уліковы запіс <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Функцыя абмену паведамленнямі па спадарожнікавай сувязі даступная для вашага ўліковага запісу."</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Функцыя абмену паведамленнямі па спадарожнікавай сувязі недаступная для вашага ўліковага запісу."</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Даведацца больш"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Як гэта працуе"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Калі няма мабільнай сеткі"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Адпраўце тэкставае паведамленне на нумар тэлефона"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Ваш тэлефон аўтаматычна падключыцца да спадарожнікавай сувязі. Для аптымальнай якасці падключэння вам лепш знаходзіцца на вуліцы пад адкрытым небам"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Калі сігналу сувязі па мабільнай сетцы няма, на экране з’явіцца прапанова скарыстаць абмен паведамленнямі па спадарожнікавай сувязі."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Пасля падключэння тэлефона да спадарожнікавай сувязі"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Выканайце інструкцыі па падключэнні да спадарожніка"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Вы можаце адпраўляць тэкставыя паведамленні каму хочаце, у тым ліку экстранным службам. Ваш тэлефон зноў падключыцца да мабільнай сеткі, калі яна стане даступнай."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> можа займаць больш часу і быць даступным толькі ў некаторых рэгіёнах. На якасць спадарожнікавага падключэння могуць уплываць надвор’е і некаторыя віды пабудоў. Выклікі праз спадарожнікавую сувязь недаступныя. Пры гэтым дапускаецца магчымасць ажыццяўлення экстранных выклікаў.\n\nМожа спатрэбіцца некаторы час, каб змяненні ў вашым уліковым запісе з’явіліся ў наладах. Па падрабязныя звесткі звяртайцеся да аператара \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\"."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Пасля падключэння вы зможаце адпраўляць тэкставыя паведамленні каму хочаце, у тым ліку экстранным службам."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Спадарожнікавае падключэнне можа працаваць больш павольна, і яно даступнае толькі ў некаторых рэгіёнах. На якасць такога падключэння могуць уплываць надвор’е і некаторыя віды пабудоў. Выклікі праз спадарожнікавую сувязь недаступныя. Пры гэтым дапускаецца магчымасць ажыццяўлення экстранных выклікаў.\n\nМожа спатрэбіцца некаторы час, каб змяненні ў вашым уліковым запісе з’явіліся ў наладах. Па падрабязныя звесткі звяртайцеся да аператара \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\"."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Падрабязней пра \"<xliff:g id="SUBJECT">%1$s</xliff:g>\""</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Не ўдалося ўключыць функцыю \"<xliff:g id="FUNCTION">%1$s</xliff:g>\""</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Каб уключыць функцыю \"<xliff:g id="FUNCTION">%1$s</xliff:g>\", спачатку выканайце падключэнне да спадарожніка"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 4fe483a28bb..d02f0029f9b 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Изпращайте и получавайте текстови съобщения чрез сателит. Услугата не се предлага с профила ви."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Сателитни съобщения, свързване със сателит"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Всичко за <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Можете да изпращате и получавате текстови съобщения чрез сателит, ако имате отговарящ на условията профил от <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Вашият план от <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Услугата за съобщения е включена за профила ви"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Можете да изпращате и получавате текстови съобщения чрез сателит, ако имате отговарящ на условията профил от <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Вашият профил в(ъв) <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Услугата за сателитни съобщения е включена с профила ви"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Услугата за сателитни съобщения не е включена с профила ви"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Научете повече"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Начин на работа"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Когато нямате достъп до мобилна мрежа"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Изпращане на текстово съобщение до телефонен номер"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Телефонът ви ще се свърже автоматично със сателит. За оптимална връзка трябва да сте на място с ясен изглед към небето."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ако нямате мобилна мрежа, ще видите опция да използвате функцията „Сателитни съобщения“."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"След като телефонът ви се свърже със сателит"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Изпълнете стъпките за свързване със сателита"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Можете да изпращате текстови съобщения на когото пожелаете, включително на службите за спешни случаи. Телефонът ви ще се свърже отново с мобилна мрежа, когато е възможно."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Доставянето на <xliff:g id="SUBJECT">%1$s</xliff:g> може да отнеме по-дълго време. Услугата се предлага само в някои райони и сателитната връзка може да бъде повлияна от времето и определени структури. Не се поддържат обаждания чрез сателит, но е възможно спешните обаждания да бъдат извършени.\n\nМоже да измине известно време, докато промените в профила ви се покажат в настройките. За подробности се обърнете към <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"След като телефонът ви се свърже, можете да изпращате текстови съобщения на когото пожелаете, включително на службите за спешни случаи."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Сателитната връзка може да бъде по-бавна и е налице само в някои райони. Времето и определени структури може да ѝ повлияят. Не се поддържат обаждания чрез сателит, но е възможно спешните обаждания да бъдат извършени.\n\nМоже да измине известно време, докато промените в профила ви се покажат в настройките. За подробности се обърнете към <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Още за услугата за <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> не може да се включи"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"За да включите <xliff:g id="FUNCTION">%1$s</xliff:g>, първо прекратете сателитната връзка"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 13232facd6e..fc1185d915b 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -4875,17 +4875,20 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"স্যাটেলাইটের মাধ্যমে টেক্সট মেসেজ পাঠান ও পান। আপনার অ্যাকাউন্টের সাথে যোগ করা হয়নি।"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"স্যাটেলাইট মেসেজিং, স্যাটেলাইট কানেক্টিভিটি"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> সম্পর্কে"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"উপযুক্ত <xliff:g id="CARRIER_NAME">%1$s</xliff:g> অ্যাকাউন্টের অংশ হিসেবে আপনি স্যাটেলাইটের মাধ্যমে টেক্সট মেসেজ পেতে ও পাঠাতে পারবেন"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"আপনার <xliff:g id="CARRIER_NAME">%1$s</xliff:g> প্ল্যান"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"আপনার অ্যাকাউন্টে মেসেজিং অন্তর্ভুক্ত আছে"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"উপযুক্ত কোনও <xliff:g id="CARRIER_NAME">%1$s</xliff:g> অ্যাকাউন্ট থাকলে, স্যাটেলাইটের মাধ্যমে আপনি টেক্সট মেসেজ পাঠাতে ও পেতে পারবেন।"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"আপনার <xliff:g id="CARRIER_NAME">%1$s</xliff:g> অ্যাকাউন্ট"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"আপনার অ্যাকাউন্টে স্যাটেলাইট মেসেজিং অন্তর্ভুক্ত আছে"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"আপনার অ্যাকাউন্টে স্যাটেলাইট মেসেজিং অন্তর্ভুক্ত নেই"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"আরও জানুন"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"এটি কীভাবে কাজ করে"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"আপনার মোবাইল নেটওয়ার্ক না থাকলে"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"কোনও একটি ফোন নম্বর টেক্সট করুন"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"আপনার ফোন স্যাটেলাইটের সাথে অটোমেটিক কানেক্ট হয়ে যাবে। সবচেয়ে ভাল কানেকশনের জন্য পরিষ্কার আকাশ দেখা যায় এমন জায়গায় থাকুন।"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"মোবাইল নেটওয়ার্ক না থাকলে, আপনি স্যাটেলাইট মেসেজিং ব্যবহার করার বিকল্প দেখতে পাবেন।"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"আপনার ফোন স্যাটেলাইটে কানেক্ট করার পরে"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"স্যাটেলাইটে কানেক্ট করতে ধাপগুলি অনুসরণ করুন"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"আপনি জরুরি পরিষেবা সহ যেকোনও ব্যক্তিকে মেসেজ পাঠাতে পারেন। মোবাইল নেটওয়ার্ক পাওয়া গেলে ফোন সেটির সাথে আবার কানেক্ট করবে।"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g>-এর ক্ষেত্রে আরও বেশি সময় লাগতে পারে এবং এটি শুধু কিছু জায়গাতে উপলভ্য। আবহাওয়া এবং নির্দিষ্ট স্ট্রাকচার আপনার স্যাটেলাইট কানেকশন প্রভাবিত করতে পারে। স্যাটেলাইটের মাধ্যমে কল করার সুবিধা উপলভ্য নেই। জরুরি কলের জন্য এখনও কানেক্ট করা যেতে পারে।\n\n\'সেটিংস\'-এ অ্যাকাউন্ট পরিবর্তনের বিষয়টি দেখানোর জন্য কিছুটা সময় লাগতে পারে। বিস্তারিত জানতে <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-এর সাথে যোগাযোগ করুন।"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"আপনার ফোন কানেক্ট হওয়ার পরে, জরুরি পরিষেবা ছাড়াও আপনি যেকোনও ব্যক্তিকে টেক্সট করতে পারবেন।"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> সম্পর্কে আরও"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> চালু করা যাচ্ছে না"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> চালু করতে, প্রথমে স্যাটেলাইট কানেকশন বন্ধ করুন"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 5f6e1a7d1cd..5af55a191f8 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Šaljite i primajte poruke putem satelita. Nije uključeno uz vaš račun."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satelitska razmjena poruka, satelitska povezivost"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"O funkciji \"<xliff:g id="SUBJECT">%1$s</xliff:g>\""</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Mogućnost slanja i primanja poruka putem satelita imate u okviru računa kod operatera <xliff:g id="CARRIER_NAME">%1$s</xliff:g> koji ispunjava uslove"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Vaš paket kod operatera <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Razmjena poruka je uključena uz račun"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Možete slati i primati poruke putem satelita uz <xliff:g id="CARRIER_NAME">%1$s</xliff:g> račun koji ispunjava uslove"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> račun"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satelitska razmjena poruka je uključena uz račun"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satelitska razmjena poruka nije uključena uz račun"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Saznajte više"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Kako funkcionira"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Kada nemate mobilnu mrežu"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Pošaljite poruku na broj telefona"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefon će se automatski povezati sa satelitom. Da veza bude najbolja, pogled na nebo ne smije biti zapriječen."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ako nemate mobilnu mrežu, vidjet ćete opciju korištenja satelitske razmjene poruka."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Nakon što se telefon poveže sa satelitom"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Slijedite korake da se povežete sa satelitom"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Poruke možete slati svakome, uključujući hitne službe. Telefon će se ponovo povezati s mobilnom mrežom kada bude dostupna."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Funkcija \"<xliff:g id="SUBJECT">%1$s</xliff:g>\" može potrajati duže, a dostupna je samo u nekim područjima. Vremenske prilike i određeni objekti mogu uticati na satelitsku vezu. Pozivanje putem satelita nije dostupno. Hitni pozivi se i dalje mogu uspostavljati.\n\nMože proći neko vrijeme dok se promjene na računu ne prikažu u Postavkama. Za detalje kontaktirajte operatera <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Nakon što se telefon poveže, možete slati poruke bilo kome, uključujući hitne službe."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Satelitska veza će možda biti sporija, a dostupna je samo u određenim područjima. Vremenske prilike i određeni objekti mogu uticati na vezu. Pozivanje putem satelita nije dostupno. Hitni pozivi se i dalje mogu uspostavljati.\n\nMože potrajati neko vrijeme dok se promjene u vezi s računom ne prikažu u Postavkama. Za detalje kontaktirajte operatera <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Više o funkciji \"<xliff:g id="SUBJECT">%1$s</xliff:g>\""</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Nije moguće uključiti <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Da uključite <xliff:g id="FUNCTION">%1$s</xliff:g>, prvo prekinite satelitsku vezu"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 0093d949532..405c28e718e 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Envia i rep missatges de text per satèl·lit. No s\'inclou amb el teu compte."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Missatges per satèl·lit, connectivitat per satèl·lit"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Sobre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Pots enviar i rebre missatges de text per satèl·lit com a part d\'un compte de <xliff:g id="CARRIER_NAME">%1$s</xliff:g> apte"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"El teu pla de <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Els missatges s\'inclouen amb el teu compte"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Pots enviar i rebre missatges de text per satèl·lit amb un compte de <xliff:g id="CARRIER_NAME">%1$s</xliff:g> apte"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"El teu compte de <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Els missatges per satèl·lit s\'inclouen amb el teu compte"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Els missatges per satèl·lit no s\'inclouen amb el teu compte"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Més informació"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Com funciona"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Quan no tinguis connexió de xarxa mòbil"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Envia un missatge de text a un número de telèfon"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"El telèfon es connectarà automàticament a un satèl·lit. Per obtenir la millor connexió possible, has de ser en una zona en què es vegi bé el cel."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Si no tens una xarxa mòbil, veuràs una opció per utilitzar els missatges per satèl·lit."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Quan el telèfon es connecti a un satèl·lit"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Segueix els passos per connectar-te al satèl·lit"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Pots enviar missatges de text a qualsevol persona, inclosos els serveis d\'emergències. El telèfon es tornarà a connectar a una xarxa mòbil quan estigui disponible."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Els <xliff:g id="SUBJECT">%1$s</xliff:g> poden tardar més i només estan disponibles en algunes zones. Les condicions meteorològiques i determinades estructures poden afectar la teva connexió per satèl·lit. Les trucades per satèl·lit no estan disponibles. És possible que puguis continuar fent trucades d\'emergència.\n\nÉs possible que els canvis al teu compte tardin una estona a mostrar-se a Configuració. Contacta amb <xliff:g id="CARRIER_NAME">%1$s</xliff:g> per obtenir més informació."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Un cop el telèfon s\'hagi connectat, podràs enviar missatges de text a qualsevol persona, inclosos els serveis d\'emergències."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Una connexió per satèl·lit pot ser més lenta i només està disponible en algunes zones. Les condicions meteorològiques i determinades estructures poden afectar la connexió. Les trucades per satèl·lit no estan disponibles. És possible que puguis continuar fent trucades d\'emergència.\n\nÉs possible que els canvis al teu compte tardin una estona a mostrar-se a Configuració. Contacta amb <xliff:g id="CARRIER_NAME">%1$s</xliff:g> per obtenir més informació."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Més informació sobre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"No es pot activar <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Per activar <xliff:g id="FUNCTION">%1$s</xliff:g>, primer finalitza la connexió per satèl·lit"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 4f57c2267c5..0e130427cf9 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Odesílání a příjem textových zpráv přes satelit. Ve vašem účtu není zahrnuto."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satelitní zprávy, satelitní připojení"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"O aplikaci <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Můžete odesílat a přijímat textové zprávy přes satelit v rámci způsobilého účtu <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Váš tarif <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Zprávy jsou součástí vašeho účtu"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Můžete odesílat a přijímat textové zprávy přes satelit se způsobilým účtem <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Váš účet <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satelitní zprávy jsou součástí vašeho účtu"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satelitní zprávy nejsou součástí vašeho účtu"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Další informace"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Jak to funguje"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Když nebudete mít mobilní síť"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Posílání textových zpráv na telefonní číslo"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Váš telefon se automaticky připojí k satelitu. Nejlepšího připojení dosáhnete na otevřeném prostranství."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Pokud není dostupná mobilní síť, zobrazí se možnost použít satelitní zprávy"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Jakmile se telefon připojí k satelitu"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Postupujte podle pokynů k připojení k satelitu"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Můžete posílat textové zprávy komukoli, včetně tísňových linek. Telefon se opět připojí k mobilní síti, až bude k dispozici."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> může trvat déle a je dostupné jen v některých oblastech. Na satelitní připojení může mít vliv počasí i některé stavby. Volání přes satelit není dostupné. Tísňová volání se přesto můžou spojit.\n\nMůže chvíli trvat, než se změny účtu projeví v Nastavení. Další podrobnosti vám sdělí operátor <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Po připojení telefonu můžete posílat textové zprávy komukoli, včetně tísňových linek."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Satelitní připojení může být pomalejší a je dostupné jen v některých oblastech. Na připojení může mít vliv počasí a některé stavby. Volání přes satelit není dostupné. Tísňová volání se přesto můžou spojit.\n\nMůže chvíli trvat, než se změny účtu projeví v Nastavení. Další podrobnosti vám sdělí operátor <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> – další informace"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> nelze zapnout"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Pokud chcete zapnout <xliff:g id="FUNCTION">%1$s</xliff:g>, nejdřív ukončete satelitní připojení"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 582db71dca2..6b8efb6cc16 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Send og modtag beskeder via satellit. Ikke tilgængeligt på din konto."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satellitbeskeder, satellitforbindelse"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Om <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Du kan sende og modtage beskeder via satellit som en del af en kvalificeret <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-konto"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Dit <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-abonnement"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Muligheden for at sende beskeder er inkluderet på din konto"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Du kan sende og modtage beskeder via satellit med en kvalificeret <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-konto"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Din <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-konto"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Din konto omfatter satellitbeskeder"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Din konto omfatter ikke satellitbeskeder"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Få flere oplysninger"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Sådan fungerer det"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Når du ikke har et mobilnetværk"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Send en besked til et telefonnummer"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Din telefon opretter automatisk forbindelse til en satellit. Du opnår den bedst mulige forbindelse, hvis du står udenfor med frit udsyn til himlen."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Hvis du ikke har et mobilnetværk, vil du se en valgmulighed for satellitbeskeder."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Når din telefon har oprettet forbindelse til en satellit"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Følg anvisningerne for at oprette forbindelse til satellitten"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Du kan sende en besked til alle, herunder nødtjenester. Din telefon opretter forbindelse til et mobilnetværk igen, når det er tilgængeligt."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> kan tage længere tid og er kun tilgængelig i nogle områder. Vejret og visse fysiske betingelser kan påvirke din satellitforbindelse. Opkald via satellit er ikke muligt. Nødopkald kan muligvis stadig gå igennem.\n\nDer kan gå lidt tid, før kontoændringerne vises i Indstillinger. Kontakt <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for at få flere oplysninger."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Når din telefon er forbundet, kan du sende en besked til alle, herunder nødtjenester."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"En satellitforbindelse kan være langsommere og er kun tilgængelig i visse områder. Vejret og visse fysiske betingelser kan påvirke forbindelsen. Opkald via satellit er ikke muligt. Nødopkald kan muligvis stadig gå igennem.\n\nDer kan gå lidt tid, før kontoændringerne vises under Indstillinger. Kontakt <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for at få flere oplysninger."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Mere om <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> kan ikke aktiveres"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Hvis du vil aktivere <xliff:g id="FUNCTION">%1$s</xliff:g>, skal du først afslutte satellitforbindelsen"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index ba3e34314fd..12a10f4c560 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Nachrichten per Satellitenfunk senden und empfangen. Dein Konto unterstützt diesen Dienst nicht."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Nachrichten per Satellit, Satellitenverbindung"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Funktion „<xliff:g id="SUBJECT">%1$s</xliff:g>“"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Mit einem berechtigten <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-Konto kannst du Nachrichten per Satellitenfunk versenden und empfangen."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Mein <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-Vertrag"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Dein Konto unterstützt Nachrichtenaustausch"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Mit einem berechtigten <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-Konto kannst du Nachrichten per Satellitenfunk versenden und empfangen"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Dein <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-Konto"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Dein Konto unterstützt Nachrichten per Satellit"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Dein Konto unterstützt keine Nachrichten per Satellit"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Weitere Informationen"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"So funktionierts"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Wenn kein Mobilfunknetz verfügbar ist"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Nachricht an eine Telefonnummer senden"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Dein Smartphone stellt automatisch eine Satellitenverbindung her. Für die bestmögliche Verbindung sollte eine freie Sicht zum Himmel bestehen."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Wenn keine Mobilfunkverbindung besteht, wird dir die Option zur Verwendung von „Nachrichten per Satellit“ angezeigt"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Nach Verbindung deines Smartphones mit einem Satelliten"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Folge den Schritten zum Herstellen einer Satellitenverbindung"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Du kannst Nachrichten an beliebige Empfänger versenden, auch an den Rettungsdienst. Sobald wieder ein Mobilfunknetz verfügbar ist, verbindet sich dein Smartphone damit."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"„<xliff:g id="SUBJECT">%1$s</xliff:g>“ ist nicht überall verfügbar und kann die Übertragung verlangsamen. Wetterbedingungen und bestimmte Gebäude, Bäume usw. können die Satellitenverbindung beeinträchtigen. Anrufe per Satellit sind nicht verfügbar. Notrufe funktionieren eventuell trotzdem.\n\nEs kann einige Zeit dauern, bis Kontoänderungen in den Einstellungen angezeigt werden. Wenn du mehr erfahren möchtest, wende dich an <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Sobald dein Smartphone verbunden ist, kannst du Nachrichten an beliebige Empfänger senden, auch an den Rettungsdienst."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Eine Satellitenverbindung ist nicht überall verfügbar und möglicherweise langsamer. Wetterbedingungen und bestimmte Gebäude, Bäume usw. können die Verbindung beeinträchtigen. Anrufe per Satellit sind nicht verfügbar. Notrufe werden eventuell trotzdem verbunden.\n\nEs kann einige Zeit dauern, bis Kontoänderungen in den Einstellungen angezeigt werden. Wenn du mehr erfahren möchtest, wende dich an <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Weitere Informationen zu „<xliff:g id="SUBJECT">%1$s</xliff:g>“"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Aktivieren von „<xliff:g id="FUNCTION">%1$s</xliff:g>“ fehlgeschlagen"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Um die Funktion „<xliff:g id="FUNCTION">%1$s</xliff:g>“ zu aktivieren, beende zuerst die Satellitenverbindung"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index 3a2cae98df2..d5b65cdd7bf 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Στείλτε και λάβετε μηνύματα κειμένου μέσω δορυφόρου. Δεν περιλαμβάνεται στον λογαριασμό σας."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Ανταλλαγή μηνυμάτων μέσω δορυφόρου, δορυφορική συνδεσιμότητα"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Σχετικά με τη λειτουργία <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Μπορείτε να στέλνετε και να λαμβάνετε μηνύματα κειμένου μέσω δορυφόρου στο πλαίσιο ενός κατάλληλου λογαριασμού <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Το πρόγραμμά σας <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Η ανταλλαγή μηνυμάτων συμπεριλαμβάνεται στον λογαριασμό σας"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Μπορείτε να στέλνετε και να λαμβάνετε μηνύματα κειμένου μέσω δορυφόρου με έναν κατάλληλο λογαριασμό <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Ο λογαριασμός σας <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Η ανταλλαγή μηνυμάτων μέσω δορυφόρου συμπεριλαμβάνεται στον λογαριασμό σας"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Η ανταλλαγή μηνυμάτων μέσω δορυφόρου δεν συμπεριλαμβάνεται στον λογαριασμό σας"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Μάθετε περισσότερα"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Πώς λειτουργεί"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Όταν δεν έχετε δίκτυο κινητής τηλεφωνίας"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Αποστολή μηνύματος σε έναν αριθμό τηλεφώνου"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Το τηλέφωνό σας θα συνδεθεί αυτόματα με έναν δορυφόρο. Για την καλύτερη δυνατή σύνδεση, φροντίστε να φαίνεται ο ουρανός χωρίς να παρεμβάλλονται εμπόδια."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Εάν δεν έχετε συνδεθεί σε δίκτυο κινητής τηλεφωνίας, θα δείτε μια επιλογή για τη χρήση της ανταλλαγής μηνυμάτων μέσω δορυφόρου."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Μετά τη σύνδεση του τηλεφώνου σας με έναν δορυφόρο"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Ακολουθήστε τα βήματα, για να συνδεθείτε στον δορυφόρο"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Μπορείτε να στέλνετε μηνύματα σε οποιονδήποτε, ακόμα και στις υπηρεσίες έκτακτης ανάγκης. Το τηλέφωνό σας θα συνδεθεί ξανά σε ένα δίκτυο κινητής τηλεφωνίας όταν είναι διαθέσιμο."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Η λειτουργία <xliff:g id="SUBJECT">%1$s</xliff:g> μπορεί να διαρκέσει περισσότερο και είναι διαθέσιμη μόνο σε ορισμένες περιοχές. Ο καιρός και ορισμένες κατασκευές ενδέχεται να επηρεάσουν τη δορυφορική σύνδεση. Η κλήση μέσω δορυφόρου δεν είναι διαθέσιμη. Μπορεί να υπάρχει ακόμη δυνατότητα για κλήσεις έκτακτης ανάγκης.\n\nΊσως χρειαστεί λίγος χρόνος, για να εμφανιστούν οι αλλαγές λογαριασμού στις Ρυθμίσεις. Για λεπτομέρειες, επικοινωνήστε με την εταιρεία κινητής τηλεφωνίας <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Αφού συνδεθεί το τηλέφωνό σας, μπορείτε να στέλνετε μηνύματα σε οποιονδήποτε, συμπεριλαμβανομένων των υπηρεσιών έκτακτης ανάγκης."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Η δορυφορική σύνδεση είναι διαθέσιμη μόνο σε ορισμένες περιοχές και μπορεί να είναι πιο αργή. Ο καιρός και ορισμένες κατασκευές μπορεί να επηρεάσουν τη σύνδεση. Η πραγματοποίηση κλήσεων μέσω δορυφόρου δεν είναι διαθέσιμη. Η σύνδεση για κλήσεις έκτακτης ανάγκης μπορεί να εξακολουθεί να είναι δυνατή.\n\nΕνδέχεται να χρειαστεί λίγος χρόνος μέχρι να εμφανιστούν οι αλλαγές λογαριασμού στις Ρυθμίσεις. Για λεπτομέρειες, επικοινωνήστε με τον πάροχο <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Περισσότερα για τη λειτουργία <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Δεν είναι δυνατή η ενεργοποίηση της επιλογής <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Για να ενεργοποιήσετε την επιλογή <xliff:g id="FUNCTION">%1$s</xliff:g>, αρχικά τερματίστε τη σύνδεση μέσω δορυφόρου"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 792b8fca599..b2861e3b1f1 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Send and receive text messages by satellite. Not included with your account."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satellite messaging, satellite connectivity"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"About <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"You can send and receive text messages by satellite as part of an eligible <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Your <xliff:g id="CARRIER_NAME">%1$s</xliff:g> plan"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Messaging is included with your account"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"You can send and receive text messages by satellite with an eligible <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Your <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satellite messaging is included with your account"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satellite messaging isn’t included with your account"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Learn more"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"How it works"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"When you don’t have a mobile network"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Text a phone number"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Your phone will auto-connect to a satellite. For the best connection, keep a clear view of the sky."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"If you don\'t have a mobile network, you\'ll see an option to use satellite messaging."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"After your phone connects to a satellite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Follow steps to connect to the satellite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"You can text anyone, including emergency services. Your phone will reconnect to a mobile network when available."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> may take longer and is available only in some areas. Weather and certain structures may affect your satellite connection. Calling by satellite isn\'t available. Emergency calls may still connect.\n\nIt may take some time for account changes to show in Settings. Contact <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for details."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Once your phone is connected, you can text anyone, including emergency services."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"A satellite connection may be slower and is available only in some areas. Weather and certain structures may affect the connection. Calling by satellite isn\'t available. Emergency calls may still connect.\n\nIt may take some time for account changes to show in Settings. Contact <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for details."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"More about <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Can\'t turn on <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"To turn on <xliff:g id="FUNCTION">%1$s</xliff:g>, first end the satellite connection"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index efe61bfd171..ac6bc257281 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Send and receive text messages by satellite. Not included with your account."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satellite messaging, satellite connectivity"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"About <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"You can send and receive text messages by satellite as part of an eligible <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Your <xliff:g id="CARRIER_NAME">%1$s</xliff:g> plan"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Messaging is included with your account"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"You can send and receive text messages by satellite with an eligible <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Your <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satellite messaging is included with your account"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satellite messaging isn’t included with your account"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Learn More"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"How it works"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"When you don’t have a mobile network"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Text a phone number"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Your phone will auto-connect to a satellite. For the best connection, keep a clear view of the sky."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"If you don’t have a mobile network, you’ll see an option to use satellite messaging."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"After your phone connects to a satellite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Follow steps to connect to the satellite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"You can text anyone, including emergency services. Your phone will reconnect to a mobile network when available."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> may take longer and is available only in some areas. Weather and certain structures may affect your satellite connection. Calling by satellite isn’t available. Emergency calls may still connect.\n\nIt may take some time for account changes to show in Settings. Contact <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for details."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"After your phone is connected, you can text anyone, including emergency services."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"A satellite connection may be slower and is available only in some areas. Weather and certain structures may affect the connection. Calling by satellite isn’t available. Emergency calls may still connect.\n\nIt may take some time for account changes to show in Settings. Contact <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for details."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"More about <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Can’t turn on <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"To turn on <xliff:g id="FUNCTION">%1$s</xliff:g>, first end the satellite connection"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 74a29ac51b2..86cab0c9d3a 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Send and receive text messages by satellite. Not included with your account."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satellite messaging, satellite connectivity"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"About <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"You can send and receive text messages by satellite as part of an eligible <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Your <xliff:g id="CARRIER_NAME">%1$s</xliff:g> plan"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Messaging is included with your account"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"You can send and receive text messages by satellite with an eligible <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Your <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satellite messaging is included with your account"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satellite messaging isn’t included with your account"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Learn more"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"How it works"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"When you don’t have a mobile network"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Text a phone number"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Your phone will auto-connect to a satellite. For the best connection, keep a clear view of the sky."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"If you don\'t have a mobile network, you\'ll see an option to use satellite messaging."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"After your phone connects to a satellite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Follow steps to connect to the satellite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"You can text anyone, including emergency services. Your phone will reconnect to a mobile network when available."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> may take longer and is available only in some areas. Weather and certain structures may affect your satellite connection. Calling by satellite isn\'t available. Emergency calls may still connect.\n\nIt may take some time for account changes to show in Settings. Contact <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for details."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Once your phone is connected, you can text anyone, including emergency services."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"A satellite connection may be slower and is available only in some areas. Weather and certain structures may affect the connection. Calling by satellite isn\'t available. Emergency calls may still connect.\n\nIt may take some time for account changes to show in Settings. Contact <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for details."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"More about <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Can\'t turn on <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"To turn on <xliff:g id="FUNCTION">%1$s</xliff:g>, first end the satellite connection"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 608ff95173e..853b6b4e64e 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Send and receive text messages by satellite. Not included with your account."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satellite messaging, satellite connectivity"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"About <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"You can send and receive text messages by satellite as part of an eligible <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Your <xliff:g id="CARRIER_NAME">%1$s</xliff:g> plan"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Messaging is included with your account"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"You can send and receive text messages by satellite with an eligible <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Your <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satellite messaging is included with your account"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satellite messaging isn’t included with your account"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Learn more"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"How it works"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"When you don’t have a mobile network"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Text a phone number"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Your phone will auto-connect to a satellite. For the best connection, keep a clear view of the sky."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"If you don\'t have a mobile network, you\'ll see an option to use satellite messaging."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"After your phone connects to a satellite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Follow steps to connect to the satellite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"You can text anyone, including emergency services. Your phone will reconnect to a mobile network when available."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> may take longer and is available only in some areas. Weather and certain structures may affect your satellite connection. Calling by satellite isn\'t available. Emergency calls may still connect.\n\nIt may take some time for account changes to show in Settings. Contact <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for details."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Once your phone is connected, you can text anyone, including emergency services."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"A satellite connection may be slower and is available only in some areas. Weather and certain structures may affect the connection. Calling by satellite isn\'t available. Emergency calls may still connect.\n\nIt may take some time for account changes to show in Settings. Contact <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for details."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"More about <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Can\'t turn on <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"To turn on <xliff:g id="FUNCTION">%1$s</xliff:g>, first end the satellite connection"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 14573034a48..16a51736098 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Envía y recibe mensajes de texto a través de satélites No se incluye con tu cuenta."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Mensajería satelital, conectividad satelital"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Acerca de <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Puedes enviar y recibir mensajes de texto por satélite como parte de una cuenta de <xliff:g id="CARRIER_NAME">%1$s</xliff:g> apta"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Tu plan de <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"La mensajería está incluida en tu cuenta"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Puedes enviar y recibir mensajes de texto por satélite con una cuenta de <xliff:g id="CARRIER_NAME">%1$s</xliff:g> elegible"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Tu cuenta de <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"La mensajería satelital está incluida con tu cuenta"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"La mensajería satelital no está incluida con tu cuenta"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Más información"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Cómo funciona"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Cuando no tienes una red móvil"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Enviar un mensaje de texto a un número de teléfono"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Tu teléfono se conectará automáticamente a un satélite. Para tener una mejor conexión, mantén una vista clara del cielo."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Si no tienes una red móvil, verás una opción para usar la mensajería satelital."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Luego de que tu teléfono se conecta a un satélite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Sigue los pasos para conectarte al satélite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Puedes enviar mensajes de texto a quien quieras, incluidos los servicios de emergencia. Tu teléfono se volverá a conectar a la red móvil cuando esté disponible."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"La <xliff:g id="SUBJECT">%1$s</xliff:g> podría demorar más y solo está disponible en ciertas áreas. El clima y ciertas estructuras podrían afectar tu conexión. Las llamadas satelitales no están disponibles. Es posible que puedas realizar llamadas de emergencia.\n\nLos cambios en la cuenta podrían demorar en mostrarse en Configuración. Comunícate con <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para obtener más información."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Una vez que el teléfono esté conectado, podrás enviar mensajes de texto a quien quieras, incluidos los servicios de emergencia."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Las conexiones satelitales solo están disponibles en ciertas áreas y pueden ser más lentas. El clima y ciertas estructuras podrían afectarlas. Las llamadas satelitales no están disponibles. Es posible que puedas realizar las llamadas de emergencia.\n\nLos cambios en la cuenta podrían demorar en mostrarse en Configuración. Comunícate con <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para obtener más información."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Más información sobre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"No se puede activar <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Para activar <xliff:g id="FUNCTION">%1$s</xliff:g>, primero termina la conexión satelital"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index ad06766fb13..75407ac1fa0 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Envía y recibe mensajes de texto por satélite. No incluido con tu cuenta."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Mensajes por satélite, conectividad por satélite"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Acerca de <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Puedes enviar y recibir mensajes de texto por satélite como parte de una cuenta de <xliff:g id="CARRIER_NAME">%1$s</xliff:g> apta"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Tu plan de <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Los mensajes están incluidos en tu cuenta"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Puedes enviar y recibir mensajes de texto por satélite con una cuenta de <xliff:g id="CARRIER_NAME">%1$s</xliff:g> apta"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Tu cuenta de <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Los mensajes por satélite están incluidos en tu cuenta"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Los mensajes por satélite no están incluidos en tu cuenta"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Más información"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Cómo funciona"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Cuando no tengas conexión de red móvil"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Enviar mensaje de texto a un número de teléfono"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Tu teléfono se conectará automáticamente a un satélite. Para obtener la mejor conexión, debes estar en una zona en la que se vea bien el cielo."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Si no tienes conexión a una red móvil, verás una opción para usar mensajes por satélite."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Cuando tu teléfono se conecte a un satélite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Sigue los pasos para conectarte al satélite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Puedes intercambiar mensajes de texto con cualquiera, incluidos los servicios de emergencias. Tu teléfono se volverá a conectar a una red móvil cuando esté disponible."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Los <xliff:g id="SUBJECT">%1$s</xliff:g> pueden tardar más y solo están disponibles en ciertas zonas. Las condiciones meteorológicas y algunas estructuras pueden afectar a tu conexión por satélite. Las llamadas por satélite no están disponibles. Puede que las llamadas de emergencia sí funcionen.\n\nLos cambios en tu cuenta pueden tardar un poco en aparecer en Ajustes. Ponte en contacto con <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para saber más."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Cuando tu teléfono se conecte, podrás enviar mensajes de texto a cualquier persona, incluidos los servicios de emergencias."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Las conexiones por satélite pueden ser más lentas y solo están disponibles en algunas zonas. Las condiciones meteorológicas y algunas estructuras pueden afectar a la conexión. Las llamadas por satélite no están disponibles. Puede que las llamadas de emergencia sí funcionen.\n\nLos cambios en tu cuenta pueden tardar un poco en aparecer en Ajustes. Ponte en contacto con <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para saber más."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Más información sobre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"No se puede activar <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Para activar <xliff:g id="FUNCTION">%1$s</xliff:g>, primero finaliza la conexión por satélite"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 6f6616a64b1..a012cb5d729 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Tekstsõnumite saatmine ja vastuvõtmine satelliidi kaudu. Ei sisaldu teie kontos."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satelliidipõhine sõnumside, satelliidi ühenduvus"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Teave <xliff:g id="SUBJECT">%1$s</xliff:g> kohta"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Saate saata ja vastu võtta tekstisõnumeid satelliidi kaudu, kui teil on sobilik operaatori <xliff:g id="CARRIER_NAME">%1$s</xliff:g> konto"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Teie operaatori <xliff:g id="CARRIER_NAME">%1$s</xliff:g> pakett"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Sõnumside on teie kontol saadaval"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Saate tekstsõnumeid satelliidi kaudu vahetada, kasutades sobilikku teenuse <xliff:g id="CARRIER_NAME">%1$s</xliff:g> kontot"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Teie teenuse <xliff:g id="CARRIER_NAME">%1$s</xliff:g> konto"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satellidipõhine sõnumside on teie konto osa"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satelliidipõhine sõnumside ei ole teie konto osa"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Lisateave"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Tööpõhimõtted"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Kui teil ei ole mobiilsidevõrku"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Saatke telefoninumber"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Teie telefon ühendatakse satelliidiga automaatselt. Parima ühenduse tagamiseks asuge taeva all."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Kui teil puudub ühendus mobiilsidevõrguga, kuvatakse teile satelliidipõhise sõnumside kasutamise valik."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Kui telefon on satelliidiga ühenduse loonud"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Järgige satelliidiga ühenduse loomise juhiseid"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Saate sõnumeid saata kellele tahes, sealhulgas hädaabiteenustele. Teie telefon loob uuesti ühenduse mobiilsidevõrguga, kui see on saadaval."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> võib olla aeglasem ja see on saadaval ainult mõnes piirkonnas. Ilm ja teatud struktuurid võivad mõjutada teie satelliidiühendust. Satelliidi kaudu helistamine pole saadaval. Hädaabikõned võivad siiski toimida.\n\nKontol tehtud muudatuste jõustumiseks seadetes võib kuluda veidi aega. Üksikasju küsige operaatorilt <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Pärast telefoni ühendamist saate saata sõnumeid kõigile, sealhulgas hädaabiteenustele."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Satelliidiühendus võib olla aeglasem ja on saadaval vaid teatud piirkondades. Ühendust võib mõjutada ilm ja teatud struktuurid. Satelliidi kaudu helistamine pole saadaval. Hädaabikõned võivad siiski toimida.\n\nKontol tehtud muudatuste jõustumiseks seadetes võib kuluda veidi aega. Lisateabe jaoks võtke ühendust operaatoriga <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Lisateave <xliff:g id="SUBJECT">%1$s</xliff:g> kohta"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Funktsiooni <xliff:g id="FUNCTION">%1$s</xliff:g> ei saa sisse lülitada"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Funktsiooni <xliff:g id="FUNCTION">%1$s</xliff:g> sisselülitamiseks katkestage esmalt satelliitühendus"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 01d4d227b30..a3b7a4d6291 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -4875,9 +4875,9 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Bidali eta jaso testu-mezuak satelite bidez. Ez dator kontuarekin."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"satelite bidezko mezularitza, satelite bidezko konexioa"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Honi buruz: <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Baldintzak betetzen dituen <xliff:g id="CARRIER_NAME">%1$s</xliff:g> operadoreko kontu bat duzunez, testu-mezuak satelite bidez bidali eta jaso ditzakezu"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> operadorearekin kontratatuta daukazun tarifa"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Mezuak trukatzeko aukera kontuarekin dator"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Baldintzak betetzen dituen <xliff:g id="CARRIER_NAME">%1$s</xliff:g> operadoreko kontu batekin, satelite bidez bidali eta jaso ditzakezu testu-mezuak"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> operadoreko kontua"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satelite bidezko mezularitza kontuarekin dator"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satelite bidezko mezularitza ez dator kontuarekin"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Lortu informazio gehiago"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Nola funtzionatzen du?"</string>
@@ -4885,7 +4885,6 @@
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefonoa automatikoki konektatuko da satelite batera. Ahalik eta konexio onena izateko, ziurtatu zerua argi ikus dezakezula."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Telefonoa satelite batera konektatu ondoren"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Edonori bidal diezazkiokezu testu-mezuak, baita larrialdi-zerbitzuei ere. Telefonoa sare mugikor batera konektatuko da berriro, halakorik erabilgarri dagoenean."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Baliteke denbora gehiago behar izatea <xliff:g id="SUBJECT">%1$s</xliff:g> erabiltzeko, eta eremu batzuetan soilik dago erabilgarri. Litekeena da satelite bidezko konexioak eguraldiaren eta egitura jakin batzuen eragina jasatea. Satelite bidez deitzeko aukera ez dago erabilgarri. Baliteke larrialdi-deiak konektatzea, halere.\n\nBaliteke denbora pixka bat behar izatea kontuan egindako aldaketak ezarpenetan agertzeko. Xehetasunak lortzeko, jarri <xliff:g id="CARRIER_NAME">%1$s</xliff:g> operadorearekin harremanetan."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Honi buruzko informazio gehiago: <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Ezin da aktibatu <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> aktibatzeko, amaitu satelite bidezko konexioa"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index c618568dd3f..b9933adfc35 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"پیامک‌ها را ازطریق ماهواره ارسال و دریافت کنید. در حساب شما گنجانده نشده است."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"پیام‌رسانی ماهواره‌ای، اتصال‌پذیری ماهواره"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"درباره <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"به‌عنوان بخشی از حساب واجدشرایط <xliff:g id="CARRIER_NAME">%1$s</xliff:g>، می‌توانید پیامک‌ها را ازطریق ماهواره ارسال و دریافت کنید"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"طرح <xliff:g id="CARRIER_NAME">%1$s</xliff:g> شما"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"پیام‌رسانی در حسابتان ارائه شده است"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"با حساب واجدشرایط <xliff:g id="CARRIER_NAME">%1$s</xliff:g>، می‌توانید ازطریق ماهواره پیام نوشتاری ارسال و دریافت کنید"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"حساب <xliff:g id="CARRIER_NAME">%1$s</xliff:g> شما"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"پیام‌رسانی ماهواره‌ای با حسابتان ارائه شده است"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"پیام‌رسانی ماهواره‌ای با حسابتان ارائه نشده است"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"بیشتر بدانید"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"روش کار"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"وقتی شبکه تلفن همراه ندارید"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ارسال پیامک به شماره تلفن"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"تلفن شما به‌طور خودکار به ماهواره متصل خواهد شد. برای داشتن بهترین اتصال، به فضای بازی بروید که دید واضحی به آسمان داشته باشید."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"اگر شبکه تلفن همراه ندارید، گزینه استفاده از «پیام‌رسانی ماهواره‌ای» را خواهید دید."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"بعداز اتصال تلفن به ماهواره"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"دنبال کردن مراحل برای اتصال به ماهواره"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"می‌توانید برای هرکسی پیام ارسال کنید، ازجمله خدمات اضطراری. هروقت شبکه تلفن همراه دردسترس قرار بگیرد، تلفن دوباره به آن متصل خواهد شد."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> ممکن است مدت زمان بیشتری طول بکشد و فقط در برخی مناطق دردسترس است. ممکن است وضعیت آب‌وهوا و برخی ساختمان‌ها بر اتصال ماهواره اثر بگذارند. تماس ماهواره‌ای دردسترس نیست. ممکن است تماس‌های اضطراری همچنان وصل شود.\n\nشاید کمی طول بکشد تا تغییرات حساب در «تنظیمات» نمایش داده شود. برای اطلاع از جزئیات، با <xliff:g id="CARRIER_NAME">%1$s</xliff:g> تماس بگیرید."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"پس‌از متصل شدن تلفن، می‌توانید به هرکسی پیامک ارسال کنید، ازجمله خدمات اضطراری."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"ممکن است اتصال ماهواره ضعیف و فقط در برخی مناطق دردسترس باشد. ممکن است وضعیت آب‌وهوا و برخی ساختمان‌ها بر اتصال اثر بگذارند. تماس ماهواره‌ای دردسترس نیست. ممکن است تماس‌های اضطراری همچنان وصل شود.\n\nشاید کمی طول بکشد تا تغییرات حساب در «تنظیمات» نمایش داده شود. برای اطلاع از جزئیات، با <xliff:g id="CARRIER_NAME">%1$s</xliff:g> تماس بگیرید."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"اطلاعات بیشتر درباره <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"‫<xliff:g id="FUNCTION">%1$s</xliff:g> روشن نشد"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"برای روشن کردن <xliff:g id="FUNCTION">%1$s</xliff:g>، ابتدا اتصال ماهواره را قطع کنید"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index f5f8fa53ee8..49c40bdb8ac 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Lähetä ja vastaanota tekstiviestejä satelliitin kautta. Ei sisälly tiliin."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satelliittiviestintä, satelliittiyhteys"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Tietoa: <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Voit lähettää ja vastaanottaa tekstiviestejä satelliitin kautta osana ehdot täyttävää <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ‑tiliä"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> ‑pakettisi"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Viestintä on osa tiliäsi"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Voit lähettää ja vastaanottaa tekstiviestejä satelliitin kautta ehdot täyttävällä <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-tilillä"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Tilisi: <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satelliittiviestintä on osa tiliäsi"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satelliittiviestintä ei sisälly tiliisi"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Lue lisää"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Näin se toimii"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Kun mobiiliverkko ei ole saatavilla"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Lähetä tekstiviesti puhelinnumeroon"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Puhelimesi yhdistää satelliittiin automaattisesti. Yhteyden laatu on paras, kun pysyt ulkona avoimella paikalla."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Jos sinulla ei ole yhteyttä mobiiliverkkoon, näet vaihtoehdon, jolla voit käyttää satelliittiviestintää."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Kun puhelin on yhdistänyt satelliittiin"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Muodosta yhteys satelliittiin seuraamalla ohjeita"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Voit lähettää tekstiviestin kenelle tahansa, mukaan lukien hätäkeskukselle. Puhelimesi yhdistää mobiiliverkkoon, kun se on mahdollista."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> voi toimia hitaammin ja olla saatavilla vain tietyillä alueilla. Sää ja jotkin rakenteet voivat vaikuttaa satelliittiyhteyteen. Satelliittiyhteydellä ei voi soittaa puheluja. Hätäpuhelut saattavat kuitenkin onnistua.\n\nVoi mennä jonkin aikaa ennen kuin muutokset näkyvät asetuksissa. <xliff:g id="CARRIER_NAME">%1$s</xliff:g> voi kertoa lisätietoja."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Kun puhelin on yhdistetty, voit lähettää tekstiviestin kenelle tahansa, myös hätäkeskukselle."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Satelliittiyhteys voi olla hitaampi ja se on saatavilla vain tietyillä alueilla. Sää ja jotkin rakenteet voivat vaikuttaa yhteyteen. Satelliittiyhteydellä ei voi soittaa puheluja. Hätäpuhelut saattavat kuitenkin onnistua.\n\nVoi mennä jonkin aikaa ennen kuin muutokset näkyvät asetuksissa. <xliff:g id="CARRIER_NAME">%1$s</xliff:g> voi antaa lisätietoa."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Lisätietoa: <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> ei ole käytettävissä"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Katkaise satelliittiyhteys, jotta <xliff:g id="FUNCTION">%1$s</xliff:g> voidaan laittaa päälle"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index c04e8d614b7..d8ee0437e5d 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Envoyez et recevez des messages texte par satellite. Non inclus avec votre compte."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Messagerie par satellite, connectivité par satellite"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"À propos de <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Vous pouvez envoyer et recevoir des messages texte par satellite à l\'aide d\'un compte <xliff:g id="CARRIER_NAME">%1$s</xliff:g> admissible"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Votre forfait <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"La messagerie est incluse avec votre compte"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Vous pouvez envoyer et recevoir des messages texte par satellite avec un compte <xliff:g id="CARRIER_NAME">%1$s</xliff:g> admissible"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Votre compte <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"La messagerie par satellite est comprise dans votre compte"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"La messagerie par satellite n\'est pas comprise dans votre compte"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"En savoir plus"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Fonctionnement"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"En l\'absence de réseau cellulaire"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Envoyer un message texte à un numéro de téléphone"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Votre téléphone se connectera automatiquement à un satellite. Pour une connexion optimale, tenez le téléphone sous un ciel dégagé."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Si vous n\'avez pas de réseau cellulaire, vous verrez une option vous permettant d\'utiliser la messagerie par satellite."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Une fois que votre téléphone s\'est connecté à un satellite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Suivre les étapes pour vous connecter au satellite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Vous pouvez envoyer des messages texte à n\'importe qui, y compris aux services d\'urgence. Votre téléphone se reconnectera à un réseau cellulaire lorsqu\'il sera accessible."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> peut prendre plus de temps et est accessible seulement dans certaines régions. Les conditions météorologiques et certaines structures peuvent avoir une incidence sur votre connexion par satellite. Les appels par satellite ne sont pas accessibles. Les appels d\'urgence pourraient tout de même se connecter.\n\nIl peut s\'écouler un certain temps avant que les modifications apportées à votre compte s\'affichent dans les paramètres. Communiquez avec <xliff:g id="CARRIER_NAME">%1$s</xliff:g> pour en savoir plus."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Une fois que votre téléphone est connecté, vous pouvez envoyer des messages texte à n\'importe qui, y compris aux services d\'urgence."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Une connexion par satellite peut être plus lente et est accessible seulement dans certaines régions. Les conditions météorologiques et certaines structures peuvent avoir une incidence sur la connexion. Les appels par satellite ne sont pas accessibles. Les appels d\'urgence pourraient tout de même se connecter.\n\nIl peut s\'écouler un certain temps avant que les modifications apportées à votre compte s\'affichent dans les paramètres. Communiquez avec <xliff:g id="CARRIER_NAME">%1$s</xliff:g> pour en savoir plus."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"En savoir plus sur <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Impossible d\'activer la fonctionnalité <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Pour activer la fonctionnalité <xliff:g id="FUNCTION">%1$s</xliff:g>, mettez d\'abord fin à la connexion par satellite"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index bda49f27783..f0fed8d8bbe 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Envoyez et recevez des messages par satellite. Non inclus dans votre compte."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Messagerie par satellite, connectivité satellite"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"À propos de la <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Vous pouvez envoyer et recevoir des messages par satellite dans le cadre d\'un compte <xliff:g id="CARRIER_NAME">%1$s</xliff:g> éligible."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Votre forfait <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"La messagerie est incluse dans votre compte"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Vous pouvez envoyer et recevoir des messages par satellite avec un compte <xliff:g id="CARRIER_NAME">%1$s</xliff:g> éligible"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Votre compte <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"La messagerie par satellite est incluse dans votre compte"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"La messagerie par satellite n\'est pas incluse dans votre compte"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"En savoir plus"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Fonctionnement"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Lorsque vous ne disposez pas de réseau mobile"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Envoyer un message à un numéro de téléphone"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Votre téléphone se connectera automatiquement à un satellite. Pour obtenir une meilleure connexion, restez à l\'extérieur avec une vue dégagée du ciel."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Si vous n\'avez pas de réseau mobile, vous trouverez une option vous permettant d\'utiliser la messagerie par satellite"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Une fois que votre téléphone se connecte à un satellite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Suivez les étapes pour vous connecter au satellite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Vous pouvez envoyer un message à n\'importe qui, y compris les services d\'urgence. Votre téléphone se reconnectera à un réseau mobile le cas échéant."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> peut prendre plus de temps et n\'est disponible que dans certaines zones. La météo et certaines structures peuvent avoir une incidence sur votre connexion satellite. Il n\'est pas possible d\'appeler par satellite. Il est toutefois possible de se connecter aux appels d\'urgence.\n\nLa prise en compte de ces modifications dans Paramètres peut prendre un certain temps. Contactez <xliff:g id="CARRIER_NAME">%1$s</xliff:g> pour plus d\'informations."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Une fois que votre téléphone est connecté, vous pouvez envoyer un message à n\'importe qui, y compris aux services d\'urgence."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Une connexion satellite peut être plus lente et n\'est disponible que dans certaines zones. La météo et certaines structures peuvent avoir une incidence sur la connexion. Il n\'est pas possible d\'appeler par satellite. Il est toutefois possible de passer des appels d\'urgence.\n\nLa prise en compte de ces modifications dans les Paramètres peut prendre un certain temps. Contactez <xliff:g id="CARRIER_NAME">%1$s</xliff:g> pour plus d\'informations."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"En savoir plus sur la <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Impossible d\'activer le <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Pour activer le <xliff:g id="FUNCTION">%1$s</xliff:g>, coupez d\'abord la connexion satellite"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 84da483c0a4..1bf8bc1cd59 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -4875,17 +4875,20 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Envía e recibe mensaxes de texto por satélite. Servizo non incluído na túa conta."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Mensaxaría por satélite, conectividade por satélite"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Acerca de <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Podes enviar e recibir mensaxes de texto por satélite como parte dunha conta de <xliff:g id="CARRIER_NAME">%1$s</xliff:g> que cumpre os requisitos"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"O teu plan de <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"A mensaxaría está incluída na túa conta"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Podes enviar e recibir mensaxes de texto por satélite cunha conta de <xliff:g id="CARRIER_NAME">%1$s</xliff:g> que cumpra os requisitos"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"A túa conta de <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"A mensaxaría por satélite inclúese na túa conta"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"A mensaxaría por satélite non se inclúe na túa conta"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Máis información"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Como funciona?"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Cando non tes ningunha rede de telefonía móbil"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Enviar unha mensaxe de texto a un número de teléfono"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"O teu teléfono conectarase automaticamente cun satélite. Para ter unha mellor conexión, debes situarte nunha zona onde o ceo estea despexado."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Se non tes unha rede de telefonía móbil, verás unha opción para usar a mensaxaría por satélite."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Despois de que o teléfono se conecte a un satélite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Sigue os pasos para conectarte ao satélite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Podes intercambiar mensaxes de texto con calquera persoa, mesmo cos servizos de emerxencia. O teléfono volverá conectarse a unha rede de telefonía móbil en canto haxa unha dispoñible."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> pode tardar máis e só está dispoñible en certas zonas. As condiciones meteorolóxicas e algunhas estruturas poden afectar á túa conexión por satélite. A función de chamada por satélite non está dispoñible. É posible que poidas facer chamadas de emerxencia.\n\nOs cambios na conta poden tardar algo en aparecer na configuración. Contacta con <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para ter máis información."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Cando o teléfono estea conectado, poderás intercambiar mensaxes de texto con calquera persoa, mesmo cos servizos de emerxencia."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Máis información sobre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Non se pode activar a función <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Para activar a función <xliff:g id="FUNCTION">%1$s</xliff:g>, primeiro pecha a conexión por satélite"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index a3822bd9134..578a8060cc7 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"સૅટલાઇટ મારફતે ટેક્સ્ટ મેસેજ મોકલો અને પ્રાપ્ત કરો. તમારા એકાઉન્ટ સાથે શામેલ નથી."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"સૅટલાઇટ મેસેજિંગ, સૅટલાઇટ કનેક્ટિવિટી"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> વિશે"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"યોગ્ય <xliff:g id="CARRIER_NAME">%1$s</xliff:g> એકાઉન્ટના ભાગ તરીકે તમે સૅટલાઇટ મારફતે ટેક્સ્ટ મેસેજ મોકલી અને પ્રાપ્ત કરી શકો છો"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"તમારો <xliff:g id="CARRIER_NAME">%1$s</xliff:g> પ્લાન"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"મેસેજિંગ તમારા એકાઉન્ટમાં શામેલ છે"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"તમે યોગ્યતા ધરાવતા <xliff:g id="CARRIER_NAME">%1$s</xliff:g> એકાઉન્ટ વડે સૅટલાઇટ દ્વારા ટેક્સ્ટ મેસેજ મોકલી અને પ્રાપ્ત કરી શકો છો"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"તમારું <xliff:g id="CARRIER_NAME">%1$s</xliff:g>નું એકાઉન્ટ"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"સૅટલાઇટ મેસેજિંગ તમારા એકાઉન્ટમાં શામેલ છે"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"સૅટલાઇટ મેસેજિંગ તમારા એકાઉન્ટમાં શામેલ નથી"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"વધુ જાણો"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"તેની કામ કરવાની રીત"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"જ્યારે તમે કોઈ મોબાઇલ નેટવર્ક ધરાવતા ન હો, ત્યારે"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ફોન નંબર ટેક્સ્ટ કરો"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"તમારો ફોન સૅટલાઇટ સાથે ઑટોમૅટિક રીતે કનેક્ટ કરવામાં આવશે. શ્રેષ્ઠ કનેક્શન માટે, સ્પષ્ટ રીતે આકાશ જોઈ શકાય તે રીતે બહાર રહો."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"જો તમે કોઈ મોબાઇલ નેટવર્ક ધરાવતા ન હો, તો તમને સૅટલાઇટ મેસેજિંગનો ઉપયોગ કરવા માટે એક વિકલ્પ દેખાશે."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"તમારો ફોન સૅટલાઇટ સાથે કનેક્ટ થયા પછી"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"સૅટલાઇટ સાથે કનેક્ટ કરવા માટે પગલાં અનુસરો"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"તમે ઇમર્જન્સી સર્વિસ સહિત કોઈને પણ ટેક્સ્ટ કરી શકો છો. જ્યારે કોઈ મોબાઇલ નેટવર્ક ઉપલબ્ધ હશે, ત્યારે તમારો ફોન તેની સાથે ફરીથી કનેક્ટ કરવામાં આવશે."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g>ને વધુ સમય લાગી શકે છે અને તે માત્ર અમુક વિસ્તારોમાં જ ઉપલબ્ધ છે. વાતાવરણ અને ચોક્કસ સંરચનાઓ તમારા સૅટલાઇટ કનેક્શનને અસર કરી શકે છે. સૅટલાઇટ મારફતે કૉલ કરવાની સુવિધા ઉપલબ્ધ નથી. છતાં પણ ઇમર્જન્સી કૉલ કનેક્ટ થઈ શકે છે.\n\nએકાઉન્ટમાં કરવામાં આવેલા ફેરફારોને સેટિંગમાં દેખાવામાં થોડો સમય લાગી શકે છે. વિગતો માટે <xliff:g id="CARRIER_NAME">%1$s</xliff:g>નો સંપર્ક કરો."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"તમારો ફોન કનેક્ટ થઈ જાય, તે પછી તમે ઇમર્જન્સી સર્વિસ સહિત, કોઈને પણ ટેક્સ્ટ કરી શકો છો."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"સૅટલાઇટ કનેક્શન કદાચ ધીમું હોઈ શકે છે અને અમુક વિસ્તારોમાં જ ઉપલબ્ધ હોઈ શકે છે. વાતાવરણ અને ચોક્કસ સંરચનાઓ કનેક્શનને અસર કરી શકે છે. સૅટલાઇટ મારફતે કૉલ કરવાની સુવિધા ઉપલબ્ધ નથી. છતાં પણ ઇમર્જન્સી કૉલ કનેક્ટ થઈ શકે છે.\n\nએકાઉન્ટમાં કરવામાં આવેલા ફેરફારોને સેટિંગમાં દેખાવામાં થોડો સમય લાગી શકે છે. વિગતો માટે <xliff:g id="CARRIER_NAME">%1$s</xliff:g>નો સંપર્ક કરો."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> વિશે વધુ માહિતી"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> ચાલુ કરી શકતા નથી"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> ચાલુ કરવા માટે, પહેલા સૅટલાઇટ કનેક્શન સમાપ્ત કરો"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 72b87746f2c..48da8a315e0 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"सैटलाइट के ज़रिए मैसेज भेजें और पाएं. आपके खाते से इस सुविधा का इस्तेमाल नहीं किया जा सकता."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"सैटलाइट के ज़रिए मैसेज भेजने की सुविधा और सैटलाइट कनेक्टिविटी"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> के बारे में जानकारी"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"अगर आपके पास <xliff:g id="CARRIER_NAME">%1$s</xliff:g> खाता है, तो आपके लिए सैटलाइट के ज़रिए मैसेज भेजने और पाने की सुविधा उपलब्ध है"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"आपका <xliff:g id="CARRIER_NAME">%1$s</xliff:g> प्लान"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"आपके खाते के प्लान में सैटलाइट के ज़रिए मैसेज भेजने की सुविधा शामिल है"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"अगर आपके पास <xliff:g id="CARRIER_NAME">%1$s</xliff:g> खाता है, तो आपके लिए सैटलाइट के ज़रिए मैसेज भेजने और पाने की सुविधा उपलब्ध है"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"आपका <xliff:g id="CARRIER_NAME">%1$s</xliff:g> खाता"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"आपके खाते के प्लान में सैटलाइट के ज़रिए मैसेज भेजने की सुविधा शामिल है"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"आपके खाते के प्लान में सैटलाइट के ज़रिए मैसेज भेजने की सुविधा शामिल नहीं है"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"ज़्यादा जानें"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"यह सुविधा कैसे काम करती है"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"मोबाइल नेटवर्क न होने पर"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"फ़ोन नंबर पर मैसेज भेजें"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"आपका फ़ोन, सैटलाइट से अपने-आप कनेक्ट हो जाएगा. अच्छे कनेक्शन के लिए, यह ज़रूरी है कि आप किसी खुली जगह में हों और आसमान साफ़ हो."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"अगर आपके मोबाइल में नेटवर्क नहीं है, तो आपके पास सैटलाइट के ज़रिए मैसेज भेजने की सुविधा का इस्तेमाल करने का विकल्प है."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"फ़ोन के सैटलाइट के साथ कनेक्ट होने पर"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"सैटलाइट से कनेक्ट करने के लिए, दिया गया तरीका अपनाएं"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"इस सुविधा के ज़रिए किसी को भी मैसेज किया जा सकता है. इसमें आपातकालीन सेवाएं भी शामिल हैं. मोबाइल नेटवर्क के उपलब्ध होने पर, आपका फ़ोन फिर से कनेक्ट हो जाएगा."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> में ज़्यादा समय लग सकता है. यह सुविधा, कुछ ही जगहों पर इस्तेमाल की जा सकती है. मौसम और ऊंची इमारतों, पहाड़ों वगैरह की वजह से, आपके सैटलाइट कनेक्शन पर असर पड़ सकता है. सैटलाइट के ज़रिए कॉल करने की सुविधा उपलब्ध नहीं है. हालांकि, आपातकालीन कॉल कनेक्ट हो सकती हैं.\n\nखाते में हुए बदलावों को सेटिंग पर दिखने में थोड़ा समय लग सकता है. ज़्यादा जानकारी के लिए, <xliff:g id="CARRIER_NAME">%1$s</xliff:g> से संपर्क करें."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"आपका फ़ोन कनेक्ट होने के बाद, आपातकालीन सेवाओं को भी मैसेज भेजे जा सकते हैं."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"सैटलाइट कनेक्शन धीमा हो सकता है और यह सिर्फ़ कुछ जगहों पर उपलब्ध है. मौसम और ऊंची इमारतों, पहाड़ों, और अन्य वजहों से, आपके सैटलाइट कनेक्शन पर असर पड़ सकता है. सैटलाइट के ज़रिए कॉल करने की सुविधा उपलब्ध नहीं है. हालांकि, आपातकालीन कॉल कनेक्ट हो सकती हैं.\n\nखाते में हुए बदलावों को सेटिंग में दिखने में थोड़ा समय लग सकता है. इस बारे में जानकारी के लिए, <xliff:g id="CARRIER_NAME">%1$s</xliff:g> से संपर्क करें."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> के बारे में ज़्यादा जानकारी"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> चालू नहीं किया जा सकता"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> चालू करने के लिए, पहले सैटलाइट कनेक्शन बंद करें"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 6e5ecd2ff1b..a7410e1fe60 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Šaljite i primajte tekstne poruke putem satelita. Nije uključeno s vašim računom."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Slanje poruka putem satelita, satelitska povezivost"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"O značajci <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Možete razmjenjivati tekstne poruke putem satelita u sklopu računa pri mobilnom operateru <xliff:g id="CARRIER_NAME">%1$s</xliff:g> koji ispunjava kriterije"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Vaš paket pri mobilnom operateru <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Slanje poruka uključeno je za vaš račun"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Možete razmjenjivati tekstne poruke putem satelita u sklopu <xliff:g id="CARRIER_NAME">%1$s</xliff:g> računa koji ispunjava kriterije"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Vaš <xliff:g id="CARRIER_NAME">%1$s</xliff:g> račun"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Slanje poruka putem satelita uključeno je s vašim računom"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Slanje poruka putem satelita nije uključeno s vašim računom"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Saznajte više"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Kako to funkcionira"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Kada nemate mobilnu mrežu"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Pošaljite poruku na telefonski broj"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Vaš telefon automatski će se povezati sa satelitom. Za najbolju vezu potreban je jasan pogled na nebo."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ako niste povezani s mobilnom mrežom, prikazuje se opcija slanja poruka putem satelita."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Nakon što se vaš telefon poveže sa satelitom"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Slijedite korake za povezivanje sa satelitom"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Možete slati poruke svima, uključujući hitne službe. Vaš telefon ponovno će se povezati s mobilnom mrežom kad bude dostupna."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Izvršavanje značajke <xliff:g id="SUBJECT">%1$s</xliff:g> moglo bi potrajati dulje, a ta je značajka dostupna samo u nekim područjima. Na vašu satelitsku vezu mogu utjecati vremenski uvjeti i određene strukture. Pozivanje putem satelita nije dostupno. Hitni pozivi i dalje se mogu povezati.\n\nMože proteći neko vrijeme dok se promjene računa prikažu u postavkama. Za pojedinosti se obratite mobilnom operateru <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Kad se telefon poveže, možete slati poruke svima, uključujući hitne službe."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Satelitska veza može biti sporija i dostupna je samo u nekim područjima. Na vezu mogu utjecati vremenski uvjeti i određene strukture. Pozivanje putem satelita nije dostupno. Hitni pozivi i dalje se mogu povezati.\n\nMože proći neko vrijeme da promjene računa budu vidljive u postavkama. Za pojedinosti se obratite mobilnom operateru <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Više o značajci <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Nije moguće uključiti funkciju <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Da biste uključili funkciju <xliff:g id="FUNCTION">%1$s</xliff:g>, najprije prekinite satelitsku vezu"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 8762f8b035c..2234737af50 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Szöveges üzeneteket küldhet és fogadhat műholdon keresztül. A szolgáltatás nem áll rendelkezésre a fiókjában."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Műholdas üzenetváltás, műholdas kapcsolat"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> névjegye"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Jogosult <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-fiók részeként szöveges üzeneteket küldhet és fogadhat műholdas kapcsolaton keresztül."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"A <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-csomag"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Az üzenetváltás rendelkezésre áll a fiókjában"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Jogosult <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-fiók esetén szöveges üzeneteket küldhet és fogadhat műholdas kapcsolaton keresztül"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Az Ön <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-fiókja"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"A műholdas üzenetváltás szolgáltatás rendelkezésre áll a fiókjában"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"A műholdas üzenetváltás szolgáltatás nem áll rendelkezésre a fiókjában"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"További információ"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Hogyan működik?"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Amikor nem áll rendelkezésre mobilhálózat"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"SMS küldése telefonszámra"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"A telefon automatikusan csatlakozik az egyik műholdhoz. A jobb kapcsolat érdekében biztosítsa az eszköz szabad rálátását az égre."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ha nem ér el mobilhálózatot, akkor megjelenik egy lehetőség a műholdas üzenetváltás funkció használatához."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Miután telefonja műholdhoz kapcsolódik"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"A műholdhoz való csatlakozáshoz kövesse a lépéseket"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Bárkinek küldhet szöveges üzeneteket, a segélyhívó szolgálatokat is beleértve. A telefon újracsatlakozik az adott mobilhálózatra (ha rendelkezésre áll)."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"A(z) <xliff:g id="SUBJECT">%1$s</xliff:g> hosszabb időt vehet igénybe, és csak bizonyos területeken áll rendelkezésre. Az időjárás és bizonyos építmények befolyásolhatják a műholdas kapcsolatot. Műholdas telefonálásra nincs lehetőség. Ettől függetlenül előfordulhat, hogy a segélyhívásokat kapcsolják.\n\nNémi időbe telhet, amíg a fiókkal kapcsolatos változások megjelennek a Beállításoknál. Részletekért keresse szolgáltatóját: <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Miután telefonja csatlakozott, Ön bárkinek küldhet SMS-t, a segélyhívó szolgálatot is beleértve."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"A műholdas kapcsolat lassabb lehet, és csak bizonyos területeken áll rendelkezésre. Az időjárás és bizonyos építmények befolyásolhatják a kapcsolatot. Műholdas telefonálásra nincs lehetőség. Ettől függetlenül előfordulhat, hogy a segélyhívásokat kapcsolják.\n\nNémi időbe telhet, amíg a fiókkal kapcsolatos változások megjelennek a Beállításoknál. Részletekért keresse szolgáltatóját: <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"További információ erről: <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Nem lehetséges a(z) <xliff:g id="FUNCTION">%1$s</xliff:g> bekapcsolása"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"A(z) <xliff:g id="FUNCTION">%1$s</xliff:g> bekapcsolásához előbb szakítsa meg a műholdas kapcsolatot"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 70cb99db107..0ecc434305b 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Տեքստային հաղորդագրությունների ուղարկում և ստացում արբանյակային կապի միջոցով։ Հասանելի չէ ձեր հաշվի համար։"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Արբանյակային հաղորդագրում, արբանյակային կապ"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"«<xliff:g id="SUBJECT">%1$s</xliff:g>» գործառույթի մասին"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Ձեր <xliff:g id="CARRIER_NAME">%1$s</xliff:g> հաշիվը թույլ է տալիս տեքստային հաղորդագրություններ ուղարկել և ստանալ արբանյակային կապի միջոցով"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Ձեր <xliff:g id="CARRIER_NAME">%1$s</xliff:g> պլանը"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Հաղորդագրումը ներառված է ձեր հաշվում"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Դուք կարող եք արբանյակի միջոցով ուղարկել և ստանալ տեքստային հաղորդագրություններ, եթե պահանջներին համապատասխանող <xliff:g id="CARRIER_NAME">%1$s</xliff:g> հաշիվ ունեք"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Ձեր <xliff:g id="CARRIER_NAME">%1$s</xliff:g> հաշիվը"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Արբանյակային կապով հաղորդագրումը ներառված է ձեր հաշվում"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Արբանյակային կապով հաղորդագրումը ներառված չէ ձեր հաշվում"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Իմանալ ավելին"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Ինչպես է դա աշխատում"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Երբ բջջային ցանցին միացած չլինեք"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Հեռախոսահամար գրեք"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Ձեր հեռախոսն ավտոմատ կմիանա արբանյակային կապին։ Կապի օպտիմալ որակի համար պետք է դրսում լինեք, և երկինքը պետք է պարզ երևա։"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Եթե բջջային ցանցը չի աշխատում, ձեզ կառաջարկվի օգտագործել արբանյակային հաղորդագրումը"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Երբ հեռախոսը միանա արբանյակային կապին"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Միացեք արբանյակին՝ հետևելով հրահանգներին"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Դուք կարող եք տեքստային հաղորդագրություններ ուղարկել ցանկացած համարի, այդ թվում՝ արտակարգ իրավիճակների ծառայություններին։ Ձեր հեռախոսը նորից կմիանա բջջային ցանցին, երբ այն հասանելի դառնա։"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g>ը կարող է ավելի երկար տևել և հասանելի է միայն որոշ տարածաշրջաններում։ Եղանակը և որոշակի կառույցներ կարող են ազդել արբանյակային կապի վրա։ Արբանյակային կապի միջոցով զանգերը հասանելի չեն՝ բացառությամբ շտապ կանչերի։\n\nԿարող է որոշակի ժամանակ պահանջվել, որպեսզի ձեր հաշվի փոփոխությունները ցուցադրվեն Կարգավորումներում։ Մանրամասների համար դիմեք <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-ին։"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Հեռախոսը միացնելուց հետո կարող եք գրել ցանկացածին, ներառյալ՝ շտապ օգնության ծառայություններին։"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Արբանյակային կապը կարող է ավելի դանդաղ լինել և հասանելի է միայն որոշ տարածքներում։ Եղանակը և որոշակի կառույցներ կարող են ազդել կապի վրա։ Արբանյակային կապի միջոցով զանգերը հասանելի չեն։ Արտակարգ իրավիճակների զանգերը կշարունակեն լինել հասանելի։\n\nՀաշվի փոփոխությունները Կարգավորումներում ցուցադրվելու համար կարող է որոշ ժամանակ պահանջվել։ Մանրամասների համար դիմեք <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-ին։"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Լրացուցիչ տեղեկություններ «<xliff:g id="SUBJECT">%1$s</xliff:g>» գործառույթի մասին"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Հնարավոր չէ միացնել այս գործառույթը (<xliff:g id="FUNCTION">%1$s</xliff:g>)"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Այս գործառույթը (<xliff:g id="FUNCTION">%1$s</xliff:g>) միացնելու համար նախ անջատեք արբանյակային կապը"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 6406bc1e65c..4328c583d7f 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Mengirim dan menerima pesan teks melalui satelit. Tidak disertakan di akun Anda."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Fitur pesan satelit, konektivitas satelit"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Tentang <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Anda dapat mengirim dan menerima pesan teks melalui satelit sebagai bagian dari akun <xliff:g id="CARRIER_NAME">%1$s</xliff:g> yang valid"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Paket <xliff:g id="CARRIER_NAME">%1$s</xliff:g> Anda"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Fitur pesan disertakan dalam akun Anda"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Anda dapat mengirim dan menerima pesan teks melalui satelit dengan akun <xliff:g id="CARRIER_NAME">%1$s</xliff:g> yang valid"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Akun <xliff:g id="CARRIER_NAME">%1$s</xliff:g> Anda"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Fitur pesan satelit disertakan pada akun Anda"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Fitur pesan satelit tidak disertakan pada akun Anda"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Pelajari Lebih Lanjut"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Cara kerjanya"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Saat Anda tidak memiliki jaringan seluler"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Kirim pesan ke nomor telepon"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Ponsel Anda akan terhubung otomatis ke satelit. Untuk koneksi terbaik, pastikan langit terlihat tanpa terhalang."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Jika jaringan seluler tidak tersedia, Anda akan melihat opsi untuk menggunakan fitur pesan satelit."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Setelah ponsel Anda terhubung ke satelit"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Ikuti langkah-langkah untuk terhubung ke satelit"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Anda dapat mengirim pesan kepada siapa pun, termasuk layanan darurat. Ponsel Anda akan terhubung kembali ke jaringan seluler jika tersedia."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> mungkin memakan waktu lebih lama dan hanya tersedia di beberapa area. Cuaca dan struktur tertentu dapat memengaruhi koneksi satelit Anda. Menelepon dengan bantuan satelit tidak tersedia. Panggilan darurat masih dapat terhubung.\n\nMungkin perlu waktu beberapa saat agar perubahan akun ditampilkan di Setelan. Hubungi <xliff:g id="CARRIER_NAME">%1$s</xliff:g> untuk mengetahui detailnya."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Setelah ponsel terhubung, Anda dapat mengirim pesan kepada siapa pun, termasuk layanan darurat."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Koneksi satelit mungkin lebih lambat dan hanya tersedia di beberapa area. Cuaca dan struktur tertentu dapat memengaruhi koneksi. Menelepon dengan bantuan satelit tidak tersedia. Panggilan darurat masih dapat terhubung.\n\nMungkin perlu waktu beberapa saat agar perubahan akun ditampilkan di Setelan. Hubungi <xliff:g id="CARRIER_NAME">%1$s</xliff:g> untuk mengetahui detailnya."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Selengkapnya tentang <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Tidak dapat mengaktifkan <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Untuk mengaktifkan <xliff:g id="FUNCTION">%1$s</xliff:g>, akhiri koneksi satelit terlebih dahulu"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 39a74978258..0b36ae617d4 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Sendu og taktu á móti SMS-skilaboðum um gervihnött. Fylgir ekki með reikningnum þínum."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Skilaboð í gegnum gervihnött, tengigeta við gervihnött"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Um <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Þú getur sent og tekið á móti SMS-skilaboðum um gervihnött ef þú ert með gjaldgengann reikning hjá <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Áskriftin þín hjá <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Skilaboðasendingar eru innifaldar í reikningnum þínum"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Þú getur sent og tekið á móti textaskilaboðum gegnum gervihnött með gjaldgengum <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-reikningi"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>-reikningurinn þinn"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Gervihnattarskilaboð eru hluti af reikningnum þínum"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Gervihnattarskilaboð eru ekki hluti af reikningnum þínum"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Nánar"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Svona virkar þetta"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Þegar farsímakerfi er ekki tiltækt"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Senda símanúmer"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Síminn mun tengjast gervihnetti sjálfkrafa. Vertu utandyra þar sem himininn sést vel til að ná sem bestri tengingu."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ef þú ert ekki með farsímakerfi muntu sjá valkost um að nota skilaboð í gegnum gervihnött."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Eftir að síminn tengist gervihnetti"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Fylgdu skrefunum til að tengjast gervihnettinum"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Þú getur sent hverjum sem er skilaboð, þ.m.t. neyðarþjónustu. Síminn mun tengjast farsímakerfi aftur þegar það er tiltækt."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> gætu tekið lengri tíma og eru aðeins í boði á tilteknum svæðum. Veður og ákveðin mannvirki kunna að hafa áhrif á gervihnattartenginguna. Símtöl í gegnum gervihnött eru ekki í boði. Þú getur hugsanlega hringt neyðarsímtöl samt sem áður.\n\nÞað gæti liðið smástund þar til breytingar á reikningi birtast í stillingunum. Hafðu samband við <xliff:g id="CARRIER_NAME">%1$s</xliff:g> til að fá frekari upplýsingar."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Eftir að síminn þinn hefur verið tengdur geturðu sent hverjum sem er skilaboð, þ.m.t. neyðarþjónustu."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Gervihnattartenging kann að vera hægari og er aðeins í boði á sumum svæðum. Veður og tilteknar byggingar kunna að hafa áhrif á tenginguna. Símtöl í gegnum gervihnött eru ekki í boði. Þú getur hugsanlega hringt neyðarsímtöl samt sem áður.\n\nÞað gæti liðið smástund þar til breytingar á reikningi birtast í stillingunum. Hafðu samband við <xliff:g id="CARRIER_NAME">%1$s</xliff:g> fyrir frekari upplýsingar."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Nánar um <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Get ekki kveikt á <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Til að kveikja á <xliff:g id="FUNCTION">%1$s</xliff:g> skaltu byrja á að slökkva á gervihnattartengingunni"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index ec93eb67dd6..867d817692b 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Invia e ricevi messaggi via satellite. Funzione non disponibile con il tuo account."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Messaggi via satellite, connettività satellitare"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Informazioni su <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Puoi scambiare messaggi via satellite come parte di un account <xliff:g id="CARRIER_NAME">%1$s</xliff:g> idoneo"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Il tuo piano di <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"I messaggi sono inclusi nel tuo account"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Puoi scambiare messaggi via satellite con un account <xliff:g id="CARRIER_NAME">%1$s</xliff:g> idoneo"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Il tuo account <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"La messaggistica satellitare è inclusa nel tuo account"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"La messaggistica satellitare non è inclusa nel tuo account"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Scopri di più"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Come funziona"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Se non disponi di una rete mobile"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Invia un messaggio a un numero di telefono"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Lo smartphone si connetterà automaticamente a un satellite. Per ottenere la migliore connessione possibile, mantieni una visuale sgombra del cielo."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Se non disponi di una rete mobile, vedrai un\'opzione per usare i messaggi via satellite."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Dopo che lo smartphone si è connesso a un satellite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Segui i passaggi per connetterti al satellite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Puoi inviare un messaggio a chiunque, anche ai servizi di emergenza. Quando sarà disponibile, lo smartphone si riconnetterà a una rete mobile."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"La <xliff:g id="SUBJECT">%1$s</xliff:g> potrebbe essere più lenta ed essere disponibile solo in alcune zone. Il meteo e determinate strutture potrebbero influire sulla connessione satellitare. Le chiamate via satellite non sono disponibili. Le chiamate di emergenza potrebbero invece ancora riuscire.\n\nPotrebbe passare del tempo prima che le modifiche al tuo account siano visibili nelle Impostazioni. Contatta <xliff:g id="CARRIER_NAME">%1$s</xliff:g> per maggiori dettagli."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Una volta che lo smartphone è connesso, puoi inviare un messaggio a chiunque, inclusi i servizi di emergenza."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Una connessione satellitare potrebbe essere più lenta ed essere disponibile solo in alcune zone. Il meteo e determinate strutture potrebbero influire sulla connessione. Le chiamate via satellite non sono disponibili. Le chiamate di emergenza potrebbero invece ancora riuscire.\n\nPotrebbe passare del tempo prima che le modifiche al tuo account siano visibili nelle Impostazioni. Contatta <xliff:g id="CARRIER_NAME">%1$s</xliff:g> per maggiori dettagli."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Ulteriori informazioni su <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Impossibile attivare la modalità <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Per attivare la funzionalità <xliff:g id="FUNCTION">%1$s</xliff:g>, devi prima terminare la connessione satellitare"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 081c6892e43..e73ecf29f3a 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"שליחה וקבלה של הודעות טקסט באמצעות לוויין. השירות לא נכלל בחשבון שלך."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"העברת הודעות באמצעות לוויין, קישוריות ללוויין"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"מידע על <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"אפשר לשלוח ולקבל הודעות טקסט באמצעות לוויין כחלק מחשבון שעומד בתנאים אצל <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"חבילת הגלישה אצל <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"העברת הודעות כלולה בחשבון שלך"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"אפשר לשלוח ולקבל הודעות טקסט באמצעות לוויין עם חשבון <xliff:g id="CARRIER_NAME">%1$s</xliff:g> שעומד בדרישות"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"חשבון <xliff:g id="CARRIER_NAME">%1$s</xliff:g> שלך"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"העברת הודעות באמצעות לוויין כלולה בחשבון"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"העברת הודעות באמצעות לוויין לא כלולה בחשבון"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"מידע נוסף"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"איך זה עובד"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"למה אין לך רשת סלולרית"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"שליחת הודעת טקסט למספר טלפון"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"הטלפון יתחבר אוטומטית ללוויין. כדי להתחבר בצורה הטובה ביותר צריך להיות בחוץ, מתחת לכיפת השמיים."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"אם אין במכשיר חיבור לרשת סלולרית, תופיע אפשרות להשתמש ב\"העברת הודעות באמצעות לוויין\"."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"אחרי שהטלפון מתחבר ללוויין"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"צריך לפעול לפי השלבים כדי להתחבר ללוויין"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"אפשר לשלוח הודעות טקסט לכל אחד, כולל לשירותי החירום. הטלפון יתחבר מחדש לרשת סלולרית כשהיא תהיה זמינה."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"‫<xliff:g id="SUBJECT">%1$s</xliff:g> אורכת זמן רב יותר וזמינה רק בחלק מהאזורים. מזג אוויר ומבנים מסוימים עשויים להשפיע על חיבור הלוויין. אי אפשר להתקשר באמצעות לוויין. ייתכן שתהיה אפשרות לבצע שיחות חירום.\n\nיכול להיות שיעבור קצת זמן עד שהשינויים בחשבון יופיעו בהגדרות. כדי לקבל פרטים, אפשר לפנות אל <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"אחרי שהטלפון מתחבר, אפשר לשלוח הודעות טקסט לכל אחד, כולל לשירותי החירום."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"החיבור ללוויין עשוי להיות איטי יותר, וזמין רק בחלק מהאזורים. מזג אוויר ומבנים מסוימים עשויים להשפיע על החיבור. אי אפשר להתקשר באמצעות לוויין. ייתכן שתהיה אפשרות לבצע שיחות חירום.\n\nיכול להיות שיעבור קצת זמן עד שהשינויים בחשבון יופיעו בהגדרות. אפשר לפנות אל <xliff:g id="CARRIER_NAME">%1$s</xliff:g> לקבלת פרטים."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"מידע נוסף על <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"אי אפשר להפעיל <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"כדי להפעיל <xliff:g id="FUNCTION">%1$s</xliff:g>, צריך להשבית קודם את חיבור הלוויין"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 6b08e2225d8..cec22100539 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"衛星通信によりテキスト メッセージを送受信します。お客様のアカウントではご利用になれません。"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"衛星通信メッセージ, 衛星接続"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> について"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"対象の <xliff:g id="CARRIER_NAME">%1$s</xliff:g> アカウントの一部として、衛星通信によるテキスト メッセージの送受信を行えます"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> のプラン"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"お客様のアカウントはメッセージの送信が可能です"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"対象の <xliff:g id="CARRIER_NAME">%1$s</xliff:g> アカウントを使用して、衛星経由でテキスト メッセージを送受信できます"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"あなたの <xliff:g id="CARRIER_NAME">%1$s</xliff:g> アカウント"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"衛星通信メッセージはお客様のアカウントに含まれています"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"衛星通信メッセージはお客様のアカウントに含まれていません"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"詳細"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"仕組み"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"モバイル ネットワークがない場合"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"電話番号にテキストを送信する"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"お使いのスマートフォンを衛星通信に自動接続します。接続を最大限良好にするには、外に出て、空がよく見える場所に移動してください"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"モバイル ネットワークを利用できない場合、衛星通信メッセージを使用するためのオプションが表示されます。"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"スマートフォンが衛星通信に接続された後"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"手順に沿って衛星に接続します"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"テキスト メッセージは、緊急サービスを含め誰にでも送信できます。モバイル ネットワークが利用できる状態になると再接続されます。"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g>は、利用できるエリアが制限され、通常より時間がかかることがあります。天候やなんらかの構造物が、衛星通信の接続に影響することがあります。衛星通信による通話はご利用いただけませんが、緊急通報はつながる場合があります。\n\n変更内容がアカウントの [設定] に反映されるまでに時間がかかることがあります。詳細については、<xliff:g id="CARRIER_NAME">%1$s</xliff:g> にお問い合わせください。"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"スマートフォンが接続されたら、緊急サービスを含め誰にでもテキスト メッセージを送信できます。"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"衛星通信は接続が遅い場合があり、利用できるエリアも制限されます。天候やなんらかの構造物が接続に影響することがあります。衛星通信による通話はご利用いただけませんが、緊急通報はつながる場合があります。\n\n変更内容がアカウントの [設定] に反映されるまでに時間がかかることがあります。詳細については、<xliff:g id="CARRIER_NAME">%1$s</xliff:g> にお問い合わせください。"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> の詳細"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> を有効にできません"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> を有効にするには、衛星通信との接続を解除してください"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index e12f85ce201..fbe37dd7da3 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"მიიღეთ და გაგზავნეთ ტექსტური შეტყობინებები სატელიტის მეშვეობით. არ შედის თქვენს ანგარიშში."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"შეტყობინებების სატელიტური მიმოცვლა, სატელიტური კავშირი"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g>-ის შესახებ"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"თქვენ, როგორც მოთხოვნის შესაბამისი <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-ის ანგარიშის წევრს, შეგიძლიათ სატელიტის მეშვეობით გააგზავნოთ და მიიღოთ ტექსტური შეტყობინებები."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"თქვენი <xliff:g id="CARRIER_NAME">%1$s</xliff:g> გეგმა"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"თქვენი ანგარიში მოიცავს შეტყობინებების მიმოცვლას"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"შეგიძლიათ გაგზავნოთ და მიიღოთ ტექსტური შეტყობინებები სატელიტის საშუალებით სათანადო <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-ის ანგარიშით"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"თქვენი <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-ის ანგარიში"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"შეტყობინებების სატელიტური მიმოცვლის ფუნქცია შედის თქვენს ანგარიშში"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"შეტყობინებების სატელიტური მიმოცვლის ფუნქცია არ შედის თქვენს ანგარიშში"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"შეიტყვეთ მეტი"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"მუშაობის პრინციპი"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"მობილური ქსელის არ ქონის შემთხვევაში"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ტელეფონის ნომრის გაგზავნა"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"თქვენი ტელეფონი ავტომატურად დაუკავშირდება სატელიტს. საუკეთესო კავშირისთვის იყავთ ისეთ ადგილას, სადაც ცის ნათელი ხედია."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"თუ მობილური ქსელი არ გაქვთ, დაინახავთ შეტყობინებების სატელიტური მიმოცვლის გამოყენების ვარიანტს."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"თქვენი ტელეფონის სატელიტთან დაკავშირების შემდეგ"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"სატელიტთან დასაკავშირებელი ნაბიჯები"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"შეტყობინების ყველგან გაგზავნა შეგიძლიათ, მათ შორის გადაუდებელი დახმარების სამსახურებში. თქვენი ტელეფონი დაუკავშირდება მობილური ქსელს, მისი ხელმისაწვდომობის შემთხვევაში."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g>-ს შეიძლება უფრო მეტი დრო დასჭირდეს და ხელმისაწვდომია მხოლოდ გარკვეულ ადგილებში. ამინდმა და გარკვეულმა კონსტრუქციებმა შეიძლება გავლენა მოახდინოს თქვენს კავშირზე სატელიტთან. სატელიტით დარეკვა მიუწვდომელია. გადაუდებელი ზარის განხორციელება მიანც შესაძლებელია.\n\nშესაძლოა გარკვეული დრო დასჭირდეს ანგარიშის პარამეტრების ცვლილებების ასახვას. დეტალებისთვის დაუკავშირდით: <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"ტელეფონის დაკავშირების შემდეგ შეგიძლიათ ტექსტური შეტყობინების გაგზავნა ნებისმიერთან, მათ შორის, გადაუდებელი დახმარების სამსახურებში."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"სატელიტური კავშირი შეიძლება იყოს უფრო ნელი და ხელმისაწვდომი მხოლოდ გარკვეულ ტერიტორიაზე. ამინდმა და გარკვეულმა სტრუქტურებმა შეიძლება კავშირზე გავლენა მოახდინონ. სატელიტით დარეკვა მიუწვდომელია. გადაუდებელი ზარის განხორციელება მაინც შესაძლებელია.\n\nშესაძლოა გარკვეული დრო დასჭირდეს ანგარიშის პარამეტრების ცვლილებების ასახვას. დეტალებისთვის დაუკავშირდით: <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"მეტი <xliff:g id="SUBJECT">%1$s</xliff:g>-ის შესახებ"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g>-ის ჩართვა ვერ ხერხდება"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g>-ის ჩასართავად ჯერ დაასრულეთ სატელიტური კავშირი"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 9f0846ac5c1..eec2edb7508 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Жерсерік көмегімен мәтіндік хабарлар жіберуге және алуға болады. Аккаунтыңызға енгізілмеген."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Жерсерік арқылы хабар алмасу, жерсерікке қосылу мүмкіндігі"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> туралы ақпарат"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> аккаунтыңыз жерсерік арқылы мәтіндік хабарларды жіберуге және алуға мүмкіндік береді."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> тарифтік жоспарыңыз"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Хабар алмасу аккаунтыңызға қосылған"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Жарамды <xliff:g id="CARRIER_NAME">%1$s</xliff:g> аккаунтын пайдаланып, жерсерік арқылы мәтіндік хабарларды жіберуге және алуға болады."</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> аккаунтыңыз"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Аккаунтыңызда жерсерік қызметі арқылы хабар алмасу мүмкіндігі бар"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Аккаунтыңызда жерсерік қызметі арқылы хабар алмасу мүмкіндігі жоқ"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Толық ақпарат"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Бұл қалай жұмыс істейді?"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Мобильдік желі жоқ кезде"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Телефон нөміріне мәтіндік хабар жіберу"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Телефоныңыз автоматты түрде жерсерікке қосылады. Қосылу сапасы жоғары болуы үшін, аспан анық көрінетін жерде болыңыз."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Егер сізде мобильдік желі болмаса, жерсерік арқылы хабар алмасу функциясын қолдану опциясын көресіз."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Телефон жерсерікке қосылған соң"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Жерсерікке қосылу үшін нұсқауларды орындаңыз"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Кез келген адамға, соның ішінде құтқару қызметтеріне мәтіндік хабар жібере аласыз. Мобильдік желі болған кезде, телефоныңыз оған қайта қосылады."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> көп уақытты алуы мүмкін және кейбір аймақтарда ғана істейді. Жерсерік байланысына ауа райы мен кейбір құрылыс объектілері әсер етуі мүмкін. Жерсерік арқылы қоңырау шалу мүмкін емес. Құтқару қызметіне бұрынғыша қоңырау шалуға болады.\n\nАккаунтқа енгізілген өзгерістердің параметрлерде шығуына біраз уақыт кетуі мүмкін. \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\" операторына хабарласып, толық мәлімет алыңыз."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Телефон жерсерікке қосылған соң, кез келген адамға, соның ішінде құтқару қызметтеріне мәтіндік хабар жібере аласыз."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Жерсеріктік байланыс баяу және тек кейбір аймақтарда қолжетімді мүмкін. Ауа райы мен кейбір құрылыс объектілері байланысқа әсер етуі мүмкін. Жерсерік арқылы қоңырау шалу мүмкін емес. Құтқару қызметіне бұрынғыша қоңырау шалуға болады.\n\nАккаунтқа енгізілген өзгерістердің параметрлерде шығуына біраз уақыт кетуі мүмкін. \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\" операторына хабарласып, толық мәлімет алыңыз."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> туралы толық ақпарат"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> функциясын қосу мүмкін емес"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> функциясын қосу үшін алдымен жерсерік байланысын тоқтатыңыз."</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index ab1778c9be4..5a30ffc6432 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"ផ្ញើ និងទទួលសារជាអក្សរតាមផ្កាយរណប។ មិនរួមបញ្ចូលជាមួយគណនីរបស់អ្នកទេ។"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"ការ​ផ្ញើ​សារតាមផ្កាយរណប ការតភ្ជាប់ផ្កាយរណប"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"អំពី <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"អ្នកអាចផ្ញើ និងទទួលសារជាអក្សរតាមផ្កាយរណបជាផ្នែកនៃគណនី <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ដែលមានសិទ្ធិ"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"គម្រោង <xliff:g id="CARRIER_NAME">%1$s</xliff:g> របស់អ្នក"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"ការ​ផ្ញើ​សារត្រូវបានរួមបញ្ចូលជាមួយគណនីរបស់អ្នក"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"អ្នកអាចផ្ញើ និងទទួលសារជាអក្សរតាមផ្កាយរណបដោយប្រើគណនី <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ដែលមានសិទ្ធិ"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"គណនី <xliff:g id="CARRIER_NAME">%1$s</xliff:g> របស់អ្នក"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"ការ​ផ្ញើ​សារតាមផ្កាយរណបត្រូវបានរួមបញ្ចូលជាមួយគណនីរបស់អ្នក"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"ការ​ផ្ញើ​សារតាមផ្កាយរណបមិនត្រូវបានរួមបញ្ចូលជាមួយគណនីរបស់អ្នកទេ"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"ស្វែងយល់បន្ថែម"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"របៀបដែលវាដំណើរការ"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"នៅពេលអ្នកមិនមានបណ្ដាញ​ទូរសព្ទ​ចល័ត"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ផ្ញើសារ​ជាអក្សរទៅលេខទូរសព្ទ"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"ទូរសព្ទរបស់អ្នកនឹងភ្ជាប់ទៅផ្កាយរណបដោយស្វ័យប្រវត្តិ។ ដើម្បីទទួលបានការតភ្ជាប់ល្អបំផុត សូមស្ថិតនៅក្រោមផ្ទៃមេឃស្រឡះ។"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"ប្រសិនបើអ្នកមិនមានបណ្ដាញ​ទូរសព្ទ​ចល័តទេ អ្នកនឹងមើលឃើញជម្រើស ដើម្បីប្រើប្រាស់ការ​ផ្ញើ​សារតាមផ្កាយរណប។"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"បន្ទាប់ពីទូរសព្ទរបស់អ្នកភ្ជាប់ទៅផ្កាយរណប"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"អនុវត្តតាមជំហាន ដើម្បីភ្ជាប់ជាមួយផ្កាយរណប"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"អ្នកអាចផ្ញើសារជាអក្សរទៅអ្នកណាក៏បាន រួមទាំងសេវាសង្គ្រោះបន្ទាន់។ ទូរសព្ទរបស់អ្នកនឹងភ្ជាប់ឡើងវិញ នៅពេលមានបណ្ដាញ​ទូរសព្ទ​ចល័ត។"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> អាចចំណាយពេលកាន់តែយូរ និងអាចប្រើបាននៅក្នុងតំបន់មួយចំនួនតែប៉ុណ្ណោះ។ អាកាសធាតុ និងរចនាសម្ព័ន្ធមួយចំនួនអាចប៉ះពាល់ដល់ការតភ្ជាប់ផ្កាយរណបរបស់អ្នក។ មិនអាចធ្វើការហៅទូរសព្ទតាមផ្កាយរណបបានទេ។ ការហៅទៅលេខសង្គ្រោះបន្ទាន់នៅតែអាចភ្ជាប់បាន។\n\nការផ្លាស់ប្ដូរចំពោះគណនីអាចចំណាយពេលបន្តិច ដើម្បីបង្ហាញនៅក្នុង \"ការកំណត់\"។ សូម​ទាក់ទង <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ដើម្បី​ទទួលបានព័ត៌មានលម្អិត។"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"បន្ទាប់ពីទូរសព្ទរបស់អ្នកបានភ្ជាប់ អ្នកអាចផ្ញើសារជាអក្សរទៅអ្នកណាក៏បាន រួមទាំងសេវាសង្គ្រោះបន្ទាន់។"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"ការ​តភ្ជាប់ផ្កាយរណបអាចនឹងយឺតជាង និងអាចប្រើបានតែនៅក្នុងតំបន់មួយចំនួនប៉ុណ្ណោះ។ អាកាសធាតុ និងរចនាសម្ព័ន្ធមួយចំនួនអាចប៉ះពាល់ដល់ការតភ្ជាប់។ មិនអាចធ្វើការហៅទូរសព្ទតាមផ្កាយរណបបានទេ។ ការហៅទៅលេខសង្គ្រោះបន្ទាន់នៅតែអាចភ្ជាប់បានដដែល។\n\nអាចចំណាយពេលខ្លះ ដើម្បីឱ្យការផ្លាស់ប្ដូរគណនីបង្ហាញនៅក្នុងការកំណត់។ សូម​ទាក់ទង <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ដើម្បី​ទទួលបានព័ត៌មានលម្អិត។"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"ព័ត៌មាន​បន្ថែម​អំពី <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"មិនអាចបើក <xliff:g id="FUNCTION">%1$s</xliff:g> បានទេ"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"ដើម្បីបើក <xliff:g id="FUNCTION">%1$s</xliff:g> សូមបញ្ចប់ការ​តភ្ជាប់ផ្កាយរណបជាមុនសិន"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 27abbb0e10e..90e594ca8df 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"ಸ್ಯಾಟಲೈಟ್ ಮೂಲಕ ಪಠ್ಯ ಸಂದೇಶಗಳನ್ನು ಕಳುಹಿಸಿ ಮತ್ತು ಸ್ವೀಕರಿಸಿ. ನಿಮ್ಮ ಖಾತೆಯೊಂದಿಗೆ ಸೇರಿಸಲಾಗಿಲ್ಲ."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"ಸ್ಯಾಟಲೈಟ್ ಮೆಸೇಜಿಂಗ್, ಸ್ಯಾಟಲೈಟ್ ಕನೆಕ್ಟಿವಿಟಿ"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> ಕುರಿತು"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"ಅರ್ಹ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ಖಾತೆಯ ಭಾಗವಾಗಿ, ನೀವು ಸ್ಯಾಟಲೈಟ್‌ನ ಮೂಲಕ ಪಠ್ಯ ಸಂದೇಶಗಳನ್ನು ಕಳುಹಿಸಬಹುದು ಮತ್ತು ಸ್ವೀಕರಿಸಬಹುದು"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"ನಿಮ್ಮ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ಪ್ಲಾನ್"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"ನಿಮ್ಮ ಖಾತೆಯೊಂದಿಗೆ ಸಂದೇಶ ಕಳುಹಿಸುವಿಕೆಯನ್ನು ಸೇರಿಸಲಾಗಿದೆ"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"ಅರ್ಹ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ಖಾತೆಯನ್ನು ಬಳಸಿಕೊಂಡು ನೀವು ಸ್ಯಾಟಲೈಟ್ ಮೂಲಕ ಪಠ್ಯ ಸಂದೇಶಗಳನ್ನು ಕಳುಹಿಸಬಹುದು ಮತ್ತು ಸ್ವೀಕರಿಸಬಹುದು"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"ನಿಮ್ಮ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ಖಾತೆ"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"ಸ್ಯಾಟಲೈಟ್ ಸಂದೇಶ ಕಳುಹಿಸುವಿಕೆಯು ನಿಮ್ಮ ಖಾತೆಯ ಜೊತೆಯಲ್ಲಿ ಸೇರಿದೆ"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"ಸ್ಯಾಟಲೈಟ್ ಸಂದೇಶ ಕಳುಹಿಸುವಿಕೆಯು ನಿಮ್ಮ ಖಾತೆಯ ಜೊತೆಯಲ್ಲಿ ಸೇರಿಲ್ಲ"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"ಇನ್ನಷ್ಟು ತಿಳಿಯಿರಿ"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"ಇದು ಹೇಗೆ ಕೆಲಸ ಮಾಡುತ್ತದೆ"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"ನೀವು ಮೊಬೈಲ್ ನೆಟ್‌ವರ್ಕ್ ಅನ್ನು ಹೊಂದಿಲ್ಲದಿದ್ದಾಗ"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ಫೋನ್ ಸಂಖ್ಯೆಗೆ ಸಂದೇಶ ಕಳುಹಿಸಿ"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"ನಿಮ್ಮ ಫೋನ್ ಸ್ಯಾಟಲೈಟ್‌ಗೆ ಆಟೋ-ಕನೆಕ್ಟ್ ಆಗುತ್ತದೆ. ಉತ್ತಮ ಕನೆಕ್ಷನ್‌ಗಾಗಿ, ಆಕಾಶ ಸ್ಪಷ್ಟವಾಗಿ ಕಾಣುವ ಹಾಗೆ ಇರಿಸಿ."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"ನೀವು ಮೊಬೈಲ್ ನೆಟ್‌ವರ್ಕ್ ಹೊಂದಿಲ್ಲದಿದ್ದರೆ, ನಿಮಗೆ ಸ್ಯಾಟಲೈಟ್ ಮೆಸೇಜಿಂಗ್ ಅನ್ನು ಬಳಸುವ ಆಯ್ಕೆ ಕಾಣುತ್ತದೆ."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"ನಿಮ್ಮ ಫೋನ್ ಸ್ಯಾಟಲೈ‌ಟ್‌ಗೆ ಕನೆಕ್ಟ್ ಆದ ನಂತರ"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"ಸ್ಯಾಟಲೈಟ್‌ಗೆ ಕನೆಕ್ಟ್ ಮಾಡಲು ಹಂತಗಳನ್ನು ಅನುಸರಿಸಿ"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"ತುರ್ತು ಸೇವೆಗಳಿಗೂ ಸಹಿತ, ನೀವು ಯಾರಿಗಾದರೂ ಸಂದೇಶ ಕಳುಹಿಸಬಹುದು. ಲಭ್ಯವಿರುವಾಗ ನಿಮ್ಮ ಫೋನ್ ಮೊಬೈಲ್ ನೆಟ್‌ವರ್ಕ್‌ಗೆ ರೀಕನೆಕ್ಟ್ ಆಗುತ್ತದೆ."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> ಹೆಚ್ಚು ಸಮಯ ತೆಗೆದುಕೊಳ್ಳಬಹುದು ಮತ್ತು ಇದು ಕೆಲವು ಪ್ರದೇಶಗಳಲ್ಲಿ ಮಾತ್ರ ಲಭ್ಯವಿರುತ್ತದೆ. ಹವಾಮಾನ ಮತ್ತು ಕೆಲವೊಂದು ರಚನೆಗಳು ನಿಮ್ಮ ಸ್ಯಾಟಲೈಟ್ ಕನೆಕ್ಷನ್ ಮೇಲೆ ಪರಿಣಾಮ ಬೀರಬಹುದು. ಸ್ಯಾಟಲೈಟ್ ಮೂಲಕ ಕರೆ ಮಾಡುವ ಸೌಲಭ್ಯ ಲಭ್ಯವಿಲ್ಲ. ಹಾಗಿದ್ದರೂ ತುರ್ತು ಕರೆಗಳು ಕನೆಕ್ಟ್ ಆಗಬಹುದು.\n\nಖಾತೆಗೆ ಮಾಡಿರುವ ಬದಲಾವಣೆಗಳು ಸೆಟ್ಟಿಂಗ್‌ಗಳಲ್ಲಿ ಕಾಣಿಸಿಕೊಳ್ಳಲು ಸ್ವಲ್ಪ ಸಮಯ ತೆಗೆದುಕೊಳ್ಳಬಹುದು. ಹೆಚ್ಚಿನ ಮಾಹಿತಿಗಾಗಿ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ಅನ್ನು ಸಂಪರ್ಕಿಸಿ."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"ನಿಮ್ಮ ಫೋನ್ ಕನೆಕ್ಟ್ ಆದ ನಂತರ, ತುರ್ತು ಸೇವೆಗಳು ಸೇರಿದಂತೆ ಯಾರಿಗಾದರೂ ನೀವು ಸಂದೇಶ ಕಳುಹಿಸಬಹುದು."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"ಸ್ಯಾಟಲೈಟ್ ಕನೆಕ್ಷನ್ ನಿಧಾನವಾಗಿರಬಹುದು ಮತ್ತು ಕೆಲವು ಪ್ರದೇಶಗಳಲ್ಲಿ ಮಾತ್ರ ಲಭ್ಯವಿದೆ. ಹವಾಮಾನ ಮತ್ತು ಕೆಲವೊಂದು ರಚನೆಗಳು ಕನೆಕ್ಷನ್ ಮೇಲೆ ಪರಿಣಾಮ ಬೀರಬಹುದು. ಸ್ಯಾಟಲೈಟ್ ಮೂಲಕ ಕರೆ ಮಾಡುವ ಸೌಲಭ್ಯ ಲಭ್ಯವಿಲ್ಲ. ಹಾಗಿದ್ದರೂ ತುರ್ತು ಕರೆಗಳು ಕನೆಕ್ಟ್ ಆಗಬಹುದು.\n\nಖಾತೆಗೆ ಮಾಡಿರುವ ಬದಲಾವಣೆಗಳು ಸೆಟ್ಟಿಂಗ್‌ಗಳಲ್ಲಿ ಕಾಣಿಸಿಕೊಳ್ಳಲು ಸ್ವಲ್ಪ ಸಮಯ ತೆಗೆದುಕೊಳ್ಳಬಹುದು. ಹೆಚ್ಚಿನ ಮಾಹಿತಿಗಾಗಿ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ಅನ್ನು ಸಂಪರ್ಕಿಸಿ."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> ಕುರಿತು ಇನ್ನಷ್ಟು"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> ಅನ್ನು ಆನ್ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> ಅನ್ನು ಆನ್ ಮಾಡಲು, ಮೊದಲು ಸ್ಯಾಟಲೈಟ್ ಕನೆಕ್ಷನ್ ಅನ್ನು ಕೊನೆಗೊಳಿಸಿ"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index cb13dfe254c..7d937649503 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"위성을 통해 문자 메시지를 주고받습니다. 계정에 포함되어 있지 않습니다."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"위성 메시지, 위성 연결"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> 정보"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"대상 <xliff:g id="CARRIER_NAME">%1$s</xliff:g> 계정에 포함되어 있는 경우 위성으로 문자 메시지를 주고 받을 수 있습니다"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"사용 중인 <xliff:g id="CARRIER_NAME">%1$s</xliff:g> 요금제"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"계정에 메시지가 포함되어 있음"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"사용 가능 한 <xliff:g id="CARRIER_NAME">%1$s</xliff:g> 계정을 사용해 위성으로 문자 메시지를 주고받을 수 있습니다"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"내 <xliff:g id="CARRIER_NAME">%1$s</xliff:g> 계정"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"위성 메시지가 계정에 포함되어 있음"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"위성 메시지가 계정에 포함되어 있지 않음"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"자세히 알아보기"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"작동 방식"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"모바일 네트워크를 이용할 수 없는 경우"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"전화번호로 문자를 보내세요"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"휴대전화가 위성에 자동 연결됩니다. 최적의 연결을 위해 하늘이 잘 보이는 상태를 유지하세요."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"모바일 네트워크에 연결되어 있지 않으면 위성 메시지를 사용할 수 있는 옵션이 표시됩니다."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"휴대전화가 위성에 연결된 후"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"단계에 따라 위성에 연결하세요"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"응급 서비스를 포함해 누구에게나 문자 메시지를 보낼 수 있습니다. 모바일 네트워크가 사용 가능해지면 휴대전화가 네트워크에 다시 연결됩니다."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g>은 시간이 더 오래 소요될 수 있으며 일부 지역에서만 사용 가능합니다. 날씨 및 특정 구조물이 위성 연결에 영향을 미칠 수 있습니다. 위성 통화를 사용할 수 없습니다. 긴급 전화는 연결될 수 있습니다.\n\n계정 변경사항이 설정에 표시되는 데 다소 시간이 걸릴 수 있습니다. 자세한 정보는 <xliff:g id="CARRIER_NAME">%1$s</xliff:g>에 문의하세요."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"휴대전화가 연결되면 응급 서비스를 포함해 누구에게나 문자 메시지를 보낼 수 있습니다."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"위성 연결은 속도가 느릴 수 있고, 일부 지역에서만 사용 가능합니다. 날씨 및 특정 구조물이 연결에 영향을 미칠 수 있습니다. 위성 통화는 사용할 수 없지만 긴급 전화는 연결될 수 있습니다.\n\n계정 변경사항이 설정에 표시되는 데 다소 시간이 걸릴 수 있습니다. 자세한 정보는 <xliff:g id="CARRIER_NAME">%1$s</xliff:g>에 문의하세요."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> 정보 더보기"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> 기능을 사용 설정할 수 없음"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> 기능을 사용 설정하려면 먼저 위성 연결을 해제하세요."</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index f28a2614cbc..2fe22c93586 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Спутник аркылуу текст билдирүүлөрдү алып же жөнөтүңүз. Аккаунтуңузга кошулган эмес."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Спутник аркылуу байланышуу, спутник байланышы"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> жөнүндө"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Эгер сизде жарамдуу <xliff:g id="CARRIER_NAME">%1$s</xliff:g> аккаунту болсо, спутник аркылуу текст билдирүүлөрдү жөнөтүп же ала аласыз"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> тарифтик планыңыз"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Аккаунтуңузда жазышуу мүмкүнчүлүгү камтылган"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Талаптарга жооп берген <xliff:g id="CARRIER_NAME">%1$s</xliff:g> аккаунтуңуз болсо, спутник аркылуу жазыша аласыз"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> аккаунтуңуз"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Аккаунтуңузда Спутник аркылуу жазышуу мүмкүнчүлүгү бар"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Аккаунтуңузда Спутник аркылуу жазышуу мүмкүнчүлүгү жок"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Кеңири маалымат"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Ал кантип иштейт"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Мобилдик тармакка туташпаган учурда"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Телефон номерине SMS жөнөтүү"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Телефонуңуз спутникке автоматтык түрдө туташат. Асман ачык көрүнгөн жерде болушуңуз керек."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Эгер мобилдик тармак болбосо, спутник аркылуу байланышуу сунушун көрөсүз"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Телефонуңуз спутникке туташкандан кийин"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Спутникке туташуу үчүн кадамдарды аткарыңыз"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Сиз каалаган адамга, анын ичинде кырсыктаганда жардамга келчү кызматтарга текст билдирүү жөнөтө аласыз. Телефонуңуз мүмкүн болгондо мобилдик тармакка кайра туташат."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> көбүрөөк убакытты алышы мүмкүн жана айрым аймактарда гана жеткиликтүү. Аба ырайы жана айрым нерселер спутник менен байланышыңызга таасирин тийгизиши мүмкүн. Спутник аркылуу чалууга болбойт. Шашылыш чалуу жеткиликтүү болушу мүмкүн.\n\nАккаунтка киргизилген өзгөртүүлөр Параметрлерде бир аздан кийин көрүнөт. Кеңири маалымат алуу үчүн <xliff:g id="CARRIER_NAME">%1$s</xliff:g> менен байланышыңыз."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Телефон туташкандан кийин каалаган адамга, анын ичинде кырсыктаганда жардамга келчү кызматтарга текст билдирүүсүн жөнөтө аласыз."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Спутник байланышы жайыраак болушу мүмкүн жана айрым аймактарда гана жеткиликтүү. Аба ырайы жана айрым нерселер байланышка таасирин тийгизиши мүмкүн. Спутник аркылуу чалууга болбойт. Шашылыш чалуу жеткиликтүү болушу мүмкүн.\n\nАккаунтка киргизилген өзгөртүүлөр Параметрлерде бир аздан кийин көрүнөт. Кеңири маалымат алуу үчүн <xliff:g id="CARRIER_NAME">%1$s</xliff:g> менен байланышыңыз."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> жөнүндө көбүрөөк маалымат"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> күйгүзүлбөй жатат"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> функциясын иштетүү үчүн алгач спутник менен байланышты токтотуңуз"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 861e1d6d976..42efa878bbf 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"ສົ່ງ ແລະ ຮັບຂໍ້ຄວາມຜ່ານດາວທຽມ. ບໍ່ຮວມມາກັບບັນຊີຂອງທ່ານ."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"ການຮັບສົ່ງຂໍ້ຄວາມຜ່ານດາວທຽມ, ການເຊື່ອມຕໍ່ຜ່ານດາວທຽມ"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"ກ່ຽວກັບ <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"ທ່ານສາມາດສົ່ງ ແລະ ຮັບຂໍ້ຄວາມຜ່ານດາວທຽມໄດ້ໂດຍເປັນພາກສ່ວນໜຶ່ງຂອງບັນຊີ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ທີ່ມີສິດ"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"ແພັກເກດ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ຂອງທ່ານ"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"ການຮັບສົ່ງຂໍ້ຄວາມຈະຮວມຢູ່ໃນບັນຊີຂອງທ່ານ"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"ທ່ານສາມາດສົ່ງ ແລະ ຮັບຂໍ້ຄວາມຜ່ານດາວທຽມດ້ວຍບັນຊີ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ທີ່ມີສິດ"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"ບັນຊີ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ຂອງທ່ານ"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"ການຮັບສົ່ງຂໍ້ຄວາມຜ່ານດາວທຽມຮວມຢູ່ໃນບັນຊີຂອງທ່ານ"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"ການຮັບສົ່ງຂໍ້ຄວາມຜ່ານດາວທຽມບໍ່ໄດ້ຮວມຢູ່ໃນບັນຊີຂອງທ່ານ"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"ສຶກສາເພີ່ມເຕີມ"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"ມັນເຮັດວຽກແນວໃດ"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"ເມື່ອທ່ານບໍ່ມີເຄືອຂ່າຍມືຖື"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ສົ່ງຂໍ້ຄວາມໄປຫາເບີໂທລະສັບ"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"ໂທລະສັບຂອງທ່ານຈະເຊື່ອມຕໍ່ກັບດາວທຽມໂດຍອັດຕະໂນມັດ. ສຳລັບການເຊື່ອມຕໍ່ທີ່ດີທີ່ສຸດ, ກະລຸນາຢູ່ໃນພື້ນທີ່ທີ່ເບິ່ງເຫັນທ້ອງຟ້າໄດ້ຢ່າງຊັດເຈນ."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"ຫາກທ່ານບໍ່ມີເຄືອຂ່າຍມືຖື, ທ່ານຈະເຫັນຕົວເລືອກໃຫ້ໃຊ້ການຮັບສົ່ງຂໍ້ຄວາມຜ່ານດາວທຽມ."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"ຫຼັງຈາກທີ່ໂທລະສັບຂອງທ່ານເຊື່ອມຕໍ່ກັບດາວທຽມ"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"ເຮັດຕາມຂັ້ນຕອນເພື່ອເຊື່ອມຕໍ່ກັບດາວທຽມ"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"ທ່ານສາມາດສົ່ງຂໍ້ຄວາມຫາໃຜກໍໄດ້, ເຊິ່ງຮວມທັງບໍລິການສຸກເສີນ. ໂທລະສັບຂອງທ່ານຈະເຊື່ອມຕໍ່ກັບເຄືອຂ່າຍມືຖືອີກຄັ້ງເມື່ອມີໃຫ້ໃຊ້."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> ອາດໃຊ້ເວລາດົນກວ່າປົກກະຕິ ແລະ ພ້ອມໃຫ້ບໍລິການໃນບາງພື້ນທີ່ເທົ່ານັ້ນ. ສະພາບອາກາດ ແລະ ໂຄງສ້າງບາງຢ່າງອາດສົ່ງຜົນຕໍ່ການເຊື່ອມຕໍ່ຜ່ານດາວທຽມຂອງທ່ານ. ການໂທຜ່ານດາວທຽມບໍ່ພ້ອມໃຫ້ບໍລິການ. ການໂທສຸກເສີນອາດຍັງເຊື່ອມຕໍ່ຢູ່.\n\nລະບົບອາດໃຊ້ເວລາໄລຍະໜຶ່ງຈົນກວ່າການປ່ຽນແປງໃນບັນຊີຈະສະແດງໃນການຕັ້ງຄ່າ. ກະລຸນາຕິດຕໍ່ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ສຳລັບລາຍລະອຽດ."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"ຫຼັງຈາກເຊື່ອມຕໍ່ໂທລະສັບຂອງທ່ານແລ້ວ, ທ່ານສາມາດສົ່ງຂໍ້ຄວາມຫາໃຜກໍໄດ້, ເຊິ່ງຮວມທັງບໍລິການສຸກເສີນ."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"ການເຊື່ອມຕໍ່ດາວທຽມອາດຈະຊ້າກວ່າ ແລະ ມີສັນຍານຢູ່ບາງເຂດເທົ່ານັ້ນ. ສະພາບອາກາດ ແລະ ໂຄງສ້າງບາງຢ່າງອາດສົ່ງຜົນຕໍ່ການເຊື່ອມຕໍ່. ການໂທຜ່ານດາວທຽມບໍ່ພ້ອມໃຫ້ບໍລິການ. ການໂທສຸກເສີນອາດຍັງເຊື່ອມຕໍ່ຢູ່.\n\nລະບົບອາດໃຊ້ເວລາໄລຍະໜຶ່ງຈົນກວ່າການປ່ຽນແປງໃນບັນຊີຈະສະແດງໃນການຕັ້ງຄ່າ. ຕິດຕໍ່ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ສຳລັບລາຍລະອຽດ."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"ຂໍ້ມູນເພີ່ມເຕີມກ່ຽວກັບ <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"ບໍ່ສາມາດເປີດ <xliff:g id="FUNCTION">%1$s</xliff:g> ໄດ້"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"ເພື່ອເປີດ <xliff:g id="FUNCTION">%1$s</xliff:g>, ໃຫ້ສິ້ນສຸດການເຊື່ອມຕໍ່ດາວທຽມກ່ອນ"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index dded9397d83..95a4f8f3649 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Siųskite ir gaukite teksto pranešimus per palydovą. Neįtraukiama į jūsų paskyrą."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Susirašinėjimas palydoviniais pranešimais, palydovinis ryšys"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Apie funkciją „<xliff:g id="SUBJECT">%1$s</xliff:g>“"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Galite siųsti ir gauti teksto pranešimus palydovo ryšiu, jei turite tinkamą „<xliff:g id="CARRIER_NAME">%1$s</xliff:g>“ paskyrą"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Jūsų „<xliff:g id="CARRIER_NAME">%1$s</xliff:g>“ planas"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Susirašinėjimo funkcija įtraukta į jūsų paskyrą"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Galite siųsti ir gauti teksto pranešimus per palydovą naudodami tinkamą „<xliff:g id="CARRIER_NAME">%1$s</xliff:g>“ paskyrą"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Jūsų „<xliff:g id="CARRIER_NAME">%1$s</xliff:g>“ paskyra"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Palydoviniai pranešimai įtraukti į jūsų paskyrą"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Palydoviniai pranešimai neįtraukti į jūsų paskyrą"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Sužinokite daugiau"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Kaip tai veikia"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Kai neturite mobiliojo ryšio tinklo"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Teksto pranešimo siuntimas telefono numeriu"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefonas bus automatiškai prijungtas prie palydovo. Kad užtikrintumėte geriausią ryšį, turi būti aiškiai matomas dangus."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Jei neturite mobiliojo ryšio tinklo, bus pateikta parinktis naudoti susirašinėjimą palydoviniais pranešimais."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Kai telefonas prisijungia prie palydovo"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Atlikite veiksmus, kad prisijungtumėte prie palydovo"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Galite siųsti teksto pranešimą bet kam, įskaitant pagalbos tarnybas. Telefonas bus iš naujo prijungtas prie mobiliojo ryšio tinklo, kai jis bus pasiekiamas."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Funkcija „<xliff:g id="SUBJECT">%1$s</xliff:g>“ gali veikti lėčiau ir būti pasiekiama tik tam tikrose vietovėse. Orų sąlygos ir tam tikros struktūros gali turėti įtakos palydovo ryšiui. Skambinti per palydovą negalima. Skambučiai pagalbos numeriu gali būti sujungiami.\n\nGali šiek tiek užtrukti, kol paskyros pakeitimai bus rodomi Nustatymuose. Kreipkitės į „<xliff:g id="CARRIER_NAME">%1$s</xliff:g>“ išsamios informacijos."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Kai telefonas prisijungs, galėsite siųsti teksto pranešimą bet kam, įskaitant pagalbos tarnybas."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Palydovinis ryšys gali būti lėtesnis ir pasiekiamas tik tam tikrose vietovėse. Orų sąlygos ir tam tikros struktūros gali turėti įtakos ryšiui. Skambinti per palydovą negalima. Skambučiai pagalbos numeriu gali būti sujungiami.\n\nGali šiek tiek užtrukti, kol paskyros pakeitimai bus rodomi Nustatymuose. Kreipkitės į „<xliff:g id="CARRIER_NAME">%1$s</xliff:g>“ išsamios informacijos."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Daugiau apie funkciją „<xliff:g id="SUBJECT">%1$s</xliff:g>“"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Nepavyko įjungti „<xliff:g id="FUNCTION">%1$s</xliff:g>“"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Jei norite įjungti „<xliff:g id="FUNCTION">%1$s</xliff:g>“, pirmiausia nutraukite palydovinį ryšį"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 04715c97109..05e83111634 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Sūtiet un saņemiet īsziņas, izmantojot satelītu. Šī iespēja nav pieejama ar jūsu kontu."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satelīta ziņojumapmaiņa, satelīta savienojamība"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Par funkciju <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Varat sūtīt un saņemt īsziņas, izmantojot satelītu, ja jums ir prasībām atbilstošs <xliff:g id="CARRIER_NAME">%1$s</xliff:g> konts"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Jūsu <xliff:g id="CARRIER_NAME">%1$s</xliff:g> plāns"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Ziņojumapmaiņa ir ietverta jūsu konta plānā"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Varat sūtīt un saņemt īsziņas, lietojot satelītu, ja jums ir prasībām atbilstošs <xliff:g id="CARRIER_NAME">%1$s</xliff:g> konts."</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Jūsu <xliff:g id="CARRIER_NAME">%1$s</xliff:g> konts"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Ziņojumapmaiņa, izmantojot satelītu, ir iekļauta jūsu kontā"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Ziņojumapmaiņa, izmantojot satelītu, nav iekļauta jūsu kontā"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Uzzināt vairāk"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Darbības principi"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Ja nav savienojuma ar mobilo tīklu"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Sūtiet īsziņu uz tālruņa numuru"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Tālrunī tiks automātiski izveidots savienojums ar satelītu. Vislabākais savienojums ir zem klajas debess."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ja nav piekļuves mobilajam tīklam, tiks rādīta iespēja izmantot satelīta ziņojumapmaiņu."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Kad tālrunī ir izveidots savienojums ar satelītu"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Izpildiet norādītās darbības, lai izveidotu savienojumu ar satelītu"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Varat sūtīt īsziņu ikvienam, tostarp ārkārtas palīdzības dienestiem. Tālrunī tiks atkārtoti izveidots savienojums ar mobilo tīklu, tiklīdz tas būs pieejams."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> var aizņemt vairāk laika, un tā ir pieejama tikai noteiktos apgabalos. Laikapstākļi un noteiktas būves var ietekmēt savienojumu ar satelītu. Zvanīšana, izmantojot satelītu, nav pieejama. Var būt iespējami ārkārtas izsaukumi.\n\nVar būt nepieciešams laiks, lai kontā veiktās izmaiņas būtu redzamas iestatījumos. Sazinieties ar operatoru <xliff:g id="CARRIER_NAME">%1$s</xliff:g> un uzziniet vairāk."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Kad tālrunī ir izveidots savienojums, varat sūtīt īsziņu ikvienam, tostarp ārkārtas palīdzības dienestiem."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Satelīta savienojums var būt lēnāks, un tas ir pieejams tikai noteiktos apgabalos. Savienojumu var ietekmēt laikapstākļi un noteiktas būves. Zvanīšana, izmantojot satelītu, nav pieejama. Var būt iespējami ārkārtas izsaukumi.\n\nVar būt nepieciešams laiks, lai kontā veiktās izmaiņas būtu redzamas iestatījumos. Sazinieties ar operatoru <xliff:g id="CARRIER_NAME">%1$s</xliff:g> un uzziniet vairāk."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Plašāka informācija par funkciju <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Nevar ieslēgt <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Lai ieslēgtu <xliff:g id="FUNCTION">%1$s</xliff:g>, vispirms pārtrauciet savienojumu ar satelītu."</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 28b0c3212cd..081e482e026 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -4875,17 +4875,20 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Испраќајте и примајте текстуални пораки преку сателит. Ова не доаѓа со вашата сметка."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Сателитска размена на пораки, сателитска врска"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"За <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Може да испраќате и примате текстуални пораки преку сателит како дел од подобна сметка на <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Вашиот пакет од <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Размената на пораки е опфатена со вашата сметка"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Може да испраќате и примате текстуални пораки преку сателит со подобна сметка на <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Вашата сметка на <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Размената на пораки преку сателит е опфатена со вашата сметка"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Размената на пораки преку сателит не е опфатена со вашата сметка"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Дознајте повеќе"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Дознајте како функционира"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Кога немате мобилна мрежа"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Испратете порака со телефонски број"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Вашиот телефон ќе се поврзе на сателит автоматски. За најдобра врска, погрижете се да имате јасен поглед кон небото."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ако немате мобилна мрежа, ќе видите опција за користење „Сателитска размена на пораки“."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Откако телефонот ќе ви се поврзе на сателит"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Следете ги чекорите за да се поврзете со сателитот"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Може да испраќате пораки до сите, меѓу кои и службите за итни случаи. Вашиот телефон повторно ќе се поврзе на мобилна мрежа кога ќе биде достапна."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> може да трае подолго и е достапна само во некои области. Временските услови и одредени структури може да влијаат на вашата сателитска врска. Повикувањето преку сателит не е достапно. Итните повици можеби и понатаму ќе се поврзуваат.\n\nМоже да биде потребно некое време за да се прикажат промените на сметката во „Поставки“. За повеќе детали, контактирајте со <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Откако ќе ви се поврзе телефонот, може да испраќате пораки до сите, меѓу кои и службите за итни случаи."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Повеќе за <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Не може да се вклучи <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"За да вклучите <xliff:g id="FUNCTION">%1$s</xliff:g>, прво прекинете ја сателитската врска"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index c265088909b..417aea6029b 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"സാറ്റലൈറ്റ് വഴി ടെക്‌സ്‌റ്റ് മെസേജുകൾ അയയ്ക്കുക, സ്വീകരിക്കുക. നിങ്ങളുടെ അക്കൗണ്ടിൽ ഉൾപ്പെടുത്തിയിട്ടില്ല."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"സാറ്റലൈറ്റ് സഹായത്തോടെ സന്ദേശമയയ്ക്കൽ, സാറ്റലൈറ്റ് കണക്റ്റിവിറ്റി"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> എന്നതിനെ കുറിച്ച്"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"യോഗ്യതയുള്ള <xliff:g id="CARRIER_NAME">%1$s</xliff:g> അക്കൗണ്ടിന്റെ ഭാഗമായി, സാറ്റലൈറ്റ് വഴി ടെക്സ്റ്റ് മെസേജുകൾ അയയ്‌ക്കാനും സ്വീകരിക്കാനും നിങ്ങൾക്ക് കഴിയും"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"നിങ്ങളുടെ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> പ്ലാൻ"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"നിങ്ങളുടെ അക്കൗണ്ടിൽ സന്ദേശമയയ്ക്കൽ ഉൾപ്പെടുത്തിയിട്ടുണ്ട്"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"യോഗ്യതയുള്ള ഒരു <xliff:g id="CARRIER_NAME">%1$s</xliff:g> അക്കൗണ്ട് ഉപയോഗിച്ച് നിങ്ങൾക്ക് സാറ്റലൈറ്റ് വഴി ടെക്‌സ്റ്റ് സന്ദേശങ്ങൾ അയയ്‌ക്കാനും സ്വീകരിക്കാനും കഴിയും"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"നിങ്ങളുടെ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> അക്കൗണ്ട്"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"നിങ്ങളുടെ അക്കൗണ്ടിൽ സാറ്റലൈറ്റ് സന്ദേശമയയ്‌ക്കൽ ഉൾപ്പെടുത്തിയിട്ടുണ്ട്"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"നിങ്ങളുടെ അക്കൗണ്ടിൽ സാറ്റലൈറ്റ് സന്ദേശമയയ്‌ക്കൽ ഉൾപ്പെടുത്തിയിട്ടില്ല"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"കൂടുതലറിയുക"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"ഇത് പ്രവർത്തിക്കുന്നത് എങ്ങനെയാണ്"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"നിങ്ങൾക്ക് മൊബൈൽ നെറ്റ്‌വർക്ക് ഇല്ലാത്തപ്പോൾ"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ഒരു ഫോൺ നമ്പർ ടെക്‌സ്‌റ്റ് ചെയ്യുക"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"നിങ്ങളുടെ ഫോൺ ഒരു സാറ്റലൈറ്റുമായി സ്വയമേവ കണക്‌റ്റ് ചെയ്യും. മികച്ച കണക്ഷൻ ലഭിക്കാൻ, ആകാശം വ്യക്തമായി കാണുന്നിടത്ത് നിൽക്കുക."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"നിങ്ങൾക്ക് മൊബൈൽ നെറ്റ്‌വർക്ക് ഇല്ലെങ്കിൽ, സാറ്റലൈറ്റ് സഹായത്തോടെ സന്ദേശമയയ്ക്കാനുള്ള ഒരു ഓപ്ഷൻ കാണാനാകും."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"നിങ്ങളുടെ ഫോൺ സാറ്റലൈറ്റുമായി കണക്‌റ്റ് ചെയ്‌തതിന് ശേഷം"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"സാറ്റലൈറ്റിലേക്ക് കണക്‌റ്റ് ചെയ്യാൻ ഇനിപ്പറയുന്ന ഘട്ടങ്ങൾ പാലിക്കുക"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"അടിയന്തര സേവനങ്ങൾക്ക് ഉൾപ്പെടെ ഏതൊരാൾക്കും ടെക്‌സ്‌റ്റ് ചെയ്യാൻ നിങ്ങൾക്ക് കഴിയും. ഒരു മൊബൈൽ നെറ്റ്‌വർക്ക് ലഭ്യമാകുമ്പോൾ നിങ്ങളുടെ ഫോൺ അതിലേക്ക് വീണ്ടും കണക്‌റ്റ് ചെയ്യും."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> എന്നതിന് കൂടുതൽ സമയമെടുത്തേക്കാം, ചില പ്രദേശങ്ങളിൽ മാത്രമേ അത് ലഭ്യമാകൂ. കാലാവസ്ഥയും ചില ഘടനകളും നിങ്ങളുടെ സാറ്റലൈറ്റ് കണക്ഷനെ ബാധിച്ചേക്കാം. സാറ്റലൈറ്റ് വഴി കോളുകൾ ചെയ്യുന്നത് ലഭ്യമല്ല. എമർജൻസി കോളുകൾ തുടർന്നും കണക്റ്റ് ചെയ്‌തേക്കാം.\n\nഅക്കൗണ്ടിലെ മാറ്റങ്ങൾ, ക്രമീകരണത്തിൽ ദൃശ്യമാകാൻ കുറച്ച് സമയമെടുത്തേക്കാം. വിശദവിവരങ്ങൾക്ക് <xliff:g id="CARRIER_NAME">%1$s</xliff:g> എന്നതിനെ ബന്ധപ്പെടുക."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"നിങ്ങളുടെ ഫോൺ കണക്‌റ്റ് ചെയ്‌ത ശേഷം, അടിയന്തര സേവനങ്ങൾ ഉൾപ്പെടെ ആർക്കും സന്ദേശമയയ്‌ക്കാം."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"സാറ്റലൈറ്റ് കണക്ഷൻ മന്ദഗതിയിലായിരിക്കാം, ചില പ്രദേശങ്ങളിൽ മാത്രമേ ലഭ്യമാകൂ. കാലാവസ്ഥയും ചില ഘടനകളും കണക്ഷനെ ബാധിച്ചേക്കാം. സാറ്റലൈറ്റ് വഴി കോളുകൾ ചെയ്യുന്നത് ലഭ്യമല്ല. എമർജൻസി കോളുകൾ തുടർന്നും കണക്റ്റ് ചെയ്‌തേക്കാം.\n\nഅക്കൗണ്ടിലെ മാറ്റങ്ങൾ, ക്രമീകരണത്തിൽ ദൃശ്യമാകാൻ കുറച്ച് സമയമെടുത്തേക്കാം. വിശദാംശങ്ങൾക്ക് <xliff:g id="CARRIER_NAME">%1$s</xliff:g> എന്നതിനെ ബന്ധപ്പെടുക."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> എന്നതിനെ കുറിച്ചുള്ള കൂടുതൽ വിവരങ്ങൾ"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> ഓണാക്കാനാകുന്നില്ല"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> ഓണാക്കാൻ, ആദ്യം സാറ്റലൈറ്റ് കണക്ഷൻ അവസാനിപ്പിക്കുക"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 3cecb727e0d..108cb7ce422 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -4875,17 +4875,20 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Хиймэл дагуулаар мессеж илгээж, хүлээн авна уу. Таны бүртгэлд багтаагүй."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Хиймэл дагуулаар дамжин мессеж бичих, хиймэл дагуулын холболт"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g>-н тухай"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Та зохих эрхтэй <xliff:g id="CARRIER_NAME">%1$s</xliff:g> бүртгэлийн нэг хэсэг байдлаар хиймэл дагуулаар мессеж илгээх болон хүлээн авах боломжтой"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Таны <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-н багц"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Таны бүртгэл хиймэл дагуулаар дамжуулан мессеж бичих боломжтой"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Та зохих эрхтэй <xliff:g id="CARRIER_NAME">%1$s</xliff:g> бүртгэлээр хиймэл дагуулаар мессеж илгээх, хүлээн авах боломжтой"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Таны <xliff:g id="CARRIER_NAME">%1$s</xliff:g> бүртгэл"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Хиймэл дагуулаар мессеж бичих нь таны бүртгэлд багтсан"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Хиймэл дагуулаар мессеж бичих нь таны бүртгэлд багтаагүй"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Нэмэлт мэдээлэл авах"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Энэ хэрхэн ажилладаг вэ?"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Танд хөдөлгөөнт холбооны сүлжээ байхгүй үед"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Утасны дугаар луу мессеж бичих"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Таны утас хиймэл дагуулд автоматаар холбогдоно. Шилдэг холболтыг авах бол тэнгэр тод харагдах газар байгаарай."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Хэрэв танд хөдөлгөөнт холбооны сүлжээ байхгүй бол та хиймэл дагуулаар дамжин мессеж бичихийг ашиглах сонголтыг харна."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Таны утас хиймэл дагуулд холбогдсоны дараа"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Хиймэл дагуулд холбогдох алхмуудыг дагах"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Та яаралтай тусламжийн үйлчилгээнүүдийг оруулаад дурын хүн рүү мессеж бичих боломжтой. Таны утас хөдөлгөөнт холбооны сүлжээг боломжтой үед үүнд дахин холбогдоно."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> удаж магадгүй ба зөвхөн зарим бүсэд боломжтой. Цаг агаар, тодорхой байгууламжууд таны хиймэл дагуулын холболтод нөлөөлж болно. Хиймэл дагуулаар дуудлага хийх боломжгүй. Яаралтай дуудлагад холбогдсон хэвээр байж магадгүй.\n\nТаны бүртгэлийн өөрчлөлт Тохиргоонд харагдах хүртэл хэсэг хугацаа зарцуулж болно. Дэлгэрэнгүй мэдээлэл авах бол <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-тай холбогдоно уу."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Та утсаа холбогдсоны дараа дурын хүн рүү мессеж бичих боломжтой бөгөөд үүнд яаралтай тусламжийн үйлчилгээ багтана."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g>-н талаарх дэлгэрэнгүй"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g>-г асаах боломжгүй"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g>-г асаахын тулд эхлээд хиймэл дагуулын холболтыг тасална уу"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 04e4ac46c9a..6d26208d2cf 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"सॅटेलाइटद्वारे एसएमएस पाठवा आणि मिळवा. तुमच्या खात्यात समाविष्ट नाही."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"सॅटेलाइट मेसेजिंग, सॅटेलाइट कनेक्टिव्हिटी"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> विषयी"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"तुम्ही <xliff:g id="CARRIER_NAME">%1$s</xliff:g> खात्याच्या पात्रतेचा भाग म्हणून उपग्रहाद्वारे एसएमएस पाठवू आणि मिळवू शकता"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"तुमचा <xliff:g id="CARRIER_NAME">%1$s</xliff:g> प्लॅन"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"तुमच्या खात्यामध्ये मेसेजिंगचा समावेश केला आहे"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"तुम्ही पात्र <xliff:g id="CARRIER_NAME">%1$s</xliff:g> खात्यासह सॅटेलाइटद्वारे एसएमएस पाठवू आणि मिळवू शकता"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"तुमचे <xliff:g id="CARRIER_NAME">%1$s</xliff:g> खाते"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"तुमच्या खात्यामध्ये उपग्रह मेसेजिंगचा समावेश आहे"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"उपग्रह मेसेजिंगचा तुमच्या खात्यामध्ये समावेश केलेला नाही"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"अधिक जाणून घ्या"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"ते कसे काम करते"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"तुमच्याकडे मोबाइल नेटवर्क नसते, तेव्हा"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"फोन नंबरला एसएमएस पाठवा"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"तुमचा फोन उपग्रहाशी ऑटो-कनेक्ट होईल. सर्वोत्तम कनेक्शनसाठी, आकाश स्पष्ट दिसेल अशा ठिकाणी बाहेर उभे रहा."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"तुमच्याकडे मोबाईल नेटवर्क नसल्यास, तुम्हाला सॅटेलाइट मेसेजिंग वापरण्याचा पर्याय दिसेल."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"तुमचा फोन उपग्रहाशी जोडल्यानंतर"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"सॅटेलाइटशी कनेक्ट करण्यासाठी पायऱ्या फॉलो करा"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"आणीबाणी सेवांसह तुम्ही कोणालाही एसएमएस पाठवू शकता. उपलब्ध असेल, तेव्हा तुमचा फोन मोबाइल नेटवर्कशी पुन्हा कनेक्ट होईल."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> ला जास्त वेळ लागू शकतो आणि ते फक्त काही भागांमध्ये उपलब्ध आहे. हवामान आणि विशिष्ट संरचना तुमच्या सॅटेलाइट कनेक्शनवर परिणाम करू शकतात. सॅटेलाइटद्वारे कॉल करणे उपलब्ध नाही. आणीबाणी कॉल अजूनही कनेक्ट होऊ शकतात.\n\nखात्यामधील बदल सेटिंग्ज मध्ये दिसण्यासाठी काही वेळ लागू शकतो. तपशिलांसाठी <xliff:g id="CARRIER_NAME">%1$s</xliff:g> शी संपर्क साधा."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"तुमचा फोन कनेक्ट केल्यानंतर, तुम्ही आणीबाणी सेवांसोबतच इतर कोणालाही एसएमएस पाठवू शकता."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"सॅटेलाइट कनेक्शनचा वेग कमी असू शकतो आणि ते फक्त काही भागांमध्ये उपलब्ध असते. हवामान आणि विशिष्ट संरचना कनेक्शनवर परिणाम करू शकतात. सॅटेलाइटद्वारे कॉल करणे उपलब्ध नाही. आणीबाणी कॉल अजूनही कनेक्ट होऊ शकतात.\n\nखात्यामधील बदल सेटिंग्ज मध्ये दिसण्यासाठी काही वेळ लागू शकतो. तपशिलांसाठी <xliff:g id="CARRIER_NAME">%1$s</xliff:g> शी संपर्क साधा."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> बद्दल आणखी"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> सुरू करू शकत नाही"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> सुरू करण्यासाठी, सर्वप्रथम सॅटेलाइट कनेक्शन बंद करा"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 2825bbf0789..8fc129cdc88 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Hantar dan terima mesej teks melalui satelit. Tidak disertakan dengan akaun anda."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Permesejan satelit, kesambungan satelit"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Perihal <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Anda boleh menghantar dan menerima mesej teks melalui satelit sebagai sebahagian daripada akaun <xliff:g id="CARRIER_NAME">%1$s</xliff:g> yang layak"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Pelan <xliff:g id="CARRIER_NAME">%1$s</xliff:g> anda"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Pemesejan disertakan dengan akaun anda"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Anda boleh menghantar dan menerima mesej teks melalui satelit dengan akaun <xliff:g id="CARRIER_NAME">%1$s</xliff:g> yang layak"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Akaun <xliff:g id="CARRIER_NAME">%1$s</xliff:g> anda"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Pemesejan satelit disertakan dengan akaun anda"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Pemesejan satelit tidak disertakan dengan akaun anda"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Ketahui Lebih Lanjut"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Cara ciri ini berfungsi"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Apabila liputan rangkaian mudah alih tiada"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Hantar teks kepada nombor telefon"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefon anda akan disambungkan secara automatik kepada satelit. Untuk mendapatkan sambungan terbaik, pastikan anda berada di kawasan dengan pandangan langit yang jelas."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Jika anda tiada rangkaian mudah alih, anda akan melihat pilihan untuk menggunakan permesejan satelit."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Selepas telefon anda disambungkan kepada satelit"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Ikut langkah penyambungan kepada satelit"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Anda boleh menghantar teks kepada sesiapa sahaja, termasuk perkhidmatan kecemasan. Telefon anda akan disambungkan semula kepada rangkaian mudah alih jika tersedia."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> mungkin mengambil masa lebih lama dan tersedia di beberapa kawasan sahaja. Cuaca dan struktur tertentu boleh menjejaskan sambungan satelit anda. Panggilan melalui satelit tidak tersedia. Panggilan kecemasan masih boleh disambungkan.\n\nPerubahan pada akaun mungkin memerlukan sedikit masa untuk dipaparkan dalam Tetapan. Hubungi <xliff:g id="CARRIER_NAME">%1$s</xliff:g> untuk mendapatkan butiran."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Selepas telefon anda disambungkan, anda boleh menghantar teks kepada sesiapa sahaja, termasuk perkhidmatan kecemasan."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Sambungan satelit mungkin lebih perlahan dan tersedia di sesetengah kawasan sahaja. Cuaca dan struktur tertentu boleh menjejaskan sambungan. Panggilan melalui satelit tidak tersedia. Panggilan kecemasan masih boleh disambungkan.\n\nPerubahan pada akaun mungkin memerlukan sedikit masa untuk dipaparkan dalam Tetapan. Hubungi <xliff:g id="CARRIER_NAME">%1$s</xliff:g> untuk mendapatkan butiran."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Maklumat lanjut tentang <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Tidak dapat menghidupkan <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Untuk menghidupkan <xliff:g id="FUNCTION">%1$s</xliff:g>, tamatkan sambungan satelit dahulu"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 01b59caef35..eb8e4b9d20f 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"ဂြိုဟ်တုဖြင့် မိုဘိုင်းမက်ဆေ့ဂျ် ပို့နိုင်၊ လက်ခံနိုင်သည်။ သင့်အကောင့်တွင် မပါဝင်ပါ။"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"ဂြိုဟ်တုမှတစ်ဆင့် မက်ဆေ့ဂျ်ပို့ခြင်း၊ ဂြိုဟ်တုချိတ်ဆက်နိုင်မှု"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> အကြောင်း"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"သတ်မှတ်ချက်ပြည့်မီသော <xliff:g id="CARRIER_NAME">%1$s</xliff:g> အကောင့် တစ်စိတ်တစ်ဒေသအဖြစ် သင်သည် ဂြိုဟ်တုဖြင့် မိုဘိုင်းမက်ဆေ့ဂျ် ပို့နိုင်၊ လက်ခံနိုင်သည်"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"သင့် <xliff:g id="CARRIER_NAME">%1$s</xliff:g> အစီအစဉ်"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"သင့်အကောင့်တွင် မက်ဆေ့ဂျ်ပို့ခြင်း ပါဝင်သည်"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"သတ်မှတ်ချက်ပြည့်မီသော <xliff:g id="CARRIER_NAME">%1$s</xliff:g> အကောင့်သုံး၍ ဂြိုဟ်တုဖြင့် မိုဘိုင်းမက်ဆေ့ဂျ်များ ပေးပို့လက်ခံနိုင်သည်"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"သင်၏ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> အကောင့်"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"ဂြိုဟ်တုမက်ဆေ့ဂျ်ပို့ခြင်းသည် သင့်အကောင့်တွင် ပါဝင်သည်"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"ဂြိုဟ်တုမက်ဆေ့ဂျ်ပို့ခြင်းသည် သင့်အကောင့်တွင် မပါဝင်ပါ"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"ပိုမိုလေ့လာရန်"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"အလုပ်လုပ်ပုံ"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"သင့်တွင် မိုဘိုင်းကွန်ရက် မရှိသောအခါ"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ဖုန်းနံပါတ်တစ်ခုသို့ စာတိုပေးပို့ခြင်း"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"သင့်ဖုန်းသည် ဂြိုဟ်တုနှင့် အလိုအလျောက်ချိတ်ဆက်မည်။ အကောင်းဆုံးချိတ်ဆက်မှုအတွက် ကောင်းကင်ကို ရှင်းလင်းစွာမြင်နိုင်အောင် ထားပါ။"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"သင့်တွင် မိုဘိုင်းကွန်ရက်မရှိပါက ဂြိုဟ်တုမှတစ်ဆင့် မက်ဆေ့ဂျ်ပို့ခြင်းကို သုံးရန် ရွေးစရာကို မြင်ရမည်။"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"သင့်ဖုန်းက ဂြိုဟ်တုနှင့် ချိတ်ဆက်ပြီးသည့်အခါ"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"ဂြိုဟ်တုနှင့် ချိတ်ဆက်ရန် အဆင့်များအတိုင်း လုပ်ဆောင်ပါ"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"အရေးပေါ်ဝန်ဆောင်မှု ဌာနများအပါအဝင် မည်သူ့ထံမဆို စာတိုပို့နိုင်သည်။ ရနိုင်သည့်အခါ သင့်ဖုန်းသည် မိုဘိုင်းကွန်ရက်နှင့် ပြန်ချိတ်ဆက်ပါမည်။"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> သည် အချိန်ပိုကြာနိုင်ပြီး ၎င်းကို နေရာအချို့တွင်သာ ရနိုင်သည်။ မိုးလေဝသအခြေအနေနှင့် အဆောက်အအုံအချို့သည် သင့်ဂြိုဟ်တုချိတ်ဆက်မှုအပေါ် သက်ရောက်နိုင်သည်။ ဂြိုဟ်တုဖြင့် ဖုန်းခေါ်ဆို၍ မရနိုင်ပါ။ အရေးပေါ်ဖုန်းခေါ်ခြင်းကို ချိတ်ဆက်နိုင်သေးသည်။\n\nဆက်တင်များတွင် အကောင့်ပြောင်းလဲမှုများကိုပြရန် အချိန်အနည်းငယ် ကြာနိုင်သည်။ အသေးစိတ်သိရှိရန် <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ကိုဆက်သွယ်ပါ။"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"သင့်ဖုန်းနှင့် ချိတ်ဆက်ပြီးပါက အရေးပေါ်ဝန်ဆောင်မှုများအပါအဝင် မည်သူမဆိုထံ စာတိုပေးပို့နိုင်ပါသည်။"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"ဂြိုဟ်တုချိတ်ဆက်မှုသည် နှေးကွေးနိုင်ပြီး ဒေသအချို့အတွက်သာ ရနိုင်သည်။ မိုးလေဝသအခြေအနေနှင့် အဆောက်အအုံအချို့သည် ချိတ်ဆက်မှုအပေါ် သက်ရောက်နိုင်သည်။ ဂြိုဟ်တုဖြင့် ဖုန်းခေါ်ဆို၍ မရနိုင်ပါ။ အရေးပေါ်ဖုန်းခေါ်ခြင်းကို ချိတ်ဆက်နိုင်သေးသည်။\n\nဆက်တင်များတွင် အကောင့်ပြောင်းလဲမှုများကိုပြရန် အချိန်အနည်းငယ် ကြာနိုင်သည်။ အသေးစိတ်သိရှိရန် <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ကို ဆက်သွယ်ပါ။"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> အကြောင်း ပိုမိုသိရှိရန်"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> ကို ဖွင့်၍မရပါ"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> ကို ဖွင့်ရန် ဂြိုဟ်တုချိတ်ဆက်မှုကို ဦးစွာအဆုံးသတ်ပါ"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index a3cab36ef8d..71e7ee62813 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Send og motta tekstmeldinger via satellitt. Ikke inkludert med kontoen din."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satellittmeldinger, satellittilkobling"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Om <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Du kan sende og motta tekstmeldinger via satellitt som en del av en kvalifisert <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-konto"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>-abonnementet ditt"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Meldinger er inkludert med kontoen din"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Du kan sende og motta tekstmeldinger via satellitt med en kvalifisert <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-konto"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>-kontoen din"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satellittmeldinger er inkludert med kontoen din"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satellittmeldinger er ikke inkludert med kontoen din"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Finn ut mer"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Slik fungerer det"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Når du ikke har et mobilnettverk"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Send en tekstmelding til et telefonnummer"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefonen kobles automatisk til en satellitt. Du får best tilkobling på steder med åpen himmel."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Hvis du ikke har mobilnettverk, ser du et alternativ for å bruke satellittmeldinger."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Når telefonen kobles til en satellitt"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Følg trinnene for å koble til satellitten"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Du kan sende melding til hvem som helst, inkludert nødtjenester. Telefonen kobles til et mobilnettverk igjen når det er tilgjengelig."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> kan ta lengre tid og er bare tilgjengelig i noen områder. Været og visse bygninger kan påvirke satellittilkoblingen. Anrop via satellitt er ikke tilgjengelig. Nødanrop kan fortsatt kobles til.\n\nDet kan ta litt tid før kontoendringer vises i innstillingene. Kontakt <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for å finne ut mer."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Når telefonen er tilkoblet, kan du sende melding til hvem som helst, inkludert nødtjenester."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"En satellittilkobling kan være tregere og er bare tilgjengelig i enkelte områder. Været og bestemte bygninger kan påvirke tilkoblingen. Anrop via satellitt er ikke tilgjengelig. Nødanrop kan fortsatt kobles til.\n\nDet kan ta litt tid før kontoendringer vises i innstillingene. Kontakt <xliff:g id="CARRIER_NAME">%1$s</xliff:g> for å finne ut mer."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Mer om <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Kan ikke slå på <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"For å slå på <xliff:g id="FUNCTION">%1$s</xliff:g>, avslutt først satellittilkoblingen"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 428e52f9dd0..5274276cb89 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -4875,17 +4875,20 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"स्याटलाइटमार्फत टेक्स्ट म्यासेजहरू पठाउनुहोस् र प्राप्त गर्नुहोस्। यो सुविधा तपाईंको खातामार्फत प्रयोग गर्न मिल्दैन।"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"स्याटलाइटमार्फत म्यासेज पठाउने सुविधा, स्याटलाइट कनेक्टिभिटी"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> का बारेमा"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"तपाईं योग्य <xliff:g id="CARRIER_NAME">%1$s</xliff:g> खाताका भागका रूपमा स्याटलाइटमार्फत टेक्स्ट म्यासेज पठाउन र प्राप्त गर्न सक्नुहुन्छ"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> सम्बन्धी योजना"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"म्यासेज पठाउने सुविधा तपाईंको खातामा समावेश गरिएको हुन्छ"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"तपाईं कुनै योग्य <xliff:g id="CARRIER_NAME">%1$s</xliff:g> खाता प्रयोग गरेर स्याटलाइटमार्फत टेक्स्ट म्यासेजहरू पठाउन तथा प्राप्त गर्न सक्नुहुन्छ"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"तपाईंको <xliff:g id="CARRIER_NAME">%1$s</xliff:g> खाता"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"स्याटलाइटमार्फत म्यासेज पठाउने सुविधा तपाईंको खातामा समावेश गरिएको हुन्छ"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"स्याटलाइटमार्फत म्यासेज पठाउने सुविधा तपाईंको खातामा समावेश गरिएको हुँदैन"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"थप जान्नुहोस्"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"यसले काम गर्ने तरिका"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"तपाईंको डिभाइसमा मोबाइल नेटवर्क उपलब्ध नभएका खण्डमा"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"टेक्स्ट म्यासेजमार्फत फोन नम्बर पठाउनुहोस्"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"तपाईंको फोन स्याटलाइटमा स्वतः कनेक्ट हुने छ। उत्कृष्ट कनेक्सन प्राप्त गर्न आफ्नो फोन आकाश राम्रोसँग देखिने ठाउँमा राखिराख्नुहोस्।"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"तपाईंको डिभाइसमा मोबाइल नेटवर्क नभएका खण्डमा तपाईं स्याटलाइटमार्फत म्यासेज पठाउने सुविधा प्रयोग गर्ने विकल्प देख्नु हुने छ।"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"तपाईंको फोन स्याटलाइटमा कनेक्ट भएपछि"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"स्याटलाइटमा कनेक्ट गर्न दिइएका चरणहरूको पालना गर्नुहोस्"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"तपाईं आपत्‌कालीन सेवालगायत सबै जनालाई टेक्स्ट म्यासेज पठाउन सक्नुहुन्छ। तपाईंको फोन मोबाइल नेटवर्क उपलब्ध भएका बेला उक्त नेटवर्कमा रिकनेक्ट हुने छ।"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> प्रयोग गर्दा सामान्यभन्दा बढी समय लाग्न सक्छ र यो सुविधा केही क्षेत्रहरूमा मात्र उपलब्ध छ। मौसम र निश्चित संरचनाहरूले स्याटलाइट कनेक्सनमा असर गर्न सक्छ। स्याटलाइटमार्फत कल गर्ने सुविधा उपलब्ध छैन। आपत्‌कालीन कल अझै पनि कनेक्ट हुन सक्छ।\n\nतपाईंको खातामा गरिएका परिवर्तनहरू सेटिङमा देखिन केही समय लाग्न सक्छ। यससम्बन्धी थप जानकारी प्राप्त गर्न <xliff:g id="CARRIER_NAME">%1$s</xliff:g> लाई सम्पर्क गर्नुहोस्।"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"तपाईंको फोन कनेक्ट भएपछि तपाईं आपत्कालीन सेवाका सबै जनालाई टेक्स्ट म्यासेज पठाउन सक्नुहुन्छ।"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> का बारेमा थप जानकारी"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> अन गर्न सकिँदैन"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> अन गर्न सर्वप्रथम स्याटलाइट कनेक्सन अन्त्य गर्नुहोस्।"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 665fcae22a8..e512e34093f 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Stuur en krijg tekstberichten per satelliet. Niet inbegrepen bij je account."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satellietberichten, satellietverbinding"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Over <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Je kunt tekstberichten via satelliet sturen en ontvangen als onderdeel van een geschikt <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-account"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Je <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-abonnement"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Berichten sturen is inbegrepen bij je account"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Je kunt tekstberichten via satelliet sturen en krijgen met een in aanmerking komend <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-account"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Je <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-account"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satellietberichten zijn inbegrepen bij je account"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satellietberichten zijn niet inbegrepen bij je account"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Meer informatie"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Hoe het werkt"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Als je geen mobiel netwerk hebt"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Tekstberichten sturen naar een telefoonnummer"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Je telefoon maakt automatisch verbinding met een satelliet. Voor de beste verbinding moet je vrij zicht op de lucht houden."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Als je geen mobiel netwerk hebt, zie je een optie om satellietberichten te gebruiken"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Nadat je telefoon verbinding maakt met een satelliet"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Volg de stappen om verbinding te maken met de satelliet"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Je kunt iedereen een tekstbericht sturen, ook hulpdiensten. Je telefoon maakt opnieuw verbinding met een mobiel netwerk zodra het beschikbaar is."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> kunnen langer duren en zijn alleen in bepaalde gebieden beschikbaar. Het weer en bepaalde constructies kunnen je satellietverbinding beïnvloeden. Bellen via satelliet is niet beschikbaar. Noodoproepen kunnen nog steeds worden verbonden.\n\nHet kan even duren voordat accountwijzigingen in Instellingen worden getoond. Neem voor informatie contact op met <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Nadat je telefoon verbinding heeft gemaakt, kun je iedereen een tekstbericht sturen, ook hulpdiensten."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Een satellietverbinding kan langzamer zijn en is alleen in bepaalde gebieden beschikbaar. Het weer en bepaalde constructies kunnen de verbinding beïnvloeden. Bellen via satelliet is niet beschikbaar. Noodoproepen kunnen nog steeds worden verbonden.\n\nHet kan even duren voordat accountwijzigingen in Instellingen worden getoond. Neem voor informatie contact op met <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Meer over <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Kan <xliff:g id="FUNCTION">%1$s</xliff:g> niet aanzetten"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Als je <xliff:g id="FUNCTION">%1$s</xliff:g> wilt aanzetten, verbreek je eerst de satellietverbinding"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index e9b5f1c2e5a..3f01b0d24b1 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -4876,17 +4876,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"ସେଟେଲାଇଟ ମାଧ୍ୟମରେ ଟେକ୍ସଟ ମେସେଜଗୁଡ଼ିକ ପଠାନ୍ତୁ ଏବଂ ପାଆନ୍ତୁ। ଆପଣଙ୍କ ଆକାଉଣ୍ଟ ସହ ଅନ୍ତର୍ଭୁକ୍ତ ନାହିଁ।"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"ସେଟେଲାଇଟ ମେସେଜିଂ, ସେଟେଲାଇଟ କନେକ୍ଟିଭିଟି"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> ବିଷୟରେ"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"ଆପଣ ଏକ ଯୋଗ୍ୟ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ଆକାଉଣ୍ଟର ଅଂଶ ଭାବରେ ସେଟେଲାଇଟ ମାଧ୍ୟମରେ ଟେକ୍ସଟ ମେସେଜ ପଠାଇପାରିବେ ଓ ପାଇପାରିବେ"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"ଆପଣଙ୍କ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ପ୍ଲାନ"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"ଆପଣଙ୍କ ଆକାଉଣ୍ଟରେ ମେସେଜିଂ ଅନ୍ତର୍ଭୁକ୍ତ"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"ଆପଣ ଏକ ଯୋଗ୍ୟ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ଆକାଉଣ୍ଟ ସହ ସେଟେଲାଇଟ ମାଧ୍ୟମରେ ଟେକ୍ସଟ ମେସେଜ ପଠାଇପାରିବେ ଏବଂ ପାଇପାରିବେ"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"ଆପଣଙ୍କ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ଆକାଉଣ୍ଟ"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"ଆପଣଙ୍କ ଆକାଉଣ୍ଟ ସହ ସେଟେଲାଇଟ ମେସେଜିଂ ଅନ୍ତର୍ଭୁକ୍ତ"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"ଆପଣଙ୍କ ଆକାଉଣ୍ଟ ସହ ସେଟେଲାଇଟ ମେସେଜିଂ ଅନ୍ତର୍ଭୁକ୍ତ ନୁହେଁ"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"ଅଧିକ ଜାଣନ୍ତୁ"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"ଏହା କିପରି କାମ କରେ"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"ଆପଣଙ୍କର ଏକ ମୋବାଇଲ ନେଟୱାର୍କ ନଥିବା ସମୟରେ"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ଏକ ଫୋନ ନମ୍ବରକୁ ଟେକ୍ସଟ ପଠାନ୍ତୁ"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"ଆପଣଙ୍କ ଫୋନ ଏକ ସେଟେଲାଇଟ ସହ ସ୍ୱତଃ-କନେକ୍ଟ ହେବ। ସର୍ବୋତ୍ତମ କନେକ୍ସନ ପାଇଁ ଆକାଶର ଏକ ସ୍ପଷ୍ଟ ଭ୍ୟୁ ରଖନ୍ତୁ।"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"ଯଦି ଆପଣଙ୍କର ଏକ ମୋବାଇଲ ନେଟୱାର୍କ ନାହିଁ, ତେବେ ସେଟେଲାଇଟ ମେସେଜିଂ ବ୍ୟବହାର କରିବାକୁ ଆପଣ ଏକ ବିକଳ୍ପ ଦେଖିବେ।"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"ଆପଣଙ୍କ ଫୋନ ଏକ ସେଟେଲାଇଟରେ କନେକ୍ଟ ହେବା ପରେ"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"ସେଟେଲାଇଟ ସହ କନେକ୍ଟ କରିବା ପାଇଁ ଷ୍ଟେପଗୁଡ଼ିକୁ ଫଲୋ କରନ୍ତୁ"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"ଜରୁରୀକାଳୀନ ସେବାଗୁଡ଼ିକ ସମେତ ଆପଣ ଯେ କୌଣସି ବ୍ୟକ୍ତିଙ୍କୁ ଟେକ୍ସଟ କରିପାରିବେ। ଉପଲବ୍ଧ ଥିଲେ ଆପଣଙ୍କ ଫୋନ ଏକ ମୋବାଇଲ ନେଟୱାର୍କ ସହ ପୁଣି କନେକ୍ଟ କରିବ।"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> ପାଇଁ ଅଧିକ ସମୟ ଲାଗିପାରେ ଏବଂ ଏହା କେବଳ କିଛି ଏରିଆରେ ଉପଲବ୍ଧ ଅଟେ। ପାଣିପାଗ ଏବଂ ନିର୍ଦ୍ଦିଷ୍ଟ ଷ୍ଟ୍ରକଚରଗୁଡ଼ିକ ଆପଣଙ୍କ ସେଟେଲାଇଟ କନେକ୍ସନକୁ ପ୍ରଭାବିତ କରିପାରେ। ସେଟେଲାଇଟ ମାଧ୍ୟମରେ କଲିଂ ଉପଲବ୍ଧ ନାହିଁ। ଜରୁରୀକାଳୀନ କଲଗୁଡ଼ିକ ଏବେ ବି କନେକ୍ଟ ହୋଇପାରେ।\n\nସେଟିଂସରେ ଆକାଉଣ୍ଟ ପରିବର୍ତ୍ତନଗୁଡ଼ିକ ଦେଖାଯିବା ପାଇଁ କିଛି ସମୟ ଲାଗିପାରେ। ବିବରଣୀ ପାଇଁ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ସହ କଣ୍ଟାକ୍ଟ କରନ୍ତୁ।"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"ଆପଣଙ୍କର ଫୋନ କନେକ୍ଟ ହେବା ପରେ, ଆପଣ ଜରୁରୀକାଳୀନ ସେବାଗୁଡ଼ିକ ସମେତ ଯେ କୌଣସି ବ୍ୟକ୍ତିଙ୍କୁ ଟେକ୍ସଟ କରିପାରିବେ।"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"ଏକ ସେଟେଲାଇଟ କନେକ୍ସନ ଧୀର ହୋଇପାରେ ଏବଂ କେବଳ କିଛି ଏରିଆରେ ଉପଲବ୍ଧ ଅଟେ। ପାଣିପାଗ ଏବଂ ନିର୍ଦ୍ଦିଷ୍ଟ ଷ୍ଟ୍ରକଚରଗୁଡ଼ିକ କନେକ୍ସନକୁ ପ୍ରଭାବିତ କରିପାରେ। ସେଟେଲାଇଟ ମାଧ୍ୟମରେ କଲିଂ ଉପଲବ୍ଧ ନାହିଁ। ଜରୁରୀକାଳୀନ କଲଗୁଡ଼ିକ ଏବେ ବି କନେକ୍ଟ ହୋଇପାରେ।\n\nସେଟିଂସରେ ଆକାଉଣ୍ଟ ପରିବର୍ତ୍ତନଗୁଡ଼ିକ ଦେଖାଯିବା ପାଇଁ କିଛି ସମୟ ଲାଗିପାରେ। ବିବରଣୀ ପାଇଁ <xliff:g id="CARRIER_NAME">%1$s</xliff:g>କୁ କଣ୍ଟାକ୍ଟ କରନ୍ତୁ।"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> ବିଷୟରେ ଅଧିକ ସୂଚନା"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g>କୁ ଚାଲୁ କରାଯାଇପାରିବ ନାହିଁ"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g>କୁ ଚାଲୁ କରିବା ପାଇଁ ପ୍ରଥମେ ସେଟେଲାଇଟ କନେକ୍ସନକୁ ସମାପ୍ତ କରନ୍ତୁ"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 804675f7b66..ce4f6f0f7b7 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"ਸੈਟੇਲਾਈਟ ਰਾਹੀਂ ਲਿਖਤ ਸੁਨੇਹੇ ਭੇਜੋ ਅਤੇ ਪ੍ਰਾਪਤ ਕਰੋ। ਤੁਹਾਡੇ ਖਾਤੇ ਨਾਲ ਇਸ ਸੁਵਿਧਾ ਦੀ ਵਰਤੋਂ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ।"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"ਸੈਟੇਲਾਈਟ ਸੁਨੇਹਾ, ਸੈਟੇਲਾਈਟ ਕਨੈਕਟੀਵਿਟੀ"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> ਬਾਰੇ"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"ਤੁਸੀਂ ਯੋਗ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ਖਾਤੇ ਦੇ ਹਿੱਸੇ ਵਜੋਂ ਸੈਟੇਲਾਈਟ ਰਾਹੀਂ ਲਿਖਤ ਸੁਨੇਹੇ ਭੇਜ ਅਤੇ ਪ੍ਰਾਪਤ ਕਰ ਸਕਦੇ ਹੋ"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"ਤੁਹਾਡਾ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ਪਲਾਨ"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"ਤੁਹਾਡੇ ਖਾਤੇ ਵਿੱਚ ਸੁਨੇਹੇ ਭੇਜਣ ਦੀ ਸੁਵਿਧਾ ਸ਼ਾਮਲ ਹੈ"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"ਤੁਸੀਂ ਯੋਗ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ਖਾਤੇ ਨਾਲ ਸੈਟੇਲਾਈਟ ਰਾਹੀਂ ਲਿਖਤ ਸੁਨੇਹੇ ਭੇਜ ਅਤੇ ਪ੍ਰਾਪਤ ਕਰ ਸਕਦੇ ਹੋ"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"ਤੁਹਾਡਾ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ਖਾਤਾ"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"ਸੈਟੇਲਾਈਟ ਸੁਨੇਹਾ ਸੇਵਾ ਤੁਹਾਡੇ ਖਾਤੇ ਵਿੱਚ ਸ਼ਾਮਲ ਹੈ"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"ਸੈਟੇਲਾਈਟ ਸੁਨੇਹਾ ਸੇਵਾ ਤੁਹਾਡੇ ਖਾਤੇ ਵਿੱਚ ਸ਼ਾਮਲ ਨਹੀਂ ਹੈ"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"ਹੋਰ ਜਾਣੋ"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"ਇਹ ਕਿਵੇਂ ਕੰਮ ਕਰਦਾ ਹੈ"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"ਤੁਹਾਡੇ ਕੋਲ ਮੋਬਾਈਲ ਨੈੱਟਵਰਕ ਨਾ ਹੋਣ \'ਤੇ"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ਫ਼ੋਨ ਨੰਬਰ \'ਤੇ ਲਿਖਤ ਸੁਨੇਹਾ ਭੇਜੋ"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"ਤੁਹਾਡਾ ਫ਼ੋਨ ਸੈਟੇਲਾਈਟ ਨਾਲ ਸਵੈ-ਕਨੈਕਟ ਹੋ ਜਾਵੇਗਾ। ਵਧੀਆ ਕੁਨੈਕਸ਼ਨ ਲਈ, ਅਸਮਾਨ ਦਾ ਸਾਫ਼ ਦ੍ਰਿਸ਼ ਨੂੰ ਬਰਕਰਾਰ ਰੱਖੋ।"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"ਜੇ ਤੁਹਾਡੇ ਕੋਲ ਮੋਬਾਈਲ ਨੈੱਟਵਰਕ ਨਹੀਂ ਹੈ, ਤਾਂ ਤੁਹਾਨੂੰ ਸੈਟੇਲਾਈਟ ਸੁਨੇਹੇ ਦੀ ਵਰਤੋਂ ਕਰਨ ਦਾ ਵਿਕਲਪ ਦਿਖਾਈ ਦੇਵੇਗਾ।"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"ਤੁਹਾਡਾ ਫ਼ੋਨ ਸੈਟੇਲਾਈਟ ਨਾਲ ਕਨੈਕਟ ਹੋ ਜਾਣ ਤੋਂ ਬਾਅਦ"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"ਸੈਟਾਲਾਈਟ ਨਾਲ ਕਨੈਕਟ ਕਰਨ ਲਈ ਪੜਾਵਾਂ ਦੀ ਪਾਲਣਾ ਕਰੋ"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"ਤੁਸੀਂ ਐਮਰਜੈਂਸੀ ਸੇਵਾਵਾਂ ਸਮੇਤ ਕਿਸੇ ਨੂੰ ਵੀ ਲਿਖਤ ਸੁਨੇਹਾ ਭੇਜ ਸਕਦੇ ਹੋ। ਉਪਲਬਧ ਹੋਣ \'ਤੇ ਤੁਹਾਡਾ ਫ਼ੋਨ ਮੋਬਾਈਲ ਨੈੱਟਵਰਕ ਨਾਲ ਮੁੜ-ਕਨੈਕਟ ਹੋ ਜਾਵੇਗਾ।"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> ਵਿੱਚ ਜ਼ਿਆਦਾ ਸਮਾਂ ਲੱਗ ਸਕਦਾ ਹੈ ਅਤੇ ਇਹ ਸਿਰਫ਼ ਕੁਝ ਖੇਤਰਾਂ ਵਿੱਚ ਉਪਲਬਧ ਹੈ। ਮੌਸਮ ਅਤੇ ਕੁਝ ਢਾਂਚੇ ਤੁਹਾਡੇ ਸੈਟੇਲਾਈਟ ਕਨੈਕਸ਼ਨ ਨੂੰ ਪ੍ਰਭਾਵਿਤ ਕਰ ਸਕਦੇ ਹਨ। ਸੈਟੇਲਾਈਟ ਰਾਹੀਂ ਕਾਲ ਕਰਨ ਦੀ ਸੁਵਿਧਾ ਉਪਲਬਧ ਨਹੀਂ ਹੈ। ਐਮਰਜੈਂਸੀ ਕਾਲਾਂ ਹਾਲੇ ਵੀ ਕਨੈਕਟ ਹੋ ਸਕਦੀਆਂ ਹਨ।\n\nਖਾਤਾ ਤਬਦੀਲੀਆਂ ਨੂੰ ਸੈਟਿੰਗਾਂ ਵਿੱਚ ਦਿਖਾਈ ਦੇਣ ਵਿੱਚ ਕੁਝ ਸਮਾਂ ਲੱਗ ਸਕਦਾ ਹੈ। ਵੇਰਵਿਆਂ ਲਈ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ਨੂੰ ਸੰਪਰਕ ਕਰੋ।"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"ਤੁਹਾਡਾ ਫ਼ੋਨ ਕਨੈਕਟ ਹੋ ਜਾਣ ਤੋਂ ਬਾਅਦ, ਤੁਸੀਂ ਐਮਰਜੈਂਸੀ ਸੇਵਾਵਾਂ ਸਮੇਤ ਕਿਸੇ ਨੂੰ ਵੀ ਲਿਖਤ ਸੁਨੇਹਾ ਭੇਜ ਸਕਦੇ ਹੋ।"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"ਸੈਟੇਲਾਈਟ ਕਨੈਕਸ਼ਨ ਹੌਲੀ ਹੋ ਸਕਦਾ ਹੈ ਅਤੇ ਸਿਰਫ਼ ਕੁਝ ਖੇਤਰਾਂ ਵਿੱਚ ਹੀ ਉਪਲਬਧ ਹੈ। ਮੌਸਮ ਅਤੇ ਕੁਝ ਢਾਂਚੇ ਕਨੈਕਸ਼ਨ ਨੂੰ ਪ੍ਰਭਾਵਿਤ ਕਰ ਸਕਦੇ ਹਨ। ਸੈਟੇਲਾਈਟ ਰਾਹੀਂ ਕਾਲ ਕਰਨ ਦੀ ਸੁਵਿਧਾ ਉਪਲਬਧ ਨਹੀਂ ਹੈ। ਐਮਰਜੈਂਸੀ ਕਾਲਾਂ ਹਾਲੇ ਵੀ ਕਨੈਕਟ ਹੋ ਸਕਦੀਆਂ ਹਨ।\n\nਖਾਤਾ ਤਬਦੀਲੀਆਂ ਨੂੰ ਸੈਟਿੰਗਾਂ ਵਿੱਚ ਦਿਖਾਈ ਦੇਣ ਵਿੱਚ ਕੁਝ ਸਮਾਂ ਲੱਗ ਸਕਦਾ ਹੈ। ਵੇਰਵਿਆਂ ਲਈ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ਨੂੰ ਸੰਪਰਕ ਕਰੋ।"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> ਬਾਰੇ ਹੋਰ ਜਾਣਕਾਰੀ"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> ਨੂੰ ਚਾਲੂ ਨਹੀਂ ਕੀਤਾ ਜਾ ਸਕਦਾ"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> ਨੂੰ ਚਾਲੂ ਕਰਨ ਲਈ, ਪਹਿਲਾਂ ਸੈਟੇਲਾਈਟ ਕਨੈਕਸ਼ਨ ਨੂੰ ਬੰਦ ਕਰੋ"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 84e8d3a9343..e8f469420bf 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Wysyłanie i odbieranie SMS-ów przez satelitę. Twoje konto tego nie obejmuje."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"przesyłanie wiadomości przez satelitę, łączność satelitarna"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> – informacje"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Możesz wymieniać wiadomości przez satelitę w ramach odpowiedniego konta u operatora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Twój abonament u operatora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Twoje konto obejmuje funkcję przesyłania wiadomości"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Możesz wymieniać wiadomości przez satelitę w ramach odpowiedniego konta u operatora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Twoje konto <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Twoje konto obejmuje funkcję przesyłania wiadomości przez satelitę"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Twoje konto nie obejmuje funkcji przesyłania wiadomości przez satelitę"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Więcej informacji"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Jak to działa"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Gdy nie masz połączenia z siecią komórkową"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Wyślij SMS-a pod numer telefonu"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Twój telefon automatycznie połączy się z satelitą. Aby uzyskać najlepszą jakość połączenia, stań w miejscu, w którym nic nie zasłania widoku nieba."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Jeśli jesteś poza zasięgiem sieci komórkowej, zobaczysz opcję przesyłania wiadomości przez satelitę."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Gdy Twój telefon połączy się z satelitą"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Postępuj zgodnie z instrukcjami, aby połączyć się z satelitą"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Możesz wysyłać SMS-y do dowolnego adresata, w tym również do służb ratunkowych. Twój telefon ponownie połączy się z siecią komórkową, gdy będzie ona dostępna."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> może zająć dłuższą chwilę. Funkcja jest dostępna wyłącznie na niektórych obszarach. Pogoda i inne czynniki mogą wpływać na Twoje połączenie satelitarne. Połączenia przez satelitę są niedostępne. Połączenia alarmowe mogą nadal być nawiązywane.\n\nMoże upłynąć trochę czasu, zanim zmiany dotyczące konta będą widoczne w Ustawieniach. Skontaktuj się z operatorem <xliff:g id="CARRIER_NAME">%1$s</xliff:g> i dowiedz się więcej."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Gdy telefon się połączy, będzie można wysyłać SMS-y do dowolnych odbiorców, w tym do służb ratunkowych."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Połączenie satelitarne może być wolniejsze i jest dostępne tylko w niektórych regionach. Pogoda i inne czynniki mogą wpływać na połączenie. Połączenia przez satelitę są niedostępne. Nadal można nawiązywać połączenia alarmowe.\n\nZmiany dotyczące konta mogą być widoczne w Ustawieniach dopiero po pewnym czasie. Aby uzyskać szczegółowe informacje, skontaktuj się z operatorem <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> – więcej informacji"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Nie można włączyć funkcji <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Aby włączyć funkcję <xliff:g id="FUNCTION">%1$s</xliff:g>, najpierw zakończ połączenie satelitarne"</string>
diff --git a/res/values-pt-rBR/strings.xml b/res/values-pt-rBR/strings.xml
index 45f3c1c3b92..3187a2791a7 100644
--- a/res/values-pt-rBR/strings.xml
+++ b/res/values-pt-rBR/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Enviar e receber mensagens de texto via satélite. Recurso não incluído na sua conta."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Mensagem via satélite, conectividade via satélite"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Sobre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"É possível enviar e receber mensagens de texto via satélite como parte de uma conta qualificada da operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Seu plano da operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"O serviço de mensagens está incluído na sua conta"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"É possível enviar e receber mensagens de texto via satélite com uma conta qualificada da operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Sua conta da <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Mensagens via satélite estão incluídas na sua conta"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Mensagens via satélite não estão incluídas na sua conta"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Saiba mais"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Como funciona"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Quando uma rede móvel não estiver disponível"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Enviar mensagem de texto para um número de telefone"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Seu smartphone vai se conectar automaticamente a um satélite. Para conseguir a melhor conexão, vá até um local com céu aberto."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Se você não tiver uma rede móvel, uma opção para usar a mensagem via satélite vai aparecer."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Depois que o smartphone se conectar a um satélite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Siga as etapas para se conectar ao satélite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"É possível enviar mensagens de texto para qualquer pessoa, inclusive para serviços de emergência. O smartphone vai se reconectar a uma rede móvel quando estiver disponível."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"A <xliff:g id="SUBJECT">%1$s</xliff:g> pode demorar mais e está disponível apenas em algumas áreas. O clima e determinadas estruturas podem afetar a conexão por satélite. A ligação via satélite não está disponível. Talvez chamadas de emergência ainda possam ser feitas.\n\nPode levar algum tempo para mudanças na conta aparecerem nas Configurações. Entre em contato com a <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para mais detalhes."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Depois que o smartphone estiver conectado, você poderá enviar mensagens de texto para qualquer pessoa, inclusive para serviços de emergência."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Uma conexão via satélite pode ser mais lenta e está disponível apenas em algumas áreas. O clima e determinadas estruturas podem afetar a conexão. A ligação via satélite não está disponível. Talvez chamadas de emergência ainda possam ser feitas.\n\nPode levar algum tempo para mudanças na conta aparecerem nas Configurações. Entre em contato com a <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para mais detalhes."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Mais informações sobre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Não é possível ativar o <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Para ativar o <xliff:g id="FUNCTION">%1$s</xliff:g>, primeiro encerre a conexão via satélite"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 345301c0123..ba8da7afa68 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Envie e receba mensagens de texto por satélite. Não está incluído na sua conta."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Mensagens por satélite, conetividade por satélite"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Acerca de <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Pode enviar e receber mensagens de texto por satélite através de uma conta elegível da operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"O seu plano da operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"As mensagens estão incluídas na sua conta"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Pode enviar e receber mensagens de texto por satélite com uma conta elegível da operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"A sua conta da operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"As mensagens por satélite estão incluídas na sua conta"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"As mensagens por satélite não estão incluídas na sua conta"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Saiba mais"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Como funciona"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Quando não tem ligação a uma rede móvel"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Envie uma mensagem de texto para um número de telefone"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"O seu telemóvel vai ligar-se automaticamente a um satélite. Para conseguir a melhor ligação, procure uma vista desimpedida para o céu."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Se não tiver uma rede móvel, é apresentada uma opção para usar as mensagens por satélite."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Depois de o seu telemóvel estabelecer ligação a um satélite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Siga os passos para estabelecer ligação ao satélite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Pode enviar mensagens de texto a qualquer pessoa, incluindo aos serviços de emergência. O seu telemóvel vai voltar a ligar-se a uma rede móvel quando esta estiver disponível."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"A funcionalidade <xliff:g id="SUBJECT">%1$s</xliff:g> pode demorar mais tempo e só está disponível em algumas áreas. As condições meteorológicas e determinadas estruturas podem afetar a sua ligação por satélite. As chamadas por satélite não estão disponíveis. Pode continuar a fazer chamadas de emergência.\n\nPode demorar algum tempo até que as alterações à conta sejam apresentadas nas Definições. Contacte a operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para mais detalhes."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Depois de o seu telemóvel estabelecer ligação, pode enviar mensagens de texto a qualquer pessoa, inclusive para os serviços de emergência."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Uma ligação por satélite pode ser mais lenta e só está disponível em algumas áreas. As condições meteorológicas e determinadas estruturas podem afetar a ligação. As chamadas por satélite não estão disponíveis. Pode continuar a fazer chamadas de emergência.\n\nPode demorar algum tempo até que as alterações à conta sejam apresentadas nas Definições. Contacte a operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para mais detalhes."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Mais acerca de <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Não é possível ativar a função <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Para ativar a função <xliff:g id="FUNCTION">%1$s</xliff:g>, termine primeiro a ligação por satélite"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 45f3c1c3b92..3187a2791a7 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Enviar e receber mensagens de texto via satélite. Recurso não incluído na sua conta."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Mensagem via satélite, conectividade via satélite"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Sobre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"É possível enviar e receber mensagens de texto via satélite como parte de uma conta qualificada da operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Seu plano da operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"O serviço de mensagens está incluído na sua conta"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"É possível enviar e receber mensagens de texto via satélite com uma conta qualificada da operadora <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Sua conta da <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Mensagens via satélite estão incluídas na sua conta"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Mensagens via satélite não estão incluídas na sua conta"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Saiba mais"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Como funciona"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Quando uma rede móvel não estiver disponível"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Enviar mensagem de texto para um número de telefone"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Seu smartphone vai se conectar automaticamente a um satélite. Para conseguir a melhor conexão, vá até um local com céu aberto."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Se você não tiver uma rede móvel, uma opção para usar a mensagem via satélite vai aparecer."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Depois que o smartphone se conectar a um satélite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Siga as etapas para se conectar ao satélite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"É possível enviar mensagens de texto para qualquer pessoa, inclusive para serviços de emergência. O smartphone vai se reconectar a uma rede móvel quando estiver disponível."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"A <xliff:g id="SUBJECT">%1$s</xliff:g> pode demorar mais e está disponível apenas em algumas áreas. O clima e determinadas estruturas podem afetar a conexão por satélite. A ligação via satélite não está disponível. Talvez chamadas de emergência ainda possam ser feitas.\n\nPode levar algum tempo para mudanças na conta aparecerem nas Configurações. Entre em contato com a <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para mais detalhes."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Depois que o smartphone estiver conectado, você poderá enviar mensagens de texto para qualquer pessoa, inclusive para serviços de emergência."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Uma conexão via satélite pode ser mais lenta e está disponível apenas em algumas áreas. O clima e determinadas estruturas podem afetar a conexão. A ligação via satélite não está disponível. Talvez chamadas de emergência ainda possam ser feitas.\n\nPode levar algum tempo para mudanças na conta aparecerem nas Configurações. Entre em contato com a <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para mais detalhes."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Mais informações sobre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Não é possível ativar o <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Para ativar o <xliff:g id="FUNCTION">%1$s</xliff:g>, primeiro encerre a conexão via satélite"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 6348ab79a75..06e6cbb095f 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Trimite și primește mesaje text prin satelit. Opțiunea nu este inclusă în contul tău."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Mesaje prin satelit, conectivitate prin satelit"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Despre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Dacă ai un cont <xliff:g id="CARRIER_NAME">%1$s</xliff:g> eligibil, poți să trimiți și să primești mesaje text prin satelit"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Planul tău <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Mesajele sunt incluse în contul tău"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Dacă ai un cont <xliff:g id="CARRIER_NAME">%1$s</xliff:g> eligibil, poți să trimiți și să primești mesaje text prin satelit"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Contul tău <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Mesajele prin satelit sunt incluse în contul tău"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Mesajele prin satelit nu sunt incluse în contul tău"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Află mai multe"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Cum funcționează"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Când nu este disponibilă o rețea mobilă"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Trimite un mesaj text către un număr de telefon"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefonul se va conecta automat la un satelit. Pentru o conexiune optimă, trebuie să vezi cerul clar."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Dacă nu ai o rețea mobilă, vei vedea opțiunea de a folosi mesajele prin satelit."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"După conectarea telefonului la un satelit"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Urmează pașii ca să te conectezi la satelit"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Poți să trimiți mesaje oricui, inclusiv serviciilor de urgență. Telefonul se va reconecta la o rețea mobilă când va fi disponibilă."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> poate dura mai mult și este disponibil doar în anumite zone. Condițiile meteo și anumite structuri pot afecta conexiunea prin satelit. Apelarea prin satelit nu este disponibilă. Este posibil ca apelurile de urgență să se conecteze în continuare.\n\nPoate dura un timp pentru ca modificările aduse contului să apară în Setări. Contactează <xliff:g id="CARRIER_NAME">%1$s</xliff:g> pentru detalii."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"După ce telefonul este conectat, poți să trimiți mesaje oricui, inclusiv serviciilor de urgență."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"O conexiune prin satelit poate fi mai lentă și este disponibilă doar în anumite zone. Condițiile meteo și anumite structuri pot afecta conexiunea. Apelarea prin satelit nu este disponibilă. Este posibil ca apelurile de urgență să se conecteze în continuare.\n\nPoate dura un timp pentru ca modificările aduse contului să apară în Setări. Contactează <xliff:g id="CARRIER_NAME">%1$s</xliff:g> pentru detalii."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Mai multe despre <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Nu se poate activa <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Ca să activezi <xliff:g id="FUNCTION">%1$s</xliff:g>, oprește conexiunea prin satelit"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 935a8e4cb9e..4dbbaccdd27 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Обмен текстовыми сообщениями по спутниковой связи. Недоступен для вашего аккаунта."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"спутниковый обмен сообщениями, обмен данными со спутником"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"О функции \"<xliff:g id="SUBJECT">%1$s</xliff:g>\""</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Ваш аккаунт оператора \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\" позволяет обмениваться текстовыми сообщениями по спутниковой связи."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Ваш тарифный план оператора \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\""</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"В вашем аккаунте есть возможность обмениваться сообщениями"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Вы можете обмениваться текстовыми сообщениями по спутниковой связи, используя отвечающий требованиям аккаунт <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Ваш аккаунт <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"В вашем аккаунте есть возможность обмениваться сообщениями по спутниковой связи"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"В вашем аккаунте нет возможности обмениваться сообщениями по спутниковой связи"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Подробнее"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Как это работает"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Если нет мобильной сети"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Отправляйте текстовые сообщения"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Ваш телефон автоматически подключится к спутниковой связи. Для оптимального качества соединения найдите место, где хорошо видно небо."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Если мобильная сеть не работает, появится предложение использовать спутниковый обмен сообщениями."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"После подключения телефона к спутниковой связи"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Подключитесь к спутнику, следуя инструкциям"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Вы можете отправлять текстовые сообщения кому угодно, в том числе экстренным службам. Ваш телефон повторно подключится к мобильной сети, когда она станет доступна."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> может занять больше времени и доступен только в некоторых регионах. На качество соединения могут влиять погода и внешние препятствия. Звонки по спутниковой связи недоступны (кроме экстренных).\n\nМожет пройти некоторое время, прежде чем изменения в вашем аккаунте появятся в настройках. За дополнительной информацией обратитесь к оператору \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\"."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"После подключения к спутнику вы сможете отправлять текстовые сообщения кому угодно, в том числе экстренным службам."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Спутниковое соединение может работать медленно и не во всех регионах. На его качество могут влиять погода и внешние препятствия. Звонки по спутниковой связи недоступны (кроме экстренных).\n\nМожет пройти некоторое время, прежде чем изменения в вашем аккаунте появятся в настройках. За дополнительной информацией обратитесь к оператору \"<xliff:g id="CARRIER_NAME">%1$s</xliff:g>\"."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g>: дополнительная информация"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Не удается включить функцию \"<xliff:g id="FUNCTION">%1$s</xliff:g>\""</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Чтобы включить функцию \"<xliff:g id="FUNCTION">%1$s</xliff:g>\", сначала отключите спутниковую связь."</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index aa3fe40d5ea..0cc1c86b967 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"චන්ද්‍රිකා මඟින් කෙටි පණිවුඩ යැවීම සහ ලබා ගැනීම. ඔබගේ ගිණුම සමග ඇතුළත් කර නැත."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"චන්ද්‍රිකා පණිවිඩ යැවීම, චන්ද්‍රිකා සබැඳුම් හැකියාව"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> ගැන"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"ඔබට සුදුසුකම් ලත් <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ගිණුමක කොටසක් ලෙස චන්ද්‍රිකා මඟින් කෙටි පණිවුඩ යැවීමට සහ ලැබීමට හැක"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"ඔබේ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> සැලැස්ම"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"ඔබේ ගිණුම සමග පණිවිඩ යැවීම ඇතුළත් වේ"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"සුදුසුකම් ලත් <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ගිණුමක් සමගින් ඔබට චන්ද්‍රිකා හරහා කෙටි පණිවිඩ යැවීමට සහ ලැබීමට හැක"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"ඔබේ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ගිණුම"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"ඔබේ ගිණුම සමග චන්ද්‍රිකා පණිවුඩ යැවීම ඇතුළත් වේ"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"ඔබේ ගිණුම සමග චන්ද්‍රිකා පණිවුඩ යැවීම ඇතුළත් නොවේ"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"තව දැන ගන්න"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"එය ක්‍රියා කරන ආකාරය"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"ඔබට ජංගම ජාලයක් නොමැති විට"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"දුරකථන අංකයක් කෙටි පණිවිඩයක් යවන්න"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"ඔබේ දුරකථනය චන්ද්‍රිකාවකට ස්වයංක්‍රීයව සම්බන්ධ වේ. හොඳම සම්බන්ධතාව සඳහා, අහසේ පැහැදිලි දර්ශනයක් තබා ගන්න."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"ඔබට ජංගම ජාලයක් නොමැති නම්, ඔබ චන්ද්‍රිකා පණිවිඩ යැවීම භාවිත කිරීමට විකල්පයක් දකියි."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"ඔබේ දුරකථනය චන්ද්‍රිකාවකට සම්බන්ධ වූ පසු"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"චන්‍ද්‍රිකාවට සම්බන්‍ධ කිරීමේ පියවර අනුගමන කරන්න"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"හදිසි සේවා ඇතුළුව ඔබට ඕනෑම කෙනෙකුට කෙටි පණිවුඩයක් යැවිය හැක. පවතින විට ඔබේ දුරකථනය ජංගම ජාලයකට නැවත සම්බන්ධ වේ."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> හට වැඩි කාලයක් ගත විය හැකි අතර සමහර ප්‍රදේශවල පමණක් ලබා ගත හැක. කාලගුණය සහ ඇතැම් ව්‍යුහයන් ඔබේ චන්ද්‍රිකා සම්බන්ධතාවයට බලපෑ හැක. චන්ද්‍රිකා මගින් ඇමතීම ලබා ගත නොහැක. හදිසි අවස්ථා ඇමතුම් තවමත් සම්බන්ධ විය හැක.\n\nගිණුම් වෙනස්කම් සැකසීම් තුළ පෙන්වීමට යම් කාලයක් ගත විය හැක. විස්තර සඳහා <xliff:g id="CARRIER_NAME">%1$s</xliff:g> සම්බන්ධ කර ගන්න."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"ඔබේ දුරකථනය සම්බන්ධ වූ පසු, ඔබට හදිසි සේවා ඇතුළු ඕනෑම කෙනෙකුට කෙටි පණිවිඩ යැවිය හැක."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"චන්ද්‍රිකා සම්බන්ධතාවයක් මන්දගාමී විය හැකි අතර සමහර ප්‍රදේශවල පමණක් ලබා ගත හැක. කාලගුණය සහ ඇතැම් ව්‍යුහ සම්බන්ධතාවයට බලපෑ හැක. චන්ද්‍රිකා මඟින් ඇමතීම ලබා ගත නොහැක. හදිසි අවස්ථා ඇමතුම් තවදුරටත් සම්බන්ධ විය හැක.\n\nගිණුම් වෙනස්කම් සැකසීම් තුළ පෙන්වීමට යම් කාලයක් ගත විය හැක. විස්තර සඳහා <xliff:g id="CARRIER_NAME">%1$s</xliff:g> අමතන්න."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> ගැන තවත්"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> ක්‍රියාත්මක කළ නොහැක"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> ක්‍රියාත්මක කිරීමට, පළමුව චන්ද්‍රිකා සම්බන්ධතාවය නිමා කරන්න"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index d3d19cbe66a..47d02b22bde 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Odosielajte a prijímajte textové správy cez satelit. Táto možnosť nie je vo vašom účte k dispozícii."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Správy cez satelit, pripojenie cez satelit"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Textová správy môžete odosielať a prijímať cez satelit, pretože váš účet <xliff:g id="CARRIER_NAME">%1$s</xliff:g> spĺňa podmienky."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Vaša tarifa <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Správy máte zahrnuté v rámci účtu"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Textové správy môžete odosielať a prijímať cez satelit s oprávneným účtom <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Váš účet <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Správy cez satelit sú zahrnuté vo vašom účte"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Správy cez satelit nie sú zahrnuté vo vašom účte"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Ďalšie informácie"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Ako to funguje"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Keď nemáte k dispozícii mobilnú sieť"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Odoslanie textovej správy na telefónne číslo"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Váš telefón sa automaticky pripojí k satelitu. V záujme čo najlepšieho pripojenia choďte na miesto, odkiaľ je dobrý výhľad na oblohu."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ak nemáte pripojenie k mobilnej sieti, zobrazí sa možnosť použiť správy cez satelit."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Keď sa váš telefón pripojí k satelitu"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Pripojte sa k satelitu podľa uvedených krokov"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Textové správy môžete posielať komukoľvek, aj tiesňovej linke. Keď bude k dispozícii mobilná sieť, váš telefón sa k nej znova pripojí."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> môžu trvať dlhšie a sú k dispozícii iba v niektorých oblastiach. Počasie a určité budovy môžu mať vplyv na pripojenie cez satelit. Volanie cez satelit nie je k dispozícii. Tiesňové volania môžu byť prepojené.\n\nMôže chvíľu trvať, kým sa zmeny účtu zobrazia v Nastaveniach. Podrobnejšie informácie vám poskytne <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Keď sa váš telefón pripojí, budete môcť posielať správy komukoľvek, aj tiesňovej linke."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Pripojenie cez satelit môže byť pomalšie a je k dispozícii iba v niektorých oblastiach. Na pripojenie môžu mať vplyv počasie a určité budovy. Volanie cez satelit nie je k dispozícii. Tiesňové volania môžu byť naďalej prepájané.\n\nMôže chvíľu trvať, kým sa zmeny účtu zobrazia v Nastaveniach. Viac informácií vám poskytne <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> – ďalšie informácie"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> sa nedá zapnúť"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Ak chcete zapnúť <xliff:g id="FUNCTION">%1$s</xliff:g>, zrušte pripojenie cez satelit"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index f0b78495799..3eea41c047e 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Pošiljanje in prejemanje sporočil po satelitski povezavi. Ni vključeno v vašem računu."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satelitska sporočila, povezljivost s sateliti"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"O <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Sporočila lahko pošiljate in prejemate po satelitski povezavi v sklopu ustreznega računa pri operaterju <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Vaš paket pri operaterju <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Sporočila so vključena v vašem računu"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Sporočila lahko pošiljate in prejemate prek satelita, če imate ustrezen račun pri operaterju <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Vaš račun pri operaterju <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satelitska sporočila so vključena v vašem računu"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satelitska sporočila niso vključena v vašem računu"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Več o tem"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Kako deluje"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Kadar mobilno omrežje ni na voljo"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Pošiljanje sporočila na telefonsko številko"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefon se bo samodejno povezal s satelitom. Za najboljšo povezavo zagotovite neoviran pogled v nebo."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Če nimate signala mobilnega omrežja, je prikazana možnost uporabe satelitskih sporočil."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Po vzpostavitvi povezave telefona s satelitom"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Uporabite postopek za povezavo s satelitom"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Sporočilo lahko pošljete vsakomur, tudi reševalnim službam. Telefon se bo znova povezal z mobilnim omrežjem, ko bo to na voljo."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Pri <xliff:g id="SUBJECT">%1$s</xliff:g> izmenjava sporočil morda traja dalj časa in je na voljo le na nekaterih območjih. Vreme in nekatere ovire lahko vplivajo na satelitsko povezavo. Klicanje po satelitski povezavi ni na voljo. Klici v sili bodo morda kljub temu izvedljivi.\n\nMorda bo trajalo nekaj časa, preden bodo spremembe računa prikazane v nastavitvah. Za podrobnosti se obrnite na operaterja <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Ko je telefon povezan, lahko sporočila pošiljate vsakomur, tudi reševalnim službam."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Satelitska povezava bo morda počasnejša in je na voljo le na nekaterih območjih. Vreme in nekatere ovire lahko vplivajo na povezavo. Klicanje po satelitski povezavi ni na voljo. Klici v sili bodo morda kljub temu izvedljivi.\n\nMorda bo trajalo nekaj časa, preden bodo spremembe računa prikazane v nastavitvah. Za podrobnosti se obrnite na operaterja <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Več o <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Funkcije <xliff:g id="FUNCTION">%1$s</xliff:g> ni mogoče vklopiti"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Če želite vklopiti funkcijo <xliff:g id="FUNCTION">%1$s</xliff:g>, najprej prekinite satelitsko povezavo"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index e82435457d0..02173b5c020 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -4875,17 +4875,20 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Dërgo dhe merr mesazhe me tekst nëpërmjet satelitit. Nuk përfshihet me llogarinë tënde."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Shkëmbimi i mesazheve nëpërmjet satelitit, lidhja satelitore"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Rreth <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Mund të dërgosh dhe të marrësh mesazhe me tekst nëpërmjet satelitit si pjesë e një llogarie të kualifikueshme të <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Plani yt i <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Mesazhet janë të përfshira me llogarinë tënde"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Mund të dërgosh dhe të marrësh mesazhe me tekst nëpërmjet satelitit me një llogari të kualifikueshme të <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Llogaria jote e <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Shkëmbimi i mesazheve nëpërmjet satelitit përfshihet me llogarinë tënde"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Shkëmbimi i mesazheve nëpërmjet satelitit nuk përfshihet me llogarinë tënde"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Mëso më shumë"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Si funksionon"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Kur nuk ke një rrjet celular"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Dërgoji mesazhi me tekst një numri telefoni"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefoni yt do të lidhet automatikisht me një satelit. Për lidhjen më të mirë, qëndro në pamje të pastër të qiellit."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Nëse nuk ke një rrjet celular, do të shikosh një opsion për të përdorur shkëmbimin e mesazheve nëpërmjet satelitit."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Pasi telefoni yt të lidhet me një satelit"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Ndiq hapat për t\'u lidhur me satelitin"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Mund t\'i dërgosh mesazh me tekst kujtdo, duke përfshirë shërbimet e urgjencës. Telefoni yt do të rilidhet me një rrjet celular kur disponohet."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> mund të kërkojë më shumë kohë dhe ofrohet vetëm në disa zona. Moti dhe disa struktura të caktuara mund të ndikojnë në lidhjen tënde satelitore. Telefonatat nëpërmjet satelitit nuk ofrohen. Telefonatat e urgjencës mund të lidhen përsëri.\n\nMund të duhet pak kohë që ndryshimet e llogarisë të shfaqen te \"Cilësimet\". Kontakto me <xliff:g id="CARRIER_NAME">%1$s</xliff:g> për detaje."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Pasi telefoni të jetë lidhur, mund t\'i dërgosh mesazh me tekst kujtdo, duke përfshirë shërbimet e urgjencës."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Më shumë rreth <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"\"<xliff:g id="FUNCTION">%1$s</xliff:g>\" nuk mund të aktivizohet"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Për të aktivizuar \"<xliff:g id="FUNCTION">%1$s</xliff:g>\", në fillim mbyll lidhjen satelitore"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 43dbb94fc2d..2e3334a4b3d 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Шаљите и примајте текстуалне поруке преко сателита. Није обухваћено налогом."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"размена порука преко сателита, сателитска веза"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Више информација о: <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Ако код мобилног оператера <xliff:g id="CARRIER_NAME">%1$s</xliff:g> имате налог који испуњава услове, можете да шаљете и примате текстуалне поруке преко сателита."</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Пакет код мобилног оператера <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Размена порука је обухваћена налогом"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Можете да шаљете и примате поруке преко сателита ако имате <xliff:g id="CARRIER_NAME">%1$s</xliff:g> налог који испуњава услове"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> налог"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Сателитска размена порука је обухваћена налогом"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Сателитска размена порука није обухваћена налогом"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Сазнајте више"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Принцип рада"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Кад немате приступ мобилној мрежи"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Пошаљите поруку на број телефона"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Телефон ће се аутоматски повезати на сателит. За најбољи квалитет везе, уверите се да вам ништа не заклања поглед на небо."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ако немате мобилну мрежу, видећете опцију да користите размену порука преко сателита."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Кад се телефон повеже на сателит"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Пратите кораке да бисте се повезали са сателитом"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Можете да шаљете поруке било коме, укључујући хитне службе. Телефон ће се поново повезати на мобилну мрежу када буде доступна."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> може да траје дуже и доступна је само у одређеним областима. Временски услови и одређене структуре могу да утичу на сателитску везу. Позивање путем сателита није доступно. Хитни позиви и даље могу да се обаве.\n\nМоже да прође неко време пре него што се промене налога прикажу у Подешавањима. Обратите се мобилном оператеру <xliff:g id="CARRIER_NAME">%1$s</xliff:g> за више детаља."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Када се телефон повеже, можете да шаљете поруке било коме, укључујући хитне службе."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Сателитска веза може да буде спорија и доступна је само у неким областима. Временски услови и одређене структуре могу да утичу на везу. Позивање путем сателита није доступно. Хитни позиви и даље могу да се обаве.\n\nМоже да прође неко време пре него што се промене налога прикажу у Подешавањима. Обратите се мобилном оператеру <xliff:g id="CARRIER_NAME">%1$s</xliff:g> за више детаља."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Више о: <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Не може да се укључи <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Да бисте укључили <xliff:g id="FUNCTION">%1$s</xliff:g>, прво завршите сателитску везу"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 0d4c358ec69..3cb665716ec 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Skicka och ta emot sms via satellit. Ingår inte i kontot."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satellitmeddelanden, satellitanslutning"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Om <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Att skicka och ta emot sms via satellit ingår i kvalificerade <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-konton"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Ditt <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-abonnemang"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Sms ingår i ditt konto"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Du kan skicka och ta emot sms via satellit med ett kvalificerat <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-konto"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Ditt <xliff:g id="CARRIER_NAME">%1$s</xliff:g>-konto"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Satellitmeddelanden ingår i kontot"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Satellitmeddelanden ingår inte i kontot"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Läs mer"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Så fungerar det"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"När du inte har ett mobilnätverk"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Skicka sms till ett telefonnummer"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefonen ansluter automatiskt till en satellit. Den bästa anslutningen får du utomhus under bar himmel."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Om du inte har ett mobilnätverk ser du alternativet att använda satellitmeddelanden."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"När telefonen ansluter till en satellit"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Följ stegen för att ansluta till satelliten"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Du kan sms:a vem som helst, inklusive räddningstjänsten. Telefonen återansluter till ett mobilnätverk när det finns ett tillgängligt."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> kan ta längre tid och är bara tillgängligt i vissa områden. Väder och vissa byggnader kan påverka din satellitanslutning. Du kan inte ringa samtal via satellit. Nödsamtal kanske fortfarande går fram.\n\nDet kan ta en stund innan kontoändringar dyker upp i inställningarna. Kontakta <xliff:g id="CARRIER_NAME">%1$s</xliff:g> för mer information."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"När telefonen är ansluten kan du sms:a vem som helst, inklusive räddningstjänsten."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"En satellitanslutning kan vara långsammare och är bara tillgänglig i vissa områden. Väder och vissa byggnader kan påverka anslutningen. Du kan inte ringa samtal via satellit. Nödsamtal kanske fortfarande går fram.\n\nDet kan ta en stund innan kontoändringar dyker upp i inställningarna. Kontakta <xliff:g id="CARRIER_NAME">%1$s</xliff:g> för mer information."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Mer om <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Det går inte att aktivera <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Om du vill aktivera <xliff:g id="FUNCTION">%1$s</xliff:g> avslutar du först satellitanslutningen"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 89e990aa41b..6139ef60aab 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Tuma na upokee ujumbe wa maandishi kupitia setilaiti. Haijajumuishwa kwenye akaunti yako."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Kutuma ujumbe kupitia setilaiti, muunganisho wa setilaiti"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Kuhusu <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Unaweza kutuma na kupokea ujumbe wa maandishi kupitia setilaiti kama sehemu ya akaunti inayotimiza masharti ya <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Mpango wako wa <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Huduma ya kutuma ujumbe imejumuishwa kwenye akaunti yako"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Unaweza kutuma na kupokea ujumbe wa maandishi kupitia setilaiti ukitumia akaunti ya <xliff:g id="CARRIER_NAME">%1$s</xliff:g> inayotimiza masharti"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Akaunti yako ya <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Huduma ya kutuma ujumbe kupitia setilaiti imejumuishwa kwenye akaunti yako"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Huduma ya kutuma ujumbe kupitia setilaiti haijajumuishwa kwenye akaunti yako"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Pata Maelezo Zaidi"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Utaratibu wake"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Ukiwa huna mtandao wa simu"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Tuma ujumbe kwa namba ya simu"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Simu yako itaunganisha kiotomatiki kwenye setilaiti. Kwa muunganisho bora, hakikisha anga inaonekana vizuri."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Ikiwa huna mtandao wa simu, utaona chaguo la kutumia kipengele cha kutuma ujumbe kupitia setilaiti."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Baada ya simu yako kuunganisha kwenye setilaiti"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Fuata hatua ili uunganishe kwenye setilaiti"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Unaweza kumtumia yeyote ujumbe, ikiwa ni pamoja na huduma za dharura. Simu yako itaunganisha tena kwenye mtandao wa simu ukipatikana."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Huduma ya <xliff:g id="SUBJECT">%1$s</xliff:g> inaweza kuchukua muda mrefu zaidi na inapatikana tu katika baadhi ya maeneo. Hali ya hewa na majengo fulani yanaweza kuathiri muunganisho wako wa setilaiti. Huduma ya kupiga simu kupitia setilaiti haipatikani. Simu za dharura bado zinaweza kuunganishwa.\n\nInaweza kuchukua muda kabla ya mabadiliko uliyofanya kwenye akaunti kuonekana katika Mipangilio. Wasiliana na <xliff:g id="CARRIER_NAME">%1$s</xliff:g> upate maelezo."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Simu yako ikishaunganishwa, unaweza kumtumia yeyote ujumbe, ikiwa ni pamoja na huduma za dharura."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Huenda muunganisho wa setilaiti ukawa hafifu na unapatikana katika baadhi ya maeneo pekee. Huenda hali ya hewa na majengo fulani yakaathiri muunganisho. Huduma ya kupiga simu kupitia setilaiti haipatikani. Simu za dharura bado zinaweza kuunganishwa.\n\nInaweza kuchukua muda kabla ya mabadiliko uliyofanya kwenye akaunti yaonekane katika Mipangilio. Wasiliana na <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ipi upate maelezo."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Maelezo zaidi kuhusu <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Imeshindwa kuwasha <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Ili uwashe <xliff:g id="FUNCTION">%1$s</xliff:g>, zima kwanza muunganisho wa setilaiti"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index e96e031e06c..64775cbb865 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"சாட்டிலைட் மூலம் மெசேஜ்களை அனுப்பலாம் பெறலாம். இந்தச் சேவை உங்கள் கணக்கிற்கு இல்லை."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"சாட்டிலைட் மெசேஜிங், சாட்டிலைட் இணைப்புநிலை"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> பற்றிய அறிமுகம்"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"தகுதியான <xliff:g id="CARRIER_NAME">%1$s</xliff:g> கணக்கின் ஒரு பகுதியாக நீங்கள் சாட்டிலைட் மூலம் மெசேஜ்களை அனுப்பலாம் பெறலாம்"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"உங்கள் <xliff:g id="CARRIER_NAME">%1$s</xliff:g> திட்டம்"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"உங்கள் கணக்கில் மெசேஜிங் அடங்கும்"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"தகுதிபெறும் <xliff:g id="CARRIER_NAME">%1$s</xliff:g> கணக்கைப் பயன்படுத்தி சாட்டிலைட் மூலம் நீங்கள் மெசேஜ் அனுப்பலாம் பெறலாம்"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"உங்கள் <xliff:g id="CARRIER_NAME">%1$s</xliff:g> கணக்கு"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"சாட்டிலைட் மெசேஜிங் உங்கள் கணக்கில் சேர்க்கப்பட்டுள்ளது"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"சாட்டிலைட் மெசேஜிங் உங்கள் கணக்கில் சேர்க்கப்படவில்லை"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"மேலும் அறிக"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"இது செயல்படும் விதம்"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"மொபைல் நெட்வொர்க் இல்லாதபோது"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ஒரு மொபைல் எண்ணுக்கு மெசேஜ் அனுப்புங்கள்"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"உங்கள் மொபைல் சாட்டிலைட்டுடன் தானாக இணைக்கப்படும். சிறந்த இணைப்பிற்கு வானம் தெளிவாகத் தெரியும் இடத்தில் வையுங்கள்."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"உங்களிடம் மொபைல் நெட்வொர்க் இல்லை என்றால், சாட்டிலைட் மெசேஜிங்கைப் பயன்படுத்துவதற்கான விருப்பத்தேர்வு காட்டப்படும்."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"சாட்டிலைட்டுடன் மொபைல் இணைக்கப்பட்ட பிறகு"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"சாட்டிலைட்டுடன் இணைப்பதற்கான படிகளைப் பின்பற்றுங்கள்"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"அவசரகாலச் சேவைகள் உட்பட எவருக்கும் நீங்கள் மெச்செஜ் அனுப்பலாம். மொபைல் நெட்வொர்க் கிடைக்கும்போது அதனுடன் உங்கள் மொபைல் மீண்டும் இணையும்."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> மூலம் மெசேஜ் அனுப்புவதற்கு அதிக நேரம் ஆகலாம். மேலும் சில பகுதிகளில் மட்டுமே இந்தச் சேவை கிடைக்கும். வானிலை மற்றும் சில கட்டமைப்புகள் உங்கள் சாட்டிலைட் இணைப்பைப் பாதிக்கக்கூடும். சாட்டிலைட் மூலம் அழைக்க முடியவில்லை. அவசர அழைப்புகளை இப்போதும் தொடர்புகொள்ளலாம்.\n\nஅமைப்புகளில் கணக்கு மாற்றங்கள் காட்டப்படுவதற்குச் சிறிது நேரம் ஆகலாம். விவரங்களுக்கு <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ஐத் தொடர்புகொள்ளுங்கள்."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"உங்கள் மொபைல் இணைக்கப்பட்டதும், அவசரகாலச் சேவைகள் உட்பட யாருக்கு வேண்டுமானாலும் நீங்கள் மெசேஜ் அனுப்பலாம்."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"சாட்டிலைட் இணைப்பு மிகவும் மெதுவாகவும் சில பகுதிகளில் மட்டுமே கிடைக்கக்கூடியதாகவும் இருக்கலாம். வானிலையும் சில கட்டமைப்புகளும் இணைப்பைப் பாதிக்கக்கூடும். சாட்டிலைட் மூலம் அழைக்க முடியவில்லை. அவசர அழைப்புகளை இப்போதும் தொடர்புகொள்ளலாம்.\n\nஅமைப்புகளில் கணக்கு மாற்றங்கள் காட்டப்படுவதற்குச் சிறிது நேரம் ஆகலாம். விவரங்களுக்கு <xliff:g id="CARRIER_NAME">%1$s</xliff:g> நிறுவனத்தைத் தொடர்புகொள்ளுங்கள்."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> குறித்த கூடுதல் தகவல்கள்"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> ஐ இயக்க முடியவில்லை"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> ஐ இயக்க, முதலில் சாட்டிலைட் இணைப்பை முடக்கவும்"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 1fb935ea019..dba7b626f51 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"శాటిలైట్ ద్వారా టెక్స్ట్ మెసేజ్‌లను పంపండి, పొందండి. మీ ఖాతాతో చేర్చలేదు."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"శాటిలైట్ మెసేజింగ్, శాటిలైట్ కనెక్టివిటీ"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> గురించి"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"మీరు అర్హత కలిగిన <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ఖాతాలో భాగంగా శాటిలైట్ ద్వారా టెక్స్ట్ మెసేజ్‌లను పంపవచ్చు, స్వీకరించవచ్చు"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"మీ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ప్లాన్"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"మీ ఖాతాతో మెసేజింగ్ చేర్చబడింది"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"అర్హత గల <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ఖాతాతో శాటిలైట్ సర్వీస్ ద్వారా మీరు టెక్స్ట్ మెసేజ్‌లను పంపవచ్చు, స్వీకరించవచ్చు"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"మీ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ఖాతా"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"మీ ఖాతాతో శాటిలైట్ మెసేజింగ్ చేర్చబడింది"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"మీ ఖాతాతో శాటిలైట్ మెసేజింగ్ చేర్చబడలేదు"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"మరింత తెలుసుకోండి"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"ఇది ఎలా పని చేస్తుంది"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"మీ మొబైల్‌లో నెట్‌వర్క్ లేనప్పుడు"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ఫోన్ నంబర్‌కు టెక్స్ట్ మెసేజ్ పంపండి"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"మీ ఫోన్ శాటిలైట్‌కు ఆటోమేటిక్‌గా కనెక్ట్ అవుతుంది. ఉత్తమ కనెక్షన్ కోసం, దయచేసి ఆకాశం స్పష్టంగా కనిపించే ప్రాంతంలో ఉంచండి."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"మీకు మొబైల్ నెట్‌వర్క్ లేకుంటే, శాటిలైట్ మెసేజింగ్‌ను ఉపయోగించే ఆప్షన్ కనిపిస్తుంది."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"మీ ఫోన్ శాటిలైట్‌కు కనెక్ట్ అయిన తర్వాత"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"శాటిలైట్‌కు కనెక్ట్ చేయడానికి దశలను ఫాలో అవ్వండి"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"మీరు ఎమర్జెన్సీ సర్వీసులతో సహా ఎవరికైనా టెక్స్ట్ మెసేజ్ పంపవచ్చు. అందుబాటులో ఉన్నప్పుడు మీ ఫోన్ మొబైల్ నెట్‌వర్క్‌కు మళ్లీ కనెక్ట్ అవుతుంది."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> కోసం ఎక్కువ సమయం పట్టవచ్చు, ఇది కొన్ని ప్రాంతాలలో మాత్రమే అందుబాటులో ఉంటుంది. వాతావరణం, నిర్దిష్ట నిర్మాణాలు మీ శాటిలైట్ కనెక్షన్‌ను ప్రభావితం చేయవచ్చు. శాటిలైట్ ద్వారా కాల్ చేయడం అందుబాటులో లేదు. శాటిలైట్ ద్వారా కాల్ చేయడం అందుబాటులో లేదు.\n\nఖాతా మార్పులు సెట్టింగ్‌లలో కనిపించడానికి కొంత సమయం పట్టవచ్చు. వివరాల కోసం <xliff:g id="CARRIER_NAME">%1$s</xliff:g>‌ను సంప్రదించండి."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"మీ ఫోన్ కనెక్ట్ అయిన తర్వాత, మీరు ఎమర్జెన్సీ సర్వీసులతో సహా ఎవరికైనా టెక్స్ట్ మెసేజ్ పంపవచ్చు."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"శాటిలైట్ కనెక్షన్ నెమ్మదిగా ఉండవచ్చు, ఇంకా కొన్ని ప్రాంతాల్లో మాత్రమే అందుబాటులో ఉండవచ్చు. వాతావరణం, నిర్దిష్ట నిర్మాణాలు కనెక్షన్‌ను ప్రభావితం చేయవచ్చు. శాటిలైట్ ద్వారా కాల్ చేయడం అందుబాటులో లేదు. ఎమర్జెన్సీ కాల్‌లు ఇప్పటికీ కనెక్ట్ చేయబడవచ్చు.\n\nఖాతా మార్పులు సెట్టింగ్‌లలో కనిపించడానికి కొంత సమయం పట్టవచ్చు. వివరాల కోసం <xliff:g id="CARRIER_NAME">%1$s</xliff:g>‌ను సంప్రదించండి."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> గురించి మరింత సమాచారం"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g>‌ను ఆన్ చేయడం సాధ్యపడలేదు"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g>‌ను ఆన్ చేయడానికి, ముందుగా శాటిలైట్ కనెక్షన్‌ను డిస్‌కనెక్ట్ చేయండి"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index d298a3af031..1833ff01158 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"รับส่งข้อความผ่านดาวเทียม ไม่รวมอยู่ในบัญชี"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"การรับส่งข้อความผ่านดาวเทียม การเชื่อมต่อผ่านดาวเทียม"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"เกี่ยวกับ <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"คุณรับส่งข้อความผ่านดาวเทียมได้โดยเป็นส่วนหนึ่งของบัญชี <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ที่มีสิทธิ์"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"แพ็กเกจ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ของคุณ"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"การรับส่งข้อความรวมอยู่ในบัญชีของคุณ"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"คุณรับส่ง SMS ผ่านดาวเทียมได้ด้วยบัญชี <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ที่มีสิทธิ์"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"บัญชี <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ของคุณ"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"การรับส่งข้อความผ่านดาวเทียมรวมอยู่ในบัญชีของคุณ"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"การรับส่งข้อความผ่านดาวเทียมไม่รวมอยู่ในบัญชีของคุณ"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"ดูข้อมูลเพิ่มเติม"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"วิธีการทำงาน"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"เมื่อคุณไม่มีเครือข่ายมือถือ"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"ส่งข้อความไปยังหมายเลขโทรศัพท์"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"โทรศัพท์ของคุณจะเชื่อมต่อกับดาวเทียมโดยอัตโนมัติ โปรดอยู่ในพื้นที่ที่มองเห็นท้องฟ้าได้อย่างชัดเจนเพื่อรับการเชื่อมต่อที่ดีที่สุด"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"หากไม่มีเครือข่ายมือถือ คุณจะเห็นตัวเลือกในการใช้การรับส่งข้อความผ่านดาวเทียม"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"หลังจากที่โทรศัพท์เชื่อมต่อกับดาวเทียม"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"ทำตามขั้นตอนเพื่อเชื่อมต่อกับดาวเทียม"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"คุณส่งข้อความถึงใครก็ได้ รวมถึงบริการช่วยเหลือฉุกเฉิน โดยโทรศัพท์จะเชื่อมต่อกับเครือข่ายมือถืออีกครั้งเมื่อมีให้ใช้งาน"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> อาจใช้เวลานานกว่าปกติและพร้อมให้ใช้งานเฉพาะในบางพื้นที่ โปรดทราบว่าสภาพอากาศและโครงสร้างบางอย่างอาจส่งผลต่อการติดต่อผ่านดาวเทียม การโทรผ่านดาวเทียมไม่พร้อมใช้งาน การโทรฉุกเฉินอาจยังเชื่อมต่ออยู่\n\nระบบอาจใช้เวลาสักครู่กว่าที่การเปลี่ยนแปลงในบัญชีจะแสดงในการตั้งค่า โปรดติดต่อ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> เพื่อสอบถามรายละเอียด"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"หลังจากเชื่อมต่อโทรศัพท์แล้ว คุณจะส่งข้อความถึงใครก็ได้ รวมถึงบริการช่วยเหลือฉุกเฉิน"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"การเชื่อมต่อผ่านดาวเทียมอาจช้ากว่าและพร้อมให้ใช้งานเฉพาะในบางพื้นที่ โปรดทราบว่าสภาพอากาศและโครงสร้างบางอย่างอาจส่งผลต่อการเชื่อมต่อ การโทรผ่านดาวเทียมไม่พร้อมใช้งาน การโทรฉุกเฉินอาจยังเชื่อมต่ออยู่\n\nระบบอาจใช้เวลาสักครู่กว่าที่การเปลี่ยนแปลงในบัญชีจะแสดงในการตั้งค่า โปรดติดต่อ <xliff:g id="CARRIER_NAME">%1$s</xliff:g> เพื่อสอบถามรายละเอียด"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"ข้อมูลเพิ่มเติมเกี่ยวกับ <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"เปิด <xliff:g id="FUNCTION">%1$s</xliff:g> ไม่ได้"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"หากต้องการเปิด <xliff:g id="FUNCTION">%1$s</xliff:g> ให้หยุดการเชื่อมต่อดาวเทียมก่อน"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 7254997623a..bc7336b0d9c 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Magpadala at makatanggap ng mga text message sa pamamagitan ng satellite. Hindi kasama sa iyong account."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Satellite messaging, koneksyon sa satellite"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Tungkol sa <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Puwede kang magpadala at makatanggap ng mga text message sa pamamagitan ng satellite bilang bahagi ng isang kwalipikadong <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Ang iyong plan sa <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Kasama sa iyong account ang pagmemensahe"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Puwede kang magpadala at makatanggap ng mga text message sa pamamagitan ng satellite gamit ang kwalipikadong <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Ang iyong <xliff:g id="CARRIER_NAME">%1$s</xliff:g> account"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Kasama ang satellite na pagmemensahe sa iyong account"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Hindi kasama ang satellite na pagmemensahe sa iyong account"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Matuto Pa"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Paano ito gumagana"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Kapag wala kang mobile network"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Mag-text ng numero ng telepono."</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Awomatikong kokonekta ang iyong telepono sa satellite. Para sa pinakamahusay na koneksyon, manatili sa kung saan may malinaw na view ng kalangitan."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Kung wala kang mobile network, may makikita kang opsyong gumamit ng satellite messaging."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Kapag nakakoenekta na ang iyong telepono sa satellite"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Sundin ang mga hakbang para kumonekta sa satellite"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Puwede kang mag-text sa kahit sino, kasama ang mga serbisyong pang-emergency. Kokonekta ulit ang iyong telepono sa mobile network kapag available."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"Posibleng mas matagal at available lang sa ilang lugar ang <xliff:g id="SUBJECT">%1$s</xliff:g>. Puwedeng makaapekto sa iyong koneksyon sa satellite ang lagay ng panahon at ilang partikular na istruktura. Hindi available ang pagtawag gamit ang satellite. Posibleng kumonekta pa rin ang mga emergency na tawag.\n\nPosibleng abutin nang ilang sandali bago lumabas ang mga pagbabago sa account sa Mga Setting. Makipag-ugnayan sa <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para sa mga detalye."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Kapag nakakonekta na ang iyong telepono, puwede kang mag-text sa kahit sino, kasama ang mga serbisyong pang-emergency."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Puwedeng mas mabagal ang koneksyon sa satellite at available lang ito sa ilang lugar. Puwedeng makaapekto sa koneksyon ang lagay ng panahon at ilang partikular na istruktura. Hindi available ang pagtawag gamit ang satellite. Posibleng kumonekta pa rin ang mga emergency na tawag.\n\nPosibleng abutin nang ilang sandali bago lumabas ang mga pagbabago sa account sa Mga Setting. Makipag-ugnayan sa <xliff:g id="CARRIER_NAME">%1$s</xliff:g> para sa mga detalye."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Higit pa tungkol sa <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Hindi ma-on ang <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Para i-on ang <xliff:g id="FUNCTION">%1$s</xliff:g>, wakasan muna ang koneksyon sa satellite"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 4a9e04b83d3..36065584187 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Uydu üzerinden kısa mesaj gönderip alın. Bu hizmet, hesabınızda sunulmaz."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Uydu üzerinden mesajlaşma, uydu bağlantısı"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> hakkında"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Uygun bir <xliff:g id="CARRIER_NAME">%1$s</xliff:g> hesabınız varsa uydu üzerinden kısa mesaj gönderip alabilirsiniz"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> planınız"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Hesabınızda uydu üzerinden mesajlaşılabilir"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Uygun bir <xliff:g id="CARRIER_NAME">%1$s</xliff:g> hesabınız varsa uydu üzerinden kısa mesaj gönderip alabilirsiniz"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> hesabınız"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Uydu üzerinden mesajlaşma, hesabınıza dahil edilir"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Uydu üzerinden mesajlaşma, hesabınıza dahil edilmez"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Daha Fazla Bilgi"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"İşleyiş şekli"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Mobil ağ bağlantınız olmadığında"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Telefon numarasına mesaj gönderin"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefonunuz otomatik olarak bir uyduya bağlanır. En iyi bağlantıyı kurmak için gökyüzünü net bir şekilde görmeniz gerekir."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Mobil ağınız yoksa uydu üzerinden mesajlaşma seçeneğini görürsünüz"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Telefonunuz bir uyduya bağlandıktan sonra"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Uyduya bağlanmayla ilgili adımları uygulayın"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Acil durum hizmetleri de dahil istediğiniz kişilere mesaj gönderebilirsiniz. Telefonunuz, mevcut olduğunda mobil ağa tekrar bağlanır."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> daha uzun sürebilir ve yalnızca bazı bölgelerde kullanılabilir. Uydu bağlantınız, hava durumundan ve bazı yapılardan etkilenebilir. Uydu üzerinden arama yapılamaz. Ancak, acil durum aramaları bağlanabilir.\n\nHesapta yapılan değişikliklerin, Ayarlar\'da görünmesi biraz zaman alabilir. Ayrıntılar için <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ile iletişime geçin."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Telefonunuz bağlandıktan sonra acil durum hizmetleri de dahil istediğiniz kişilere mesaj gönderebilirsiniz."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Uydu bağlantısı daha yavaş olabilir ve yalnızca bazı bölgelerde kullanılabilir. Hava durumu ve bazı yapılar bağlantıyı etkileyebilir. Uydu üzerinden arama yapılamaz. Ancak, acil durum aramaları bağlanabilir.\n\nHesapta yapılan değişikliklerin, Ayarlar\'da görünmesi biraz zaman alabilir. Ayrıntılar İçin <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ile iletişime geçin."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> hakkında daha fazla bilgi"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> etkinleştirilemiyor"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> işlevini etkinleştirmek için önce uydu bağlantısını sonlandırın"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index ad4cb110cf2..1c022972ce7 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Обмінюйтеся текстовими повідомленнями через супутник. Цю функцію не включено у ваш обліковий запис."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Супутниковий обмін повідомленнями, супутниковий зв’язок"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Про <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"За допомогою відповідного облікового запису <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ви можете обмінюватися текстовими повідомленнями через супутник"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Ваш план оператора <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Послугу обміну повідомленнями включено у ваш обліковий запис"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"За допомогою відповідного облікового запису <xliff:g id="CARRIER_NAME">%1$s</xliff:g> ви можете обмінюватися текстовими повідомленнями через супутник"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Ваш обліковий запис <xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Послугу обміну повідомленнями через супутник включено у ваш обліковий запис"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Послугу обміну повідомленнями через супутник не включено у ваш обліковий запис"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Докладніше"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Як це працює"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Коли мобільна мережа недоступна"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Надішліть текстове повідомлення на номер телефону"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Ваш телефон автоматично підключатиметься до супутника. Для кращого зв’язку вийдіть на відкрите місце (без накриття)."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Якщо мобільна мережа недоступна, ви можете скористатися супутниковим обміном повідомленнями."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Коли телефон підключиться до супутника"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Підключіться до супутника, дотримуючись вказівок"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Ви можете надсилати текстові повідомлення будь-кому, зокрема службам екстреної допомоги. Телефон знову підключиться до мобільної мережі, коли вона стане доступною."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> може тривати довше, і ця функція доступна лише в деяких регіонах. На з’єднання із супутником можуть впливати погодні умови й деякі будівлі. Дзвінки через супутник недоступні. Можуть підтримуватися екстрені виклики.\n\nПотрібен деякий час, щоб зміни у вашому обліковому записі відобразилися в налаштуваннях. Щоб дізнатися більше, зверніться до оператора <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Коли телефон підключиться, ви зможете надсилати текстові повідомлення будь-кому, зокрема службам екстреної допомоги."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Супутниковий зв’язок може бути повільнішим, і він доступний лише в деяких регіонах. На з’єднання можуть впливати погодні умови й деякі будівлі. Дзвінки через супутник недоступні. Можуть підтримуватися екстрені виклики.\n\nПотрібен деякий час, щоб зміни у вашому обліковому записі відобразилися в налаштуваннях. Щоб дізнатися більше, зверніться до оператора <xliff:g id="CARRIER_NAME">%1$s</xliff:g>."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Докладніше про <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Не вдається ввімкнути <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Щоб увімкнути <xliff:g id="FUNCTION">%1$s</xliff:g>, спершу відключіть супутниковий зв’язок"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 89fbf9d0c27..358512aaebf 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"سیٹلائٹ کے ذریعے ٹیکسٹ پیغامات بھیجیں اور موصول کریں۔ آپ کے اکاؤنٹ میں شامل نہیں ہے۔"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"سیٹلائٹ پیغام رسانی، سیٹلائٹ کنیکٹیوٹی"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"‫<xliff:g id="SUBJECT">%1$s</xliff:g> کے بارے میں"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"آپ ایک اہل <xliff:g id="CARRIER_NAME">%1$s</xliff:g> اکاؤنٹ کے حصے کے طور پر سیٹلائٹ کے ذریعے ٹیکسٹ پیغامات بھیج اور موصول کر سکتے ہیں۔"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"آپ کا <xliff:g id="CARRIER_NAME">%1$s</xliff:g> پلان"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"پیغام رسانی آپ کے اکاؤنٹ میں شامل ہے"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"آپ ایک اہل <xliff:g id="CARRIER_NAME">%1$s</xliff:g> اکاؤنٹ کے ساتھ سیٹلائٹ کے ذریعے ٹیکسٹ پیغامات بھیج اور موصول کر سکتے ہیں"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"آپ کا <xliff:g id="CARRIER_NAME">%1$s</xliff:g> اکاؤنٹ"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"سیٹلائٹ پیغام رسانی آپ کے اکاؤنٹ کے ساتھ شامل ہے"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"سیٹلائٹ پیغام رسانی آپ کے اکاؤنٹ میں شامل نہیں ہے"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"مزید جانیں"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"اس کے کام کرنے کا طریقہ"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"آپ کے پاس موبائل نیٹ ورک نہ ہونے پر"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"فون نمبر پر ٹیکسٹ پیغام بھیجیں"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"آپ کا فون سیٹلائٹ سے خودکار طور پر منسلک ہو جائے گا۔ بہترین کنکشن کے لیے، ایسی جگہ رہیں جہاں آسمان صاف نظر آ رہا ہو۔"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"اگر آپ کے پاس موبائل نیٹ ورک نہیں ہے تو آپ کو سیٹلائٹ پیغام رسانی خصوصیت استعمال کرنے کا اختیار نظر آئے گا۔"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"آپ کا فون سیٹلائٹ سے منسلک ہونے کے بعد"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"سیٹلائٹ سے منسلک کرنے کے لیے اقدامات پر عمل کریں"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"آپ ایمرجنسی سروسز سمیت کسی کو بھی ٹیکسٹ پیغام بھیج سکتے ہیں۔ دستیاب ہونے پر آپ کا فون موبائل نیٹ ورک سے دوبارہ منسلک ہو جائے گا۔"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"‫<xliff:g id="SUBJECT">%1$s</xliff:g> میں زیادہ وقت لگ سکتا ہے اور یہ صرف کچھ علاقوں میں دستیاب ہے۔ موسم اور کچھ ساختیں آپ کے سیٹلائٹ کنکشن کو متاثر کر سکتی ہیں۔ سیٹلائٹ کالنگ دستیاب نہیں ہے۔ ایمرجنسی کالز اب بھی منسلک ہو سکتی ہیں۔\n\nاکاؤنٹ کی تبدیلیوں کو ترتیبات میں ظاہر ہونے میں کچھ وقت لگ سکتا ہے۔ تفصیلات کے لیے <xliff:g id="CARRIER_NAME">%1$s</xliff:g> سے رابطہ کریں۔"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"آپ کا فون منسلک ہونے کے بعد، آپ ایمرجنسی سروسز سمیت کسی کو بھی ٹیکسٹ پیغام بھیج سکتے ہیں۔"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"سیٹیلائٹ کنکشن سست ہو سکتا ہے اور ممکن ہے کہ کچھ ہی علاقوں میں دستیاب ہو۔ موسم اور کچھ ساختیں کنکشن کو متاثر کر سکتی ہیں۔ سیٹلائٹ کالنگ دستیاب نہیں ہے۔ ایمرجنسی کالز اب بھی منسلک ہو سکتی ہیں۔\n\nاکاؤنٹ کی تبدیلیوں کو ترتیبات میں ظاہر ہونے میں کچھ وقت لگ سکتا ہے۔ تفصیلات کے لیے <xliff:g id="CARRIER_NAME">%1$s</xliff:g> سے رابطہ کریں۔"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"‫<xliff:g id="SUBJECT">%1$s</xliff:g> کے بارے میں مزید"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> آن نہیں ہو سکتا"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> آن کرنے کے لیے، پہلے سیٹلائٹ کنکشن ختم کریں"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 8ffe008ee3b..bfc28a811cd 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Sputnik orqali matnli xabar yuborish va qabul qilish. Hisobingizda mavjud emas."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"sunʼiy yoʻldosh orqali xabarlashuv, sunʼiy yoʻldosh aloqasi"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"<xliff:g id="SUBJECT">%1$s</xliff:g> haqida"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Mos <xliff:g id="CARRIER_NAME">%1$s</xliff:g> hisobining bir qismi sifatida sputnik orqali matnli xabarlarni yuborishingiz va qabul qilishingiz mumkin"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> tarif rejangiz"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Xabarlashish hisobingizga kiritilgan"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Mos <xliff:g id="CARRIER_NAME">%1$s</xliff:g> hisobi bilan sputnik orqali SMS yuborishingiz va qabul qilishingiz mumkin"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> hisobingiz"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Sputnik orqali xabarlashuv hisobingizga kiritilgan"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Sputnik orqali xabarlashuv hisobingizga kiritilmagan"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Batafsil"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Ishlash tartibi"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Mobil tarmoq mavjud boʻlmaganda"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Telefon raqamiga xabar yuborish"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Telefoningiz sputnikka avtomatik ulanadi. Yaxshiroq aloqa uchun ochiq osmon ostida turing."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Mobil tarmoq mavjud boʻlmasa, sputnik orqali xabarlashuv bandi chiqadi."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Telefoningiz spurtnikka ulangandan keyin"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Sputnikka ulanish uchun quyidagi amallarni bajaring"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Istalgan kishiga, shuningdek, favqulodda xizmatlarga ham xabar yubora olasiz. Telefoningiz mobil tarmoq ishlashi bilan unga ulanadi."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> uzoqroq vaqt olishi mumkin va faqat ayrim hududlarda ishlaydi. Ob-havo va ayrim tuzilmalar sputnik ulanishiga taʼsir qilishi mumkin. Sputnik orqali chaqiruv mavjud emas. Favqulodda chaqiruvlar hali ham ulanishi mumkin.\n\nHisob oʻzgarishlari Sozlamalarda chiqishi uchun biroz vaqt ketishi mumkin. Tafsilotlar uchun <xliff:g id="CARRIER_NAME">%1$s</xliff:g> bilan bogʻlaning."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Telefoningiz ulangach, istalgan kishiga, jumladan, favqulodda xizmatlarga ham xabar yubora olasiz."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Sputnik aloqasi sekinroq yoki faqat ayrim hududlarda mavjud boʻlishi mumkin. Ob-havo va ayrim tuzilmalar ulanishga taʼsir qilishi mumkin. Sputnik orqali chaqiruv mavjud emas. Favqulodda chaqiruvlar hali ham ulanishi mumkin.\n\nHisob oʻzgarishlari Sozlamalarda chiqishi uchun biroz vaqt ketishi mumkin. Tafsilotlar uchun <xliff:g id="CARRIER_NAME">%1$s</xliff:g> bilan bogʻlaning."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"<xliff:g id="SUBJECT">%1$s</xliff:g> haqida batafsil"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"<xliff:g id="FUNCTION">%1$s</xliff:g> yoqilmadi"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"<xliff:g id="FUNCTION">%1$s</xliff:g> yoqish uchun avval sputnik aloqasini uzing"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 7c6e8dfee86..379d4afebaf 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Gửi và nhận tin nhắn văn bản qua vệ tinh. Dịch vụ này không đi kèm với tài khoản của bạn."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Nhắn tin qua vệ tinh, kết nối vệ tinh"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Khoảng <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Bạn có thể gửi và nhận tin nhắn văn bản qua vệ tinh. Đây là một trong những tính năng của tài khoản <xliff:g id="CARRIER_NAME">%1$s</xliff:g> đủ điều kiện"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Gói <xliff:g id="CARRIER_NAME">%1$s</xliff:g> của bạn"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Tài khoản của bạn có quyền dùng dịch vụ nhắn tin"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Bạn có thể gửi và nhận tin nhắn văn bản qua vệ tinh bằng một tài khoản <xliff:g id="CARRIER_NAME">%1$s</xliff:g> đủ điều kiện"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"Tài khoản <xliff:g id="CARRIER_NAME">%1$s</xliff:g> của bạn"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Tính năng Nhắn tin qua vệ tinh có sẵn trong tài khoản của bạn"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Tính năng Nhắn tin qua vệ tinh không có sẵn trong tài khoản của bạn"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Tìm hiểu thêm"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Cách hoạt động"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Khi bạn không có mạng di động"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Gửi tin nhắn đến số điện thoại"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Điện thoại của bạn sẽ tự động kết nối với vệ tinh. Để có kết nối chất lượng tốt nhất, hãy tìm đến nơi có thể nhìn rõ bầu trời."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Nếu không có mạng di động, bạn sẽ thấy lựa chọn sử dụng tính năng nhắn tin qua vệ tinh."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Sau khi điện thoại của bạn kết nối với vệ tinh"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Làm theo các bước để kết nối với vệ tinh"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Bạn có thể gửi tin nhắn văn bản cho bất cứ ai, gồm cả các dịch vụ khẩn cấp. Điện thoại của bạn sẽ kết nối lại với mạng di động khi có mạng."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g> có thể mất nhiều thời gian hơn và chỉ dùng được ở một số khu vực. Thời tiết và một số công trình có thể ảnh hưởng đến kết nối vệ tinh của bạn. Không dùng được tính năng gọi điện qua vệ tinh. Cuộc gọi khẩn cấp có thể vẫn kết nối được.\n\nCó thể mất một chút thời gian để các thay đổi đối với tài khoản xuất hiện trong phần Cài đặt. Hãy liên hệ với <xliff:g id="CARRIER_NAME">%1$s</xliff:g> để biết thông tin chi tiết."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Sau khi điện thoại kết nối, bạn có thể nhắn tin cho bất cứ ai, kể cả các dịch vụ khẩn cấp."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Kết nối vệ tinh có thể chậm hơn và chỉ dùng được ở một số khu vực. Thời tiết và một số công trình có thể ảnh hưởng đến kết nối. Không dùng được tính năng gọi điện qua vệ tinh. Cuộc gọi khẩn cấp có thể vẫn kết nối được.\n\nCó thể mất một chút thời gian để các thay đổi đối với tài khoản xuất hiện trong phần Cài đặt. Hãy liên hệ với <xliff:g id="CARRIER_NAME">%1$s</xliff:g> để biết thông tin chi tiết."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Xem thêm thông tin về <xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Không bật được <xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Để bật <xliff:g id="FUNCTION">%1$s</xliff:g>, trước tiên hãy ngắt kết nối vệ tinh"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 0264ca1ea28..fef1ffd0025 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"通过卫星收发短信。您的账号不支持此功能。"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"卫星消息, 卫星连接, Satellite messaging, satellite connectivity"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"关于<xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"您可以使用符合条件的<xliff:g id="CARRIER_NAME">%1$s</xliff:g>账号通过卫星收发短信。"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"您的<xliff:g id="CARRIER_NAME">%1$s</xliff:g>套餐"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"您的账号支持消息功能"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"您可以使用符合条件的<xliff:g id="CARRIER_NAME">%1$s</xliff:g>账号通过卫星收发短信"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"您的<xliff:g id="CARRIER_NAME">%1$s</xliff:g>账号"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"您的账号支持卫星消息功能"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"您的账号不支持卫星消息功能"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"了解详情"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"运作方式"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"当您没有移动网络时"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"向某个电话号码发送短信"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"您的手机会自动连接到卫星。为获得最佳连接质量，请确保您身在能清楚看到天空的场所。"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"如果没有移动网络，您将看到使用卫星消息的选项。"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"当您的手机连接到卫星后"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"按照步骤连接到卫星"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"您可以给任何对象发短信，包括应急服务机构。当有可用的移动网络时，您的手机将重新连接到移动网络。"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g>可能需要较长时间才会送达，而且此功能目前仅覆盖部分地区。天气和某些建筑物可能会影响卫星连接质量。不支持卫星通话。但紧急呼叫有可能连通。\n\n账号更改可能要过一段时间才能显示在“设置”中。详情请联系<xliff:g id="CARRIER_NAME">%1$s</xliff:g>查询。"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"手机连接后，您可以给任何对象发短信，包括应急服务机构。"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"卫星连接速度可能较慢，而且此功能目前仅覆盖部分地区。天气和某些建筑物可能会影响连接质量。不支持卫星通话。紧急呼叫或许仍可连通。\n\n账号更改可能要过一段时间才能显示在“设置”中。详情请联系<xliff:g id="CARRIER_NAME">%1$s</xliff:g>查询。"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"关于<xliff:g id="SUBJECT">%1$s</xliff:g>的更多信息"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"无法开启<xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"若要开启<xliff:g id="FUNCTION">%1$s</xliff:g>，请先断开卫星连接"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index aa74490764f..9d2aaf694cf 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"透過衛星收發短訊。你的帳戶不支援此功能。"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"衛星訊息、衛星連接"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"關於「<xliff:g id="SUBJECT">%1$s</xliff:g>」"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"合資格的 <xliff:g id="CARRIER_NAME">%1$s</xliff:g> 帳戶支援透過衛星收發訊息"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"你的 <xliff:g id="CARRIER_NAME">%1$s</xliff:g> 計劃"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"你的帳戶支援衛星訊息"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"你可使用合資格的 <xliff:g id="CARRIER_NAME">%1$s</xliff:g> 帳戶透過衛星收發短訊"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"你的 <xliff:g id="CARRIER_NAME">%1$s</xliff:g> 帳戶"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"你的帳戶支援衛星訊息"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"你的帳戶不支援衛星訊息"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"瞭解詳情"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"運作方式"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"沒有流動網絡時"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"向電話號碼發短訊"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"手機將自動連接衛星。在清楚看到天空的的地方可獲得最佳連線。"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"如果沒有流動網絡，你會看到使用衛星訊息的選項。"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"手機連接衛星後"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"按照以下步驟連線至衛星"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"你可發短訊給任何人，包括緊急服務。如果有可用的流動網絡，手機就會重新連線。"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"「<xliff:g id="SUBJECT">%1$s</xliff:g>」可能需要比較長的時間才會送達，而且此功能只支援部分地區。天氣和特定結構可能會影響衛星連線。系統不支援衛星電話，但緊急電話或仍能接通。\n\n「設定」頁面可能要一段時間後才會顯示帳戶變動，請聯絡 <xliff:g id="CARRIER_NAME">%1$s</xliff:g> 查詢詳情。"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"手機連線後，你便可發短訊給任何人，包括緊急服務。"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"衛星連線可能較慢，此功能只支援部分地區。天氣和特定結構可能會影響連線。系統不支援衛星電話，但緊急電話可能仍能接通。\n\n「設定」頁面可能要一段時間後才會顯示帳戶變動，歡迎聯絡 <xliff:g id="CARRIER_NAME">%1$s</xliff:g> 查詢詳情。"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"更多有關「<xliff:g id="SUBJECT">%1$s</xliff:g>」的資料"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"無法開啟<xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"如要開啟<xliff:g id="FUNCTION">%1$s</xliff:g>，請先中斷衛星連線"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 6de76b04ba3..7be6114546d 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -4875,17 +4875,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"透過衛星收發訊息 (你的帳戶不支援這項功能)。"</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"衛星訊息, 衛星連線"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"關於<xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"適用的「<xliff:g id="CARRIER_NAME">%1$s</xliff:g>」帳戶支援透過衛星收發訊息"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"你的「<xliff:g id="CARRIER_NAME">%1$s</xliff:g>」方案"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"你的帳戶支援訊息功能"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"你可以在符合資格的「<xliff:g id="CARRIER_NAME">%1$s</xliff:g>」帳戶中透過衛星收發訊息"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"你的「<xliff:g id="CARRIER_NAME">%1$s</xliff:g>」帳戶"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"你的帳戶支援衛星訊息"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"你的帳戶不支援衛星訊息"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"瞭解詳情"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"運作方式"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"沒有行動網路時"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"傳送訊息到某個電話號碼"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"手機會自動連上衛星。為獲得最佳連線品質，請在沒有物體遮住天空的地方使用。"</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"如果沒有行動網路，你會看到使用衛星訊息的選項。"</string>
     <string name="title_supported_service" msgid="4275535165812691571">"手機連上衛星後"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"按照步驟連上衛星"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"你可以傳送訊息給任何人，包括緊急救援服務。如果有可用的行動網路，手機就會重新連線。"</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"<xliff:g id="SUBJECT">%1$s</xliff:g>可能需要比較長的時間才會送達，而且這項功能僅支援部分地區。天氣和特定結構可能會影響衛星連線的品質。系統不支援衛星電話，但你仍可撥打緊急電話。\n\n「設定」頁面可能要一段時間後才會顯示帳戶變動，詳情請洽「<xliff:g id="CARRIER_NAME">%1$s</xliff:g>」。"</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"手機連線後，你可以傳送訊息給任何人，包括緊急救援服務。"</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"衛星連線可能較緩慢，而且這項功能僅支援部分地區。天氣和特定結構可能會影響連線品質。系統不支援衛星電話，但你仍可撥打緊急電話。\n\n「設定」頁面可能要一段時間後才會顯示帳戶變動，詳情請洽「<xliff:g id="CARRIER_NAME">%1$s</xliff:g>」。"</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"進一步瞭解<xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"無法開啟<xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"如要開啟<xliff:g id="FUNCTION">%1$s</xliff:g>，請先中斷衛星連線"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 1438ae46df8..a3abd59f7fa 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -4876,17 +4876,21 @@
     <string name="satellite_setting_disabled_summary" msgid="8428393986403708690">"Thumela futhi wamukele umyalezo obhaliwe ngesethelayithi. Akufakwanga e-akhawuntini yakho."</string>
     <string name="keywords_satellite_setting" msgid="613553612424945946">"Ukuthumela imiyalezo ngesethelayithi, ukuxhumana ngesethelayithi"</string>
     <string name="category_name_about_satellite_messaging" msgid="4978095955643523120">"Mayelana ne-<xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
-    <string name="title_about_satellite_setting" msgid="9212860038048311345">"Ungathumela futhi wamukele imiyalezo ebhaliwe ngesethelayithi njengengxenye ye-akhawunti efanelekayo ye-<xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="category_title_your_satellite_plan" msgid="3017895097366691841">"Uhlelo lwakho lwe-<xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
-    <string name="title_have_satellite_plan" msgid="857337944804101443">"Ukulayeza kufakwe e-akhawuntini yakho"</string>
+    <string name="title_about_satellite_setting" msgid="3563087940535642558">"Ungathumela futhi wamukele imiyalezo ebhaliwe ngesathelayithi nge-akhawunti efanelekayo ye-<xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="category_title_your_satellite_plan" msgid="8169426217950247126">"I-akhawunti yakho ye-<xliff:g id="CARRIER_NAME">%1$s</xliff:g>"</string>
+    <string name="title_have_satellite_plan" msgid="2048372355699977947">"Ukuyaleza kwesethelayithi kubandakanywe ku-akhawunti yakho"</string>
     <string name="title_no_satellite_plan" msgid="2876056203035197505">"Ukuyaleza kwesethelayithi akubandakanyiwe ne-akhawunti yakho"</string>
     <string name="summary_add_satellite_setting" msgid="190359698593056946">"Funda Kabanzi"</string>
     <string name="category_name_how_it_works" msgid="585303230539269496">"Indlela esebenza ngayo"</string>
     <string name="title_satellite_connection_guide" msgid="3294802307913609072">"Uma ungenayo inethiwekhi yeselula"</string>
+    <string name="title_satellite_connection_guide_for_manual_type" msgid="7223875100977941341">"Thumela umyalezo enombolweni yefoni"</string>
     <string name="summary_satellite_connection_guide" msgid="3496123195218418456">"Ifoni yakho izoxhuma ngokuzenzakalela kusethelayithi. Ngokuxhuma okuncono, gcina isibhakabhaka sikhanya bha."</string>
+    <string name="summary_satellite_connection_guide_for_manual_type" msgid="5075149380084376662">"Uma ungenayo inethiwekhi yeselula, uzobona indlela yokukhetha ukuthumela umyalezo ngesethelayithi."</string>
     <string name="title_supported_service" msgid="4275535165812691571">"Ngemva kokuthi ifoni yakho ixhume kusethelayithi"</string>
+    <string name="title_supported_service_for_manual_type" msgid="6009284624466359864">"Landela izinyathelo ukuze uxhume kusethelayithi"</string>
     <string name="summary_supported_service" msgid="4320535903444834786">"Ungathumelela noma ubani umyalezo, okubandakanya amasevisi ezimo eziphuthumayo. Ifoni yakho izophinde ixhume kunethiwekhi yeselula uma itholakala."</string>
-    <string name="satellite_setting_summary_more_information" msgid="1028146147094166868">"I-<xliff:g id="SUBJECT">%1$s</xliff:g> ingase ithathe isikhathi eside futhi itholakala kuphela ezindaweni ezithile. Isimo sezulu nezakhiwo ezithile zingathikameza uxhumo lwakho lwesethelayithi. Ukufona ngesethelayithi akutholakali. Amakholi ephuthumayo isengaxhuma.\n\nKungathatha isikhathi esithile ukuthi ushintsho lwe-akhawunti luvele Kumasethingi. Xhumana ne-<xliff:g id="CARRIER_NAME">%1$s</xliff:g> ukuthola imininingwane."</string>
+    <string name="summary_supported_service_for_manual_type" msgid="2147958362763058271">"Ngemva kokuba ifoni yakho ixhunyiwe, ungathumela umyalezo kunoma ubani, kuhlanganise amasevisi ezimo eziphuthumayo."</string>
+    <string name="satellite_setting_summary_more_information" msgid="276312352285564071">"Ukuxhuma kwesethelayithi kungase kuhambe kancane futhi kutholakala kuphela ezindaweni ezithile. Isimo sezulu nezakhiwo ezithile zingathikameza ukuxhuma. Ukufona ngesathelayithi akutholakali. Amakholi ezimo eziphuthumayo asengaxhumeka.\n\nKungathatha isikhathi esithile ukuthi ushintsho lwe-akhawunti luvele Kumasethingi. Xhumana ne-<xliff:g id="CARRIER_NAME">%1$s</xliff:g> uthole imininingwane."</string>
     <string name="more_about_satellite_messaging" msgid="1039277943532711584">"Okwengeziwe nge-<xliff:g id="SUBJECT">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_title" msgid="1610117852475376931">"Ayikwazi ukuvula i-<xliff:g id="FUNCTION">%1$s</xliff:g>"</string>
     <string name="satellite_warning_dialog_content" msgid="936419945275934955">"Ukuze uvule i-<xliff:g id="FUNCTION">%1$s</xliff:g>, qala ngokumisa uxhumo lwesathelayithi"</string>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 730c258601c..db679d7e5da 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -12334,11 +12334,11 @@
     <!-- Category name "About satellite messaging" [CHAR_LIMIT=NONE] -->
     <string name="category_name_about_satellite_messaging">About <xliff:g id="subject" example="satellite messaging">%1$s</xliff:g></string>
     <!-- Summary for category "About satellite messaging" [CHAR_LIMIT=NONE] -->
-    <string name="title_about_satellite_setting">You can send and receive text messages by satellite as part of an eligible <xliff:g id="carrier_name" example="T-Mobile">%1$s</xliff:g> account</string>
+    <string name="title_about_satellite_setting">You can send and receive text messages by satellite with an eligible <xliff:g id="carrier_name" example="T-Mobile">%1$s</xliff:g> account</string>
     <!-- Category title "Your mobile plan" [CHAR_LIMIT=NONE] -->
-    <string name="category_title_your_satellite_plan">Your <xliff:g id="carrier_name" example="T-Mobile">%1$s</xliff:g> plan</string>
+    <string name="category_title_your_satellite_plan">Your <xliff:g id="carrier_name" example="T-Mobile">%1$s</xliff:g> account</string>
     <!-- Title for category "Your mobile plan when satellite is included in plan" [CHAR_LIMIT=NONE] -->
-    <string name="title_have_satellite_plan">Messaging is included with your account</string>
+    <string name="title_have_satellite_plan">Satellite messaging is included with your account</string>
     <!-- Title for category "Your mobile plan when satellite is not included in plan" [CHAR_LIMIT=NONE] -->
     <string name="title_no_satellite_plan">Satellite messaging isn\u2019t included with your account</string>
     <!-- text view "Learn more" [CHAR_LIMIT=NONE] -->
@@ -12347,14 +12347,22 @@
     <string name="category_name_how_it_works">How it works</string>
     <!-- Title for satellite connection guide [CHAR_LIMIT=NONE] -->
     <string name="title_satellite_connection_guide">When you don\u2019t have a mobile network</string>
+    <!-- Title for satellite connection guide for NTN manual connection type. [CHAR_LIMIT=NONE] -->
+    <string name="title_satellite_connection_guide_for_manual_type">Text a phone number</string>
     <!-- Summary for satellite connection guide [CHAR_LIMIT=NONE] -->
     <string name="summary_satellite_connection_guide">Your phone will auto-connect to a satellite. For the best connection, keep a clear view of the sky.</string>
+    <!-- Summary for satellite connection guide for NTN manual connection type. [CHAR_LIMIT=NONE] -->
+    <string name="summary_satellite_connection_guide_for_manual_type">If you don\u2019t have a mobile network, you\u2019ll see an option to use satellite messaging.</string>
     <!-- Title for satellite supported service [CHAR_LIMIT=NONE] -->
     <string name="title_supported_service">After your phone connects to a satellite</string>
+    <!-- Title for satellite supported service for NTN manual connection type. [CHAR_LIMIT=NONE] -->
+    <string name="title_supported_service_for_manual_type">Follow steps to connect to the satellite</string>
     <!-- Summary for satellite supported service [CHAR_LIMIT=NONE] -->
     <string name="summary_supported_service">You can text anyone, including emergency services. Your phone will reconnect to a mobile network when available.</string>
+    <!-- Summary for satellite supported service for NTN manual connection type. [CHAR_LIMIT=NONE] -->
+    <string name="summary_supported_service_for_manual_type">After your phone is connected, you can text anyone, including emergency services.</string>
     <!-- learn more text - more about satellite messaging [CHAR_LIMIT=NONE] -->
-    <string name="satellite_setting_summary_more_information"><xliff:g id="subject" example="satellite messaging">%1$s</xliff:g> may take longer and is available only in some areas. Weather and certain structures may affect your satellite connection. Calling by satellite isn\u2019t available. Emergency calls may still connect.\n\nIt may take some time for account changes to show in Settings. Contact <xliff:g id="carrier_name" example="T-Mobile">%1$s</xliff:g> for details.</string>
+    <string name="satellite_setting_summary_more_information">A satellite connection may be slower and is available only in some areas. Weather and certain structures may affect the connection. Calling by satellite isn\u2019t available. Emergency calls may still connect.\n\nIt may take some time for account changes to show in Settings. Contact <xliff:g id="carrier_name" example="T-Mobile">%1$s</xliff:g> for details.</string>
     <!-- more about satellite messaging [CHAR_LIMIT=NONE] -->
     <string name="more_about_satellite_messaging">More about <xliff:g id="subject" example="satellite messaging">%1$s</xliff:g></string>
     <!-- Title for satellite warning dialog to avoid user using wifi/bluetooth/airplane mode [CHAR_LIMIT=NONE] -->
diff --git a/src/com/android/settings/applications/AppInfoBase.java b/src/com/android/settings/applications/AppInfoBase.java
index 1d774826c2d..02237b886d9 100644
--- a/src/com/android/settings/applications/AppInfoBase.java
+++ b/src/com/android/settings/applications/AppInfoBase.java
@@ -20,6 +20,7 @@ import static com.android.settingslib.RestrictedLockUtils.EnforcedAdmin;
 
 import android.Manifest;
 import android.app.Activity;
+import android.app.ActivityManager;
 import android.app.Dialog;
 import android.app.admin.DevicePolicyManager;
 import android.app.settings.SettingsEnums;
@@ -34,6 +35,7 @@ import android.content.pm.PackageManager.NameNotFoundException;
 import android.hardware.usb.IUsbManager;
 import android.os.Bundle;
 import android.os.IBinder;
+import android.os.RemoteException;
 import android.os.ServiceManager;
 import android.os.UserHandle;
 import android.os.UserManager;
@@ -176,20 +178,19 @@ public abstract class AppInfoBase extends SettingsPreferenceFragment
         if (!(activity instanceof SettingsActivity)) {
             return false;
         }
-        final String callingPackageName =
-                ((SettingsActivity) activity).getInitialCallingPackage();
-
-        if (TextUtils.isEmpty(callingPackageName)) {
-            Log.w(TAG, "Not able to get calling package name for permission check");
-            return false;
-        }
-        if (mPm.checkPermission(Manifest.permission.INTERACT_ACROSS_USERS_FULL, callingPackageName)
-                != PackageManager.PERMISSION_GRANTED) {
-            Log.w(TAG, "Package " + callingPackageName + " does not have required permission "
-                    + Manifest.permission.INTERACT_ACROSS_USERS_FULL);
+        try {
+            int callerUid = ActivityManager.getService().getLaunchedFromUid(
+                    activity.getActivityToken());
+            if (ActivityManager.checkUidPermission(Manifest.permission.INTERACT_ACROSS_USERS_FULL,
+                    callerUid) != PackageManager.PERMISSION_GRANTED) {
+                Log.w(TAG, "Uid " + callerUid + " does not have required permission "
+                        + Manifest.permission.INTERACT_ACROSS_USERS_FULL);
+                return false;
+            }
+            return true;
+        } catch (RemoteException e) {
             return false;
         }
-        return true;
     }
 
     protected void setIntentAndFinish(boolean appChanged) {
diff --git a/src/com/android/settings/network/telephony/SatelliteSetting.java b/src/com/android/settings/network/telephony/SatelliteSetting.java
index 52957d98b30..a65f327ce94 100644
--- a/src/com/android/settings/network/telephony/SatelliteSetting.java
+++ b/src/com/android/settings/network/telephony/SatelliteSetting.java
@@ -68,6 +68,9 @@ public class SatelliteSetting extends RestrictedDashboardFragment {
     private static final String PREF_KEY_YOUR_SATELLITE_DATA_PLAN = "key_your_satellite_data_plan";
     private static final String PREF_KEY_CATEGORY_ABOUT_SATELLITE = "key_category_about_satellite";
     private static final String KEY_FOOTER_PREFERENCE = "satellite_setting_extra_info_footer_pref";
+    private static final String KEY_SATELLITE_CONNECTION_GUIDE = "key_satellite_connection_guide";
+    private static final String KEY_SUPPORTED_SERVICE = "key_supported_service";
+
 
     static final String SUB_ID = "sub_id";
     static final String EXTRA_IS_SERVICE_DATA_TYPE = "is_service_data_type";
@@ -221,6 +224,15 @@ public class SatelliteSetting extends RestrictedDashboardFragment {
             category.setEnabled(false);
             category.setShouldDisableView(true);
         }
+        if (!isCarrierRoamingNtnConnectedTypeManual()) {
+            return;
+        }
+        Preference connectionGuide = findPreference(KEY_SATELLITE_CONNECTION_GUIDE);
+        connectionGuide.setTitle(R.string.title_satellite_connection_guide_for_manual_type);
+        connectionGuide.setSummary(R.string.summary_satellite_connection_guide_for_manual_type);
+        Preference supportedService = findPreference(KEY_SUPPORTED_SERVICE);
+        supportedService.setTitle(R.string.title_supported_service_for_manual_type);
+        supportedService.setSummary(R.string.summary_supported_service_for_manual_type);
     }
 
     private void updateFooterContent() {
@@ -229,7 +241,7 @@ public class SatelliteSetting extends RestrictedDashboardFragment {
         if (footerPreference != null) {
             footerPreference.setSummary(
                     getResources().getString(R.string.satellite_setting_summary_more_information,
-                            getSubjectString(), mSimOperatorName));
+                            mSimOperatorName));
 
             final String[] link = new String[1];
             link[0] = readSatelliteMoreInfoString();
diff --git a/src/com/android/settings/network/telephony/SatelliteSettingsPreferenceCategoryController.java b/src/com/android/settings/network/telephony/SatelliteSettingsPreferenceCategoryController.java
index db09651b641..80d4ece1991 100644
--- a/src/com/android/settings/network/telephony/SatelliteSettingsPreferenceCategoryController.java
+++ b/src/com/android/settings/network/telephony/SatelliteSettingsPreferenceCategoryController.java
@@ -79,6 +79,7 @@ public class SatelliteSettingsPreferenceCategoryController
     public void displayPreference(PreferenceScreen screen) {
         super.displayPreference(screen);
         mPreferenceCategory = screen.findPreference(getPreferenceKey());
+        mPreferenceCategory.setTitle(R.string.category_title_satellite_connectivity);
     }
 
     @Override
@@ -135,11 +136,6 @@ public class SatelliteSettingsPreferenceCategoryController
                 Log.d(TAG, "Satellite preference category is not initialized yet");
                 return;
             }
-            if (isDataAvailable) {
-                mPreferenceCategory.setTitle(R.string.category_title_satellite_connectivity);
-            } else if (isSmsAvailable) {
-                mPreferenceCategory.setTitle(R.string.satellite_setting_title);
-            }
         }
 
         @Override
diff --git a/src/com/android/settings/notification/NotificationAccessConfirmationActivity.java b/src/com/android/settings/notification/NotificationAccessConfirmationActivity.java
index 1adeb644155..8448a8e752a 100644
--- a/src/com/android/settings/notification/NotificationAccessConfirmationActivity.java
+++ b/src/com/android/settings/notification/NotificationAccessConfirmationActivity.java
@@ -41,7 +41,6 @@ import android.os.UserManager;
 import android.service.notification.NotificationListenerService;
 import android.text.TextUtils;
 import android.util.Slog;
-import android.view.WindowManager;
 import android.view.accessibility.AccessibilityEvent;
 import android.widget.Toast;
 
@@ -161,20 +160,6 @@ public class NotificationAccessConfirmationActivity extends Activity
         getWindow().setCloseOnTouchOutside(false); 
     }
 
-    @Override
-    public void onResume() {
-        super.onResume();
-        getWindow().addFlags(
-                WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
-    }
-
-    @Override
-    public void onPause() {
-        getWindow().clearFlags(
-                WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
-        super.onPause();
-    }
-
     private void onAllow() {
         mNm.setNotificationListenerAccessGranted(mComponentName, true);
 
diff --git a/tests/robotests/src/com/android/settings/notification/NotificationAccessConfirmationActivityTest.java b/tests/robotests/src/com/android/settings/notification/NotificationAccessConfirmationActivityTest.java
index 0a953615abf..8ae242f0869 100644
--- a/tests/robotests/src/com/android/settings/notification/NotificationAccessConfirmationActivityTest.java
+++ b/tests/robotests/src/com/android/settings/notification/NotificationAccessConfirmationActivityTest.java
@@ -16,6 +16,8 @@
 
 package com.android.settings.notification;
 
+import static android.view.WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS;
+
 import static com.android.internal.notification.NotificationAccessConfirmationActivityContract.EXTRA_COMPONENT_NAME;
 
 import static com.google.common.truth.Truth.assertThat;
@@ -42,6 +44,19 @@ import org.robolectric.RuntimeEnvironment;
 @RunWith(RobolectricTestRunner.class)
 public class NotificationAccessConfirmationActivityTest {
 
+    @Test
+    public void onCreate_setsWindowFlags() {
+        ComponentName cn = new ComponentName("com.example", "com.example.SomeService");
+        installPackage(cn.getPackageName(), "Example");
+
+        NotificationAccessConfirmationActivity activity = startActivityWithIntent(cn);
+
+        assertThat(activity.getWindow().getAttributes().privateFlags
+                & SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS).isNotEqualTo(0);
+        assertThat(activity.getWindow().getAttributes().flags
+                & SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS).isEqualTo(0);
+    }
+
     @Test
     public void start_withMissingIntentFilter_finishes() {
         ComponentName cn = new ComponentName("com.example", "com.example.SomeService");
```

