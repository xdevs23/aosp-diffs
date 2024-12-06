```diff
diff --git a/libs/WifiTrackerLib/Android.bp b/libs/WifiTrackerLib/Android.bp
index 03d86e075..ac9bc731d 100644
--- a/libs/WifiTrackerLib/Android.bp
+++ b/libs/WifiTrackerLib/Android.bp
@@ -23,6 +23,7 @@ android_library {
     defaults: ["WifiTrackerLibDefaults"],
     static_libs: [
         "wifi_aconfig_flags_lib",
+        "android.net.wifi.flags-aconfig-java",
     ],
     srcs: ["src/**/*.java"],
 }
diff --git a/libs/WifiTrackerLib/res/values-af/strings.xml b/libs/WifiTrackerLib/res/values-af/strings.xml
index 15ed2ce55..8c589f06d 100644
--- a/libs/WifiTrackerLib/res/values-af/strings.xml
+++ b/libs/WifiTrackerLib/res/values-af/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Kan nie toegang tot private DNS-bediener kry nie"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Gekoppel aan toestel. Kan nie internet verskaf nie."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Lae gehalte"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (minder veilig)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Word nie deur jou organisasie toegelaat nie"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> van <xliff:g id="MODEL_NAME">%2$s</xliff:g> af"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} van jou foon af}TABLET{{NETWORK_NAME} van jou tablet af}COMPUTER{{NETWORK_NAME} van jou rekenaar af}WATCH{{NETWORK_NAME} van jou horlosie af}VEHICLE{{NETWORK_NAME} van jou voertuig af}other{{NETWORK_NAME} van jou toestel af}}"</string>
@@ -62,7 +63,7 @@
     <string name="wifitrackerlib_wifi_security_short_eap_suiteb" msgid="6335062557041604336">"Suite-B-192"</string>
     <string name="wifitrackerlib_wifi_security_eap_suiteb" msgid="4715703239786225763">"WPA3-Enterprise 192-bis"</string>
     <string name="wifitrackerlib_wifi_security_short_wpa_wpa2" msgid="6770438383385707243">"WPA/WPA2"</string>
-    <string name="wifitrackerlib_wifi_security_wpa_wpa2" msgid="5767878305316110228">"WPA/WPA2-Personal"</string>
+    <string name="wifitrackerlib_wifi_security_wpa_wpa2" msgid="5767878305316110228">"WPA/WPA2-persoonlik"</string>
     <string name="wifitrackerlib_wifi_security_short_wpa_wpa2_wpa3" msgid="4489424775550194618">"WPA/WPA2/WPA3"</string>
     <string name="wifitrackerlib_wifi_security_wpa_wpa2_wpa3" msgid="4154428413248489642">"WPA/WPA2/WPA3-Personal"</string>
     <string name="wifitrackerlib_wifi_security_wep" msgid="7714779033848180369">"WEP"</string>
diff --git a/libs/WifiTrackerLib/res/values-am/strings.xml b/libs/WifiTrackerLib/res/values-am/strings.xml
index a1f97068c..ae33839c7 100644
--- a/libs/WifiTrackerLib/res/values-am/strings.xml
+++ b/libs/WifiTrackerLib/res/values-am/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"የግል ዲኤንኤስ አገልጋይ ሊደረስበት አይችልም"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"ከመሣሪያው ጋር ተገናኝቷል። በይነመረብ ማቅረብ አልተቻለም።"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"አነስተኛ ጥራት"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (ያነሰ ደህንነቱ የተጠበቀ)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"በእርስዎ ድርጅት አልተፈቀደም"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> ከ<xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} ከስልክዎ}TABLET{{NETWORK_NAME} ከጡባዊዎ}COMPUTER{{NETWORK_NAME} ከኮምፒውተርዎ}WATCH{{NETWORK_NAME}ከሰዓትዎ}VEHICLE{{NETWORK_NAME} ከተሽከርካሪዎ}other{{NETWORK_NAME} ከመሣሪያዎ}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ar/strings.xml b/libs/WifiTrackerLib/res/values-ar/strings.xml
index 97d1baa47..466d6c7e0 100644
--- a/libs/WifiTrackerLib/res/values-ar/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ar/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"لا يمكن الوصول إلى خادم أسماء نظام نطاقات خاص"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"الشبكة متصلة بالجهاز. يتعذّر توفير اتصال بالإنترنت."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"جودة منخفضة"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"‫<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (مستوى أمان أقل)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"لا تسمح بها مؤسستك"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"\"<xliff:g id="NETWORK_NAME">%1$s</xliff:g>\" من \"<xliff:g id="MODEL_NAME">%2$s</xliff:g>\""</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{شبكة \"{NETWORK_NAME}\" من هاتفك}TABLET{شبكة \"{NETWORK_NAME}\" من جهازك اللوحي}COMPUTER{شبكة \"{NETWORK_NAME}\" من جهاز الكمبيوتر}WATCH{شبكة \"{NETWORK_NAME}\" من ساعتك}VEHICLE{شبكة \"{NETWORK_NAME}\" من مركبتك}other{شبكة \"{NETWORK_NAME}\" من جهازك}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-as/strings.xml b/libs/WifiTrackerLib/res/values-as/strings.xml
index d11c213a8..b50ee4ffd 100644
--- a/libs/WifiTrackerLib/res/values-as/strings.xml
+++ b/libs/WifiTrackerLib/res/values-as/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"ব্যক্তিগত DNS ছাৰ্ভাৰ এক্সেছ কৰিব নোৱাৰি"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"ডিভাইচৰ সৈতে সংযোগ কৰা হৈছে। ইণ্টাৰনেট সংযোগ প্ৰদান কৰিব নোৱাৰি।"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"নিম্ন মানৰ"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (কম সুৰক্ষিত)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"আপোনাৰ প্ৰতিষ্ঠানে অনুমতি নিদিয়ে"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g>ৰ পৰা <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{আপোনাৰ ফ’নৰ পৰা {NETWORK_NAME}}TABLET{আপোনাৰ টেবলেটৰ পৰা {NETWORK_NAME}}COMPUTER{আপোনাৰ কম্পিউটাৰৰ পৰা {NETWORK_NAME}}WATCH{আপোনাৰ ঘড়ীৰ পৰা {NETWORK_NAME}}VEHICLE{আপোনাৰ বাহনৰ পৰা {NETWORK_NAME}}other{আপোনাৰ ডিভাইচৰ পৰা {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-az/strings.xml b/libs/WifiTrackerLib/res/values-az/strings.xml
index 97c3675c9..5cdc992b5 100644
--- a/libs/WifiTrackerLib/res/values-az/strings.xml
+++ b/libs/WifiTrackerLib/res/values-az/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Özəl DNS serverinə giriş mümkün deyil"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Cihaza qoşulub. İnternet təmin etmək olmur."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Aşağı keyfiyyət"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (daha az güvənli)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Təşkilatınız icazə vermir"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> tərəfindən <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{Telefonunuzdan: {NETWORK_NAME}}TABLET{Planşetinizdən: {NETWORK_NAME}}COMPUTER{Komputerinizdən: {NETWORK_NAME}}WATCH{Saatınızdan: {NETWORK_NAME}}VEHICLE{Avtomobilinizdən: {NETWORK_NAME}}other{Cihazınızdan: {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-b+sr+Latn/strings.xml b/libs/WifiTrackerLib/res/values-b+sr+Latn/strings.xml
index 20e1eac11..17f168b6b 100644
--- a/libs/WifiTrackerLib/res/values-b+sr+Latn/strings.xml
+++ b/libs/WifiTrackerLib/res/values-b+sr+Latn/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Pristup privatnom DNS serveru nije uspeo"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Uređaj je povezan. Pružanje interneta nije uspelo."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Loš kvalitet"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (manje bezbedno)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Ne dozvoljava vaša organizacija"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> – <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} sa telefona}TABLET{{NETWORK_NAME} sa tableta}COMPUTER{{NETWORK_NAME} sa računara}WATCH{{NETWORK_NAME} sa sata}VEHICLE{{NETWORK_NAME} sa vozila}other{{NETWORK_NAME} sa uređaja}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-be/strings.xml b/libs/WifiTrackerLib/res/values-be/strings.xml
index 187550211..abb5115e5 100644
--- a/libs/WifiTrackerLib/res/values-be/strings.xml
+++ b/libs/WifiTrackerLib/res/values-be/strings.xml
@@ -43,11 +43,12 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Не ўдалося атрымаць доступ да прыватнага DNS-сервера"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Падключана да прылады. Не ўдалося падключыцца да інтэрнэту."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Нізкая якасць"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (менш бяспечна)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Забаронена ў вашай арганізацыі"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> ад <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
-    <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} (з вашага тэлефона)}TABLET{{NETWORK_NAME} (з вашага планшэта)}COMPUTER{{NETWORK_NAME} (з вашага камп\'ютара)}WATCH{{NETWORK_NAME} (з вашага гадзінніка)}VEHICLE{{NETWORK_NAME} (з вашага аўтамабіля)}other{{NETWORK_NAME} (з вашай прылады)}}"</string>
+    <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} (з вашага тэлефона)}TABLET{{NETWORK_NAME} (з вашага планшэта)}COMPUTER{{NETWORK_NAME} (з вашага камп’ютара)}WATCH{{NETWORK_NAME} (з вашага гадзінніка)}VEHICLE{{NETWORK_NAME} (з вашага аўтамабіля)}other{{NETWORK_NAME} (з вашай прылады)}}"</string>
     <string name="wifitrackerlib_hotspot_network_summary_error_generic" msgid="2339836723160908882">"Не ўдаецца падключыцца. Паўтарыце спробу яшчэ раз."</string>
-    <string name="wifitrackerlib_hotspot_network_summary_error_settings" msgid="6928234716406336668">"{DEVICE_TYPE,select, PHONE{Не ўдаецца падключыцца. Праверце налады тэлефона і паўтарыце спробу.}TABLET{Не ўдаецца падключыцца. Праверце налады планшэта і паўтарыце спробу.}COMPUTER{Не ўдаецца падключыцца. Праверце налады камп\'ютара і паўтарыце спробу.}WATCH{Не ўдаецца падключыцца. Праверце налады гадзінніка і паўтарыце спробу.}VEHICLE{Не ўдаецца падключыцца. Праверце налады аўтамабіля і паўтарыце спробу.}other{Не ўдаецца падключыцца. Праверце налады прылады і паўтарыце спробу.}}"</string>
+    <string name="wifitrackerlib_hotspot_network_summary_error_settings" msgid="6928234716406336668">"{DEVICE_TYPE,select, PHONE{Не ўдаецца падключыцца. Праверце налады тэлефона і паўтарыце спробу.}TABLET{Не ўдаецца падключыцца. Праверце налады планшэта і паўтарыце спробу.}COMPUTER{Не ўдаецца падключыцца. Праверце налады камп’ютара і паўтарыце спробу.}WATCH{Не ўдаецца падключыцца. Праверце налады гадзінніка і паўтарыце спробу.}VEHICLE{Не ўдаецца падключыцца. Праверце налады аўтамабіля і паўтарыце спробу.}other{Не ўдаецца падключыцца. Праверце налады прылады і паўтарыце спробу.}}"</string>
     <string name="wifitrackerlib_hotspot_network_summary_error_carrier_block" msgid="359780026027619177">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> не дазваляе ўстанаўліваць гэта падключэнне"</string>
     <string name="wifitrackerlib_hotspot_network_summary_error_carrier_incomplete" msgid="3407132390461094984">"Не ўдаецца падключыцца. Звярніцеся па дапамогу да аператара \"<xliff:g id="NETWORK_NAME">%1$s</xliff:g>\"."</string>
     <string name="wifitrackerlib_hotspot_network_alternate" msgid="4966814473758893807">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> ад прылады <xliff:g id="DEVICE_NAME">%2$s</xliff:g>"</string>
diff --git a/libs/WifiTrackerLib/res/values-bg/strings.xml b/libs/WifiTrackerLib/res/values-bg/strings.xml
index 48864a4aa..438a93a71 100644
--- a/libs/WifiTrackerLib/res/values-bg/strings.xml
+++ b/libs/WifiTrackerLib/res/values-bg/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Не може да се осъществи достъп до частния DNS сървър"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Установена е връзка с устройство. Няма интернет."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Ниско качество"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (не толкова надеждно)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Не се разрешава от организацията ви"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> от <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} от телефона ви}TABLET{{NETWORK_NAME} от таблета ви}COMPUTER{{NETWORK_NAME} от компютъра ви}WATCH{{NETWORK_NAME} от часовника ви}VEHICLE{{NETWORK_NAME} от превозното ви средство}other{{NETWORK_NAME} от устройството ви}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-bn/strings.xml b/libs/WifiTrackerLib/res/values-bn/strings.xml
index d14282b68..990c55acf 100644
--- a/libs/WifiTrackerLib/res/values-bn/strings.xml
+++ b/libs/WifiTrackerLib/res/values-bn/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"ব্যক্তিগত ডিএনএস সার্ভার অ্যাক্সেস করা যাবে না"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"ডিভাইসের সাথে কানেক্ট করা। ইন্টারনেট পরিষেবা প্রদান করা যাচ্ছে না।"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"খারাপ কোয়ালিটি"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (কম সুরক্ষিত)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"আপনার প্রতিষ্ঠানের অননুমোদিত নেটওয়ার্ক"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> থেকে <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} আপনার ফোন থেকে}TABLET{{NETWORK_NAME} আপনার ট্যাবলেট থেকে}COMPUTER{{NETWORK_NAME} আপনার কম্পিউটার থেকে}WATCH{{NETWORK_NAME} আপনার ঘড়ি থেকে}VEHICLE{{NETWORK_NAME} আপনার গাড়ি থেকে}other{{NETWORK_NAME} আপনার ডিভাইস থেকে}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-bs/strings.xml b/libs/WifiTrackerLib/res/values-bs/strings.xml
index 53727bbac..bfb1b73c7 100644
--- a/libs/WifiTrackerLib/res/values-bs/strings.xml
+++ b/libs/WifiTrackerLib/res/values-bs/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Nije moguće pristupiti privatnom DNS serveru"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Povezano s uređajem. Nije moguće pružiti internetsku vezu."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Nizak kvalitet"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (manje sigurno)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Ne dozvoljava vaša organizacija"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> s uređaja <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} s telefona}TABLET{{NETWORK_NAME} s tableta}COMPUTER{{NETWORK_NAME} s računara}WATCH{{NETWORK_NAME} sa sata}VEHICLE{{NETWORK_NAME} iz vozila}other{{NETWORK_NAME} s uređaja}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ca/strings.xml b/libs/WifiTrackerLib/res/values-ca/strings.xml
index 31ad8ce19..ff5719425 100644
--- a/libs/WifiTrackerLib/res/values-ca/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ca/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"No es pot accedir al servidor DNS privat"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Connectat al dispositiu. Sense accés a Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Qualitat baixa"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (menys segur)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"No permesa per la teva organització"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> de <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} des del telèfon}TABLET{{NETWORK_NAME} des de la tauleta}COMPUTER{{NETWORK_NAME} des de l\'ordinador}WATCH{{NETWORK_NAME} des del rellotge}VEHICLE{{NETWORK_NAME} des del vehicle}other{{NETWORK_NAME} des del dispositiu}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-cs/strings.xml b/libs/WifiTrackerLib/res/values-cs/strings.xml
index b08de3aec..fe522dbff 100644
--- a/libs/WifiTrackerLib/res/values-cs/strings.xml
+++ b/libs/WifiTrackerLib/res/values-cs/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Nelze získat přístup k soukromému serveru DNS"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Připojeno k zařízení. Internet není k dispozici."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Nízká kvalita"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (méně zabezpečené)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Není povoleno vaší organizací"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> ze zařízení <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} z vašeho telefonu}TABLET{{NETWORK_NAME} z vašeho tabletu}COMPUTER{{NETWORK_NAME} z vašeho počítače}WATCH{{NETWORK_NAME} z vašich hodinek}VEHICLE{{NETWORK_NAME} z vašeho auta}other{{NETWORK_NAME} z vašeho zařízení}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-da/strings.xml b/libs/WifiTrackerLib/res/values-da/strings.xml
index a067cd3f6..161216075 100644
--- a/libs/WifiTrackerLib/res/values-da/strings.xml
+++ b/libs/WifiTrackerLib/res/values-da/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Der er ikke adgang til den private DNS-server"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Forbundet til enheden. Der er ikke noget internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Dårlig kvalitet"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (mindre sikker)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Tillades ikke af din organisation"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> fra <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} fra din telefon}TABLET{{NETWORK_NAME} fra din tablet}COMPUTER{{NETWORK_NAME} fra din computer}WATCH{{NETWORK_NAME} fra dit ur}VEHICLE{{NETWORK_NAME} fra dit køretøj}other{{NETWORK_NAME} fra din enhed}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-de/strings.xml b/libs/WifiTrackerLib/res/values-de/strings.xml
index 6773dc94a..2140ee398 100644
--- a/libs/WifiTrackerLib/res/values-de/strings.xml
+++ b/libs/WifiTrackerLib/res/values-de/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Auf den Server des privaten DNS kann nicht zugegriffen werden"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Mit Gerät verbunden. Internetverbindung nicht möglich."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Niedrige Qualität"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (weniger sicher)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Von deiner Organisation nicht zugelassen"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> von <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} von deinem Smartphone}TABLET{{NETWORK_NAME} von deinem Tablet}COMPUTER{{NETWORK_NAME} von deinem Computer}WATCH{{NETWORK_NAME} von deiner Smartwatch}VEHICLE{{NETWORK_NAME} von deinem Fahrzeug}other{{NETWORK_NAME} von deinem Gerät}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-el/strings.xml b/libs/WifiTrackerLib/res/values-el/strings.xml
index 3dd62d722..196e1a85e 100644
--- a/libs/WifiTrackerLib/res/values-el/strings.xml
+++ b/libs/WifiTrackerLib/res/values-el/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Δεν είναι δυνατή η πρόσβαση στον ιδιωτικό διακομιστή DNS."</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Συνδέθηκε στη συσκευή. Δεν είναι δυνατή η παροχή διαδικτύου."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Χαμηλή ποιότητα"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (λιγότερο ασφαλές)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Δεν επιτρέπεται από τον οργανισμό σας"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> από <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} από το τηλέφωνό σας}TABLET{{NETWORK_NAME} από το tablet σας}COMPUTER{{NETWORK_NAME} από τον υπολογιστή σας}WATCH{{NETWORK_NAME} από το ρολόι σας}VEHICLE{{NETWORK_NAME} από το όχημά σας}other{{NETWORK_NAME} από τη συσκευή σας}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-en-rAU/strings.xml b/libs/WifiTrackerLib/res/values-en-rAU/strings.xml
index 8d9a47a03..48c9a4397 100644
--- a/libs/WifiTrackerLib/res/values-en-rAU/strings.xml
+++ b/libs/WifiTrackerLib/res/values-en-rAU/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Private DNS server cannot be accessed"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Connected to device. Can\'t provide Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Low quality"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (less secure)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Not allowed by your organisation"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> from <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} from your phone}TABLET{{NETWORK_NAME} from your tablet}COMPUTER{{NETWORK_NAME} from your computer}WATCH{{NETWORK_NAME} from your watch}VEHICLE{{NETWORK_NAME} from your vehicle}other{{NETWORK_NAME} from your device}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-en-rCA/strings.xml b/libs/WifiTrackerLib/res/values-en-rCA/strings.xml
index 841cf4ca2..c776690ef 100644
--- a/libs/WifiTrackerLib/res/values-en-rCA/strings.xml
+++ b/libs/WifiTrackerLib/res/values-en-rCA/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Private DNS server cannot be accessed"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Connected to device. Can\'t provide internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Low quality"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (less secure)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Not allowed by your organization"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> from <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} from your phone}TABLET{{NETWORK_NAME} from your tablet}COMPUTER{{NETWORK_NAME} from your computer}WATCH{{NETWORK_NAME} from your watch}VEHICLE{{NETWORK_NAME} from your vehicle}other{{NETWORK_NAME} from your device}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-en-rGB/strings.xml b/libs/WifiTrackerLib/res/values-en-rGB/strings.xml
index 8d9a47a03..48c9a4397 100644
--- a/libs/WifiTrackerLib/res/values-en-rGB/strings.xml
+++ b/libs/WifiTrackerLib/res/values-en-rGB/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Private DNS server cannot be accessed"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Connected to device. Can\'t provide Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Low quality"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (less secure)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Not allowed by your organisation"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> from <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} from your phone}TABLET{{NETWORK_NAME} from your tablet}COMPUTER{{NETWORK_NAME} from your computer}WATCH{{NETWORK_NAME} from your watch}VEHICLE{{NETWORK_NAME} from your vehicle}other{{NETWORK_NAME} from your device}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-en-rIN/strings.xml b/libs/WifiTrackerLib/res/values-en-rIN/strings.xml
index 8d9a47a03..48c9a4397 100644
--- a/libs/WifiTrackerLib/res/values-en-rIN/strings.xml
+++ b/libs/WifiTrackerLib/res/values-en-rIN/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Private DNS server cannot be accessed"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Connected to device. Can\'t provide Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Low quality"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (less secure)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Not allowed by your organisation"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> from <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} from your phone}TABLET{{NETWORK_NAME} from your tablet}COMPUTER{{NETWORK_NAME} from your computer}WATCH{{NETWORK_NAME} from your watch}VEHICLE{{NETWORK_NAME} from your vehicle}other{{NETWORK_NAME} from your device}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-en-rXC/strings.xml b/libs/WifiTrackerLib/res/values-en-rXC/strings.xml
index 9a3965d53..9aa354b70 100644
--- a/libs/WifiTrackerLib/res/values-en-rXC/strings.xml
+++ b/libs/WifiTrackerLib/res/values-en-rXC/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‏‎‎‏‏‏‏‏‏‎‎‏‏‏‏‎‎‏‎‏‎‎‏‎‎‏‎‏‏‎‎‎‏‎‎‏‎‎‎‎‎‏‎‏‎‎‎‎‏‏‏‎‎‏‏‏‏‎‎‏‏‎Private DNS server cannot be accessed‎‏‎‎‏‎"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‎‏‎‎‏‏‎‎‏‎‎‎‏‎‏‎‎‏‎‏‎‎‏‏‎‎‏‎‏‎‏‎‎‎‏‎‏‏‏‏‏‎‎‏‏‏‎‏‎‎‎‏‎‏‎‎‏‎‎‏‎Connected to device. Can\'t provide internet.‎‏‎‎‏‎"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‏‏‏‎‎‎‏‎‎‏‏‎‎‎‏‏‏‎‏‎‏‏‏‎‎‏‏‏‏‎‎‎‎‎‎‏‏‏‏‎‏‎‏‏‎‎‎‎‏‏‎‎‏‏‎‎‏‏‎‏‎Low quality‎‏‎‎‏‎"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‎‎‎‎‏‎‎‎‏‏‎‏‎‎‎‎‎‏‎‏‏‎‎‎‏‎‎‎‎‎‏‎‏‎‏‏‎‎‎‏‏‎‏‎‎‏‎‎‎‏‎‎‏‏‏‎‏‏‎‏‎‎‎‏‎‎‏‏‎<xliff:g id="SECURITY_TYPE">%1$s</xliff:g>‎‏‎‎‏‏‏‎ (less secure)‎‏‎‎‏‎"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‎‏‎‏‏‎‏‏‏‏‏‏‎‎‏‏‏‎‏‎‏‏‎‏‏‎‎‎‎‏‎‎‎‏‏‏‎‏‎‎‏‎‏‎‎‎‎‎‎‎‏‏‎‏‏‏‎‏‎‏‏‎Not allowed by your organization‎‏‎‎‏‎"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‎‏‎‏‎‎‏‎‏‎‎‎‏‏‎‏‎‎‏‎‏‏‎‏‏‏‏‏‏‏‎‎‏‏‏‎‏‎‎‏‎‎‏‏‏‏‎‏‎‏‏‎‏‏‎‎‏‏‏‏‎‎‎‏‎‎‏‏‎<xliff:g id="NETWORK_NAME">%1$s</xliff:g>‎‏‎‎‏‏‏‎ from ‎‏‎‎‏‏‎<xliff:g id="MODEL_NAME">%2$s</xliff:g>‎‏‎‎‏‏‏‎‎‏‎‎‏‎"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‎‎‎‎‎‎‏‎‏‏‎‏‎‏‏‎‏‎‏‏‎‏‎‎‏‏‏‏‎‏‏‎‎‏‎‎‏‏‏‎‏‏‎‏‎‎‎‎‎‏‎‎‎‎‏‏‎‏‎‏‎‎‏‎‎‏‏‎{NETWORK_NAME}‎‏‎‎‏‏‏‎ from your phone‎‏‎‎‏‎}TABLET{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‎‎‎‎‎‎‏‎‏‏‎‏‎‏‏‎‏‎‏‏‎‏‎‎‏‏‏‏‎‏‏‎‎‏‎‎‏‏‏‎‏‏‎‏‎‎‎‎‎‏‎‎‎‎‏‏‎‏‎‏‎‎‏‎‎‏‏‎{NETWORK_NAME}‎‏‎‎‏‏‏‎ from your tablet‎‏‎‎‏‎}COMPUTER{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‎‎‎‎‎‎‏‎‏‏‎‏‎‏‏‎‏‎‏‏‎‏‎‎‏‏‏‏‎‏‏‎‎‏‎‎‏‏‏‎‏‏‎‏‎‎‎‎‎‏‎‎‎‎‏‏‎‏‎‏‎‎‏‎‎‏‏‎{NETWORK_NAME}‎‏‎‎‏‏‏‎ from your computer‎‏‎‎‏‎}WATCH{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‎‎‎‎‎‎‏‎‏‏‎‏‎‏‏‎‏‎‏‏‎‏‎‎‏‏‏‏‎‏‏‎‎‏‎‎‏‏‏‎‏‏‎‏‎‎‎‎‎‏‎‎‎‎‏‏‎‏‎‏‎‎‏‎‎‏‏‎{NETWORK_NAME}‎‏‎‎‏‏‏‎ from your watch‎‏‎‎‏‎}VEHICLE{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‎‎‎‎‎‎‏‎‏‏‎‏‎‏‏‎‏‎‏‏‎‏‎‎‏‏‏‏‎‏‏‎‎‏‎‎‏‏‏‎‏‏‎‏‎‎‎‎‎‏‎‎‎‎‏‏‎‏‎‏‎‎‏‎‎‏‏‎{NETWORK_NAME}‎‏‎‎‏‏‏‎ from your vehicle‎‏‎‎‏‎}other{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‎‎‎‎‎‎‏‎‏‏‎‏‎‏‏‎‏‎‏‏‎‏‎‎‏‏‏‏‎‏‏‎‎‏‎‎‏‏‏‎‏‏‎‏‎‎‎‎‎‏‎‎‎‎‏‏‎‏‎‏‎‎‏‎‎‏‏‎{NETWORK_NAME}‎‏‎‎‏‏‏‎ from your device‎‏‎‎‏‎}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-es-rUS/strings.xml b/libs/WifiTrackerLib/res/values-es-rUS/strings.xml
index 6b47fe8a1..c60d18928 100644
--- a/libs/WifiTrackerLib/res/values-es-rUS/strings.xml
+++ b/libs/WifiTrackerLib/res/values-es-rUS/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"No se puede acceder al servidor DNS privado"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Se estableció conexión con el dispositivo. No se puede acceder a Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Baja calidad"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (menos seguridad)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Tu organización no lo permite"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> de <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} en tu teléfono}TABLET{{NETWORK_NAME} en tu tablet}COMPUTER{{NETWORK_NAME} en tu computadora}WATCH{{NETWORK_NAME} en tu reloj}VEHICLE{{NETWORK_NAME} en tu vehículo}other{{NETWORK_NAME} en tu dispositivo}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-es/strings.xml b/libs/WifiTrackerLib/res/values-es/strings.xml
index c25e41634..061ffad81 100644
--- a/libs/WifiTrackerLib/res/values-es/strings.xml
+++ b/libs/WifiTrackerLib/res/values-es/strings.xml
@@ -43,9 +43,10 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"No se ha podido acceder al servidor DNS privado"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Conectado al dispositivo. Sin acceso a Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Calidad baja"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (menos segura)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"No permitido por tu organización"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> de <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
-    <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} desde tu teléfono}TABLET{{NETWORK_NAME} desde tu tablet}COMPUTER{{NETWORK_NAME} desde tu ordenador}WATCH{{NETWORK_NAME} desde tu smartwatch}VEHICLE{{NETWORK_NAME} desde tu vehículo}other{{NETWORK_NAME} desde tu dispositivo}}"</string>
+    <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} desde tu teléfono}TABLET{{NETWORK_NAME} desde tu teléfono}COMPUTER{{NETWORK_NAME} desde tu teléfono}WATCH{{NETWORK_NAME} desde tu smartwatch}VEHICLE{{NETWORK_NAME} desde tu smartwatch}other{{NETWORK_NAME} desde tu smartwatch}}"</string>
     <string name="wifitrackerlib_hotspot_network_summary_error_generic" msgid="2339836723160908882">"No se puede conectar. Prueba a conectarte de nuevo."</string>
     <string name="wifitrackerlib_hotspot_network_summary_error_settings" msgid="6928234716406336668">"{DEVICE_TYPE,select, PHONE{No se puede conectar. Comprueba los ajustes del teléfono y vuelve a intentarlo.}TABLET{No se puede conectar. Comprueba los ajustes de la tablet y vuelve a intentarlo.}COMPUTER{No se puede conectar. Comprueba los ajustes del ordenador y vuelve a intentarlo.}WATCH{No se puede conectar. Comprueba los ajustes del reloj y vuelve a intentarlo.}VEHICLE{No se puede conectar. Comprueba los ajustes del vehículo y vuelve a intentarlo.}other{No se puede conectar. Comprueba los ajustes del dispositivo y vuelve a intentarlo.}}"</string>
     <string name="wifitrackerlib_hotspot_network_summary_error_carrier_block" msgid="359780026027619177">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> no permite esta conexión"</string>
@@ -94,6 +95,6 @@
     <string name="wifitrackerlib_wifi_band_5_ghz" msgid="2179047349922091556">"5 GHz"</string>
     <string name="wifitrackerlib_wifi_band_6_ghz" msgid="6532408050869498777">"6 GHz"</string>
     <string name="wifitrackerlib_multiband_separator" msgid="6838172120482590336">", "</string>
-    <string name="wifitrackerlib_link_speed_mbps" msgid="5880214340478706112">"<xliff:g id="LINK_SPEED_MBPS">%1$d</xliff:g> Mb/s"</string>
+    <string name="wifitrackerlib_link_speed_mbps" msgid="5880214340478706112">"<xliff:g id="LINK_SPEED_MBPS">%1$d</xliff:g> Mbps"</string>
     <string name="wifitrackerlib_link_speed_on_band" msgid="2433114336144744962">"<xliff:g id="LINK_SPEED">%1$s</xliff:g> de <xliff:g id="BAND">%2$s</xliff:g>"</string>
 </resources>
diff --git a/libs/WifiTrackerLib/res/values-et/strings.xml b/libs/WifiTrackerLib/res/values-et/strings.xml
index 435af211d..720e35ee0 100644
--- a/libs/WifiTrackerLib/res/values-et/strings.xml
+++ b/libs/WifiTrackerLib/res/values-et/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Privaatsele DNS-serverile ei pääse juurde"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Seadmega ühendatud. Internetiühendust ei saa luua."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Kehva kvaliteediga"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (vähem turvaline)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Teie organisatsioon pole seda lubanud"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> seadmest <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} teie telefonist}TABLET{{NETWORK_NAME} teie tahvelarvutist}COMPUTER{{NETWORK_NAME} teie arvutist}WATCH{{NETWORK_NAME} teie kellast}VEHICLE{{NETWORK_NAME} teie sõidukist}other{{NETWORK_NAME} teie seadmest}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-eu/strings.xml b/libs/WifiTrackerLib/res/values-eu/strings.xml
index 137a79d2f..ed33a4529 100644
--- a/libs/WifiTrackerLib/res/values-eu/strings.xml
+++ b/libs/WifiTrackerLib/res/values-eu/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Ezin da atzitu DNS zerbitzari pribatua"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Gailura konektatuta. Ezin da Interenetarako sarbiderik eman."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Kalitate txikia"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (ez da hain segurua)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Erakundeak ez du baimenik eman"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> (<xliff:g id="MODEL_NAME">%2$s</xliff:g>)"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} telefonoaren bidez}TABLET{{NETWORK_NAME} tabletaren bidez}COMPUTER{{NETWORK_NAME} ordenagailuaren bidez}WATCH{{NETWORK_NAME} erlojuaren bidez}VEHICLE{{NETWORK_NAME} ibilgailuaren bidez}other{{NETWORK_NAME} gailuaren bidez}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-fa/strings.xml b/libs/WifiTrackerLib/res/values-fa/strings.xml
index 8902a4793..f6da59278 100644
--- a/libs/WifiTrackerLib/res/values-fa/strings.xml
+++ b/libs/WifiTrackerLib/res/values-fa/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"دسترسی به سرور ساناد خصوصی ممکن نیست"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"به دستگاه متصل است. نمی‌تواند اینترنت ارائه دهد."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"کیفیت پایین"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"‫<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (امنیت کمتری دارد)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"سازمان شما آن را مجاز نکرده است"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> از <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} از تلفن شما}TABLET{{NETWORK_NAME} از رایانه لوحی شما}COMPUTER{{NETWORK_NAME} از رایانه شما}WATCH{{NETWORK_NAME}از ساعت شما}VEHICLE{{NETWORK_NAME} از خودرو شما}other{{NETWORK_NAME} از دستگاه شما}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-fi/strings.xml b/libs/WifiTrackerLib/res/values-fi/strings.xml
index 86b76b787..995ebc5d2 100644
--- a/libs/WifiTrackerLib/res/values-fi/strings.xml
+++ b/libs/WifiTrackerLib/res/values-fi/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Ei pääsyä yksityiselle DNS-palvelimelle"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Yhdistetty laitteeseen. Ei voi muodostaa internetyhteyttä."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Heikko laatu"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (vähemmän turvallinen)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Ei sallita organisaatiossasi"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> laitteesta <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} puhelimelta}TABLET{{NETWORK_NAME} tabletilta}COMPUTER{{NETWORK_NAME} tietokoneelta}WATCH{{NETWORK_NAME} kellosta}VEHICLE{{NETWORK_NAME} ajoneuvosta}other{{NETWORK_NAME} omalta laitteeltasi}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-fr-rCA/strings.xml b/libs/WifiTrackerLib/res/values-fr-rCA/strings.xml
index 41f79761f..a2f75ad5e 100644
--- a/libs/WifiTrackerLib/res/values-fr-rCA/strings.xml
+++ b/libs/WifiTrackerLib/res/values-fr-rCA/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Impossible d\'accéder au serveur DNS privé"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Connecté à l\'appareil. Aucune connexion Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Faible qualité"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (moins sécurisé)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Non autorisé par votre organisation"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> de <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} à partir de votre téléphone}TABLET{{NETWORK_NAME} à partir de votre tablette}COMPUTER{{NETWORK_NAME} à partir de votre ordinateur}WATCH{{NETWORK_NAME} à partir de votre montre}VEHICLE{{NETWORK_NAME} à partir de votre véhicule}other{{NETWORK_NAME} à partir de votre appareil}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-fr/strings.xml b/libs/WifiTrackerLib/res/values-fr/strings.xml
index 17a33264e..727a7d416 100644
--- a/libs/WifiTrackerLib/res/values-fr/strings.xml
+++ b/libs/WifiTrackerLib/res/values-fr/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Impossible d\'accéder au serveur DNS privé"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Connecté à l\'appareil. Connexion Internet impossible."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Faible qualité"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (moins sécurisé)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Non autorisé par votre organisation"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> (<xliff:g id="MODEL_NAME">%2$s</xliff:g>)"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} sur votre téléphone}TABLET{{NETWORK_NAME} sur votre tablette}COMPUTER{{NETWORK_NAME} sur votre ordinateur}WATCH{{NETWORK_NAME} sur votre montre}VEHICLE{{NETWORK_NAME} dans votre véhicule}other{{NETWORK_NAME} sur votre appareil}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-gl/arrays.xml b/libs/WifiTrackerLib/res/values-gl/arrays.xml
index 83fc931f5..cac987aa9 100644
--- a/libs/WifiTrackerLib/res/values-gl/arrays.xml
+++ b/libs/WifiTrackerLib/res/values-gl/arrays.xml
@@ -26,10 +26,10 @@
     <item msgid="9055468790485684083">"Conectando…"</item>
     <item msgid="6099499723199990208">"Autenticando…"</item>
     <item msgid="6794055951297347103">"Obtendo enderezo IP…"</item>
-    <item msgid="5450920562291300229">"Conectada"</item>
+    <item msgid="5450920562291300229">"Conectado"</item>
     <item msgid="6332116533879646145">"Suspendida"</item>
     <item msgid="294459081501073818">"Desconectando…"</item>
-    <item msgid="1577368920272598676">"Desconectada"</item>
+    <item msgid="1577368920272598676">"Desconectado"</item>
     <item msgid="7655843177582495451">"Produciuse un erro"</item>
     <item msgid="8953752690917593623">"Bloqueada"</item>
     <item msgid="4400457817750243671">"Evitando conexión deficiente temporalmente"</item>
diff --git a/libs/WifiTrackerLib/res/values-gl/strings.xml b/libs/WifiTrackerLib/res/values-gl/strings.xml
index f303d2fe9..e72b83c70 100644
--- a/libs/WifiTrackerLib/res/values-gl/strings.xml
+++ b/libs/WifiTrackerLib/res/values-gl/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Non se puido acceder ao servidor DNS privado"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Estableceuse conexión co dispositivo. Internet non está dispoñible."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Pouca calidade"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (menos segura)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Non permitida pola túa organización"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> de <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} desde o teléfono}TABLET{{NETWORK_NAME} desde a tableta}COMPUTER{{NETWORK_NAME} desde o ordenador}WATCH{{NETWORK_NAME} desde o reloxo}VEHICLE{{NETWORK_NAME} desde o vehículo}other{{NETWORK_NAME} desde o dispositivo}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-gu/strings.xml b/libs/WifiTrackerLib/res/values-gu/strings.xml
index b1769559f..acef9e392 100644
--- a/libs/WifiTrackerLib/res/values-gu/strings.xml
+++ b/libs/WifiTrackerLib/res/values-gu/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"ખાનગી DNS સર્વર ઍક્સેસ કરી શકાતા નથી"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"ડિવાઇસ સાથે કનેક્ટેડ છે. ઇન્ટરનેટ સેવા પ્રદાન કરી શકાતી નથી."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"ઓછી ક્વૉલિટી"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (ઓછું સુરક્ષિત)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"તમારી સંસ્થા દ્વારા મંજૂર નથી"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> તરફથી <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} તમારા ફોન પરથી}TABLET{{NETWORK_NAME} તમારા ટૅબ્લેટ પરથી}COMPUTER{{NETWORK_NAME} તમારા કમ્પ્યૂટર પરથી}WATCH{{NETWORK_NAME} તમારી વૉચ પરથી}VEHICLE{{NETWORK_NAME} તમારા વાહન પરથી}other{{NETWORK_NAME} તમારા ડિવાઇસ પરથી}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-hi/strings.xml b/libs/WifiTrackerLib/res/values-hi/strings.xml
index 983aa6a11..d1cecfc17 100644
--- a/libs/WifiTrackerLib/res/values-hi/strings.xml
+++ b/libs/WifiTrackerLib/res/values-hi/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"निजी डीएनएस सर्वर को ऐक्सेस नहीं किया जा सकता"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"डिवाइस से कनेक्ट है. इंटरनेट सेवा उपलब्ध नहीं है."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"खराब कनेक्शन"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (कम सुरक्षित)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"आपके संगठन ने इसकी अनुमति नहीं दी है"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> से <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{आपके फ़ोन से {NETWORK_NAME} लिया गया है}TABLET{आपके टैबलेट से {NETWORK_NAME} लिया गया है}COMPUTER{आपके कंप्यूटर से {NETWORK_NAME} लिया गया है}WATCH{आपकी स्मार्टवॉच से {NETWORK_NAME} लिया गया है}VEHICLE{आपकी गाड़ी से {NETWORK_NAME} लिया गया है}other{आपके डिवाइस से {NETWORK_NAME} लिया गया है}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-hr/strings.xml b/libs/WifiTrackerLib/res/values-hr/strings.xml
index 8217a5396..85a9c8516 100644
--- a/libs/WifiTrackerLib/res/values-hr/strings.xml
+++ b/libs/WifiTrackerLib/res/values-hr/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Nije moguće pristupiti privatnom DNS poslužitelju"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Uspostavljena je veza s uređajem. Povezivanje s internetom nije moguće."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Niska kvaliteta"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (manje sigurno)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Vaša organizacija ne dopušta upotrebu"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g>, <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} s vašeg telefona}TABLET{{NETWORK_NAME} s vašeg tableta}COMPUTER{{NETWORK_NAME} s vašeg računala}WATCH{{NETWORK_NAME} s vašeg sata}VEHICLE{{NETWORK_NAME} iz vašeg vozila}other{{NETWORK_NAME} s vašeg uređaja}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-hu/strings.xml b/libs/WifiTrackerLib/res/values-hu/strings.xml
index 62ec5a828..9335924f3 100644
--- a/libs/WifiTrackerLib/res/values-hu/strings.xml
+++ b/libs/WifiTrackerLib/res/values-hu/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"A privát DNS-kiszolgálóhoz nem lehet hozzáférni"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Csatlakoztatva az eszközhöz. Nincs internethozzáférés."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Gyenge minőségű"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (kevésbé biztonságos)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Szervezete nem engedélyezte"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> – <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} a telefonjáról}TABLET{{NETWORK_NAME} a táblagépéről}COMPUTER{{NETWORK_NAME} a számítógépéről}WATCH{{NETWORK_NAME} az órájáról}VEHICLE{{NETWORK_NAME} a járművéről}other{{NETWORK_NAME} az eszközéről}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-hy/strings.xml b/libs/WifiTrackerLib/res/values-hy/strings.xml
index 35cacac5b..6cce38b28 100644
--- a/libs/WifiTrackerLib/res/values-hy/strings.xml
+++ b/libs/WifiTrackerLib/res/values-hy/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Մասնավոր DNS սերվերն անհասանելի է"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Միացված է սարքին։ Հնարավոր չէ տրամադրել ինտերնետ կապ։"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Ցածր որակ"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (պակաս անվտանգ)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Թույլատրված չէ ձեր կազմակերպության կողմից"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g>՝ <xliff:g id="MODEL_NAME">%2$s</xliff:g>-ից"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} ձեր հեռախոսից}TABLET{{NETWORK_NAME} ձեր պլանշետից}COMPUTER{{NETWORK_NAME} ձեր համակարգչից}WATCH{{NETWORK_NAME} ձեր ժամացույցից}VEHICLE{{NETWORK_NAME} ձեր մեքենայից}other{{NETWORK_NAME} ձեր սարքից}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-in/strings.xml b/libs/WifiTrackerLib/res/values-in/strings.xml
index f2439a003..cc23f615c 100644
--- a/libs/WifiTrackerLib/res/values-in/strings.xml
+++ b/libs/WifiTrackerLib/res/values-in/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Server DNS pribadi tidak dapat diakses"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Terhubung ke perangkat. Tidak dapat menyediakan koneksi internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Kualitas rendah"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (kurang aman)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Tidak diizinkan oleh organisasi Anda"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> dari <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} dari ponsel Anda}TABLET{{NETWORK_NAME} dari tablet Anda}COMPUTER{{NETWORK_NAME} dari komputer Anda}WATCH{{NETWORK_NAME} dari smartwatch Anda}VEHICLE{{NETWORK_NAME} dari kendaraan Anda}other{{NETWORK_NAME} dari perangkat Anda}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-is/strings.xml b/libs/WifiTrackerLib/res/values-is/strings.xml
index 73e017955..48e84bdde 100644
--- a/libs/WifiTrackerLib/res/values-is/strings.xml
+++ b/libs/WifiTrackerLib/res/values-is/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Ekki næst í DNS-einkaþjón"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Tengt við tæki. Nettenging næst ekki."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Lítil gæði"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (ekki eins öruggt)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Fyrirtækið leyfir þetta ekki"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> frá <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} úr símanum þínum}TABLET{{NETWORK_NAME} úr spjaldtölvunni þinni}COMPUTER{{NETWORK_NAME} úr tölvunni þinni}WATCH{{NETWORK_NAME} úr úrinu þínu}VEHICLE{{NETWORK_NAME} úr ökutækinu þínu}other{{NETWORK_NAME} úr tækinu þínu}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-it/strings.xml b/libs/WifiTrackerLib/res/values-it/strings.xml
index a03c426b5..45c6c3f91 100644
--- a/libs/WifiTrackerLib/res/values-it/strings.xml
+++ b/libs/WifiTrackerLib/res/values-it/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Non è possibile accedere al server DNS privato"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Connessione al dispositivo effettuata. Impossibile accedere a Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Bassa qualità"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (minore sicurezza)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Uso non consentito dall\'organizzazione"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> da <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} dal tuo smartphone}TABLET{{NETWORK_NAME} dal tuo tablet}COMPUTER{{NETWORK_NAME} dal tuo computer}WATCH{{NETWORK_NAME} dal tuo smartwatch}VEHICLE{{NETWORK_NAME} dal tuo veicolo}other{{NETWORK_NAME} dal tuo dispositivo}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-iw/strings.xml b/libs/WifiTrackerLib/res/values-iw/strings.xml
index 2f3c7c1eb..abfa3bb63 100644
--- a/libs/WifiTrackerLib/res/values-iw/strings.xml
+++ b/libs/WifiTrackerLib/res/values-iw/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"‏לא ניתן לגשת לשרת DNS הפרטי"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"יש חיבור למכשיר. לא ניתן לספק חיבור לאינטרנט."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"איכות נמוכה"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"‫<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (פחות מאובטח)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"הארגון שלך לא מתיר את האפשרות הזו"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> מ-<xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} מהטלפון שלך}TABLET{{NETWORK_NAME} מהטאבלט שלך}COMPUTER{{NETWORK_NAME} מהמחשב שלך}WATCH{{NETWORK_NAME} מהשעון שלך}VEHICLE{{NETWORK_NAME} מהרכב שלך}other{{NETWORK_NAME} מהמכשיר שלך}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ja/strings.xml b/libs/WifiTrackerLib/res/values-ja/strings.xml
index be3a27fa1..d3996fc48 100644
--- a/libs/WifiTrackerLib/res/values-ja/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ja/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"プライベート DNS サーバーにアクセスできません"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"デバイスに接続されました。インターネットにアクセスできません。"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"低品質"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g>（安全性: 低）"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"組織によって許可されていません"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> から <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME}（スマートフォン）}TABLET{{NETWORK_NAME}（タブレット）}COMPUTER{{NETWORK_NAME}（パソコン）}WATCH{{NETWORK_NAME}（スマートウォッチ）}VEHICLE{{NETWORK_NAME}（車）}other{{NETWORK_NAME}（デバイス）}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ka/strings.xml b/libs/WifiTrackerLib/res/values-ka/strings.xml
index 8f5cb1bfe..ad2d106f8 100644
--- a/libs/WifiTrackerLib/res/values-ka/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ka/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"პირად DNS სერვერზე წვდომა შეუძლებელია"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"დაუკავშირდა მოწყობილობას. ინტერნეტის მიწოდება ვერ ხერხდება."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"დაბალი ხარისხი"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (ნაკლებად დაცული)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"არ არის დაშვებული თქვენი ორგანიზაციის მიერ"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g>, წყარო: <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} თქვენი ტელეფონიდან}TABLET{{NETWORK_NAME} თქვენი ტაბლეტიდან}COMPUTER{{NETWORK_NAME} თქვენი კომპიუტერიდან}WATCH{{NETWORK_NAME} თქვენი საათიდან}VEHICLE{{NETWORK_NAME} თქვენი მანქანიდან}other{{NETWORK_NAME} თქვენი მოწყობილობიდან}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-kk/arrays.xml b/libs/WifiTrackerLib/res/values-kk/arrays.xml
index 475f9253b..12e7c841e 100644
--- a/libs/WifiTrackerLib/res/values-kk/arrays.xml
+++ b/libs/WifiTrackerLib/res/values-kk/arrays.xml
@@ -26,7 +26,7 @@
     <item msgid="9055468790485684083">"Қосылып жатыр…"</item>
     <item msgid="6099499723199990208">"Растауда…"</item>
     <item msgid="6794055951297347103">"IP мекенжайы алынуда…"</item>
-    <item msgid="5450920562291300229">"Жалғанды"</item>
+    <item msgid="5450920562291300229">"Қосылды"</item>
     <item msgid="6332116533879646145">"Уақытша ажыратылды"</item>
     <item msgid="294459081501073818">"Ажыратылуда…"</item>
     <item msgid="1577368920272598676">"Ажыратылды"</item>
diff --git a/libs/WifiTrackerLib/res/values-kk/strings.xml b/libs/WifiTrackerLib/res/values-kk/strings.xml
index 6eca27d63..f66f47adc 100644
--- a/libs/WifiTrackerLib/res/values-kk/strings.xml
+++ b/libs/WifiTrackerLib/res/values-kk/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Жеке DNS серверіне кіру мүмкін емес."</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Құрылғыға қосылды. Интернетке қосылым жоқ."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Төмен сапа"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (қауіпсіздік деңгейі төменірек)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Ұйымыңыз рұқсат етпеген"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> ұсынған <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{Телефондағы {NETWORK_NAME}}TABLET{Планшеттегі {NETWORK_NAME}}COMPUTER{Компьютердегі {NETWORK_NAME}}WATCH{Сағаттағы {NETWORK_NAME}}VEHICLE{Көліктегі {NETWORK_NAME}}other{Құрылғыдағы {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-km/strings.xml b/libs/WifiTrackerLib/res/values-km/strings.xml
index 2660c71a4..2a10fb6f0 100644
--- a/libs/WifiTrackerLib/res/values-km/strings.xml
+++ b/libs/WifiTrackerLib/res/values-km/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"មិនអាច​ចូលប្រើ​ម៉ាស៊ីនមេ DNS ឯកជន​បានទេ"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"បានភ្ជាប់​ជាមួយ​ឧបករណ៍។ មិនអាចផ្ដល់​អ៊ីនធឺណិតបានទេ។"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"គុណភាព​ទាប"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (មិនសូវមានសុវត្ថិភាព)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"មិនបាន​អនុញ្ញាត​ដោយ​ស្ថាប័ន​របស់​អ្នកទេ"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> ពី <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} ពីទូរសព្ទរបស់អ្នក}TABLET{{NETWORK_NAME} ពីថេប្លេតរបស់អ្នក}COMPUTER{{NETWORK_NAME} ពីកុំព្យូទ័ររបស់អ្នក}WATCH{{NETWORK_NAME} ពីនាឡិការបស់អ្នក}VEHICLE{{NETWORK_NAME} ពីយានជំនិះរបស់អ្នក}other{{NETWORK_NAME} ពីឧបករណ៍របស់អ្នក}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-kn/strings.xml b/libs/WifiTrackerLib/res/values-kn/strings.xml
index d8960c79b..f4dd5ba0b 100644
--- a/libs/WifiTrackerLib/res/values-kn/strings.xml
+++ b/libs/WifiTrackerLib/res/values-kn/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"ಖಾಸಗಿ DNS ಸರ್ವರ್ ಅನ್ನು ಪ್ರವೇಶಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"ಸಾಧನಕ್ಕೆ ಕನೆಕ್ಟ್ ಮಾಡಲಾಗಿದೆ. ಇಂಟರ್ನೆಟ್ ಸಂಪರ್ಕ ಒದಗಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"ಕಳಪೆ ಕನೆಕ್ಷನ್"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (ಕಡಿಮೆ ಸುರಕ್ಷಿತ)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"ನಿಮ್ಮ ಸಂಸ್ಥೆಯಿಂದ ಅನುಮತಿಸಲಾಗಿಲ್ಲ"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> ನಿಂದ <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{ನಿಮ್ಮ ಫೋನ್‌ನಿಂದ {NETWORK_NAME}}TABLET{ನಿಮ್ಮ ಟ್ಯಾಬ್ಲೆಟ್‌ನಿಂದ {NETWORK_NAME}}COMPUTER{ನಿಮ್ಮ ಕಂಪ್ಯೂಟರ್‌ನಿಂದ {NETWORK_NAME}}WATCH{ನಿಮ್ಮ ವಾಚ್‌ನಿಂದ {NETWORK_NAME}}VEHICLE{ನಿಮ್ಮ ವಾಹನದಿಂದ {NETWORK_NAME}}other{ನಿಮ್ಮ ಸಾಧನದಿಂದ {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ko/strings.xml b/libs/WifiTrackerLib/res/values-ko/strings.xml
index 84892c8ad..3d78a8789 100644
--- a/libs/WifiTrackerLib/res/values-ko/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ko/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"비공개 DNS 서버에 액세스할 수 없음"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"기기에 연결되었습니다. 인터넷을 이용할 수 없습니다."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"품질 낮음"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g>(보안 수준 낮음)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"조직에서 허용하지 않음"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g>의 <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{휴대전화의 {NETWORK_NAME}}TABLET{태블릿의 {NETWORK_NAME}}COMPUTER{컴퓨터의 {NETWORK_NAME}}WATCH{시계의 {NETWORK_NAME}}VEHICLE{차량의 {NETWORK_NAME}}other{기기의 {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ky/strings.xml b/libs/WifiTrackerLib/res/values-ky/strings.xml
index ba610e38d..c82832ac9 100644
--- a/libs/WifiTrackerLib/res/values-ky/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ky/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Жеке DNS сервери жеткиликсиз"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Түзмөккө туташып турат. Интернет жок."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Начар сапат"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (коопсуздук деңгээли төмөнүрөөк)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Уюмуңуз тыюу салган"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g>–<xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{Телефонуңуздагы {NETWORK_NAME} тармагы}TABLET{Планшетиңиздеги {NETWORK_NAME} тармагы}COMPUTER{Компьютериңиздеги {NETWORK_NAME} тармагы}WATCH{Саатыңыздагы {NETWORK_NAME} тармагы}VEHICLE{Унааңыздагы {NETWORK_NAME} тармагы}other{Түзмөгүңүздөгү {NETWORK_NAME} тармагы}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-lo/strings.xml b/libs/WifiTrackerLib/res/values-lo/strings.xml
index 64f05b7af..6c28d45b7 100644
--- a/libs/WifiTrackerLib/res/values-lo/strings.xml
+++ b/libs/WifiTrackerLib/res/values-lo/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"ບໍ່ສາມາດເຂົ້າເຖິງເຊີບເວີ DNS ສ່ວນຕົວໄດ້"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"ເຊື່ອມຕໍ່ຫາອຸປະກອນແລ້ວ. ບໍ່ສາມາດໃຫ້ບໍລິການອິນເຕີເນັດໄດ້."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"ຄຸນນະພາບຕໍ່າ"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (ປອດໄພໜ້ອຍກວ່າ)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"ອົງການຂອງທ່ານບໍ່ອະນຸຍາດ"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> ຈາກ <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} ຈາກໂທລະສັບຂອງທ່ານ}TABLET{{NETWORK_NAME} ຈາກແທັບເລັດຂອງທ່ານ}COMPUTER{{NETWORK_NAME} ຈາກຄອມພິວເຕີຂອງທ່ານ}WATCH{{NETWORK_NAME} ຈາກໂມງຂອງທ່ານ}VEHICLE{{NETWORK_NAME} ຈາກລົດຂອງທ່ານ}other{{NETWORK_NAME} ຈາກອຸປະກອນຂອງທ່ານ}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-lt/strings.xml b/libs/WifiTrackerLib/res/values-lt/strings.xml
index 372e13efb..4d48cc907 100644
--- a/libs/WifiTrackerLib/res/values-lt/strings.xml
+++ b/libs/WifiTrackerLib/res/values-lt/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Privataus DNS serverio negalima pasiekti"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Prisijungta prie įrenginio. Nepavyksta prisijungti prie interneto."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Prastas ryšys"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (mažiau saugu)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Jūsų organizacijoje neleidžiama"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"„<xliff:g id="NETWORK_NAME">%1$s</xliff:g>“ iš „<xliff:g id="MODEL_NAME">%2$s</xliff:g>“"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{„{NETWORK_NAME}“ iš telefono}TABLET{„{NETWORK_NAME}“ iš planšetinio kompiuterio}COMPUTER{„{NETWORK_NAME}“ iš kompiuterio}WATCH{„{NETWORK_NAME}“ iš laikrodžio}VEHICLE{„{NETWORK_NAME}“ iš transporto priemonės}other{„{NETWORK_NAME}“ iš įrenginio}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-lv/strings.xml b/libs/WifiTrackerLib/res/values-lv/strings.xml
index 0f76ef15d..544ec0717 100644
--- a/libs/WifiTrackerLib/res/values-lv/strings.xml
+++ b/libs/WifiTrackerLib/res/values-lv/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Nevar piekļūt privātam DNS serverim."</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Izveidots savienojums ar ierīci. Nav piekļuves internetam."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Zema kvalitāte"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (mazāk drošs)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Jūsu organizācija to neatļauj"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> no <xliff:g id="MODEL_NAME">%2$s</xliff:g> ierīces"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} no jūsu tālruņa}TABLET{{NETWORK_NAME} no jūsu planšetdatora}COMPUTER{{NETWORK_NAME} no jūsu datora}WATCH{{NETWORK_NAME} no jūsu pulksteņa}VEHICLE{{NETWORK_NAME} no jūsu transportlīdzekļa}other{{NETWORK_NAME} no jūsu ierīces}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-mk/strings.xml b/libs/WifiTrackerLib/res/values-mk/strings.xml
index 280fffe48..20c815e4f 100644
--- a/libs/WifiTrackerLib/res/values-mk/strings.xml
+++ b/libs/WifiTrackerLib/res/values-mk/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Не може да се пристапи до приватниот DNS-сервер"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Поврзано со уредот. Не може да се обезбеди интернет."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Лош квалитет"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (помалку безбедно)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Не е дозволено од вашата организација"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> од <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} од вашиот телефон}TABLET{{NETWORK_NAME} од вашиот таблет}COMPUTER{{NETWORK_NAME} од вашиот компјутер}WATCH{{NETWORK_NAME} од вашиот часовник}VEHICLE{{NETWORK_NAME} од вашето возило}other{{NETWORK_NAME} од вашиот уред}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ml/strings.xml b/libs/WifiTrackerLib/res/values-ml/strings.xml
index d9dc8df48..ffac2ceba 100644
--- a/libs/WifiTrackerLib/res/values-ml/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ml/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"സ്വകാര്യ DNS സെർവർ ആക്‌സസ് ചെയ്യാനാവുന്നില്ല"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"ഉപകരണത്തിലേക്ക് കണക്റ്റ് ചെയ്‌തു. ഇന്റർനെറ്റ് നൽകാനാകില്ല."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"കുറഞ്ഞ നിലവാരം"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (സുരക്ഷ കുറഞ്ഞത്)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"നിങ്ങളുടെ ഓർഗനൈസേഷൻ അനുവദിക്കുന്നില്ല"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> എന്നതിൽ നിന്നുള്ള <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{നിങ്ങളുടെ ഫോണിൽ നിന്നുള്ള {NETWORK_NAME}}TABLET{നിങ്ങളുടെ ടാബ്‌ലെറ്റിൽ നിന്നുള്ള {NETWORK_NAME}}COMPUTER{നിങ്ങളുടെ കമ്പ്യൂട്ടറിൽ നിന്നുള്ള {NETWORK_NAME}}WATCH{നിങ്ങളുടെ വാച്ചിൽ നിന്നുള്ള {NETWORK_NAME}}VEHICLE{നിങ്ങളുടെ വാഹനത്തിൽ നിന്നുള്ള {NETWORK_NAME}}other{നിങ്ങളുടെ ഉപകരണത്തിൽ നിന്നുള്ള {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-mn/strings.xml b/libs/WifiTrackerLib/res/values-mn/strings.xml
index 517f2faaf..bfa4e6f15 100644
--- a/libs/WifiTrackerLib/res/values-mn/strings.xml
+++ b/libs/WifiTrackerLib/res/values-mn/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Хувийн DNS серверт хандах боломжгүй байна"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Төхөөрөмжид холбогдсон байна. Интернэт олгох боломжгүй."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Чанар муу"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (хамгаалалт бага)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Танай байгууллагаас зөвшөөрдөггүй"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g>-с ирсэн <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{Таны утасны {NETWORK_NAME}}TABLET{Таны таблетын {NETWORK_NAME}}COMPUTER{Таны компьютерын {NETWORK_NAME}}WATCH{Таны цагны {NETWORK_NAME}}VEHICLE{Таны тээврийн хэрэгслийн {NETWORK_NAME}}other{Таны төхөөрөмжийн {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-mr/strings.xml b/libs/WifiTrackerLib/res/values-mr/strings.xml
index 9590a084d..630e802eb 100644
--- a/libs/WifiTrackerLib/res/values-mr/strings.xml
+++ b/libs/WifiTrackerLib/res/values-mr/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"खाजगी DNS सर्व्हर ॲक्सेस करू शकत नाही"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"डिव्हाइसशी कनेक्ट केले. इंटरनेट उपलब्ध नाही."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"कमी गुणवत्ता"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (कमी सुरक्षित)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"तुमच्या संस्थेने अनुमती दिलेली नाही"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> वरील <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{तुमच्या फोनवरून {NETWORK_NAME}}TABLET{तुमच्या टॅबलेटवरून {NETWORK_NAME}}COMPUTER{तुमच्या काँप्युटरवरून {NETWORK_NAME}}WATCH{तुमच्या वॉचवरून {NETWORK_NAME}}VEHICLE{तुमच्या वाहनावरून {NETWORK_NAME}}other{तुमच्या डिव्हाइसवरून {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ms/strings.xml b/libs/WifiTrackerLib/res/values-ms/strings.xml
index f96f5d2f6..5f1c4fa05 100644
--- a/libs/WifiTrackerLib/res/values-ms/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ms/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Pelayan DNS peribadi tidak boleh diakses"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Disambungkan pada peranti. Tidak dapat menyediakan Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Kualiti rendah"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (kurang selamat)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Tidak dibenarkan oleh organisasi anda"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> daripada <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} daripada telefon anda}TABLET{{NETWORK_NAME} daripada tablet anda}COMPUTER{{NETWORK_NAME} daripada komputer anda}WATCH{{NETWORK_NAME} daripada jam tangan anda}VEHICLE{{NETWORK_NAME} daripada kenderaan anda}other{{NETWORK_NAME} daripada peranti anda}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-my/strings.xml b/libs/WifiTrackerLib/res/values-my/strings.xml
index 5793797a7..9b32fe4a4 100644
--- a/libs/WifiTrackerLib/res/values-my/strings.xml
+++ b/libs/WifiTrackerLib/res/values-my/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"သီးသန့် ဒီအန်အက်စ် (DNS) ဆာဗာကို သုံး၍မရပါ"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"စက်ပစ္စည်းသို့ ချိတ်ဆက်ထားသည်။ အင်တာနက်ကို မပေးနိုင်ပါ။"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"အရည်အသွေး နိမ့်သည်"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (သိပ်မလုံခြုံပါ)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"သင်၏အဖွဲ့အစည်းက ခွင့်မပြုပါ"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> ထံမှ <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{သင့်ဖုန်းမှ {NETWORK_NAME}}TABLET{သင့်တက်ဘလက်မှ {NETWORK_NAME}}COMPUTER{သင့်ကွန်ပျူတာမှ {NETWORK_NAME}}WATCH{သင့်လက်ပတ်နာရီမှ {NETWORK_NAME}}VEHICLE{သင့်ယာဉ်မှ {NETWORK_NAME}}other{သင့်စက်ပစ္စည်းမှ {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-nb/strings.xml b/libs/WifiTrackerLib/res/values-nb/strings.xml
index d387d895d..c5a6976ee 100644
--- a/libs/WifiTrackerLib/res/values-nb/strings.xml
+++ b/libs/WifiTrackerLib/res/values-nb/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Den private DNS-tjeneren kan ikke nås"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Koblet til enheten. Kan ikke gi internettilgang."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Lav kvalitet"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (mindre sikker)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Ikke tillatt av organisasjonen din"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> fra <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} fra telefonen}TABLET{{NETWORK_NAME} fra nettbrettet}COMPUTER{{NETWORK_NAME} fra datamaskinen}WATCH{{NETWORK_NAME} fra klokken}VEHICLE{{NETWORK_NAME} fra kjøretøyet}other{{NETWORK_NAME} fra enheten}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ne/strings.xml b/libs/WifiTrackerLib/res/values-ne/strings.xml
index 421380d37..fa9bd618a 100644
--- a/libs/WifiTrackerLib/res/values-ne/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ne/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"निजी DNS सर्भरमाथि पहुँच राख्न सकिँदैन"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"डिभाइसमा कनेक्ट गरियो। इन्टरनेट उपलब्ध छैन।"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"न्यून गुणस्तर"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (कम सुरक्षित)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"तपाईंको सङ्गठनले अनुमति दिएको छैन"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> को <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{तपाईंको फोनबाट: {NETWORK_NAME}}TABLET{तपाईंको ट्याब्लेटबाट: {NETWORK_NAME}}COMPUTER{तपाईंको कम्प्युटरबाट: {NETWORK_NAME}}WATCH{तपाईंको स्मार्ट वाचबाट: {NETWORK_NAME}}VEHICLE{तपाईंको गाडीबाट: {NETWORK_NAME}}other{तपाईंको डिभाइसबाट: {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-nl/strings.xml b/libs/WifiTrackerLib/res/values-nl/strings.xml
index 8e9c9bac4..e4b1db4db 100644
--- a/libs/WifiTrackerLib/res/values-nl/strings.xml
+++ b/libs/WifiTrackerLib/res/values-nl/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Geen toegang tot privé-DNS-server"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Verbonden met apparaat. Kan geen internet bieden."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Lage kwaliteit"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (minder goed beveiligd)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Niet toegestaan door je organisatie"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> van <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} op je telefoon}TABLET{{NETWORK_NAME} op je tablet}COMPUTER{{NETWORK_NAME} op je computer}WATCH{{NETWORK_NAME} op je smartwatch}VEHICLE{{NETWORK_NAME} via je voertuig}other{{NETWORK_NAME} op je apparaat}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-or/strings.xml b/libs/WifiTrackerLib/res/values-or/strings.xml
index 7b7c3d035..cedd77988 100644
--- a/libs/WifiTrackerLib/res/values-or/strings.xml
+++ b/libs/WifiTrackerLib/res/values-or/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"ବ୍ୟକ୍ତିଗତ DNS ସର୍ଭରକୁ ଆକ୍ସେସ୍ କରାଯାଇପାରିବ ନାହିଁ"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"ଡିଭାଇସ୍ ସହ ସଂଯୋଗ କରାଯାଇଛି। ଇଣ୍ଟରନେଟ୍ ପ୍ରଦାନ କରାଯାଇପାରିବ ନାହିଁ।"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"ନିମ୍ନ ଗୁଣବତ୍ତା"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (କମ ସୁରକ୍ଷିତ)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"ଆପଣଙ୍କ ସଂସ୍ଥା ଦ୍ୱାରା ଅନୁମତି ଦିଆଯାଏ ନାହିଁ"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g>ରୁ <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{ଆପଣଙ୍କ ଫୋନରୁ {NETWORK_NAME}}TABLET{ଆପଣଙ୍କ ଟାବଲେଟରୁ {NETWORK_NAME}}COMPUTER{ଆପଣଙ୍କ କମ୍ପ୍ୟୁଟରରୁ {NETWORK_NAME}}WATCH{ଆପଣଙ୍କ ୱାଚରୁ {NETWORK_NAME}}VEHICLE{ଆପଣଙ୍କ ଗାଡ଼ିରୁ {NETWORK_NAME}}other{ଆପଣଙ୍କ ଡିଭାଇସରୁ {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-pa/strings.xml b/libs/WifiTrackerLib/res/values-pa/strings.xml
index 67268b239..9fbc72b95 100644
--- a/libs/WifiTrackerLib/res/values-pa/strings.xml
+++ b/libs/WifiTrackerLib/res/values-pa/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"ਨਿੱਜੀ DNS ਸਰਵਰ \'ਤੇ ਪਹੁੰਚ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"ਡੀਵਾਈਸ ਨਾਲ ਕਨੈਕਟ ਕੀਤਾ ਗਿਆ। ਇੰਟਰਨੈੱਟ ਮੁਹੱਈਆ ਨਹੀਂ ਹੋ ਸਕਦਾ।"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"ਠੀਕ-ਠਾਕ ਕਨੈਕਸ਼ਨ"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (ਘੱਟ ਸੁਰੱਖਿਅਤ)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"ਤੁਹਾਡੀ ਸੰਸਥਾ ਵੱਲੋਂ ਇਸਦੀ ਆਗਿਆ ਨਹੀਂ ਦਿੱਤੀ ਗਈ"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> ਤੋਂ <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{ਤੁਹਾਡੇ ਫ਼ੋਨ ਤੋਂ {NETWORK_NAME}}TABLET{ਤੁਹਾਡੇ ਟੈਬਲੈੱਟ ਤੋਂ {NETWORK_NAME}}COMPUTER{ਤੁਹਾਡੇ ਕੰਪਿਊਟਰ ਤੋਂ {NETWORK_NAME}}WATCH{ਤੁਹਾਡੀ ਘੜੀ ਤੋਂ {NETWORK_NAME}}VEHICLE{ਤੁਹਾਡੇ ਵਾਹਨ ਤੋਂ {NETWORK_NAME}}other{ਤੁਹਾਡੇ ਡੀਵਾਈਸ ਤੋਂ {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-pl/strings.xml b/libs/WifiTrackerLib/res/values-pl/strings.xml
index 3b683c219..0b6024a36 100644
--- a/libs/WifiTrackerLib/res/values-pl/strings.xml
+++ b/libs/WifiTrackerLib/res/values-pl/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Brak dostępu do prywatnego serwera DNS"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Podłączono do urządzenia. Nie można zapewnić dostępu do internetu."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Niska jakość"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (mniej bezpieczna)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Niedozwolone przez Twoją organizację"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> z urządzenia <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} z Twojego telefonu}TABLET{{NETWORK_NAME} z Twojego tabletu}COMPUTER{{NETWORK_NAME} z Twojego komputera}WATCH{{NETWORK_NAME} z Twojego zegarka}VEHICLE{{NETWORK_NAME} z Twojego pojazdu}other{{NETWORK_NAME} z Twojego urządzenia}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-pt-rBR/strings.xml b/libs/WifiTrackerLib/res/values-pt-rBR/strings.xml
index 02c9030b2..bfaa05265 100644
--- a/libs/WifiTrackerLib/res/values-pt-rBR/strings.xml
+++ b/libs/WifiTrackerLib/res/values-pt-rBR/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Não é possível acessar o servidor DNS particular"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Conectada ao dispositivo. Sem acesso à Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Conexão lenta"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (menos segurança)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Não permitido por sua organização"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> do <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} do smartphone}TABLET{{NETWORK_NAME} do tablet}COMPUTER{{NETWORK_NAME} do computador}WATCH{{NETWORK_NAME} do relógio}VEHICLE{{NETWORK_NAME} do veículo}other{{NETWORK_NAME} do dispositivo}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-pt-rPT/strings.xml b/libs/WifiTrackerLib/res/values-pt-rPT/strings.xml
index 708f77ca0..4259a30c2 100644
--- a/libs/WifiTrackerLib/res/values-pt-rPT/strings.xml
+++ b/libs/WifiTrackerLib/res/values-pt-rPT/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Não é possível aceder ao servidor DNS privado."</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Ligado ao dispositivo. Não é possível disponibilizar Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Baixa qualidade"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (menos seguro)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Não é permitido pela sua organização"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> de <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} a partir do telemóvel}TABLET{{NETWORK_NAME} a partir do tablet}COMPUTER{{NETWORK_NAME} a partir do computador}WATCH{{NETWORK_NAME} a partir do relógio}VEHICLE{{NETWORK_NAME} a partir do veículo}other{{NETWORK_NAME} a partir do dispositivo}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-pt/strings.xml b/libs/WifiTrackerLib/res/values-pt/strings.xml
index 02c9030b2..bfaa05265 100644
--- a/libs/WifiTrackerLib/res/values-pt/strings.xml
+++ b/libs/WifiTrackerLib/res/values-pt/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Não é possível acessar o servidor DNS particular"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Conectada ao dispositivo. Sem acesso à Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Conexão lenta"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (menos segurança)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Não permitido por sua organização"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> do <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} do smartphone}TABLET{{NETWORK_NAME} do tablet}COMPUTER{{NETWORK_NAME} do computador}WATCH{{NETWORK_NAME} do relógio}VEHICLE{{NETWORK_NAME} do veículo}other{{NETWORK_NAME} do dispositivo}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ro/strings.xml b/libs/WifiTrackerLib/res/values-ro/strings.xml
index 1fb512481..8e789b4cf 100644
--- a/libs/WifiTrackerLib/res/values-ro/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ro/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Serverul DNS privat nu poate fi accesat"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"S-a conectat la dispozitiv. Nu se poate stabili o conexiune la internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Calitate slabă"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (mai puțin sigur)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Nu este acceptată de organizația ta"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> de la <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} de pe telefon}TABLET{{NETWORK_NAME} de pe tabletă}COMPUTER{{NETWORK_NAME} de pe computer}WATCH{{NETWORK_NAME} de pe ceas}VEHICLE{{NETWORK_NAME} din mașină}other{{NETWORK_NAME} de pe dispozitiv}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ru/strings.xml b/libs/WifiTrackerLib/res/values-ru/strings.xml
index 12c0c4fc0..d9ca45ff6 100644
--- a/libs/WifiTrackerLib/res/values-ru/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ru/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Доступа к частному DNS-серверу нет"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Подключено к устройству. Нет доступа к интернету."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"низкое качество"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (менее надежная защита)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Запрещено системным администратором"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"Сеть \"<xliff:g id="NETWORK_NAME">%1$s</xliff:g>\", устройство <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{Сеть \"{NETWORK_NAME}\" на телефоне}TABLET{Сеть \"{NETWORK_NAME}\" на планшете}COMPUTER{Сеть \"{NETWORK_NAME}\" на компьютере}WATCH{Сеть \"{NETWORK_NAME}\" на часах}VEHICLE{Сеть \"{NETWORK_NAME}\" в автомобиле}other{Сеть \"{NETWORK_NAME}\" на устройстве}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-si/strings.xml b/libs/WifiTrackerLib/res/values-si/strings.xml
index 7e1988c39..5566c5cba 100644
--- a/libs/WifiTrackerLib/res/values-si/strings.xml
+++ b/libs/WifiTrackerLib/res/values-si/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"පුද්ගලික DNS සේවාදායකයට ප්‍රවේශ වීමට නොහැකිය"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"උපාංගයට සම්බන්ධයි. අන්තර්ජාලය සැපයීමට නොහැකිය."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"අඩු ගුණත්වය"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (අඩුවෙන් සුරක්ෂිත)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"ඔබගේ සංවිධානය විසින් ඉඩ නොදේ"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> සිට <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{ඔබේ දුරකථනයෙන් {NETWORK_NAME}}TABLET{ඔබේ ටැබ්ලටයෙන් {NETWORK_NAME}}COMPUTER{ඔබේ පරිගණකයෙන් {NETWORK_NAME}}WATCH{ඔබේ ඔරලෝසුවෙන් {NETWORK_NAME}}VEHICLE{ඔබේ වාහනයෙන් {NETWORK_NAME}}other{ඔබේ උපාංගයෙන් {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-sk/strings.xml b/libs/WifiTrackerLib/res/values-sk/strings.xml
index ddb36b820..95923a881 100644
--- a/libs/WifiTrackerLib/res/values-sk/strings.xml
+++ b/libs/WifiTrackerLib/res/values-sk/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"K súkromnému serveru DNS sa nepodarilo získať prístup"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Pripojené k zariadeniu. Internet nie je možné poskytnúť."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Nízka kvalita"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (menej zabezpečené)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Nie je povolené vašou organizáciou"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> zariadenia <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} z telefónu}TABLET{{NETWORK_NAME} z tabletu}COMPUTER{{NETWORK_NAME} z počítača}WATCH{{NETWORK_NAME} z hodiniek}VEHICLE{{NETWORK_NAME} z vozidla}other{{NETWORK_NAME} zo zariadenia}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-sl/strings.xml b/libs/WifiTrackerLib/res/values-sl/strings.xml
index ebe8bc2c0..c3de4d84c 100644
--- a/libs/WifiTrackerLib/res/values-sl/strings.xml
+++ b/libs/WifiTrackerLib/res/values-sl/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Do zasebnega strežnika DNS ni mogoče dostopati"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Povezava z napravo je vzpostavljena. Dostop do interneta ni na voljo."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Nizka kakovost"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (manj varno)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Organizacija tega ne dovoljuje."</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"Omrežje <xliff:g id="NETWORK_NAME">%1$s</xliff:g> (<xliff:g id="MODEL_NAME">%2$s</xliff:g>)"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} iz vašega telefona}TABLET{{NETWORK_NAME} iz vašega tabličnega računalnika}COMPUTER{{NETWORK_NAME} iz vašega računalnika}WATCH{{NETWORK_NAME} iz vaše ure}VEHICLE{{NETWORK_NAME} iz vašega vozila}other{{NETWORK_NAME} iz vaše naprave}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-sq/strings.xml b/libs/WifiTrackerLib/res/values-sq/strings.xml
index d6e4a557a..21dddb106 100644
--- a/libs/WifiTrackerLib/res/values-sq/strings.xml
+++ b/libs/WifiTrackerLib/res/values-sq/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Nuk mund të qasesh në serverin privat DNS"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"U lidh me pajisjen. Interneti nuk mund të ofrohet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Cilësi e ulët"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (më pak i sigurt)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Nuk lejohet nga organizata jote"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> nga <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} nga telefoni yt}TABLET{{NETWORK_NAME} nga tableti yt}COMPUTER{{NETWORK_NAME} nga kompjuteri yt}WATCH{{NETWORK_NAME} nga ora jote}VEHICLE{{NETWORK_NAME} nga automjeti yt}other{{NETWORK_NAME} nga pajisja jote}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-sr/strings.xml b/libs/WifiTrackerLib/res/values-sr/strings.xml
index a597d56bd..9ddc1ff77 100644
--- a/libs/WifiTrackerLib/res/values-sr/strings.xml
+++ b/libs/WifiTrackerLib/res/values-sr/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Приступ приватном DNS серверу није успео"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Уређај је повезан. Пружање интернета није успело."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Лош квалитет"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (мање безбедно)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Не дозвољава ваша организација"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> – <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} са телефона}TABLET{{NETWORK_NAME} са таблета}COMPUTER{{NETWORK_NAME} са рачунара}WATCH{{NETWORK_NAME} са сата}VEHICLE{{NETWORK_NAME} са возила}other{{NETWORK_NAME} са уређаја}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-sv/strings.xml b/libs/WifiTrackerLib/res/values-sv/strings.xml
index 7e9e2d08c..1ae142a2c 100644
--- a/libs/WifiTrackerLib/res/values-sv/strings.xml
+++ b/libs/WifiTrackerLib/res/values-sv/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Det går inte att komma åt den privata DNS-servern."</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Ansluten till enheten. Det går inte att ansluta till internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Låg kvalitet"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (mindre säker)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Tillåts inte av din organisation"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> från <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} från telefonen}TABLET{{NETWORK_NAME} från surfplattan}COMPUTER{{NETWORK_NAME} från datorn}WATCH{{NETWORK_NAME} från klockan}VEHICLE{{NETWORK_NAME} från fordonet}other{{NETWORK_NAME} från enheten}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-sw/strings.xml b/libs/WifiTrackerLib/res/values-sw/strings.xml
index cbe7c1138..18f02bddd 100644
--- a/libs/WifiTrackerLib/res/values-sw/strings.xml
+++ b/libs/WifiTrackerLib/res/values-sw/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Seva ya faragha ya DNS haiwezi kufikiwa"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Kifaa kimeunganishwa. Imeshindwa kusambaza intaneti."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Ubora wa chini"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (si salama sana)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Shirika lako haliruhusu"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> kutoka kwenye <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} kutoka kwenye simu yako}TABLET{{NETWORK_NAME} kutoka kwenye kishikwambi chako}COMPUTER{{NETWORK_NAME} kutoka kwenye kompyuta yako}WATCH{{NETWORK_NAME} kutoka kwenye saa yako}VEHICLE{{NETWORK_NAME} kutoka kwenye gari lako}other{{NETWORK_NAME} kutoka kwenye kifaa chako}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ta/strings.xml b/libs/WifiTrackerLib/res/values-ta/strings.xml
index ab3271e5b..5f7ca6513 100644
--- a/libs/WifiTrackerLib/res/values-ta/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ta/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"தனிப்பட்ட DNS சேவையகத்தை அணுக இயலாது"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"சாதனத்துடன் இணைக்கப்பட்டது. இணைய இணைப்பு இல்லை."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"குறைந்த தரம்"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (குறைந்த பாதுகாப்பு)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"உங்கள் நிறுவனத்தால் அனுமதிக்கப்படவில்லை"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> வழங்கும் <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{உங்கள் மொபைலில் இருந்து {NETWORK_NAME}}TABLET{உங்கள் டேப்லெட்டில் இருந்து {NETWORK_NAME}}COMPUTER{உங்கள் கம்ப்யூட்டரில் இருந்து {NETWORK_NAME}}WATCH{உங்கள் வாட்ச்சில் இருந்து {NETWORK_NAME}}VEHICLE{உங்கள் வாகனத்தில் இருந்து {NETWORK_NAME}}other{உங்கள் சாதனத்தில் இருந்து {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-te/strings.xml b/libs/WifiTrackerLib/res/values-te/strings.xml
index 3569e3264..7b6553a0d 100644
--- a/libs/WifiTrackerLib/res/values-te/strings.xml
+++ b/libs/WifiTrackerLib/res/values-te/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"ప్రైవేట్ DNS సర్వర్‌ను యాక్సెస్ చేయడం సాధ్యపడదు"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"పరికరానికి కనెక్ట్ అయింది. ఇంటర్నెట్‌ను అందిచడం సాధ్యం కాదు."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"తక్కువ క్వాలిటీ"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (తక్కువ సురక్షితమైనది)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"మీ సంస్థచే అనుమతించబడదు"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> నుండి <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{మీ ఫోన్ నుండి {NETWORK_NAME}}TABLET{మీ టాబ్లెట్ నుండి {NETWORK_NAME}}COMPUTER{మీ కంప్యూటర్ నుండి {NETWORK_NAME}}WATCH{మీ వాచ్ నుండి {NETWORK_NAME}}VEHICLE{మీ వెహికల్‌ నుండి {NETWORK_NAME}}other{మీ పరికరం నుండి {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-th/strings.xml b/libs/WifiTrackerLib/res/values-th/strings.xml
index 6728de040..0b82871d4 100644
--- a/libs/WifiTrackerLib/res/values-th/strings.xml
+++ b/libs/WifiTrackerLib/res/values-th/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"เข้าถึงเซิร์ฟเวอร์ DNS ส่วนตัวไม่ได้"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"เชื่อมต่ออุปกรณ์แล้ว แต่ไม่มีอินเทอร์เน็ต"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"คุณภาพต่ำ"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (ปลอดภัยน้อยกว่า)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"องค์กรของคุณไม่อนุญาต"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> จาก <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} จากโทรศัพท์ของคุณ}TABLET{{NETWORK_NAME} จากแท็บเล็ตของคุณ}COMPUTER{{NETWORK_NAME} จากคอมพิวเตอร์ของคุณ}WATCH{{NETWORK_NAME} จากนาฬิกาของคุณ}VEHICLE{{NETWORK_NAME} จากรถของคุณ}other{{NETWORK_NAME} จากอุปกรณ์ของคุณ}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-tl/strings.xml b/libs/WifiTrackerLib/res/values-tl/strings.xml
index 1351308d3..d1f6f3d72 100644
--- a/libs/WifiTrackerLib/res/values-tl/strings.xml
+++ b/libs/WifiTrackerLib/res/values-tl/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Hindi ma-access ang pribadong DNS server"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Nakakonekta sa device. Hindi makapagbigay ng internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Mababang kalidad"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (mas hindi secure)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Hindi pinapayagan ng iyong organisasyon"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> mula sa <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} mula sa telepono mo}TABLET{{NETWORK_NAME} mula sa tablet mo}COMPUTER{{NETWORK_NAME} mula sa computer mo}WATCH{{NETWORK_NAME} mula sa relo mo}VEHICLE{{NETWORK_NAME} mula sa sasakyan mo}other{{NETWORK_NAME} mula sa device mo}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-tr/strings.xml b/libs/WifiTrackerLib/res/values-tr/strings.xml
index 611330844..f97a60590 100644
--- a/libs/WifiTrackerLib/res/values-tr/strings.xml
+++ b/libs/WifiTrackerLib/res/values-tr/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Gizli DNS sunucusuna erişilemiyor"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Cihaza bağlandı. İnternet bağlantısı sağlanamıyor."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Düşük kalite"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (daha az güvenli)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Kuruluşunuz tarafından izin verilmiyor"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> kaynağından <xliff:g id="NETWORK_NAME">%1$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{Telefonunuzdaki {NETWORK_NAME}}TABLET{Tabletinizdeki {NETWORK_NAME}}COMPUTER{Bilgisayarınızdaki {NETWORK_NAME}}WATCH{Kol saatinizdeki {NETWORK_NAME}}VEHICLE{Aracınızdaki {NETWORK_NAME}}other{Cihazınızdaki {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-uk/strings.xml b/libs/WifiTrackerLib/res/values-uk/strings.xml
index 9094e718c..59e9ec712 100644
--- a/libs/WifiTrackerLib/res/values-uk/strings.xml
+++ b/libs/WifiTrackerLib/res/values-uk/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Немає доступу до приватного DNS-сервера"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Підключено до пристрою. Інтернет-з\'єднання відсутнє."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Низька якість"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (менш захищене з’єднання)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Заборонено у вашій організації"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> з пристрою <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} з вашого телефона}TABLET{{NETWORK_NAME} з вашого планшета}COMPUTER{{NETWORK_NAME} з вашого комп’ютера}WATCH{{NETWORK_NAME} з вашого годинника}VEHICLE{{NETWORK_NAME} з вашого автомобіля}other{{NETWORK_NAME} з вашого пристрою}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-ur/strings.xml b/libs/WifiTrackerLib/res/values-ur/strings.xml
index dd10fe500..9ea9fffc6 100644
--- a/libs/WifiTrackerLib/res/values-ur/strings.xml
+++ b/libs/WifiTrackerLib/res/values-ur/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"‏نجی DNS سرور تک رسائی حاصل نہیں کی جا سکی"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"آلے سے منسلک ہے۔ انٹرنیٹ فراہم نہیں کیا جا سکتا۔"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"ادنٰی معیار"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (کم محفوظ)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"آپ کی تنظیم کی طرف سے اجازت نہیں ہے"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> منجانب <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{آپ کے فون سے {NETWORK_NAME}}TABLET{آپ کے ٹیبلیٹ سے {NETWORK_NAME}}COMPUTER{آپ کے کمپیوٹر سے {NETWORK_NAME}}WATCH{آپ کی گھڑی سے {NETWORK_NAME}}VEHICLE{آپ کی گاڑی سے {NETWORK_NAME}}other{آپ کے آلے سے {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-uz/strings.xml b/libs/WifiTrackerLib/res/values-uz/strings.xml
index afad9319a..2caf879a4 100644
--- a/libs/WifiTrackerLib/res/values-uz/strings.xml
+++ b/libs/WifiTrackerLib/res/values-uz/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Xususiy DNS server ishlamayapti"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Qurilmaga ulandi. Internetga ulanmagan."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Sifati past"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (kamroq xavfsiz)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Tashkilotingiz ruxsat bermagan"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="MODEL_NAME">%2$s</xliff:g> <xliff:g id="NETWORK_NAME">%1$s</xliff:g> yubordi"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{Telefoningizdan: {NETWORK_NAME}}TABLET{Planshetingizdan: {NETWORK_NAME}}COMPUTER{Kompyuteringizdan: {NETWORK_NAME}}WATCH{Soatingizdan: {NETWORK_NAME}}VEHICLE{Avtomobilingizdan: {NETWORK_NAME}}other{Qurilmangizdan: {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-vi/strings.xml b/libs/WifiTrackerLib/res/values-vi/strings.xml
index 6488fa3e0..f5bfd97c0 100644
--- a/libs/WifiTrackerLib/res/values-vi/strings.xml
+++ b/libs/WifiTrackerLib/res/values-vi/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Không thể truy cập máy chủ DNS riêng tư"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Đã kết nối với thiết bị. Không thể cung cấp Internet."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Chất lượng thấp"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (kém an toàn)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Không được tổ chức của bạn cho phép"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> trên <xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME} trên điện thoại của bạn}TABLET{{NETWORK_NAME} trên máy tính bảng của bạn}COMPUTER{{NETWORK_NAME} trên máy tính của bạn}WATCH{{NETWORK_NAME} trên đồng hồ của bạn}VEHICLE{{NETWORK_NAME} trên xe của bạn}other{{NETWORK_NAME} trên thiết bị của bạn}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-zh-rCN/strings.xml b/libs/WifiTrackerLib/res/values-zh-rCN/strings.xml
index d14a963a3..3b4f208d2 100644
--- a/libs/WifiTrackerLib/res/values-zh-rCN/strings.xml
+++ b/libs/WifiTrackerLib/res/values-zh-rCN/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"无法访问专用 DNS 服务器"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"已连接到设备，但无法提供互联网连接。"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"质量不佳"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g>（安全性较低）"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"您的组织不允许使用"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"来自 <xliff:g id="MODEL_NAME">%2$s</xliff:g> 的“<xliff:g id="NETWORK_NAME">%1$s</xliff:g>”"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{{NETWORK_NAME}（来自您的手机）}TABLET{{NETWORK_NAME}（来自您的平板电脑）}COMPUTER{{NETWORK_NAME}（来自您的计算机）}WATCH{{NETWORK_NAME}（来自您的手表）}VEHICLE{{NETWORK_NAME}（来自您的汽车）}other{{NETWORK_NAME}（来自您的设备）}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-zh-rHK/strings.xml b/libs/WifiTrackerLib/res/values-zh-rHK/strings.xml
index e2434f26b..1031b0213 100644
--- a/libs/WifiTrackerLib/res/values-zh-rHK/strings.xml
+++ b/libs/WifiTrackerLib/res/values-zh-rHK/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"無法存取私人 DNS 伺服器"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"已連接裝置，但無法提供互聯網連線。"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"品質欠佳"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (安全性較低)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"你的機構禁止使用"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"來自「<xliff:g id="MODEL_NAME">%2$s</xliff:g>」的「<xliff:g id="NETWORK_NAME">%1$s</xliff:g>」"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{手機的 {NETWORK_NAME}}TABLET{平板電腦的 {NETWORK_NAME}}COMPUTER{電腦的 {NETWORK_NAME}}WATCH{手錶的 {NETWORK_NAME}}VEHICLE{汽車的 {NETWORK_NAME}}other{裝置的 {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-zh-rTW/strings.xml b/libs/WifiTrackerLib/res/values-zh-rTW/strings.xml
index 76f22eba6..670c1efda 100644
--- a/libs/WifiTrackerLib/res/values-zh-rTW/strings.xml
+++ b/libs/WifiTrackerLib/res/values-zh-rTW/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"無法存取私人 DNS 伺服器"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"已連上裝置，但無法提供網際網路連線。"</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"品質不佳"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (安全性較低)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"貴機構禁止使用"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"<xliff:g id="NETWORK_NAME">%1$s</xliff:g> (來自<xliff:g id="MODEL_NAME">%2$s</xliff:g>)"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{手機的 {NETWORK_NAME}}TABLET{平板電腦的 {NETWORK_NAME}}COMPUTER{電腦的 {NETWORK_NAME}}WATCH{手錶的 {NETWORK_NAME}}VEHICLE{車輛的 {NETWORK_NAME}}other{裝置的 {NETWORK_NAME}}}"</string>
diff --git a/libs/WifiTrackerLib/res/values-zu/strings.xml b/libs/WifiTrackerLib/res/values-zu/strings.xml
index ceb000e7e..456d6b956 100644
--- a/libs/WifiTrackerLib/res/values-zu/strings.xml
+++ b/libs/WifiTrackerLib/res/values-zu/strings.xml
@@ -43,6 +43,7 @@
     <string name="wifitrackerlib_private_dns_broken" msgid="6049401148262718707">"Iseva eyimfihlo ye-DNS ayikwazi ukufinyelelwa"</string>
     <string name="wifitrackerlib_wifi_connected_cannot_provide_internet" msgid="3803471522215612745">"Ixhunywe kudivayisi. Ayikwazi ukunikeza i-inthanethi."</string>
     <string name="wifi_connected_low_quality" msgid="4478331645458058445">"Ikhwalithi ephansi"</string>
+    <string name="wifi_connected_less_secure" msgid="2385231117439764954">"<xliff:g id="SECURITY_TYPE">%1$s</xliff:g> (okuvikeleke kancane)"</string>
     <string name="wifitrackerlib_admin_restricted_network" msgid="5439914801076897515">"Ayivunyelwe yinhlangano yakho"</string>
     <string name="wifitrackerlib_hotspot_network_summary" msgid="7661086683527884190">"I-<xliff:g id="NETWORK_NAME">%1$s</xliff:g> evela ku-<xliff:g id="MODEL_NAME">%2$s</xliff:g>"</string>
     <string name="wifitrackerlib_hotspot_network_summary_new" msgid="1165705867298669621">"{DEVICE_TYPE,select, PHONE{I-{NETWORK_NAME} ukusuka kufoni yakho}TABLET{I-{NETWORK_NAME} ukusuka kuthebhulethi yakho}COMPUTER{I-{NETWORK_NAME} ukusuka kukhompyutha yakho}WATCH{I-{NETWORK_NAME} ukusuka kuwashi lakho}VEHICLE{I-{NETWORK_NAME} ukusuka emotweni yakho}other{I-{NETWORK_NAME} ukusuka kudivayisi yakho}}"</string>
diff --git a/libs/WifiTrackerLib/res/values/strings.xml b/libs/WifiTrackerLib/res/values/strings.xml
index 5be3c7d7c..f0d56ccfc 100644
--- a/libs/WifiTrackerLib/res/values/strings.xml
+++ b/libs/WifiTrackerLib/res/values/strings.xml
@@ -115,6 +115,9 @@
     <!-- Summary for Connected wifi network with a low quality connection [CHAR LIMIT=NONE] -->
     <string name="wifi_connected_low_quality">Low quality</string>
 
+    <!-- Summary for Connected wifi network with a less secure connection [CHAR LIMIT=NONE] -->
+    <string name="wifi_connected_less_secure"><xliff:g id="security type" example="WEP">%1$s</xliff:g> (less secure)</string>
+
     <!-- Summary for admin restricted networks [CHAR LIMIT=NONE] -->
     <string name="wifitrackerlib_admin_restricted_network">Not allowed by your organization</string>
 
diff --git a/libs/WifiTrackerLib/sdk_src/src/com/android/wifitrackerlib/NonSdkApiWrapper.java b/libs/WifiTrackerLib/sdk_src/src/com/android/wifitrackerlib/NonSdkApiWrapper.java
index 1af89f8c6..0dbc28333 100644
--- a/libs/WifiTrackerLib/sdk_src/src/com/android/wifitrackerlib/NonSdkApiWrapper.java
+++ b/libs/WifiTrackerLib/sdk_src/src/com/android/wifitrackerlib/NonSdkApiWrapper.java
@@ -56,15 +56,6 @@ class NonSdkApiWrapper {
         return rawText;
     }
 
-    /**
-     * Tries to get WifiInfo from network capabilities if it is VCN-over-Wifi.
-     */
-    static WifiInfo getWifiInfoIfVcn(@NonNull NetworkCapabilities networkCapabilities) {
-        // This is only useful for treating CELLULAR over WIFI as a carrier merged network in
-        // provider model Settings. Since SUW doesn't use the provider model, this is not used.
-        return null;
-    }
-
     /**
      * Returns whether or not the device is in retail demo mode.
      */
@@ -117,4 +108,20 @@ class NonSdkApiWrapper {
         // Google3 can't access trunk stable flags, so default to false.
         return false;
     }
+
+    /**
+     * Whether the hotspot network unknown status resets connecting state flag is enabled.
+     */
+    static boolean isHotspotNetworkUnknownStatusResetsConnectingStateEnabled() {
+        // Google3 can't access trunk stable flags, so default to false.
+        return false;
+    }
+
+    /**
+     * Whether the hotspot network entry connecting state for details page flag is enabled.
+     */
+    static boolean isHotspotNetworkConnectingStateForDetailsPageEnabled() {
+        // Google3 can't access trunk stable flags, so default to false.
+        return false;
+    }
 }
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/HotspotNetworkDetailsTracker.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/HotspotNetworkDetailsTracker.java
index e223ec403..f7e505b01 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/HotspotNetworkDetailsTracker.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/HotspotNetworkDetailsTracker.java
@@ -26,6 +26,7 @@ import android.net.Network;
 import android.net.NetworkCapabilities;
 import android.net.wifi.WifiManager;
 import android.net.wifi.sharedconnectivity.app.HotspotNetwork;
+import android.net.wifi.sharedconnectivity.app.HotspotNetworkConnectionStatus;
 import android.os.Build;
 import android.os.Handler;
 import android.telephony.SubscriptionManager;
@@ -47,6 +48,9 @@ import java.util.List;
 public class HotspotNetworkDetailsTracker extends NetworkDetailsTracker {
     private static final String TAG = "HotspotNetworkDetailsTracker";
 
+    private static final String EXTRA_KEY_CONNECTION_STATUS_CONNECTED =
+            "connection_status_connected";
+
     private final HotspotNetworkEntry mChosenEntry;
 
     private HotspotNetwork mHotspotNetworkData;
@@ -142,6 +146,25 @@ public class HotspotNetworkDetailsTracker extends NetworkDetailsTracker {
         mChosenEntry.updateHotspotNetworkData(mHotspotNetworkData);
     }
 
+    @WorkerThread
+    @Override
+    protected void handleHotspotNetworkConnectionStatusChanged(
+            @NonNull HotspotNetworkConnectionStatus status) {
+        if (!mInjector.isSharedConnectivityFeatureEnabled()
+                || !NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled()) {
+            return;
+        }
+        if (status.getHotspotNetwork().getDeviceId()
+                != mChosenEntry.getHotspotNetworkEntryKey().getDeviceId()) {
+            return;
+        }
+        if (status.getExtras().getBoolean(EXTRA_KEY_CONNECTION_STATUS_CONNECTED, false)) {
+            mChosenEntry.onConnectionStatusChanged(HotspotNetworkEntry.CONNECTION_STATUS_CONNECTED);
+        } else {
+            mChosenEntry.onConnectionStatusChanged(status.getStatus());
+        }
+    }
+
     @WorkerThread
     private void updateStartInfo() {
         handleDefaultSubscriptionChanged(SubscriptionManager.getDefaultDataSubscriptionId());
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/HotspotNetworkEntry.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/HotspotNetworkEntry.java
index 67aca3dec..f0e7c7b4f 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/HotspotNetworkEntry.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/HotspotNetworkEntry.java
@@ -196,6 +196,16 @@ public class HotspotNetworkEntry extends WifiEntry {
                         Collections.singletonList(wifiInfo.getCurrentSecurityType())));
     }
 
+    @Override
+    @ConnectedState
+    public synchronized int getConnectedState() {
+        if (NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled()
+                && mCalledConnect) {
+            return CONNECTED_STATE_CONNECTING;
+        }
+        return super.getConnectedState();
+    }
+
     @Override
     public int getLevel() {
         if (getConnectedState() == CONNECTED_STATE_DISCONNECTED) {
@@ -217,7 +227,9 @@ public class HotspotNetworkEntry extends WifiEntry {
         if (mHotspotNetworkData == null) {
             return "";
         }
-        if (mCalledConnect) {
+        if (NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled()
+                ? mCalledConnect && !concise // Do not include connecting... for concise summary
+                : mCalledConnect) {
             return mContext.getString(R.string.wifitrackerlib_hotspot_network_connecting);
         }
         if (mConnectionError) {
@@ -450,6 +462,13 @@ public class HotspotNetworkEntry extends WifiEntry {
     public void onConnectionStatusChanged(@ConnectionStatus int status) {
         mLastStatus = status;
         switch (status) {
+            case HotspotNetworkConnectionStatus.CONNECTION_STATUS_UNKNOWN:
+                if (NonSdkApiWrapper.isHotspotNetworkUnknownStatusResetsConnectingStateEnabled()) {
+                    mCalledConnect = false;
+                    mConnectionError = false;
+                    notifyOnUpdated();
+                }
+                break;
             case HotspotNetworkConnectionStatus.CONNECTION_STATUS_ENABLING_HOTSPOT:
                 mCalledConnect = true;
                 mConnectionError = false;
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/NonSdkApiWrapper.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/NonSdkApiWrapper.java
index 5d90f7324..f4c152880 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/NonSdkApiWrapper.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/NonSdkApiWrapper.java
@@ -16,6 +16,9 @@
 
 package com.android.wifitrackerlib;
 
+import static android.net.wifi.flags.Flags.hotspotNetworkConnectingStateForDetailsPage;
+import static android.net.wifi.flags.Flags.hotspotNetworkUnknownStatusResetsConnectingState;
+
 import static com.android.wifi.flags.Flags.androidVWifiApi;
 import static com.android.wifi.flags.Flags.networkProviderBatteryChargingStatus;
 
@@ -25,8 +28,6 @@ import android.content.Context;
 import android.net.ConnectivityManager;
 import android.net.Network;
 import android.net.NetworkCapabilities;
-import android.net.TransportInfo;
-import android.net.vcn.VcnTransportInfo;
 import android.net.wifi.WifiInfo;
 import android.os.UserManager;
 import android.text.Annotation;
@@ -94,17 +95,6 @@ class NonSdkApiWrapper {
         return rawText;
     }
 
-    /**
-     * Tries to get WifiInfo from network capabilities if it is VCN-over-Wifi.
-     */
-    static WifiInfo getWifiInfoIfVcn(@NonNull NetworkCapabilities networkCapabilities) {
-        TransportInfo transportInfo = networkCapabilities.getTransportInfo();
-        if (transportInfo instanceof VcnTransportInfo) {
-            return ((VcnTransportInfo) transportInfo).getWifiInfo();
-        }
-        return null;
-    }
-
     /**
      * Returns whether or not the device is in retail demo mode.
      */
@@ -152,4 +142,18 @@ class NonSdkApiWrapper {
         // Google3 can't access trunk stable flags, so default to false.
         return androidVWifiApi();
     }
+
+    /**
+     * Whether the hotspot network unknown status resets connecting state flag is enabled.
+     */
+    static boolean isHotspotNetworkUnknownStatusResetsConnectingStateEnabled() {
+        return hotspotNetworkUnknownStatusResetsConnectingState();
+    }
+
+    /**
+     * Whether the hotspot network entry connecting state for details page flag is enabled.
+     */
+    static boolean isHotspotNetworkConnectingStateForDetailsPageEnabled() {
+        return hotspotNetworkConnectingStateForDetailsPage();
+    }
 }
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/OsuWifiEntry.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/OsuWifiEntry.java
index ffb933009..44ee8bf35 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/OsuWifiEntry.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/OsuWifiEntry.java
@@ -141,7 +141,7 @@ class OsuWifiEntry extends WifiEntry {
         if (hasAdminRestrictions()) {
             return false;
         }
-        return mLevel != WIFI_LEVEL_UNREACHABLE
+        return mScanResultLevel != WIFI_LEVEL_UNREACHABLE
                 && getConnectedState() == CONNECTED_STATE_DISCONNECTED;
     }
 
@@ -165,10 +165,10 @@ class OsuWifiEntry extends WifiEntry {
         if (bestScanResult != null) {
             mSsid = bestScanResult.SSID;
             if (getConnectedState() == CONNECTED_STATE_DISCONNECTED) {
-                mLevel = mWifiManager.calculateSignalLevel(bestScanResult.level);
+                mScanResultLevel = mWifiManager.calculateSignalLevel(bestScanResult.level);
             }
         } else {
-            mLevel = WIFI_LEVEL_UNREACHABLE;
+            mScanResultLevel = WIFI_LEVEL_UNREACHABLE;
         }
         notifyOnUpdated();
     }
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/PasspointWifiEntry.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/PasspointWifiEntry.java
index de22e4c14..9a0420834 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/PasspointWifiEntry.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/PasspointWifiEntry.java
@@ -195,6 +195,7 @@ public class PasspointWifiEntry extends WifiEntry implements WifiEntry.WifiEntry
                     connectedStateDescription = getConnectedDescription(mContext,
                             mWifiConfig,
                             mNetworkCapabilities,
+                            mWifiInfo,
                             isDefaultNetwork(),
                             isLowQuality(),
                             mConnectivityReport);
@@ -300,7 +301,7 @@ public class PasspointWifiEntry extends WifiEntry implements WifiEntry.WifiEntry
             return mOsuWifiEntry != null && mOsuWifiEntry.canConnect();
         }
 
-        return mLevel != WIFI_LEVEL_UNREACHABLE
+        return mScanResultLevel != WIFI_LEVEL_UNREACHABLE
                 && getConnectedState() == CONNECTED_STATE_DISCONNECTED && mWifiConfig != null;
     }
 
@@ -538,12 +539,12 @@ public class PasspointWifiEntry extends WifiEntry implements WifiEntry.WifiEntry
                 mWifiConfig.SSID = "\"" + bestScanResult.SSID + "\"";
             }
             if (getConnectedState() == CONNECTED_STATE_DISCONNECTED) {
-                mLevel = bestScanResult != null
+                mScanResultLevel = bestScanResult != null
                         ? mWifiManager.calculateSignalLevel(bestScanResult.level)
                         : WIFI_LEVEL_UNREACHABLE;
             }
         } else {
-            mLevel = WIFI_LEVEL_UNREACHABLE;
+            mScanResultLevel = WIFI_LEVEL_UNREACHABLE;
         }
         notifyOnUpdated();
     }
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardWifiEntry.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardWifiEntry.java
index 302352fc1..bda8289e4 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardWifiEntry.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/StandardWifiEntry.java
@@ -207,6 +207,7 @@ public class StandardWifiEntry extends WifiEntry {
                 connectedStateDescription = getConnectedDescription(mContext,
                         mTargetWifiConfig,
                         mNetworkCapabilities,
+                        mWifiInfo,
                         isDefaultNetwork(),
                         isLowQuality(),
                         mConnectivityReport);
@@ -306,7 +307,7 @@ public class StandardWifiEntry extends WifiEntry {
 
     @Override
     public synchronized boolean canConnect() {
-        if (mLevel == WIFI_LEVEL_UNREACHABLE
+        if (mScanResultLevel == WIFI_LEVEL_UNREACHABLE
                 || getConnectedState() != CONNECTED_STATE_DISCONNECTED) {
             return false;
         }
@@ -696,7 +697,7 @@ public class StandardWifiEntry extends WifiEntry {
         final ScanResult bestScanResult = getBestScanResultByLevel(mTargetScanResults);
 
         if (getConnectedState() == CONNECTED_STATE_DISCONNECTED) {
-            mLevel = bestScanResult != null
+            mScanResultLevel = bestScanResult != null
                     ? mWifiManager.calculateSignalLevel(bestScanResult.level)
                     : WIFI_LEVEL_UNREACHABLE;
         }
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/Utils.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/Utils.java
index 816d4020c..431941b32 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/Utils.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/Utils.java
@@ -252,6 +252,7 @@ public class Utils {
     static String getConnectedDescription(@NonNull Context context,
             @Nullable WifiConfiguration wifiConfiguration,
             @NonNull NetworkCapabilities networkCapabilities,
+            @Nullable WifiInfo wifiInfo,
             boolean isDefaultNetwork,
             boolean isLowQuality,
             @Nullable ConnectivityDiagnosticsManager.ConnectivityReport connectivityReport) {
@@ -303,6 +304,14 @@ public class Utils {
                     R.array.wifitrackerlib_wifi_status)[DetailedState.CONNECTED.ordinal()]);
         }
 
+        if (shouldShowConnected) {
+            if (wifiInfo != null && wifiInfo.getCurrentSecurityType() == SECURITY_TYPE_WEP) {
+                // "WEP (less secure)"
+                sj.add(context.getString(R.string.wifi_connected_less_secure,
+                        getSecurityString(context, Arrays.asList(SECURITY_TYPE_WEP), false)));
+            }
+        }
+
         if (isLowQuality) {
             // "Low quality"
             sj.add(context.getString(R.string.wifi_connected_low_quality));
@@ -1207,7 +1216,7 @@ public class Utils {
         if (transportInfo instanceof WifiInfo) {
             return (WifiInfo) transportInfo;
         }
-        return NonSdkApiWrapper.getWifiInfoIfVcn(capabilities);
+        return null;
     }
 
     /**
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiEntry.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiEntry.java
index e75d9a251..d3525d81c 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiEntry.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiEntry.java
@@ -25,6 +25,7 @@ import static com.android.wifitrackerlib.Utils.getSingleSecurityTypeFromMultiple
 
 import android.content.Context;
 import android.net.ConnectivityDiagnosticsManager;
+import android.net.ConnectivityManager;
 import android.net.LinkAddress;
 import android.net.LinkProperties;
 import android.net.Network;
@@ -37,6 +38,7 @@ import android.net.wifi.WifiInfo;
 import android.net.wifi.WifiManager;
 import android.os.Handler;
 import android.text.TextUtils;
+import android.util.Log;
 
 import androidx.annotation.AnyThread;
 import androidx.annotation.IntDef;
@@ -70,6 +72,10 @@ import java.util.stream.Collectors;
  * actions on the represented network.
  */
 public class WifiEntry {
+    public static final String TAG = "WifiEntry";
+
+    private static final int MAX_UNDERLYING_NETWORK_DEPTH = 5;
+
     /**
      * Security type based on WifiConfiguration.KeyMgmt
      */
@@ -238,8 +244,8 @@ public class WifiEntry {
     // Callback associated with this WifiEntry. Subclasses should call its methods appropriately.
     private WifiEntryCallback mListener;
     protected final Handler mCallbackHandler;
-
-    protected int mLevel = WIFI_LEVEL_UNREACHABLE;
+    protected int mWifiInfoLevel = WIFI_LEVEL_UNREACHABLE;
+    protected int mScanResultLevel = WIFI_LEVEL_UNREACHABLE;
     protected WifiInfo mWifiInfo;
     protected NetworkInfo mNetworkInfo;
     protected Network mNetwork;
@@ -339,7 +345,10 @@ public class WifiEntry {
      * A value of WIFI_LEVEL_UNREACHABLE indicates an out of range network.
      */
     public int getLevel() {
-        return mLevel;
+        if (mWifiInfoLevel != WIFI_LEVEL_UNREACHABLE) {
+            return mWifiInfoLevel;
+        }
+        return mScanResultLevel;
     };
 
     /**
@@ -367,25 +376,48 @@ public class WifiEntry {
      * Returns whether this network is the default network or not (i.e. this network is the one
      * currently being used to provide internet connection).
      */
-    public boolean isDefaultNetwork() {
+    public synchronized boolean isDefaultNetwork() {
         if (mNetwork != null && mNetwork.equals(mDefaultNetwork)) {
             return true;
         }
 
-        // Try to get a WifiInfo from the default network capabilities in case it's a
-        // VcnTransportInfo with an underlying WifiInfo.
-        if (mDefaultNetworkCapabilities == null) {
+        // Match based on the underlying networks if there are any (e.g. VPN).
+        return doesUnderlyingNetworkMatch(mDefaultNetworkCapabilities, 0);
+    }
+
+    private boolean doesUnderlyingNetworkMatch(@Nullable NetworkCapabilities caps, int depth) {
+        if (depth > MAX_UNDERLYING_NETWORK_DEPTH) {
+            Log.e(TAG, "Underlying network depth greater than max depth of "
+                    + MAX_UNDERLYING_NETWORK_DEPTH);
             return false;
         }
-        WifiInfo defaultWifiInfo = Utils.getWifiInfo(mDefaultNetworkCapabilities);
-        if (defaultWifiInfo != null) {
-            return connectionInfoMatches(defaultWifiInfo);
+
+        if (caps == null) {
+            return false;
         }
 
-        // Match based on the underlying networks if there are any (e.g. VPN).
         List<Network> underlyingNetworks = BuildCompat.isAtLeastT()
-                ? mDefaultNetworkCapabilities.getUnderlyingNetworks() : null;
-        return underlyingNetworks != null && underlyingNetworks.contains(mNetwork);
+                ? caps.getUnderlyingNetworks() : null;
+        if (underlyingNetworks == null) {
+            return false;
+        }
+        if (underlyingNetworks.contains(mNetwork)) {
+            return true;
+        }
+
+        // Check the underlying networks of the underlying networks.
+        ConnectivityManager connectivityManager = mInjector.getConnectivityManager();
+        if (connectivityManager == null) {
+            Log.wtf(TAG, "ConnectivityManager is null!");
+            return false;
+        }
+        for (Network underlying : underlyingNetworks) {
+            if (doesUnderlyingNetworkMatch(
+                    connectivityManager.getNetworkCapabilities(underlying), depth + 1)) {
+                return true;
+            }
+        }
+        return false;
     }
 
     /**
@@ -1021,17 +1053,18 @@ public class WifiEntry {
         notifyOnUpdated();
     }
 
-    private synchronized void updateWifiInfo(WifiInfo wifiInfo) {
+    protected synchronized void updateWifiInfo(WifiInfo wifiInfo) {
         if (wifiInfo == null) {
             mWifiInfo = null;
             mConnectedInfo = null;
+            mWifiInfoLevel = WIFI_LEVEL_UNREACHABLE;
             updateSecurityTypes();
             return;
         }
         mWifiInfo = wifiInfo;
         final int wifiInfoRssi = mWifiInfo.getRssi();
         if (wifiInfoRssi != INVALID_RSSI) {
-            mLevel = mWifiManager.calculateSignalLevel(wifiInfoRssi);
+            mWifiInfoLevel = mWifiManager.calculateSignalLevel(wifiInfoRssi);
         }
         if (getConnectedState() == CONNECTED_STATE_CONNECTED) {
             if (mCalledConnect) {
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiPickerTracker.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiPickerTracker.java
index a382b727e..6751aa54a 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiPickerTracker.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiPickerTracker.java
@@ -24,15 +24,18 @@ import static com.android.wifitrackerlib.OsuWifiEntry.osuProviderToOsuWifiEntryK
 import static com.android.wifitrackerlib.PasspointWifiEntry.uniqueIdToPasspointWifiEntryKey;
 import static com.android.wifitrackerlib.StandardWifiEntry.ScanResultKey;
 import static com.android.wifitrackerlib.StandardWifiEntry.StandardWifiEntryKey;
+import static com.android.wifitrackerlib.WifiEntry.CONNECTED_STATE_CONNECTING;
 import static com.android.wifitrackerlib.WifiEntry.CONNECTED_STATE_DISCONNECTED;
 import static com.android.wifitrackerlib.WifiEntry.WIFI_LEVEL_UNREACHABLE;
 
 import static java.util.stream.Collectors.toList;
 import static java.util.stream.Collectors.toMap;
 
+import android.Manifest;
 import android.annotation.TargetApi;
 import android.content.Context;
 import android.content.Intent;
+import android.content.pm.PackageManager;
 import android.net.ConnectivityDiagnosticsManager;
 import android.net.ConnectivityManager;
 import android.net.LinkProperties;
@@ -292,7 +295,7 @@ public class WifiPickerTracker extends BaseWifiTracker {
         }
 
         // Update configs and scans
-        updateWifiConfigurations(mWifiManager.getPrivilegedConfiguredNetworks());
+        updateWifiConfigurationsInternal();
         updatePasspointConfigurations(mWifiManager.getPasspointConfigurations());
         mScanResultUpdater.update(mWifiManager.getScanResults());
         conditionallyUpdateScanResults(true /* lastScanSucceeded */);
@@ -350,7 +353,7 @@ public class WifiPickerTracker extends BaseWifiTracker {
     @WorkerThread
     /** All wifi entries and saved entries needs to be updated. */
     protected void processConfiguredNetworksChanged() {
-        updateWifiConfigurations(mWifiManager.getPrivilegedConfiguredNetworks());
+        updateWifiConfigurationsInternal();
         updatePasspointConfigurations(mWifiManager.getPasspointConfigurations());
         // Update scans since config changes may result in different entries being shown.
         conditionallyUpdateScanResults(false /* lastScanSucceeded */);
@@ -566,6 +569,10 @@ public class WifiPickerTracker extends BaseWifiTracker {
         activeWifiEntries.removeIf(entry -> entry instanceof StandardWifiEntry
                 && activeHotspotNetworkKeys.contains(
                 ((StandardWifiEntry) entry).getStandardWifiEntryKey().getScanResultKey()));
+        if (NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled()) {
+            activeWifiEntries.removeIf(entry -> entry instanceof HotspotNetworkEntry
+                    && entry.getConnectedState() == CONNECTED_STATE_CONNECTING);
+        }
         activeWifiEntries.sort(WifiEntry.WIFI_PICKER_COMPARATOR);
         final Set<ScanResultKey> scanResultKeysWithVisibleSuggestions =
                 mSuggestedWifiEntryCache.stream()
@@ -642,9 +649,16 @@ public class WifiPickerTracker extends BaseWifiTracker {
                             && !(savedEntryKeys.contains(
                             entry.getStandardWifiEntryKey().getScanResultKey()))).collect(
                     toList()));
-            wifiEntries.addAll(mHotspotNetworkEntryCache.stream().filter(entry ->
+            if (NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled()) {
+                wifiEntries.addAll(mHotspotNetworkEntryCache.stream().filter(entry ->
+                        entry.getConnectedState() == CONNECTED_STATE_DISCONNECTED
+                                || entry.getConnectedState() == CONNECTED_STATE_CONNECTING).collect(
+                        toList()));
+            } else {
+                wifiEntries.addAll(mHotspotNetworkEntryCache.stream().filter(entry ->
                     entry.getConnectedState() == CONNECTED_STATE_DISCONNECTED).collect(
                     toList()));
+            }
         }
         Collections.sort(wifiEntries, WifiEntry.WIFI_PICKER_COMPARATOR);
         if (isVerboseLoggingEnabled()) {
@@ -1175,6 +1189,16 @@ public class WifiPickerTracker extends BaseWifiTracker {
         }
     }
 
+    @WorkerThread
+    private void updateWifiConfigurationsInternal() {
+        if (mContext.checkSelfPermission(Manifest.permission.READ_WIFI_CREDENTIAL)
+            == PackageManager.PERMISSION_GRANTED) {
+            updateWifiConfigurations(mWifiManager.getPrivilegedConfiguredNetworks());
+        } else {
+            updateWifiConfigurations(mWifiManager.getConfiguredNetworks());
+        }
+    }
+
     @WorkerThread
     private void updatePasspointConfigurations(@NonNull List<PasspointConfiguration> configs) {
         checkNotNull(configs, "Config list should not be null!");
@@ -1208,7 +1232,7 @@ public class WifiPickerTracker extends BaseWifiTracker {
             // We're connected but don't have any configured networks, so fetch the list of configs
             // again. This can happen when we fetch the configured networks after SSR, but the Wifi
             // thread times out waiting for driver restart and returns an empty list of networks.
-            updateWifiConfigurations(mWifiManager.getPrivilegedConfiguredNetworks());
+            updateWifiConfigurationsInternal();
         }
         // Create a WifiEntry for the current connection if there are no scan results yet.
         conditionallyCreateConnectedWifiEntry(Utils.getWifiInfo(capabilities));
diff --git a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiTrackerInjector.java b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiTrackerInjector.java
index c70a88a41..566cb9203 100644
--- a/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiTrackerInjector.java
+++ b/libs/WifiTrackerLib/src/com/android/wifitrackerlib/WifiTrackerInjector.java
@@ -18,6 +18,7 @@ package com.android.wifitrackerlib;
 
 import android.app.admin.DevicePolicyManager;
 import android.content.Context;
+import android.net.ConnectivityManager;
 import android.net.wifi.WifiManager;
 import android.os.Build;
 import android.os.UserManager;
@@ -25,6 +26,7 @@ import android.provider.DeviceConfig;
 import android.util.ArraySet;
 
 import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
 import java.util.Set;
 
@@ -37,6 +39,8 @@ public class WifiTrackerInjector {
     @NonNull private final Context mContext;
     private final boolean mIsDemoMode;
     private final WifiManager mWifiManager;
+    @Nullable
+    private final ConnectivityManager mConnectivityManager;
     private final UserManager mUserManager;
     private final DevicePolicyManager mDevicePolicyManager;
     @NonNull private final Set<String> mNoAttributionAnnotationPackages;
@@ -47,6 +51,7 @@ public class WifiTrackerInjector {
     WifiTrackerInjector(@NonNull Context context) {
         mContext = context;
         mWifiManager = context.getSystemService(WifiManager.class);
+        mConnectivityManager = context.getSystemService(ConnectivityManager.class);
         mIsDemoMode = NonSdkApiWrapper.isDemoMode(context);
         mUserManager = context.getSystemService(UserManager.class);
         mDevicePolicyManager = context.getSystemService(DevicePolicyManager.class);
@@ -110,4 +115,9 @@ public class WifiTrackerInjector {
     public void disableVerboseLogging() {
         mVerboseLoggingDisabledOverride = true;
     }
+
+    @Nullable
+    public ConnectivityManager getConnectivityManager() {
+        return mConnectivityManager;
+    }
 }
diff --git a/libs/WifiTrackerLib/tests/Android.bp b/libs/WifiTrackerLib/tests/Android.bp
index cbda67f7b..a1ab277d8 100644
--- a/libs/WifiTrackerLib/tests/Android.bp
+++ b/libs/WifiTrackerLib/tests/Android.bp
@@ -32,7 +32,7 @@ java_defaults {
     ],
 
     libs: [
-        "android.test.mock",
+        "android.test.mock.stubs.system",
     ],
 
     jni_libs: [
diff --git a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/HotspotNetworkEntryTest.java b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/HotspotNetworkEntryTest.java
index dedf4af01..633dcafb4 100644
--- a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/HotspotNetworkEntryTest.java
+++ b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/HotspotNetworkEntryTest.java
@@ -1101,4 +1101,142 @@ public class HotspotNetworkEntryTest {
 
         assertThat(entry.getSummary()).isNotEqualTo("Can't connect. Try connecting again.");
     }
+
+    @Test
+    public void testGetSummary_connectionCanceled_resetsConnectingString() {
+        final HotspotNetworkEntry entry = new HotspotNetworkEntry(
+                mMockInjector, mMockContext, mTestHandler,
+                mMockWifiManager, mMockSharedConnectivityManager, TEST_HOTSPOT_NETWORK_DATA);
+        entry.setListener(mMockListener);
+        entry.connect(mMockConnectCallback);
+        MockitoSession session = mockitoSession().spyStatic(NonSdkApiWrapper.class).startMocking();
+        try {
+            doReturn(true).when(() ->
+                    NonSdkApiWrapper.isHotspotNetworkUnknownStatusResetsConnectingStateEnabled());
+            entry.onConnectionStatusChanged(
+                    HotspotNetworkConnectionStatus.CONNECTION_STATUS_ENABLING_HOTSPOT);
+            mTestLooper.dispatchAll();
+            assertThat(entry.getSummary()).isEqualTo("Connecting…");
+
+            entry.onConnectionStatusChanged(
+                    HotspotNetworkConnectionStatus.CONNECTION_STATUS_UNKNOWN);
+            mTestLooper.dispatchAll();
+
+            assertThat(entry.getSummary()).isNotEqualTo("Connecting…");
+        } finally {
+            session.finishMocking();
+        }
+    }
+
+    @Test
+    public void testGetSummary_concise_enabling_detailsPageFlagFalse_returnsConnectingString() {
+        final HotspotNetworkEntry entry = new HotspotNetworkEntry(
+                mMockInjector, mMockContext, mTestHandler,
+                mMockWifiManager, mMockSharedConnectivityManager, TEST_HOTSPOT_NETWORK_DATA);
+
+        entry.setListener(mMockListener);
+        entry.connect(mMockConnectCallback);
+        entry.onConnectionStatusChanged(
+                HotspotNetworkConnectionStatus.CONNECTION_STATUS_ENABLING_HOTSPOT);
+        mTestLooper.dispatchAll();
+
+        MockitoSession session = mockitoSession().spyStatic(NonSdkApiWrapper.class).startMocking();
+        try {
+            doReturn(false).when(() ->
+                    NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled());
+            assertThat(entry.getSummary(true)).isEqualTo("Connecting…");
+        } finally {
+            session.finishMocking();
+        }
+    }
+
+    @Test
+    public void testGetSummary_concise_enabling_detailsPageFlagTrue_returnsSummaryString() {
+        final HotspotNetworkEntry entry = new HotspotNetworkEntry(
+                mMockInjector, mMockContext, mTestHandler,
+                mMockWifiManager, mMockSharedConnectivityManager, TEST_HOTSPOT_NETWORK_DATA);
+
+        entry.setListener(mMockListener);
+        entry.connect(mMockConnectCallback);
+        entry.onConnectionStatusChanged(
+                HotspotNetworkConnectionStatus.CONNECTION_STATUS_ENABLING_HOTSPOT);
+        mTestLooper.dispatchAll();
+
+        MockitoSession session = mockitoSession().spyStatic(NonSdkApiWrapper.class).startMocking();
+        try {
+            doReturn(true).when(() ->
+                    NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled());
+            assertThat(entry.getSummary(true)).isEqualTo("Google Fi from your phone");
+        } finally {
+            session.finishMocking();
+        }
+    }
+
+    @Test
+    public void testGetSummary_notConcise_enabling_detailsPageFlagTrue_returnsConnectingString() {
+        final HotspotNetworkEntry entry = new HotspotNetworkEntry(
+                mMockInjector, mMockContext, mTestHandler,
+                mMockWifiManager, mMockSharedConnectivityManager, TEST_HOTSPOT_NETWORK_DATA);
+
+        entry.setListener(mMockListener);
+        entry.connect(mMockConnectCallback);
+        entry.onConnectionStatusChanged(
+                HotspotNetworkConnectionStatus.CONNECTION_STATUS_ENABLING_HOTSPOT);
+        mTestLooper.dispatchAll();
+
+        MockitoSession session = mockitoSession().spyStatic(NonSdkApiWrapper.class).startMocking();
+        try {
+            doReturn(true).when(() ->
+                    NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled());
+            assertThat(entry.getSummary(false)).isEqualTo("Connecting…");
+        } finally {
+            session.finishMocking();
+        }
+    }
+
+    @Test
+    public void testGetConnectedState_enabling_detailsPageFlagFalse_returnsDisconnected() {
+        final HotspotNetworkEntry entry = new HotspotNetworkEntry(
+                mMockInjector, mMockContext, mTestHandler,
+                mMockWifiManager, mMockSharedConnectivityManager, TEST_HOTSPOT_NETWORK_DATA);
+
+        entry.setListener(mMockListener);
+        entry.connect(mMockConnectCallback);
+        entry.onConnectionStatusChanged(
+                HotspotNetworkConnectionStatus.CONNECTION_STATUS_ENABLING_HOTSPOT);
+        mTestLooper.dispatchAll();
+
+        MockitoSession session = mockitoSession().spyStatic(NonSdkApiWrapper.class).startMocking();
+        try {
+            doReturn(false).when(() ->
+                    NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled());
+            assertThat(entry.getConnectedState())
+                    .isEqualTo(HotspotNetworkEntry.CONNECTED_STATE_DISCONNECTED);
+        } finally {
+            session.finishMocking();
+        }
+    }
+
+    @Test
+    public void testGetConnectedState_enabling_detailsPageFlagTrue_returnsConnecting() {
+        final HotspotNetworkEntry entry = new HotspotNetworkEntry(
+                mMockInjector, mMockContext, mTestHandler,
+                mMockWifiManager, mMockSharedConnectivityManager, TEST_HOTSPOT_NETWORK_DATA);
+
+        entry.setListener(mMockListener);
+        entry.connect(mMockConnectCallback);
+        entry.onConnectionStatusChanged(
+                HotspotNetworkConnectionStatus.CONNECTION_STATUS_ENABLING_HOTSPOT);
+        mTestLooper.dispatchAll();
+
+        MockitoSession session = mockitoSession().spyStatic(NonSdkApiWrapper.class).startMocking();
+        try {
+            doReturn(true).when(() ->
+                    NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled());
+            assertThat(entry.getConnectedState())
+                    .isEqualTo(HotspotNetworkEntry.CONNECTED_STATE_CONNECTING);
+        } finally {
+            session.finishMocking();
+        }
+    }
 }
diff --git a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/NonSdkApiWrapperTest.java b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/NonSdkApiWrapperTest.java
index 6c744b6db..25cfafa8a 100644
--- a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/NonSdkApiWrapperTest.java
+++ b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/NonSdkApiWrapperTest.java
@@ -16,16 +16,10 @@
 
 package com.android.wifitrackerlib;
 
-import static com.google.common.truth.Truth.assertThat;
-
 import static org.junit.Assert.assertEquals;
 import static org.mockito.Mockito.mock;
-import static org.mockito.Mockito.when;
 
 import android.content.Context;
-import android.net.NetworkCapabilities;
-import android.net.vcn.VcnTransportInfo;
-import android.net.wifi.WifiInfo;
 import android.text.Annotation;
 import android.text.SpannableString;
 import android.text.SpannableStringBuilder;
@@ -72,24 +66,4 @@ public class NonSdkApiWrapperTest {
         assertEquals(outputSpannableString.getSpans(0, outputSpannableString.length(),
                 ClickableSpan.class).length, 0);
     }
-
-    /**
-     * Verifies the functionality of {@link NonSdkApiWrapper#getWifiInfoIfVcn(NetworkCapabilities)}
-     */
-    @Test
-    public void testGetVcnWifiInfo() {
-        NetworkCapabilities networkCapabilities  = mock(NetworkCapabilities.class);
-
-        assertThat(NonSdkApiWrapper.getWifiInfoIfVcn(networkCapabilities)).isNull();
-
-        VcnTransportInfo vcnTransportInfo = mock(VcnTransportInfo.class);
-        when(networkCapabilities.getTransportInfo()).thenReturn(vcnTransportInfo);
-
-        assertThat(NonSdkApiWrapper.getWifiInfoIfVcn(networkCapabilities)).isNull();
-
-        WifiInfo wifiInfo = mock(WifiInfo.class);
-        when(vcnTransportInfo.getWifiInfo()).thenReturn(wifiInfo);
-
-        assertThat(NonSdkApiWrapper.getWifiInfoIfVcn(networkCapabilities)).isEqualTo(wifiInfo);
-    }
 }
diff --git a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/SavedNetworkTrackerTest.java b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/SavedNetworkTrackerTest.java
index d5a29767f..f66deb008 100644
--- a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/SavedNetworkTrackerTest.java
+++ b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/SavedNetworkTrackerTest.java
@@ -151,6 +151,7 @@ public class SavedNetworkTrackerTest {
         when(mMockConnectivityManager.getLinkProperties(mMockNetwork))
                 .thenReturn(mMockLinkProperties);
         when(mInjector.getContext()).thenReturn(mMockContext);
+        when(mInjector.getConnectivityManager()).thenReturn(mMockConnectivityManager);
         when(mMockContext.getResources()).thenReturn(mResources);
         when(mMockContext.getSystemService(ConnectivityDiagnosticsManager.class))
                 .thenReturn(mMockConnectivityDiagnosticsManager);
diff --git a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/UtilsTest.java b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/UtilsTest.java
index cf85810ed..8d83d1875 100644
--- a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/UtilsTest.java
+++ b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/UtilsTest.java
@@ -44,6 +44,7 @@ import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.reset;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.when;
 
@@ -99,6 +100,7 @@ public class UtilsTest {
     private static final String STRING_AVAILABLE_VIA_APP = "available_via_";
     private static final String STRING_CONNECTED_VIA_APP = "connected_via_";
     private static final String STRING_CONNECTED_LOW_QUALITY = "low_quality";
+    private static final String STRING_CONNECTED_LESS_SECURE = "less secure";
     private static final String STRING_NETWORK_AVAILABLE_SIGN_IN = "network_available_sign_in";
     private static final String STRING_LIMITED_CONNECTION = "limited_connection";
     private static final String STRING_CHECKING_FOR_INTERNET_ACCESS =
@@ -136,6 +138,11 @@ public class UtilsTest {
     private static final String STRING_LINK_SPEED_MBPS = " Mbps";
     private static final String STRING_LINK_SPEED_ON_BAND = " on ";
 
+    private static final String STRING_WEP_SECURITY = "WEP";
+    private static final String STRING_WEP_LESS_SECURE_APPEND =
+                    STRING_SUMMARY_SEPARATOR
+                    + STRING_WEP_SECURITY + " (" + STRING_CONNECTED_LESS_SECURE + ")";
+
     @Mock private WifiTrackerInjector mMockInjector;
     @Mock private Context mMockContext;
     @Mock private Resources mMockResources;
@@ -219,6 +226,11 @@ public class UtilsTest {
         when(mMockContext.getString(eq(R.string.wifitrackerlib_link_speed_on_band),
                 any())).thenAnswer((answer) -> answer.getArguments()[1] + STRING_LINK_SPEED_ON_BAND
                 + answer.getArguments()[2]);
+
+        when(mMockContext.getString(R.string.wifitrackerlib_wifi_security_wep))
+                .thenReturn(STRING_WEP_SECURITY);
+        when(mMockContext.getString(R.string.wifi_connected_less_secure, STRING_WEP_SECURITY))
+                .thenReturn(STRING_WEP_SECURITY + " (" + STRING_CONNECTED_LESS_SECURE + ")");
     }
 
     @Test
@@ -787,6 +799,7 @@ public class UtilsTest {
     public void testGetConnectedDescription() {
         WifiConfiguration wifiConfig = mock(WifiConfiguration.class);
         NetworkCapabilities networkCapabilities = mock(NetworkCapabilities.class);
+        WifiInfo wifiInfo = mock(WifiInfo.class);
         ConnectivityDiagnosticsManager.ConnectivityReport connectivityReport = mock(
                 ConnectivityDiagnosticsManager.ConnectivityReport.class);
 
@@ -795,6 +808,7 @@ public class UtilsTest {
                 mMockContext,
                 wifiConfig,
                 networkCapabilities,
+                wifiInfo,
                 true,
                 false,
                 null)).isEqualTo(STRING_CHECKING_FOR_INTERNET_ACCESS);
@@ -803,6 +817,7 @@ public class UtilsTest {
                 mMockContext,
                 null,
                 networkCapabilities,
+                wifiInfo,
                 false,
                 false,
                 null)).isEqualTo(STRING_CHECKING_FOR_INTERNET_ACCESS);
@@ -814,6 +829,7 @@ public class UtilsTest {
                 mMockContext,
                 null,
                 networkCapabilities,
+                wifiInfo,
                 true,
                 false,
                 null)).isEqualTo(STRING_WIFI_STATUS_CONNECTED);
@@ -823,6 +839,7 @@ public class UtilsTest {
                 mMockContext,
                 null,
                 networkCapabilities,
+                wifiInfo,
                 false,
                 true,
                 null)).isEqualTo(STRING_CONNECTED_LOW_QUALITY);
@@ -834,6 +851,7 @@ public class UtilsTest {
                 mMockContext,
                 wifiConfig,
                 networkCapabilities,
+                wifiInfo,
                 true,
                 false,
                 connectivityReport)).isEqualTo(STRING_WIFI_STATUS_CONNECTED
@@ -845,6 +863,7 @@ public class UtilsTest {
                 mMockContext,
                 wifiConfig,
                 networkCapabilities,
+                wifiInfo,
                 true,
                 false,
                 connectivityReport)).isEqualTo(STRING_CONNECTED_CANNOT_PROVIDE_INTERNET);
@@ -855,6 +874,7 @@ public class UtilsTest {
                 mMockContext,
                 wifiConfig,
                 networkCapabilities,
+                wifiInfo,
                 true,
                 false,
                 connectivityReport)).isEqualTo(STRING_PRIVATE_DNS_BROKEN);
@@ -866,6 +886,7 @@ public class UtilsTest {
                 mMockContext,
                 wifiConfig,
                 networkCapabilities,
+                wifiInfo,
                 true,
                 false,
                 null)).isEqualTo(STRING_LIMITED_CONNECTION);
@@ -877,6 +898,7 @@ public class UtilsTest {
                 mMockContext,
                 wifiConfig,
                 networkCapabilities,
+                wifiInfo,
                 true,
                 false,
                 null)).isEqualTo(STRING_NETWORK_AVAILABLE_SIGN_IN);
@@ -895,6 +917,7 @@ public class UtilsTest {
                 mMockContext,
                 suggestionConfig,
                 networkCapabilities,
+                wifiInfo,
                 true,
                 false,
                 connectivityReport)).isEqualTo(STRING_CONNECTED_VIA_APP + "appLabel"
@@ -907,6 +930,7 @@ public class UtilsTest {
                 mMockContext,
                 suggestionConfig,
                 networkCapabilities,
+                wifiInfo,
                 false,
                 true,
                 connectivityReport)).isEqualTo(STRING_AVAILABLE_VIA_APP + "appLabel"
@@ -921,6 +945,7 @@ public class UtilsTest {
                 mMockContext,
                 suggestionConfig,
                 networkCapabilities,
+                wifiInfo,
                 true,
                 false,
                 connectivityReport)).isEqualTo(STRING_AVAILABLE_VIA_APP + "appLabel"
@@ -935,10 +960,36 @@ public class UtilsTest {
                 mMockContext,
                 suggestionConfig,
                 networkCapabilities,
+                wifiInfo,
                 true,
                 false,
                 connectivityReport)).isEqualTo(STRING_CONNECTED_VIA_APP + "appLabel"
                 + STRING_SUMMARY_SEPARATOR + STRING_LIMITED_CONNECTION);
+
+        // Connected / WEP (less secure)
+        reset(networkCapabilities);
+        when(networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
+                .thenReturn(true);
+        when(wifiInfo.getCurrentSecurityType()).thenReturn(WifiInfo.SECURITY_TYPE_WEP);
+        assertThat(Utils.getConnectedDescription(
+                mMockContext,
+                null,
+                networkCapabilities,
+                wifiInfo,
+                true,
+                false,
+                null)).isEqualTo(STRING_WIFI_STATUS_CONNECTED + STRING_WEP_LESS_SECURE_APPEND);
+
+        // Connected via app / WEP (less secure)
+        assertThat(Utils.getConnectedDescription(
+                mMockContext,
+                suggestionConfig,
+                networkCapabilities,
+                wifiInfo,
+                true,
+                false,
+                connectivityReport)).isEqualTo(STRING_CONNECTED_VIA_APP + "appLabel"
+                + STRING_WEP_LESS_SECURE_APPEND);
     }
 
     @Test
diff --git a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/WifiPickerTrackerTest.java b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/WifiPickerTrackerTest.java
index ef50c4ca8..adb538bb4 100644
--- a/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/WifiPickerTrackerTest.java
+++ b/libs/WifiTrackerLib/tests/src/com/android/wifitrackerlib/WifiPickerTrackerTest.java
@@ -197,6 +197,7 @@ public class WifiPickerTrackerTest {
                         return TransportInfo.super.makeCopy(redactions);
                     }
                 });
+        when(mMockVcnNetworkCapabilities.getUnderlyingNetworks()).thenReturn(List.of(mMockNetwork));
         // A real NetworkCapabilities is needed here in order to create a copy (with location info)
         // using the NetworkCapabilities constructor in handleOnStart.
         NetworkCapabilities realNetCaps = new NetworkCapabilities.Builder()
@@ -226,6 +227,7 @@ public class WifiPickerTrackerTest {
                         "Connected", "Suspended", "Disconnecting", "Unsuccessful", "Blocked",
                         "Temporarily avoiding poor connection"});
         when(mInjector.isSharedConnectivityFeatureEnabled()).thenReturn(true);
+        when(mInjector.getConnectivityManager()).thenReturn(mMockConnectivityManager);
     }
 
     /**
@@ -601,7 +603,7 @@ public class WifiPickerTrackerTest {
         when(mMockWifiManager.getPrivilegedConfiguredNetworks())
                 .thenReturn(Collections.singletonList(config));
         when(mMockWifiManager.getScanResults()).thenReturn(Arrays.asList(
-                buildScanResult("ssid", "bssid", START_MILLIS)));
+                buildScanResult("ssid", "bssid", START_MILLIS, GOOD_RSSI)));
         wifiPickerTracker.onStart();
         mTestLooper.dispatchAll();
         verify(mMockConnectivityManager).registerNetworkCallback(
@@ -618,6 +620,54 @@ public class WifiPickerTrackerTest {
                 .onWifiEntriesChanged(WifiPickerTracker.WIFI_ENTRIES_CHANGED_REASON_GENERAL);
         assertThat(wifiPickerTracker.getWifiEntries()).isEmpty();
         assertThat(wifiPickerTracker.getConnectedWifiEntry()).isEqualTo(entry);
+
+        // Disconnect and verify network is on unconnectedl ist.
+        mNetworkCallbackCaptor.getValue().onLost(mMockNetwork);
+        mTestLooper.dispatchAll();
+
+        verify(mMockCallback, atLeastOnce())
+                .onWifiEntriesChanged(WifiPickerTracker.WIFI_ENTRIES_CHANGED_REASON_GENERAL);
+        assertThat(wifiPickerTracker.getConnectedWifiEntry()).isNull();
+        assertThat(wifiPickerTracker.getWifiEntries().get(0)).isEqualTo(entry);
+    }
+
+    /**
+     * Tests that connecting to a network will update getConnectedEntry() to return the connected
+     * WifiEntry and remove that entry from getWifiEntries().
+     */
+    @Test
+    public void testGetConnectedEntry_connectToNetworkNoScans_returnsConnectedEntry() {
+        final WifiPickerTracker wifiPickerTracker = createTestWifiPickerTracker();
+        final WifiConfiguration config = new WifiConfiguration();
+        config.SSID = "\"ssid\"";
+        config.networkId = 1;
+        when(mMockWifiManager.getPrivilegedConfiguredNetworks())
+                .thenReturn(Collections.singletonList(config));
+        when(mMockWifiInfo.getNetworkId()).thenReturn(1);
+        when(mMockWifiInfo.getRssi()).thenReturn(-50);
+        wifiPickerTracker.onStart();
+        mTestLooper.dispatchAll();
+        verify(mMockConnectivityManager).registerNetworkCallback(
+                any(), mNetworkCallbackCaptor.capture(), any());
+
+        // Connect to network and verify it's the connected entry.
+        mNetworkCallbackCaptor.getValue().onCapabilitiesChanged(
+                mMockNetwork, mMockNetworkCapabilities);
+        verify(mMockCallback, atLeastOnce())
+                .onWifiEntriesChanged(WifiPickerTracker.WIFI_ENTRIES_CHANGED_REASON_GENERAL);
+        assertThat(wifiPickerTracker.getWifiEntries()).isEmpty();
+        assertThat(wifiPickerTracker.getConnectedWifiEntry().getTitle()).isEqualTo("ssid");
+
+        // Disconnect and verify network is removed from list.
+        mNetworkCallbackCaptor.getValue().onLost(mMockNetwork);
+        mTestLooper.dispatchAll();
+
+        verify(mMockCallback, atLeastOnce())
+                .onWifiEntriesChanged(WifiPickerTracker.WIFI_ENTRIES_CHANGED_REASON_GENERAL);
+        assertThat(wifiPickerTracker.getConnectedWifiEntry()).isNull();
+        // TODO: The original author of this test mistakenly didn't check isEmpty(), and
+        // adding that check now fails the test.
+        // assertThat(wifiPickerTracker.getWifiEntries()).isEmpty();
     }
 
     /**
@@ -732,34 +782,6 @@ public class WifiPickerTrackerTest {
         assertThat(wifiPickerTracker.getConnectedWifiEntry().getTitle()).isEqualTo("ssid");
     }
 
-    /**
-     * Tests that disconnecting from a network will update getConnectedEntry() to return null.
-     */
-    @Test
-    public void testGetConnectedEntry_disconnectFromNetwork_returnsNull() {
-        final WifiPickerTracker wifiPickerTracker = createTestWifiPickerTracker();
-        final WifiConfiguration config = new WifiConfiguration();
-        config.SSID = "\"ssid\"";
-        config.networkId = 1;
-        when(mMockWifiManager.getPrivilegedConfiguredNetworks())
-                .thenReturn(Collections.singletonList(config));
-        when(mMockWifiManager.getScanResults()).thenReturn(Arrays.asList(
-                buildScanResult("ssid", "bssid", START_MILLIS)));
-        when(mMockWifiInfo.getNetworkId()).thenReturn(1);
-        when(mMockWifiInfo.getRssi()).thenReturn(-50);
-        wifiPickerTracker.onStart();
-        mTestLooper.dispatchAll();
-        verify(mMockConnectivityManager).registerNetworkCallback(
-                any(), mNetworkCallbackCaptor.capture(), any());
-
-        mNetworkCallbackCaptor.getValue().onLost(mMockNetwork);
-        mTestLooper.dispatchAll();
-
-        verify(mMockCallback, atLeastOnce())
-                .onWifiEntriesChanged(WifiPickerTracker.WIFI_ENTRIES_CHANGED_REASON_GENERAL);
-        assertThat(wifiPickerTracker.getConnectedWifiEntry()).isNull();
-    }
-
     /**
      * Tests that disconnecting from a network during the stopped state will result in the network
      * being disconnected once we've started again.
@@ -2256,11 +2278,9 @@ public class WifiPickerTrackerTest {
             // Connect to VCN-over-Wifi network
             when(mMockWifiInfo.isCarrierMerged()).thenReturn(true);
             when(mMockWifiInfo.getSubscriptionId()).thenReturn(subId);
-            doReturn(mMockWifiInfo).when(() ->
-                    NonSdkApiWrapper.getWifiInfoIfVcn(mMockVcnNetworkCapabilities));
             doReturn(true).when(() -> NonSdkApiWrapper.isPrimary(mMockWifiInfo));
             mNetworkCallbackCaptor.getValue().onCapabilitiesChanged(
-                    mMockNetwork, mMockVcnNetworkCapabilities);
+                    mMockNetwork, mMockNetworkCapabilities);
             MergedCarrierEntry mergedCarrierEntry = wifiPickerTracker.getMergedCarrierEntry();
             assertThat(mergedCarrierEntry.getConnectedState())
                     .isEqualTo(CONNECTED_STATE_CONNECTED);
@@ -2275,6 +2295,60 @@ public class WifiPickerTrackerTest {
         }
     }
 
+    /**
+     * Tests that the MergedCarrierEntry is the default network when it is connected and
+     * VPN-over-VCN-over-Wifi is the default network.
+     */
+    @Test
+    public void testGetMergedCarrierEntry_vpnOverVcnWifiIsDefault_entryIsDefaultNetwork() {
+        final int subId = 1;
+        final WifiPickerTracker wifiPickerTracker = createTestWifiPickerTracker();
+        wifiPickerTracker.onStart();
+        mTestLooper.dispatchAll();
+        verify(mMockContext).registerReceiver(mBroadcastReceiverCaptor.capture(),
+                any(), any(), any());
+        final Intent intent = new Intent(TelephonyManager.ACTION_DEFAULT_DATA_SUBSCRIPTION_CHANGED);
+        intent.putExtra("subscription", subId);
+        mBroadcastReceiverCaptor.getValue().onReceive(mMockContext, intent);
+        verify(mMockConnectivityManager).registerNetworkCallback(
+                any(), mNetworkCallbackCaptor.capture(), any());
+        verify(mMockConnectivityManager, atLeast(0)).registerSystemDefaultNetworkCallback(
+                mDefaultNetworkCallbackCaptor.capture(), any());
+        verify(mMockConnectivityManager, atLeast(0)).registerDefaultNetworkCallback(
+                mDefaultNetworkCallbackCaptor.capture(), any());
+
+        MockitoSession session = mockitoSession().spyStatic(NonSdkApiWrapper.class).startMocking();
+        try {
+            // Connect to VPN-over-VCN-over-Wifi network
+            when(mMockWifiInfo.isCarrierMerged()).thenReturn(true);
+            when(mMockWifiInfo.getSubscriptionId()).thenReturn(subId);
+            doReturn(true).when(() -> NonSdkApiWrapper.isPrimary(mMockWifiInfo));
+            mNetworkCallbackCaptor.getValue().onCapabilitiesChanged(
+                    mMockNetwork, mMockNetworkCapabilities);
+            MergedCarrierEntry mergedCarrierEntry = wifiPickerTracker.getMergedCarrierEntry();
+            assertThat(mergedCarrierEntry.getConnectedState())
+                    .isEqualTo(CONNECTED_STATE_CONNECTED);
+            // Wifi isn't default yet, so isDefaultNetwork returns false
+            assertThat(mergedCarrierEntry.isDefaultNetwork()).isFalse();
+
+
+            Network vpnNetwork = mock(Network.class);
+            Network vcnNetwork = mock(Network.class);
+            NetworkCapabilities vpnOverVcnOverWifiNetworkCapabilities =
+                    mock(NetworkCapabilities.class);
+            when(vpnOverVcnOverWifiNetworkCapabilities.getUnderlyingNetworks())
+                    .thenReturn(List.of(vcnNetwork));
+            when(mMockConnectivityManager.getNetworkCapabilities(vcnNetwork))
+                    .thenReturn(mMockVcnNetworkCapabilities);
+            mDefaultNetworkCallbackCaptor.getValue().onCapabilitiesChanged(vpnNetwork,
+                    vpnOverVcnOverWifiNetworkCapabilities);
+            // Now VPN-over-VCN-over-Wifi is default, so isDefaultNetwork returns true
+            assertThat(mergedCarrierEntry.isDefaultNetwork()).isTrue();
+        } finally {
+            session.finishMocking();
+        }
+    }
+
     /**
      * Tests that a MergedCarrierEntry is returned even if WifiPickerTracker hasn't been initialized
      * via handleOnStart() yet.
@@ -3064,4 +3138,122 @@ public class WifiPickerTrackerTest {
 
         verify(connectCallback).onConnectResult(WifiEntry.ConnectCallback.CONNECT_STATUS_SUCCESS);
     }
+
+    @Test
+    public void testHotspotNetworks_connectingToHotspot_detailsPageFlagFalse_entryInActive() {
+        final HotspotNetwork testHotspotNetwork = new HotspotNetwork.Builder()
+                .setDeviceId(1)
+                .setNetworkProviderInfo(new NetworkProviderInfo
+                        .Builder("My Phone", "Pixel 7")
+                        .setDeviceType(NetworkProviderInfo.DEVICE_TYPE_PHONE)
+                        .setBatteryPercentage(100)
+                        .setConnectionStrength(3)
+                        .build())
+                .setHostNetworkType(HotspotNetwork.NETWORK_TYPE_CELLULAR)
+                .setNetworkName("Google Fi")
+                .setHotspotSsid("Instant Hotspot abcde")
+                .addHotspotSecurityType(SECURITY_TYPE_PSK)
+                .build();
+        when(mMockSharedConnectivityManager.getHotspotNetworks()).thenReturn(
+                Collections.singletonList(testHotspotNetwork));
+        when(mMockSharedConnectivityManager.getHotspotNetworkConnectionStatus()).thenReturn(
+                new HotspotNetworkConnectionStatus.Builder()
+                        .setStatus(HotspotNetworkConnectionStatus
+                                .CONNECTION_STATUS_ENABLING_HOTSPOT)
+                        .setHotspotNetwork(testHotspotNetwork)
+                        .build());
+        when(mMockWifiInfo.getNetworkId()).thenReturn(1);
+        when(mMockWifiInfo.getRssi()).thenReturn(GOOD_RSSI);
+        when(mMockWifiInfo.getSSID()).thenReturn("Instant Hotspot abcde");
+        when(mMockWifiInfo.getCurrentSecurityType()).thenReturn(SECURITY_TYPE_PSK);
+        when(mMockWifiManager.getScanResults()).thenReturn(Collections.singletonList(
+                buildScanResult("Instant Hotspot abcde", "0a:0b:0c:0d:0e:0f", START_MILLIS,
+                        "[PSK/SAE]")));
+        NetworkInfo mockNetworkInfo = mock(NetworkInfo.class);
+        when(mockNetworkInfo.getDetailedState())
+                .thenReturn(NetworkInfo.DetailedState.CONNECTING);
+        MockitoSession session = mockitoSession().spyStatic(NonSdkApiWrapper.class).startMocking();
+        final WifiPickerTracker wifiPickerTracker = createTestWifiPickerTracker();
+        try {
+            doReturn(false).when(() ->
+                    NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled());
+            wifiPickerTracker.onStart();
+            mTestLooper.dispatchAll();
+            verify(mMockContext).registerReceiver(
+                    mBroadcastReceiverCaptor.capture(), any(), any(), any());
+            verify(mMockSharedConnectivityManager).registerCallback(any(),
+                    mSharedConnectivityCallbackCaptor.capture());
+            mSharedConnectivityCallbackCaptor.getValue().onServiceConnected();
+            Intent networkStateChanged = new Intent(WifiManager.NETWORK_STATE_CHANGED_ACTION);
+            networkStateChanged.putExtra(WifiManager.EXTRA_NETWORK_INFO, mockNetworkInfo);
+            mBroadcastReceiverCaptor.getValue().onReceive(mMockContext, networkStateChanged);
+            mTestLooper.dispatchAll();
+        } finally {
+            session.finishMocking();
+        }
+
+        assertThat(wifiPickerTracker.getWifiEntries().stream().filter(
+                entry -> entry instanceof HotspotNetworkEntry).toList()).isEmpty();
+        assertThat(wifiPickerTracker.getActiveWifiEntries().stream().filter(
+                entry -> entry instanceof HotspotNetworkEntry).toList()).hasSize(1);
+    }
+
+    @Test
+    public void testHotspotNetworks_connectingToHotspot_detailsPageFlagTrue_entryInAvailable() {
+        final HotspotNetwork testHotspotNetwork = new HotspotNetwork.Builder()
+                .setDeviceId(1)
+                .setNetworkProviderInfo(new NetworkProviderInfo
+                        .Builder("My Phone", "Pixel 7")
+                        .setDeviceType(NetworkProviderInfo.DEVICE_TYPE_PHONE)
+                        .setBatteryPercentage(100)
+                        .setConnectionStrength(3)
+                        .build())
+                .setHostNetworkType(HotspotNetwork.NETWORK_TYPE_CELLULAR)
+                .setNetworkName("Google Fi")
+                .setHotspotSsid("Instant Hotspot abcde")
+                .addHotspotSecurityType(SECURITY_TYPE_PSK)
+                .build();
+        when(mMockSharedConnectivityManager.getHotspotNetworks()).thenReturn(
+                Collections.singletonList(testHotspotNetwork));
+        when(mMockSharedConnectivityManager.getHotspotNetworkConnectionStatus()).thenReturn(
+                new HotspotNetworkConnectionStatus.Builder()
+                        .setStatus(HotspotNetworkConnectionStatus
+                                .CONNECTION_STATUS_ENABLING_HOTSPOT)
+                        .setHotspotNetwork(testHotspotNetwork)
+                        .build());
+        when(mMockWifiInfo.getNetworkId()).thenReturn(1);
+        when(mMockWifiInfo.getRssi()).thenReturn(GOOD_RSSI);
+        when(mMockWifiInfo.getSSID()).thenReturn("Instant Hotspot abcde");
+        when(mMockWifiInfo.getCurrentSecurityType()).thenReturn(SECURITY_TYPE_PSK);
+        when(mMockWifiManager.getScanResults()).thenReturn(Collections.singletonList(
+                buildScanResult("Instant Hotspot abcde", "0a:0b:0c:0d:0e:0f", START_MILLIS,
+                        "[PSK/SAE]")));
+        NetworkInfo mockNetworkInfo = mock(NetworkInfo.class);
+        when(mockNetworkInfo.getDetailedState())
+                .thenReturn(NetworkInfo.DetailedState.CONNECTING);
+        MockitoSession session = mockitoSession().spyStatic(NonSdkApiWrapper.class).startMocking();
+        final WifiPickerTracker wifiPickerTracker = createTestWifiPickerTracker();
+        try {
+            doReturn(true).when(() ->
+                    NonSdkApiWrapper.isHotspotNetworkConnectingStateForDetailsPageEnabled());
+            wifiPickerTracker.onStart();
+            mTestLooper.dispatchAll();
+            verify(mMockContext).registerReceiver(
+                    mBroadcastReceiverCaptor.capture(), any(), any(), any());
+            verify(mMockSharedConnectivityManager).registerCallback(any(),
+                    mSharedConnectivityCallbackCaptor.capture());
+            mSharedConnectivityCallbackCaptor.getValue().onServiceConnected();
+            Intent networkStateChanged = new Intent(WifiManager.NETWORK_STATE_CHANGED_ACTION);
+            networkStateChanged.putExtra(WifiManager.EXTRA_NETWORK_INFO, mockNetworkInfo);
+            mBroadcastReceiverCaptor.getValue().onReceive(mMockContext, networkStateChanged);
+            mTestLooper.dispatchAll();
+        } finally {
+            session.finishMocking();
+        }
+
+        assertThat(wifiPickerTracker.getWifiEntries().stream().filter(
+                entry -> entry instanceof HotspotNetworkEntry).toList()).hasSize(1);
+        assertThat(wifiPickerTracker.getActiveWifiEntries().stream().filter(
+                entry -> entry instanceof HotspotNetworkEntry).toList()).isEmpty();
+    }
 }
diff --git a/libwifi_system/supplicant_manager.cpp b/libwifi_system/supplicant_manager.cpp
index 60720d40f..c702370e3 100644
--- a/libwifi_system/supplicant_manager.cpp
+++ b/libwifi_system/supplicant_manager.cpp
@@ -21,13 +21,9 @@
 #include <fcntl.h>
 #include <string.h>
 #include <sys/stat.h>
+#include <sys/system_properties.h>
 #include <unistd.h>
 
-// This ugliness is necessary to access internal implementation details
-// of the property subsystem.
-#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
-#include <sys/_system_properties.h>
-
 namespace android {
 namespace wifi_system {
 namespace {
```

