```diff
diff --git a/aconfig/root.aconfig b/aconfig/root.aconfig
index d3f3f5ff..f82a8704 100644
--- a/aconfig/root.aconfig
+++ b/aconfig/root.aconfig
@@ -18,3 +18,10 @@ flag {
   bug: "347912855"
 }
 
+flag {
+  name: "check_frp_active"
+  namespace: "enterprise"
+  description: "Fix persistent data block check for provisioning"
+  bug: "365473481"
+}
+
diff --git a/res/drawable/empty_icon.xml b/res/drawable/empty_icon.xml
new file mode 100644
index 00000000..e94356f0
--- /dev/null
+++ b/res/drawable/empty_icon.xml
@@ -0,0 +1,11 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- This is an icon with no content taking up the same space as vd_theme_24. -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportHeight="24.0"
+    android:viewportWidth="24.0">
+  <path
+      android:fillColor="@android:color/transparent"
+      android:pathData="M0,0" />
+</vector>
diff --git a/res/drawable/gs_work_vd_theme_24.xml b/res/drawable/gs_work_vd_theme_24.xml
new file mode 100644
index 00000000..60d5da33
--- /dev/null
+++ b/res/drawable/gs_work_vd_theme_24.xml
@@ -0,0 +1,3 @@
+<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" android:height="24dp" android:viewportWidth="960" android:viewportHeight="960" android:tint="?attr/colorControlNormal">
+<path android:fillColor="@android:color/white" android:pathData="M160,840Q127,840 103.5,816.5Q80,793 80,760L80,320Q80,287 103.5,263.5Q127,240 160,240L320,240L320,160Q320,127 343.5,103.5Q367,80 400,80L560,80Q593,80 616.5,103.5Q640,127 640,160L640,240L800,240Q833,240 856.5,263.5Q880,287 880,320L880,760Q880,793 856.5,816.5Q833,840 800,840L160,840ZM160,760L800,760Q800,760 800,760Q800,760 800,760L800,320Q800,320 800,320Q800,320 800,320L160,320Q160,320 160,320Q160,320 160,320L160,760Q160,760 160,760Q160,760 160,760ZM400,240L560,240L560,160Q560,160 560,160Q560,160 560,160L400,160Q400,160 400,160Q400,160 400,160L400,240ZM160,760Q160,760 160,760Q160,760 160,760L160,320Q160,320 160,320Q160,320 160,320L160,320Q160,320 160,320Q160,320 160,320L160,760Q160,760 160,760Q160,760 160,760Z"/>
+</vector>
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 9f13a38e..cba1bb66 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -24,8 +24,8 @@
     <string name="setup_work_profile" msgid="1468934631731845267">"Stel werkprofiel op"</string>
     <string name="company_controls_workspace" msgid="2808025277267917221">"Jou organisasie beheer hierdie profiel en hou dit veilig. Jy beheer alle ander goed op jou toestel."</string>
     <string name="company_controls_device" msgid="8230957518758871390">"Jou organisasie sal hierdie toestel beheer en dit veilig hou."</string>
-    <string name="the_following_is_your_mdm" msgid="6613658218262376404">"Die volgende program sal toegang tot hierdie profiel moet hê:"</string>
-    <string name="the_following_is_your_mdm_for_device" msgid="6717973404364414816">"Die volgende program sal jou toestel bestuur:"</string>
+    <string name="the_following_is_your_mdm" msgid="6613658218262376404">"Die volgende app sal toegang tot hierdie profiel moet hê:"</string>
+    <string name="the_following_is_your_mdm_for_device" msgid="6717973404364414816">"Die volgende app sal jou toestel bestuur:"</string>
     <string name="next" msgid="1004321437324424398">"Volgende"</string>
     <string name="setting_up_workspace" msgid="7862472373642601041">"Stel tans werkprofiel op …"</string>
     <string name="admin_has_ability_to_monitor_profile" msgid="1018585795537086728">"Jou IT-admin kan instellings, korporatiewe toegang, programme, toestemmings, data en netwerkaktiwiteit wat met hierdie profiel geassosieer word, asook jou oproepgeskiedenis en kontaksoekgeskiedenis, monitor en bestuur. Kontak jou IT-admin vir meer inligting, insluitend jou organisasie se privaatheidsbeleide."</string>
@@ -45,7 +45,7 @@
     <string name="managed_device_info" msgid="1529447646526616811">"Inligting oor bestuurde toestel"</string>
     <string name="default_managed_profile_name" msgid="5370257687074907055">"Werkprofiel"</string>
     <string name="delete_profile_title" msgid="2841349358380849525">"Vee bestaande profiel uit?"</string>
-    <string name="opening_paragraph_delete_profile" msgid="4913885310795775967">"Jy het reeds \'n werkprofiel. Dit word met die volgende program bestuur:"</string>
+    <string name="opening_paragraph_delete_profile" msgid="4913885310795775967">"Jy het reeds \'n werkprofiel. Dit word met die volgende app bestuur:"</string>
     <string name="read_more_delete_profile" msgid="7789171620401666343"><a href="#read_this_link">"Lees hier"</a>" voordat jy voortgaan."</string>
     <string name="sure_you_want_to_delete_profile" msgid="6927697984573575564">"As jy voortgaan, sal alle programme en data in hierdie profiel uitgevee word."</string>
     <string name="delete_profile" msgid="2299218578684663459">"Vee uit"</string>
@@ -110,7 +110,7 @@
     <string name="setup_isnt_finished_contact_admin" msgid="8849644190723875952">"Opstelling is nie klaar nie. Kontak jou IT-administrateur vir hulp."</string>
     <string name="for_help_contact_admin" msgid="5922538077702487859">"Kontak jou IT-administrateur vir hulp"</string>
     <string name="organization_admin" msgid="5975914478148511290">"IT-administrateur"</string>
-    <string name="your_org_app_used" msgid="5336414768293540831">"<xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> sal hierdie toestel met die volgende program bestuur en monitor:"</string>
+    <string name="your_org_app_used" msgid="5336414768293540831">"<xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> sal hierdie toestel met die volgende app bestuur en monitor:"</string>
     <string name="your_organization_beginning" msgid="5952561489910967255">"Jou organisasie"</string>
     <string name="your_organization_middle" msgid="8288538158061644733">"jou organisasie"</string>
     <string name="view_terms" msgid="7230493092383341605">"Bekyk bepalings"</string>
@@ -156,7 +156,7 @@
     <string name="setup_provisioning_header" msgid="4282483198266806271">"Maak tans gereed om werktoestel op te stel …"</string>
     <string name="setup_provisioning_header_description" msgid="2567041263563823566">"Stel tans administrasieprogram op"</string>
     <string name="brand_screen_header" msgid="8865808542690116648">"Hierdie toestel behoort aan jou organisasie"</string>
-    <string name="brand_screen_subheader" msgid="7664792208784456436">"Die volgende program sal gebruik word om hierdie foon te bestuur en te monitor"</string>
+    <string name="brand_screen_subheader" msgid="7664792208784456436">"Die volgende app sal gebruik word om hierdie foon te bestuur en te monitor"</string>
     <string name="account_management_disclaimer_header" msgid="8013083414694316564">"Jou rekening word bestuur"</string>
     <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"Jou IT-admin gebruik mobiele bestuur om sekuriteitbeleide toe te pas"</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"Maak tans gereed vir werkopstelling …"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index f1dbdf37..2962f902 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -160,9 +160,9 @@
     <string name="account_management_disclaimer_header" msgid="8013083414694316564">"Dein Konto wird verwaltet"</string>
     <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"Dein IT-Administrator verwendet die Mobilgeräteverwaltung, um Sicherheitsrichtlinien durchzusetzen"</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"Einrichtung des Arbeitsprofils wird vorbereitet…"</string>
-    <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"Richten wir dein Arbeitsprofil ein"</string>
-    <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"In deinem Arbeitsprofil werden Apps für die Arbeit abgelegt"</string>
-    <string name="work_profile_provisioning_step_2_header" msgid="6001172190404670248">"Apps für die Arbeit pausieren, wenn du für heute fertig bist"</string>
+    <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"Arbeitsprofil einrichten"</string>
+    <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"In deinem Arbeitsprofil werden geschäftliche Apps abgelegt"</string>
+    <string name="work_profile_provisioning_step_2_header" msgid="6001172190404670248">"Geschäftliche Apps pausieren, wenn du Feierabend hast"</string>
     <string name="work_profile_provisioning_step_3_header" msgid="4316106639726774330">"Dein IT-Administrator kann Daten in deinem Arbeitsprofil sehen"</string>
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"Arbeitsprofil wird eingerichtet…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"Geschäftliche Apps werden in deinem Arbeitsprofil abgelegt. Wenn du mit deiner Arbeit für heute fertig bist, kannst du deine geschäftlichen Apps pausieren. Dein IT-Administrator kann die Daten in deinem Arbeitsprofil sehen."</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index e9584f9d..1e5f2b4c 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -188,7 +188,7 @@
     <string name="cope_provisioning_step_3_header" msgid="7161795433847296201">"Admin. gailua kontrola dezake, eta zenbait aplik. blokeatu"</string>
     <string name="cope_provisioning_summary" msgid="4993405755138454918">"Laneko aplikazioak laneko profilean gordetzen dira, eta IKT saileko administratzaileak kudeatzen ditu. Aplikazio pertsonalak bereizita daude eta ez daude laneko aplikazioen artean ikusgai. IKT saileko administratzaileak <xliff:g id="DEVICE_NAME">%1$s</xliff:g> gailua kontrola dezake, eta aplikazio jakin batzuk blokeatu."</string>
     <string name="just_a_sec" msgid="6244676028626237220">"Itxaron unetxo batean…"</string>
-    <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"Pribatutasun-abisua"</string>
+    <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"Pribatutasun-gogorarazpena"</string>
     <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"Baliteke IKT saileko administratzaileak <xliff:g id="DEVICE_NAME">%1$s</xliff:g> gailuan dauzkazun datuak eta egiten dituzun jarduerak ikusi ahal izatea"</string>
     <string name="financed_device_screen_header" msgid="5934940812896302344">"<xliff:g id="CREDITOR_NAME">%2$s</xliff:g> erakundeak eman du <xliff:g id="DEVICE_NAME">%1$s</xliff:g> gailua"</string>
     <string name="financed_make_payments_subheader_title" msgid="743966229235451097">"Egin <xliff:g id="DEVICE_NAME">%1$s</xliff:g> gailuarekin erlazionatutako ordainketak"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index ff4c322b..3b208079 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -36,7 +36,7 @@
     <string name="contact_your_admin_for_more_info" msgid="9209568156969966347">"Contatta l\'amministratore IT per ulteriori informazioni, comprese le norme sulla privacy della tua organizzazione."</string>
     <string name="learn_more_link" msgid="3012495805919550043">"Scopri di più"</string>
     <string name="cancel_setup" msgid="2949928239276274745">"Annulla"</string>
-    <string name="ok_setup" msgid="4593707675416137504">"OK"</string>
+    <string name="ok_setup" msgid="4593707675416137504">"Ok"</string>
     <string name="user_consent_msg" msgid="8820951802130353584">"Accetto"</string>
     <string name="url_error" msgid="5958494012986243186">"Impossibile visualizzare il link."</string>
     <string name="navigation_button_description" msgid="6106309408994461239">"Torna indietro"</string>
@@ -63,7 +63,7 @@
     <string name="change_device_launcher" msgid="4523563368433637980">"Cambia Avvio app del dispositivo"</string>
     <string name="launcher_app_cant_be_used_by_work_profile" msgid="3524366082000739743">"Questa app Avvio app non supporta il tuo profilo di lavoro"</string>
     <string name="cancel_provisioning" msgid="3408069559452653724">"Annulla"</string>
-    <string name="pick_launcher" msgid="4257084827403983845">"OK"</string>
+    <string name="pick_launcher" msgid="4257084827403983845">"Ok"</string>
     <string name="user_setup_incomplete" msgid="6494920045526591079">"Configurazione utenti incompleta"</string>
     <string name="default_owned_device_username" msgid="3915120202811807955">"Utente del dispositivo di lavoro"</string>
     <string name="setup_work_device" msgid="6003988351437862369">"Configurazione dispositivo di lavoro…"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index dbe6969e..64b752db 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -55,7 +55,7 @@
     <string name="encrypt_this_device_question" msgid="8719916619866892601">"להצפין את המכשיר?"</string>
     <string name="encrypt" msgid="1749320161747489212">"הצפנה"</string>
     <string name="continue_provisioning_notify_title" msgid="5191449100153186648">"ההצפנה הושלמה"</string>
-    <string name="continue_provisioning_notify_text" msgid="1066841819786425980">"יש להקיש כדי להמשיך בהגדרת פרופיל העבודה שלך"</string>
+    <string name="continue_provisioning_notify_text" msgid="1066841819786425980">"יש ללחוץ כדי להמשיך בהגדרת פרופיל העבודה שלך"</string>
     <string name="managed_provisioning_error_text" msgid="7063621174570680890">"‏לא ניתן להגדיר את פרופיל העבודה שלך. יש ליצור קשר עם מחלקת ה-IT או לנסות שוב מאוחר יותר."</string>
     <string name="cant_add_work_profile" msgid="9217268909964154934">"לא ניתן להוסיף פרופיל עבודה"</string>
     <string name="cant_replace_or_remove_work_profile" msgid="7861054306792698290">"לא ניתן להחליף או להסיר את פרופיל העבודה"</string>
@@ -131,7 +131,7 @@
     <string name="setup_device" msgid="1679201701102889156">"הגדרת המכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g>"</string>
     <string name="setup_device_encryption" msgid="2628196093806001835">"הגדרת המכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g>. הצפנה"</string>
     <string name="setup_device_progress" msgid="8792474713196537598">"הגדרת המכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g>. ההתקדמות מוצגת"</string>
-    <string name="learn_more_label" msgid="2723716758654655009">"לחצן \'למידע נוסף\'"</string>
+    <string name="learn_more_label" msgid="2723716758654655009">"כפתור \'למידע נוסף\'"</string>
     <string name="mdm_icon_label" msgid="3399134595549660561">"סמל <xliff:g id="ICON_LABEL">%1$s</xliff:g>"</string>
     <string name="section_heading" msgid="3924666803774291908">"כותרת הקטע \'<xliff:g id="SECTION_HEADING">%1$s</xliff:g>\'."</string>
     <string name="section_content" msgid="8875502515704374394">"תוכן הקטע \'<xliff:g id="SECTION_HEADING">%1$s</xliff:g>\': <xliff:g id="SECTION_CONTENT">%2$s</xliff:g>"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 29921ebe..221cd386 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -21,7 +21,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_label" msgid="1527793174155125990">"ಕೆಲಸದ ಸೆಟಪ್"</string>
     <string name="provisioning_error_title" msgid="6320515739861578118">"ಓಹ್!"</string>
-    <string name="setup_work_profile" msgid="1468934631731845267">"ಕೆಲಸದ ಪ್ರೊಫೈಲ್ ಹೊಂದಿಸಿ"</string>
+    <string name="setup_work_profile" msgid="1468934631731845267">"ಕೆಲಸದ ಪ್ರೊಫೈಲ್ ಸೆಟಪ್ ಮಾಡಿ"</string>
     <string name="company_controls_workspace" msgid="2808025277267917221">"ಈ ಪ್ರೊಫೈಲ್‌ ಅನ್ನು ನಿಮ್ಮ ಸಂಸ್ಥೆಯು ನಿಯಂತ್ರಿಸುತ್ತದೆ ಹಾಗೂ ಅದನ್ನು ಸುರಕ್ಷಿತವಾಗಿ ಕಾಪಾಡುತ್ತದೆ. ನಿಮ್ಮ ಸಾಧನದಲ್ಲಿರುವ ಪ್ರತಿಯೊಂದನ್ನೂ ನೀವು ನಿಯಂತ್ರಿಸಬಹುದು."</string>
     <string name="company_controls_device" msgid="8230957518758871390">"ನಿಮ್ಮ ಸಂಸ್ಥೆಯು ಈ ಸಾಧನವನ್ನು ನಿಯಂತ್ರಿಸುತ್ತದೆ ಹಾಗೂ ಅದನ್ನು ಸುರಕ್ಷಿತವಾಗಿರಿಸುತ್ತದೆ."</string>
     <string name="the_following_is_your_mdm" msgid="6613658218262376404">"ಕೆಳಗಿನ ಅಪ್ಲಿಕೇಶನ್‌ಗೆ ಈ ಪ್ರೊಫೈಲ್ ಪ್ರವೇಶಿಸುವ ಅಗತ್ಯವಿದೆ:"</string>
@@ -88,7 +88,7 @@
     <string name="error_hash_mismatch" msgid="1145488923243178454">"ಚೆಕ್‌ಸಮ್ ದೋಷ ಎದುರಾಗಿರುವ ಕಾರಣ ನಿರ್ವಾಹಕ ಆ್ಯಪ್ ಬಳಸಲು ಸಾಧ್ಯವಾಗುತ್ತಿಲ್ಲ. ಸಹಾಯಕ್ಕಾಗಿ, ನಿಮ್ಮ IT ನಿರ್ವಾಹಕರನ್ನು ಸಂಪರ್ಕಿಸಿ."</string>
     <string name="error_download_failed" msgid="3274283629837019452">"ನಿರ್ವಹಣೆ ಆ್ಯಪ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ"</string>
     <string name="error_package_invalid" msgid="555402554502033988">"ನಿರ್ವಾಹಕ ಆ್ಯಪ್ ಬಳಸಲು ಸಾಧ್ಯವಿಲ್ಲ. ಇದರ ಘಟಕಗಳು ಕಾಣೆಯಾಗಿವೆ ಅಥವಾ ದೋಷಪೂರಿತವಾಗಿವೆ. ಸಹಾಯಕ್ಕಾಗಿ, ನಿಮ್ಮ IT ನಿರ್ವಾಹಕರನ್ನು ಸಂಪರ್ಕಿಸಿ."</string>
-    <string name="error_installation_failed" msgid="2282903750318407285">"ನಿರ್ವಹಣೆ ಅಪ್ಲಿಕೇಶನ್‌ ಸ್ಥಾಪಿಸಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ"</string>
+    <string name="error_installation_failed" msgid="2282903750318407285">"ನಿರ್ವಹಣೆ ಆ್ಯಪ್‌ ಸ್ಥಾಪಿಸಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ"</string>
     <string name="profile_owner_cancel_message" msgid="6868736915633023477">"ಹೊಂದಿಸುವುದನ್ನು ನಿಲ್ಲಿಸುವುದೇ?"</string>
     <string name="profile_owner_cancel_cancel" msgid="4408725524311574891">"ಇಲ್ಲ"</string>
     <string name="profile_owner_cancel_ok" msgid="5951679183850766029">"ಹೌದು"</string>
@@ -116,18 +116,18 @@
     <string name="view_terms" msgid="7230493092383341605">"ನಿಯಮಗಳನ್ನು ವೀಕ್ಷಿಸಿ"</string>
     <string name="accept_and_continue" msgid="1632679734918410653">"ಸಮ್ಮತಿಸಿ, ಮುಂದುವರಿಸಿ"</string>
     <string name="back" msgid="6455622465896147127">"ಹಿಂದೆ"</string>
-    <string name="set_up_your_device" msgid="1896651520959894681">"ನಿಮ್ಮ ಸಾಧನ ಹೊಂದಿಸಿ"</string>
+    <string name="set_up_your_device" msgid="1896651520959894681">"ನಿಮ್ಮ ಸಾಧನ ಸೆಟಪ್ ಮಾಡಿ"</string>
     <string name="info_anim_title_0" msgid="3285414600215959704">"ನೀವು ಕೆಲಸ ಮಾಡುವ ರೀತಿಯನ್ನು ಬದಲಾಯಿಸಿ"</string>
     <string name="info_anim_title_1" msgid="2657512519467714760">"ಕೆಲಸವನ್ನು ವೈಯಕ್ತಿಕದಿಂದ ಪ್ರತ್ಯೇಕಿಸಿ"</string>
     <string name="one_place_for_work_apps" msgid="2595597562302953960">"ಉದ್ಯೋಗ ಅಪ್ಲಿಕೇಶನ್‌ಗಳಿಗಾಗಿ ಒಂದೇ ಸ್ಥಳ"</string>
     <string name="info_anim_title_2" msgid="4629781398620470204">"ನೀವು ಪೂರ್ಣಗೊಳಿಸಿದಾಗ ಕೆಲಸವನ್ನು ಆಫ್ ಮಾಡಿ"</string>
     <string name="provisioning" msgid="4512493827019163451">"ಒದಗಿಸಲಾಗುತ್ತಿದೆ"</string>
     <string name="copying_certs" msgid="5697938664953550881">"CA ಪ್ರಮಾಣಪತ್ರಗಳನ್ನು ಹೊಂದಿಸಲಾಗುತ್ತಿದೆ"</string>
-    <string name="setup_profile" msgid="5573950582159698549">"ನಿಮ್ಮ ಪ್ರೊಫೈಲ್ ಹೊಂದಿಸಿ"</string>
+    <string name="setup_profile" msgid="5573950582159698549">"ನಿಮ್ಮ ಪ್ರೊಫೈಲ್ ಸೆಟಪ್ ಮಾಡಿ"</string>
     <string name="profile_benefits_description" msgid="758432985984252636">"ಉದ್ಯೋಗ ಪ್ರೊಫೈಲ್ ಬಳಸುವ ಮೂಲಕ, ನೀವು ಉದ್ಯೋಗ ಡೇಟಾವನ್ನು ವೈಯಕ್ತಿಕ ಡೇಟಾದಿಂದ ಪ್ರತ್ಯೇಕಿಸಬಹುದು"</string>
     <string name="comp_profile_benefits_description" msgid="379837075456998273">"ಉದ್ಯೋಗ ಪ್ರೊಫೈಲ್ ಬಳಸಿಕೊಂಡು, ನಿಮ್ಮ ಉದ್ಯೋಗ ಅಪ್ಲಿಕೇಶನ್‌ಗಳನ್ನು ನೀವು ಒಂದೇ ಸ್ಥಳದಲ್ಲಿ ಇರಿಸಿಕೊಳ್ಳಬಹುದು"</string>
-    <string name="setup_profile_encryption" msgid="5241291404536277038">"ನಿಮ್ಮ ಪ್ರೊಫೈಲ್ ಹೊಂದಿಸಿ. ಎನ್‌ಕ್ರಿಪ್ಶನ್"</string>
-    <string name="setup_profile_progress" msgid="7742718527853325656">"ನಿಮ್ಮ ಪ್ರೊಫೈಲ್‌ ಹೊಂದಿಸಿ. ಪ್ರಗತಿಯನ್ನು ತೋರಿಸಲಾಗುತ್ತಿದೆ"</string>
+    <string name="setup_profile_encryption" msgid="5241291404536277038">"ನಿಮ್ಮ ಪ್ರೊಫೈಲ್ ಸೆಟಪ್ ಮಾಡಿ. ಎನ್‌ಕ್ರಿಪ್ಶನ್"</string>
+    <string name="setup_profile_progress" msgid="7742718527853325656">"ನಿಮ್ಮ ಪ್ರೊಫೈಲ್‌ ಸೆಟಪ್ ಮಾಡಿ. ಪ್ರಗತಿಯನ್ನು ತೋರಿಸಲಾಗುತ್ತಿದೆ"</string>
     <string name="setup_device" msgid="1679201701102889156">"ನಿಮ್ಮ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ಅನ್ನು ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="setup_device_encryption" msgid="2628196093806001835">"ನಿಮ್ಮ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ಅನ್ನು ಸೆಟಪ್ ಮಾಡಿ. ಎನ್‌ಕ್ರಿಪ್ಷನ್"</string>
     <string name="setup_device_progress" msgid="8792474713196537598">"ನಿಮ್ಮ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ಅನ್ನು ಸೆಟಪ್ ಮಾಡಿ. ಪ್ರಗತಿಯನ್ನು ತೋರಿಸಲಾಗುತ್ತಿದೆ"</string>
@@ -154,7 +154,7 @@
     <string name="work_profile_description" msgid="8524116010729569213">"ನಿಮ್ಮ ಕೆಲಸದ ಅಪ್ಲಿಕೇಶನ್‌ಗಳನ್ನು ಈ ಪ್ರೊಫೈಲ್‌ನಲ್ಲಿ ಇರಿಸಲಾಗುತ್ತದೆ ಮತ್ತು ನಿಮ್ಮ ಸಂಸ್ಥೆಯ ಮೂಲಕ ನಿರ್ವಹಿಸಲಾಗುತ್ತದೆ"</string>
     <string name="device_owner_description" msgid="168013145812679664">"ಈ ಸಾಧನವನ್ನು ಸುರಕ್ಷಿತವಾಗಿ ಇರಿಸಲಾಗುತ್ತದೆ ಮತ್ತು ನಿಮ್ಮ ಸಂಸ್ಥೆಯ ಮೂಲಕ ನಿರ್ವಹಿಸಲಾಗುತ್ತದೆ"</string>
     <string name="setup_provisioning_header" msgid="4282483198266806271">"ಕೆಲಸದ ಸಾಧನವನ್ನು ಸೆಟಪ್ ಮಾಡಲು ಸಿದ್ಧಗೊಳ್ಳುತ್ತಿದೆ ..."</string>
-    <string name="setup_provisioning_header_description" msgid="2567041263563823566">"ನಿರ್ವಹಣೆ ಅಪ್ಲಿಕೇಶನ್ ಹೊಂದಿಸಲಾಗುತ್ತಿದೆ"</string>
+    <string name="setup_provisioning_header_description" msgid="2567041263563823566">"ನಿರ್ವಹಣೆ ಆ್ಯಪ್‌ ಹೊಂದಿಸಲಾಗುತ್ತಿದೆ"</string>
     <string name="brand_screen_header" msgid="8865808542690116648">"ಈ ಸಾಧನವು ನಿಮ್ಮ ಸಂಸ್ಥೆಗೆ ಸೇರಿರುತ್ತದೆ"</string>
     <string name="brand_screen_subheader" msgid="7664792208784456436">"ಈ ಫೋನ್ ಅನ್ನು ನಿರ್ವಹಿಸಲು ಮತ್ತು ಮೇಲ್ವಿಚಾರಣೆ ಮಾಡಲು ಕೆಳಗಿನ ಆ್ಯಪ್‌ ಅನ್ನು ಬಳಸಲಾಗುತ್ತದೆ"</string>
     <string name="account_management_disclaimer_header" msgid="8013083414694316564">"ನಿಮ್ಮ ಖಾತೆಯನ್ನು ಹೊಸ ಸಾಧನದಲ್ಲಿ ನಿರ್ವಹಿಸಲಾಗುತ್ತದೆ"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index c5d27636..7e0d8812 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -155,7 +155,7 @@
     <string name="device_owner_description" msgid="168013145812679664">"此设备将由贵单位确保其安全并负责管理"</string>
     <string name="setup_provisioning_header" msgid="4282483198266806271">"正在准备设置工作设备…"</string>
     <string name="setup_provisioning_header_description" msgid="2567041263563823566">"设置管理应用"</string>
-    <string name="brand_screen_header" msgid="8865808542690116648">"此设备归贵单位所有"</string>
+    <string name="brand_screen_header" msgid="8865808542690116648">"此设备归贵组织所有"</string>
     <string name="brand_screen_subheader" msgid="7664792208784456436">"以下应用将用于管理和监控此手机"</string>
     <string name="account_management_disclaimer_header" msgid="8013083414694316564">"您的账号是受管理的账号"</string>
     <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"您的 IT 管理员会使用移动设备管理服务强制执行安全政策"</string>
diff --git a/src/com/android/managedprovisioning/common/SetupGlifLayoutActivity.java b/src/com/android/managedprovisioning/common/SetupGlifLayoutActivity.java
index 888ea8e8..69ca116f 100644
--- a/src/com/android/managedprovisioning/common/SetupGlifLayoutActivity.java
+++ b/src/com/android/managedprovisioning/common/SetupGlifLayoutActivity.java
@@ -17,19 +17,18 @@
 package com.android.managedprovisioning.common;
 
 import android.annotation.Nullable;
+import android.content.Context;
 import android.content.res.Resources;
 import android.os.Bundle;
 import android.text.Editable;
 import android.text.Layout;
 import android.text.TextWatcher;
+import android.util.TypedValue;
 import android.widget.TextView;
-
 import androidx.annotation.VisibleForTesting;
-
 import com.android.managedprovisioning.R;
-
 import com.google.android.setupdesign.GlifLayout;
-
+import com.google.android.setupdesign.template.IconMixin;
 
 /**
  * Base class for setting up the layout.
@@ -89,8 +88,22 @@ public abstract class SetupGlifLayoutActivity extends SetupLayoutActivity {
             increaseMaxLinesIfNecessary(header, mInitialHeaderMaxLines);
         }
 
+    if (ThemeHelper.shouldApplyGlifExpressiveStyle(this)) {
+        layout.setIcon(getDrawable(R.drawable.gs_work_vd_theme_24));
+        IconMixin iconMixin = layout.getMixin(IconMixin.class);
+        iconMixin.setIconTint(resolveColor(layout.getContext(), android.R.attr.colorPrimary));
+    } else {
         layout.setIcon(getDrawable(R.drawable.ic_enterprise_blue_24dp));
     }
+  }
+
+  private int resolveColor(Context context, int attr) {
+    TypedValue typedValue = new TypedValue();
+    if (context.getTheme().resolveAttribute(attr, typedValue, true)) {
+      return context.getColor(typedValue.resourceId);
+    }
+    return 0;
+  }
 
     /**
      * If the text takes more than its {@code textView}'s {@code initialMaxLines}, expand it one
diff --git a/src/com/android/managedprovisioning/common/SetupLayoutActivity.java b/src/com/android/managedprovisioning/common/SetupLayoutActivity.java
index dd228fbc..8df60260 100644
--- a/src/com/android/managedprovisioning/common/SetupLayoutActivity.java
+++ b/src/com/android/managedprovisioning/common/SetupLayoutActivity.java
@@ -78,11 +78,16 @@ public abstract class SetupLayoutActivity extends Hilt_SetupLayoutActivity {
         if (!isWaitingScreen()) {
             mTransitionHelper.applyContentScreenTransitions(this);
         }
-        updateDefaultNightMode();
-        setTheme(mThemeHelper.inferThemeResId(this, getIntent()));
-        if (shouldSetupDynamicColors()) {
-            mThemeHelper.setupDynamicColors(this);
+        boolean themeSet = mThemeHelper.setSuwTheme(this);
+        ProvisionLogger.logd("applyStyles themeSet:" + themeSet);
+        if (!themeSet) {
+            updateDefaultNightMode();
+            setTheme(mThemeHelper.inferThemeResId(this, getIntent()));
+            if (shouldSetupDynamicColors()) {
+                mThemeHelper.setupDynamicColors(this);
+            }
         }
+
         super.onCreate(savedInstanceState);
 
         getWindow().addSystemFlags(SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
@@ -106,7 +111,9 @@ public abstract class SetupLayoutActivity extends Hilt_SetupLayoutActivity {
     @Override
     public void onConfigurationChanged(@NonNull Configuration newConfig) {
         super.onConfigurationChanged(newConfig);
-        updateDefaultNightMode();
+        if (!mThemeHelper.setSuwTheme(this)) {
+            updateDefaultNightMode();
+        }
     }
 
     private void updateDefaultNightMode() {
diff --git a/src/com/android/managedprovisioning/common/ThemeHelper.java b/src/com/android/managedprovisioning/common/ThemeHelper.java
index f26da7f9..3534d670 100644
--- a/src/com/android/managedprovisioning/common/ThemeHelper.java
+++ b/src/com/android/managedprovisioning/common/ThemeHelper.java
@@ -40,7 +40,7 @@ import com.airbnb.lottie.LottieComposition;
 import com.google.android.setupcompat.util.WizardManagerHelper;
 import com.google.android.setupdesign.R;
 import com.google.android.setupdesign.util.ThemeResolver;
-
+import static com.google.android.setupdesign.util.ThemeHelper.trySetSuwTheme;
 /**
  * Helper with utility methods to manage the ManagedProvisioning theme and night mode.
  */
@@ -73,6 +73,11 @@ public class ThemeHelper {
                 .resolveTheme(defaultTheme, themeName, shouldSuppressDayNight(context));
     }
 
+    /** Returns {@code true} if the SUW theme is set. */
+    public boolean setSuwTheme(Context context) {
+        requireNonNull(context);
+        return trySetSuwTheme(context);
+    }
     /**
      * Sets up theme-specific colors. Must be called after {@link
      * #inferThemeResId(Context, Intent)}.
@@ -82,6 +87,13 @@ public class ThemeHelper {
         trySetDynamicColor(context);
     }
 
+    /** Returns {@code true} if this {@code context} should applied Glif expressive style. */
+    public static boolean shouldApplyGlifExpressiveStyle(Context context) {
+        requireNonNull(context);
+        return
+            com.google.android.setupdesign.util.ThemeHelper.shouldApplyGlifExpressiveStyle(context);
+    }
+
     /**
      * Returns the appropriate day or night mode, depending on the setup wizard flags.
      *
diff --git a/src/com/android/managedprovisioning/common/Utils.java b/src/com/android/managedprovisioning/common/Utils.java
index f690f133..50d99016 100644
--- a/src/com/android/managedprovisioning/common/Utils.java
+++ b/src/com/android/managedprovisioning/common/Utils.java
@@ -75,6 +75,7 @@ import com.google.android.setupcompat.template.FooterButton;
 import com.google.android.setupcompat.template.FooterButton.ButtonType;
 import com.google.android.setupdesign.GlifLayout;
 import com.google.android.setupdesign.util.DeviceHelper;
+import com.google.android.setupdesign.util.ThemeHelper;
 
 import java.io.FileInputStream;
 import java.io.IOException;
@@ -960,4 +961,15 @@ public class Utils {
                 }
             });
     }
+
+    /**
+     * Hides icon from [GlifLayout]. This is useful when we don't want to show an icon on loading
+     * screen.
+     */
+    public void hideIconIfBc25Enabled(GlifLayout glifLayout) {
+        if (ThemeHelper.shouldApplyGlifExpressiveStyle(glifLayout.getContext())) {
+        ProvisionLogger.logd("Setting icon to empty for loading screens");
+        glifLayout.setIcon(glifLayout.getContext().getDrawable(R.drawable.empty_icon));
+        }
+    }
 }
diff --git a/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityController.java b/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityController.java
index ba216005..bc17243b 100644
--- a/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityController.java
+++ b/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityController.java
@@ -1051,6 +1051,12 @@ public class PreProvisioningActivityController {
             ProvisionLogger.logd("Reset protection not supported.");
             return false;
         }
+
+        if (Flags.checkFrpActive()) {
+            boolean isFrpActive = mPdbManager.isFactoryResetProtectionActive();
+            ProvisionLogger.logd("Is factory reset protection active: " + isFrpActive);
+            return isFrpActive;
+        }
         int size = mPdbManager.getDataBlockSize();
         ProvisionLogger.logd("Data block size: " + size);
         return size > 0;
diff --git a/src/com/android/managedprovisioning/provisioning/AdminIntegratedFlowPrepareActivity.java b/src/com/android/managedprovisioning/provisioning/AdminIntegratedFlowPrepareActivity.java
index c53b4bd0..8b0d37e8 100644
--- a/src/com/android/managedprovisioning/provisioning/AdminIntegratedFlowPrepareActivity.java
+++ b/src/com/android/managedprovisioning/provisioning/AdminIntegratedFlowPrepareActivity.java
@@ -130,6 +130,7 @@ public class AdminIntegratedFlowPrepareActivity extends AbstractProvisioningActi
         CharSequence deviceName = DeviceHelper.getDeviceName(getApplicationContext());
         final String title = getString(R.string.setup_device_progress, deviceName);
         initializeLayoutParams(R.layout.empty_loading_layout, headerResId);
+        getUtils().hideIconIfBc25Enabled(findViewById(R.id.setup_wizard_layout));
         setTitle(title);
     }
 
diff --git a/src/com/android/managedprovisioning/provisioning/ProvisioningActivityBridgeImpl.java b/src/com/android/managedprovisioning/provisioning/ProvisioningActivityBridgeImpl.java
index d9e572f2..52aa096a 100644
--- a/src/com/android/managedprovisioning/provisioning/ProvisioningActivityBridgeImpl.java
+++ b/src/com/android/managedprovisioning/provisioning/ProvisioningActivityBridgeImpl.java
@@ -89,6 +89,7 @@ abstract class ProvisioningActivityBridgeImpl implements ProvisioningActivityBri
         activity.setTitle(title);
 
         GlifLayout layout = activity.findViewById(R.id.setup_wizard_layout);
+        getUtils().hideIconIfBc25Enabled(layout);
         setupEducationViews(layout, activity, getShouldSkipEducationScreens(),
                 getProgressLabelResId());
         if (getUtils().isFinancedDeviceAction(getParams().provisioningAction)) {
```

