```diff
diff --git a/README.md b/README.md
index 75a126d9..a6a3f8bd 100644
--- a/README.md
+++ b/README.md
@@ -14,8 +14,6 @@ Bundled app responsible for provisioning an enterprise device
 }
 ```
 
-![Code](https://chart.googleapis.com/chart?chs=420x420&cht=qr&chl=%7B%27android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME%27%3A+%27com.afwsamples.testdpc%2Fcom.afwsamples.testdpc.DeviceAdminReceiver%27%2C+%27android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION%27%3A+%27https%3A%2F%2Ftestdpc-latest-apk.appspot.com%2Fpreview%27%2C+%27android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM%27%3A+%27gJD2YwtOiWJHkSMkkIfLRlj-quNqG1fb6v100QmzM9w%3D%27%7D&choe=UTF-8)
-
 ## AS Setup
 
 ```bash
diff --git a/aconfig/root.aconfig b/aconfig/root.aconfig
index 316e59c3..d3f3f5ff 100644
--- a/aconfig/root.aconfig
+++ b/aconfig/root.aconfig
@@ -1,4 +1,4 @@
-# proto-file: build/make/tools/aconfig/protos/aconfig.proto
+# proto-file: build/make/tools/aconfig/aconfig_protos/aconfig.proto
 # proto-message: flag_declarations
 
 package: "com.android.managedprovisioning.flags"
@@ -10,3 +10,11 @@ flag {
   description: "Enables Cosmic Ray features"
   bug: "288413994"
 }
+
+flag {
+  name: "bad_state_v3_early_rh_download_enabled"
+  namespace: "enterprise"
+  description: "Download and provision role holder provisioning before precondition checks"
+  bug: "347912855"
+}
+
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index ce59980a..9f13a38e 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -167,11 +167,11 @@
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"Stel tans jou werkprofiel op …"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"Werkprogramme word in jou werkprofiel gehou. Jy kan jou werkprogramme onderbreek wanneer jy klaar is vir die dag. Data in jou werkprofiel is sigbaar vir jou IT-administrateur."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"Kom ons stel jou werktoestel op"</string>
-    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Hou jou werkprogramme binne jou bereik"</string>
+    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Hou jou werkapps binne jou bereik"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Hierdie <xliff:g id="DEVICE_NAME">%1$s</xliff:g> is nie privaat nie"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"Jou IT-admin kan dalk jou data en aktiwiteit op hierdie <xliff:g id="DEVICE_NAME">%1$s</xliff:g> sien."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"Jou aktiwiteit en data"</string>
-    <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"Programtoestemmings"</string>
+    <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"Apptoestemmings"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_subheader" msgid="1973320148595109400">"Jou IT-admin kan toestemmings vir apps op hierdie <xliff:g id="DEVICE_NAME">%1$s</xliff:g> stel, soos mikrofoon-, kamera- en liggingtoestemmings."</string>
     <string name="fully_managed_device_provisioning_progress_label" msgid="3925516135130021966">"Stel tans jou toestel op …"</string>
     <string name="fully_managed_device_provisioning_summary" msgid="2532673962822596806">"Gebruik hierdie <xliff:g id="DEVICE_NAME_0">%1$s</xliff:g> om maklik toegang tot jou werkapps te kry. Hierdie <xliff:g id="DEVICE_NAME_1">%1$s</xliff:g> is nie privaat nie, en jou IT-admin kan dalk jou data en aktiwiteit sien."</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 64dc2e8d..a8b7660c 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -45,12 +45,12 @@
     <string name="managed_device_info" msgid="1529447646526616811">"معلومات الجهاز المُدار"</string>
     <string name="default_managed_profile_name" msgid="5370257687074907055">"ملف العمل"</string>
     <string name="delete_profile_title" msgid="2841349358380849525">"هل تريد حذف الملف الشخصي الحالي؟"</string>
-    <string name="opening_paragraph_delete_profile" msgid="4913885310795775967">"لديك مسبقًا ملف شخصي للعمل تتم إدارته باستخدام التطبيق التالي:"</string>
+    <string name="opening_paragraph_delete_profile" msgid="4913885310795775967">"لديك مسبقًا ملف للعمل تتم إدارته باستخدام التطبيق التالي:"</string>
     <string name="read_more_delete_profile" msgid="7789171620401666343">"قبل المتابعة، يجب "<a href="#read_this_link">"قراءة هذا"</a>"."</string>
     <string name="sure_you_want_to_delete_profile" msgid="6927697984573575564">"سيتم حذف جميع التطبيقات والبيانات في هذا الملف الشخصي عند المتابعة."</string>
     <string name="delete_profile" msgid="2299218578684663459">"حذف"</string>
     <string name="cancel_delete_profile" msgid="5155447537894046036">"إلغاء"</string>
-    <string name="encrypt_device_text_for_profile_owner_setup" msgid="6865483664167134470">"لضبط إعدادات ملفك الشخصي للعمل، يجب تشفير \"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>\". قد يستغرق هذا بعض الوقت."</string>
+    <string name="encrypt_device_text_for_profile_owner_setup" msgid="6865483664167134470">"لضبط إعدادات ملف العمل الخاص بك، يجب تشفير \"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>\". قد يستغرق هذا بعض الوقت."</string>
     <string name="encrypt_device_text_for_device_owner_setup" msgid="230099563510460941">"لضبط إعدادات جهاز \"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>\" هذا، يجب تشفيره أولاً. قد يستغرق هذا بعض الوقت."</string>
     <string name="encrypt_this_device_question" msgid="8719916619866892601">"هل تريد ترميز هذا الجهاز؟"</string>
     <string name="encrypt" msgid="1749320161747489212">"ترميز"</string>
@@ -59,7 +59,7 @@
     <string name="managed_provisioning_error_text" msgid="7063621174570680890">"تعذر إعداد ملف العمل. يمكنك الاتصال بقسم تكنولوجيا المعلومات أو إعادة المحاولة لاحقًا."</string>
     <string name="cant_add_work_profile" msgid="9217268909964154934">"يتعذر إضافة ملف العمل"</string>
     <string name="cant_replace_or_remove_work_profile" msgid="7861054306792698290">"يتعذَّر استبدال ملف العمل أو إزالته"</string>
-    <string name="work_profile_cant_be_added_contact_admin" msgid="4866281518235832928">"تتعذَّر إضافة ملف شخصي للعمل على جهاز \"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>\" هذا. إذا كان لديك أسئلة، يمكنك التواصل مع مشرف تكنولوجيا."</string>
+    <string name="work_profile_cant_be_added_contact_admin" msgid="4866281518235832928">"تتعذَّر إضافة ملف للعمل على جهاز \"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>\" هذا. إذا كان لديك أسئلة، يمكنك التواصل مع مشرف تكنولوجيا."</string>
     <string name="change_device_launcher" msgid="4523563368433637980">"تغيير مشغّل الجهاز"</string>
     <string name="launcher_app_cant_be_used_by_work_profile" msgid="3524366082000739743">"لا يمكن لملف العمل استخدام تطبيق المشغّل هذا"</string>
     <string name="cancel_provisioning" msgid="3408069559452653724">"إلغاء"</string>
@@ -98,8 +98,8 @@
     <string name="continue_button" msgid="7177918589510964446">"متابعة"</string>
     <string name="work_profile_setup_stop" msgid="6772128629992514750">"إيقاف"</string>
     <string name="dismiss" msgid="9009534756748565880">"إغلاق"</string>
-    <string name="profile_owner_info" msgid="8975319972303812298">"أنت بصدد إنشاء ملف شخصي للعمل تتم إدارته ومراقبته بواسطة مؤسستك. تسري البنود."</string>
-    <string name="profile_owner_info_with_terms_headers" msgid="7373591910245655373">"أنت بصدد إنشاء ملف شخصي للعمل يخضع لإدارة ومراقبة مؤسستك. تسري البنود المتبعة في <xliff:g id="TERMS_HEADERS">%1$s</xliff:g>."</string>
+    <string name="profile_owner_info" msgid="8975319972303812298">"أنت بصدد إنشاء ملف للعمل تتم إدارته ومراقبته بواسطة مؤسستك. تسري البنود."</string>
+    <string name="profile_owner_info_with_terms_headers" msgid="7373591910245655373">"أنت بصدد إنشاء ملف للعمل يخضع لإدارة ومراقبة مؤسستك. تسري البنود المتبعة في <xliff:g id="TERMS_HEADERS">%1$s</xliff:g>."</string>
     <string name="profile_owner_info_comp" msgid="9190421701126119142">"سيتم إنشاء ملف شخصي لتطبيقات العمل، وسيخضع هذا الملف الشخصي وباقي محتوى الجهاز لإدارة ومراقبة مؤسستك. تسري البنود."</string>
     <string name="profile_owner_info_with_terms_headers_comp" msgid="2012766614492554556">"سيتم إنشاء ملف شخصي لتطبيقات العمل، وسيخضع هذا الملف الشخصي وباقي محتوى الجهاز لإدارة ومراقبة مؤسستك. تسري البنود في <xliff:g id="TERMS_HEADERS">%1$s</xliff:g>."</string>
     <string name="device_owner_info" msgid="3716661456037934467">"ستدير مؤسسة <xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> هذا الجهاز وتراقبه وتحافظ على أمانه. وسيتم تطبيق الأحكام السارية. <xliff:g id="VIEW_TERMS">%2$s</xliff:g>"</string>
@@ -124,7 +124,7 @@
     <string name="provisioning" msgid="4512493827019163451">"جارٍ توفير الشهادات"</string>
     <string name="copying_certs" msgid="5697938664953550881">"‏جارٍ إعداد شهادات CA"</string>
     <string name="setup_profile" msgid="5573950582159698549">"إعداد الملف الشخصي"</string>
-    <string name="profile_benefits_description" msgid="758432985984252636">"باستخدام ملف شخصي للعمل، يمكنك الفصل بين بيانات العمل والبيانات الشخصية"</string>
+    <string name="profile_benefits_description" msgid="758432985984252636">"باستخدام ملف للعمل، يمكنك الفصل بين بيانات العمل والبيانات الشخصية"</string>
     <string name="comp_profile_benefits_description" msgid="379837075456998273">"يعني استخدامك ملفًا شخصيًا للعمل أنه يمكنك الاحتفاظ بتطبيقات عملك في مكان واحد"</string>
     <string name="setup_profile_encryption" msgid="5241291404536277038">"إعداد ملفك الشخصي. التشفير"</string>
     <string name="setup_profile_progress" msgid="7742718527853325656">"إعداد ملفك الشخصي. جارٍ عرض التقدم"</string>
@@ -161,11 +161,11 @@
     <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"تتم إدارة الأجهزة الجوّالة من قِبل مشرف تكنولوجيا المعلومات في مؤسستك لفرض سياسات الأمان."</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"جارٍ إعداد جهاز العمل…"</string>
     <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"لنبدأ بإعداد ملف العمل"</string>
-    <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"يتم الاحتفاظ بتطبيقات العمل في ملفك الشخصي للعمل"</string>
+    <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"يتم الاحتفاظ بتطبيقات العمل في ملف العمل الخاص بك"</string>
     <string name="work_profile_provisioning_step_2_header" msgid="6001172190404670248">"إيقاف تطبيقات العمل مؤقتًا عند انتهاء مهام يوم العمل"</string>
-    <string name="work_profile_provisioning_step_3_header" msgid="4316106639726774330">"يمكن لمشرف تكنولوجيا المعلومات رؤية البيانات في ملفك الشخصي للعمل"</string>
+    <string name="work_profile_provisioning_step_3_header" msgid="4316106639726774330">"يمكن لمشرف تكنولوجيا المعلومات رؤية البيانات في ملف العمل الخاص بك"</string>
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"جارٍ إعداد ملف العمل…"</string>
-    <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"يتم الاحتفاظ بتطبيقات العمل في ملفك الشخصي للعمل. يمكنك إيقاف تطبيقات العمل مؤقتًا عند انتهاء مهام يوم العمل. إنّ بيانات ملفك الشخصي للعمل مرئية لمشرف تكنولوجيا المعلومات في مؤسستك."</string>
+    <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"يتم الاحتفاظ بتطبيقات العمل في ملف العمل الخاص بك. يمكنك إيقاف تطبيقات العمل مؤقتًا عند انتهاء مهام يوم العمل. إنّ بيانات ملف العمل الخاص بك مرئية لمشرف تكنولوجيا المعلومات في مؤسستك."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"حان وقت إعداد جهاز العمل"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"التحكم بسهولة في تطبيقات العمل"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"جهاز \"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>\" هذا ليس خاصًا"</string>
@@ -186,7 +186,7 @@
     <string name="cope_provisioning_step_1_header" msgid="1945759718804756423">"تبقى تطبيقات العمل بحساب العمل ويديرها مشرف تقنية المعلومات"</string>
     <string name="cope_provisioning_step_2_header" msgid="2388399739294883042">"التطبيقات الشخصية منفصلة عن تطبيقات العمل ومخفية عنها"</string>
     <string name="cope_provisioning_step_3_header" msgid="7161795433847296201">"يستطيع المشرف التحكم بالجهاز وحظر التطبيقات"</string>
-    <string name="cope_provisioning_summary" msgid="4993405755138454918">"يتم الاحتفاظ بتطبيقات العمل في ملفك الشخصي للعمل ويديرها مشرف تكنولوجيا المعلومات في مؤسستك. تكون التطبيقات الشخصية منفصلة عن تطبيقات العمل ومخفية عنها. يستطيع مشرف تكنولوجيا المعلومات التحكّم في جهاز \"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>\" هذا وحظر تطبيقات معيّنة."</string>
+    <string name="cope_provisioning_summary" msgid="4993405755138454918">"يتم الاحتفاظ بتطبيقات العمل في ملف العمل الخاص بك ويديرها مشرف تكنولوجيا المعلومات في مؤسستك. تكون التطبيقات الشخصية منفصلة عن تطبيقات العمل ومخفية عنها. يستطيع مشرف تكنولوجيا المعلومات التحكّم في جهاز \"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>\" هذا وحظر تطبيقات معيّنة."</string>
     <string name="just_a_sec" msgid="6244676028626237220">"لحظة من فضلك…"</string>
     <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"تذكير الخصوصية"</string>
     <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"قد يتمكّن مشرف تكنولوجيا المعلومات من الاطّلاع على بياناتك وأنشطتك على جهاز \"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>\" هذا."</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index a773ad05..79ceebcc 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -168,7 +168,7 @@
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"Працоўныя праграмы захоўваюцца ў вашым працоўным профілі. На перыяд, калі вы не будзеце карыстацца працоўнымі праграмамі, вы можаце прыпыніць іх. Ваш ІT-адміністратар можа бачыць даныя ў працоўным профілі."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"Давайце наладзім вашу працоўную прыладу"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Заўсёды трымайце свае працоўныя праграмы пад рукой"</string>
-    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Гэта прылада <xliff:g id="DEVICE_NAME">%1$s</xliff:g> не з\'яўляецца прыватнай"</string>
+    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Гэта прылада <xliff:g id="DEVICE_NAME">%1$s</xliff:g> не з’яўляецца прыватнай"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"Ваш ІT-адміністратар можа праглядаць вашы даныя і дзеянні на гэтай прыладзе <xliff:g id="DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"Вашы дзеянні і даныя"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"Дазволы праграм"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 6836d4b6..00b2a0c8 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -29,7 +29,7 @@
     <string name="next" msgid="1004321437324424398">"Següent"</string>
     <string name="setting_up_workspace" msgid="7862472373642601041">"S\'està configurant el perfil de treball…"</string>
     <string name="admin_has_ability_to_monitor_profile" msgid="1018585795537086728">"El teu administrador de TI pot supervisar i gestionar la configuració, l\'accés corporatiu, les aplicacions, els permisos, les dades i l\'activitat de xarxa associats a aquest perfil, a més de l\'historial de trucades i l\'historial de cerques de contactes. Contacta amb l\'administrador de TI per obtenir més informació i consultar les polítiques de privadesa de la teva organització."</string>
-    <string name="admin_has_ability_to_monitor_device" msgid="7786186939607332934">"L\'administrador de TI pot supervisar i gestionar la configuració, l\'accés corporatiu, les aplicacions, els permisos i les dades associades a <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, inclosa l\'activitat de xarxa, així com la ubicació, l\'historial de trucades i l\'historial de cerques de contactes al dispositiu.<xliff:g id="LINE_BREAK">
+    <string name="admin_has_ability_to_monitor_device" msgid="7786186939607332934">"L\'administrador de TI pot supervisar i gestionar la configuració, l\'accés corporatiu, les aplicacions, els permisos i les dades associades al teu dispositiu <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, inclosa l\'activitat de xarxa, així com la ubicació, l\'historial de trucades i l\'historial de cerques de contactes del dispositiu.<xliff:g id="LINE_BREAK">
 
 </xliff:g>Contacta amb l\'administrador de TI per obtenir més informació i consultar les polítiques de privadesa de la teva organització."</string>
     <string name="theft_protection_disabled_warning" msgid="3708092473574738478">"Per utilitzar les funcions de protecció antirobatori has de fer servir un bloqueig de pantalla protegit per contrasenya al dispositiu."</string>
@@ -109,7 +109,7 @@
     <string name="if_questions_contact_admin" msgid="3509427015901582047">"Si tens cap dubte, contacta amb l\'administrador de TI"</string>
     <string name="setup_isnt_finished_contact_admin" msgid="8849644190723875952">"No s\'ha completat la configuració. Contacta amb l\'administrador de TI per obtenir ajuda."</string>
     <string name="for_help_contact_admin" msgid="5922538077702487859">"Per obtenir ajuda, contacta amb l\'administrador de TI"</string>
-    <string name="organization_admin" msgid="5975914478148511290">"Administrador de TI"</string>
+    <string name="organization_admin" msgid="5975914478148511290">"administrador de TI"</string>
     <string name="your_org_app_used" msgid="5336414768293540831">"<xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> gestionarà i supervisarà aquest dispositiu amb l\'aplicació següent:"</string>
     <string name="your_organization_beginning" msgid="5952561489910967255">"La teva organització"</string>
     <string name="your_organization_middle" msgid="8288538158061644733">"la teva organització"</string>
@@ -168,11 +168,11 @@
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"Les aplicacions de treball es desaran al teu perfil professional. Pots posar-les en pausa quan hagis acabat la jornada. L\'administrador de TI pot veure les dades del teu perfil de treball."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"Configurem el teu dispositiu de la feina"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Pots tenir totes les teves aplicacions de treball al teu abast"</string>
-    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Aquest dispositiu (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>) no és privat"</string>
-    <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"És possible que l\'administrador de TI pugui veure les teves dades i la teva activitat en aquest dispositiu (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>)."</string>
+    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Aquest dispositiu <xliff:g id="DEVICE_NAME">%1$s</xliff:g> no és privat"</string>
+    <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"És possible que l\'administrador de TI pugui veure les teves dades i la teva activitat en aquest dispositiu <xliff:g id="DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"Activitat i dades"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"Permisos d\'aplicacions"</string>
-    <string name="fully_managed_device_provisioning_permissions_secondary_subheader" msgid="1973320148595109400">"L\'administrador de TI pot configurar els permisos de les aplicacions d\'aquest dispositiu (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>), inclosos els permisos d\'accés al micròfon, a la càmera i a la ubicació."</string>
+    <string name="fully_managed_device_provisioning_permissions_secondary_subheader" msgid="1973320148595109400">"L\'administrador de TI pot configurar els permisos de les aplicacions d\'aquest dispositiu <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, inclosos els permisos d\'accés al micròfon, a la càmera i a la ubicació."</string>
     <string name="fully_managed_device_provisioning_progress_label" msgid="3925516135130021966">"S\'està configurant el dispositiu…"</string>
     <string name="fully_managed_device_provisioning_summary" msgid="2532673962822596806">"Utilitza aquest dispositiu (<xliff:g id="DEVICE_NAME_0">%1$s</xliff:g>) per accedir fàcilment a les teves aplicacions de treball. Aquest dispositiu (<xliff:g id="DEVICE_NAME_1">%1$s</xliff:g>) no és privat i, per tant, és possible que l\'administrador de TI pugui veure les teves dades i la teva activitat."</string>
     <string name="fully_managed_device_with_permission_control_provisioning_summary" msgid="3487964472228264628">"Utilitza aquest dispositiu (<xliff:g id="DEVICE_NAME_0">%1$s</xliff:g>) per accedir fàcilment a les teves aplicacions de treball. Aquest dispositiu (<xliff:g id="DEVICE_NAME_1">%1$s</xliff:g>) no és privat i, per tant, és possible que l\'administrador de TI pugui veure la teva activitat i les teves dades. L\'administrador de TI també pot configurar els permisos de les aplicacions d\'aquest dispositiu, inclosos els permisos d\'accés al micròfon, a la càmera i a la ubicació."</string>
@@ -183,13 +183,13 @@
     <string name="fully_managed_device_unsupported_DPC_in_headless_mode_header" msgid="7938653381656306039">"No es pot configurar el dispositiu"</string>
     <string name="fully_managed_device_unsupported_DPC_in_headless_mode_subheader" msgid="5158035482490079567">"Aquest dispositiu no es pot inscriure en el mode de dispositiu completament gestionat. Restableix les dades de fàbrica del dispositiu i contacta amb el teu administrador de TI."</string>
     <string name="fully_managed_device_reset_button" msgid="5957116315144904542">"Restableix les dades de fàbrica"</string>
-    <string name="cope_provisioning_step_1_header" msgid="1945759718804756423">"Les apps treball són al teu perfil i les gestiona l’admin."</string>
+    <string name="cope_provisioning_step_1_header" msgid="1945759718804756423">"Les apps de treball són al perfil de treball i les gestiona l\'admin. TI"</string>
     <string name="cope_provisioning_step_2_header" msgid="2388399739294883042">"Les apps personals estan separades de les del treball"</string>
     <string name="cope_provisioning_step_3_header" msgid="7161795433847296201">"El teu admin. pot controlar el dispositiu i bloquejar apps"</string>
-    <string name="cope_provisioning_summary" msgid="4993405755138454918">"L\'administrador de TI gestiona les teves aplicacions de treball, que es desen al teu perfil de treball. Les aplicacions personals es mantenen amagades i separades de les aplicacions de treball. L\'administrador de TI pot controlar aquest dispositiu (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>) i bloquejar determinades aplicacions."</string>
+    <string name="cope_provisioning_summary" msgid="4993405755138454918">"L\'administrador de TI gestiona les teves aplicacions de treball, que es desen al teu perfil de treball. Les aplicacions personals es mantenen amagades i separades de les aplicacions de treball. L\'administrador de TI pot controlar aquest dispositiu <xliff:g id="DEVICE_NAME">%1$s</xliff:g> i bloquejar determinades aplicacions."</string>
     <string name="just_a_sec" msgid="6244676028626237220">"Un moment…"</string>
     <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"Recordatori de privadesa"</string>
-    <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"És possible que l\'administrador de TI pugui veure les teves dades i la teva activitat en aquest dispositiu (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>)"</string>
+    <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"És possible que l\'administrador de TI pugui veure les teves dades i la teva activitat en aquest dispositiu <xliff:g id="DEVICE_NAME">%1$s</xliff:g>"</string>
     <string name="financed_device_screen_header" msgid="5934940812896302344">"<xliff:g id="CREDITOR_NAME">%2$s</xliff:g> proporciona aquest dispositiu (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>)"</string>
     <string name="financed_make_payments_subheader_title" msgid="743966229235451097">"Paga aquest dispositiu (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>)"</string>
     <string name="financed_make_payments_subheader_description" msgid="7391276584735956742">"<xliff:g id="CREDITOR_NAME_0">%1$s</xliff:g> pot instal·lar l\'aplicació <xliff:g id="CREDITOR_NAME_1">%2$s</xliff:g> perquè puguis pagar aquest dispositiu (<xliff:g id="DEVICE_NAME">%3$s</xliff:g>)."</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 70199e94..f1dbdf37 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -158,7 +158,7 @@
     <string name="brand_screen_header" msgid="8865808542690116648">"Dieses Gerät gehört deiner Organisation"</string>
     <string name="brand_screen_subheader" msgid="7664792208784456436">"Dieses Smartphone wird über die folgende App verwaltet und überwacht"</string>
     <string name="account_management_disclaimer_header" msgid="8013083414694316564">"Dein Konto wird verwaltet"</string>
-    <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"Ihr IT-Administrator verwendet die Mobilgeräteverwaltung, um Sicherheitsrichtlinien durchzusetzen"</string>
+    <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"Dein IT-Administrator verwendet die Mobilgeräteverwaltung, um Sicherheitsrichtlinien durchzusetzen"</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"Einrichtung des Arbeitsprofils wird vorbereitet…"</string>
     <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"Richten wir dein Arbeitsprofil ein"</string>
     <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"In deinem Arbeitsprofil werden Apps für die Arbeit abgelegt"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index b644c09c..850b2dd7 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -105,11 +105,11 @@
     <string name="device_owner_info" msgid="3716661456037934467">"Ο οργανισμός <xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> θα διαχειρίζεται, θα παρακολουθεί και θα διατηρεί ασφαλή αυτήν τη συσκευή. Ισχύουν όροι. <xliff:g id="VIEW_TERMS">%2$s</xliff:g>"</string>
     <string name="device_owner_info_with_terms_headers" msgid="1254243288669282977">"Ο οργανισμός <xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> θα διαχειρίζεται, θα παρακολουθεί και θα διατηρεί ασφαλή αυτήν τη συσκευή. Ισχύουν οι όροι από <xliff:g id="TERMS_HEADERS">%2$s</xliff:g>. <xliff:g id="VIEW_TERMS">%3$s</xliff:g>"</string>
     <string name="link_isnt_secure_and_cant_be_opened_until_device_setup_finished" msgid="1604497932637832657">"Αυτός ο σύνδεσμος δεν είναι ασφαλής και δεν μπορεί να ανοιχθεί μέχρι να ολοκληρωθεί η ρύθμιση της συσκευής: <xliff:g id="LINK_RAW_TEST">%1$s</xliff:g>"</string>
-    <string name="contact_device_provider" msgid="2843488903902493030">"Για να μάθετε περισσότερα, επικοινωνήστε με τον <xliff:g id="IT_ADMIN">%1$s</xliff:g>."</string>
+    <string name="contact_device_provider" msgid="2843488903902493030">"Ο <xliff:g id="IT_ADMIN">%1$s</xliff:g> μπορεί να σας δώσει περισσότερες πληροφορίες."</string>
     <string name="if_questions_contact_admin" msgid="3509427015901582047">"Εάν έχετε απορίες, επικοινωνήστε με τον διαχειριστή IT"</string>
     <string name="setup_isnt_finished_contact_admin" msgid="8849644190723875952">"Η ρύθμιση δεν έχει ολοκληρωθεί. Για βοήθεια, επικοινωνήστε με τον διαχειριστή IT σας."</string>
     <string name="for_help_contact_admin" msgid="5922538077702487859">"Για βοήθεια, επικοινωνήστε με τον διαχειριστή IT."</string>
-    <string name="organization_admin" msgid="5975914478148511290">"Διαχειριστής IT"</string>
+    <string name="organization_admin" msgid="5975914478148511290">"Διαχειριστή IT"</string>
     <string name="your_org_app_used" msgid="5336414768293540831">"Ο οργανισμός <xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> θα διαχειρίζεται και θα παρακολουθεί αυτήν τη συσκευή χρησιμοποιώντας την παρακάτω εφαρμογή:"</string>
     <string name="your_organization_beginning" msgid="5952561489910967255">"Ο οργανισμός σας"</string>
     <string name="your_organization_middle" msgid="8288538158061644733">"ο οργανισμός σας"</string>
@@ -167,7 +167,7 @@
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"Δημιουργία του προφίλ εργασίας σας…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"Οι εφαρμογές εργασίας διατηρούνται στο προφίλ εργασίας σας. Μπορείτε να θέσετε σε παύση τις εφαρμογές εργασίας σας όταν τελειώσετε την εργασία σας. Μόνο τα δεδομένα στο προφίλ εργασίας σας θα είναι ορατά στον διαχειριστή IT σας."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"Ας ρυθμίσουμε τη συσκευή εργασίας σας"</string>
-    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Διατηρήσετε στη διάθεσή σας τις εφαρμογές εργασίας σας"</string>
+    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Οι εφαρμογές της εργασίας σας πάντα στη διάθεσή σας"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Η συσκευή <xliff:g id="DEVICE_NAME">%1$s</xliff:g> δεν είναι ιδιωτική"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"Ο διαχειριστής IT μπορεί να έχει τη δυνατότητα να δει τα δεδομένα και τη δραστηριότητά σας στη συσκευή <xliff:g id="DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"Η δραστηριότητα και τα δεδομένα σας"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index d7146263..e281ab09 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -32,7 +32,7 @@
     <string name="admin_has_ability_to_monitor_device" msgid="7786186939607332934">"El administrador de TI puede supervisar y administrar la configuración, el acceso corporativo, las apps, los permisos y los datos asociados a este dispositivo <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, lo que incluye la actividad de red, la ubicación, el historial de llamadas y el historial de búsqueda de contactos del dispositivo.<xliff:g id="LINE_BREAK">
 
 </xliff:g>Comuníquese con el administrador de TI para obtener más información, incluidas las políticas de privacidad de la organización."</string>
-    <string name="theft_protection_disabled_warning" msgid="3708092473574738478">"Para poder usar las funciones de protección contra robos, debes activar el bloqueo de pantalla mediante protección por contraseña."</string>
+    <string name="theft_protection_disabled_warning" msgid="3708092473574738478">"Para usar las funciones de protección ante robo, el dispositivo debe tener un bloqueo de pantalla con contraseña."</string>
     <string name="contact_your_admin_for_more_info" msgid="9209568156969966347">"Comunícate con tu administrador de TI para obtener más información, como las políticas de privacidad de la organización."</string>
     <string name="learn_more_link" msgid="3012495805919550043">"Más información"</string>
     <string name="cancel_setup" msgid="2949928239276274745">"Cancelar"</string>
@@ -174,8 +174,8 @@
     <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"Permisos de apps"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_subheader" msgid="1973320148595109400">"Tu administrador de TI puede configurar permisos para apps en este dispositivo <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, incluidos los del micrófono, la cámara y la ubicación."</string>
     <string name="fully_managed_device_provisioning_progress_label" msgid="3925516135130021966">"Configurando tu dispositivo…"</string>
-    <string name="fully_managed_device_provisioning_summary" msgid="2532673962822596806">"Use este dispositivo <xliff:g id="DEVICE_NAME_0">%1$s</xliff:g> para acceder fácilmente a tus apps de trabajo. Este dispositivo <xliff:g id="DEVICE_NAME_1">%1$s</xliff:g> no es privado, por lo que posiblemente el administrador de TI pueda ver tus datos y actividades."</string>
-    <string name="fully_managed_device_with_permission_control_provisioning_summary" msgid="3487964472228264628">"Use este dispositivo <xliff:g id="DEVICE_NAME_0">%1$s</xliff:g> para acceder fácilmente a tus apps de trabajo. Este dispositivo <xliff:g id="DEVICE_NAME_1">%1$s</xliff:g> no es privado, por lo que posiblemente el administrador de TI pueda ver tus datos y actividades. Tu administrador de TI también puede configurar permisos para apps en este dispositivo, incluidos los del micrófono, la cámara y la ubicación."</string>
+    <string name="fully_managed_device_provisioning_summary" msgid="2532673962822596806">"Usa este dispositivo <xliff:g id="DEVICE_NAME_0">%1$s</xliff:g> para acceder fácilmente a tus apps de trabajo. Este dispositivo <xliff:g id="DEVICE_NAME_1">%1$s</xliff:g> no es privado, por lo que posiblemente el administrador de TI pueda ver tus datos y actividades."</string>
+    <string name="fully_managed_device_with_permission_control_provisioning_summary" msgid="3487964472228264628">"Usa este dispositivo <xliff:g id="DEVICE_NAME_0">%1$s</xliff:g> para acceder fácilmente a tus apps de trabajo. Este dispositivo <xliff:g id="DEVICE_NAME_1">%1$s</xliff:g> no es privado, por lo que posiblemente el administrador de TI pueda ver tus datos y actividades. Tu administrador de TI también puede configurar permisos para apps en este dispositivo, incluidos los del micrófono, la cámara y la ubicación."</string>
     <string name="fully_managed_device_provisioning_return_device_title" msgid="8500829014794276683">"Devuelve este dispositivo al administrador de TI"</string>
     <string name="fully_managed_device_provisioning_return_device_subheader" msgid="6194410367910957686">"Regresa a la pantalla anterior o restablece el dispositivo y devuélvelo al administrador de TI."</string>
     <string name="fully_managed_device_cancel_setup_button" msgid="4910041382610777599">"Cancelar configuración"</string>
@@ -183,7 +183,7 @@
     <string name="fully_managed_device_unsupported_DPC_in_headless_mode_header" msgid="7938653381656306039">"No se puede configurar el dispositivo"</string>
     <string name="fully_managed_device_unsupported_DPC_in_headless_mode_subheader" msgid="5158035482490079567">"No se puede inscribir este dispositivo en un modo completamente administrado. Restablece la configuración de fábrica del dispositivo y comunícate con tu administrador de TI."</string>
     <string name="fully_managed_device_reset_button" msgid="5957116315144904542">"Restablecer configuración de fábrica"</string>
-    <string name="cope_provisioning_step_1_header" msgid="1945759718804756423">"El admin de TI administra las apps de trabajo en tu perfil"</string>
+    <string name="cope_provisioning_step_1_header" msgid="1945759718804756423">"El administrador de TI administra las apps de trabajo, que se almacenan en tu perfil de trabajo"</string>
     <string name="cope_provisioning_step_2_header" msgid="2388399739294883042">"Las apps personales se separan y ocultan de las de trabajo"</string>
     <string name="cope_provisioning_step_3_header" msgid="7161795433847296201">"Tu admin de TI controla el dispositivo y puede bloquear apps"</string>
     <string name="cope_provisioning_summary" msgid="4993405755138454918">"Las apps de trabajo se almacenan en el perfil de trabajo y son gestionadas por tu administrador de TI. Las apps personales se mantienen separadas y ocultas de las de trabajo. Tu administrador de TI puede controlar este dispositivo <xliff:g id="DEVICE_NAME">%1$s</xliff:g> y bloquear determinadas apps."</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 337c3c63..511b1e57 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -105,7 +105,7 @@
     <string name="device_owner_info" msgid="3716661456037934467">"<xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> hallinnoi, valvoo ja suojaa tätä laitetta. Käyttöehtoja sovelletaan. <xliff:g id="VIEW_TERMS">%2$s</xliff:g>"</string>
     <string name="device_owner_info_with_terms_headers" msgid="1254243288669282977">"<xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> hallinnoi, valvoo ja suojaa tätä laitetta. Seuraavia käyttöehtoja sovelletaan: <xliff:g id="TERMS_HEADERS">%2$s</xliff:g>. <xliff:g id="VIEW_TERMS">%3$s</xliff:g>"</string>
     <string name="link_isnt_secure_and_cant_be_opened_until_device_setup_finished" msgid="1604497932637832657">"Tämä linkki ei ole turvallinen, eikä sitä voi avata ennen kuin laite on määritetty: <xliff:g id="LINK_RAW_TEST">%1$s</xliff:g>."</string>
-    <string name="contact_device_provider" msgid="2843488903902493030">"<xliff:g id="IT_ADMIN">%1$s</xliff:g> antaa sinulle lisätietoja."</string>
+    <string name="contact_device_provider" msgid="2843488903902493030">"<xliff:g id="IT_ADMIN">%1$s</xliff:g> antaa tarvittaessa lisätietoja."</string>
     <string name="if_questions_contact_admin" msgid="3509427015901582047">"Jos sinulla on kysyttävää, ota yhteyttä IT-järjestelmänvalvojaan."</string>
     <string name="setup_isnt_finished_contact_admin" msgid="8849644190723875952">"Määritys ei ole valmis. Pyydä apua IT-järjestelmänvalvojalta."</string>
     <string name="for_help_contact_admin" msgid="5922538077702487859">"Pyydä apua IT-järjestelmänvalvojalta."</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index d984f48f..c91e1906 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -64,7 +64,7 @@
     <string name="launcher_app_cant_be_used_by_work_profile" msgid="3524366082000739743">"Impossible d\'utiliser ce lanceur d\'applis avec votre profil professionnel"</string>
     <string name="cancel_provisioning" msgid="3408069559452653724">"Annuler"</string>
     <string name="pick_launcher" msgid="4257084827403983845">"OK"</string>
-    <string name="user_setup_incomplete" msgid="6494920045526591079">"Configuration de l\'utilisateur incomplète"</string>
+    <string name="user_setup_incomplete" msgid="6494920045526591079">"Configuration incomplète de l\'utilisateur"</string>
     <string name="default_owned_device_username" msgid="3915120202811807955">"Utilisateur de l\'appareil professionnel"</string>
     <string name="setup_work_device" msgid="6003988351437862369">"Configuration de l\'appareil professionnel en cours…"</string>
     <string name="device_doesnt_allow_encryption_contact_admin" msgid="410347019947997299">"Cet appareil (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>) n\'autorise pas le chiffrement, qui est nécessaire pour la configuration. Pour obtenir de l\'aide, communiquez avec votre administrateur informatique."</string>
@@ -109,7 +109,7 @@
     <string name="if_questions_contact_admin" msgid="3509427015901582047">"Si vous avez des questions, communiquez avec votre administrateur informatique"</string>
     <string name="setup_isnt_finished_contact_admin" msgid="8849644190723875952">"La configuration n\'est pas terminée. Pour obtenir de l\'aide, communiquez avec votre administrateur informatique."</string>
     <string name="for_help_contact_admin" msgid="5922538077702487859">"Pour obtenir de l\'aide, communiquez avec votre administrateur informatique"</string>
-    <string name="organization_admin" msgid="5975914478148511290">"administrateur informatique"</string>
+    <string name="organization_admin" msgid="5975914478148511290">"Administrateur informatique"</string>
     <string name="your_org_app_used" msgid="5336414768293540831">"<xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> gérera et contrôlera cet appareil à l\'aide de l\'appli suivante :"</string>
     <string name="your_organization_beginning" msgid="5952561489910967255">"Votre entreprise"</string>
     <string name="your_organization_middle" msgid="8288538158061644733">"votre entreprise"</string>
@@ -167,7 +167,7 @@
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"Configuration de votre profil professionnel en cours…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"Les applis professionnelles restent dans votre profil professionnel. Vous pouvez suspendre vos applis professionnelles lorsque vous avez terminé pour la journée. Votre administrateur informatique a accès aux données de votre profil professionnel."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"Configurons votre appareil professionnel"</string>
-    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Accédez à vos applis professionnelles en toute simplicité"</string>
+    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Accéder facilement à vos applis professionnelles"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Cet appareil (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>) n\'est pas privé"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"Il se peut que votre administrateur informatique puisse voir vos données et votre activité sur cet appareil (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>)."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"Vos activités et vos données"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 9b22421b..890c367f 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -166,7 +166,7 @@
     <string name="work_profile_provisioning_step_3_header" msgid="4316106639726774330">"Votre administrateur informatique peut voir les données de votre profil professionnel"</string>
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"Configuration de votre profil pro…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"Les applications professionnelles sont conservées dans votre profil professionnel. Vous pouvez mettre en pause vos applications professionnelles lorsque vous avez fini votre journée. Les données dans votre profil professionnel sont visibles par votre administrateur informatique."</string>
-    <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"Configurez votre appareil professionnel"</string>
+    <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"Configurons votre appareil professionnel"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Gardez vos applications professionnelles à portée de main"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Ce <xliff:g id="DEVICE_NAME">%1$s</xliff:g> n\'est pas privé"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"Votre administrateur informatique peut voir vos données et votre activité sur ce <xliff:g id="DEVICE_NAME">%1$s</xliff:g>."</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 68c6526f..d246b832 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -169,8 +169,8 @@
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"ચાલો, તમારી ઑફિસના ડિવાઇસનું સેટઅપ કરીએ"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"તમારી ઑફિસ માટેની ઍપને તમારી આંગળીના ટેરવે રાખો"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"આ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ખાનગી નથી"</string>
-    <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"તમારા IT ઍડમિન આ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> પર તમારો ડેટા અને તમારી પ્રવૃત્તિ કદાચ જોઈ શકશે."</string>
-    <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"તમારી પ્રવૃત્તિ અને ડેટા"</string>
+    <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"તમારા IT ઍડમિન આ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> પર તમારો ડેટા અને તમારી ઍક્ટિવિટી કદાચ જોઈ શકશે."</string>
+    <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"તમારી ઍક્ટિવિટી અને ડેટા"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"ઍપની પરવાનગીઓ"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_subheader" msgid="1973320148595109400">"તમારા IT ઍડમિન, આ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> પર ઍપ માટેની પરવાનગીઓ સેટ કરી શકે છે, જેમ કે માઇક્રોફોન, કૅમેરા અને લોકેશનની પરવાનગીઓ."</string>
     <string name="fully_managed_device_provisioning_progress_label" msgid="3925516135130021966">"તમારું ડિવાઇસ સેટ થઈ રહ્યું છે…"</string>
@@ -189,7 +189,7 @@
     <string name="cope_provisioning_summary" msgid="4993405755138454918">"ઑફિસ માટેની ઍપ તમારી ઑફિસની પ્રોફાઇલમાં રાખવામાં આવે છે અને તમારા IT ઍડમિન દ્વારા મેનેજ કરવામાં આવે છે. વ્યક્તિગત ઍપ અલગ હોય છે અને તે ઑફિસ માટેની ઍપથી છુપાયેલી હોય છે. તમારા IT ઍડમિન આ <xliff:g id="DEVICE_NAME">%1$s</xliff:g>ને નિયંત્રિત કરી શકે છે અને અમુક ઍપને બ્લૉક કરી શકે છે."</string>
     <string name="just_a_sec" msgid="6244676028626237220">"માત્ર એક સેકન્ડ…"</string>
     <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"પ્રાઇવસી રિમાઇન્ડર"</string>
-    <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"તમારા IT ઍડમિન આ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> પર તમારો ડેટા અને તમારી પ્રવૃત્તિ કદાચ જોઈ શકશે"</string>
+    <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"તમારા IT ઍડમિન આ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> પર તમારો ડેટા અને તમારી ઍક્ટિવિટી કદાચ જોઈ શકશે"</string>
     <string name="financed_device_screen_header" msgid="5934940812896302344">"આ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> <xliff:g id="CREDITOR_NAME">%2$s</xliff:g> દ્વારા પ્રદાન કરવામાં આવ્યું છે"</string>
     <string name="financed_make_payments_subheader_title" msgid="743966229235451097">"આ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> માટે ચુકવણીઓ કરો"</string>
     <string name="financed_make_payments_subheader_description" msgid="7391276584735956742">"<xliff:g id="CREDITOR_NAME_0">%1$s</xliff:g> <xliff:g id="CREDITOR_NAME_1">%2$s</xliff:g> ઍપ ઇન્સ્ટૉલ કરી શકે છે, જેથી તમે આ <xliff:g id="DEVICE_NAME">%3$s</xliff:g> માટે ચુકવણીઓ કરી શકો."</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 6f26694f..593e9bd4 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -161,7 +161,7 @@
     <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"आपका आईटी एडमिन, सुरक्षा नीतियों को लागू करने के लिए मोबाइल मैनेजमेंट का इस्तेमाल करता है"</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"वर्क डिवाइस, सेटअप के लिए तैयार हो रहा है…"</string>
     <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"चलिए, आपकी वर्क प्रोफ़ाइल सेट अप करते हैं"</string>
-    <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"ऑफ़िस के काम से जुड़े ऐप्लिकेशन, आपकी वर्क प्रोफ़ाइल में रखे जाते हैं"</string>
+    <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"वर्क ऐप्लिकेशन, आपकी वर्क प्रोफ़ाइल में रखे जाते हैं"</string>
     <string name="work_profile_provisioning_step_2_header" msgid="6001172190404670248">"ऑफ़िस का दिनभर का काम खत्म हो जाने के बाद, इससे जुड़े ऐप्लिकेशन बंद करें"</string>
     <string name="work_profile_provisioning_step_3_header" msgid="4316106639726774330">"आपके आईटी एडमिन को आपकी वर्क प्रोफ़ाइल में सेव डेटा दिखता है"</string>
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"वर्क प्रोफ़ाइल सेट की जा रही है…"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index ec5b7f3b..112a1ea7 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -158,7 +158,7 @@
     <string name="brand_screen_header" msgid="8865808542690116648">"Ovaj uređaj pripada vašoj organizaciji"</string>
     <string name="brand_screen_subheader" msgid="7664792208784456436">"Za upravljanje telefonom i njegovo praćenje koristit će se sljedeća aplikacija"</string>
     <string name="account_management_disclaimer_header" msgid="8013083414694316564">"Računom se upravlja"</string>
-    <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"Vaš IT administrator upotrebljava upravljanje mobitelima radi provedbe sigurnosnih pravila"</string>
+    <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"Vaš IT administrator upravlja mobilnim uređajima radi provedbe sigurnosnih pravila"</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"Priprema za postavljanje poslovnog profila…"</string>
     <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"Postavimo vaš poslovni profil"</string>
     <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"Poslovne aplikacije nalaze se na vašem poslovnom profilu"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 81a4dce3..d0620718 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -150,8 +150,8 @@
     <string name="join_many_items_last" msgid="7469666990442158802">"<xliff:g id="ALL_BUT_LAST_ITEM">%1$s</xliff:g>, dan <xliff:g id="LAST_ITEM_0">%2$s</xliff:g>"</string>
     <string name="join_many_items_first" msgid="8365482726853276608">"<xliff:g id="FIRST_ITEM">%1$s</xliff:g>, <xliff:g id="ALL_BUT_FIRST_AND_LAST_ITEM">%2$s</xliff:g>"</string>
     <string name="join_many_items_middle" msgid="8569294838319639963">"<xliff:g id="ADDED_ITEM">%1$s</xliff:g>, <xliff:g id="REST_OF_ITEMS">%2$s</xliff:g>"</string>
-    <string name="take_a_few_minutes" msgid="6282806501305322838">"Proses ini mungkin perlu beberapa menit"</string>
-    <string name="work_profile_description" msgid="8524116010729569213">"Aplikasi kerja Anda akan disimpan di profil ini dan dikelola oleh organisasi"</string>
+    <string name="take_a_few_minutes" msgid="6282806501305322838">"Proses ini perlu waktu beberapa menit"</string>
+    <string name="work_profile_description" msgid="8524116010729569213">"Aplikasi kerja disimpan di profil ini dan dikelola organisasi Anda"</string>
     <string name="device_owner_description" msgid="168013145812679664">"Perangkat ini akan dijaga agar tetap aman dan dikelola oleh organisasi Anda"</string>
     <string name="setup_provisioning_header" msgid="4282483198266806271">"Bersiap menyiapkan perangkat kerja…"</string>
     <string name="setup_provisioning_header_description" msgid="2567041263563823566">"Menyiapkan aplikasi admin"</string>
@@ -183,10 +183,10 @@
     <string name="fully_managed_device_unsupported_DPC_in_headless_mode_header" msgid="7938653381656306039">"Perangkat tidak dapat disiapkan"</string>
     <string name="fully_managed_device_unsupported_DPC_in_headless_mode_subheader" msgid="5158035482490079567">"Perangkat ini tidak dapat didaftarkan ke mode terkelola sepenuhnya. Reset perangkat ke setelan pabrik dan hubungi admin IT Anda."</string>
     <string name="fully_managed_device_reset_button" msgid="5957116315144904542">"Reset ke setelan pabrik"</string>
-    <string name="cope_provisioning_step_1_header" msgid="1945759718804756423">"Apl kerja ada di profil kerja &amp; dikelola admin IT"</string>
-    <string name="cope_provisioning_step_2_header" msgid="2388399739294883042">"Apl pribadi terpisah &amp; tersembunyi dari apl kerja"</string>
-    <string name="cope_provisioning_step_3_header" msgid="7161795433847296201">"Admin IT dapat mengontrol perangkat &amp; memblokir apl tertentu"</string>
-    <string name="cope_provisioning_summary" msgid="4993405755138454918">"Aplikasi kerja disimpan dalam profil kerja Anda dan dikelola oleh admin IT Anda. Aplikasi pribadi terpisah dan disembunyikan dari aplikasi kerja. Admin IT Anda dapat mengontrol <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ini dan memblokir aplikasi tertentu."</string>
+    <string name="cope_provisioning_step_1_header" msgid="1945759718804756423">"Aplikasi kerja disimpan di profil kerja &amp; dikelola admin IT"</string>
+    <string name="cope_provisioning_step_2_header" msgid="2388399739294883042">"Aplikasi pribadi tersembunyi &amp; terpisah dari aplikasi kerja"</string>
+    <string name="cope_provisioning_step_3_header" msgid="7161795433847296201">"Admin IT dapat mengontrol perangkat ini &amp; memblokir aplikasi"</string>
+    <string name="cope_provisioning_summary" msgid="4993405755138454918">"Aplikasi kerja disimpan di profil kerja dan dikelola admin IT Anda. Aplikasi pribadi tersembunyi dan terpisah dari aplikasi kerja. Admin IT Anda dapat mengontrol <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ini dan memblokir aplikasi tertentu."</string>
     <string name="just_a_sec" msgid="6244676028626237220">"Tunggu sebentar…"</string>
     <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"Pengingat privasi"</string>
     <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"Admin IT mungkin dapat melihat data dan aktivitas Anda di <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ini"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index df8f0ca9..dbe6969e 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -150,7 +150,7 @@
     <string name="join_many_items_last" msgid="7469666990442158802">"<xliff:g id="ALL_BUT_LAST_ITEM">%1$s</xliff:g> ו-<xliff:g id="LAST_ITEM_0">%2$s</xliff:g>"</string>
     <string name="join_many_items_first" msgid="8365482726853276608">"<xliff:g id="FIRST_ITEM">%1$s</xliff:g>, <xliff:g id="ALL_BUT_FIRST_AND_LAST_ITEM">%2$s</xliff:g>"</string>
     <string name="join_many_items_middle" msgid="8569294838319639963">"<xliff:g id="ADDED_ITEM">%1$s</xliff:g>, <xliff:g id="REST_OF_ITEMS">%2$s</xliff:g>"</string>
-    <string name="take_a_few_minutes" msgid="6282806501305322838">"הפעולה עשויה להימשך מספר דקות"</string>
+    <string name="take_a_few_minutes" msgid="6282806501305322838">"זה יכול לקחת כמה דקות"</string>
     <string name="work_profile_description" msgid="8524116010729569213">"אפליקציות לעבודה יישמרו בפרופיל הזה וינוהלו על ידי הארגון שלך"</string>
     <string name="device_owner_description" msgid="168013145812679664">"המכשיר הזה יישאר מאובטח וינוהל על ידי הארגון שלך"</string>
     <string name="setup_provisioning_header" msgid="4282483198266806271">"בתהליך להגדרת מכשיר העבודה…"</string>
@@ -168,8 +168,8 @@
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"‏אפליקציות לעבודה נשמרות בפרופיל העבודה שלך. אפשר להשהות את האפליקציות לעבודה בסוף היום. הנתונים בפרופיל העבודה שלך גלויים למנהל ה-IT."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"נתחיל להגדיר את מכשיר העבודה שלך"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"אפשר לשמור את אפליקציות העבודה במקום נגיש"</string>
-    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"המכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g> לא פרטי"</string>
-    <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"‏ייתכן שמנהל ה-IT שלך יכול לראות את הנתונים והפעילות במכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g>."</string>
+    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"זהו לא מכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g> פרטי"</string>
+    <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"‏יכול להיות שהאדמין ב-IT שלך יכול לראות את הנתונים והפעילות במכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"הנתונים והפעילות שלך"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"הרשאות הניתנות לאפליקציות"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_subheader" msgid="1973320148595109400">"‏מנהל ה-IT יכול להגדיר הרשאות לאפליקציות במכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, כמו הרשאות לשימוש במיקרופון, במצלמה ובמיקום."</string>
@@ -184,12 +184,12 @@
     <string name="fully_managed_device_unsupported_DPC_in_headless_mode_subheader" msgid="5158035482490079567">"‏לא ניתן לרשום את המכשיר הזה למצב מנוהל באופן מלא. יש לאפס את המכשיר להגדרות המקוריות ולפנות לאדמין ב-IT."</string>
     <string name="fully_managed_device_reset_button" msgid="5957116315144904542">"איפוס להגדרות המקוריות"</string>
     <string name="cope_provisioning_step_1_header" msgid="1945759718804756423">"‏אפליקציות לעבודה נשמרות בפרופיל שלך ומנוהלות ע\"י האדמין ב-IT"</string>
-    <string name="cope_provisioning_step_2_header" msgid="2388399739294883042">"אפליקציות אישיות מאוחסנות בנפרד ומוסתרות מאפליקציות לעבודה"</string>
+    <string name="cope_provisioning_step_2_header" msgid="2388399739294883042">"אפליקציות אישיות מאוחסנות בנפרד ומוסתרות מהאפליקציות לעבודה"</string>
     <string name="cope_provisioning_step_3_header" msgid="7161795433847296201">"‏האדמין ב-IT יכול לשלוט במכשיר הזה ולחסום אפליקציות מסוימות"</string>
     <string name="cope_provisioning_summary" msgid="4993405755138454918">"‏אפליקציות לעבודה נשמרות בפרופיל העבודה ומנוהלות על ידי מנהל ה-IT. אפליקציות לשימוש אישי מאוחסנות בנפרד ומוסתרות מהאפליקציות לעבודה. מנהל ה-IT יכול לשלוט במכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ולחסום אפליקציות מסוימות."</string>
     <string name="just_a_sec" msgid="6244676028626237220">"רק רגע…"</string>
     <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"תזכורת לגבי פרטיות"</string>
-    <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"‏ייתכן שמנהל ה-IT שלך יכול לראות את הנתונים והפעילות במכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g>"</string>
+    <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"‏יכול להיות שהאדמין ב-IT שלך יכול לראות את הנתונים והפעילות במכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g>"</string>
     <string name="financed_device_screen_header" msgid="5934940812896302344">"המכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g> סופק על ידי <xliff:g id="CREDITOR_NAME">%2$s</xliff:g>"</string>
     <string name="financed_make_payments_subheader_title" msgid="743966229235451097">"ביצוע תשלומים עבור המכשיר <xliff:g id="DEVICE_NAME">%1$s</xliff:g>"</string>
     <string name="financed_make_payments_subheader_description" msgid="7391276584735956742">"ספק האשראי <xliff:g id="CREDITOR_NAME_0">%1$s</xliff:g> יכול להתקין את האפליקציה <xliff:g id="CREDITOR_NAME_1">%2$s</xliff:g> כדי לאפשר לך לבצע תשלומים עבור המכשיר <xliff:g id="DEVICE_NAME">%3$s</xliff:g>."</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index eac88d8c..cadf39ed 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -162,7 +162,7 @@
     <string name="downloading_administrator_header" msgid="8660294318893902915">"仕事用プロファイルのセットアップを準備しています…"</string>
     <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"仕事用プロファイルを設定しましょう"</string>
     <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"仕事用アプリは仕事用プロファイルに保存されます"</string>
-    <string name="work_profile_provisioning_step_2_header" msgid="6001172190404670248">"1 日の仕事を終えたら仕事用アプリを一時停止する"</string>
+    <string name="work_profile_provisioning_step_2_header" msgid="6001172190404670248">"1 日の仕事を終えたら仕事用アプリを一時停止します"</string>
     <string name="work_profile_provisioning_step_3_header" msgid="4316106639726774330">"仕事用プロファイル内のデータは IT 管理者に公開されます"</string>
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"仕事用プロファイルをセットアップしています…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"仕事用アプリは仕事用プロファイルに保存されます。1 日の仕事を終えたら仕事用アプリを一時停止できます。仕事用プロファイル内のデータは IT 管理者に公開されます。"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 9ec20240..e47de0ff 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -150,7 +150,7 @@
     <string name="join_many_items_last" msgid="7469666990442158802">"<xliff:g id="ALL_BUT_LAST_ITEM">%1$s</xliff:g> және <xliff:g id="LAST_ITEM_0">%2$s</xliff:g>"</string>
     <string name="join_many_items_first" msgid="8365482726853276608">"<xliff:g id="FIRST_ITEM">%1$s</xliff:g>, <xliff:g id="ALL_BUT_FIRST_AND_LAST_ITEM">%2$s</xliff:g>"</string>
     <string name="join_many_items_middle" msgid="8569294838319639963">"<xliff:g id="ADDED_ITEM">%1$s</xliff:g>, <xliff:g id="REST_OF_ITEMS">%2$s</xliff:g>"</string>
-    <string name="take_a_few_minutes" msgid="6282806501305322838">"Бұл бірнеше минут алуы мүмкін"</string>
+    <string name="take_a_few_minutes" msgid="6282806501305322838">"Бұл бірнеше минутқа созылуы мүмкін"</string>
     <string name="work_profile_description" msgid="8524116010729569213">"Жұмыс қолданбаларыңыз осы профильде сақталады және ұйым арқылы басқарылады"</string>
     <string name="device_owner_description" msgid="168013145812679664">"Бұл құрылғы ұйымның қорғауында және бақылауында болады"</string>
     <string name="setup_provisioning_header" msgid="4282483198266806271">"Жұмыс құрғылғысының параметрлері орнатылайын деп жатыр…"</string>
@@ -167,7 +167,7 @@
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"Жұмыс профиліңіз реттелуде…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"Жұмыс қолданбалары жұмыс профилінде сақталады. Күннің соңында жұмыс қолданбаларын тоқтатып қоя аласыз. Әкімші жұмыс профиліңіздегі деректерді көреді."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"Жұмыс құрылғыңызды реттейік."</string>
-    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Жұмыс қолданбаларын оңай пайдаланыңыз"</string>
+    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Жұмыс қолданбаларына оңай қол жеткізіңіз"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"<xliff:g id="DEVICE_NAME">%1$s</xliff:g> жеке құрылғы емес"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"Әкімші осы <xliff:g id="DEVICE_NAME">%1$s</xliff:g> құрылғысындағы деректеріңізді және әрекеттеріңізді көре алады."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"Әрекетіңіз және деректеріңіз"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 2a4636a4..29921ebe 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -45,7 +45,7 @@
     <string name="managed_device_info" msgid="1529447646526616811">"ನಿರ್ವಹಿಸುವ ಸಾಧನದ ಮಾಹಿತಿ"</string>
     <string name="default_managed_profile_name" msgid="5370257687074907055">"ಕೆಲಸದ ಪ್ರೊಫೈಲ್"</string>
     <string name="delete_profile_title" msgid="2841349358380849525">"ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಪ್ರೊಫೈಲ್ ಅನ್ನು ಅಳಿಸುವುದೇ?"</string>
-    <string name="opening_paragraph_delete_profile" msgid="4913885310795775967">"ನೀವು ಈಗಾಗಲೇ ಕೆಲಸದ ಪ್ರೊಫೈಲ್ ಹೊಂದಿರುವಿರಿ. ಅದನ್ನು ಕೆಳಗಿನ ಅಪ್ಲಿಕೇಶನ್ ಬಳಸಿಕೊಂಡು ನಿರ್ವಹಿಸಲಾಗಿದೆ:"</string>
+    <string name="opening_paragraph_delete_profile" msgid="4913885310795775967">"ನೀವು ಈಗಾಗಲೇ ಕೆಲಸದ ಪ್ರೊಫೈಲ್ ಹೊಂದಿರುವಿರಿ. ಅದನ್ನು ಕೆಳಗಿನ ಆ್ಯಪ್ ಬಳಸಿಕೊಂಡು ನಿರ್ವಹಿಸಲಾಗಿದೆ:"</string>
     <string name="read_more_delete_profile" msgid="7789171620401666343">"ಮುಂದುವರಿಯುವ ಮೊದಲು, "<a href="#read_this_link">"ಇದನ್ನು ಓದಿ"</a>"."</string>
     <string name="sure_you_want_to_delete_profile" msgid="6927697984573575564">"ನೀವು ಮುಂದುವರಿಸಿದರೆ, ಈ ಪ್ರೊಫೈಲ್‌ನಲ್ಲಿನ ಎಲ್ಲ ಅಪ್ಲಿಕೇಶನ್‌ಗಳು ಮತ್ತು ಡೇಟಾವನ್ನು ಅಳಿಸಲಾಗುತ್ತದೆ."</string>
     <string name="delete_profile" msgid="2299218578684663459">"ಅಳಿಸಿ"</string>
@@ -61,7 +61,7 @@
     <string name="cant_replace_or_remove_work_profile" msgid="7861054306792698290">"ಉದ್ಯೋಗದ ಪ್ರೊಫೈಲ್‌ ಅನ್ನು ಬದಲಾಯಿಸಲು ಅಥವಾ ತೆಗೆದುಹಾಕಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
     <string name="work_profile_cant_be_added_contact_admin" msgid="4866281518235832928">"ಉದ್ಯೋಗ ಪ್ರೊಫೈಲ್ ಅನ್ನು ಈ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ಗೆ ಸೇರಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ. ನಿಮ್ಮಲ್ಲಿ ಯಾವುದೇ ಪ್ರಶ್ನೆಗಳಿದ್ದರೆ, ನಿಮ್ಮ IT ನಿರ್ವಾಹಕರನ್ನು ಸಂಪರ್ಕಿಸಿ."</string>
     <string name="change_device_launcher" msgid="4523563368433637980">"ಸಾಧನದ ಲಾಂಚರ್ ಬದಲಾಯಿಸಿ"</string>
-    <string name="launcher_app_cant_be_used_by_work_profile" msgid="3524366082000739743">"ಈ ಲಾಂಚರ್ ಅಪ್ಲಿಕೇಶನ್ ಅನ್ನು ನಿಮ್ಮ ಉದ್ಯೋಗ ಪ್ರೊಫೈಲ್‌ ಬಳಸಿಕೊಳ್ಳಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
+    <string name="launcher_app_cant_be_used_by_work_profile" msgid="3524366082000739743">"ಈ ಲಾಂಚರ್ ಆ್ಯಪ್ ಅನ್ನು ನಿಮ್ಮ ಉದ್ಯೋಗ ಪ್ರೊಫೈಲ್‌ ಬಳಸಿಕೊಳ್ಳಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
     <string name="cancel_provisioning" msgid="3408069559452653724">"ರದ್ದುಮಾಡಿ"</string>
     <string name="pick_launcher" msgid="4257084827403983845">"ಸರಿ"</string>
     <string name="user_setup_incomplete" msgid="6494920045526591079">"ಬಳಕೆದಾರ ಸೆಟಪ್ ಅಪೂರ್ಣವಾಗಿದೆ"</string>
@@ -86,7 +86,7 @@
     <string name="frp_clear_progress_title" msgid="8628074089458234965">"ಅಳಿಸಲಾಗುತ್ತಿದೆ"</string>
     <string name="frp_clear_progress_text" msgid="1740164332830598827">"ದಯವಿಟ್ಟು ನಿರೀಕ್ಷಿಸಿ..."</string>
     <string name="error_hash_mismatch" msgid="1145488923243178454">"ಚೆಕ್‌ಸಮ್ ದೋಷ ಎದುರಾಗಿರುವ ಕಾರಣ ನಿರ್ವಾಹಕ ಆ್ಯಪ್ ಬಳಸಲು ಸಾಧ್ಯವಾಗುತ್ತಿಲ್ಲ. ಸಹಾಯಕ್ಕಾಗಿ, ನಿಮ್ಮ IT ನಿರ್ವಾಹಕರನ್ನು ಸಂಪರ್ಕಿಸಿ."</string>
-    <string name="error_download_failed" msgid="3274283629837019452">"ನಿರ್ವಹಣೆ ಅಪ್ಲಿಕೇಶನ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ"</string>
+    <string name="error_download_failed" msgid="3274283629837019452">"ನಿರ್ವಹಣೆ ಆ್ಯಪ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ"</string>
     <string name="error_package_invalid" msgid="555402554502033988">"ನಿರ್ವಾಹಕ ಆ್ಯಪ್ ಬಳಸಲು ಸಾಧ್ಯವಿಲ್ಲ. ಇದರ ಘಟಕಗಳು ಕಾಣೆಯಾಗಿವೆ ಅಥವಾ ದೋಷಪೂರಿತವಾಗಿವೆ. ಸಹಾಯಕ್ಕಾಗಿ, ನಿಮ್ಮ IT ನಿರ್ವಾಹಕರನ್ನು ಸಂಪರ್ಕಿಸಿ."</string>
     <string name="error_installation_failed" msgid="2282903750318407285">"ನಿರ್ವಹಣೆ ಅಪ್ಲಿಕೇಶನ್‌ ಸ್ಥಾಪಿಸಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ"</string>
     <string name="profile_owner_cancel_message" msgid="6868736915633023477">"ಹೊಂದಿಸುವುದನ್ನು ನಿಲ್ಲಿಸುವುದೇ?"</string>
@@ -105,12 +105,12 @@
     <string name="device_owner_info" msgid="3716661456037934467">"ಈ ಸಾಧನವನ್ನು <xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> ಮೂಲಕ ನಿರ್ವಹಣೆ, ಮೇಲ್ವಿಚಾರಣೆ ಮತ್ತು ಸಂರಕ್ಷಣೆ ಮಾಡಲಾಗುತ್ತದೆ. ನಿಯಮಗಳು ಅನ್ವಯವಾಗುತ್ತವೆ. <xliff:g id="VIEW_TERMS">%2$s</xliff:g>"</string>
     <string name="device_owner_info_with_terms_headers" msgid="1254243288669282977">"ಈ ಸಾಧನವನ್ನು <xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> ಮೂಲಕ ನಿರ್ವಹಣೆ, ಮೇಲ್ವಿಚಾರಣೆ ಮತ್ತು ಸಂರಕ್ಷಣೆ ಮಾಡಲಾಗುತ್ತದೆ. <xliff:g id="TERMS_HEADERS">%2$s</xliff:g> ನ ನಿಯಮಗಳು ಅನ್ವಯವಾಗುತ್ತವೆ. <xliff:g id="VIEW_TERMS">%3$s</xliff:g>"</string>
     <string name="link_isnt_secure_and_cant_be_opened_until_device_setup_finished" msgid="1604497932637832657">"ಈ ಲಿಂಕ್ ಸುರಕ್ಷಿತವಾಗಿಲ್ಲ ಮತ್ತು ಸಾಧನದ ಸೆಟಪ್ ಪೂರ್ತಿಯಾಗುವವರೆಗೆ ತೆರೆಯಲು ಸಾಧ್ಯವಿಲ್ಲ: <xliff:g id="LINK_RAW_TEST">%1$s</xliff:g>"</string>
-    <string name="contact_device_provider" msgid="2843488903902493030">"ಇನ್ನಷ್ಟು ತಿಳಿಯಲು, ನಿಮ್ಮ <xliff:g id="IT_ADMIN">%1$s</xliff:g> ಅವರನ್ನು ಸಂಪರ್ಕಿಸಿ."</string>
+    <string name="contact_device_provider" msgid="2843488903902493030">"ಇನ್ನಷ್ಟು ತಿಳಿಯಲು, ನಿಮ್ಮ <xliff:g id="IT_ADMIN">%1$s</xliff:g> ಸಂಪರ್ಕಿಸಿ."</string>
     <string name="if_questions_contact_admin" msgid="3509427015901582047">"ನಿಮಗೆ ಯಾವುದೇ ಪ್ರಶ್ನೆಗಳಿದ್ದರೆ, ನಿಮ್ಮ IT ನಿರ್ವಾಹಕರನ್ನು ಸಂಪರ್ಕಿಸಿ"</string>
     <string name="setup_isnt_finished_contact_admin" msgid="8849644190723875952">"ಸೆಟಪ್ ಪೂರ್ಣಗೊಂಡಿಲ್ಲ. ಸಹಾಯಕ್ಕಾಗಿ, ನಿಮ್ಮ IT ನಿರ್ವಾಹಕರನ್ನು ಸಂಪರ್ಕಿಸಿ."</string>
     <string name="for_help_contact_admin" msgid="5922538077702487859">"ಸಹಾಯಕ್ಕಾಗಿ, ನಿಮ್ಮ IT ನಿರ್ವಾಹಕರನ್ನು ಸಂಪರ್ಕಿಸಿ"</string>
-    <string name="organization_admin" msgid="5975914478148511290">"IT ನಿರ್ವಾಹಕರು"</string>
-    <string name="your_org_app_used" msgid="5336414768293540831">"ಈ ಕೆಳಗಿನ ಅಪ್ಲಿಕೇಶನ್ ಬಳಸಿಕೊಂಡು ಈ ಸಾಧನವನ್ನು <xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> ನಿರ್ವಹಿಸುತ್ತದೆ ಮತ್ತು ಮೇಲ್ವಿಚಾರಣೆ ಮಾಡುತ್ತದೆ:"</string>
+    <string name="organization_admin" msgid="5975914478148511290">"IT ನಿರ್ವಾಹಕರನ್ನು"</string>
+    <string name="your_org_app_used" msgid="5336414768293540831">"ಈ ಕೆಳಗಿನ ಆ್ಯಪ್ ಬಳಸಿಕೊಂಡು ಈ ಸಾಧನವನ್ನು <xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> ನಿರ್ವಹಿಸುತ್ತದೆ ಮತ್ತು ಮೇಲ್ವಿಚಾರಣೆ ಮಾಡುತ್ತದೆ:"</string>
     <string name="your_organization_beginning" msgid="5952561489910967255">"ನಿಮ್ಮ ಸಂಘಟನೆ"</string>
     <string name="your_organization_middle" msgid="8288538158061644733">"ನಿಮ್ಮ ಸಂಸ್ಥೆ"</string>
     <string name="view_terms" msgid="7230493092383341605">"ನಿಯಮಗಳನ್ನು ವೀಕ್ಷಿಸಿ"</string>
@@ -157,7 +157,7 @@
     <string name="setup_provisioning_header_description" msgid="2567041263563823566">"ನಿರ್ವಹಣೆ ಅಪ್ಲಿಕೇಶನ್ ಹೊಂದಿಸಲಾಗುತ್ತಿದೆ"</string>
     <string name="brand_screen_header" msgid="8865808542690116648">"ಈ ಸಾಧನವು ನಿಮ್ಮ ಸಂಸ್ಥೆಗೆ ಸೇರಿರುತ್ತದೆ"</string>
     <string name="brand_screen_subheader" msgid="7664792208784456436">"ಈ ಫೋನ್ ಅನ್ನು ನಿರ್ವಹಿಸಲು ಮತ್ತು ಮೇಲ್ವಿಚಾರಣೆ ಮಾಡಲು ಕೆಳಗಿನ ಆ್ಯಪ್‌ ಅನ್ನು ಬಳಸಲಾಗುತ್ತದೆ"</string>
-    <string name="account_management_disclaimer_header" msgid="8013083414694316564">"ನಿಮ್ಮ ಖಾತೆಯು ನಿರ್ವಹಿಸಿದ ಖಾತೆಯಾಗಿದೆ"</string>
+    <string name="account_management_disclaimer_header" msgid="8013083414694316564">"ನಿಮ್ಮ ಖಾತೆಯನ್ನು ಹೊಸ ಸಾಧನದಲ್ಲಿ ನಿರ್ವಹಿಸಲಾಗುತ್ತದೆ"</string>
     <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"ಭದ್ರತಾ ನೀತಿಗಳನ್ನು ಜಾರಿಗೊಳಿಸಲು ನಿಮ್ಮ IT ನಿರ್ವಾಹಕರು ಮೊಬೈಲ್ ನಿರ್ವಹಣೆಯನ್ನು ಬಳಸುತ್ತಾರೆ"</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"ಕೆಲಸದ ಸಾಧನ ಸೆಟಪ್ ಮಾಡಲು ಸಿದ್ಧವಾಗುತ್ತಿದೆ…"</string>
     <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"ನಿಮ್ಮ ಉದ್ಯೋಗ ಪ್ರೊಫೈಲ್ ಅನ್ನು ಸೆಟಪ್ ಮಾಡೋಣ"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index fa47141b..76d5ef14 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -29,7 +29,7 @@
     <string name="next" msgid="1004321437324424398">"Кийинки"</string>
     <string name="setting_up_workspace" msgid="7862472373642601041">"Жумуш профили жөндөлүүдө…"</string>
     <string name="admin_has_ability_to_monitor_profile" msgid="1018585795537086728">"IT администраторуңуз параметрлерди, корпоративдик мүмкүнчүлүктү, колдонмолорду, уруксаттарды, маалыматты жана бул профилге байланыштуу тармактагы аракеттерди, ошондой эле чалуулардын таржымалы жана байланыштарды издөө таржымалын көзөмөлдөп, башкара алат. Кеңири маалымат алып, уюмуңуздун купуялык эрежелерин билүү үчүн IT администраторуңузга кайрылыңыз."</string>
-    <string name="admin_has_ability_to_monitor_device" msgid="7786186939607332934">"IT администраторуңуз параметрлерди, корпоративдик кирүү мүмкүнчүлүгүн, колдонмолорду, уруксаттарды жана ушул <xliff:g id="DEVICE_NAME">%1$s</xliff:g> түзмөгүнө байланыштуу нерселерди, ошондой эле Интернеттеги аракеттериңиз, түзмөгүңүздүн жайгашкан жери, чалуу таржымалы жана байланыштарды издөө таржымалы тууралуу маалыматты көзөмөлдөп жана тескей алат.<xliff:g id="LINE_BREAK">
+    <string name="admin_has_ability_to_monitor_device" msgid="7786186939607332934">"IT администраторуңуз параметрлерди, колдонмолорду, уруксаттарды, ошондой эле ушул <xliff:g id="DEVICE_NAME">%1$s</xliff:g> түзмөгүндөгү корпоративдик ресурстарды жана башка нерселерди пайдалануу мүмкүнчүлүгүн, ошондой эле Интернеттеги аракеттериңизди, түзмөгүңүздүн жайгашкан жерин, чалуулар таржымалын жана изделген байланыштарды көзөмөлдөп, тескейт.<xliff:g id="LINE_BREAK">
 
 </xliff:g>Көбүрөөк маалымат алып, ишканаңыздын купуялык эрежелерин билүү үчүн IT администраторуңузга кайрылыңыз."</string>
     <string name="theft_protection_disabled_warning" msgid="3708092473574738478">"Түзмөгүңүздүн уурдалып кетишинен коргоо функциясын колдонуу үчүн түзмөгүңүздү сырсөз менен кулпулап коюңуз."</string>
@@ -158,7 +158,7 @@
     <string name="brand_screen_header" msgid="8865808542690116648">"Бул түзмөк уюмуңузга таандык"</string>
     <string name="brand_screen_subheader" msgid="7664792208784456436">"Бул телефон төмөнкү колдонмо аркылуу башкарылып, көзөмөлдөнөт"</string>
     <string name="account_management_disclaimer_header" msgid="8013083414694316564">"Аккаунтуңуз башкарылууда"</string>
-    <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"IT администраторуңуз коопсуздук эрежелерин сактоо үчүн мобилдик түзмөктөрдү тескөө системасын иштетти"</string>
+    <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"Коопсуздук эрежелерин сактоо максатында IT администраторуңуз мобилдик түзмөктөрдү тескеген системаны иштетти"</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"Жумуш профилин түзүүгө даярдык көрүлүүдө…"</string>
     <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"Келиңиз, жумуш профилиңизди түзүп алалы"</string>
     <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"Жумуш колдонмолору жумуш профилиңизде сакталат"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 14fbf310..c9e9d3e9 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -167,7 +167,7 @@
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"तुमचे कार्य प्रोफाइल सेट करत आहे…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"कार्य अ‍ॅप्स तुमच्या कार्य प्रोफाइलमध्ये ठेवली जातात. तुमचे काम संपल्यावर तुम्ही तुमची कार्य अ‍ॅप्स थांबवू शकता. तुमच्या आयटी अ‍ॅडमिनला तुमच्या कार्य प्रोफाइलमधील डेटा दिसतो."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"चला तुमचे कार्य डिव्हाइस सेट करू या"</string>
-    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"तुमची कार्य अ‍ॅप्स तुमच्या हाताशी ठेवा"</string>
+    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"तुमची कामाशी संबंधित अ‍ॅप्स तुमच्या हाताशी ठेवा"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"हे <xliff:g id="DEVICE_NAME">%1$s</xliff:g> खाजगी नाही"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"तुमचा आयटी अ‍ॅडमिन कदाचित या <xliff:g id="DEVICE_NAME">%1$s</xliff:g> वरील तुमचा डेटा आणि अ‍ॅक्टिव्हिटी पाहू शकतो."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"तुमची अ‍ॅक्टिव्हिटी आणि डेटा"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 53784088..7fad44c2 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -157,7 +157,7 @@
     <string name="setup_provisioning_header_description" msgid="2567041263563823566">"Konfigurerer administratorapp"</string>
     <string name="brand_screen_header" msgid="8865808542690116648">"Denne enheten tilhører organisasjonen din"</string>
     <string name="brand_screen_subheader" msgid="7664792208784456436">"Følgende app brukes til å administrere og overvåke denne telefonen"</string>
-    <string name="account_management_disclaimer_header" msgid="8013083414694316564">"Kontoen din administreres"</string>
+    <string name="account_management_disclaimer_header" msgid="8013083414694316564">"Kontoen din er administrert"</string>
     <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"IT-administratoren bruker administrering av mobilenheter for å gjøre retningslinjene for sikkerhet obligatoriske"</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"Klargjør for jobbkonfigurering …"</string>
     <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"La oss konfigurere jobbprofilen din"</string>
@@ -167,7 +167,7 @@
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"Konfigurerer jobbprofilen din …"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"Jobbapper oppbevares i jobbprofilen din. Du kan sette jobbappene dine på pause når du er ferdig for dagen. Dataene i jobbprofilen din er synlige for IT-administratoren din."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"La oss konfigurere jobbenheten din"</string>
-    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Få enkel tilgang til jobbappene dine"</string>
+    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Få enkelt tilgang til jobbappene dine"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Denne <xliff:g id="DEVICE_NAME">%1$s</xliff:g>-enheten er ikke privat"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"IT-administratoren kan se dataene dine og det du gjør på denne <xliff:g id="DEVICE_NAME">%1$s</xliff:g>-enheten."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"Aktiviteten din og dataene dine"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index ecdfe109..28eba5a4 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -94,7 +94,7 @@
     <string name="profile_owner_cancel_ok" msgid="5951679183850766029">"हो"</string>
     <string name="profile_owner_cancelling" msgid="5679573829145112822">"रद्द गरिँदै..."</string>
     <string name="work_profile_setup_later_title" msgid="9069148190226279892">"के प्रोफाइल सेटअप रोक्ने हो?"</string>
-    <string name="work_profile_setup_later_message" msgid="122069011117225292">"तपाईंले पछि आफ्नो कार्य प्रोफाइललाई आफ्नो संगठनको यन्त्र व्यवस्थापन एपमा सेटअप गर्न सक्नुहुन्छ"</string>
+    <string name="work_profile_setup_later_message" msgid="122069011117225292">"तपाईंले पछि आफ्नो संस्थाको डिभाइस म्यानेजमेन्ट एपमा आफ्नो कार्य प्रोफाइल सेटअप गर्न सक्नुहुन्छ"</string>
     <string name="continue_button" msgid="7177918589510964446">"जारी राख्नुहोस्"</string>
     <string name="work_profile_setup_stop" msgid="6772128629992514750">"रोक्नुहोस्"</string>
     <string name="dismiss" msgid="9009534756748565880">"खारेज गर्नुहोस्"</string>
@@ -157,7 +157,7 @@
     <string name="setup_provisioning_header_description" msgid="2567041263563823566">"प्रशासक एप सेटअप गर्दै"</string>
     <string name="brand_screen_header" msgid="8865808542690116648">"यो डिभाइस तपाईंको सङ्गठनको स्वामित्वमा छ"</string>
     <string name="brand_screen_subheader" msgid="7664792208784456436">"यो फोनको व्यवस्थापन तथा अनुगमन गर्न निम्न एपको उपयोग गरिने छ"</string>
-    <string name="account_management_disclaimer_header" msgid="8013083414694316564">"तपाईंको खाता नयाँ डिभाइसमा व्यवस्थापन गरिने छ"</string>
+    <string name="account_management_disclaimer_header" msgid="8013083414694316564">"तपाईंको खाता व्यवस्थापन गरिएको छ"</string>
     <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"तपाईंका IT एड्मिन सुरक्षासम्बन्धी नीतिहरू लागू गर्न मोबाइल डिभाइस व्यवस्थापन गर्ने सुविधा प्रयोग गर्नुहुन्छ"</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"कामका लागि डिभाइस सेटअप गर्ने तयारी गरिँदै छ…"</string>
     <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"सर्वप्रथम आफ्नो कार्य प्रोफाइल सेटअप गरौँ"</string>
@@ -166,7 +166,7 @@
     <string name="work_profile_provisioning_step_3_header" msgid="4316106639726774330">"तपाईंका IT एडमिनले तपाईंको कार्यलयको प्रोफाइलमा भएका डेटा हेर्न सक्छन्"</string>
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"तपाईंको कार्य प्रोफाइल सेट गरिँदै छ…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"कामसम्बन्धी एपहरू तपाईंको कार्यलयको प्रोफाइलमा राखिन्छन्। तपाईंले दिनभरिको काम सकेपछि तपाईं कामसम्बन्धी एपहरू पज गर्न सक्नुहुन्छ। तपाईंका IT एडमिनले तपाईंको कार्यलयको प्रोफाइलमा भएका डेटा हेर्न सक्छन्।"</string>
-    <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"तपाईंको कार्यस्थलको डिभाइस सेट अप गरौँ"</string>
+    <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"तपाईंको कार्यालयको डिभाइस सेट अप गर्नुहोस्"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"आफ्ना कामसम्बन्धी एपहरू सजिलै भेट्टाउनुहोस्"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"यो <xliff:g id="DEVICE_NAME">%1$s</xliff:g> निजी डिभाइस होइन"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"तपाईंका IT एड्मिन तपाईंले यो <xliff:g id="DEVICE_NAME">%1$s</xliff:g> मा गर्ने क्रियाकलाप र यसमा भएका डेटा हेर्न सक्छन्।"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 86a30610..b5e1f699 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -113,7 +113,7 @@
     <string name="your_org_app_used" msgid="5336414768293540831">"ନିମ୍ନ ଆପ୍‍ ବ୍ୟବହାର କରି <xliff:g id="YOUR_ORGANIZATION">%1$s</xliff:g> ଏହି ଡିଭାଇସ୍‍ ପରିଚାଳନା ଓ ନୀରିକ୍ଷଣ କରିବ:"</string>
     <string name="your_organization_beginning" msgid="5952561489910967255">"ଆପଣଙ୍କ ସଂସ୍ଥା"</string>
     <string name="your_organization_middle" msgid="8288538158061644733">"ଆପଣଙ୍କ ସଂସ୍ଥା"</string>
-    <string name="view_terms" msgid="7230493092383341605">"ସର୍ତ୍ତାବଳୀ ଦେଖନ୍ତୁ"</string>
+    <string name="view_terms" msgid="7230493092383341605">"ସର୍ତ୍ତାବଳୀ ଭ୍ୟୁ କରନ୍ତୁ"</string>
     <string name="accept_and_continue" msgid="1632679734918410653">"ସ୍ୱୀକାର କରନ୍ତୁ ଏବଂ ଜାରି ରଖନ୍ତୁ"</string>
     <string name="back" msgid="6455622465896147127">"ପଛକୁ"</string>
     <string name="set_up_your_device" msgid="1896651520959894681">"ଆପଣଙ୍କ ଡିଭାଇସ୍‌ ସେଟ୍ ଅପ୍ କରନ୍ତୁ"</string>
@@ -168,7 +168,7 @@
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"ୱାର୍କ୍ ଆପଗୁଡ଼ିକ ଆପଣଙ୍କ ୱାର୍କ ପ୍ରୋଫାଇଲରେ ରଖାଯାଇଛି। ଆପଣ ଆପଣଙ୍କ ପୂରା ଦିନର କାମ ସମାପ୍ତ କରିସାରିବା ପରେ ଆପଣଙ୍କର ୱାର୍କ୍ ଆପଗୁଡ଼ିକୁ ବିରତ କରିପାରିବେ। ଆପଣଙ୍କ ୱାର୍କ୍ ପ୍ରୋଫାଇଲରେ ଥିବା ଡାଟା ଆପଣଙ୍କ IT ଆଡମିନଙ୍କୁ ଦେଖାଯାଉଛି।"</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"ଚାଲନ୍ତୁ ଆପଣଙ୍କ ୱାର୍କ ଡିଭାଇସକୁ ସେଟ ଅପ କରିବା"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"ଆପଣଙ୍କର ଆଙ୍ଗୁଠି ଟିପରେ ନିଜର ୱର୍କ ଆପ୍ସ ରଖନ୍ତୁ"</string>
-    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"ଏହି <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ବ୍ୟକ୍ତିଗତ ନୁହେଁ"</string>
+    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"ଏହି <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ପ୍ରାଇଭେଟ ନୁହେଁ"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"ଆପଣଙ୍କ IT ଆଡମିନ ଏହି <xliff:g id="DEVICE_NAME">%1$s</xliff:g>ରେ ଆପଣଙ୍କ ଡାଟା ଏବଂ କାର୍ଯ୍ୟକଳାପ ଦେଖିବାକୁ ସକ୍ଷମ ହୋଇପାରନ୍ତି।"</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"ଆପଣଙ୍କ କାର୍ଯ୍ୟକଳାପ ଏବଂ ଡାଟା"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"ଆପ ଅନୁମତିଗୁଡ଼ିକ"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index c6c93b5f..6a36eeb9 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -160,13 +160,13 @@
     <string name="account_management_disclaimer_header" msgid="8013083414694316564">"ਤੁਹਾਡਾ ਖਾਤਾ ਪ੍ਰਬੰਧਿਤ ਹੈ"</string>
     <string name="account_management_disclaimer_subheader" msgid="8991450067243733878">"ਤੁਹਾਡਾ ਆਈ.ਟੀ. ਪ੍ਰਸ਼ਾਸਕ ਸੁਰੱਖਿਆ ਨੀਤੀਆਂ ਨੂੰ ਲਾਗੂ ਕਰਨ ਲਈ ਮੋਬਾਈਲ ਪ੍ਰਬੰਧਨ ਦੀ ਵਰਤੋਂ ਕਰਦਾ ਹੈ"</string>
     <string name="downloading_administrator_header" msgid="8660294318893902915">"ਕਾਰਜ ਸੈੱਟਅੱਪ ਲਈ ਤਿਆਰੀ ਕੀਤੀ ਜਾ ਰਹੀ ਹੈ…"</string>
-    <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"ਚਲੋ ਤੁਹਾਡਾ ਕਾਰਜ ਪ੍ਰੋਫਾਈਲ ਸੈੱਟਅੱਪ ਕਰੀਏ"</string>
+    <string name="work_profile_provisioning_accept_header_post_suw" msgid="1353127953275291089">"ਚਲੋ ਤੁਹਾਡਾ ਕੰਮ ਸੰਬੰਧੀ ਪ੍ਰੋਫਾਈਲ ਸੈੱਟਅੱਪ ਕਰੀਏ"</string>
     <string name="work_profile_provisioning_step_1_header" msgid="7914961694921466366">"ਕੰਮ ਸੰਬੰਧੀ ਐਪਾਂ ਤੁਹਾਡੇ ਕਾਰਜ ਪ੍ਰੋਫਾਈਲ ਵਿੱਚ ਰੱਖੀਆਂ ਜਾਂਦੀਆਂ ਹਨ"</string>
     <string name="work_profile_provisioning_step_2_header" msgid="6001172190404670248">"ਕੰਮ ਪੂਰਾ ਹੋਣ \'ਤੇ ਕੰਮ ਸੰਬੰਧੀ ਐਪਾਂ ਇੱਕ ਦਿਨ ਲਈ ਰੋਕੋ"</string>
     <string name="work_profile_provisioning_step_3_header" msgid="4316106639726774330">"ਤੁਹਾਡੇ ਕਾਰਜ ਪ੍ਰੋਫਾਈਲ ਵਿਚਲਾ ਡਾਟਾ ਤੁਹਾਡੇ ਆਈ.ਟੀ. ਪ੍ਰਸ਼ਾਸਕ ਨੂੰ ਦਿਸੇਗਾ"</string>
-    <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"ਤੁਹਾਡੇ ਕਾਰਜ ਪ੍ਰੋਫਾਈਲ ਦਾ ਸੈੱਟਅੱਪ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ…"</string>
+    <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"ਤੁਹਾਡੇ ਕੰਮ ਸੰਬੰਧੀ ਪ੍ਰੋਫਾਈਲ ਦਾ ਸੈੱਟਅੱਪ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"ਕੰਮ ਸੰਬੰਧੀ ਐਪਾਂ ਤੁਹਾਡੇ ਕਾਰਜ ਪ੍ਰੋਫਾਈਲ ਵਿੱਚ ਰੱਖੀਆਂ ਜਾਂਦੀਆਂ ਹਨ। ਦਿਨ ਦਾ ਕੰਮ ਪੂਰਾ ਹੋਣ \'ਤੇ ਤੁਸੀਂ ਆਪਣੀਆਂ ਕੰਮ ਸੰਬੰਧੀ ਐਪਾਂ ਨੂੰ ਰੋਕ ਸਕਦੇ ਹੋ। ਤੁਹਾਡੇ ਕਾਰਜ ਪ੍ਰੋਫਾਈਲ ਵਿੱਚ ਡਾਟਾ ਤੁਹਾਡੇ ਆਈ.ਟੀ. ਪ੍ਰਸ਼ਾਸਕ ਨੂੰ ਦਿਸੇਗਾ।"</string>
-    <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"ਚਲੋ ਤੁਹਾਡਾ ਕਾਰਜ ਪ੍ਰੋਫਾਈਲ ਵਾਲਾ ਡੀਵਾਈਸ ਸੈੱਟਅੱਪ ਕਰੀਏ"</string>
+    <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"ਚਲੋ ਤੁਹਾਡਾ ਕੰਮ ਸੰਬੰਧੀ ਪ੍ਰੋਫਾਈਲ ਵਾਲਾ ਡੀਵਾਈਸ ਸੈੱਟਅੱਪ ਕਰੀਏ"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"ਆਪਣੀਆਂ ਕੰਮ ਸੰਬੰਧੀ ਐਪਾਂ ਆਪਣੇ ਕੋਲ ਰੱਖੋ"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"ਇਹ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ਨਿੱਜੀ ਨਹੀਂ ਹੈ"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"ਸ਼ਾਇਦ ਤੁਹਾਡਾ ਆਈ.ਟੀ. ਪ੍ਰਸ਼ਾਸਕ ਇਸ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> \'ਤੇ ਤੁਹਾਡਾ ਡਾਟਾ ਅਤੇ ਸਰਗਰਮੀ ਦੇਖ ਸਕਦਾ ਹੈ।"</string>
@@ -189,7 +189,7 @@
     <string name="cope_provisioning_summary" msgid="4993405755138454918">"ਕੰਮ ਸੰਬੰਧੀ ਐਪਾਂ ਤੁਹਾਡੇ ਕਾਰਜ ਪ੍ਰੋਫਾਈਲ ਵਿੱਚ ਰੱਖੀਆਂ ਜਾਂਦੀਆਂ ਹਨ ਅਤੇ ਉਨ੍ਹਾਂ ਦਾ ਪ੍ਰਬੰਧਨ ਤੁਹਾਡੇ ਆਈ.ਟੀ. ਪ੍ਰਸ਼ਾਸਕ ਵੱਲੋਂ ਕੀਤਾ ਜਾਂਦਾ ਹੈ। ਨਿੱਜੀ ਐਪਾਂ ਕੰਮ ਸੰਬੰਧੀ ਐਪਾਂ ਤੋਂ ਵੱਖਰੀਆਂ ਅਤੇ ਲੁਕਵੀਆਂ ਹੁੰਦੀਆਂ ਹਨ। ਤੁਹਾਡਾ ਆਈ.ਟੀ. ਪ੍ਰਸ਼ਾਸਕ ਇਸ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ਨੂੰ ਕੰਟਰੋਲ ਕਰ ਸਕਦਾ ਹੈ ਅਤੇ ਕੁਝ ਐਪਾਂ ਨੂੰ ਬਲਾਕ ਕਰ ਸਕਦਾ ਹੈ।"</string>
     <string name="just_a_sec" msgid="6244676028626237220">"ਬਸ ਇੱਕ ਸਕਿੰਟ…"</string>
     <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"ਪਰਦੇਦਾਰੀ ਯਾਦ-ਸੂਚਨਾ"</string>
-    <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"ਸ਼ਾਇਦ ਤੁਹਾਡਾ ਆਈ.ਟੀ. ਪ੍ਰਸ਼ਾਸਕ ਇਸ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> \'ਤੇ ਤੁਹਾਡਾ ਡਾਟਾ ਅਤੇ ਸਰਗਰਮੀ ਦੇਖ ਸਕਦਾ ਹੈ"</string>
+    <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"ਹੋ ਸਕਦਾ ਹੈ ਕਿ ਤੁਹਾਡਾ ਆਈ.ਟੀ. ਪ੍ਰਸ਼ਾਸਕ ਇਸ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> \'ਤੇ ਤੁਹਾਡਾ ਡਾਟਾ ਅਤੇ ਸਰਗਰਮੀ ਦੇਖ ਸਕੇ।"</string>
     <string name="financed_device_screen_header" msgid="5934940812896302344">"ਇਹ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> <xliff:g id="CREDITOR_NAME">%2$s</xliff:g> ਵੱਲੋਂ ਮੁਹੱਈਆ ਕਰਵਾਇਆ ਜਾਂਦਾ ਹੈ"</string>
     <string name="financed_make_payments_subheader_title" msgid="743966229235451097">"ਇਸ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ਲਈ ਭੁਗਤਾਨ ਕਰੋ"</string>
     <string name="financed_make_payments_subheader_description" msgid="7391276584735956742">"<xliff:g id="CREDITOR_NAME_0">%1$s</xliff:g> <xliff:g id="CREDITOR_NAME_1">%2$s</xliff:g> ਐਪ ਨੂੰ ਸਥਾਪਤ ਕਰ ਸਕਦਾ ਹੈ ਤਾਂ ਕਿ ਤੁਸੀਂ ਇਸ <xliff:g id="DEVICE_NAME">%3$s</xliff:g> ਲਈ ਭੁਗਤਾਨ ਕਰ ਸਕੋ।"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index cca85b88..276d413c 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -28,8 +28,8 @@
     <string name="the_following_is_your_mdm_for_device" msgid="6717973404364414816">"Ta aplikacja będzie zarządzać urządzeniem:"</string>
     <string name="next" msgid="1004321437324424398">"Dalej"</string>
     <string name="setting_up_workspace" msgid="7862472373642601041">"Konfiguruję profil służbowy…"</string>
-    <string name="admin_has_ability_to_monitor_profile" msgid="1018585795537086728">"Administrator IT może sprawdzać ustawienia, firmowe opcje dostępu, aplikacje, uprawnienia, dane i powiązaną z tym profilem aktywność w sieci, historię połączeń oraz historię wyszukiwania kontaktów. Może też nimi zarządzać. Aby dowiedzieć się więcej oraz poznać politykę prywatności obowiązującą w Twojej organizacji, skontaktuj się z administratorem IT."</string>
-    <string name="admin_has_ability_to_monitor_device" msgid="7786186939607332934">"Administrator IT może sprawdzać ustawienia, firmowe uprawnienia dostępu, aplikacje, uprawnienia i dane powiązane z tym urządzeniem <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, w tym aktywność sieciową, lokalizację urządzenia, historię połączeń i historię wyszukiwania kontaktów. Może też nimi zarządzać.<xliff:g id="LINE_BREAK">
+    <string name="admin_has_ability_to_monitor_profile" msgid="1018585795537086728">"Administrator IT może sprawdzać ustawienia, firmowe opcje dostępu, aplikacje, uprawnienia, dane i powiązaną z tym profilem aktywność w sieci, historię połączeń oraz historię wyszukiwania kontaktów. Może też tymi opcjami zarządzać. Aby dowiedzieć się więcej oraz poznać politykę prywatności obowiązującą w Twojej organizacji, skontaktuj się z administratorem IT."</string>
+    <string name="admin_has_ability_to_monitor_device" msgid="7786186939607332934">"Administrator IT może sprawdzać ustawienia, firmowe uprawnienia dostępu, aplikacje, uprawnienia i dane powiązane z tym urządzeniem <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, w tym aktywność sieciową, lokalizację urządzenia, historię połączeń i historię wyszukiwania kontaktów. Może też tymi opcjami zarządzać.<xliff:g id="LINE_BREAK">
 
 </xliff:g>Skontaktuj się z administratorem IT, aby dowiedzieć się więcej oraz poznać politykę prywatności obowiązującą w Twojej organizacji."</string>
     <string name="theft_protection_disabled_warning" msgid="3708092473574738478">"Aby korzystać z funkcji ochrony przed kradzieżą, musisz włączyć na urządzeniu blokadę ekranu zabezpieczoną hasłem."</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index a8c2cdf6..bebd402b 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -29,9 +29,9 @@
     <string name="next" msgid="1004321437324424398">"Seguinte"</string>
     <string name="setting_up_workspace" msgid="7862472373642601041">"A configurar o perfil de trabalho..."</string>
     <string name="admin_has_ability_to_monitor_profile" msgid="1018585795537086728">"O administrador de TI pode monitorizar e gerir as definições, o acesso empresarial, as apps, as autorizações, os dados e a atividade de rede associados a este perfil, bem como o seu histórico de chamadas e histórico de pesquisas de contactos. Contacte o administrador de TI para obter mais informações e saber mais sobre as políticas de privacidade da sua organização."</string>
-    <string name="admin_has_ability_to_monitor_device" msgid="7786186939607332934">"O seu administrador de TI tem a capacidade de monitorizar e gerir as definições, o acesso empresarial, as apps, as autorizações e os dados associados a este dispositivo <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, incluindo a atividade da rede, bem como a localização, o histórico de chamadas e o histórico de pesquisas de contactos do dispositivo.<xliff:g id="LINE_BREAK">
+    <string name="admin_has_ability_to_monitor_device" msgid="7786186939607332934">"O seu administrador de TI tem a capacidade de monitorizar e gerir as definições, o acesso empresarial, as apps, as autorizações e os dados associados a este dispositivo <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, incluindo a atividade da rede, a localização, o histórico de chamadas e o histórico de pesquisas de contactos do dispositivo.<xliff:g id="LINE_BREAK">
 
-</xliff:g>Contacte o administrador de TI para obter mais informações, incluindo as políticas de privacidade da sua organização."</string>
+</xliff:g>Contacte o administrador de TI para aceder a mais informações, incluindo as políticas de privacidade da sua organização."</string>
     <string name="theft_protection_disabled_warning" msgid="3708092473574738478">"Para utilizar as funcionalidades de proteção contra roubo, necessita de um bloqueio de ecrã protegido por palavra-passe para o dispositivo."</string>
     <string name="contact_your_admin_for_more_info" msgid="9209568156969966347">"Contacte o administrador de TI para obter mais informações, incluindo as políticas de privacidade da sua entidade."</string>
     <string name="learn_more_link" msgid="3012495805919550043">"Saiba mais"</string>
@@ -167,11 +167,11 @@
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"A configurar o perfil de trabalho…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"As apps de trabalho são mantidas no seu perfil de trabalho. Pode colocá-las em pausa quando terminar o seu dia. Os dados no seu perfil de trabalho estão visíveis para o administrador de TI."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"Vamos configurar o seu dispositivo de trabalho"</string>
-    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Mantenha as aplicações de trabalho na ponta dos seus dedos"</string>
+    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Tenha as apps de trabalho sempre à mão"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Este dispositivo <xliff:g id="DEVICE_NAME">%1$s</xliff:g> não é privado"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"O seu administrador de TI pode conseguir ver os seus dados e atividade neste dispositivo <xliff:g id="DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"A sua atividade e dados"</string>
-    <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"Autorizações da app"</string>
+    <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"Autorizações de apps"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_subheader" msgid="1973320148595109400">"O seu administrador de TI pode definir autorizações para apps neste dispositivo <xliff:g id="DEVICE_NAME">%1$s</xliff:g>, como autorizações de acesso à localização, à câmara e ao microfone."</string>
     <string name="fully_managed_device_provisioning_progress_label" msgid="3925516135130021966">"A configurar o seu dispositivo…"</string>
     <string name="fully_managed_device_provisioning_summary" msgid="2532673962822596806">"Use este dispositivo <xliff:g id="DEVICE_NAME_0">%1$s</xliff:g> para aceder facilmente às suas apps de trabalho. Este dispositivo <xliff:g id="DEVICE_NAME_1">%1$s</xliff:g> não é privado e, por isso, o administrador de TI pode conseguir ver os seus dados e atividade."</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 9b3fe791..b3fdf72a 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -183,9 +183,9 @@
     <string name="fully_managed_device_unsupported_DPC_in_headless_mode_header" msgid="7938653381656306039">"Dispozitivul nu poate fi configurat"</string>
     <string name="fully_managed_device_unsupported_DPC_in_headless_mode_subheader" msgid="5158035482490079567">"Dispozitivul nu poate fi înregistrat la modul complet gestionat. Readu dispozitivul la setările din fabrică și contactează administratorul IT."</string>
     <string name="fully_managed_device_reset_button" msgid="5957116315144904542">"Resetează la setările din fabrică"</string>
-    <string name="cope_provisioning_step_1_header" msgid="1945759718804756423">"Aplicații în profilul de serviciu, gestionate de adminul IT"</string>
+    <string name="cope_provisioning_step_1_header" msgid="1945759718804756423">"Aplicații în profilul de serviciu, gestionate de administratorul IT"</string>
     <string name="cope_provisioning_step_2_header" msgid="2388399739294883042">"Aplicațiile personale sunt izolate, ascunse de cele de lucru"</string>
-    <string name="cope_provisioning_step_3_header" msgid="7161795433847296201">"Adminul IT poate controla dispozitivul și bloca aplicații"</string>
+    <string name="cope_provisioning_step_3_header" msgid="7161795433847296201">"Administratorul IT poate controla dispozitivul și bloca aplicații"</string>
     <string name="cope_provisioning_summary" msgid="4993405755138454918">"Aplicațiile pentru lucru se păstrează în profilul de serviciu și sunt gestionate de administratorul IT. Aplicațiile personale sunt separate și ascunse de cele pentru lucru. Administratorul IT poate să controleze dispozitivul <xliff:g id="DEVICE_NAME">%1$s</xliff:g> și să blocheze anumite aplicații."</string>
     <string name="just_a_sec" msgid="6244676028626237220">"O secundă…"</string>
     <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"Memento privind confidențialitatea"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 30dfed1d..2d1531b9 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -168,7 +168,7 @@
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"Pracovné aplikácie sú uchovávané vo vašom pracovnom profile. Na konci pracovného dňa môžete pracovné aplikácie pozastaviť. Váš správca IT vidí iba údaje vo vašom pracovnom profile."</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"Poďme nastaviť vaše pracovné zariadenie"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"Majte svoje pracovné aplikácie poruke"</string>
-    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Zariadenie <xliff:g id="DEVICE_NAME">%1$s</xliff:g> nie je súkromné"</string>
+    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"Toto zariadenie <xliff:g id="DEVICE_NAME">%1$s</xliff:g> nie je súkromné"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"Váš správca IT si môže zobraziť vaše údaje a aktivitu v zariadení <xliff:g id="DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"Vaša aktivita a údaje"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"Povolenia aplikácií"</string>
@@ -188,8 +188,8 @@
     <string name="cope_provisioning_step_3_header" msgid="7161795433847296201">"Správca IT môže zariadenie ovládať a blokovať aplikácie"</string>
     <string name="cope_provisioning_summary" msgid="4993405755138454918">"Pracovné aplikácie sa uchovávajú vo vašom pracovnom profile a spravuje ich váš správca IT. Osobné aplikácie sú od pracovných oddelené a nie je ich vidieť. Váš správca IT môže zariadenie <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ovládať a blokovať určité aplikácie."</string>
     <string name="just_a_sec" msgid="6244676028626237220">"Moment…"</string>
-    <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"Pripomenutie týkajúce sa ochrany súkromia"</string>
-    <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"Váš správca IT si môže zobraziť vaše údaje a aktivitu v zariadení <xliff:g id="DEVICE_NAME">%1$s</xliff:g>"</string>
+    <string name="fully_managed_device_provisioning_privacy_title" msgid="4017627906103556021">"Pripomenutie k ochrane súkromia"</string>
+    <string name="fully_managed_device_provisioning_privacy_body" msgid="2107315052054483060">"Váš správca IT si môže zobraziť vaše údaje a aktivitu v zariadení <xliff:g id="DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="financed_device_screen_header" msgid="5934940812896302344">"Zariadenie <xliff:g id="DEVICE_NAME">%1$s</xliff:g> poskytuje <xliff:g id="CREDITOR_NAME">%2$s</xliff:g>"</string>
     <string name="financed_make_payments_subheader_title" msgid="743966229235451097">"Splácanie zariadenia <xliff:g id="DEVICE_NAME">%1$s</xliff:g>"</string>
     <string name="financed_make_payments_subheader_description" msgid="7391276584735956742">"<xliff:g id="CREDITOR_NAME_0">%1$s</xliff:g> môže nainštalovať aplikáciu <xliff:g id="CREDITOR_NAME_1">%2$s</xliff:g>, aby ste mohli zariadenie <xliff:g id="DEVICE_NAME">%3$s</xliff:g> splácať."</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index f4315e48..38580e41 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -32,7 +32,7 @@
     <string name="admin_has_ability_to_monitor_device" msgid="7786186939607332934">"Skrbnik za IT lahko nadzira in upravlja nastavitve, dostop za podjetje, aplikacije, dovoljenja in podatke, povezane s to napravo (<xliff:g id="DEVICE_NAME">%1$s</xliff:g>), vključno z omrežno dejavnostjo, podatki o lokaciji naprave, zgodovino klicev in zgodovino iskanja stikov.<xliff:g id="LINE_BREAK">
 
 </xliff:g>Za več informacij, vključno s pravilniki organizacije o zasebnosti, se obrnite na skrbnika za IT."</string>
-    <string name="theft_protection_disabled_warning" msgid="3708092473574738478">"Za uporabo funkcij za zaščito pred krajo morate imeti v napravi nastavljeno zaklepanje zaslona z geslom."</string>
+    <string name="theft_protection_disabled_warning" msgid="3708092473574738478">"Za uporabo funkcij za zaščito ob tatvini morate imeti v napravi nastavljeno zaklepanje zaslona z geslom."</string>
     <string name="contact_your_admin_for_more_info" msgid="9209568156969966347">"Za več informacij, vključno s pravilniki organizacije o zasebnosti, se obrnite na skrbnika za IT."</string>
     <string name="learn_more_link" msgid="3012495805919550043">"Več o tem"</string>
     <string name="cancel_setup" msgid="2949928239276274745">"Prekliči"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index e3aaecd3..b5b73eb6 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -167,7 +167,7 @@
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"మీ వర్క్ ప్రొఫైల్‌ను సెటప్ చేస్తోంది…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"కార్యాలయ యాప్‌లు మీ కార్యాలయ ప్రొఫైల్‌లో ఉంచబడతాయి. మీ రోజువారీ పని పూర్తయినప్పుడు మీ కార్యాలయ యాప్‌లను మీరు పాజ్ చేయవచ్చు. మీ కార్యాలయ ప్రొఫైల్‌లోని డేటా మీ IT అడ్మిన్‌లకు కనిపిస్తుంది"</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"మీ వర్క్ పరికరాన్ని సెటప్ చేయండి"</string>
-    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"మీ వర్క్ యాప్‌లను సత్వరం యాక్సెస్ చేయగలిగేలా అందుబాటులో ఉంచుకోండి"</string>
+    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"మీ వర్క్ యాప్‌లను వెంటనే యాక్సెస్ చేయగలిగేలా అందుబాటులో ఉంచుకోండి"</string>
     <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"ఈ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> ప్రైవేట్ పరికరం కాదు"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"మీ IT అడ్మిన్, ఈ <xliff:g id="DEVICE_NAME">%1$s</xliff:g>‌లోని మీ డేటాను, యాక్టివిటీని చూడగలిగే అవకాశం ఉంది."</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"మీ యాక్టివిటీ &amp; డేటా"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 24c9fd80..84981894 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -168,7 +168,7 @@
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"‏دفتری ایپس کو آپ کی دفتری پروفائل میں رکھا جاتا ہے۔ دن کا اپنا کام مکمل کرنے کے بعد آپ اپنی دفتری ایپس کو موقوف کر سکتے ہیں۔ آپ کا IT منتظم آپ کی دفتری پروفائل میں موجود ڈیٹا دیکھ سکتا ہے۔"</string>
     <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"آئیے آپ کا دفتری آلہ سیٹ اپ کریں"</string>
     <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"اپنی دفتری ایپس کو اپنے لیے بآسانی قابل رسائی بنائيں"</string>
-    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"یہ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> نجی ہے"</string>
+    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"یہ <xliff:g id="DEVICE_NAME">%1$s</xliff:g> نجی نہیں ہے"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"‏آپ کا IT منتظم اس <xliff:g id="DEVICE_NAME">%1$s</xliff:g> پر آپ کا ڈیٹا اور سرگرمی دیکھنے کا اہل ہو سکتا ہے"</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"آپ کی سرگرمی اور ڈیٹا"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"ایپ کی اجازتیں"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index c2ba4217..c5d27636 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -166,9 +166,9 @@
     <string name="work_profile_provisioning_step_3_header" msgid="4316106639726774330">"您的 IT 管理员可以查看您工作资料内的数据"</string>
     <string name="work_profile_provisioning_progress_label" msgid="2627905308998389193">"正在设置您的工作资料…"</string>
     <string name="work_profile_provisioning_summary" msgid="3436190271657388747">"工作应用会保存在您的工作资料中。您可以在完成一天的工作之后暂停工作应用。您的 IT 管理员可以查看您工作资料内的数据。"</string>
-    <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"请设置您的工作用设备"</string>
-    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"让您的工作应用触手可及"</string>
-    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"此<xliff:g id="DEVICE_NAME">%1$s</xliff:g>并非私人设备"</string>
+    <string name="fully_managed_device_provisioning_accept_header" msgid="2944032660440403130">"开始设置您的工作设备"</string>
+    <string name="fully_managed_device_provisioning_step_1_header" msgid="6396274703116708592">"让工作应用触手可及"</string>
+    <string name="fully_managed_device_provisioning_step_2_header" msgid="142633978260399682">"此 <xliff:g id="DEVICE_NAME">%1$s</xliff:g> 并非私人设备"</string>
     <string name="fully_managed_device_provisioning_step_2_subheader" msgid="3981784440341141618">"您的 IT 管理员或许可以查看您在此<xliff:g id="DEVICE_NAME">%1$s</xliff:g>上的数据和活动"</string>
     <string name="fully_managed_device_provisioning_permissions_header" msgid="2852101532084770993">"您的活动和数据"</string>
     <string name="fully_managed_device_provisioning_permissions_secondary_header" msgid="4419374850927705136">"应用权限"</string>
diff --git a/src/com/android/managedprovisioning/common/Flags.kt b/src/com/android/managedprovisioning/common/Flags.kt
index 270f5065..6625452b 100644
--- a/src/com/android/managedprovisioning/common/Flags.kt
+++ b/src/com/android/managedprovisioning/common/Flags.kt
@@ -30,4 +30,5 @@ class DefaultFlags(
     override fun isCosmicRayEnabled(): Boolean =
         onboardingFlags.isDebug ||
                 (onboardingFlags.isContractEnabled && aconfigFlags.isCosmicRayEnabled)
+
 }
diff --git a/src/com/android/managedprovisioning/finalization/UserProvisioningStateHelper.java b/src/com/android/managedprovisioning/finalization/UserProvisioningStateHelper.java
index 5e2e1063..8f0cf079 100644
--- a/src/com/android/managedprovisioning/finalization/UserProvisioningStateHelper.java
+++ b/src/com/android/managedprovisioning/finalization/UserProvisioningStateHelper.java
@@ -28,7 +28,6 @@ import static android.content.Context.DEVICE_POLICY_SERVICE;
 import static com.android.internal.util.Preconditions.checkNotNull;
 
 import android.app.admin.DevicePolicyManager;
-import android.app.admin.flags.Flags;
 import android.content.Context;
 import android.os.UserHandle;
 
@@ -179,7 +178,11 @@ public class UserProvisioningStateHelper {
 
     private void setUserProvisioningState(int state, int userId) {
         ProvisionLogger.logi("Setting userProvisioningState for user " + userId + " to: " + state);
-        mDevicePolicyManager.setUserProvisioningState(state, userId);
+        try {
+            mDevicePolicyManager.setUserProvisioningState(state, userId);
+        } catch (IllegalStateException e) {
+            ProvisionLogger.loge("Exception caught while changing provisioning state", e);
+        }
     }
 
     private void maybeSetHeadlessSystemUserProvisioningState(ProvisioningParams params, int newState) {
@@ -187,9 +190,8 @@ public class UserProvisioningStateHelper {
             return; // No special headless logic for managed profiles
         }
         if (mUtils.isHeadlessSystemUserMode()
-                && (!Flags.headlessDeviceOwnerProvisioningFixEnabled()
-                || mDevicePolicyManager.getHeadlessDeviceOwnerMode()
-                == HEADLESS_DEVICE_OWNER_MODE_AFFILIATED)
+                && mDevicePolicyManager.getHeadlessDeviceOwnerMode()
+                == HEADLESS_DEVICE_OWNER_MODE_AFFILIATED
                 && mMyUserId != UserHandle.USER_SYSTEM) {
             // For affiliated DO, headless system user's DO has to be set on system user and
             // therefore system user has to be marked the same as the calling user.
diff --git a/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivity.java b/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivity.java
index 5dc117ce..398850fe 100644
--- a/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivity.java
+++ b/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivity.java
@@ -507,7 +507,7 @@ public class PreProvisioningActivity extends Hilt_PreProvisioningActivity implem
         } else if (resultCode
                 == RESULT_UPDATE_DEVICE_POLICY_MANAGEMENT_ROLE_HOLDER_PROVISIONING_DISABLED
         ) {
-            mController.performPlatformProvidedProvisioning();
+            mController.performPlatformProvidedProvisioning(getIntent(), getCallingPackage());
         } else if (resultCode
                 != RESULT_UPDATE_DEVICE_POLICY_MANAGEMENT_ROLE_HOLDER_UNRECOVERABLE_ERROR) {
             mController.resetRoleHolderUpdateRetryCount();
@@ -519,7 +519,8 @@ public class PreProvisioningActivity extends Hilt_PreProvisioningActivity implem
                 if (isRoleHolderUpdaterRequestingPlatformDrivenProvisioning(resultData)) {
                     ProvisionLogger.logi("Result is " + resultCode
                             + " and applied fallback strategy.");
-                    mController.performPlatformProvidedProvisioning();
+                    mController.performPlatformProvidedProvisioning(getIntent(),
+                            getCallingPackage());
                 } else {
                     mAnalyticsTracker.logRoleHolderUpdaterUpdateFailed();
                     failRoleHolderUpdate();
@@ -533,10 +534,10 @@ public class PreProvisioningActivity extends Hilt_PreProvisioningActivity implem
             }
         } else if (mController.getParams().allowOffline) {
             ProvisionLogger.logi("Result is " + resultCode + ". Allowed offline provisioning.");
-            mController.performPlatformProvidedProvisioning();
+            mController.performPlatformProvidedProvisioning(getIntent(), getCallingPackage());
         } else if (isRoleHolderUpdaterRequestingPlatformDrivenProvisioning(resultData)) {
             ProvisionLogger.logi("Result is " + resultCode + " and applied fallback strategy.");
-            mController.performPlatformProvidedProvisioning();
+            mController.performPlatformProvidedProvisioning(getIntent(), getCallingPackage());
         } else {
             mAnalyticsTracker.logRoleHolderUpdaterUpdateFailed();
             failRoleHolderUpdate();
@@ -558,7 +559,7 @@ public class PreProvisioningActivity extends Hilt_PreProvisioningActivity implem
             mController.incrementRoleHolderUpdateRetryCount();
         } else if (resultCode
                 == RESULT_UPDATE_DEVICE_POLICY_MANAGEMENT_ROLE_HOLDER_PROVISIONING_DISABLED) {
-            mController.performPlatformProvidedProvisioning();
+            mController.performPlatformProvidedProvisioning(getIntent(), getCallingPackage());
         } else if (resultCode
                 != RESULT_UPDATE_DEVICE_POLICY_MANAGEMENT_ROLE_HOLDER_UNRECOVERABLE_ERROR) {
             boolean isProvisioningStarted = mController.startAppropriateProvisioning(
@@ -569,7 +570,8 @@ public class PreProvisioningActivity extends Hilt_PreProvisioningActivity implem
                 if (isRoleHolderUpdaterRequestingPlatformDrivenProvisioning(resultData)) {
                     ProvisionLogger.logi("Result is " + resultCode
                             + " and applied fallback strategy.");
-                    mController.performPlatformProvidedProvisioning();
+                    mController.performPlatformProvidedProvisioning(getIntent(),
+                            getCallingPackage());
                 } else {
                     failRoleHolderUpdate();
                     ProvisionLogger.loge("Failed to start provisioning after a "
@@ -582,10 +584,10 @@ public class PreProvisioningActivity extends Hilt_PreProvisioningActivity implem
             }
         } else if (mController.getParams().allowOffline) {
             ProvisionLogger.logi("Result is " + resultCode + ". Allowed offline provisioning.");
-            mController.performPlatformProvidedProvisioning();
+            mController.performPlatformProvidedProvisioning(getIntent(), getCallingPackage());
         } else if (isRoleHolderUpdaterRequestingPlatformDrivenProvisioning(resultData)) {
             ProvisionLogger.logi("Result is " + resultCode + " and applied fallback strategy.");
-            mController.performPlatformProvidedProvisioning();
+            mController.performPlatformProvidedProvisioning(getIntent(), getCallingPackage());
         } else {
             failRoleHolderUpdate();
             ProvisionLogger.loge("Failed to perform a role holder-requested role holder "
diff --git a/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityController.java b/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityController.java
index f7276fa7..ba216005 100644
--- a/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityController.java
+++ b/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityController.java
@@ -106,6 +106,7 @@ import com.android.managedprovisioning.common.RoleHolderUpdaterProvider;
 import com.android.managedprovisioning.common.SettingsFacade;
 import com.android.managedprovisioning.common.StoreUtils;
 import com.android.managedprovisioning.common.Utils;
+import com.android.managedprovisioning.flags.Flags;
 import com.android.managedprovisioning.model.DisclaimersParam;
 import com.android.managedprovisioning.model.ProvisioningParams;
 import com.android.managedprovisioning.model.ProvisioningParams.FlowType;
@@ -122,6 +123,7 @@ import java.util.IllformedLocaleException;
 import java.util.List;
 import java.util.function.BiFunction;
 
+
 /**
  * Controller which contains business logic related to provisioning preparation.
  *
@@ -238,7 +240,7 @@ public class PreProvisioningActivityController {
         // In T allowOffline is used here to force platform provisioning.
         if (getParams().allowOffline) {
             ProvisionLogger.logw("allowOffline set, provisioning via platform.");
-            performPlatformProvidedProvisioning();
+            performPlatformProvidedProvisioning(managedProvisioningIntent, callingPackage);
             return true;
         }
 
@@ -257,7 +259,7 @@ public class PreProvisioningActivityController {
                     mUi.startRoleHolderProvisioning(roleHolderProvisioningIntent);
                 } else {
                     ProvisionLogger.logw("Falling back to provisioning via platform.");
-                    performPlatformProvidedProvisioning();
+                    performPlatformProvidedProvisioning(managedProvisioningIntent, callingPackage);
                 }
             });
             return true;
@@ -265,7 +267,7 @@ public class PreProvisioningActivityController {
                 || !mRoleHolderUpdaterHelper.isRoleHolderUpdaterDefined()
                 || !isRoleHolderProvisioningAllowed) {
             ProvisionLogger.logw("Provisioning via platform.");
-            performPlatformProvidedProvisioning();
+            performPlatformProvidedProvisioning(managedProvisioningIntent, callingPackage);
             return true;
         }
         ProvisionLogger.logw("Role holder is configured, can't provision via role holder and "
@@ -404,31 +406,20 @@ public class PreProvisioningActivityController {
         }
 
         ProvisioningParams params = mViewModel.getParams();
-        if (!checkFactoryResetProtection(params, callingPackage)) {
-            return;
-        }
-
-        if (!verifyActionAndCaller(intent, callingPackage)) {
-            return;
-        }
 
         mProvisioningAnalyticsTracker.logProvisioningExtras(mContext, intent);
         mProvisioningAnalyticsTracker.logEntryPoint(mContext, intent, mSettingsFacade);
 
-        // Check whether provisioning is allowed for the current action. This check needs to happen
-        // before any actions that might affect the state of the device.
-        // Note that checkDevicePolicyPreconditions takes care of calling
-        // showProvisioningErrorAndClose. So we only need to show the factory reset dialog (if
-        // applicable) and return.
-        if (!checkDevicePolicyPreconditions()) {
-            return;
-        }
-
-        if (!isIntentActionValid(intent.getAction())) {
-            ProvisionLogger.loge(
-                    ACTION_PROVISION_MANAGED_DEVICE + " is no longer a supported intent action.");
-            mUi.abortProvisioning();
-            return;
+        // Pre provisioning checks will be performed by the roleholder or platform at a later point
+        // in the flow if the flag returns true
+        if (!Flags.badStateV3EarlyRhDownloadEnabled()) {
+            if (!passesPreProvisioningChecks(intent, callingPackage)) {
+                ProvisionLogger.loge(
+                        "Pre-provisioning checks have failed, cancelling provisioning");
+                return;
+            }
+        } else {
+            ProvisionLogger.logd("Skipping pre-provisioning checks until roleholder download");
         }
 
         if (isDeviceOwnerProvisioning()) {
@@ -492,7 +483,45 @@ public class PreProvisioningActivityController {
         ProvisionLogger.logi("Finish logging provisioning extras");
     }
 
-    void performPlatformProvidedProvisioning() {
+    boolean passesPreProvisioningChecks(Intent managedProvisioningIntent, String callingPackage) {
+        ProvisioningParams params = mViewModel.getParams();
+
+        if (!checkFactoryResetProtection(params, callingPackage)) {
+            return false;
+        }
+
+        if (!verifyActionAndCaller(managedProvisioningIntent, callingPackage)) {
+            return false;
+        }
+        // Check whether provisioning is allowed for the current action. This check needs to happen
+        // before any actions that might affect the state of the device.
+        // Note that checkDevicePolicyPreconditions takes care of calling
+        // showProvisioningErrorAndClose. So we only need to show the factory reset dialog (if
+        // applicable) and return.
+        if (!checkDevicePolicyPreconditions()) {
+            return false;
+        }
+
+        if (!isIntentActionValid(managedProvisioningIntent.getAction())) {
+            ProvisionLogger.loge(
+                    ACTION_PROVISION_MANAGED_DEVICE
+                            + " is no longer a supported intent action.");
+            mUi.abortProvisioning();
+            return false;
+        }
+
+        return true;
+    }
+
+    void performPlatformProvidedProvisioning(Intent managedProvisioningIntent,
+            String callingPackage) {
+
+        if (Flags.badStateV3EarlyRhDownloadEnabled()
+                && !passesPreProvisioningChecks(managedProvisioningIntent, callingPackage)) {
+            ProvisionLogger.loge("Pre-provisioning checks have failed, cancelling provisioning");
+            return;
+        }
+
         ProvisionLogger.logw("Provisioning via platform-provided provisioning");
         ProvisioningParams params = mViewModel.getParams();
         if (mSharedPreferences.isProvisioningFlowDelegatedToRoleHolder()) {
diff --git a/studio-dev/.gitignore b/studio-dev/.gitignore
deleted file mode 100644
index 03947991..00000000
--- a/studio-dev/.gitignore
+++ /dev/null
@@ -1,3 +0,0 @@
-studio/*
-deviceFiles/*
-.studio_version_cache
diff --git a/studio-dev/MPStudio.desktop b/studio-dev/MPStudio.desktop
deleted file mode 100644
index 8ceb1d49..00000000
--- a/studio-dev/MPStudio.desktop
+++ /dev/null
@@ -1,10 +0,0 @@
-[Desktop Entry]
-Name=Managed Provisioning Studio
-Exec=%STUDIOW_PATH% %u
-Path=%ANDROID_TOP%
-Icon=%STUDIOW_ICON%
-Terminal=false
-Type=Application
-Categories=Development;IDE;Java;
-StartupWMClass=jetbrains-studio
-X-Desktop-File-Install-Version=0.26
diff --git a/studio-dev/ManagedProvisioningGradleProject/.gitignore b/studio-dev/ManagedProvisioningGradleProject/.gitignore
deleted file mode 100644
index efb95072..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.gitignore
+++ /dev/null
@@ -1,23 +0,0 @@
-.gradle/*
-gradlew.bat
-local.properties
-studiow.properties
-
-.build-cache*
-
-**/*.iml
-**/.DS_Store
-**/build/*
-SystemUI/linked_elmyra_protos/**
-SystemUI/wm_shell_protos/**
-SystemUILib/linked_elmyra_protos/**
-SystemUILib/wm_shell_protos/**
-
-!.idea
-.idea/*
-!.idea/runConfigurations
-!.idea/vcs.xml
-!/.idea/copyright
-
-.symlinkSrc/
-test-file
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/copyright/Apache_2.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/copyright/Apache_2.xml
deleted file mode 100644
index b0119964..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/copyright/Apache_2.xml
+++ /dev/null
@@ -1,10 +0,0 @@
-<component name="CopyrightManager">
-    <copyright>
-        <option name="notice"
-                value="Copyright (C) &amp;#36;today.year The Android Open Source Project&#10;&#10;Licensed under the Apache License, Version 2.0 (the &quot;License&quot;);&#10;you may not use this file except in compliance with the License.&#10;You may obtain a copy of the License at&#10;&#10;     http://www.apache.org/licenses/LICENSE-2.0&#10;&#10;Unless required by applicable law or agreed to in writing, software&#10;distributed under the License is distributed on an &quot;AS IS&quot; BASIS,&#10;WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.&#10;See the License for the specific language governing permissions and&#10;limitations under the License."/>
-        <option name="keyword" value="Copyright"/>
-        <option name="allowReplaceKeyword" value=""/>
-        <option name="myName" value="Apache 2"/>
-        <option name="myLocal" value="true"/>
-    </copyright>
-</component>
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/copyright/profiles_settings.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/copyright/profiles_settings.xml
deleted file mode 100644
index 84a32428..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/copyright/profiles_settings.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<component name="CopyrightManager">
-    <settings default="">
-        <module2copyright>
-            <element module="Project Files" copyright="Apache 2"/>
-        </module2copyright>
-    </settings>
-</component>
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/NexusLauncher.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/NexusLauncher.xml
deleted file mode 100644
index 01ba9f98..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/NexusLauncher.xml
+++ /dev/null
@@ -1,59 +0,0 @@
-<component name="ProjectRunConfigurationManager">
-  <configuration default="false" name="NexusLauncher" type="AndroidRunConfigurationType" factoryName="Android App" activateToolWindowBeforeRun="false">
-    <module name="SysUIGradleProject.NexusLauncher.main" />
-    <option name="DEPLOY" value="true" />
-    <option name="DEPLOY_APK_FROM_BUNDLE" value="false" />
-    <option name="DEPLOY_AS_INSTANT" value="false" />
-    <option name="ARTIFACT_NAME" value="" />
-    <option name="PM_INSTALL_OPTIONS" value="" />
-    <option name="ALL_USERS" value="false" />
-    <option name="DYNAMIC_FEATURES_DISABLED_LIST" value="" />
-    <option name="ACTIVITY_EXTRA_FLAGS" value="-S --activityType 2" />
-    <option name="MODE" value="specific_activity" />
-    <option name="CLEAR_LOGCAT" value="false" />
-    <option name="SHOW_LOGCAT_AUTOMATICALLY" value="false" />
-    <option name="SKIP_NOOP_APK_INSTALLATIONS" value="true" />
-    <option name="FORCE_STOP_RUNNING_APP" value="true" />
-    <option name="TARGET_SELECTION_MODE" value="DEVICE_AND_SNAPSHOT_COMBO_BOX" />
-    <option name="SELECTED_CLOUD_MATRIX_CONFIGURATION_ID" value="-1" />
-    <option name="SELECTED_CLOUD_MATRIX_PROJECT_ID" value="" />
-    <option name="DEBUGGER_TYPE" value="Java" />
-    <Auto>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-    </Auto>
-    <Hybrid>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-    </Hybrid>
-    <Java />
-    <Native>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-    </Native>
-    <Profilers>
-      <option name="ADVANCED_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_CPU_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_CPU_PROFILING_CONFIGURATION_NAME" value="Sample Java Methods" />
-      <option name="STARTUP_NATIVE_MEMORY_PROFILING_ENABLED" value="false" />
-      <option name="NATIVE_MEMORY_SAMPLE_RATE_BYTES" value="2048" />
-    </Profilers>
-    <option name="DEEP_LINK" value="" />
-    <option name="ACTIVITY_CLASS" value="com.google.android.apps.nexuslauncher.NexusLauncherActivity" />
-    <option name="SEARCH_ACTIVITY_IN_GLOBAL_SCOPE" value="false" />
-    <option name="SKIP_ACTIVITY_VALIDATION" value="true" />
-    <method v="2">
-      <option name="Android.Gradle.BeforeRunTask" enabled="true" />
-    </method>
-  </configuration>
-</component>
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/SystemUIGoogle.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/SystemUIGoogle.xml
deleted file mode 100644
index dfaae950..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/SystemUIGoogle.xml
+++ /dev/null
@@ -1,64 +0,0 @@
-<component name="ProjectRunConfigurationManager">
-  <configuration default="false" name="SystemUIGoogle" type="AndroidRunConfigurationType" factoryName="Android App" activateToolWindowBeforeRun="false" singleton="false">
-    <module name="SysUIGradleProject.SystemUI.main" />
-    <option name="DEPLOY" value="false" />
-    <option name="DEPLOY_APK_FROM_BUNDLE" value="false" />
-    <option name="DEPLOY_AS_INSTANT" value="false" />
-    <option name="ARTIFACT_NAME" value="" />
-    <option name="PM_INSTALL_OPTIONS" value="none &gt; /dev/null 2&gt;&amp;1 ; install_command() { if ! [ -z $(su root getprop partition.system.verified 2&gt;/dev/null) ]; then &gt;&amp;2 echo &quot;Failure [INSTALL_FAILED_INTERNAL_ERROR Verity must be disabled to push]&quot;; return 1; fi; su root remount; if TARGET_PATH=`pm path com.android.systemui 2&gt;&amp;1`; then TARGET_PATH=`echo $TARGET_PATH | cut -d ':' -f 2`; else echo &quot;Failure [INSTALL_FAILED_INTERNAL_ERROR Unable to get apk path: $TARGET_PATH]&quot;; return 1; fi; for SOURCE_PATH in $@; do :; done; su root mv $SOURCE_PATH $TARGET_PATH &amp;&amp; su root kill `pidof com.android.systemui` || { echo &quot;Failure [INSTALL_FAILED_INTERNAL_ERROR mv $SOURCE_PATH $TARGET_PATH failed]&quot;; return 1;}; }; install_command" />
-    <option name="ALL_USERS" value="false" />
-    <option name="ALWAYS_INSTALL_WITH_PM" value="false" />
-    <option name="CLEAR_APP_STORAGE" value="false" />
-    <option name="ACTIVITY_EXTRA_FLAGS" value="" />
-    <option name="MODE" value="do_nothing" />
-    <option name="CLEAR_LOGCAT" value="false" />
-    <option name="SHOW_LOGCAT_AUTOMATICALLY" value="false" />
-    <option name="INSPECTION_WITHOUT_ACTIVITY_RESTART" value="false" />
-    <option name="TARGET_SELECTION_MODE" value="SHOW_DIALOG" />
-    <option name="SELECTED_CLOUD_MATRIX_CONFIGURATION_ID" value="-1" />
-    <option name="SELECTED_CLOUD_MATRIX_PROJECT_ID" value="" />
-    <option name="DEBUGGER_TYPE" value="Auto" />
-    <Auto>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-    </Auto>
-    <Hybrid>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-    </Hybrid>
-    <Java>
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-    </Java>
-    <Native>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-    </Native>
-    <Profilers>
-      <option name="ADVANCED_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_CPU_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_CPU_PROFILING_CONFIGURATION_NAME" value="Callstack Sample" />
-      <option name="STARTUP_NATIVE_MEMORY_PROFILING_ENABLED" value="false" />
-      <option name="NATIVE_MEMORY_SAMPLE_RATE_BYTES" value="2048" />
-    </Profilers>
-    <option name="DEEP_LINK" value="" />
-    <option name="ACTIVITY_CLASS" value="" />
-    <option name="SEARCH_ACTIVITY_IN_GLOBAL_SCOPE" value="false" />
-    <option name="SKIP_ACTIVITY_VALIDATION" value="false" />
-    <method v="2">
-      <option name="Android.Gradle.BeforeRunTask" enabled="true" goal=":SystemUI:pushSystemUIGoogleDebugApk" />
-    </method>
-  </configuration>
-</component>
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/SystemUILib_with_NullAway.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/SystemUILib_with_NullAway.xml
deleted file mode 100644
index 388a44a6..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/SystemUILib_with_NullAway.xml
+++ /dev/null
@@ -1,23 +0,0 @@
-<component name="ProjectRunConfigurationManager">
-  <configuration default="false" name="SystemUILib with NullAway" type="GradleRunConfiguration" factoryName="Gradle">
-    <ExternalSystemSettings>
-      <option name="executionName" />
-      <option name="externalProjectPath" value="$PROJECT_DIR$" />
-      <option name="externalSystemIdString" value="GRADLE" />
-      <option name="scriptParameters" value="" />
-      <option name="taskDescriptions">
-        <list />
-      </option>
-      <option name="taskNames">
-        <list>
-          <option value=":SystemUILib:compileNullsafeJavaWithJavac" />
-        </list>
-      </option>
-      <option name="vmOptions" value="" />
-    </ExternalSystemSettings>
-    <ExternalSystemDebugServerProcess>true</ExternalSystemDebugServerProcess>
-    <ExternalSystemReattachDebugProcess>true</ExternalSystemReattachDebugProcess>
-    <DebugAllEnabled>false</DebugAllEnabled>
-    <method v="2" />
-  </configuration>
-</component>
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/SystemUITitan.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/SystemUITitan.xml
deleted file mode 100644
index 201547c9..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/SystemUITitan.xml
+++ /dev/null
@@ -1,64 +0,0 @@
-<component name="ProjectRunConfigurationManager">
-  <configuration default="false" name="SystemUITitan" type="AndroidRunConfigurationType" factoryName="Android App" activateToolWindowBeforeRun="false" singleton="false">
-    <module name="SysUIGradleProject.SystemUI.main" />
-    <option name="DEPLOY" value="false" />
-    <option name="DEPLOY_APK_FROM_BUNDLE" value="false" />
-    <option name="DEPLOY_AS_INSTANT" value="false" />
-    <option name="ARTIFACT_NAME" value="" />
-    <option name="PM_INSTALL_OPTIONS" value="none &gt; /dev/null 2&gt;&amp;1 ; install_command() { if ! [ -z $(su root getprop partition.system.verified 2&gt;/dev/null) ]; then &gt;&amp;2 echo &quot;Failure [INSTALL_FAILED_INTERNAL_ERROR Verity must be disabled to push]&quot;; return 1; fi; su root remount; if TARGET_PATH=`pm path com.android.systemui 2&gt;&amp;1`; then TARGET_PATH=`echo $TARGET_PATH | cut -d ':' -f 2`; else echo &quot;Failure [INSTALL_FAILED_INTERNAL_ERROR Unable to get apk path: $TARGET_PATH]&quot;; return 1; fi; for SOURCE_PATH in $@; do :; done; su root mv $SOURCE_PATH $TARGET_PATH &amp;&amp; su root kill `pidof com.android.systemui` || { echo &quot;Failure [INSTALL_FAILED_INTERNAL_ERROR mv $SOURCE_PATH $TARGET_PATH failed]&quot;; return 1;}; }; install_command" />
-    <option name="ALL_USERS" value="false" />
-    <option name="ALWAYS_INSTALL_WITH_PM" value="false" />
-    <option name="CLEAR_APP_STORAGE" value="false" />
-    <option name="ACTIVITY_EXTRA_FLAGS" value="" />
-    <option name="MODE" value="do_nothing" />
-    <option name="CLEAR_LOGCAT" value="false" />
-    <option name="SHOW_LOGCAT_AUTOMATICALLY" value="false" />
-    <option name="INSPECTION_WITHOUT_ACTIVITY_RESTART" value="false" />
-    <option name="TARGET_SELECTION_MODE" value="SHOW_DIALOG" />
-    <option name="SELECTED_CLOUD_MATRIX_CONFIGURATION_ID" value="-1" />
-    <option name="SELECTED_CLOUD_MATRIX_PROJECT_ID" value="" />
-    <option name="DEBUGGER_TYPE" value="Auto" />
-    <Auto>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-    </Auto>
-    <Hybrid>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-    </Hybrid>
-    <Java>
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-    </Java>
-    <Native>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-    </Native>
-    <Profilers>
-      <option name="ADVANCED_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_CPU_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_CPU_PROFILING_CONFIGURATION_NAME" value="Callstack Sample" />
-      <option name="STARTUP_NATIVE_MEMORY_PROFILING_ENABLED" value="false" />
-      <option name="NATIVE_MEMORY_SAMPLE_RATE_BYTES" value="2048" />
-    </Profilers>
-    <option name="DEEP_LINK" value="" />
-    <option name="ACTIVITY_CLASS" value="" />
-    <option name="SEARCH_ACTIVITY_IN_GLOBAL_SCOPE" value="false" />
-    <option name="SKIP_ACTIVITY_VALIDATION" value="false" />
-    <method v="2">
-      <option name="Android.Gradle.BeforeRunTask" enabled="true" goal=":SystemUI:pushSystemUITitanDebugApk" />
-    </method>
-  </configuration>
-</component>
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/Update_Source_Link.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/Update_Source_Link.xml
deleted file mode 100644
index a68418af..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/Update_Source_Link.xml
+++ /dev/null
@@ -1,23 +0,0 @@
-<component name="ProjectRunConfigurationManager">
-  <configuration default="false" name="Update Source Link" type="GradleRunConfiguration" factoryName="Gradle">
-    <ExternalSystemSettings>
-      <option name="executionName" />
-      <option name="externalProjectPath" value="$PROJECT_DIR$" />
-      <option name="externalSystemIdString" value="GRADLE" />
-      <option name="scriptParameters" value="--stacktrace" />
-      <option name="taskDescriptions">
-        <list />
-      </option>
-      <option name="taskNames">
-        <list>
-          <option value=":updateSdkSources" />
-        </list>
-      </option>
-      <option name="vmOptions" value="" />
-    </ExternalSystemSettings>
-    <ExternalSystemDebugServerProcess>true</ExternalSystemDebugServerProcess>
-    <ExternalSystemReattachDebugProcess>true</ExternalSystemReattachDebugProcess>
-    <DebugAllEnabled>false</DebugAllEnabled>
-    <method v="2" />
-  </configuration>
-</component>
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/WallpaperPickerGoogle.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/WallpaperPickerGoogle.xml
deleted file mode 100644
index ba3da09c..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/WallpaperPickerGoogle.xml
+++ /dev/null
@@ -1,59 +0,0 @@
-<component name="ProjectRunConfigurationManager">
-  <configuration default="false" name="WallpaperPickerGoogle" type="AndroidRunConfigurationType" factoryName="Android App" activateToolWindowBeforeRun="false">
-    <module name="SysUIGradleProject.WallpaperPickerGoogle.main" />
-    <option name="DEPLOY" value="true" />
-    <option name="DEPLOY_APK_FROM_BUNDLE" value="false" />
-    <option name="DEPLOY_AS_INSTANT" value="false" />
-    <option name="ARTIFACT_NAME" value="" />
-    <option name="PM_INSTALL_OPTIONS" value="" />
-    <option name="ALL_USERS" value="false" />
-    <option name="DYNAMIC_FEATURES_DISABLED_LIST" value="" />
-    <option name="ACTIVITY_EXTRA_FLAGS" value="-S --activityType 2" />
-    <option name="MODE" value="do_nothing" />
-    <option name="CLEAR_LOGCAT" value="false" />
-    <option name="SHOW_LOGCAT_AUTOMATICALLY" value="false" />
-    <option name="SKIP_NOOP_APK_INSTALLATIONS" value="true" />
-    <option name="FORCE_STOP_RUNNING_APP" value="true" />
-    <option name="TARGET_SELECTION_MODE" value="DEVICE_AND_SNAPSHOT_COMBO_BOX" />
-    <option name="SELECTED_CLOUD_MATRIX_CONFIGURATION_ID" value="-1" />
-    <option name="SELECTED_CLOUD_MATRIX_PROJECT_ID" value="" />
-    <option name="DEBUGGER_TYPE" value="Java" />
-    <Auto>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-    </Auto>
-    <Hybrid>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-    </Hybrid>
-    <Java />
-    <Native>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-    </Native>
-    <Profilers>
-      <option name="ADVANCED_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_CPU_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_CPU_PROFILING_CONFIGURATION_NAME" value="Sample Java Methods" />
-      <option name="STARTUP_NATIVE_MEMORY_PROFILING_ENABLED" value="false" />
-      <option name="NATIVE_MEMORY_SAMPLE_RATE_BYTES" value="2048" />
-    </Profilers>
-    <option name="DEEP_LINK" value="" />
-    <option name="ACTIVITY_CLASS" value="" />
-    <option name="SEARCH_ACTIVITY_IN_GLOBAL_SCOPE" value="false" />
-    <option name="SKIP_ACTIVITY_VALIDATION" value="true" />
-    <method v="2">
-      <option name="Android.Gradle.BeforeRunTask" enabled="true" />
-    </method>
-  </configuration>
-</component>
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/WallpaperPickerGoogle_deviceless_tests.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/WallpaperPickerGoogle_deviceless_tests.xml
deleted file mode 100644
index f7294e13..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/WallpaperPickerGoogle_deviceless_tests.xml
+++ /dev/null
@@ -1,24 +0,0 @@
-<component name="ProjectRunConfigurationManager">
-  <configuration default="false" name="WallpaperPickerGoogle deviceless tests" type="GradleRunConfiguration" factoryName="Gradle">
-    <ExternalSystemSettings>
-      <option name="executionName" />
-      <option name="externalProjectPath" value="$PROJECT_DIR$" />
-      <option name="externalSystemIdString" value="GRADLE" />
-      <option name="scriptParameters" value="" />
-      <option name="taskDescriptions">
-        <list />
-      </option>
-      <option name="taskNames">
-        <list>
-          <option value=":WallpaperPickerGoogle:testGoogleDebugUnitTest" />
-        </list>
-      </option>
-      <option name="vmOptions" />
-    </ExternalSystemSettings>
-    <ExternalSystemDebugServerProcess>true</ExternalSystemDebugServerProcess>
-    <ExternalSystemReattachDebugProcess>true</ExternalSystemReattachDebugProcess>
-    <DebugAllEnabled>false</DebugAllEnabled>
-    <ForceTestExec>false</ForceTestExec>
-    <method v="2" />
-  </configuration>
-</component>
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/WallpaperPickerGoogle_instrumented_tests.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/WallpaperPickerGoogle_instrumented_tests.xml
deleted file mode 100644
index 2ef3052d..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/runConfigurations/WallpaperPickerGoogle_instrumented_tests.xml
+++ /dev/null
@@ -1,64 +0,0 @@
-<component name="ProjectRunConfigurationManager">
-  <configuration default="false" name="WallpaperPickerGoogle instrumented tests" type="AndroidTestRunConfigurationType" factoryName="Android Instrumented Tests">
-    <module name="SysUIGradleProject.WallpaperPickerGoogle.androidTest" />
-    <option name="TESTING_TYPE" value="0" />
-    <option name="METHOD_NAME" value="" />
-    <option name="CLASS_NAME" value="" />
-    <option name="PACKAGE_NAME" value="" />
-    <option name="TEST_NAME_REGEX" value="" />
-    <option name="INSTRUMENTATION_RUNNER_CLASS" value="" />
-    <option name="EXTRA_OPTIONS" value="" />
-    <option name="RETENTION_ENABLED" value="No" />
-    <option name="RETENTION_MAX_SNAPSHOTS" value="2" />
-    <option name="RETENTION_COMPRESS_SNAPSHOTS" value="false" />
-    <option name="CLEAR_LOGCAT" value="false" />
-    <option name="SHOW_LOGCAT_AUTOMATICALLY" value="false" />
-    <option name="INSPECTION_WITHOUT_ACTIVITY_RESTART" value="false" />
-    <option name="TARGET_SELECTION_MODE" value="DEVICE_AND_SNAPSHOT_COMBO_BOX" />
-    <option name="SELECTED_CLOUD_MATRIX_CONFIGURATION_ID" value="-1" />
-    <option name="SELECTED_CLOUD_MATRIX_PROJECT_ID" value="" />
-    <option name="DEBUGGER_TYPE" value="Auto" />
-    <Auto>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-      <option name="DEBUG_SANDBOX_SDK" value="false" />
-    </Auto>
-    <Hybrid>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-      <option name="DEBUG_SANDBOX_SDK" value="false" />
-    </Hybrid>
-    <Java>
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-      <option name="DEBUG_SANDBOX_SDK" value="false" />
-    </Java>
-    <Native>
-      <option name="USE_JAVA_AWARE_DEBUGGER" value="false" />
-      <option name="SHOW_STATIC_VARS" value="true" />
-      <option name="WORKING_DIR" value="" />
-      <option name="TARGET_LOGGING_CHANNELS" value="lldb process:gdb-remote packets" />
-      <option name="SHOW_OPTIMIZED_WARNING" value="true" />
-      <option name="ATTACH_ON_WAIT_FOR_DEBUGGER" value="false" />
-      <option name="DEBUG_SANDBOX_SDK" value="false" />
-    </Native>
-    <Profilers>
-      <option name="ADVANCED_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_CPU_PROFILING_ENABLED" value="false" />
-      <option name="STARTUP_CPU_PROFILING_CONFIGURATION_NAME" value="Java/Kotlin Method Sample (legacy)" />
-      <option name="STARTUP_NATIVE_MEMORY_PROFILING_ENABLED" value="false" />
-      <option name="NATIVE_MEMORY_SAMPLE_RATE_BYTES" value="2048" />
-    </Profilers>
-    <method v="2">
-      <option name="Android.Gradle.BeforeRunTask" enabled="true" />
-    </method>
-  </configuration>
-</component>
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/.idea/vcs.xml b/studio-dev/ManagedProvisioningGradleProject/.idea/vcs.xml
deleted file mode 100644
index 4a7db195..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/.idea/vcs.xml
+++ /dev/null
@@ -1,142 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<project version="4">
-  <component name="CommitMessageInspectionProfile">
-    <profile version="1.0">
-      <inspection_tool class="BodyLimit" enabled="true" level="WARNING" enabled_by_default="true" />
-      <inspection_tool class="SubjectBodySeparation" enabled="true" level="WARNING" enabled_by_default="true" />
-      <inspection_tool class="SubjectLimit" enabled="true" level="WARNING" enabled_by_default="true" />
-    </profile>
-  </component>
-  <component name="VcsDirectoryMappings">
-    <mapping directory="$PROJECT_DIR$/../../../../../external/android_onboarding" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../external/robolectric" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../external/setupcompat" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../external/setupdesign" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/av" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/base" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/compile/libbcc" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/compile/mclinker" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/compile/slang" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/ex" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/hardware/interfaces" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/layoutlib" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/libs/binary_translation" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/libs/gsma_services" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/libs/modules-utils" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/libs/native_bridge_support" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/libs/service_entitlement" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/libs/systemui" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/minikin" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/multidex" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/native" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/bitmap" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/calendar" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/car/services" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/car/setupwizard" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/chips" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/colorpicker" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/localepicker" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/net/ethernet" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/net/ims" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/net/voip" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/net/wifi" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/photoviewer" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/setupwizard" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/telephony" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/timezonepicker" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/tv/tvsystem" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/vcard" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/opt/wear" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/proto_logging" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/rs" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../frameworks/wilhelm" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../.." vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/abi-dumps/ndk" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/abi-dumps/platform" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/abi-dumps/vndk" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/android-emulator" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/asuite" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/bazel/common" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/bazel/darwin-x86_64" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/bazel/linux-x86_64" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/build-tools" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/bundletool" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/checkcolor" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/checkstyle" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/clang-tools" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/clang/host/linux-x86" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/cmdline-tools" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/devtools" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/fuchsia_sdk" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.17-4.8" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/gcc/linux-x86/host/x86_64-w64-mingw32-4.8" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/go/linux-x86" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/gradle-plugin" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/jdk/jdk11" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/jdk/jdk17" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/jdk/jdk21" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/jdk/jdk8" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/jdk/jdk9" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/ktlint" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/manifest-merger" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/maven_repo/bumptech" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/misc" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/AdServices" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/AppSearch" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/Bluetooth" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/ConfigInfrastructure" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/Connectivity" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/CrashRecovery" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/DeviceLock" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/HealthFitness" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/IPsec" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/Media" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/MediaProvider" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/OnDevicePersonalization" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/Permission" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/Profiling" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/RemoteKeyProvisioning" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/Scheduling" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/SdkExtensions" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/StatsD" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/Uwb" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/WebViewBootstrap" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/Wifi" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/art" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/module_sdk/conscrypt" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/ndk" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/qemu-kernel" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/r8" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/remoteexecution-client" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/runtime" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/rust" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/sdk" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/tools" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/vndk/v29" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/vndk/v30" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/vndk/v31" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/vndk/v32" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/vndk/v33" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../prebuilts/vndk/v34" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/app_compat/csuite" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/catbox" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/cts-root" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/dittosuite" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/framework" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/mlts/benchmark" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/mlts/models" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/mts" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/robolectric-extensions" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/sts" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/suite_harness" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/vts" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/vts-testcase/hal" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/vts-testcase/hal-trace" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/vts-testcase/kernel" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/vts-testcase/nbu" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/vts-testcase/performance" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/vts-testcase/security" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/vts-testcase/vndk" vcs="Git" />
-    <mapping directory="$PROJECT_DIR$/../../../../../test/wvts" vcs="Git" />
-  </component>
-</project>
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/FrameworkFlags/AndroidManifest.xml b/studio-dev/ManagedProvisioningGradleProject/FrameworkFlags/AndroidManifest.xml
deleted file mode 100644
index 568741e5..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/FrameworkFlags/AndroidManifest.xml
+++ /dev/null
@@ -1,2 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<manifest />
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/FrameworkFlags/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/FrameworkFlags/build.gradle.kts
deleted file mode 100644
index 87e4ef67..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/FrameworkFlags/build.gradle.kts
+++ /dev/null
@@ -1,33 +0,0 @@
-plugins {
-    id("aconfig")
-    id(libs.plugins.android.library.get().pluginId)
-}
-
-val androidTop = extra["ANDROID_TOP"].toString()
-val moduleDir = "$androidTop/frameworks/base/core"
-
-aconfig {
-    aconfigDeclaration {
-        packageName.set("android.widget.flags")
-        srcFile.setFrom(fileTree("$moduleDir/java/android/widget/flags") {
-            include("*.aconfig")
-        })
-    }
-    aconfigDeclaration {
-        packageName.set("android.os")
-        srcFile.setFrom("$moduleDir/java/android/os/flags.aconfig")
-    }
-    aconfigDeclaration {
-        packageName.set("android.app.admin.flags")
-        srcFile.setFrom("$moduleDir/java/android/app/admin/flags/flags.aconfig")
-    }
-}
-
-android {
-    namespace = "android.frameworks.base"
-    sourceSets {
-        named("main") {
-            manifest.srcFile("AndroidManifest.xml")
-        }
-    }
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/ManagedProvisioning/.gitignore b/studio-dev/ManagedProvisioningGradleProject/ManagedProvisioning/.gitignore
deleted file mode 100644
index 3cb39ef6..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/ManagedProvisioning/.gitignore
+++ /dev/null
@@ -1 +0,0 @@
-native_libs
diff --git a/studio-dev/ManagedProvisioningGradleProject/ManagedProvisioning/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/ManagedProvisioning/build.gradle.kts
deleted file mode 100644
index 5f317cb2..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/ManagedProvisioning/build.gradle.kts
+++ /dev/null
@@ -1,219 +0,0 @@
-import com.android.build.api.artifact.SingleArtifact
-import com.google.protobuf.gradle.proto
-import java.util.Locale
-
-plugins {
-    id("aconfig")
-    id(libs.plugins.android.application.get().pluginId)
-    id(libs.plugins.protobuf.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-    id(libs.plugins.hilt.get().pluginId)
-}
-apply<ResourceFixerPlugin>()
-
-val androidTop = extra["ANDROID_TOP"].toString()
-val moduleDir = extra["MANAGED_PROVISIONING_DIR"].toString()
-val googleTruthVersion = extra["google_truth_version"].toString()
-val robolibBuildDir = project(":RobolectricLib").buildDir.toString()
-
-aconfig {
-    aconfigDeclaration {
-        packageName.set("com.android.managedprovisioning.flags")
-        containerName.set("system")
-        srcFile.setFrom(fileTree("$moduleDir/aconfig").matching {
-            include("*.aconfig")
-        })
-    }
-}
-
-hilt {
-    enableAggregatingTask = false
-}
-
-android {
-    namespace = "com.android.managedprovisioning"
-    testNamespace = "com.android.managedprovisioning.tests"
-    defaultConfig {
-        // TODO: Remove this once b/78467428 is resolved
-        vectorDrawables.useSupportLibrary = true
-        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
-        testApplicationId = "com.android.managedprovisioning.tests"
-
-        versionCode = 1000000
-        versionName = "BuildFromAndroidStudio"
-        applicationId = "com.android.managedprovisioning"
-    }
-    signingConfigs {
-        getByName("debug") {
-            storeFile = file("$androidTop/vendor/google/certs/devkeys/platform.keystore")
-        }
-    }
-    buildTypes {
-        release {
-            proguardFiles("$moduleDir/proguard.flags")
-        }
-    }
-
-    sourceSets {
-        named("main") {
-            manifest.srcFile("$moduleDir/AndroidManifest.xml")
-            res {
-                srcDir("$moduleDir/res")
-            }
-            proto {
-                srcDir("$moduleDir/proto")
-            }
-            aidl {
-                srcDir("$moduleDir/src")
-            }
-            java {
-                srcDir("$moduleDir/src")
-            }
-        }
-
-        named("androidTest") {
-            java {
-                srcDir("$moduleDir/tests/instrumentation/src")
-            }
-            manifest {
-                srcFile("$moduleDir/tests/instrumentation/AndroidManifest.xml")
-            }
-            res {
-                srcDir("$moduleDir/tests/instrumentation/res")
-            }
-        }
-
-        named("test") {
-            java {
-                srcDir("$moduleDir/tests/robotests/src")
-                resources {
-                    srcDir("$moduleDir/tests/robotests/config/")
-                }
-            }
-            manifest {
-                srcFile("$moduleDir/tests/instrumentation/AndroidManifest-base.xml")
-            }
-            res {
-                srcDir("$moduleDir/tests/tests/instrumentation/res")
-            }
-        }
-    }
-
-    // Do not generate META-INF
-    packagingOptions.jniLibs.excludes.add("META-INF/*")
-    packagingOptions.resources.excludes.add("META-INF/*")
-    packagingOptions.resources.excludes.add("protobuf.meta")
-
-    buildFeatures {
-        aidl = true
-    }
-    testOptions {
-        unitTests {
-            isIncludeAndroidResources = true
-        }
-    }
-}
-
-androidComponents {
-    // Disable the "release" buildType for ManagedProvisioning
-    beforeVariants(selector().all()) {
-        it.enable = it.buildType != "release"
-    }
-
-    onVariants { variant ->
-        // Capitalized variant name, e.g. debugGoogle -> DebugGoogle
-        val variantName = variant.name.replaceFirstChar {
-            if (it.isLowerCase()) it.titlecase(Locale.getDefault()) else it.toString()
-        }
-        project.tasks.register<PushApkTask>("pushManagedProvisioning${variantName}Apk") {
-            workingDir = rootDir
-            apkFolder.set(variant.artifacts.get(SingleArtifact.APK))
-            builtArtifactsLoader.set(variant.artifacts.getBuiltArtifactsLoader())
-        }
-    }
-}
-
-kapt {
-    correctErrorTypes = true
-}
-
-dependencies {
-    implementation(libs.protobuf.javalite)
-    kapt("com.google.auto.value:auto-value:1.7.4")
-    compileOnly("com.google.auto.value:auto-value-annotations:1.7.4")
-
-    // Common dependencies
-    api("androidx.annotation:annotation")
-    api(libs.androidx.legacy.support.v4)
-    api("androidx.webkit:webkit")
-    api(libs.javax.inject)
-
-    api(project(":FrameworkFlags"))
-    api(project(":android_onboarding.contracts.provisioning"))
-    api(project(":android_onboarding.contracts.annotations"))
-    api(project(":android_onboarding.contracts.setupwizard"))
-    api(project(":android_onboarding.flags_hilt"))
-    api(project(":setupdesign"))
-    api(project(":setupdesign"))
-    api(project(":setupdesign-lottie-loading-layout"))
-
-    // Dagger
-    api(libs.dagger)
-    api(libs.dagger.android)
-    kapt(libs.dagger.compiler)
-    kapt(libs.dagger.android.processor)
-
-    api(libs.hilt.android)
-    kapt(libs.hilt.android.compiler)
-
-    kaptTest(libs.dagger.compiler)
-    kaptTest(libs.dagger.android.processor)
-    kaptTest(libs.hilt.android.compiler)
-
-    kaptAndroidTest(libs.dagger.compiler)
-    kaptAndroidTest(libs.dagger.android.processor)
-    kaptAndroidTest(libs.hilt.android.compiler)
-
-    api(libs.guava)
-    api(libs.com.airbnb.android.lottie)
-
-    testImplementation(project(":RobolectricLib"))
-    // this is compile only, to work around the incomplete MockSDK provided to SysUIStudio
-    // from it's ./studiow script.  Robolectric will provide this jar at runtime via
-    // It's SdkProvider and will also apply shadow logic at that time.
-    testImplementation(fileTree("${robolibBuildDir}/android_all/") {
-        include("*.jar")
-    })
-    testImplementation(libs.androidx.test.rules)
-    testImplementation(libs.testng)
-    testImplementation(libs.hilt.android.testing)
-    testImplementation(project(":android_onboarding.contracts.testing"))
-    testImplementation("androidx.test.ext:junit")
-    // testImplementation("androidx.compose.ui:ui")
-    testImplementation("androidx.test:core:1.5.0")
-    testImplementation("androidx.test.ext:truth")
-    // testImplementation("androidx.core:core-animation-testing")
-    testImplementation(libs.truth)
-    testImplementation(libs.google.truth)
-    testImplementation("org.mockito:mockito-core:2.28.1")
-    // //this needs to be modern to support JDK-17 + asm byte code.
-    testImplementation("org.mockito:mockito-inline:4.11.0")
-    testImplementation(libs.junit)
-}
-
-protobuf {
-    // Configure the protoc executable
-    protoc {
-        artifact = "${libs.protobuf.protoc.get()}"
-    }
-    generateProtoTasks {
-        all().configureEach {
-            builtins {
-                register("java") {
-                    option("lite")
-                }
-            }
-        }
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/ManagedProvisioning/empty-manifest.xml b/studio-dev/ManagedProvisioningGradleProject/ManagedProvisioning/empty-manifest.xml
deleted file mode 100644
index 8072ee00..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/ManagedProvisioning/empty-manifest.xml
+++ /dev/null
@@ -1,2 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<manifest />
diff --git a/studio-dev/ManagedProvisioningGradleProject/ModuleUtils/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/ModuleUtils/build.gradle.kts
deleted file mode 100644
index 9ba6b58d..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/ModuleUtils/build.gradle.kts
+++ /dev/null
@@ -1,26 +0,0 @@
-plugins {
-    id("com.android.library")
-    id("org.jetbrains.kotlin.android")
-}
-val androidTop = extra["ANDROID_TOP"].toString()
-android {
-    namespace = "com.android.internal.modules.utils"
-
-    sourceSets.getByName("main") {
-        java.setSrcDirs(listOf(
-                "$androidTop/frameworks/libs/modules-utils/java",
-        ))
-        java.exclude(
-                "android/annotations/**",
-                "com/android/internal/**",
-                "com/android/modules/**",
-        )
-        manifest.srcFile("empty-manifest.xml")
-    }
-    kotlinOptions {
-        jvmTarget = "17"
-    }
-}
-dependencies {
-    implementation("androidx.core:core-ktx:+")
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/ModuleUtils/empty-manifest.xml b/studio-dev/ManagedProvisioningGradleProject/ModuleUtils/empty-manifest.xml
deleted file mode 100644
index 8072ee00..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/ModuleUtils/empty-manifest.xml
+++ /dev/null
@@ -1,2 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<manifest />
diff --git a/studio-dev/ManagedProvisioningGradleProject/RobolectricLib/build.gradle b/studio-dev/ManagedProvisioningGradleProject/RobolectricLib/build.gradle
deleted file mode 100644
index bc853d96..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/RobolectricLib/build.gradle
+++ /dev/null
@@ -1,81 +0,0 @@
-plugins {
-    id 'java-library'
-}
-apply plugin: AarDepsPlugin
-
-final String GIT_BRANCH = ""
-final int BUILD_ID = -1
-
-java {
-    sourceCompatibility = JavaVersion.VERSION_17
-    targetCompatibility = JavaVersion.VERSION_17
-}
-
-sourceSets {
-  main {
-    java.srcDirs = [
-            "src",
-            "${ANDROID_TOP}/external/robolectric/utils/src/main/java/",
-            "${ANDROID_TOP}/external/robolectric/resources/src/main/java/",
-            "${ANDROID_TOP}/external/robolectric/nativeruntime/src/main/java/",
-            "${ANDROID_TOP}/external/robolectric/sandbox/src/main/java/",
-            "${ANDROID_TOP}/external/robolectric/robolectric/src/main/java/",
-            //shadow jar code
-            "${ANDROID_TOP}/external/robolectric/shadows/framework/src/main/java/",
-            //android specific robolectric extensions
-            "${ANDROID_TOP}/test/robolectric-extensions/plugins/src/main/java/"
-    ]
-    resources.srcDirs = [
-            "${ANDROID_TOP}/test/robolectric-extensions/resources/",
-            "${ANDROID_TOP}/prebuilts/misc/common/robolectric-native-prebuilt/resources/"
-      ]
-  }
-}
-
-task generateBuildConfig {
-    ext.outputDir = "$buildDir/generated/java"
-    inputs.property('version', project.version)
-    outputs.dir outputDir
-    doLast {
-        mkdir "$outputDir/com/google/android/sysui"
-        file("$outputDir/com/google/android/sysui/BuildConfig.java").text =
-                """|package com.google.android.sysui;
-               |class BuildConfig {
-               |    public static final String OUT_PATH = "$buildDir";
-               |}""".stripMargin()
-    }
-}
-
-task downloadAndroidAll(type: RoboJarFetcherTask) {
-    rootPath = ANDROID_TOP
-    outPath = buildDir
-    suggestedGitBranch = GIT_BRANCH
-    buildId = BUILD_ID
-}
-
-compileJava {
-    options.compilerArgs << '-Aorg.robolectric.annotation.processing.shadowPackage=org.robolectric'
-    dependsOn generateBuildConfig
-    dependsOn downloadAndroidAll
-}
-sourceSets.main.java.srcDir generateBuildConfig.outputDir
-
-dependencies {
-    api libs.robolectric
-    // Dependencies for shadow jar code:
-    api 'androidx.annotation:annotation-jvm:1.6.0@jar'
-    annotationProcessor 'com.google.auto.service:auto-service:1.0.1'
-    compileOnly 'com.google.auto.service:auto-service-annotations:1.0.1'
-    // Robolectic specific configurations for code generation (of shadow jar code)
-    annotationProcessor 'org.robolectric:processor:4.11-SNAPSHOT'
-    annotationProcessor 'com.google.auto.service:auto-service:1.0.1'
-    implementation 'com.google.auto.service:auto-service-annotations:1.0.1'
-    implementation 'junit:junit:4.13.2'
-    implementation 'org.conscrypt:conscrypt-openjdk-uber:2.5.2'
-    api 'androidx.test.espresso:espresso-core:3.6.0-alpha1@aar'
-    api 'androidx.test.espresso:espresso-idling-resource:3.6.0-alpha1@aar'
-
-
-    // Android-all jar
-    implementation fileTree(dir: "${buildDir}/android_all/", include: '*.jar')
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/RobolectricLib/src/com/google/android/sysui/ToTSdkProvider.java b/studio-dev/ManagedProvisioningGradleProject/RobolectricLib/src/com/google/android/sysui/ToTSdkProvider.java
deleted file mode 100644
index 71eeac57..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/RobolectricLib/src/com/google/android/sysui/ToTSdkProvider.java
+++ /dev/null
@@ -1,42 +0,0 @@
-package com.google.android.sysui;
-
-import com.google.auto.service.AutoService;
-
-import org.robolectric.android.plugins.AndroidLocalSdkProvider;
-import org.robolectric.internal.dependency.DependencyResolver;
-import org.robolectric.pluginapi.SdkProvider;
-import org.robolectric.util.inject.Supercedes;
-
-import java.io.File;
-import java.nio.file.Path;
-
-import javax.annotation.Priority;
-import javax.inject.Inject;
-
-/**
- * SDK provider to latest system image from build server.
- */
-@AutoService(SdkProvider.class)
-@Priority(10)
-@Supercedes(AndroidLocalSdkProvider.class)
-public class ToTSdkProvider extends AndroidLocalSdkProvider {
-
-    @Inject
-    public ToTSdkProvider(DependencyResolver dependencyResolver) {
-        super(dependencyResolver);
-    }
-
-    @Override
-    protected Path findTargetJar() {
-        File jarDir = new File(BuildConfig.OUT_PATH, "android_all");
-        for (File f : jarDir.listFiles()) {
-            if (f.isFile()) {
-                String name = f.getName();
-                if (name.startsWith("android-all") && name.endsWith(".jar")) {
-                    return f.toPath();
-                }
-            }
-        }
-        return null;
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.contract_eligibility_checker/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.contract_eligibility_checker/build.gradle.kts
deleted file mode 100644
index d7152d41..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.contract_eligibility_checker/build.gradle.kts
+++ /dev/null
@@ -1,39 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-    "$top/external/android_onboarding/src/com/android/onboarding/bedsteadonboarding/contractutils"
-
-android {
-    namespace = "com.android.onboarding.bedsteadonboarding.contractutils"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir) {
-                include("ContractExecutionEligibilityChecker.kt")
-            }))
-        }
-    }
-}
-
-dependencies {
-    api(project(":android_onboarding.bedsteadonboarding.providers"))
-    api(project(":android_onboarding.bedsteadonboarding.contractutils"))
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.contractutils/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.contractutils/build.gradle.kts
deleted file mode 100644
index f65359c5..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.contractutils/build.gradle.kts
+++ /dev/null
@@ -1,39 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/bedsteadonboarding/contractutils"
-
-android {
-    namespace = "com.android.onboarding.bedsteadonboarding.contractutils"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir) {
-                include("ContractUtils.kt")
-            }))
-        }
-    }
-}
-
-dependencies {
-    api(project(":android_onboarding.nodes"))
-    api(project(":android_onboarding.contracts.annotations"))
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.data/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.data/build.gradle.kts
deleted file mode 100644
index ae3fe98e..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.data/build.gradle.kts
+++ /dev/null
@@ -1,36 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/bedsteadonboarding/data"
-
-android {
-    namespace = "com.android.onboarding.bedsteadonboarding.data"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir)))
-        }
-    }
-}
-
-dependencies {
-    api(project(":android_onboarding.contracts.annotations"))
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.permissions/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.permissions/build.gradle.kts
deleted file mode 100644
index 01bf51ae..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.permissions/build.gradle.kts
+++ /dev/null
@@ -1,35 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/bedsteadonboarding/permissions"
-
-android {
-    namespace = "com.android.onboarding.bedsteadonboarding.permissions"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir)))
-        }
-    }
-}
-
-dependencies {
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.providers/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.providers/build.gradle.kts
deleted file mode 100644
index b95ae305..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.bedsteadonboarding.providers/build.gradle.kts
+++ /dev/null
@@ -1,37 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/bedsteadonboarding/providers"
-
-android {
-    namespace = "com.android.onboarding.bedsteadonboarding.providers"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir)))
-        }
-    }
-}
-
-dependencies {
-    api(project(":android_onboarding.bedsteadonboarding.permissions"))
-    api(project(":android_onboarding.bedsteadonboarding.data"))
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.common.annotations/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.common.annotations/build.gradle.kts
deleted file mode 100644
index 5519d5c8..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.common.annotations/build.gradle.kts
+++ /dev/null
@@ -1,35 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/common/annotations"
-
-android {
-    namespace = "com.android.onboarding.common.annotations"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir)))
-        }
-    }
-}
-
-dependencies {
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.common/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.common/build.gradle.kts
deleted file mode 100644
index e9878046..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.common/build.gradle.kts
+++ /dev/null
@@ -1,43 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/common"
-
-android {
-    namespace = "com.android.onboarding.common"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir)))
-        }
-    }
-}
-
-dependencies {
-    api(libs.dagger)
-    api(libs.dagger.android)
-    kapt(libs.dagger.compiler)
-    kapt(libs.dagger.android.processor)
-
-    api(libs.javax.inject)
-    api(libs.androidx.annotation)
-    api(project(":android_onboarding.common.annotations"))
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.annotations/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.annotations/build.gradle.kts
deleted file mode 100644
index 1e8a5811..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.annotations/build.gradle.kts
+++ /dev/null
@@ -1,36 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/contracts/annotations"
-
-android {
-    namespace = "com.android.onboarding.contracts.annotations"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir)))
-        }
-    }
-}
-
-dependencies {
-    api(libs.androidx.annotation)
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.provisioning/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.provisioning/build.gradle.kts
deleted file mode 100644
index 8b092ab9..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.provisioning/build.gradle.kts
+++ /dev/null
@@ -1,42 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/contracts/provisioning"
-
-android {
-    namespace = "com.android.onboarding.contracts.provisioning"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir)))
-        }
-    }
-}
-
-dependencies {
-    api(project(":android_onboarding.common"))
-    api(project(":android_onboarding.contracts"))
-    api(project(":android_onboarding.contracts.setupwizard"))
-    api(project(":android_onboarding.contracts.annotations"))
-    api(project(":setupcompat"))
-    api(libs.androidx.annotation)
-    api(libs.javax.inject)
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.setupwizard/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.setupwizard/build.gradle.kts
deleted file mode 100644
index a6140926..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.setupwizard/build.gradle.kts
+++ /dev/null
@@ -1,39 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/contracts/setupwizard"
-
-android {
-    namespace = "com.android.onboarding.contracts.setupwizard"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir)))
-        }
-    }
-}
-
-dependencies {
-    api(project(":android_onboarding.common"))
-    api(project(":android_onboarding.contracts"))
-    api(project(":setupcompat"))
-    api(libs.javax.inject)
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.testing/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.testing/build.gradle.kts
deleted file mode 100644
index 2d619db6..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts.testing/build.gradle.kts
+++ /dev/null
@@ -1,57 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/contracts/testing"
-val robolibBuildDir = project(":RobolectricLib").buildDir.toString()
-
-android {
-    namespace = "com.android.onboarding.contracts.testing"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            manifest.srcFile("$moduleDir/AndroidManifest.xml")
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir) {
-                // Excluded until g3 finishes appcompat migration
-                exclude("TestAppCompatActivity.kt")
-            }))
-        }
-    }
-}
-
-dependencies {
-    api(libs.androidx.annotation)
-    api(project(":android_onboarding.contracts"))
-    api(libs.androidx.test.core)
-    api(libs.androidx.activity.ktx)
-    api(libs.androidx.fragment.ktx)
-    api(libs.androidx.appcompat)
-    api(libs.apache.commons.lang3)
-    api(kotlin("reflect"))
-
-    api(project(":RobolectricLib"))
-    // this is compile only, to work around the incomplete MockSDK provided to SysUIStudio
-    // from it's ./studiow script.  Robolectric will provide this jar at runtime via
-    // It's SdkProvider and will also apply shadow logic at that time.
-    api(fileTree("${robolibBuildDir}/android_all/") {
-        include("*.jar")
-    })
-    api(libs.truth)
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts/build.gradle.kts
deleted file mode 100644
index f02f96b2..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.contracts/build.gradle.kts
+++ /dev/null
@@ -1,42 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/contracts"
-
-android {
-    namespace = "com.android.onboarding.contracts"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-            proguardFiles(getDefaultProguardFile("proguard-android.txt"), "$moduleDir/proguard.pgcfg")
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir)))
-        }
-    }
-}
-
-dependencies {
-    api("androidx.activity:activity-ktx")
-    api(project(":android_onboarding.bedsteadonboarding.contract_eligibility_checker"))
-    api(project(":android_onboarding.contracts.annotations"))
-    api(project(":android_onboarding.nodes"))
-    api(libs.errorprone.annotations)
-    api(libs.javax.inject)
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.flags/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.flags/build.gradle.kts
deleted file mode 100644
index e24d4ac8..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.flags/build.gradle.kts
+++ /dev/null
@@ -1,40 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/flags"
-
-android {
-    namespace = "com.android.onboarding.flags"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        named("main") {
-            java.srcDirs(listOf("src"), symlinkedSources(moduleDir) {
-                include(
-                        "DefaultOnboardingFlagsProvider.kt",
-                        "OnboardingFlagsProvider.kt",
-                )
-            })
-        }
-    }
-}
-
-dependencies {
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.flags_hilt/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.flags_hilt/build.gradle.kts
deleted file mode 100644
index c11d3391..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.flags_hilt/build.gradle.kts
+++ /dev/null
@@ -1,45 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-    id(libs.plugins.hilt.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir = "$top/external/android_onboarding/src/com/android/onboarding/flags"
-
-android {
-    namespace = "com.android.onboarding.flags"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        named("main") {
-            java.srcDirs("src", symlinkedSources(moduleDir) {
-                include("OnboardingFlagsHiltModule.kt")
-            })
-        }
-    }
-}
-
-dependencies {
-    api(project(":android_onboarding.flags"))
-    api(libs.dagger)
-    api(libs.dagger.android)
-    kapt(libs.dagger.compiler)
-    kapt(libs.dagger.android.processor)
-
-    api(libs.hilt.android)
-    kapt(libs.hilt.android.compiler)
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.nodes/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/android_onboarding.nodes/build.gradle.kts
deleted file mode 100644
index 53bb05f1..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/android_onboarding.nodes/build.gradle.kts
+++ /dev/null
@@ -1,62 +0,0 @@
-import com.google.protobuf.gradle.proto
-
-/**
- * This is an adaptation of the build.gradle found in external/android_onboarding.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id(libs.plugins.android.library.get().pluginId)
-    id(libs.plugins.kotlin.android.get().pluginId)
-    id(libs.plugins.kotlin.kapt.get().pluginId)
-    id(libs.plugins.protobuf.get().pluginId)
-}
-
-val top = extra["ANDROID_TOP"].toString()
-val moduleDir =
-        "$top/external/android_onboarding/src/com/android/onboarding/nodes"
-
-android {
-    namespace = "com.android.onboarding.nodes"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-        }
-    }
-
-    sourceSets {
-        named("main") {
-            java.srcDirs(listOf("src", symlinkedSources(moduleDir)))
-            proto {
-                setSrcDirs(listOf(moduleDir))
-            }
-        }
-    }
-}
-
-dependencies {
-    implementation(libs.protobuf.javalite)
-    api("androidx.activity:activity-ktx")
-    api(libs.guava)
-    api(project(":android_onboarding.contracts.annotations"))
-    api(project(":android_onboarding.flags"))
-}
-
-protobuf {
-    // Configure the protoc executable
-    protoc {
-        artifact = "${libs.protobuf.protoc.get()}"
-    }
-    generateProtoTasks {
-        all().configureEach {
-            builtins {
-                register("java") {
-                    option("lite")
-                }
-            }
-        }
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/build.gradle b/studio-dev/ManagedProvisioningGradleProject/build.gradle
deleted file mode 100644
index aa726fac..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/build.gradle
+++ /dev/null
@@ -1,149 +0,0 @@
-import kotlin.Triple
-import org.apache.tools.ant.taskdefs.condition.Os
-
-plugins {
-    id("org.jetbrains.gradle.plugin.idea-ext") version "1.1.7"
-}
-
-final boolean IS_ARM_MAC = Os.isFamily(Os.FAMILY_MAC) &&
-        System.getProperty("os.arch") == "aarch64"
-
-allprojects {
-    ext {
-        ANDROID_TOP = "${new File("${rootDir}", ANDROID_RELATIVE_TOP).canonicalPath}"
-        SYS_UI_DIR = "${ANDROID_TOP}/frameworks/base/packages/SystemUI"
-        SETTINGS_DIR = "${ANDROID_TOP}/frameworks/base/packages/SettingsLib"
-        GOOGLE_SYS_UI_DIR = "${ANDROID_TOP}/vendor/unbundled_google/packages/SystemUIGoogle/"
-        MANAGED_PROVISIONING_DIR = "${ANDROID_TOP}/packages/apps/ManagedProvisioning/"
-        // We need to explicitly request x86_64 binaries on M1 Macs since protoc compiler
-        // for ARM doesn't exist for current protobuf version.
-        PROTO_ARCH_SUFFIX = IS_ARM_MAC ? ":osx-x86_64" : ""
-
-        // Whether we should compile SystemUI with Compose enabled or not.
-        USE_COMPOSE = true
-    }
-}
-
-final String GRADLE_BUILD_ROOT = "${ANDROID_TOP}/out/gradle/build"
-buildDir = "${GRADLE_BUILD_ROOT}/${rootProject.name}/build"
-
-gradle.beforeProject {
-    rootProject.subprojects {
-        buildDir = "${GRADLE_BUILD_ROOT}/${rootProject.name}/${project.name}/build"
-    }
-}
-
-tasks.register('updateSdkSources', SdkSourceUpdaterTask) {
-    androidRoot = new File("${ANDROID_TOP}")
-}
-
-idea {
-    project {
-        settings {
-            taskTriggers {
-                afterSync tasks.named("updateSdkSources")
-            }
-        }
-    }
-}
-
-final Map<String, Triple> LIB_VERSION_MAP = new RepoDependencyMapper()
-        .mapPath("${ANDROID_TOP}/prebuilts/sdk/current/androidx/m2repository")
-        .mapPath("${ANDROID_TOP}/prebuilts/sdk/current/androidx-legacy/m2repository")
-        .mapPath("${ANDROID_TOP}/prebuilts/sdk/current/extras/material-design-x")
-        .mapPath("${ANDROID_TOP}/prebuilts/misc/common/androidx-test")
-        .getMap()
-
-allprojects {
-    configurations.configureEach {
-        resolutionStrategy.eachDependency { DependencyResolveDetails details ->
-            // Override any transitive dependency to also use the local version
-            Triple targetOverride = LIB_VERSION_MAP.get(details.requested.module.toString())
-            if (targetOverride != null) {
-                if (targetOverride.second != null) {
-                    details.useTarget group: targetOverride.first, name: targetOverride.second, version: targetOverride.third
-                } else {
-                    details.useVersion(targetOverride.third)
-                }
-            }
-        }
-    }
-}
-
-Properties properties = new Properties()
-properties.load(project.rootProject.file('studiow.properties').newDataInputStream())
-// String like UdcDevForTree456b
-rootProject.ext.set("compileSdkPreviewString", properties.getProperty('compile.sdk.preview'))
-// String like android-UdcDevForTree456b
-rootProject.ext.set("compileSdkVersionString", properties.getProperty('compile.sdk.version'))
-
-// Check env var to see if the gradle script was launched using the studiow script. Launching
-// Android Studio and then opening the Gradle project afterwards IS UNSUPPORTED. Android Studio
-// needs to be lunched using studiow so that it can validate settings and update the build
-// environment.
-if (System.getenv('STUDIO_LAUNCHED_WITH_WRAPPER') == null) {
-    throw new Exception("Android Studio for SystemUI must be launched using " +
-            "the studiow script found in \$ANDROID_BUILD_TOP/" +
-            "vendor/unbundled_google/packages/SystemUIGoogle/studio-dev/studiow.")
-}
-
-subprojects {
-    afterEvaluate { project ->
-        if (project.hasProperty("android")) {
-            android {
-                // Settings compileSdkVersion also sets compileSdkPreview. No need to set both
-                compileSdkVersion(compileSdkVersionString)
-                buildToolsVersion BUILD_TOOLS_VERSION
-                defaultConfig {
-                    minSdkPreview TARGET_SDK
-                }
-                compileOptions {
-                    sourceCompatibility JavaVersion.VERSION_17
-                    targetCompatibility JavaVersion.VERSION_17
-                }
-
-                if (android.hasProperty("kotlinOptions")) {
-                    kotlinOptions {
-                        jvmTarget = "17"
-                        freeCompilerArgs = ["-Xjvm-default=all"]
-                    }
-                }
-
-                // Disable abortOnError everywhere. Otherwise, the :build task will fail for 100%
-                // of our projects
-                lint {
-                    abortOnError false
-                }
-            }
-        }
-
-        /**
-         * TODO(b/269759002): Replace this workaround with DSL like "disableCompileSdk" if available
-         * AndroidX uses the same workaround in their internal build by setting androidx.useMaxDepVersions
-         *
-         * Workaround to fix the following error:
-         *
-         * 3 issues were found when checking AAR metadata:
-         *
-         *   1.  Dependency 'androidx.window:window:1.1.0-alpha06' requires libraries and applications that
-         *       depend on it to compile against codename "UpsideDownCake" of the
-         *       Android APIs.
-         *
-         *       :ComposeGallery is currently compiled against android-UpsideDownCakeForSysUiStudioRev456b2dc4.
-         *
-         *       Recommended action: Use a different version of dependency 'androidx.window:window:1.1.0-alpha06',
-         *       or set compileSdkPreview to "UpsideDownCake" in your build.gradle
-         *       file if you intend to experiment with that preview SDK.
-         */
-//        tasks.withType(CheckAarMetadataTask).configureEach({ task ->
-//            task.enabled = false
-//        })
-    }
-}
-
-tasks.named('wrapper') {
-    // Delete gradlew.bat because Windows builds are not supported
-    doLast {
-        delete "${projectDir}/gradlew.bat"
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/.gradle b/studio-dev/ManagedProvisioningGradleProject/buildSrc/.gradle
deleted file mode 120000
index 182e99df..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/.gradle
+++ /dev/null
@@ -1 +0,0 @@
-../../../../../../out/gradle/build/buildSrc/.gradle
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/build b/studio-dev/ManagedProvisioningGradleProject/buildSrc/build
deleted file mode 120000
index 5d04cc05..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/build
+++ /dev/null
@@ -1 +0,0 @@
-../../../../../../out/gradle/build/buildSrc/build
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/buildSrc/build.gradle.kts
deleted file mode 100644
index 08e051d8..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/build.gradle.kts
+++ /dev/null
@@ -1,32 +0,0 @@
-plugins {
-  `java-gradle-plugin`
-  `kotlin-dsl`
-  `groovy-gradle-plugin`
-}
-
-val androidTop = "$rootDir/../../../../../../"
-
-// Due to a gradle bug, we also need to have a symlink to build, which is why
-// SystemUIGoogle/studio-dev/SysUIGradleProject/buildSrc/build points to
-// ../../../../../../../out/gradle/build/buildSrc/build.
-// The symlink dest dir is created in studiow. See: https://github.com/gradle/gradle/issues/13847
-buildDir = file("$androidTop/out/gradle/build/buildSrc/build")
-
-val libDir = "${androidTop}/vendor/unbundled_google/libraries/androidbuildinternal"
-
-dependencies {
-  implementation(localGroovy())
-  implementation(libs.scriptClasspath.android)
-  implementation(libs.scriptClasspath.kotlin)
-  implementation(libs.scriptClasspath.errorprone)
-  implementation(libs.scriptClasspath.nullaway)
-  implementation(libs.scriptClasspath.protobuf)
-  implementation(libs.scriptClasspath.hilt)
-  implementation(libs.guava)
-
-  // dependencies for jar fetcher
-  implementation("com.google.api-client:google-api-client:1.33.0")
-  implementation("org.apache.commons:commons-compress:1.21")
-  implementation("com.google.oauth-client:google-oauth-client-jetty:1.33.0")
-  implementation(fileTree(libDir) { include("libandroid_build_v3_java.jar") })
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/settings.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/buildSrc/settings.gradle.kts
deleted file mode 100644
index 7ea2879e..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/settings.gradle.kts
+++ /dev/null
@@ -1,20 +0,0 @@
-pluginManagement {
-    repositories {
-        gradlePluginPortal()
-    }
-}
-
-dependencyResolutionManagement {
-    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
-    rulesMode.set(RulesMode.FAIL_ON_PROJECT_RULES)
-    repositories {
-        google()
-        gradlePluginPortal()
-    }
-
-    versionCatalogs {
-        create("libs") {
-            from(files("../gradle/libs.versions.toml"))
-        }
-    }
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/AarDepsPlugins.groovy b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/AarDepsPlugins.groovy
deleted file mode 100644
index ab1c0b81..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/AarDepsPlugins.groovy
+++ /dev/null
@@ -1,114 +0,0 @@
-import static org.gradle.api.artifacts.type.ArtifactTypeDefinition.ARTIFACT_TYPE_ATTRIBUTE;
-
-import com.android.build.gradle.internal.dependency.ExtractAarTransform;
-import com.google.common.base.Joiner;
-import java.io.File;
-import java.util.ArrayList;
-import java.util.List;
-import java.util.concurrent.atomic.AtomicReference;
-import javax.inject.Inject;
-import org.gradle.api.Action;
-import org.gradle.api.Plugin;
-import org.gradle.api.Project;
-import org.gradle.api.Task;
-import org.gradle.api.artifacts.transform.TransformOutputs;
-import org.gradle.api.file.FileCollection;
-import org.gradle.api.tasks.compile.JavaCompile;
-import org.jetbrains.annotations.NotNull;
-
-/**
- * Resolve aar dependencies into jars for non-Android projects.
- */
-public class AarDepsPlugin implements Plugin<Project> {
-  @Override
-  public void apply(Project project) {
-    project
-        .getDependencies()
-        .registerTransform(
-            ClassesJarExtractor.class,
-            reg -> {
-              reg.getParameters().getProjectName().set(project.getName());
-              reg.getFrom().attribute(ARTIFACT_TYPE_ATTRIBUTE, "aar");
-              reg.getTo().attribute(ARTIFACT_TYPE_ATTRIBUTE, "jar");
-            });
-
-    project.afterEvaluate(
-        p ->
-            project
-                .getConfigurations()
-                .forEach(
-                    c -> {
-                      // I suspect we're meant to use the org.gradle.usage attribute, but this
-                      // works.
-                      if (c.getName().endsWith("Classpath")) {
-                        c.attributes(
-                            cfgAttrs -> cfgAttrs.attribute(ARTIFACT_TYPE_ATTRIBUTE, "jar"));
-                      }
-                    }));
-
-    // warn if any AARs do make it through somehow; there must be a gradle configuration
-    // that isn't matched above.
-    //noinspection Convert2Lambda
-    project
-        .getTasks()
-        .withType(JavaCompile.class)
-        .all(
-            // the following Action<Task needs to remain an anonymous subclass or gradle's
-            // incremental compile breaks (run `gradlew -i classes` twice to see impact):
-            t -> t.doFirst(new Action<Task>() {
-              @Override
-              public void execute(Task task) {
-                List<File> aarFiles = AarDepsPlugin.this.findAarFiles(t.getClasspath());
-                if (!aarFiles.isEmpty()) {
-                  throw new IllegalStateException(
-                      "AARs on classpath: " + Joiner.on("\n  ").join(aarFiles));
-                }
-              }
-            }));
-  }
-
-  private List<File> findAarFiles(FileCollection files) {
-    List<File> bad = new ArrayList<>();
-    for (File file : files.getFiles()) {
-      if (file.getName().toLowerCase().endsWith(".aar")) {
-        bad.add(file);
-      }
-    }
-    return bad;
-  }
-
-  public static abstract class ClassesJarExtractor extends ExtractAarTransform {
-    @Inject
-    public ClassesJarExtractor() {
-    }
-
-    @Override
-    public void transform(@NotNull TransformOutputs outputs) {
-      AtomicReference<File> classesJarFile = new AtomicReference<>();
-      AtomicReference<File> outJarFile = new AtomicReference<>();
-      super.transform(new TransformOutputs() {
-        // This is the one that ExtractAarTransform calls.
-        @Override
-        public File dir(Object o) {
-          // ExtractAarTransform needs a place to extract the AAR. We don't really need to
-          // register this as an output, but it'd be tricky to avoid it.
-          File dir = outputs.dir(o);
-
-          // Also, register our jar file. Its name needs to be quasi-unique or
-          // IntelliJ Gradle/Android plugins get confused.
-          classesJarFile.set(new File(new File(dir, "jars"), "classes.jar"));
-          outJarFile.set(new File(new File(dir, "jars"), o + ".jar"));
-          outputs.file(o + "/jars/" + o + ".jar");
-          return outputs.dir(o);
-        }
-
-        @Override
-        public File file(Object o) {
-          throw new IllegalStateException("shouldn't be called");
-        }
-      });
-
-      classesJarFile.get().renameTo(outJarFile.get());
-    }
-  }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/ExcludeUtils.groovy b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/ExcludeUtils.groovy
deleted file mode 100644
index ac67d733..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/ExcludeUtils.groovy
+++ /dev/null
@@ -1,47 +0,0 @@
-import org.gradle.api.file.FileTreeElement
-
-import java.util.regex.Pattern
-
-class ExcludeUtils {
-    /**
-     * Returns true if f should be excluded.
-     * f is excluded only if:
-     * - its absolute path contains [pathMustContain] AND
-     * - its path matches one of the regex in [regexToKeep].
-     */
-    static boolean excludeIfNotIn(
-            String pathMustContain,
-            ArrayList<String> regexToKeep,
-            FileTreeElement f) {
-        if (f.isDirectory()) return false
-        def absolutePath = f.file.absolutePath
-
-        if (!absolutePath.contains(pathMustContain)) return false
-
-        // keeping only those in regexToKeep
-        def toRemove = !regexToKeep.any { absolutePath =~ Pattern.compile(it) }
-        // To debug: println("file: ${f.getName()} to remove: ${toRemove}")
-        return toRemove
-    }
-
-    /**
-     * Returns true if f should be excluded.
-     * f is excluded only if:
-     * - its absolute path contains [pathMustContain] AND
-     * - its path matches one of the regex in [regexToExclude].
-     */
-    static boolean excludeIfIn(
-            String pathMustContain,
-            ArrayList<String> regexToExclude,
-            FileTreeElement f) {
-        if (f.isDirectory()) return false
-        def absolutePath = f.file.absolutePath
-
-        if (!absolutePath.contains(pathMustContain)) return false
-
-        // keeping only those in regexToKeep
-        def toRemove = regexToExclude.any { absolutePath =~ Pattern.compile(it) }
-        // To debug: println("file: ${f.getName()} to remove: ${toRemove}")
-        return toRemove
-    }
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/FilterCopyTask.groovy b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/FilterCopyTask.groovy
deleted file mode 100644
index 85f94b76..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/FilterCopyTask.groovy
+++ /dev/null
@@ -1,47 +0,0 @@
-import org.gradle.api.DefaultTask
-import org.gradle.api.file.DirectoryProperty
-import org.gradle.api.provider.ListProperty
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.InputDirectory
-import org.gradle.api.tasks.OutputDirectory
-import org.gradle.api.tasks.TaskAction
-import org.gradle.work.Incremental
-import org.gradle.work.InputChanges
-
-import java.nio.file.Files
-import java.nio.file.StandardCopyOption
-
-/**
- * Filters resources to the given product type.
- */
-abstract class FilterCopyTask extends DefaultTask {
-    @Incremental
-    @InputDirectory
-    abstract DirectoryProperty getInputDir()
-
-    @OutputDirectory
-    abstract DirectoryProperty getOutputDir()
-
-    @Input
-    abstract ListProperty<String> getIncludes()
-
-    @TaskAction
-    void execute(InputChanges inputChanges) {
-        System.out.println("test copy task was called")
-        def inputPath = inputDir.get().asFile
-        inputChanges.getFileChanges(inputDir).each { change ->
-            File changedFile = change.file
-            def relative = inputPath.relativePath(changedFile)
-            File targetFile = outputDir.file(relative).get().asFile
-            if (!changedFile.exists() || ! includes.get().contains(relative)) {
-                targetFile.delete()
-                return
-            }
-            if (includes.get().contains(relative)) {
-                System.out.println("checking file: " + relative)
-                targetFile.parentFile.mkdirs()
-                Files.copy(changedFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
-            }
-        }
-    }
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/FilterResourcesTask.groovy b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/FilterResourcesTask.groovy
deleted file mode 100644
index e8103815..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/FilterResourcesTask.groovy
+++ /dev/null
@@ -1,68 +0,0 @@
-import org.gradle.api.DefaultTask
-import org.gradle.api.file.DirectoryProperty
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.InputDirectory
-import org.gradle.api.tasks.OutputDirectory
-import org.gradle.api.tasks.TaskAction
-import org.gradle.work.Incremental
-import org.gradle.work.InputChanges
-
-import java.nio.file.Files
-import java.nio.file.StandardCopyOption
-import java.util.regex.Pattern
-
-/**
- * Filters resources to the given product type.
- */
-abstract class FilterResourcesTask extends DefaultTask {
-    @Incremental
-    @InputDirectory
-    abstract DirectoryProperty getInputDir()
-
-    @OutputDirectory
-    abstract DirectoryProperty getOutputDir()
-
-    @Input
-    String productType
-
-    @TaskAction
-    void execute(InputChanges inputChanges) {
-        def inputPath = inputDir.get().asFile
-        inputChanges.getFileChanges(inputDir).each { change ->
-
-            File changedFile = change.file;
-
-            def relative = inputPath.relativePath(changedFile)
-            File targetFile = outputDir.file(relative).get().asFile
-            if (!changedFile.exists()) {
-                targetFile.delete()
-                return
-            }
-            targetFile.parentFile.mkdirs()
-
-            if (changedFile.name.endsWith(".xml")) {
-                String match1 = "product="
-                String match2 = match1 + '"' + productType + '"'
-                String match3 = match1 + "'" + productType + "'"
-                Pattern match4 = Pattern.compile(/<\/\w+>/);
-                StringBuilder filteredText = new StringBuilder();
-                boolean bulkDelete = false;
-
-                changedFile.eachLine { line ->
-                    if (bulkDelete) {
-                        bulkDelete = !line.find(match4);
-                    } else if (!line.contains(match1)
-                            || line.contains(match2)
-                            || line.contains(match3)) {
-                        filteredText.append(line).append('\n')
-                    } else {
-                        bulkDelete = !line.find(match4);
-                    }
-                }
-                targetFile.text = filteredText.toString();
-            } else {
-                Files.copy(changedFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
-            }
-        }
-    }
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/ResourceFixerPlugin.groovy b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/ResourceFixerPlugin.groovy
deleted file mode 100644
index 060d64eb..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/ResourceFixerPlugin.groovy
+++ /dev/null
@@ -1,99 +0,0 @@
-import com.android.build.api.variant.AndroidComponentsExtension
-import org.apache.tools.ant.taskdefs.condition.Os
-import org.gradle.api.Plugin
-import org.gradle.api.Project
-import org.w3c.dom.Document
-import org.w3c.dom.Element
-
-import javax.xml.parsers.DocumentBuilder
-import javax.xml.parsers.DocumentBuilderFactory
-import javax.xml.transform.TransformerFactory
-import javax.xml.transform.dom.DOMSource
-import javax.xml.transform.stream.StreamResult
-
-/**
- * Utility plugin to fix some common resource issues with gradle:
- *  - add support for androidprv attributes
- */
-class ResourceFixerPlugin implements Plugin<Project> {
-
-    @Override
-    void apply(Project project) {
-
-        def extension = project.getExtensions().getByType(AndroidComponentsExtension.class);
-        def allVariants = []
-
-        def androidTop = project.extensions.extraProperties.get("ANDROID_TOP");
-        String buildTools = project.extensions.extraProperties.get("BUILD_TOOLS_VERSION")
-        buildTools = buildTools.replace(' ', '-')
-        def aapt = "$androidTop/out/gradle/MockSdk/build-tools/$buildTools/aapt2"
-
-        // Store all variant names
-        extension.onVariants(extension.selector().all(), variant -> {
-            allVariants.add(variant.name)
-            allVariants.add("${variant.name}AndroidTest")
-            allVariants.add("${variant.name}UnitTest")
-        })
-
-        // After the project is evaluated, update the mergeResource task
-        project.afterEvaluate {
-            allVariants.forEach(variant -> {
-                def taskName = "merge${variant.capitalize()}Resources";
-                def mergeTask = project.tasks.findByName(taskName);
-                if (mergeTask == null) {
-                    System.out.println("Task not found " + taskName);
-                    return
-                }
-                mergeTask.doLast {
-                    processResources(
-                            new File(project.buildDir, "intermediates/incremental/${variant}/${taskName}/merged.dir"),
-                            new File(project.buildDir, "intermediates/merged_res/${variant}"),
-                            new File(aapt))
-                }
-            })
-        }
-    }
-
-    void processResources(File xmlDir, File outputDir, File aapt) {
-        for (File values: xmlDir.listFiles()) {
-            if (values.getName().startsWith("values") && values.isDirectory()) {
-                for (File xml : values.listFiles()) {
-                    if (xml.isFile() && xml.getName().endsWith(".xml")
-                            && xml.getText().contains("androidprv:")) {
-                        processAndroidPrv(xml, outputDir, aapt);
-                    }
-                }
-            }
-        }
-    }
-
-    private void processAndroidPrv(File xmlFile, File outputDir, File aapt) {
-        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
-        DocumentBuilder db = dbf.newDocumentBuilder();
-        Document doc = db.parse(xmlFile);
-
-        Element root = doc.getDocumentElement();
-        if (root.hasAttribute("xmlns:androidprv")) {
-            // This file is already processed
-            System.out.println("Skipping " + xmlFile.absolutePath);
-            return
-        }
-        root.setAttribute("xmlns:androidprv", "http://schemas.android.com/apk/prv/res/android");
-
-        // Update the file
-        TransformerFactory.newInstance().newTransformer()
-                .transform(new DOMSource(doc), new StreamResult(xmlFile))
-
-        // recompile
-        String command = aapt.getAbsolutePath() +
-                " compile " +
-                xmlFile.getAbsolutePath() +
-                " -o " +
-                outputDir.getAbsolutePath()
-        def proc = command.execute()
-        def sout = new StringBuilder(), serr = new StringBuilder()
-        proc.consumeProcessOutput(sout, serr)
-        proc.waitForOrKill(5000)
-        System.out.println("Processed " + xmlFile.absolutePath + "  " + sout + "  " + serr);
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/SdkSourceUpdaterTask.groovy b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/SdkSourceUpdaterTask.groovy
deleted file mode 100644
index c3fd1083..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/SdkSourceUpdaterTask.groovy
+++ /dev/null
@@ -1,127 +0,0 @@
-import org.gradle.api.DefaultTask
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.OutputFile
-import org.gradle.api.tasks.TaskAction
-import org.w3c.dom.Document
-import org.w3c.dom.Element
-import org.w3c.dom.Node
-import org.w3c.dom.NodeList
-
-import javax.xml.parsers.DocumentBuilder
-import javax.xml.parsers.DocumentBuilderFactory
-import javax.xml.transform.TransformerFactory
-import javax.xml.transform.dom.DOMSource
-import javax.xml.transform.stream.StreamResult
-
-import static org.gradle.api.internal.lambdas.SerializableLambdas.spec;
-
-/**
- * Gradle task to update sources link in sdk
- */
-class SdkSourceUpdaterTask extends DefaultTask  {
-
-    private static final JDK_TABLE_PATH = "out/gradle/AndroidStudio/config/options/jdk.table.xml"
-    private static final JAVA_CORE_PATH = "frameworks/base/core/java"
-    private static final JAVA_GRAPHICS_PATH = "frameworks/base/graphics/java"
-
-    @Input
-    String androidRoot
-
-    public SdkSourceUpdaterTask() {
-        setOnlyIf("Sdk file is missing", spec(task -> new File(androidRoot, JDK_TABLE_PATH).exists()))
-        outputs.upToDateWhen {
-            String sdkDefLines = new File(androidRoot, JDK_TABLE_PATH).text
-            String corePath = new File(androidRoot, JAVA_CORE_PATH).getCanonicalPath()
-            String graphicsPath = new File(androidRoot, JAVA_GRAPHICS_PATH).getCanonicalPath()
-            return sdkDefLines.contains(corePath) && sdkDefLines.contains(graphicsPath)
-        }
-    }
-
-    @OutputFile
-    public File getOutputFile() {
-        return new File(androidRoot, JDK_TABLE_PATH)
-    }
-
-    @TaskAction
-    void execute() throws Exception {
-        File sdkDef = new File(androidRoot, JDK_TABLE_PATH)
-        if (!sdkDef.exists()) {
-            throw new IllegalStateException("Sdk config file not found at " + sdkDef);
-        }
-
-        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
-        DocumentBuilder db = dbf.newDocumentBuilder();
-        Document doc = db.parse(sdkDef);
-
-        NodeList list = doc.getElementsByTagName("jdk");
-        for (int i = 0; i < list.getLength(); i++) {
-            Node node = list.item(i);
-            if (node.getNodeType() == Node.ELEMENT_NODE) {
-                Element element = (Element) node;
-                Element homePath = findFirstElement(element, "homePath");
-                if (homePath == null) {
-                    continue;
-                }
-
-                String pathValue = homePath.getAttribute("value");
-                if (pathValue == null || pathValue.isBlank()) {
-                    continue;
-                }
-
-
-                if (!pathValue.contains("out/gradle/MockSdk")) {
-                    continue;
-                }
-
-                // Found the right SDK
-                Element sourcePath = findFirstElement(element, "sourcePath");
-                if (sourcePath == null) {
-                    // TODO: Add source path
-                    continue;
-                }
-
-                while (sourcePath.hasChildNodes())
-                    sourcePath.removeChild(sourcePath.getFirstChild());
-
-                // Create root
-                Element el = createRoot(doc, "type", "composite");
-                sourcePath.appendChild(el);
-
-                // Create paths
-                el.appendChild(createRoot(doc, "type", "simple", "url", "file://" + new File(androidRoot, JAVA_CORE_PATH).getCanonicalPath()));
-                el.appendChild(createRoot(doc, "type", "simple", "url", "file://" + new File(androidRoot, JAVA_GRAPHICS_PATH).getCanonicalPath()));
-            }
-        }
-
-        // Write the xml
-        TransformerFactory.newInstance().newTransformer()
-                .transform(new DOMSource(doc), new StreamResult(sdkDef))
-
-        System.out.println("======================================")
-        System.out.println("======================================")
-        System.out.println("       Android sources linked")
-        System.out.println("Restart IDE for changes to take effect")
-        System.out.println("======================================")
-        System.out.println("======================================")
-    }
-
-    private Element createRoot(Document doc, String... attrs) {
-        Element el = doc.createElement("root");
-        for (int i = 0; i < attrs.length; i += 2) {
-            el.setAttribute(attrs[i], attrs[i + 1]);
-        }
-        return el;
-    }
-
-    private Element findFirstElement(Element node, String tag) {
-        NodeList paths = node.getElementsByTagName(tag);
-        if (paths.getLength() < 1) {
-            return null;
-        }
-        Node n = paths.item(0);
-        if (n.getNodeType() != Node.ELEMENT_NODE) {
-            return null;
-        }
-        return (Element) n;
-    }
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/sysuigradleproject.nullaway-conventions.gradle b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/sysuigradleproject.nullaway-conventions.gradle
deleted file mode 100644
index 9245fd6b..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/sysuigradleproject.nullaway-conventions.gradle
+++ /dev/null
@@ -1,29 +0,0 @@
-import net.ltgt.gradle.errorprone.CheckSeverity
-
-plugins {
-    id 'net.ltgt.errorprone'
-    id 'net.ltgt.nullaway'
-}
-
-tasks.withType(JavaCompile).configureEach {
-    options.compilerArgs += ["-Xmaxerrs", "10000"] // Display all errors
-    if (name.contains("Nullsafe")) {
-        options.errorprone.disableAllChecks = true
-        options.errorprone.nullaway {
-            severity = CheckSeverity.ERROR
-
-            // Control the packages and classes that are treated as annotated
-            annotatedPackages.add("com.android.systemui.qs")
-
-            // Ignore Dagger-generated classes
-            excludedClassAnnotations.add("dagger.internal.DaggerGenerated")
-        }
-    } else {
-        options.errorprone.enabled = false
-    }
-}
-
-dependencies {
-    annotationProcessor "com.uber.nullaway:nullaway:0.9.1"
-    annotationProcessor "com.google.errorprone:error_prone_core:2.4.0"
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/sysuigradleproject.protobuf-kotlin-lite.gradle b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/sysuigradleproject.protobuf-kotlin-lite.gradle
deleted file mode 100644
index 87c90823..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/groovy/sysuigradleproject.protobuf-kotlin-lite.gradle
+++ /dev/null
@@ -1,37 +0,0 @@
-plugins {
-    id 'com.google.protobuf'
-}
-
-ext {
-    // http://cs/h/android/platform/superproject/main/+/main:external/protobuf/version.json
-    // TODO: protobuf_version should be "3.21.7", but upgrading causes a lot of build failures,
-    // and the fix is non-trivial because of our usage of javanano
-    protobuf_version = "3.0.0"
-}
-
-dependencies {
-    api "com.google.protobuf:protobuf-lite:${protobuf_version}"
-}
-
-protobuf {
-    // Configure the protoc executable
-    protoc {
-        artifact = "com.google.protobuf:protoc:${protobuf_version}${PROTO_ARCH_SUFFIX}"
-    }
-    generateProtoTasks {
-        all().each { task ->
-            task.builtins {
-                remove java
-            }
-            task.plugins {
-                javalite {}
-            }
-        }
-    }
-    plugins {
-        javalite {
-            // The codegen for lite comes as a separate artifact
-            artifact = "com.google.protobuf:protoc-gen-javalite:${protobuf_version}${PROTO_ARCH_SUFFIX}"
-        }
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigCreateCacheTask.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigCreateCacheTask.kt
deleted file mode 100644
index b236f82a..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigCreateCacheTask.kt
+++ /dev/null
@@ -1,43 +0,0 @@
-import org.gradle.api.file.ConfigurableFileCollection
-import org.gradle.api.file.RegularFileProperty
-import org.gradle.api.tasks.AbstractExecTask
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.InputFile
-import org.gradle.api.tasks.InputFiles
-import org.gradle.api.tasks.Optional
-import org.gradle.api.tasks.OutputFile
-
-abstract class AConfigCreateCacheTask :
-        AbstractExecTask<AConfigCreateCacheTask>(AConfigCreateCacheTask::class.java) {
-
-    @get:InputFile
-    abstract val aconfigPath: RegularFileProperty
-
-    @get:Input
-    abstract var packageName: String
-
-    @get:Input
-    @get:Optional
-    abstract var containerName: String?
-
-    @get:InputFiles
-    abstract val srcFiles: ConfigurableFileCollection
-
-    @get:OutputFile
-    abstract val outputFile: RegularFileProperty
-
-    override fun exec() {
-        commandLine(aconfigPath.get())
-        args("create-cache", "--package", packageName)
-        if(containerName != null) {
-            args("--container", containerName)
-        }
-
-        srcFiles.files.forEach { aconfigFile ->
-            args("--declarations", aconfigFile)
-        }
-        args("--cache", "${outputFile.get()}")
-        CommandLineUtils.debugPrintCommandLineArgs(this)
-        super.exec()
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigCreateJavaLibTask.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigCreateJavaLibTask.kt
deleted file mode 100644
index 9c778469..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigCreateJavaLibTask.kt
+++ /dev/null
@@ -1,33 +0,0 @@
-import org.gradle.api.file.DirectoryProperty
-import org.gradle.api.file.RegularFileProperty
-import org.gradle.api.tasks.AbstractExecTask
-import org.gradle.api.tasks.InputFile
-import org.gradle.api.tasks.OutputDirectory
-
-abstract class AConfigCreateJavaLibTask :
-    AbstractExecTask<AConfigCreateJavaLibTask>(AConfigCreateJavaLibTask::class.java) {
-
-    @get:InputFile
-    abstract val aconfigPath: RegularFileProperty
-
-    @get:InputFile
-    abstract val cacheFile: RegularFileProperty
-
-    @get:OutputDirectory
-    abstract val outputFolder: DirectoryProperty
-
-    override fun exec() {
-        commandLine(aconfigPath.get())
-        args(
-            "create-java-lib",
-            "--mode",
-            "production",
-            "--cache",
-            cacheFile.get(),
-            "--out",
-            outputFolder.get()
-        )
-        CommandLineUtils.debugPrintCommandLineArgs(this)
-        super.exec()
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigExtension.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigExtension.kt
deleted file mode 100644
index eee1b28a..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigExtension.kt
+++ /dev/null
@@ -1,22 +0,0 @@
-import org.gradle.api.Action
-import org.gradle.api.DomainObjectSet
-import org.gradle.api.file.ConfigurableFileCollection
-import org.gradle.api.model.ObjectFactory
-import org.gradle.api.provider.Property
-
-interface AConfigDeclaration {
-    val packageName: Property<String>
-    val containerName: Property<String>
-    val srcFile: ConfigurableFileCollection
-}
-
-open class AConfigExtension(private val objectFactory: ObjectFactory) {
-
-    val declarations: DomainObjectSet<AConfigDeclaration> = objectFactory.domainObjectSet(AConfigDeclaration::class.java)
-
-    fun aconfigDeclaration(action: Action<AConfigDeclaration>) {
-        val declaration = objectFactory.newInstance(AConfigDeclaration::class.java)
-        action.execute(declaration)
-        declarations.add(declaration)
-    }
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigPlugin.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigPlugin.kt
deleted file mode 100644
index e96d7432..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/AConfigPlugin.kt
+++ /dev/null
@@ -1,59 +0,0 @@
-import com.android.build.api.variant.AndroidComponentsExtension
-import com.android.build.gradle.api.AndroidBasePlugin
-import org.apache.tools.ant.taskdefs.condition.Os
-import org.gradle.api.Plugin
-import org.gradle.api.Project
-import org.gradle.configurationcache.extensions.capitalized
-import org.gradle.kotlin.dsl.create
-import org.gradle.kotlin.dsl.extra
-import org.gradle.kotlin.dsl.getByType
-import org.gradle.kotlin.dsl.register
-import org.gradle.kotlin.dsl.withType
-import java.io.File
-
-abstract class AConfigPlugin : Plugin<Project> {
-
-    override fun apply(project: Project) {
-        project.plugins.withType<AndroidBasePlugin> {
-            project.dependencies.add("implementation", project.project(":ModuleUtils"))
-            project.dependencies.add("implementation", project.project(":platform-compat"))
-
-            project.extensions.create<AConfigExtension>("aconfig", project.objects)
-            val androidComponents = project.extensions.getByType(AndroidComponentsExtension::class.java)
-            val androidTop = project.extra["ANDROID_TOP"].toString()
-            val platform = if (Os.isFamily(Os.FAMILY_MAC)) "darwin" else "linux"
-            androidComponents.onVariants { variant ->
-                val variantName = variant.name.capitalized()
-                val aconfigExtension = project.extensions.getByType<AConfigExtension>()
-                val aconfigBin = File("$androidTop/prebuilts/build-tools/$platform-x86/bin/aconfig")
-
-                aconfigExtension.declarations.forEach {
-                    val pkgName = it.packageName.get()
-                    val addFlagCacheTaskProvider = project.tasks.register<AConfigCreateCacheTask>(
-                            "generate${variantName}FlagCache_$pkgName"
-                    ) {
-                        aconfigPath.set(aconfigBin)
-                        packageName = pkgName
-                        containerName = it.containerName.orNull
-                        srcFiles.setFrom(it.srcFile)
-                        outputFile.set(
-                                project.layout.buildDirectory.file(
-                                        "intermediates/${variant.name}/aconfig/flag-cache-$pkgName.pb"
-                                )
-                        )
-                    }
-                    val addFlagLibTaskProvider = project.tasks.register<AConfigCreateJavaLibTask>(
-                            "generate${variantName}FlagLib_$pkgName"
-                    ) {
-                        aconfigPath.set(aconfigBin)
-                        cacheFile.set(addFlagCacheTaskProvider.flatMap(AConfigCreateCacheTask::outputFile))
-                    }
-                    variant.sources.java?.addGeneratedSourceDirectory(
-                            addFlagLibTaskProvider,
-                            AConfigCreateJavaLibTask::outputFolder
-                    )
-                }
-            }
-        }
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/CommandLineUtils.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/CommandLineUtils.kt
deleted file mode 100644
index 3f036760..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/CommandLineUtils.kt
+++ /dev/null
@@ -1,19 +0,0 @@
-import org.gradle.api.tasks.AbstractExecTask
-
-class CommandLineUtils {
-    companion object {
-        const val DEBUG = false
-
-        fun debugPrintCommandLineArgs(task: AbstractExecTask<*>) {
-            if (!DEBUG) return
-            println("---- begin command-line ----")
-            println("cd ${task.workingDir}")
-            task.commandLine.forEachIndexed { i, s ->
-                if (i != 0) print("    ")
-                print("$s")
-                if (i != task.commandLine.size) println(" \\") else println()
-            }
-            println("---- end command-line ----")
-        }
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/CreateEventLogTask.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/CreateEventLogTask.kt
deleted file mode 100644
index 92bb0048..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/CreateEventLogTask.kt
+++ /dev/null
@@ -1,45 +0,0 @@
-import org.apache.tools.ant.taskdefs.condition.Os
-import org.gradle.api.file.DirectoryProperty
-import org.gradle.api.file.RegularFile
-import org.gradle.api.tasks.AbstractExecTask
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.InputFile
-import org.gradle.api.tasks.OutputDirectory
-import java.io.File
-import javax.inject.Inject
-
-/**
- * Runs java-event-log-tags.py to generate a java class containing constants for each of the event
- * log tags in the given input file.
- */
-abstract class CreateEventLogTask
-@Inject constructor() : AbstractExecTask<CreateEventLogTask>(CreateEventLogTask::class.java) {
-
-    @get:OutputDirectory
-    abstract val outputFolder: DirectoryProperty
-
-    @get:Input
-    abstract var androidBuildTop: String
-
-    @get:Input
-    abstract var outputFileName: String
-
-    @get:InputFile
-    abstract var logtagsFile: RegularFile
-
-    override fun exec() {
-        workingDir = File("$androidBuildTop/build/make/tools")
-
-        val outputFile = File(outputFolder.get().asFile, "$outputFileName")
-
-        val platform = if (Os.isFamily(Os.FAMILY_MAC)) "darwin" else "linux"
-        commandLine(
-                "$androidBuildTop/prebuilts/build-tools/path/$platform-x86/python3",
-                "java-event-log-tags.py",
-                "-o", outputFile, logtagsFile
-        )
-        println("commandLine = $commandLine")
-        super.exec()
-        println("Tags file created at $outputFile")
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/GenerateCompatAnnotationSrcDir.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/GenerateCompatAnnotationSrcDir.kt
deleted file mode 100644
index 7430c8f5..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/GenerateCompatAnnotationSrcDir.kt
+++ /dev/null
@@ -1,24 +0,0 @@
-import org.gradle.api.file.DirectoryProperty
-import org.gradle.api.tasks.AbstractExecTask
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.OutputDirectory
-import javax.inject.Inject
-
-abstract class GenerateCompatAnnotationSrcDir
-@Inject constructor() : AbstractExecTask<GenerateCompatAnnotationSrcDir>(GenerateCompatAnnotationSrcDir::class.java) {
-
-    @get:OutputDirectory
-    abstract val outputFolder: DirectoryProperty
-
-    @get:Input
-    abstract var symlinkTarget: String
-
-    @get:Input
-    abstract var linkName: String
-
-    override fun exec() {
-        commandLine("ln", "-sf", symlinkTarget, outputFolder.get())
-        CommandLineUtils.debugPrintCommandLineArgs(this)
-        super.exec()
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/GenerateJavaAidlDependencies.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/GenerateJavaAidlDependencies.kt
deleted file mode 100644
index 96bb03e4..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/GenerateJavaAidlDependencies.kt
+++ /dev/null
@@ -1,45 +0,0 @@
-import org.apache.tools.ant.taskdefs.condition.Os
-import org.gradle.api.file.ConfigurableFileCollection
-import org.gradle.api.file.DirectoryProperty
-import org.gradle.api.tasks.AbstractExecTask
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.InputFiles
-import org.gradle.api.tasks.OutputDirectory
-import javax.inject.Inject
-
-abstract class GenerateJavaAidlDependencies
-@Inject constructor() : AbstractExecTask<GenerateJavaAidlDependencies>(GenerateJavaAidlDependencies::class.java) {
-
-    @get:OutputDirectory
-    abstract val outputFolder: DirectoryProperty
-
-    @get:Input
-    abstract var androidBuildTop: String
-
-    @get:InputFiles
-    abstract val aidlSrcDirs: ConfigurableFileCollection
-
-    @get:InputFiles
-    abstract val aidlIncludeDirs: ConfigurableFileCollection
-
-    override fun exec() {
-        val platform = if (Os.isFamily(Os.FAMILY_MAC)) "darwin" else "linux"
-        commandLine("$androidBuildTop/prebuilts/build-tools/${platform}-x86/bin/aidl")
-        args("--lang=java", "--stability=vintf", "-v", "1", "--hash=1", "--structured")
-
-        aidlIncludeDirs.files.forEach { includeDir ->
-            args("-I", includeDir)
-        }
-        args("--out", outputFolder.get())
-
-        // Recursively list all the aidl files in the src directories
-        aidlSrcDirs.files.forEach { srcDir ->
-            args(project.fileTree(srcDir) {
-                include("**/*.aidl")
-            }.files)
-        }
-
-        CommandLineUtils.debugPrintCommandLineArgs(this)
-        super.exec()
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/PushApkTask.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/PushApkTask.kt
deleted file mode 100644
index 0ff75647..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/PushApkTask.kt
+++ /dev/null
@@ -1,47 +0,0 @@
-import com.android.build.api.variant.BuiltArtifactsLoader
-import org.gradle.api.file.DirectoryProperty
-import org.gradle.api.provider.Property
-import org.gradle.api.tasks.AbstractExecTask
-import org.gradle.api.tasks.InputFiles
-import org.gradle.api.tasks.Internal
-import javax.inject.Inject
-
-abstract class PushApkTask
-@Inject constructor() : AbstractExecTask<PushApkTask>(PushApkTask::class.java) {
-
-    @get:InputFiles
-    abstract val apkFolder: DirectoryProperty
-
-    @get:Internal
-    abstract val builtArtifactsLoader: Property<BuiltArtifactsLoader>
-
-    override fun exec() {
-        val builtArtifacts = builtArtifactsLoader.get().load(apkFolder.get())
-            ?: throw RuntimeException("Cannot load APKs")
-        if (builtArtifacts.elements.isEmpty()) {
-            throw RuntimeException("Build artifact not found. Can't install apk if it doesn't exist.")
-        }
-        val numArtifacts = builtArtifacts.elements.size
-        if (numArtifacts > 1) {
-            throw RuntimeException(
-                "Too many build artifacts. Expected 1 apk file but received $numArtifacts. " +
-                        "The push-apk.sh script only supports installing one apk file."
-            )
-        }
-        // TODO(b/234033515): This does not yet account for ANDROID_ADB_SERVER_PORT
-        val deviceSerials =
-            project.providers.gradleProperty("internal.android.inject.device.serials")
-        if (!deviceSerials.isPresent) {
-            throw RuntimeException(
-                "No Android serial present. Make sure your Android Studio VM options contains " +
-                        "-Dgradle.ide.internal.build.injection.device.serial.number=true"
-            )
-        }
-        builtArtifacts.elements.forEach {
-            commandLine("sh", "push-apk.sh", it.outputFile, deviceSerials.get())
-        }
-
-        CommandLineUtils.debugPrintCommandLineArgs(this)
-        super.exec()
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/RepoDependencyMapper.java b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/RepoDependencyMapper.java
deleted file mode 100644
index 055d4a4b..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/RepoDependencyMapper.java
+++ /dev/null
@@ -1,73 +0,0 @@
-import java.io.File;
-import java.util.ArrayList;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Map;
-import java.util.stream.Collectors;
-
-import kotlin.Triple;
-
-/**
- * Class to create a map of available dependencies in repo
- */
-public class RepoDependencyMapper {
-
-  private final Map<String, Triple<String, String, String>> mVersionMap = new HashMap<>();
-
-  public RepoDependencyMapper mapPath(String path) {
-    return mapPath(path, "");
-  }
-
-  /**
-   * Parses the provided path for a possible m2repository
-   */
-  public RepoDependencyMapper mapPath(String path, String prefix) {
-    File repoPath = new File(path);
-    for (File child : repoPath.listFiles()) {
-      checkEndPoint(child, new ArrayList<>(), prefix);
-    }
-    return this;
-  }
-
-  public Map<String, Triple<String, String, String>> getMap() {
-    return mVersionMap;
-  }
-
-  private void checkEndPoint(File current, List<File> parents, String prefix) {
-    if (!current.isDirectory()) {
-      return;
-    }
-
-    parents.add(current);
-    for (File child : current.listFiles()) {
-      checkEndPoint(child, parents, prefix);
-    }
-    parents.remove(current);
-
-    // Check if this is the end point.
-    int parentsCount = parents.size();
-    if (parentsCount > 0) {
-      String versionName = current.getName();
-      String moduleName = parents.get(parentsCount - 1).getName();
-      if (new File(current, moduleName + "-" + versionName + ".pom").exists()) {
-        String groupName = prefix + parents.subList(0, parentsCount - 1)
-            .stream().map(File::getName).collect(Collectors.joining("."));
-
-        String moduleOverride = null;
-        for (String suffix : PLATFORM_TYPE_SUFFIX) {
-          if (moduleName.endsWith(suffix)) {
-            moduleOverride = moduleName;
-            moduleName = moduleName.substring(0, moduleName.length() - suffix.length());
-            break;
-          }
-        }
-
-        System.out.println(groupName + ":" + moduleName + " -> " + versionName);
-        mVersionMap.put(groupName + ":" + moduleName,
-            new Triple<>(groupName, moduleOverride, versionName));
-      }
-    }
-  }
-
-  private static final String[] PLATFORM_TYPE_SUFFIX = new String[]{"-jvm", "-android"};
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/RoboJarFetcherTask.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/RoboJarFetcherTask.kt
deleted file mode 100644
index 9543641c..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/RoboJarFetcherTask.kt
+++ /dev/null
@@ -1,355 +0,0 @@
-import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp
-import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver
-import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow
-import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport
-import com.google.api.client.http.HttpTransport
-import com.google.api.client.json.gson.GsonFactory
-import com.google.api.client.util.store.DataStore
-import com.google.api.client.util.store.DataStoreFactory
-import com.google.api.client.util.store.FileDataStoreFactory
-import com.google.api.services.androidbuildinternal.v3.Androidbuildinternal
-import com.google.api.services.androidbuildinternal.v3.AndroidbuildinternalScopes
-import org.apache.commons.compress.archivers.zip.ZipFile
-import org.apache.commons.compress.utils.IOUtils
-import org.gradle.api.DefaultTask
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.TaskAction
-import org.xml.sax.SAXException
-import java.io.File
-import java.io.FileOutputStream
-import java.io.IOException
-import java.net.HttpURLConnection
-import java.net.URL
-import java.nio.ByteBuffer
-import java.nio.channels.Channels
-import java.nio.channels.ReadableByteChannel
-import java.nio.channels.SeekableByteChannel
-import java.nio.file.Path
-import java.security.GeneralSecurityException
-import java.util.Collections
-import java.util.logging.Logger
-import javax.xml.parsers.DocumentBuilderFactory
-import javax.xml.parsers.ParserConfigurationException
-
-/**
- * Task that grabs the most recent build from the branch under development (git_main, etc)
- * This task uses the androidbuildinternal api jar to access build servers.
- *
- * The jar is found here:
- * vendor/unbundled_google/libraries/androidbuildinternal/
- *
- * Their are several assumptions baked in to this code.
- *
- *
- * * "sdk-trunk_staging" is a build target
- * * "sdk-trunk_staging" containing a test artifact called: "android-all-robolectric.jar"
- *
- * To see builds and artifacts look here:
- * https://android-build.corp.google.com/build_explorer/branch/git_main/?gridSize=20&activeTarget=sdk-trunk_staging&selectionType=START_BUILD_WINDOW&numBuilds=20
- *
- * The API called to find the latest build can be played with here:
- * https://apis-explorer-internal.corp.google.com/?discoveryUrl=https:%2F%2Fwww.googleapis.com%2Fdiscovery%2Fv1%2Fapis%2Fandroidbuildinternal%2Fv3%2Frest&creds=public&methodId=androidbuildinternal.build.list
- *
- * If we want to try to be more precise a pull the current checkout's build the best option today
- * is to guess which git project is the latest and use the API behind: go/wimcl to find the buildId
- * that most closely matches the buildId the user is on.   Unclear if this is necessary.
- *
- */
-abstract class RoboJarFetcherTask : DefaultTask() {
-
-    @get:Input
-    abstract var rootPath: String
-
-    @get:Input
-    abstract var outPath: String
-
-    @get:Input
-    abstract var suggestedGitBranch: String
-
-    @get:Input
-    abstract var buildId: Long
-
-    @TaskAction
-    fun taskAction() {
-        println("Fetching android_all jar")
-        // Setting this property is needed in the gradle jvm to allow
-        // this task to start a web browser on its own rather than
-        // begging the user to do so in standard out.
-        val originalSysProp = System.getProperty("java.awt.headless")
-        System.setProperty("java.awt.headless", "false")
-        val generator = RoboJarFetcher(rootPath, outPath, suggestedGitBranch, buildId)
-        val path = generator.downloadAndroidJarFromServer()
-        System.setProperty("java.awt.headless", originalSysProp)
-        println("Jar downloaded at $path")
-    }
-}
-
-private class RoboJarFetcher(
-        private val rootPath: String,
-        private val outPath: String,
-        private val suggestedGitBranch: String,
-        private val buildId: Long
-) {
-
-    private val dataStoreFactory: DataStoreFactory
-    private val localProps: DataStore<Long>
-    private var client: Androidbuildinternal? = null
-    private var lastFetchedBuildId: Long = -1
-
-    init {
-        val dataDir = File(outPath, "gapi")
-        dataDir.mkdirs()
-        dataStoreFactory = FileDataStoreFactory(dataDir)
-        localProps = dataStoreFactory.getDataStore(LOCAL_PROPS)
-    }
-
-    /**
-     * Downloads and returns the jar for latest robolectric system image
-     */
-    @Throws(IOException::class)
-    fun downloadAndroidJarFromServer(): Path {
-        val jar = cachedJar()
-        if (jar != null) {
-            return jar
-        }
-
-        // Download from server
-        val buildId = latestBuildId()
-        LOGGER.info("Downloading jar for buildId $buildId")
-        val downloadUrl = buildClient().buildartifact()
-                .getdownloadurl(buildId.toString(), TARGET, "latest", "android-all-robolectric.jar")
-                .set("redirect", false)
-                .execute()
-                .signedUrl
-        LOGGER.info("Download url $downloadUrl")
-        val out = getFileForBuildNumber(buildId)
-        val tempFile = File(out.parentFile, out.name + ".tmp")
-        FileOutputStream(tempFile).use { o -> IOUtils.copy(URL(downloadUrl).openStream(), o) }
-        tempFile.renameTo(out)
-        localProps[KEY_BUILD_NUMBER] = buildId
-        localProps[KEY_EXPIRY_TIME] = System.currentTimeMillis() + EXPIRY_TIMEOUT
-
-        // Cleanup, delete all other files.
-        for (f in out.parentFile.listFiles()) {
-            if (f != out) {
-                f.delete()
-            }
-        }
-        return out.toPath()
-    }
-
-    @Throws(IOException::class)
-    private fun cachedJar(): Path? {
-        val buildNumber = localProps[KEY_BUILD_NUMBER] ?: return null
-        val targetFile = getFileForBuildNumber(buildNumber)
-        if (!targetFile.exists()) {
-            return null
-        }
-        if (buildId != -1L) {
-            // If we want a fixed build number, ignore expiry check
-            return if (buildNumber == buildId) targetFile.toPath() else null
-        }
-
-        // Verify if this is still valid
-        var expiryTime = localProps[KEY_EXPIRY_TIME] ?: return null
-        if (expiryTime < System.currentTimeMillis()) {
-            // Check if we are still valid.
-            val latestBuildId = try {
-                latestBuildId()
-            } catch (e: Exception) {
-                LOGGER.warning("Error fetching buildId from build server, using existing jar")
-                return targetFile.toPath()
-            }
-            if (buildNumber != latestBuildId) {
-                // New build available, download and return that
-                return null
-            }
-            // Since we just verified, update the expiry
-            expiryTime = System.currentTimeMillis() + EXPIRY_TIMEOUT
-            localProps[KEY_EXPIRY_TIME] = expiryTime
-        }
-        return targetFile.toPath()
-    }
-
-    @Throws(IOException::class)
-    private fun latestBuildId() : Long {
-        if (buildId >= 0) {
-            return buildId
-        }
-        if (lastFetchedBuildId > -1) {
-            return lastFetchedBuildId
-        }
-        val gitBranch = currentGitBranch()
-        val result = buildClient()
-                .build()
-                .list()
-                .setSortingType("buildId")
-                .setBuildType("submitted")
-                .setBranch("git_$gitBranch")
-                .setTarget(TARGET)
-                .setBuildAttemptStatus("complete")
-                .setSuccessful(true)
-                .setMaxResults(1L)
-                .execute()
-        val buildId = result.builds[0].buildId
-        LOGGER.info("Latest build id: $buildId")
-        lastFetchedBuildId = buildId.toLong()
-        return lastFetchedBuildId
-    }
-
-    @Throws(IOException::class)
-    private fun buildClient() : Androidbuildinternal {
-        if (client != null) {
-            return client as Androidbuildinternal
-        }
-        try {
-            val transport: HttpTransport = GoogleNetHttpTransport.newTrustedTransport()
-            val flow = GoogleAuthorizationCodeFlow.Builder(
-                    transport,
-                    GsonFactory.getDefaultInstance(),
-                    CLIENT_ID, CLIENT_SECRET,
-                    AndroidbuildinternalScopes.all())
-                    .setDataStoreFactory(dataStoreFactory)
-                    .setAccessType("offline")
-                    .setApprovalPrompt("force")
-                    .build()
-            val credential = AuthorizationCodeInstalledApp(flow,
-                    LocalServerReceiver())
-                    .authorize("user")
-            return Androidbuildinternal.Builder(
-                    transport, GsonFactory.getDefaultInstance(), credential)
-                    .build().also { client = it }
-        } catch (gse: GeneralSecurityException) {
-            throw IOException(gse)
-        }
-    }
-
-    @Throws(IOException::class)
-    fun currentGitBranch(): String {
-        if (suggestedGitBranch.isNotEmpty()) {
-            return suggestedGitBranch
-        }
-
-        // Try to find from repo manifest
-        val manifest = File("$rootPath/.repo/manifests/default.xml")
-        return try {
-            DocumentBuilderFactory.newInstance()
-                    .newDocumentBuilder()
-                    .parse(manifest)
-                    .getElementsByTagName("default")
-                    .item(0)
-                    .attributes
-                    .getNamedItem("revision")
-                    .nodeValue
-        } catch (ex: ParserConfigurationException) {
-            throw IOException(ex)
-        } catch (ex: SAXException) {
-            throw IOException(ex)
-        }
-    }
-
-    private fun getFileForBuildNumber(buildNumber: Long): File {
-        val dir = File(outPath, "android_all")
-        dir.mkdirs()
-        return File(dir, "android-all-robolectric-$buildNumber.jar")
-    }
-
-    companion object {
-        private val LOGGER = Logger.getLogger("RoboJarFetcher")
-        private const val CLIENT_ID =
-                "547163898880-gm920odpvl47ba6cpehjsna4ef978739.apps.googleusercontent.com"
-        private const val CLIENT_SECRET = "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"
-        private const val TARGET = "sdk-trunk_staging"
-        private const val LOCAL_PROPS = "local_props"
-        private const val KEY_EXPIRY_TIME = "expiry_time"
-        private const val KEY_BUILD_NUMBER = "build_number"
-        private const val EXPIRY_TIMEOUT = (60 * 60 * 1000 * 48).toLong() // 2 days
-    }
-}
-
-private class RemoteByteChannel(urlString: String?) : SeekableByteChannel {
-    private val url: URL
-    private val size: Long
-    private var requestedPos: Long? = null
-    private var currentPos: Long = 0
-    private var currentConn: HttpURLConnection? = null
-    private var currentChannel: ReadableByteChannel? = null
-
-    init {
-        url = URL(urlString)
-        val conn = newConn()
-        conn.requestMethod = "HEAD"
-        conn.connect()
-        conn.responseCode
-        size = conn.getHeaderField("content-length").toLong()
-        conn.disconnect()
-    }
-
-    private fun closeCurrentConn() {
-        currentChannel?.let (IOUtils::closeQuietly)
-        currentChannel = null
-
-        currentConn?.let(HttpURLConnection::disconnect)
-        currentConn = null
-    }
-
-    @Throws(IOException::class)
-    private fun newConn(): HttpURLConnection {
-        closeCurrentConn()
-        return (url.openConnection() as HttpURLConnection).also { currentConn = it }
-    }
-
-    @Throws(IOException::class)
-    override fun read(byteBuffer: ByteBuffer): Int {
-        requestedPos?.let {
-            if (it != currentPos) {
-                currentPos = it
-                closeCurrentConn()
-            }
-        }
-        requestedPos = null
-
-        if (currentChannel == null) {
-            val conn = newConn()
-            conn.setRequestProperty("Range", "bytes=$currentPos-")
-            conn.connect()
-            currentChannel = Channels.newChannel(conn.inputStream)
-        }
-        val expected = byteBuffer.remaining()
-        IOUtils.readFully(currentChannel, byteBuffer)
-        val remaining = byteBuffer.remaining()
-        currentPos += (expected - remaining).toLong()
-        return expected - remaining
-    }
-
-    @Throws(IOException::class)
-    override fun write(byteBuffer: ByteBuffer): Int {
-        throw IOException("Not supported")
-    }
-
-    override fun position(): Long {
-        return requestedPos ?: currentPos
-    }
-
-    override fun position(l: Long): SeekableByteChannel {
-        requestedPos = l
-        return this
-    }
-
-    override fun size(): Long {
-        return size
-    }
-
-    @Throws(IOException::class)
-    override fun truncate(l: Long): SeekableByteChannel {
-        throw IOException("Not supported")
-    }
-
-    override fun isOpen(): Boolean {
-        return currentChannel != null
-    }
-
-    override fun close() {
-        closeCurrentConn()
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/StatsGenerator.java b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/StatsGenerator.java
deleted file mode 100644
index 8a58262b..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/StatsGenerator.java
+++ /dev/null
@@ -1,505 +0,0 @@
-import com.github.javaparser.utils.Log;
-
-import java.io.BufferedReader;
-import java.io.Closeable;
-import java.io.File;
-import java.io.FileOutputStream;
-import java.io.FileReader;
-import java.io.IOException;
-import java.io.PrintStream;
-import java.util.ArrayList;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Set;
-import java.util.StringJoiner;
-import java.util.logging.Logger;
-import java.util.regex.Matcher;
-import java.util.regex.Pattern;
-
-public class StatsGenerator {
-    private static final Logger LOGGER = Logger.getLogger(StatsGenerator.class.toString());
-    private static final boolean DEBUG = false;
-    private static final Pattern SINGLE_ENTRY = Pattern.compile(
-            "^\\s*((optional|repeated) )?(([a-zA-Z_0-9\\.]+)\\s+)?([a-zA-Z_0-9]+)\\s*=\\s*(\\-?\\d+)([^\\d;][^\\;]*)?;$");
-
-    private final List<String> mAllImports = new ArrayList<>();
-    private final File mRootPath;
-
-    public StatsGenerator(File rootPath) {
-        mRootPath = rootPath;
-    }
-
-    public void process(File atomFile, Set<File> atomExtensions, String module, String packageName,
-            File outputFile) throws IOException {
-        PrintStream output = new PrintStream(new FileOutputStream(outputFile));
-
-        output.println("package " + packageName + ";");
-        output.println();
-        output.println("import android.util.StatsEvent;");
-        output.println();
-
-        String className = outputFile.getName();
-        className = className.substring(0, className.indexOf("."));
-        output.println("public class " + className + " { ");
-        output.println();
-
-        GroupEntry out = new GroupEntry(null);
-        parseFile(out, atomFile);
-
-        if (atomExtensions != null) {
-            for (File ext : atomExtensions) {
-                parseExtension(out, ext);
-            }
-        }
-
-        GroupEntry atom = out.findGroup("atom");
-        GroupEntry pulledGroup = atom.findGroup("pulled");
-        List<SingleEntry> children = new ArrayList<>();
-        children.addAll(atom.findGroup("pushed").getSingles());
-        children.addAll(atom.findGroup("pulled").getSingles());
-
-        for (SingleEntry e : atom.getSingles()) {
-            if (e.extra.contains(module)) {
-                e.writeTo("", output);
-                output.println();
-
-                System.out.println(">> " + out.findGroup(e.type) + "  " + e.type);
-                printGroup(out.findGroup(e.type), output, convertToSymbolGroupPrefix(e.type));
-                output.println();
-                output.println();
-            }
-        }
-
-        for (SingleEntry e : children) {
-            if (e.extra.contains(module)) {
-                e.writeTo("", output);
-                output.println();
-
-                if (DEBUG) System.out.println(">> " + out.findGroup(e.type) + "  " + e.type);
-                printGroup(out.findGroup(e.type), output, convertToSymbolGroupPrefix(e.type));
-                output.println();
-                output.println();
-            }
-        }
-
-        for (SingleEntry e : pulledGroup.getSingles()) {
-            if (e.extra.contains(module)) {
-                GroupEntry group = out.findGroup(e.type);
-                output.println(group.constructBuildStatsEventMethod());
-            }
-        }
-
-        // Add a Placeholder write method
-        output.println("  // Placeholder code for local development only");
-        output.println("  public static void write(int code, Object... params) { }");
-        output.println();
-        output.println("}");
-        output.close();
-    }
-
-    private static void printGroup(GroupEntry entry, PrintStream output, String prefix) {
-        for (SingleEntry e : entry.getSingles()) {
-            GroupEntry subGroup = entry.findGroup(e.type);
-            if (subGroup != null) {
-                printGroup(subGroup, output, prefix + convertToSymbolGroupPrefix(e.name));
-            } else {
-                switch (e.type) {
-                    case "bool":
-                    case "int32":
-                    case "int64":
-                    case "float":
-                    case "string":
-                    case "null":    // In case of enum
-                        e.writeTo(prefix, output);
-                        break;
-                    default:
-                        LOGGER.warning("Type not found " + e);
-                }
-            }
-        }
-    }
-
-    private static String convertToSymbolGroupPrefix(String name) {
-        int dot = name.lastIndexOf('.');
-        if (dot >= 0) {
-            name = name.substring(dot + 1);
-        }
-        return name.replaceAll("([a-z])([A-Z])", "$1_$2").toUpperCase() + "__";
-    }
-
-    private String parseFile(GroupEntry out, File path) throws IOException {
-        ArrayList<String> outImports = new ArrayList<>();
-        String outerPath;
-        try (MyReader reader = new MyReader(new BufferedReader(new FileReader(path)), outImports)) {
-            parseGroup(out, reader, "");
-            out.javaPackage = reader.javaPackage;
-            outerPath = reader.rootPrefix;
-        }
-        parseImports(outImports, out, false);
-        return outerPath;
-    }
-
-    private void parseImports(ArrayList<String> imports, GroupEntry out,
-            boolean skipDuplicate) throws IOException {
-        for (String p : imports) {
-            if (mAllImports.contains(p) && skipDuplicate) {
-                System.err.println("Importing already parsed file " + p);
-                continue;
-            }
-            mAllImports.add(p);
-            File importFile = new File(mRootPath, p);
-            if (importFile.exists()) {
-                GroupEntry grp = new GroupEntry(null);
-                String pkg = parseFile(grp, importFile);
-
-                GroupEntry grp2 = out.imports.get(pkg);
-                if (grp2 == null) {
-                    out.imports.put(pkg, grp);
-                } else {
-                    grp2.children.addAll(grp.children);
-                    grp2.imports.putAll(grp.imports);
-                }
-            }
-        }
-    }
-
-    private void parseExtension(GroupEntry out, File path) throws IOException {
-        ArrayList<String> outImports = new ArrayList<>();
-        try (MyReader reader = new MyReader(new BufferedReader(new FileReader(path)), outImports)) {
-            String line = null;
-            try {
-                while (!(line = reader.getEntry()).startsWith("}")) {
-                    if (line.endsWith("{")) {
-                        String prefix = "";
-                        if (DEBUG) System.out.println(prefix + " :: " + line);
-                        String[] parts = line.split(" ", 3);
-
-                        GroupEntry group = new GroupEntry(out.root);
-                        group.name = parts[1];
-                        group.type = parts[0];
-
-                        GroupEntry existing = out.findGroup(group.name);
-                        if (existing != null) {
-                            if (!"extend".equals(group.type)) {
-                                System.out.println("Found duplicated entry without extension");
-                                continue;
-                            }
-                            parseGroup(existing, reader, prefix + "   ");
-                        } else {
-                            parseGroup(group, reader, prefix + "   ");
-                            out.children.add(group);
-                        }
-                    }
-                }
-            } catch (RuntimeException e) {
-                LOGGER.warning("Error at line " + line);
-                throw e;
-            }
-
-            parseGroup(out, reader, "");
-        }
-
-        parseImports(outImports, out, true);
-    }
-
-    private static void parseGroup(GroupEntry out, MyReader reader, String prefix)
-            throws IOException {
-        String line = null;
-        try {
-            while (!(line = reader.getEntry()).startsWith("}")) {
-                Entry entry;
-                if (line.endsWith("{")) {
-                    if (DEBUG) System.out.println(prefix + " :: " + line);
-                    String[] parts = line.split(" ", 3);
-
-                    GroupEntry group = new GroupEntry(out.root);
-                    group.name = parts[1];
-                    group.type = parts[0];
-
-                    parseGroup(group, reader, prefix + "   ");
-                    entry = group;
-                } else {
-                    String ot = line;
-                    Matcher m = SINGLE_ENTRY.matcher(line.trim());
-                    if (!m.matches()) {
-                        continue;
-                    }
-                    SingleEntry singleEntry = new SingleEntry();
-                    singleEntry.type = m.group(4) + "";
-                    singleEntry.name = m.group(5);
-                    singleEntry.value = m.group(6);
-                    singleEntry.extra = m.group(7) + "";
-                    entry = singleEntry;
-                    if (DEBUG) System.out.println(prefix + " -- " + line);
-                }
-
-                out.children.add(entry);
-            }
-        } catch (RuntimeException e) {
-            LOGGER.warning("Error at line " + line);
-            throw e;
-        }
-    }
-
-    private static class Entry {
-        String type;
-        String name;
-
-        public String javaType() {
-            switch (type) {
-                case "bool":
-                    return "boolean";
-                case "int32":
-                    return "int";
-                case "int64":
-                    return "long";
-                case "float":
-                    return "float";
-                case "string":
-                    return "String";
-                default:
-                    return "Object";
-            }
-        }
-
-        /**
-         * Convert {@code name} from lower_underscore_case to lowerCamelCase.
-         *
-         * The equivalent in guava would be {@code LOWER_UNDERSCORE.to(LOWER_CAMEL, name)}, but to
-         * keep the build system simple we don't want to depend on guava.
-         */
-        public String javaName() {
-            if (name.length() == 0) {
-                return "";
-            }
-            StringBuilder sb = new StringBuilder(name.length());
-            sb.append(name.charAt(0));
-            boolean upperCaseNext = false;
-            for (int i = 1; i < name.length(); i++) {
-                char c = name.charAt(i);
-                if (c == '_') {
-                    upperCaseNext = true;
-                } else {
-                    if (upperCaseNext) {
-                        c = Character.toUpperCase(c);
-                    }
-                    sb.append(c);
-                    upperCaseNext = false;
-                }
-            }
-            return sb.toString();
-        }
-
-        @Override
-        public String toString() {
-            return name + ":" + type;
-        }
-    }
-
-    private static class SingleEntry extends Entry {
-        String value;
-        String extra;
-
-        public void writeTo(String prefix, PrintStream output) {
-            output.println("  public static final int "
-                    + prefix + name.toUpperCase() + " = " + value + ";");
-        }
-
-        public String constructStatsEventWriter(String builderName, GroupEntry g) {
-            switch (type) {
-                case "bool":
-                    return String.format("%s.writeBoolean(%s);", builderName, javaName());
-                case "int32":
-                    return String.format("%s.writeInt(%s);", builderName, javaName());
-                case "int64":
-                    return String.format("%s.writeLong(%s);", builderName, javaName());
-                case "float":
-                    return String.format("%s.writeFloat(%s);", builderName, javaName());
-                case "string":
-                    return String.format("%s.writeString(%s);", builderName, javaName());
-                default:
-                    LOGGER.warning("Type not found " + type + "  " + g.name);
-                    return ";";
-            }
-        }
-    }
-
-    private static class GroupEntry extends Entry {
-        final HashMap<String, GroupEntry> imports;
-        final GroupEntry root;
-        final ArrayList<Entry> children = new ArrayList<>();
-
-        String javaPackage = "";
-
-        public GroupEntry(GroupEntry root) {
-            if (root == null) {
-                this.root = this;
-                this.imports = new HashMap<>();
-            } else {
-                this.root = root;
-                this.imports = root.imports;
-            }
-        }
-
-        public GroupEntry findGroup(String name) {
-            for (Entry e : children) {
-                if (e.name.equalsIgnoreCase(name)) {
-                    return (GroupEntry) e;
-                }
-            }
-            if (root != this) {
-                GroupEntry e = root.findGroup(name);
-                if (e != null) {
-                    return e;
-                }
-            }
-            if (name.indexOf(".") >= 0) {
-                // Look in imports
-                String pkg = name.substring(0, name.lastIndexOf(".") + 1);
-                String key = name.substring(name.lastIndexOf(".") + 1);
-
-                GroupEntry imp = imports.get(pkg);
-                if (imp != null) {
-                    return imp.findGroup(key);
-                }
-                // Try import with a subclass packageName
-                if (javaPackage != null) {
-                    imp = imports.get(javaPackage + pkg);
-                    if (imp != null) {
-                        return imp.findGroup(key);
-                    }
-                }
-            }
-            return null;
-        }
-
-        public List<SingleEntry> getSingles() {
-            List<SingleEntry> result = new ArrayList<>();
-            for (Entry e : children) {
-                if (e instanceof SingleEntry) {
-                    result.add((SingleEntry) e);
-                }
-            }
-            return result;
-        }
-
-        public String constructBuildStatsEventMethod() {
-            StringJoiner responseBuilder = new StringJoiner("\n");
-            responseBuilder.add("  // Placeholder code for local development only");
-            StringJoiner argBuilder = new StringJoiner(", ");
-            getSingles().forEach(entry -> argBuilder.add(
-                    entry.javaType() + " " + entry.javaName()));
-
-
-            String signature = String.format(
-                    "  public static StatsEvent buildStatsEvent(int code, %s){", argBuilder);
-
-            responseBuilder.add(signature)
-                    .add("      final StatsEvent.Builder builder = StatsEvent.newBuilder();")
-                    .add("      builder.setAtomId(code);");
-            getSingles().stream().map(
-                    entry -> entry.constructStatsEventWriter("      builder",this)).forEach(
-                    responseBuilder::add);
-
-            return responseBuilder.add("      return builder.build();")
-                    .add("  }").toString();
-        }
-    }
-
-    private static class MyReader implements Closeable {
-
-        final List<String> outImports;
-        final BufferedReader reader;
-
-        String rootPrefix = "";
-        String javaPackage = "";
-        String javaOuterClassName = "";
-        boolean javaMultipleFiles = false;
-
-        boolean started = false;
-        boolean finished = false;
-
-        MyReader(BufferedReader reader, List<String> outImport) {
-            this.reader = reader;
-            this.outImports = outImport;
-        }
-
-        private String extractQuotes(String line) {
-            Pattern p = Pattern.compile("\"([^\"]*)\"");
-            Matcher m = p.matcher(line);
-            return m.find() ? m.group(1) : "";
-        }
-
-        private String parseHeaders() throws IOException {
-            String line = getEntry();
-            if (line.startsWith("message") || line.equals("}")
-                    || line.startsWith("enum") || line.startsWith("extend")) {
-                return line;
-            }
-            if (line.startsWith("import")) {
-                String impSrc = extractQuotes(line);
-                if (!impSrc.isEmpty()) {
-                    outImports.add(impSrc);
-                }
-            } else if (line.startsWith("option")) {
-                if (line.contains(" java_package ")) {
-                    rootPrefix = extractQuotes(line) + ".";
-                    javaPackage = rootPrefix;
-                } else if (line.contains(" java_outer_classname ")) {
-                    javaOuterClassName = extractQuotes(line);
-                } else if (line.contains(" java_multiple_files ")) {
-                    javaMultipleFiles = line.contains("true");
-                }
-            } else if (line.startsWith("package")) {
-                rootPrefix = line.split(" ")[1].split(";")[0].trim() + ".";
-                javaPackage = rootPrefix;
-            }
-            return parseHeaders();
-        }
-
-        private void onHeaderParseComplete() {
-            if (!javaMultipleFiles && !javaOuterClassName.isEmpty()) {
-                rootPrefix = rootPrefix + javaOuterClassName + ".";
-            }
-        }
-
-        String getEntry() throws IOException {
-            if (!started) {
-                started = true;
-                String entry = parseHeaders();
-                onHeaderParseComplete();
-                return entry;
-            }
-            String line = reader.readLine();
-
-            if (line == null) {
-                // Finished everything
-                finished = true;
-                return "}";
-            }
-
-            line = line.trim();
-
-            // Skip comments
-            int commentIndex = line.indexOf("//");
-            if (commentIndex > -1) {
-                line = line.substring(0, commentIndex).trim();
-            }
-
-            if (line.startsWith("/*")) {
-                while (!line.contains("*/")) line = reader.readLine().trim();
-                line = getEntry();
-            }
-
-            if (!line.endsWith("{") && !line.endsWith(";") && !line.endsWith("}")) {
-                line = line + " " + getEntry();
-            }
-            return line.trim();
-        }
-
-        @Override
-        public void close() throws IOException {
-            reader.close();
-        }
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/StatsGeneratorTask.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/StatsGeneratorTask.kt
deleted file mode 100644
index 924c41f4..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/StatsGeneratorTask.kt
+++ /dev/null
@@ -1,41 +0,0 @@
-import org.gradle.api.DefaultTask
-import org.gradle.api.file.ConfigurableFileCollection
-import org.gradle.api.file.DirectoryProperty
-import org.gradle.api.file.RegularFileProperty
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.InputFile
-import org.gradle.api.tasks.InputFiles
-import org.gradle.api.tasks.OutputDirectory
-import org.gradle.api.tasks.TaskAction
-import java.io.File
-
-abstract class StatsGeneratorTask : DefaultTask() {
-
-    @get:InputFile
-    abstract val atomsFile: RegularFileProperty
-
-    @get:InputFiles
-    abstract val atomsExtensions: ConfigurableFileCollection
-
-    @get:OutputDirectory
-    abstract val outputFolder: DirectoryProperty
-
-    @get:Input
-    abstract var javaFileName: String
-
-    @get:Input
-    abstract var androidTop: String
-
-    @get:Input
-    abstract var module: String
-
-    @get:Input
-    abstract var packageName: String
-
-    @TaskAction
-    fun taskAction() {
-        val generator = StatsGenerator(File(androidTop))
-        generator.process(atomsFile.get().asFile, atomsExtensions.files,
-                module, packageName, File(outputFolder.get().asFile, javaFileName))
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/SymbolicLinksTask.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/SymbolicLinksTask.kt
deleted file mode 100644
index 8365bed0..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/SymbolicLinksTask.kt
+++ /dev/null
@@ -1,58 +0,0 @@
-import org.gradle.api.DefaultTask
-import org.gradle.api.file.ConfigurableFileCollection
-import org.gradle.api.file.FileType
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.InputFiles
-import org.gradle.api.tasks.Optional
-import org.gradle.api.tasks.OutputDirectory
-import org.gradle.api.tasks.TaskAction
-import org.gradle.work.ChangeType
-import org.gradle.work.Incremental
-import org.gradle.work.InputChanges
-import java.io.File
-
-import java.nio.file.Files
-
-/**
- * Create symbolic links of a collection of files in a set output directory.
- *
- * The files must all be rooted at androidTop. This will create a file tree at outputDirectory that
- * mimics the structure rooted at androidTop.
- */
-abstract class SymbolicLinksTask : DefaultTask() {
-
-    @get:Incremental
-    @get:InputFiles
-    abstract val inputDirectories: ConfigurableFileCollection
-
-    @get:OutputDirectory
-    abstract var outputDirectory: String
-
-    @get:Input
-    abstract var androidBuildTop: String
-
-    init {
-        group = "symlink"
-    }
-
-    @TaskAction
-    fun execute(inputChanges: InputChanges) {
-        var androidTopFile = File(androidBuildTop).canonicalFile
-        inputChanges.getFileChanges(inputDirectories).forEach { change ->
-            var file = change.file
-            if (change.fileType == FileType.DIRECTORY) {
-                println("Creating link to ${file.path}")
-                var relativePath = file.canonicalFile.relativeTo(androidTopFile)
-                var symbolicLinkPath =
-                        project.file("$outputDirectory/$relativePath").toPath()
-                if (change.changeType == ChangeType.ADDED && !symbolicLinkPath.toFile().exists()) {
-                    symbolicLinkPath.parent.toFile().mkdirs()
-                    Files.createSymbolicLink(symbolicLinkPath, file.toPath())
-                }
-            } else {
-                // We only need to create symbolic links to directories.
-                // System.err.println("${file.path} is not a directory")
-            }
-        }
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/VerifySystemUiResourceOrderPlugin.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/VerifySystemUiResourceOrderPlugin.kt
deleted file mode 100644
index af25fb66..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/VerifySystemUiResourceOrderPlugin.kt
+++ /dev/null
@@ -1,86 +0,0 @@
-import com.android.build.api.variant.AndroidComponentsExtension
-import com.android.build.api.variant.ComponentIdentity
-import com.android.build.gradle.tasks.MergeResources
-import org.gradle.api.Plugin
-import org.gradle.api.Project
-import org.gradle.api.artifacts.component.ProjectComponentIdentifier
-import org.gradle.configurationcache.extensions.capitalized
-
-/**
- * Plugin that verifies that correct order is used for Google and AOSP SystemUI resources. When
- * there are multiple modules with the same resource, AGP will use the order of the dependencies
- * declaration.
- *
- * See https://developer.android.com/build/dependencies#dependency-order for more details
- */
-abstract class VerifySystemUiResourceOrderPlugin : Plugin<Project> {
-
-    override fun apply(project: Project) {
-        project.extensions.configure(AndroidComponentsExtension::class.java) {
-            onVariants { variant ->
-                project.afterEvaluate {
-                    val capitalizedVariantName = variant.name.capitalized()
-                    val mergeTask =
-                        project.tasks.named(
-                            "merge${capitalizedVariantName}Resources",
-                            MergeResources::class.java
-                        )
-
-                    mergeTask.configure { doLast { verifyOrder(variant) } }
-                }
-            }
-        }
-    }
-
-    private fun MergeResources.verifyOrder(variant: ComponentIdentity) {
-        val projectPaths = librariesProjectPaths
-
-        // The lower the index, the higher is the priority
-        val googleResourcesPriority = projectPaths.indexOf(GOOGLE_RESOURCES_PROJECT)
-        val aospResourcesPriority = projectPaths.indexOf(AOSP_RESOURCES_PROJECT)
-
-        if (variant.isGoogleSpecific()) {
-            if (googleResourcesPriority == INDEX_NOT_FOUND) {
-                throw IllegalArgumentException(
-                    "Project ${projectPath.get()} doesn't have $GOOGLE_RESOURCES_PROJECT dependency"
-                )
-            }
-            if (aospResourcesPriority == INDEX_NOT_FOUND) {
-                throw IllegalArgumentException(
-                    "Project ${projectPath.get()} doesn't have $AOSP_RESOURCES_PROJECT dependency"
-                )
-            }
-
-            if (googleResourcesPriority > aospResourcesPriority) {
-                val prioritiesDescription =
-                    "'$GOOGLE_RESOURCES_PROJECT' index: $googleResourcesPriority, " +
-                        "'$AOSP_RESOURCES_PROJECT' index: $aospResourcesPriority"
-
-                throw IllegalArgumentException(
-                    "Invalid resource dependencies order, expected Google resources " +
-                        "($GOOGLE_RESOURCES_PROJECT) to have higher priority " +
-                        "(earlier in the list) than AOSP resources " +
-                        "($AOSP_RESOURCES_PROJECT) for task ${this.name}.\n\n" +
-                        prioritiesDescription
-                )
-            }
-        }
-    }
-
-    private val MergeResources.librariesProjectPaths: List<String>
-        get() =
-            resourcesComputer.libraries
-                .get()
-                .map { it.id.componentIdentifier }
-                .filterIsInstance<ProjectComponentIdentifier>()
-                .map { it.projectPath }
-
-    private fun ComponentIdentity.isGoogleSpecific(): Boolean =
-        name.contains("google", ignoreCase = true) || name.contains("titan", ignoreCase = true)
-
-    private companion object {
-        private const val GOOGLE_RESOURCES_PROJECT = ":sysuig-resources"
-        private const val AOSP_RESOURCES_PROJECT = ":SystemUI-res"
-        private const val INDEX_NOT_FOUND = -1
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/_global.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/_global.kt
deleted file mode 100644
index a6cc32b3..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/_global.kt
+++ /dev/null
@@ -1,53 +0,0 @@
-import org.gradle.api.Action
-import org.gradle.api.Project
-import org.gradle.api.file.FileCollection
-import org.gradle.api.tasks.Delete
-import org.gradle.api.tasks.compile.JavaCompile
-import org.gradle.api.tasks.util.PatternFilterable
-import org.gradle.configurationcache.extensions.capitalized
-import org.gradle.kotlin.dsl.maybeCreate
-import org.gradle.kotlin.dsl.register
-import org.gradle.kotlin.dsl.withType
-import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
-import task.SymlinkSourcesTask
-import java.io.File
-
-fun Project.symlinkedSources(
-        dir: String,
-        name: String = File(dir).name,
-        excludeSubdirectories: Boolean = true,
-        test: Boolean = false,
-        filter: Action<PatternFilterable> = Action { },
-): FileCollection {
-    val sourceDir = File(dir)
-    val type = if (test) "test" else "main"
-    val outputDir = rootDir.resolve(".symlinkSrc/${project.name}/${type}/${name}")
-    val task = tasks.register<SymlinkSourcesTask>("symlink${type.capitalized()}Sources${name.capitalized()}") {
-        description = "Filter sources from ${sourceDir.absolutePath} and link them to ${outputDir.absolutePath}"
-        this.sourcesRoot.set(dir)
-        this.files {
-            exclude { !it.isDirectory && it.file.extension !in arrayOf("kt", "java") }
-            if (excludeSubdirectories) {
-                exclude { it.isDirectory }
-            }
-            filter.execute(this)
-        }
-        this.destinationDir.set(outputDir)
-    }
-    tasks.withType<KotlinCompile> { dependsOn(task) }
-    tasks.withType<JavaCompile> { dependsOn(task) }
-    tasks.maybeCreate<Delete>("cleanSymlinkedSources").apply {
-        group = "symlink"
-        delete(outputDir)
-    }
-    val symlinkSources = tasks.maybeCreate("symlinkSources").apply {
-        group = "symlink"
-        dependsOn(task)
-    }
-    rootProject.tasks.named("updateSdkSources") {
-        dependsOn(symlinkSources)
-    }
-    return files(task.flatMap(SymlinkSourcesTask::destinationDir)) {
-        builtBy(task)
-    }
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/aconfig.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/aconfig.gradle.kts
deleted file mode 100644
index eea24c78..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/aconfig.gradle.kts
+++ /dev/null
@@ -1,19 +0,0 @@
-import org.gradle.kotlin.dsl.apply
-
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
- * limitations under the License.
- */
-
-apply<AConfigPlugin>()
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/com.android.library-empty-src.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/com.android.library-empty-src.gradle.kts
deleted file mode 100644
index 14c63200..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/com.android.library-empty-src.gradle.kts
+++ /dev/null
@@ -1,20 +0,0 @@
-plugins {
-    id("com.android.library")
-}
-
-android {
-    sourceSets {
-        sourceSets.forEach {
-            it.java.setSrcDirs(emptyList<String>())
-            it.kotlin.setSrcDirs(emptyList<String>())
-            it.res.setSrcDirs(emptyList<String>())
-            it.assets.setSrcDirs(emptyList<String>())
-            it.aidl.setSrcDirs(emptyList<String>())
-            it.renderscript.setSrcDirs(emptyList<String>())
-            it.baselineProfiles.setSrcDirs(emptyList<String>())
-            it.jni.setSrcDirs(emptyList<String>())
-            it.jniLibs.setSrcDirs(emptyList<String>())
-            it.resources.setSrcDirs(emptyList<String>())
-        }
-    }
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/task/SymlinkSourcesTask.kt b/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/task/SymlinkSourcesTask.kt
deleted file mode 100644
index 5bbf75f8..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/buildSrc/src/main/java/task/SymlinkSourcesTask.kt
+++ /dev/null
@@ -1,68 +0,0 @@
-package task
-
-import org.gradle.api.Action
-import org.gradle.api.DefaultTask
-import org.gradle.api.file.ConfigurableFileTree
-import org.gradle.api.file.DirectoryProperty
-import org.gradle.api.file.FileType
-import org.gradle.api.file.ProjectLayout
-import org.gradle.api.provider.Property
-import org.gradle.api.tasks.Input
-import org.gradle.api.tasks.InputFiles
-import org.gradle.api.tasks.OutputDirectory
-import org.gradle.api.tasks.TaskAction
-import org.gradle.api.tasks.util.PatternFilterable
-import org.gradle.work.ChangeType
-import org.gradle.work.Incremental
-import org.gradle.work.InputChanges
-import java.io.File
-import java.nio.file.Files
-import javax.inject.Inject
-import kotlin.io.path.Path
-
-@Suppress("LeakingThis")
-internal abstract class SymlinkSourcesTask : DefaultTask() {
-    @get:Input
-    abstract val sourcesRoot: Property<String>
-
-    @get:InputFiles
-    @get:Incremental
-    protected abstract val files: ConfigurableFileTree
-
-    fun files(filter: Action<PatternFilterable>) {
-        filter.execute(files)
-    }
-
-    @get:OutputDirectory
-    abstract val destinationDir: DirectoryProperty
-
-    @get:Inject
-    protected abstract val layout: ProjectLayout
-
-    init {
-        group = "symlink"
-        files.from(sourcesRoot)
-    }
-
-    @TaskAction
-    fun execute(inputChanges: InputChanges) {
-        val sourcesRootDir = File(sourcesRoot.get())
-        inputChanges.getFileChanges(files).forEach { change ->
-            val file = change.file
-            val relativePath = file.canonicalFile.relativeTo(sourcesRootDir)
-            val symbolicLinkPath = Path("${destinationDir.get()}/$relativePath")
-            val symbolicLinkFile = symbolicLinkPath.toFile()
-            if (file !in files && file.absolutePath != sourcesRootDir.absolutePath) {
-                logger.info("Cleaning up filtered out symlink {}", symbolicLinkPath)
-                symbolicLinkFile.deleteRecursively()
-            } else if (change.changeType == ChangeType.REMOVED) {
-                logger.info("Removing symbolic link at {}", symbolicLinkPath)
-                symbolicLinkFile.deleteRecursively()
-            } else if (change.fileType == FileType.FILE && change.changeType == ChangeType.ADDED && !symbolicLinkFile.exists()) {
-                logger.info("Creating symbolic link to {}", file.path)
-                symbolicLinkFile.parentFile.mkdirs()
-                Files.createSymbolicLink(symbolicLinkPath, file.toPath())
-            }
-        }
-    }
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/gradle.properties b/studio-dev/ManagedProvisioningGradleProject/gradle.properties
deleted file mode 100644
index 502e9727..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/gradle.properties
+++ /dev/null
@@ -1,66 +0,0 @@
-# Until all the dependencies move to android X
-android.useAndroidX=true
-android.enableJetifier=false
-android.debug.obsoleteApi=true
-# Don't warn about needing to update AGP
-android.suppressUnsupportedCompileSdk=34
-org.gradle.parallel=true
-kapt.use.worker.api=true
-# Force Android Studio to build using the JDK of our choice, or the embedded JDK included with the
-# Android Studio installation. You can confirm this works by running the following command to list
-# all Java toolchains:
-#
-#    gradle -q javaToolchains
-#
-org.gradle.java.installations.auto-detect=false
-org.gradle.java.installations.auto-download=false
-org.gradle.java.installations.fromEnv=STUDIO_JDK
-PLAY_SERVICES_VERSION=12.4-SNAPSHOT
-# Matches http://cs/h/android/platform/superproject/main/+/main:prebuilts/sdk/tools/linux/bin/source.properties
-BUILD_TOOLS_VERSION=34.0.0
-TARGET_SDK=34
-gradle=build -x lint -x lintVitalRelease
-org.gradle.jvmargs=-Xmx8g
-ANDROID_RELATIVE_TOP=../../../../../
-# http://cs/h/android/platform/superproject/main/+/main:external/protobuf/version.json
-#protobuf_version=3.21.7
-protobuf_version=3.0.0
-# http://cs/h/android/platform/superproject/main/+/main:external/protobuf/javanano/pom.xml?q=Export-Package
-protobuf_javanano_version=3.0.0-alpha-7
-protobuf_lite_version=3.0.0
-# http://cs/h/android/platform/superproject/main/+/main:external/dagger2/METADATA?l=14
-dagger_version=2.47
-# http://cs/h/android/platform/superproject/main/+/main:external/kotlinx.coroutines/METADATA?l=8
-kotlin_coroutine_version=1.7.2
-# http://cs/h/android/platform/superproject/main/+/main:prebuilts/sdk/current/androidx/m2repository/androidx/compose/compiler/compiler-hosted
-compose_compiler_version=1.5.1
-google_truth_version=1.1
-gson_version=2.10.1
-# Use this setting if the version of Android Lint in the Android Tree is newer than
-# the version of AGP we are using for the SysUi Studio Gradle Build.
-#
-# See: https://googlesamples.github.io/android-custom-lint-rules/usage/newer-lint.md.html
-#
-# To query the current lint version used by soong, run:
-#   ./prebuilts/cmdline-tools/tools/bin/lint --version
-#
-# If this prints something like "8.0.0-dev", you'll need to check the git log to find the exact
-# build ID. You should see a commit containing a message like: "Update cmdline-tools to ab/9458967".
-#
-# TODO: To track upstream build artifacts more accurately, we might be able to fetch the right
-# versions using AGP's nightly repo.
-# See: https://groups.google.com/a/google.com/g/android-gradle/c/SwjHMeFNeg8/m/DxZuyMwSAQAJ
-#android.experimental.lint.version = 8.3.0-alpha07
-# lintGradlePluginVersion = gradlePluginVersion + 23.0.0
-# For explanation, see: http://go/android-lint-api-guide#example:samplelintcheckgithubproject/lintversion%3F
-# For versions, see: https://maven.google.com/web/index.html?q=lint#com.android.tools.lint:lint
-lintGradlePluginVersion=31.3.0-alpha07
-auto_service_version=1.0.1
-# Citc client to full code for overlay lib. If empty, the library is not included
-ACETONE_LIB_CITC_CLIENT=
-# TODO: Remove after fixing b/295208392
-# See also: http://go/android-dev/build/optimize-your-build#use-non-transitive-r-classes
-android.nonTransitiveRClass=false
-# Added to allow test artifacts (e.g. screenshots) to be stored and kept on device after a run
-# See b/295039976 for more details
-android.injected.androidTest.leaveApksInstalledAfterRun=true
diff --git a/studio-dev/ManagedProvisioningGradleProject/gradle/libs.versions.toml b/studio-dev/ManagedProvisioningGradleProject/gradle/libs.versions.toml
deleted file mode 100644
index 048a010b..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/gradle/libs.versions.toml
+++ /dev/null
@@ -1,102 +0,0 @@
-[versions]
-# For more info on Android Studio <-> AGP compatibilty, see:
-#   http://go/android-dev/studio/preview/features#agp-previews
-# For all available versions, see:
-#   http://go/gmaven-index#com.android.library:com.android.library.gradle.plugin
-android-gradle-plugin = "8.4.0-alpha12"
-android-studio = "2023.3.1 Canary 12"
-
-idea-ext-gradle-plugin = "1.1.7"
-errorprone-gradle-plugin = "1.2.0"
-errorprone-annotations-gradle-plugin = "2.21.1"
-googleTruthVersion = "1.1.3"
-guava = "30.0-android"
-javaxInject = "1"
-# http://cs/h/android/platform/superproject/main/+/main:external/kotlinc/build.txt
-kotlin = "1.9.10"
-# http://cs/h/android/platform/superproject/main/+/main:external/kotlinx.coroutines/METADATA
-kotlinCoroutineVersion = "1.7.3"
-legacySupportV4 = "1.0.0"
-mockito = "2.28.3"
-protobuf-gradle-plugin = "0.9.4"
-protobuf = "3.8.0"
-# TODO(b/280326338): Track //external/robolectric version
-robolectric = "4.11-SNAPSHOT"
-# http://cs/h/android/platform/superproject/main/+/main:external/junit/version
-junit = "4.13.2"
-lottie = "5.2.0"
-androidx-benchmark = "1.2.3"
-# http://cs/h/android/platform/superproject/main/+/main:external/dagger2/METADATA?l=14
-dagger = "2.47"
-hilt = "2.47"
-testng = "7.8.0"
-
-[plugins]
-android-application = { id = "com.android.application", version.ref = "android-gradle-plugin" }
-android-library = { id = "com.android.library", version.ref = "android-gradle-plugin" }
-kotlin-android = { id = "org.jetbrains.kotlin.android", version.ref = "kotlin" }
-kotlin-kapt = { id = "org.jetbrains.kotlin.kapt", version.ref = "kotlin" }
-hilt = { id = "com.google.dagger.hilt.android", version.ref = "hilt" }
-protobuf = { id = "com.google.protobuf", version.ref = "protobuf-gradle-plugin" }
-
-[libraries]
-androidx-annotation = { module = "androidx.annotation:annotation" }
-androidx-appcompat = { module = "androidx.appcompat:appcompat" }
-androidx-core = { module = "androidx.core:core" }
-android-support-v7-appcompat = { module = "com.android.support:appcompat-v7", version = "28.0.0" }
-apache-commons-lang3 = {module="org.apache.commons:commons-lang3", version = "3.14.0"}
-androidx-legacy-support-core-ui = { module = "androidx.legacy:legacy-support-core-ui" }
-androidx-legacy-support-v4 = { module = "androidx.legacy:legacy-support-v4", version.ref = "legacySupportV4" }
-androidx-recyclerview = { module = "androidx.recyclerview:recyclerview" }
-androidx-window = { module = "androidx.window:window" }
-com-google-android-material = { module = "com.google.android.material:material" }
-androidx-ktx = { module = "androidx.core:core-ktx" }
-errorprone-annotations = { module = "com.google.errorprone:error_prone_annotations", version.ref = "errorprone-annotations-gradle-plugin" }
-espresso-contrib = { module = "androidx.test.espresso:espresso-contrib" }
-espresso-core = { module = "androidx.test.espresso:espresso-core" }
-espresso-intents = { module = "androidx.test.espresso:espresso-intents" }
-google-truth = { module = "com.google.truth:truth", version.ref = "googleTruthVersion" }
-guava = { module = "com.google.guava:guava", version.ref = "guava" }
-javax-inject = { module = "javax.inject:javax.inject", version.ref = "javaxInject" }
-kotlin-reflect = { module = "org.jetbrains.kotlin:kotlin-reflect", version.ref = "kotlin" }
-kotlin-stdlib-jdk7 = { module = "org.jetbrains.kotlin:kotlin-stdlib-jdk7", version.ref = "kotlin" }
-kotlin-stdlib-jdk8 = { module = "org.jetbrains.kotlin:kotlin-stdlib-jdk8", version.ref = "kotlin" }
-kotlinx-coroutines-android = { module = "org.jetbrains.kotlinx:kotlinx-coroutines-android", version.ref = "kotlinCoroutineVersion" }
-lifecycle-common-java8 = { module = "androidx.lifecycle:lifecycle-common-java8" }
-lifecycle-extensions = { module = "androidx.lifecycle:lifecycle-extensions" }
-mockitoInline = { module = "com.linkedin.dexmaker:dexmaker-mockito-inline", version.ref = "mockito" }
-mockitoInlineExtended = { module = "com.linkedin.dexmaker:dexmaker-mockito-inline-extended", version.ref = "mockito" }
-mockitoKotlin = { module = "org.mockito.kotlin:mockito-kotlin", version = "2.2.11" }
-protobuf-javalite = { module = "com.google.protobuf:protobuf-javalite", version.ref = "protobuf" }
-protobuf-protoc = { module = "com.google.protobuf:protoc", version.ref = "protobuf" }
-rules = { module = "androidx.test:rules" }
-androidx-test-rules = { module = "androidx.test:rules" }
-androidx-test-core = { module = "androidx.test:core" }
-scriptClasspath-nullaway = { module = "net.ltgt.gradle:gradle-nullaway-plugin", version.ref = "errorprone-gradle-plugin" }
-scriptClasspath-android = { module = "com.android.tools.build:gradle", version.ref = "android-gradle-plugin" }
-scriptClasspath-kotlin = { module = "org.jetbrains.kotlin:kotlin-gradle-plugin", version.ref = "kotlin" }
-scriptClasspath-errorprone = { module = "net.ltgt.gradle:gradle-errorprone-plugin", version.ref = "errorprone-gradle-plugin" }
-scriptClasspath-protobuf = { module = "com.google.protobuf:protobuf-gradle-plugin", version.ref = "protobuf-gradle-plugin" }
-scriptClasspath-hilt = { module = "com.google.dagger:hilt-android-gradle-plugin", version.ref = "hilt" }
-robolectric = { module = "org.robolectric:robolectric", version.ref = "robolectric" }
-truth = { module = "androidx.test.ext:truth" }
-androidx-benchmark-macro = { module = "androidx.benchmark:benchmark-macro", version.ref = "androidx-benchmark" }
-androidx-benchmark-common = { module = "androidx.benchmark:benchmark-common", version.ref = "androidx-benchmark" }
-androidx-activity-ktx = { group = "androidx.activity", name = "activity-ktx" }
-androidx-fragment-ktx = { module = "androidx.fragment:fragment-ktx" }
-androidx-junit-ktx = { group = "androidx.test.ext", name = "junit-ktx" }
-junit = { group = "junit", name = "junit", version.ref = "junit" }
-testng = { module = "org.testng:testng", version.ref = "testng" }
-# http://cs/h/googleplex-android/platform/superproject/main/+/main:external/lottie/METADATA
-com-airbnb-android-lottie = { group = "com.airbnb.android", name = "lottie", version.ref = "lottie" }
-androidx-appsearch = { group = "androidx.appsearch", name = "appsearch", version = "1.1.0-alpha03" }
-androidx-appsearch-platform-storage = { group = "androidx.appsearch", name = "appsearch-platform-storage", version = "1.1.0-alpha03" }
-androidx-appsearch-builtin-types = { group = "androidx.appsearch", name = "appsearch-builtin-types", version = "1.1.0-alpha03" }
-androidx-concurrent-futures-ktx = { group = "androidx.concurrent", name = "concurrent-futures-ktx", version = "1.2.0-alpha02" }
-dagger = { module = "com.google.dagger:dagger", version.ref = "dagger" }
-dagger-android = { module = "com.google.dagger:dagger-android", version.ref = "dagger" }
-dagger-compiler = { module = "com.google.dagger:dagger-compiler", version.ref = "dagger" }
-dagger-android-processor = { module = "com.google.dagger:dagger-android-processor", version.ref = "dagger" }
-hilt-android = { module = "com.google.dagger:hilt-android", version.ref = "hilt" }
-hilt-android-compiler = { module = "com.google.dagger:hilt-android-compiler", version.ref = "hilt" }
-hilt-android-testing = { module = "com.google.dagger:hilt-android-testing", version.ref = "hilt" }
diff --git a/studio-dev/ManagedProvisioningGradleProject/gradle/wrapper/gradle-wrapper.jar b/studio-dev/ManagedProvisioningGradleProject/gradle/wrapper/gradle-wrapper.jar
deleted file mode 100644
index 033e24c4..00000000
Binary files a/studio-dev/ManagedProvisioningGradleProject/gradle/wrapper/gradle-wrapper.jar and /dev/null differ
diff --git a/studio-dev/ManagedProvisioningGradleProject/gradle/wrapper/gradle-wrapper.properties b/studio-dev/ManagedProvisioningGradleProject/gradle/wrapper/gradle-wrapper.properties
deleted file mode 100644
index 649b1477..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/gradle/wrapper/gradle-wrapper.properties
+++ /dev/null
@@ -1,10 +0,0 @@
-distributionBase=GRADLE_USER_HOME
-distributionPath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-8.6-bin.zip
-networkTimeout=10000
-validateDistributionUrl=true
-zipStoreBase=GRADLE_USER_HOME
-zipStorePath=wrapper/dists
-# We can't use a distribution SHA to verify file integrity because Android Studio does not support
-# it. For more details, see https://github.com/gradle/gradle/issues/9361.
-#distributionSha256Sum=
diff --git a/studio-dev/ManagedProvisioningGradleProject/gradlew b/studio-dev/ManagedProvisioningGradleProject/gradlew
deleted file mode 100755
index fcb6fca1..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/gradlew
+++ /dev/null
@@ -1,248 +0,0 @@
-#!/bin/sh
-
-#
-# Copyright © 2015-2021 the original authors.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-##############################################################################
-#
-#   Gradle start up script for POSIX generated by Gradle.
-#
-#   Important for running:
-#
-#   (1) You need a POSIX-compliant shell to run this script. If your /bin/sh is
-#       noncompliant, but you have some other compliant shell such as ksh or
-#       bash, then to run this script, type that shell name before the whole
-#       command line, like:
-#
-#           ksh Gradle
-#
-#       Busybox and similar reduced shells will NOT work, because this script
-#       requires all of these POSIX shell features:
-#         * functions;
-#         * expansions «$var», «${var}», «${var:-default}», «${var+SET}»,
-#           «${var#prefix}», «${var%suffix}», and «$( cmd )»;
-#         * compound commands having a testable exit status, especially «case»;
-#         * various built-in commands including «command», «set», and «ulimit».
-#
-#   Important for patching:
-#
-#   (2) This script targets any POSIX shell, so it avoids extensions provided
-#       by Bash, Ksh, etc; in particular arrays are avoided.
-#
-#       The "traditional" practice of packing multiple parameters into a
-#       space-separated string is a well documented source of bugs and security
-#       problems, so this is (mostly) avoided, by progressively accumulating
-#       options in "$@", and eventually passing that to Java.
-#
-#       Where the inherited environment variables (DEFAULT_JVM_OPTS, JAVA_OPTS,
-#       and GRADLE_OPTS) rely on word-splitting, this is performed explicitly;
-#       see the in-line comments for details.
-#
-#       There are tweaks for specific operating systems such as AIX, CygWin,
-#       Darwin, MinGW, and NonStop.
-#
-#   (3) This script is generated from the Groovy template
-#       https://github.com/gradle/gradle/blob/HEAD/subprojects/plugins/src/main/resources/org/gradle/api/internal/plugins/unixStartScript.txt
-#       within the Gradle project.
-#
-#       You can find Gradle at https://github.com/gradle/gradle/.
-#
-##############################################################################
-
-# Attempt to set APP_HOME
-
-# Resolve links: $0 may be a link
-app_path=$0
-
-# Need this for daisy-chained symlinks.
-while
-    APP_HOME=${app_path%"${app_path##*/}"}  # leaves a trailing /; empty if no leading path
-    [ -h "$app_path" ]
-do
-    ls=$( ls -ld "$app_path" )
-    link=${ls#*' -> '}
-    case $link in             #(
-      /*)   app_path=$link ;; #(
-      *)    app_path=$APP_HOME$link ;;
-    esac
-done
-
-# This is normally unused
-# shellcheck disable=SC2034
-APP_BASE_NAME=${0##*/}
-APP_HOME=$( cd "${APP_HOME:-./}" && pwd -P ) || exit
-
-# Use the maximum available, or set MAX_FD != -1 to use that value.
-MAX_FD=maximum
-
-warn () {
-    echo "$*"
-} >&2
-
-die () {
-    echo
-    echo "$*"
-    echo
-    exit 1
-} >&2
-
-# OS specific support (must be 'true' or 'false').
-cygwin=false
-msys=false
-darwin=false
-nonstop=false
-case "$( uname )" in                #(
-  CYGWIN* )         cygwin=true  ;; #(
-  Darwin* )         darwin=true  ;; #(
-  MSYS* | MINGW* )  msys=true    ;; #(
-  NONSTOP* )        nonstop=true ;;
-esac
-
-CLASSPATH=$APP_HOME/gradle/wrapper/gradle-wrapper.jar
-
-
-# Determine the Java command to use to start the JVM.
-if [ -n "$JAVA_HOME" ] ; then
-    if [ -x "$JAVA_HOME/jre/sh/java" ] ; then
-        # IBM's JDK on AIX uses strange locations for the executables
-        JAVACMD=$JAVA_HOME/jre/sh/java
-    else
-        JAVACMD=$JAVA_HOME/bin/java
-    fi
-    if [ ! -x "$JAVACMD" ] ; then
-        die "ERROR: JAVA_HOME is set to an invalid directory: $JAVA_HOME
-
-Please set the JAVA_HOME variable in your environment to match the
-location of your Java installation."
-    fi
-else
-    JAVACMD=java
-    if ! command -v java >/dev/null 2>&1
-    then
-        die "ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
-
-Please set the JAVA_HOME variable in your environment to match the
-location of your Java installation."
-    fi
-fi
-
-# Increase the maximum file descriptors if we can.
-if ! "$cygwin" && ! "$darwin" && ! "$nonstop" ; then
-    case $MAX_FD in #(
-      max*)
-        # In POSIX sh, ulimit -H is undefined. That's why the result is checked to see if it worked.
-        # shellcheck disable=SC3045
-        MAX_FD=$( ulimit -H -n ) ||
-            warn "Could not query maximum file descriptor limit"
-    esac
-    case $MAX_FD in  #(
-      '' | soft) :;; #(
-      *)
-        # In POSIX sh, ulimit -n is undefined. That's why the result is checked to see if it worked.
-        # shellcheck disable=SC3045
-        ulimit -n "$MAX_FD" ||
-            warn "Could not set maximum file descriptor limit to $MAX_FD"
-    esac
-fi
-
-# Collect all arguments for the java command, stacking in reverse order:
-#   * args from the command line
-#   * the main class name
-#   * -classpath
-#   * -D...appname settings
-#   * --module-path (only if needed)
-#   * DEFAULT_JVM_OPTS, JAVA_OPTS, and GRADLE_OPTS environment variables.
-
-# For Cygwin or MSYS, switch paths to Windows format before running java
-if "$cygwin" || "$msys" ; then
-    APP_HOME=$( cygpath --path --mixed "$APP_HOME" )
-    CLASSPATH=$( cygpath --path --mixed "$CLASSPATH" )
-
-    JAVACMD=$( cygpath --unix "$JAVACMD" )
-
-    # Now convert the arguments - kludge to limit ourselves to /bin/sh
-    for arg do
-        if
-            case $arg in                                #(
-              -*)   false ;;                            # don't mess with options #(
-              /?*)  t=${arg#/} t=/${t%%/*}              # looks like a POSIX filepath
-                    [ -e "$t" ] ;;                      #(
-              *)    false ;;
-            esac
-        then
-            arg=$( cygpath --path --ignore --mixed "$arg" )
-        fi
-        # Roll the args list around exactly as many times as the number of
-        # args, so each arg winds up back in the position where it started, but
-        # possibly modified.
-        #
-        # NB: a `for` loop captures its iteration list before it begins, so
-        # changing the positional parameters here affects neither the number of
-        # iterations, nor the values presented in `arg`.
-        shift                   # remove old arg
-        set -- "$@" "$arg"      # push replacement arg
-    done
-fi
-
-
-# Add default JVM options here. You can also use JAVA_OPTS and GRADLE_OPTS to pass JVM options to this script.
-DEFAULT_JVM_OPTS='"-Xmx64m" "-Xms64m"'
-
-# Collect all arguments for the java command;
-#   * $DEFAULT_JVM_OPTS, $JAVA_OPTS, and $GRADLE_OPTS can contain fragments of
-#     shell script including quotes and variable substitutions, so put them in
-#     double quotes to make sure that they get re-expanded; and
-#   * put everything else in single quotes, so that it's not re-expanded.
-
-set -- \
-        "-Dorg.gradle.appname=$APP_BASE_NAME" \
-        -classpath "$CLASSPATH" \
-        org.gradle.wrapper.GradleWrapperMain \
-        "$@"
-
-# Stop when "xargs" is not available.
-if ! command -v xargs >/dev/null 2>&1
-then
-    die "xargs is not available"
-fi
-
-# Use "xargs" to parse quoted args.
-#
-# With -n1 it outputs one arg per line, with the quotes and backslashes removed.
-#
-# In Bash we could simply go:
-#
-#   readarray ARGS < <( xargs -n1 <<<"$var" ) &&
-#   set -- "${ARGS[@]}" "$@"
-#
-# but POSIX shell has neither arrays nor command substitution, so instead we
-# post-process each arg (as a line of input to sed) to backslash-escape any
-# character that might be a shell metacharacter, then use eval to reverse
-# that process (while maintaining the separation between arguments), and wrap
-# the whole thing up as a single "set" statement.
-#
-# This will of course break if any of these variables contains a newline or
-# an unmatched quote.
-#
-
-eval "set -- $(
-        printf '%s\n' "$DEFAULT_JVM_OPTS $JAVA_OPTS $GRADLE_OPTS" |
-        xargs -n1 |
-        sed ' s~[^-[:alnum:]+,./:=@_]~\\&~g; ' |
-        tr '\n' ' '
-    )" '"$@"'
-
-exec "$JAVACMD" "$@"
diff --git a/studio-dev/ManagedProvisioningGradleProject/platform-compat/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/platform-compat/build.gradle.kts
deleted file mode 100644
index 0d464adf..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/platform-compat/build.gradle.kts
+++ /dev/null
@@ -1,9 +0,0 @@
-plugins {
-    java
-}
-
-sourceSets {
-    main {
-        java.setSrcDirs(listOf("java"))
-    }
-}
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/platform-compat/java/android/compat/annotation b/studio-dev/ManagedProvisioningGradleProject/platform-compat/java/android/compat/annotation
deleted file mode 120000
index 17491d13..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/platform-compat/java/android/compat/annotation
+++ /dev/null
@@ -1 +0,0 @@
-../../../../../../../../../tools/platform-compat/java/android/compat/annotation
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/push-apk.sh b/studio-dev/ManagedProvisioningGradleProject/push-apk.sh
deleted file mode 100755
index 78711491..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/push-apk.sh
+++ /dev/null
@@ -1,75 +0,0 @@
-# Script to install SystemUI apk in system partition
-APK_FILE="$1"
-if [ -n "$2" ]; then
-  export ANDROID_SERIAL="$2"
-fi
-
-# TODO(b/234033515): Device list info does not yet contain adb server port
-# You might need to manually set this environment variable if you changed the adb server port in
-# the Android Studio settings:
-#export ANDROID_ADB_SERVER_PORT=
-
-if [ -z "$APK_FILE" ]; then
-    echo "Apk file not specified. Using default SystemUI-google-debug.apk"
-    SCRIPT_DIR="$(cd $(dirname $0) && pwd)"
-    BUILD_DIR="$SCRIPT_DIR/../../../../../../out/gradle/build/SysUIGradleProject/SystemUI/build"
-    APK_FILE="$BUILD_DIR/intermediates/apk/google/debug/SystemUI-google-debug.apk"
-fi
-
-echo "ANDROID_SERIAL=$ANDROID_SERIAL"
-echo "APK_FILE=$APK_FILE"
-
-if [ ! -f "$APK_FILE" ]; then
-    echo "Compiled APK not found $APK_FILE" > /dev/stderr
-    exit 1
-fi
-
-adb root || exit 1
-adb wait-for-device
-
-VERITY_ENABLED="$(adb shell getprop | grep 'partition.*verified')"
-if [ -n "$VERITY_ENABLED" ]; then
-    echo "Disabling verity and rebooting"
-    adb disable-verity
-    adb reboot
-
-    echo "Waiting for device"
-    adb wait-for-device root
-    adb wait-for-device
-fi
-
-adb remount
-
-TARGET_PATH="$(adb shell pm path com.android.systemui | cut -d ':' -f 2)"
-if [ -z "$TARGET_PATH" ]; then
-    echo "Unable to get apk path: $TARGET_PATH]" > /dev/stderr
-    exit 1
-fi
-
-echo "Pushing apk to device at $TARGET_PATH"
-adb push "$APK_FILE" "$TARGET_PATH"
-adb shell fsync "$TARGET_PATH"
-
-# Restart the system, then wait up to 60 seconds for 'adb shell dumpsys package' to become available
-echo "Restarting the system..."
-adb shell 'stop ; start'
-sleep 2
-MAX_TRIES=29
-N=0
-while [[ "$N" -lt "$MAX_TRIES" && -z "$(adb shell dumpsys package com.android.systemui 2>&1 | grep versionName)" ]]; do
-    sleep 2
-    N="$((N+1))"
-done
-
-if [[ "$N" -ge "$MAX_TRIES" ]]; then
-    echo "Timed out waiting for package service. Failed to run 'adb shell dumpsys package'."
-    exit 1
-fi
-
-VERSION="$(adb shell dumpsys package com.android.systemui 2>&1 | grep versionName)"
-if [[ "$VERSION" == *"BuildFromAndroidStudio"* ]]; then
-    echo "Install complete"
-else
-    echo "Installation verification failed. Package versionName does not contain \"BuildFromAndroidStudio\" as expected."
-    exit 1
-fi
diff --git a/studio-dev/ManagedProvisioningGradleProject/settings.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/settings.gradle.kts
deleted file mode 100644
index 91c73544..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/settings.gradle.kts
+++ /dev/null
@@ -1,267 +0,0 @@
-pluginManagement {
-  repositories {
-    mavenCentral()
-    google()
-    gradlePluginPortal()
-  }
-}
-
-val ANDROID_RELATIVE_TOP = extra["ANDROID_RELATIVE_TOP"].toString()
-val ACETONE_LIB_CITC_CLIENT = extra["ACETONE_LIB_CITC_CLIENT"].toString()
-
-dependencyResolutionManagement {
-  repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
-  rulesMode = RulesMode.FAIL_ON_PROJECT_RULES
-
-  repositories {
-    maven {
-      name = "prebuilts/sdk/current/androidx/m2repository"
-      url = uri("${ANDROID_RELATIVE_TOP}/prebuilts/sdk/current/androidx/m2repository")
-    }
-    maven {
-      name = "prebuilts/sdk/current/androidx-legacy/m2repository"
-      url = uri("${ANDROID_RELATIVE_TOP}/prebuilts/sdk/current/androidx-legacy/m2repository")
-    }
-    maven {
-      name = "prebuilts/misc/common/androidx-test"
-      url = uri("${ANDROID_RELATIVE_TOP}/prebuilts/misc/common/androidx-test")
-    }
-    maven {
-      name = "prebuilts/sdk/current/extras/material-design-x"
-      url = uri("${ANDROID_RELATIVE_TOP}/prebuilts/sdk/current/extras/material-design-x")
-    }
-    maven {
-      name = "vendor/unbundled_google/packages/PrebuiltGmsCore/v17/m2repo-1p"
-      url =
-        uri("${ANDROID_RELATIVE_TOP}/vendor/unbundled_google/packages/PrebuiltGmsCore/v17/m2repo-1p")
-    }
-    maven { url = uri("https://oss.sonatype.org/content/repositories/snapshots") }
-
-    mavenCentral {
-      content {
-        excludeGroupByRegex("androidx(\\..*)?")
-        excludeGroupByRegex("android(\\..*)?")
-        excludeGroupByRegex("com\\.android(\\..*)?")
-      }
-    }
-
-    google {
-      content {
-        // Needed by :WallpaperPickerGoogle:assembleGoogleDebug
-        includeVersion("androidx.legacy", "legacy-support-v4", "1.0.0")
-        includeVersion("android.arch.lifecycle", "runtime", "1.0.0")
-        includeVersion("android.arch.lifecycle", "common", "1.0.0")
-        includeVersion("android.arch.core", "common", "1.0.0")
-        // Needed by WallpaperPickerGoogle tests
-        includeModule("androidx.multidex", "multidex")
-        // Needed by ComposeGalleryLib:assemble
-        includeGroup("androidx.compose.compiler")
-        // Needed for compiling in Android Studio
-        includeGroupByRegex("com\\.android(\\..*)?")
-        includeGroupByRegex("com\\.google(\\..*)?")
-      }
-    }
-  }
-}
-
-val ANDROID_ROOT_DIR = file(rootDir).resolve("../../../../../")
-val androidTop = file(rootDir.getParent()).resolve("../../../../").getCanonicalPath()
-
-/**
- * Includes a module with a custom dir. Ignores the module if the directory does not exist.
- *
- * **Heads-up:** the project will **NOT** load if the project is not in the repo manifest of the
- * small branch.
- *
- * @param name: the project name to be included.
- * @params dir: the project directory child path, where parent is ANDROID_ROOT_DIR.
- */
-fun includeAndroidProject(name: String, dir: String) {
-  val projectRoot = file(ANDROID_ROOT_DIR).resolve(dir)
-  if (projectRoot.exists()) {
-    include(name)
-    project(name).projectDir = projectRoot
-  } else {
-    logger.lifecycle("Android project \"$name\" not found. Did you checkout it with repo? Expected location is \"${projectRoot.path}\".")
-  }
-}
-
-/**
- * Includes a module with a modified root where the build.gradle.kts file is still stored near the
- * root of this project. This is useful so that you don"t need to specify relative paths in the
- * project"s build.gradle.kts file.
-
- * @param projectName = The name of a module that has a build.gradle.kts in an empty dir, for example
- *                 "AiAi" would represent AiAi/build.gradle.kts
- * @param projectRoot = The path to the project relative to ANDROID_BUILD_TOP. This will be set as
- *                 the project"s projectDir
- */
-fun includeProject(projectName: String, projectRoot: String) {
-  val projectId = ":$projectName"
-  include(projectId)
-  val projectDescriptor = project(projectId)
-  val pathToBuildFile = projectDescriptor.buildFile.canonicalFile
-  projectDescriptor.projectDir = file(androidTop).resolve(projectRoot)
-  projectDescriptor.buildFileName = pathToBuildFile.toRelativeString(projectDescriptor.projectDir)
-}
-
-// Enable the project below if trying to debug platform code
-// include ":PlatformCode"
-
-// includeAndroidProject(":IconLoader", "frameworks/libs/systemui/iconloaderlib")
-//
-// include(":SettingsLibDeviceState")
-// include(":SettingsLibWidget")
-// include(":SettingsLibColor")
-// include(":SettingsLibUtils")
-// include(":SettingsLib")
-// include(":WifiTrackerLib")
-include(":ModuleUtils")
-//
-// include(":PlatformAnimationLibrary")
-// include(":ComposeCoreLib")
-// include(":ComposeFeaturesLib")
-// include(":ComposeGalleryLib")
-// include(":ComposeGallery")
-// include(":ComposeTestingLib")
-// include(":ComposeSceneTransitionLayoutLib")
-// include(":ComposeSceneTransitionLayoutDemoLib")
-// include(":ComposeSceneTransitionLayoutDemo")
-// include(":CustomizationLib")
-// include(":SharedLib")
-// include(":SharedTestLib")
-// include(":tracinglib")
-include(":platform-compat")
-//
-// include(":SettingsLibActionBarShadow")
-// include(":SettingsLibActionButtonsPreference")
-// include(":SettingsLibActivityEmbedding")
-// include(":SettingsLibAdaptiveIcon")
-// include(":SettingsLibAppPreference")
-// include(":SettingsLibBannerMessagePreference")
-// include(":SettingsLibBarChartPreference")
-// include(":SettingsLibButtonPreference")
-// include(":SettingsLibCollapsingToolbarBaseActivity")
-// include(":SettingsLibEntityHeaderWidgets")
-// include(":SettingsLibFooterPreference")
-// include(":SettingsLibHelpUtils")
-// include(":SettingsLibIllustrationPreference")
-// include(":SettingsLibLayoutPreference")
-// include(":SettingsLibMainSwitchPreference")
-// include(":SettingsLibProfileSelector")
-// include(":SettingsLibProgressBar")
-// include(":SettingsLibRestrictedLockUtils")
-// include(":SettingsLibSearchWidget")
-// include(":SettingsLibSelectorWithWidgetPreference")
-// include(":SettingsLibSettingsSpinner")
-// include(":SettingsLibSettingsTheme")
-// include(":SettingsLibSettingsTransition")
-// include(":SettingsLibTile")
-// include(":SettingsLibTopIntroPreference")
-// include(":SettingsLibTwoTargetPreference")
-// include(":SettingsLibUsageProgressBarPreference")
-//
-// include(":SystemUI-res")
-// include(":sysuig-resources")
-//
-// includeProject("SystemUISharedLib-Keyguard", "frameworks/base/packages/SystemUI/shared/keyguard")
-// include(":UiAutomatorHelpersLib")
-// include(":UnfoldLib")
-// include(":PixelAtoms")
-// include(":WMShell")
-// include(":WMShellFlags")
-// include(":WMShellFlicker")
-// include(":PlatformProtosNano")
-// include(":FlickerLibParsers")
-// include(":PerfettoProtos")
-// include(":LayersProtosLight")
-// include(":AiAiUi")
-// include(":LowLightDreamLib")
-// include(":BcSmartspace")
-// include(":SystemUIChecks")
-// include(":SystemUIClocks")
-// include(":SystemUICommon")
-// include(":SystemUIPlugins")
-include(":FrameworkFlags")
-include(":ManagedProvisioning")
-// include(":SystemUILogLib")
-// include(":PlatformParameterizedLib")
-// include(":SystemUIScreenshotLib")
-// include(":SystemUIScreenshotViewUtilsLib")
-// include(":SystemUIScreenshotBiometricsTestsLib")
-// include(":SystemUITestUtils")
-// include(":SystemUI")
-// include(":SystemUIFlags")
-// include(":NotificationFlags")
-// include(":SystemUISharedFlags")
-// include(":SystemUI-statsd")
-// include(":BiometricsSharedLib")
-//
-// //Robolectric Locations:
-include(":RobolectricLib")       // Contains a Robolectric android-all SdkProvider that downloads from the Google CI systems
-//
-include(":setupcompat")
-include(":setupdesign")
-include(":setupdesign-strings")
-include(":setupdesign-lottie-loading-layout")
-//
-// includeAndroidProject(":LauncherQsTiles", "vendor/unbundled_google/libraries/launcherqstiles")
-// includeAndroidProject(":SearchUi", "vendor/unbundled_google/libraries/searchuilib")
-// includeAndroidProject(":ViewCaptureLib", "frameworks/libs/systemui/viewcapturelib")
-// includeAndroidProject(":MotionToolLib", "frameworks/libs/systemui/motiontoollib")
-// includeAndroidProject(":AnimationLibrary", "frameworks/libs/systemui/animationlib")
-// includeAndroidProject(":NexusLauncher", "vendor/unbundled_google/packages/NexusLauncher")
-// includeAndroidProject(":WallpaperPickerGoogle", "vendor/unbundled_google/packages/WallpaperPickerGoogle")
-//
-// include(":Monet")
-// include(":MonetLib")
-// include(":ScreenshotLib")
-//
-// if (ACETONE_LIB_CITC_CLIENT.isNotBlank()) {
-//     includeAndroidProject(":OverlayLib", "vendor/unbundled_google/packages/Launcher3/overlaylib")
-// }
-//
-// includeAndroidProject(":TitanSysuiConfigOverlay", "vendor/google/nexus_overlay/TitanSysuiConfigOverlay")
-//
-// // Sysui and launcher e2e tests projects:
-// include(":PlatformScenarioTestsLib")
-// include(":PlatformScenarioTests")
-// include(":PlatformTestingAnnotations")
-// include(":UiTestsLibLauncher")
-//
-// include(":SystemUIRoboScreenshotLib")
-//
-// // For trunk stable flags testing.
-// include(":PlatformTestingFlagHelper")
-//
-// // Uncomment this for DockSetup app
-// // include(":DockSetup")
-//
-// // Uncomment this for OneSearch Plugin app
-// // include(":OneSearch")
-// // project(":OneSearch").projectDir = file(rootDir).resolve("../../../NexusLauncher/plugins/OneSearchPlugin")
-//
-// // Uncomment this for Launcher Support app.
-// // When enabling this also set enableJetifier to false in gradle.properties
-// // include(":SupportApp")
-// // project(":SupportApp").projectDir = file(rootDir).resolve("../../../Launcher3/supportApp")
-//
-// // Slim Launcher used for developing an alternate Launcher+Overview experience
-// include(":SlimLauncher")
-// project(":SlimLauncher").projectDir = file(rootDir).resolve("../../../Launcher3/SlimLauncher")
-
-include(":android_onboarding.bedsteadonboarding.data")
-include(":android_onboarding.bedsteadonboarding.permissions")
-include(":android_onboarding.bedsteadonboarding.providers")
-include(":android_onboarding.bedsteadonboarding.contract_eligibility_checker")
-include(":android_onboarding.bedsteadonboarding.contractutils")
-include(":android_onboarding.common")
-include(":android_onboarding.common.annotations")
-include(":android_onboarding.contracts")
-include(":android_onboarding.contracts.annotations")
-include(":android_onboarding.contracts.provisioning")
-include(":android_onboarding.contracts.setupwizard")
-include(":android_onboarding.contracts.testing")
-include(":android_onboarding.flags")
-include(":android_onboarding.flags_hilt")
-include(":android_onboarding.nodes")
\ No newline at end of file
diff --git a/studio-dev/ManagedProvisioningGradleProject/setupcompat/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/setupcompat/build.gradle.kts
deleted file mode 100644
index 54a95680..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/setupcompat/build.gradle.kts
+++ /dev/null
@@ -1,46 +0,0 @@
-/**
- * This is a copy of external/setupcompat/build.gradle tailored for the library"s inclusion in
- * sysui studio builds.
- */
-
-plugins {
-    id("com.android.library")
-    id("org.jetbrains.kotlin.android")
-}
-
-val top = extra["ANDROID_TOP"].toString()
-
-android {
-    namespace = "com.google.android.setupcompat"
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-            proguardFiles(getDefaultProguardFile("proguard-android.txt"), "$top/external/setupcompat/proguard.flags")
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            manifest.srcFile("$top/external/setupcompat/AndroidManifest.xml")
-            java.srcDirs(listOf(
-                    "$top/external/setupcompat/main/java",
-                "$top/external/setupcompat/partnerconfig/java",
-            ))
-            aidl.srcDirs(listOf("$top/external/setupcompat/main/aidl"))
-            res.srcDirs(listOf("$top/external/setupcompat/main/res"))
-        }
-    }
-    buildFeatures {
-        aidl = true
-    }
-    kotlinOptions {
-        jvmTarget = "17"
-    }
-}
-
-dependencies {
-    implementation(libs.androidx.annotation)
-    implementation(libs.errorprone.annotations)
-    implementation(libs.androidx.window)
-    implementation("androidx.core:core-ktx:+")
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/setupdesign-lottie-loading-layout/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/setupdesign-lottie-loading-layout/build.gradle.kts
deleted file mode 100644
index 8313de98..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/setupdesign-lottie-loading-layout/build.gradle.kts
+++ /dev/null
@@ -1,42 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/setupdesign/lottie_loading_layout.
- * There are certain classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-  id("com.android.library")
-    id("org.jetbrains.kotlin.android")
-}
-
-val top = extra["ANDROID_TOP"].toString()
-
-android {
-  namespace = "com.google.android.setupdesign.lottieloadinglayout"
-  defaultConfig {
-    vectorDrawables.useSupportLibrary = true
-  }
-
-  buildTypes {
-    release {
-      isMinifyEnabled = false
-    }
-  }
-
-  sourceSets {
-    sourceSets.getByName("main") {
-      manifest.srcFile("$top/external/setupdesign/lottie_loading_layout/AndroidManifest.xml")
-      java.srcDirs(listOf("src", "$top/external/setupdesign/lottie_loading_layout/src"))
-      res.srcDirs(listOf("$top/external/setupdesign/lottie_loading_layout/res"))
-    }
-  }
-    kotlinOptions {
-        jvmTarget = "17"
-    }
-}
-
-dependencies {
-  api(libs.androidx.annotation)
-  api(project(":setupcompat"))
-  api(project(":setupdesign"))
-  api(libs.com.airbnb.android.lottie)
-    implementation("androidx.core:core-ktx:+")
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/setupdesign-strings/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/setupdesign-strings/build.gradle.kts
deleted file mode 100644
index 8eda8106..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/setupdesign-strings/build.gradle.kts
+++ /dev/null
@@ -1,31 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/setupdesign. There are certain
- * classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id("com.android.library")
-    id("org.jetbrains.kotlin.android")
-}
-
-val top = extra["ANDROID_TOP"].toString()
-
-android {
-    namespace = "com.google.android.setupdesign.strings"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            manifest.srcFile("$top/external/setupdesign/strings/AndroidManifest.xml")
-            res.srcDirs(listOf("$top/external/setupdesign/strings/res"))
-        }
-    }
-    kotlinOptions {
-        jvmTarget = "17"
-    }
-}
-
-dependencies {
-    implementation("androidx.core:core-ktx:+")
-}
diff --git a/studio-dev/ManagedProvisioningGradleProject/setupdesign/build.gradle.kts b/studio-dev/ManagedProvisioningGradleProject/setupdesign/build.gradle.kts
deleted file mode 100644
index 0af117bc..00000000
--- a/studio-dev/ManagedProvisioningGradleProject/setupdesign/build.gradle.kts
+++ /dev/null
@@ -1,49 +0,0 @@
-/**
- * This is an adaptation of the build.gradle found in external/setupdesign. There are certain
- * classes that must be modified in order to work with the sysui studio build.
- */
-plugins {
-    id("com.android.library")
-    id("org.jetbrains.kotlin.android")
-}
-
-val top = extra["ANDROID_TOP"].toString()
-
-android {
-    namespace = "com.google.android.setupdesign"
-    defaultConfig {
-        vectorDrawables.useSupportLibrary = true
-    }
-
-    buildTypes {
-        release {
-            isMinifyEnabled = false
-            proguardFiles(getDefaultProguardFile("proguard-android.txt"), "$top/external/setupdesign/proguard.flags")
-        }
-    }
-
-    sourceSets {
-        sourceSets.getByName("main") {
-            manifest.srcFile("$top/external/setupdesign/main/AndroidManifest.xml")
-            java.srcDirs(listOf("src", "$top/external/setupdesign/main/src"))
-            res.srcDirs(listOf("$top/external/setupdesign/main/res"))
-        }
-    }
-    kotlinOptions {
-        jvmTarget = "17"
-    }
-}
-
-dependencies {
-    api(libs.androidx.annotation)
-    api(libs.androidx.appcompat)
-    api(libs.androidx.core)
-    api(libs.androidx.legacy.support.core.ui)
-    api(libs.androidx.recyclerview)
-    api(libs.androidx.window)
-    api(libs.com.google.android.material)
-    api(libs.errorprone.annotations)
-    api(project(":setupcompat"))
-    api(project(":setupdesign-strings"))
-    implementation("androidx.core:core-ktx:+")
-}
\ No newline at end of file
diff --git a/studio-dev/README.md b/studio-dev/README.md
deleted file mode 100644
index 69ca2b27..00000000
--- a/studio-dev/README.md
+++ /dev/null
@@ -1,217 +0,0 @@
-## SystemUI in Android Studio (internal documentation)
-
-```sh
-$ ./packages/apps/ManagedProvisioning/studio-dev/studiow
-```
-
-### Setup
-- Run this command from the root of the initialized repo directory to start android studio
-```sh
-$ ./packages/apps/ManagedProvisioning/studio-dev/studiow
-```
-- Make changes and run `SystemUI` run configuration from Android Studio (or `SystemUITitan` when working with tablets). This configuration for system UI injects custom shell function to remount and replace the apk instead of using pm install, using a different run configuration will not work.
-
-##### -studio branch (useful for mac)
-You can alternatively checkout the sysui-studio repo branch `xxx-sysui-studio-dev` (e.g.: [master-sysui-studio-dev](https://goto.google.com/repo-init/master-sysui-studio-dev). This tracks the same git branches as the corresponding `xxx` branch but with minimal dependencies.
-Command line `make` will not work on this branch as it only tracks a small number of projects to keep the checkout as small as possible (as of late 2022: 55G with [partial clones](https://goto.google.com/git-reaper) of all repositories).
-
-### First run
-- Make sure to have the rooted device connected. The script pulls the dex files from the device and decompiles them to create an SDK with hidden APIs.
-- If import settings dialog shows up in Android Studio, select do-not import.
-- If sdk wizard shows up, cancel and select never run in future.
-- If the project do not open (happens when sdk wizard shows up), close Android Studio and run `studiow` again.
-- First time you install systemUI, you might need to
-  - run 'adb disable-verity' (which requires a reboot)
-  - reboot your device for dexopt to kick in
-
-### Running tests
-You should be able to run instrumented tests in AndroidStudio using `SystemUI` configuration.
-
-### Updating SDK
-If after a sync, you are unable to compile, it's probably because some API in framework changed and
-you need to update your SDK. Depending on how you checked out your tree, there are two ways to
-update the SDK. In either case, you should pass the `--update-sdk` flag.
-
-For a minimal studiow-dev checkout, the SDK must be pulled from the device. Flash your device with
-latest image (corresponding to the tree you are working on) from [Flashstation](http://go/flash) and
-update the sdk using the `--update-sdk` flag:
-
-```sh
-$ ./packages/apps/ManagedProvisioning/studio-dev/studiow --update-sdk
-```
-
-For a platform checkout, you have the option to use the built SDK from your tree's out/ directory.
-This SDK exists if you've previously built with `m`. The script will prefer to use the built SDK if
-it exists, otherwise it will attempt to pull the SDK from the attached device. You can pass
-`--pull-sdk` to override this behavior and _always_ pull the SDK from the attached device, whether
-or not the built SDK exists.
-
-For example:
- - If you are using a sysui-studio checkout, it will always pull the SDK from the attached device.
- - If you are using a platform checkout which you've never built, it will pull the SDK from the
-   attached device.
- - If you are using a platform checkout which you've built with `m`, it will use the SDK from the
-   out/ directory. However, in this scenario, if you wanted to use the SDK from the attached device
-   instead you can pass `--pull-sdk`.
-
-### Adding dependencies
-
-When you add new dependencies to SystemUI (Android.bp files), they will also need to be added
-in the sysui-studio gradle files in SysUIGradleProject/ before they are available in your project.
-These dependencies should stay in sync - don't add dependencies to Gradle that aren't in Soong.
-
-## FAQ / Helpful info
-
-This project is using android studio + gradle as a build system, and as such it can be tricky to bootstrap for a first time set up or after a sync. This section is for some common problem/solution pairs we run into and also some general things to try.
-
-#### We have both flavors, country _and_ western
-
-Remember that this project can be run from a full platform checkout **or** a minimal studio-dev checkout.
-
-#### Make sure the sdk is updated after a sync
-
- `./studiow --update-sdk` is your friend.
-
- We pull the framework.jar (&friends) from the device and do some `<magic>` to compile against hidden framework APIs. Therefore, you have to build and flash the device to be current, and then pull the resulting jars from the device using the above command.
-
- > NOTE: if you're using the studio-dev branch (minimal checkout), then you want to ensure that the device image is as close in time to your local checkout as possible. You'll want to flash the device to the most recent possible build when you do a sync. Platform builds will always be in lock-step so long as you build after syncing.
-
-#### Android sdk choice
-
-Android Studio shouldn't ask you to choose which Android SDK to use and will instead select the
-right SDK automatically. But, [if it does ask](https://screenshot.googleplex.com/AtA62tTRyKWiSWg),
-choose the **project** SDK (likely in the `.../<branchname>/prebuilts/fullsdk-linux` directory),
-**not** the Android SDK (likely in the `.../<username>/Android/Sdk` directory).
-
-#### Javac `@IntDef`s compiler error
-
-You will find `@IntDef` clauses all over the platform. It sometimes works in ASwB-studio but breaks the build at sysui-studio-dev. The reason is `Java 8 javac` has some issue to deal with this but not `Java 9 javac`. The workaround solution would be to avoid the static imports.
-
-Build errors (cannot find symbol @IntDef) in Java 8 javac:
-```
-import static com.example.myapplication.MainActivity.LockTypes.PASSWORD;
-import static com.example.myapplication.MainActivity.LockTypes.PIN;
-import static com.example.myapplication.MainActivity.LockTypes.PATTERN;
-
-@IntDef({
-        PASSWORD,
-        PIN,
-        PATTERN
-})
-@interface LockTypes {
-    int PASSWORD = 0;
-    int PIN = 1;
-    int PATTERN = 2;
-}
-```
-
-Workaround to avoid the static imports:
-```
-@IntDef({
-        LockTypes.PASSWORD,
-        LockTypes.PIN,
-        LockTypes.PATTERN
-})
-@interface LockTypes {
-    int PASSWORD = 0;
-    int PIN = 1;
-    int PATTERN = 2;
-}
-```
-You could find more details discussion
-[here](https://buganizer.corp.google.com/issues/67418397).
-
-#### Some other things to think about:
-
-1. Build > clean project
-2. File > Invalidate caches & restart
-
-#### Android Studio is not launching
-
-If Android Studio fails to start when running studio wrapper you can try to launch the binary directly to see more logs.
-
-After running studio wrapper once you can find the binary in `~/.AndroidStudioSystemUI` directory. For example, on macOS it may look like this:
-
-```
-/Users/{{USERNAME}}/.AndroidStudioSystemUI/bin/android-studio-ide-201.6953283-mac/Android Studio.app/Contents/MacOS/studio
-```
-
-One of the issues that you may encounter is merging studio.vmoptions from different Android Studio installations that result into conflicting options.
-
-You may see something similar to this in the logs:
-
-```
-...
-2021-06-02 13:58:37.069 studio[20732:221422] Processing VMOptions file at /Users/{{USERNAME}}/.AndroidStudioSystemUI/bin/android-studio-ide-201.6953283-mac/Android Studio.app/Contents/bin/studio.vmoptions
-2021-06-02 13:58:37.070 studio[20732:221422] Done
-2021-06-02 13:58:37.070 studio[20732:221422] Processing VMOptions file at /Users/{{USERNAME}}/Library/Application Support/Google/AndroidStudio4.1/studio.vmoptions
-2021-06-02 13:58:37.070 studio[20732:221422] Done
-2021-06-02 13:58:37.070 studio[20732:221422] Processing VMOptions file at
-2021-06-02 13:58:37.072 studio[20732:221422] No content found
-Conflicting collector combinations in option list; please refer to the release notes for the combinations allowed
-2021-06-02 13:58:37.079 studio[20732:221422] JNI_CreateJavaVM (/Users/{{USERNAME}}/.AndroidStudioSystemUI/bin/android-studio-ide-201.6953283-mac/Android Studio.app/Contents/jre/jdk) failed: 4294967295
-```
-
-To resolve this you can remove all other Android Studio installations (including `Application Support/Google/AndroidStudio*` directories) and re-launch the wrapper.
-
-If the logs show an error similar to:
-
-```
-Error opening zip file or JAR manifest missing : ../plugins/g3plugins/bin/FileProfilingAgent.jar
-Error occurred during initialization of VM
-agent library failed to init: instrument
-```
-
-you can edit the file
-
-```
-/Users/{{USERNAME}}/Library/Application\ Support/Google/AndroidStudio2021.2/studio.vmoptions
-```
-
-and comment out the line
-
-```
-# -javaagent:../plugins/g3plugins/bin/FileProfilingAgent.jar
-```
-
-and try launching as normal.
-
-
-#### Enable hidden projects
-
-Some projects are hidden in Android Studio (the support app, platform code, and the one search plugin). To enable these projects for debugging and building, for example, the One Search Plugin, you need to uncomment it in `packages/apps/ManagedProvisioning/studio-dev/SysUIGradleProject/settings.gradle` for these lines:
-
-```
-// Uncomment this for OneSearch Plugin app
-// include ':OneSearch'
-// project(':OneSearch').projectDir = new File(rootDir,'../../../NexusLauncher/plugins/OneSearchPlugin')
-```
-
-After syncing gradle, the project should show up in Configurations in Android Studio. You might also need to update the configuration for some projects.
-
-#### Kotlin compiler errors
-
-Sometimes Android Studio encounters a version error when resolving the Kotlin compiler, due to version mismatches.
-To fix this, add `-Xskip-prerelease-check` to the ["Additional command line arguments"](https://screenshot.googleplex.com/5h3FUEx5vjuazD9)
-in the "Kotlin compiler" section of Settings.
-
-#### KVM enabled for CRD
-
-If you are using Chrome remote desktop and see an error like:
-
-```
-Setting up SDK from scratch
-Found ADB at /path/to/adb
-Updating framework.aidl file at: /path/to/framework.aidl
-Updating private apis sdk
-restarting adbd as root
-adb: error: connect failed: closed
-
-```
-
-you might need to enable kvm with the following command:
-
-```
-sudo setfacl -m u:${USER}:rw /dev/kvm
-```
-
diff --git a/studio-dev/StubGenerator/.gitignore b/studio-dev/StubGenerator/.gitignore
deleted file mode 100644
index 76d4b558..00000000
--- a/studio-dev/StubGenerator/.gitignore
+++ /dev/null
@@ -1,9 +0,0 @@
-.gradle/*
-gradle/*
-gradlew*
-local.properties
-.idea/*
-
-**/*.iml
-**/.DS_Store
-**/build/*
diff --git a/studio-dev/StubGenerator/StubGenerator.jar b/studio-dev/StubGenerator/StubGenerator.jar
deleted file mode 100644
index e4410455..00000000
Binary files a/studio-dev/StubGenerator/StubGenerator.jar and /dev/null differ
diff --git a/studio-dev/StubGenerator/build.gradle.kts b/studio-dev/StubGenerator/build.gradle.kts
deleted file mode 100644
index bf16ddd3..00000000
--- a/studio-dev/StubGenerator/build.gradle.kts
+++ /dev/null
@@ -1,33 +0,0 @@
-plugins {
-  java
-}
-
-//create a single Jar with all dependencies
-tasks {
-  register<Jar>("fatJar") {
-    manifest {
-      attributes(
-        mapOf(
-          "Main-Class" to "com.android.development.SdkGenerator"
-        )
-      )
-    }
-    archiveClassifier = "all"
-    from(configurations.compileClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
-    with(jar.get())
-  }
-}
-
-repositories {
-  mavenCentral()
-}
-
-dependencies {
-  implementation("org.smali:dexlib2:2.2.7")
-  implementation("org.ow2.asm:asm:7.0")
-}
-
-java {
-  sourceCompatibility = JavaVersion.VERSION_1_8
-  targetCompatibility = JavaVersion.VERSION_1_8
-}
diff --git a/studio-dev/StubGenerator/src/main/java/com/android/development/DexToStubConverter.java b/studio-dev/StubGenerator/src/main/java/com/android/development/DexToStubConverter.java
deleted file mode 100644
index d5a34d15..00000000
--- a/studio-dev/StubGenerator/src/main/java/com/android/development/DexToStubConverter.java
+++ /dev/null
@@ -1,539 +0,0 @@
-package com.android.development;
-
-
-import static org.jf.dexlib2.AccessFlags.PUBLIC;
-import static org.jf.dexlib2.AccessFlags.STATIC;
-
-import org.jf.dexlib2.Opcode;
-import org.jf.dexlib2.ReferenceType;
-import org.jf.dexlib2.ValueType;
-import org.jf.dexlib2.dexbacked.DexBackedClassDef;
-import org.jf.dexlib2.dexbacked.DexBackedField;
-import org.jf.dexlib2.dexbacked.DexBackedMethod;
-import org.jf.dexlib2.iface.Annotatable;
-import org.jf.dexlib2.iface.Annotation;
-import org.jf.dexlib2.iface.AnnotationElement;
-import org.jf.dexlib2.iface.Member;
-import org.jf.dexlib2.iface.MethodParameter;
-import org.jf.dexlib2.iface.instruction.Instruction;
-import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
-import org.jf.dexlib2.iface.reference.FieldReference;
-import org.jf.dexlib2.iface.value.AnnotationEncodedValue;
-import org.jf.dexlib2.iface.value.ArrayEncodedValue;
-import org.jf.dexlib2.iface.value.BooleanEncodedValue;
-import org.jf.dexlib2.iface.value.ByteEncodedValue;
-import org.jf.dexlib2.iface.value.CharEncodedValue;
-import org.jf.dexlib2.iface.value.DoubleEncodedValue;
-import org.jf.dexlib2.iface.value.EncodedValue;
-import org.jf.dexlib2.iface.value.EnumEncodedValue;
-import org.jf.dexlib2.iface.value.FloatEncodedValue;
-import org.jf.dexlib2.iface.value.IntEncodedValue;
-import org.jf.dexlib2.iface.value.LongEncodedValue;
-import org.jf.dexlib2.iface.value.ShortEncodedValue;
-import org.jf.dexlib2.iface.value.StringEncodedValue;
-import org.jf.dexlib2.iface.value.TypeEncodedValue;
-import org.jf.dexlib2.immutable.value.ImmutableEncodedValueFactory;
-import org.objectweb.asm.AnnotationVisitor;
-import org.objectweb.asm.ClassWriter;
-import org.objectweb.asm.Label;
-import org.objectweb.asm.MethodVisitor;
-import org.objectweb.asm.Opcodes;
-import org.objectweb.asm.Type;
-
-import java.io.IOException;
-import java.io.PrintStream;
-import java.util.ArrayList;
-import java.util.Arrays;
-import java.util.Collection;
-import java.util.Collections;
-import java.util.HashMap;
-import java.util.HashSet;
-import java.util.List;
-import java.util.Set;
-import java.util.logging.Logger;
-import java.util.regex.Pattern;
-import java.util.stream.StreamSupport;
-import java.util.zip.ZipEntry;
-import java.util.zip.ZipOutputStream;
-
-/**
- * A converter which takes a dex file and creates a jar containing all the classes, and methods
- * and fields stubbed out.
- */
-public class DexToStubConverter {
-
-    private static final Logger LOGGER = Logger.getLogger(DexToStubConverter.class.toString());
-
-    private static final Pattern INNER_OR_LAMBDA = Pattern.compile("\\$[0-9\\$]");
-
-    private static final int STATIC_FINAL_CODE = Opcodes.ACC_STATIC | Opcodes.ACC_FINAL;
-    private static final int ABS_INTERFACE_CODE = Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE;
-
-    // Default dalvik annotations which store extra meta-data about the member
-    private static final String ANNOTATION_INNER_CLASS = "Ldalvik/annotation/InnerClass;";
-    private static final String ANNOTATION_DEFAULT_VALUE = "Ldalvik/annotation/AnnotationDefault;";
-    private static final String ANNOTATION_SIGNATURE = "Ldalvik/annotation/Signature;";
-    private static final String ANNOTATION_MEMBER_CLASS = "Ldalvik/annotation/MemberClasses;";
-    private static final String ANNOTATION_THROWS = "Ldalvik/annotation/Throws;";
-
-    private static final String INTERFACE_I_INTERFACE = "Landroid/os/IInterface;";
-
-    private static final String INTERFACE_PARCELABLE = "Landroid/os/Parcelable;";
-
-    private static final String FIELD_CREATOR_NAME = "CREATOR";
-    private static final String FIELD_CREATOR_TYPE = "Landroid/os/Parcelable$Creator;";
-
-    // Opcodes for operations that can be used in the static init block to initialize fields.
-    // Fields that are initialized in the static block should not get a default value assigned.
-    // These fields are not constants and get their value in runtime. Assigning a default value
-    // in the SDK would cause the compiler to inline these values. Skipping the runtime evaluation.
-    private static final HashSet<Opcode> STATIC_INIT_OPCODES = new HashSet<>(Arrays.asList(
-            Opcode.SPUT,
-            Opcode.SPUT_WIDE,
-            Opcode.SPUT_OBJECT,
-            Opcode.SPUT_BOOLEAN,
-            Opcode.SPUT_BYTE,
-            Opcode.SPUT_CHAR,
-            Opcode.SPUT_SHORT,
-            Opcode.SPUT_VOLATILE,
-            Opcode.SPUT_WIDE_VOLATILE,
-            Opcode.SPUT_OBJECT_VOLATILE
-    ));
-
-    // Map between parent class and subclass information
-    private final HashMap<String, InnerClassData> mInnerClassMap = new HashMap<>();
-    private final ZipOutputStream mOut;
-
-    // Look for dupes
-    private final HashSet<String> mZipEntries = new HashSet<>();
-
-    private int mNextLineNumber = 0;
-
-    private final HashSet<String> mParcelables = new HashSet<>();
-    private final HashSet<String> mInterfaces = new HashSet<>();
-
-    public DexToStubConverter(ZipOutputStream out) {
-        mOut = out;
-        mZipEntries.clear();
-    }
-
-    /**
-     * Initializes any subclass information about this class
-     */
-    public void expectClass(DexBackedClassDef classDef) {
-        String classDefType = classDef.getType();
-        if (INNER_OR_LAMBDA.matcher(classDefType).find()) {
-            return;
-        }
-
-        String className = typeToPath(classDefType);
-        int accessFlags = classDef.getAccessFlags();
-        for (AnnotationElement ae : findAnnotation(classDef, ANNOTATION_INNER_CLASS)) {
-            if ("accessFlags".equals(ae.getName())
-                    && ae.getValue().getValueType() == ValueType.INT) {
-                accessFlags = ((IntEncodedValue) ae.getValue()).getValue();
-            }
-        }
-
-        if (className.contains("$")) {
-            mInnerClassMap.put(className,  new InnerClassData(className, accessFlags));
-        } else {
-            List<String> interfaces = classDef.getInterfaces();
-            if (PUBLIC.isSet(accessFlags)) {
-                if (interfaces.contains(INTERFACE_I_INTERFACE)) {
-                    mInterfaces.add(Type.getType(classDefType).getClassName() + ";");
-                } else if (interfaces.contains(INTERFACE_PARCELABLE)) {
-                    if (StreamSupport.stream(classDef.getStaticFields().spliterator(), false)
-                            .filter(d -> PUBLIC.isSet(d.accessFlags)
-                                    && STATIC.isSet(d.accessFlags)
-                                    && FIELD_CREATOR_NAME.equals(d.getName())
-                                    && FIELD_CREATOR_TYPE.equals(d.getType()))
-                            .findFirst().isPresent()) {
-                        mParcelables.add(Type.getType(classDefType).getClassName() + ";");
-                    }
-                }
-            }
-        }
-    }
-
-    /**
-     * Parses a line from the aidl file and updates internal state accordingly
-     */
-    public void expectAidlDef(String def) {
-        String[] parts = def.split(" ");
-        if (parts.length < 2) {
-            return;
-        }
-        if ("parcelable".equals(parts[0].trim())) {
-            mParcelables.remove(parts[1].trim());
-        } else if ("interface".equals(parts[0].trim())) {
-            mInterfaces.remove(parts[1].trim());
-        }
-    }
-
-    /**
-     * Prints any missing aidl definitions to {@code out}
-     */
-    public void printInterfaces(PrintStream out) {
-        for (String s : mParcelables) {
-            out.println("parcelable " + s);
-        }
-        for (String s : mInterfaces) {
-            out.println("interface " + s);
-        }
-    }
-
-    /**
-     * Writes the class definition in the output stream
-     */
-    public String writeClass(DexBackedClassDef classDef) throws IOException {
-        mNextLineNumber = 0;
-        String classDefType = classDef.getType();
-        String className = typeToPath(classDefType);
-        String entryName = className + ".class";
-
-        if (INNER_OR_LAMBDA.matcher(classDefType).find()) {
-            LOGGER.fine("Skipping " + classDefType);
-            // TODO: return null?
-            return entryName;
-        }
-
-        Set<String> dependentInnerClasses = new HashSet<>();
-        dependentInnerClasses.add(className);
-
-        // TODO: Can skip private classes?
-        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
-        String[] interfaces = null;
-        List<String> interfaceList = classDef.getInterfaces();
-        if (!interfaceList.isEmpty()) {
-            interfaces = interfaceList.toArray(new String[interfaceList.size()]);
-            for (int i = 0; i < interfaces.length; i++) {
-                interfaces[i] = typeToPath(interfaces[i]);
-                dependentInnerClasses.add(interfaces[i]);
-            }
-        }
-
-        int accessCode = classDef.getAccessFlags();
-        if ((accessCode & ABS_INTERFACE_CODE) != ABS_INTERFACE_CODE) {
-            // Mark the class as open in case it is not an interface. This prevents inlining
-            // of constants
-            accessCode |= Opcodes.ACC_OPEN;
-        }
-
-        String superClass = typeToPath(classDef.getSuperclass());
-        cw.visit(Opcodes.V1_8,
-                accessCode,
-                className,
-                parseSignature(classDef),
-                superClass,
-                interfaces);
-        dependentInnerClasses.add(superClass);
-
-        if (classDef.getSourceFile() != null) {
-            cw.visitSource(classDef.getSourceFile(), null);
-        }
-
-        // If this is an annotation interface, get default values
-        HashMap<String, EncodedValue> defaultValues = null;
-        if ((classDef.getAccessFlags() & Opcodes.ACC_ANNOTATION) == Opcodes.ACC_ANNOTATION) {
-            defaultValues = new HashMap<>();
-            for (AnnotationElement ae :
-                    findAnnotation(classDef, ANNOTATION_DEFAULT_VALUE)) {
-                if (!(ae.getValue() instanceof AnnotationEncodedValue)) {
-                    continue;
-                }
-                AnnotationEncodedValue aev = (AnnotationEncodedValue) ae.getValue();
-                for (AnnotationElement aa : aev.getElements()) {
-                    defaultValues.put(aa.getName(), aa.getValue());
-                }
-            }
-        }
-
-        Set<String> staticallyInitializedFields = new HashSet<>();
-        // Write methods
-        for (DexBackedMethod method : classDef.getMethods()) {
-            if ("<clinit>".equals(method.getName())) {
-                for (Instruction i : method.getImplementation().getInstructions()) {
-                    if (STATIC_INIT_OPCODES.contains(i.getOpcode())
-                            && i instanceof ReferenceInstruction) {
-                        ReferenceInstruction ri = (ReferenceInstruction) i;
-                        if (ri.getReferenceType() == ReferenceType.FIELD) {
-                            FieldReference fr = (FieldReference) ri.getReference();
-                            if (classDefType.equals(fr.getDefiningClass())) {
-                                staticallyInitializedFields.add(fr.getName());
-                            }
-                        }
-                    }
-                }
-
-                // Ignore static blocks
-                continue;
-            }
-
-            // Skip private methods, but keep private constructor
-            if (!"<init>".equals(method.getName()) && isPrivate(method)) {
-                continue;
-            }
-            MethodParameter[] params = method.getParameters().stream().toArray(MethodParameter[]::new);
-            Type[] paramTypes = new Type[params.length];
-            for (int i = 0; i < paramTypes.length; i++) {
-                paramTypes[i] = Type.getType(params[i].getType());
-                dependentInnerClasses.add(typeToPath(params[i].getType()));
-            }
-            dependentInnerClasses.add(typeToPath(method.getReturnType()));
-
-            String descriptor = Type.getMethodDescriptor(Type.getType(method.getReturnType()), paramTypes);
-            String[] exception = getExceptionList(method);
-            MethodVisitor mv = cw.visitMethod(method.getAccessFlags(), method.getName(),
-                    descriptor, parseSignature(method), exception);
-
-            if ((method.getAccessFlags() & Opcodes.ACC_ABSTRACT) != Opcodes.ACC_ABSTRACT) {
-                mv.visitCode();
-                Label startLabel = addLabel(mv);
-
-                if ("<init>".equals(method.getName()) && classDef.getSuperclass() != null) {
-                    // Create constructor
-                    mv.visitVarInsn(Opcodes.ALOAD, 0);
-                    mv.visitMethodInsn(
-                            Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
-                }
-
-                insertThrowStub(mv);
-
-                Label endLabel = new Label();
-                mv.visitLabel(endLabel);
-                // Add param names
-                int shift = 0;
-                if ((method.getAccessFlags() & Opcodes.ACC_STATIC) != Opcodes.ACC_STATIC) {
-                    mv.visitLocalVariable("this", classDefType, null, startLabel, endLabel, 0);
-                    shift = 1;
-                }
-
-                for (int i = 0; i < params.length; i++) {
-                    String name = params[i].getName();
-                    if (name != null) {
-                        mv.visitLocalVariable(name,
-                                paramTypes[i].getDescriptor(), null, startLabel, endLabel,
-                                i + shift);
-                    }
-                }
-                mv.visitMaxs(3, shift + paramTypes.length);
-            }
-
-            if (defaultValues != null) {
-                EncodedValue ev = defaultValues.get(method.getName());
-                if (ev != null) {
-                    Object value = encodedValueToObject(ev);
-                    if (value != null) {
-                        AnnotationVisitor av = mv.visitAnnotationDefault();
-                        av.visit(null, value);
-                        av.visitEnd();
-                    } else if (ev.getValueType() == ValueType.ARRAY) {
-                        AnnotationVisitor av = mv.visitAnnotationDefault();
-                        av.visitArray(null);
-                        av.visitEnd();
-                    } else if (ev.getValueType() == ValueType.ENUM) {
-                        FieldReference fr = ((EnumEncodedValue) ev).getValue();
-                        AnnotationVisitor av = mv.visitAnnotationDefault();
-                        av.visitEnum(null, fr.getType(), fr.getName());
-                        av.visitEnd();
-                    } else if (ev.getValueType() == ValueType.ANNOTATION) {
-                        AnnotationVisitor av = mv.visitAnnotationDefault();
-                        av.visitAnnotation(null, ((AnnotationEncodedValue) ev).getType());
-                        av.visitEnd();
-                    } else {
-                        LOGGER.warning("Missing type parsing: " +
-                                classDefType + " " + method.getName() + " " + ev);
-                    }
-                }
-            }
-            mv.visitEnd();
-        }
-
-        // Write fields
-        for (DexBackedField field : classDef.getFields()) {
-            if (isPrivate(field)) {
-                continue;
-            }
-
-            Object value = staticallyInitializedFields.contains(field.getName())
-                    ? null : getFieldValue(field);
-
-            cw.visitField(field.getAccessFlags(), field.getName(),
-                    Type.getType(field.getType()).getDescriptor(),
-                    parseSignature(field),
-                    value)
-                .visitEnd();
-        }
-
-        // Inner classes
-        collectTypeNames(classDef, ANNOTATION_MEMBER_CLASS, dependentInnerClasses);
-        for (String dependentClass : dependentInnerClasses) {
-            InnerClassData icd = mInnerClassMap.get(dependentClass);
-            if (icd != null) {
-                icd.write(cw);
-            }
-        }
-
-        if (mZipEntries.add(entryName)) {
-            mOut.putNextEntry(new ZipEntry(entryName));
-            mOut.write(cw.toByteArray());
-            LOGGER.fine("Written " + className);
-        }
-        return entryName;
-    }
-
-    private Object getFieldValue(DexBackedField field) {
-        if ((field.getAccessFlags() & STATIC_FINAL_CODE) != STATIC_FINAL_CODE) {
-            return null;
-        }
-        EncodedValue value = field.getInitialValue();
-        if (value == null) {
-            value = ImmutableEncodedValueFactory.defaultValueForType(field.getType());
-        }
-        return encodedValueToObject(value);
-    }
-
-    private static Object encodedValueToObject(EncodedValue value) {
-        // TODO: Can probably support more types
-        switch (value.getValueType()) {
-            case ValueType.BYTE:
-                return ((ByteEncodedValue) value).getValue();
-            case ValueType.SHORT:
-                return ((ShortEncodedValue) value).getValue();
-            case ValueType.CHAR:
-                return ((CharEncodedValue) value).getValue();
-            case ValueType.INT:
-                return ((IntEncodedValue) value).getValue();
-            case ValueType.LONG:
-                return ((LongEncodedValue) value).getValue();
-            case ValueType.FLOAT:
-                return ((FloatEncodedValue) value).getValue();
-            case ValueType.DOUBLE:
-                return ((DoubleEncodedValue) value).getValue();
-            case ValueType.STRING:
-                return ((StringEncodedValue) value).getValue();
-            case ValueType.BOOLEAN:
-                return ((BooleanEncodedValue) value).getValue();
-            case ValueType.ANNOTATION:
-            case ValueType.TYPE:
-
-            default:
-                return null;
-        }
-    }
-
-    /**
-     * Returns the list of exceptions as type strings defined by the method or null
-     */
-    private String[] getExceptionList(DexBackedMethod method) {
-        ArrayList<String> out = new ArrayList<>();
-        collectTypeNames(method, ANNOTATION_THROWS, out);
-        if (out.isEmpty()) {
-            return null;
-        }
-        return out.toArray(new String[out.size()]);
-    }
-
-    private static void collectTypeNames(Annotatable annotatable, String type,
-            Collection<String> out) {
-        for (AnnotationElement e : findAnnotation(annotatable, type)) {
-            collectNames(e.getValue(), out);
-        }
-    }
-
-    /**
-     * Recursively collect names in the encoded value
-     */
-    private static void collectNames(EncodedValue ev, Collection<String> out) {
-        if (ev instanceof ArrayEncodedValue) {
-            ArrayEncodedValue aev = (ArrayEncodedValue) ev;
-            for (EncodedValue e : aev.getValue()) {
-                collectNames(e, out);
-            }
-        } else if (ev instanceof TypeEncodedValue) {
-            TypeEncodedValue dbtev = (TypeEncodedValue) ev;
-            out.add(typeToPath(dbtev.getValue()));
-        }
-    }
-
-    private String parseSignature(Annotatable annotatable) {
-        String s = null;
-        for (AnnotationElement el : findAnnotation(annotatable, ANNOTATION_SIGNATURE)) {
-            ArrayEncodedValue e = (ArrayEncodedValue) el.getValue();
-            for (EncodedValue ev : e.getValue()) {
-                if (s == null) {
-                    s = "";
-                }
-                s += ((StringEncodedValue) ev).getValue();
-            }
-        }
-        return s;
-    }
-
-    /**
-     * Inserts a throw statement in the method body
-     */
-    private void insertThrowStub(MethodVisitor mv) {
-        mv.visitTypeInsn(Opcodes.NEW, "java/lang/RuntimeException");
-        mv.visitInsn(Opcodes.DUP);
-        mv.visitLdcInsn("stub");
-        mv.visitMethodInsn(
-                Opcodes.INVOKESPECIAL,          // opcode
-                "java/lang/RuntimeException",   // owner
-                "<init>",                       // name
-                "(Ljava/lang/String;)V",        // desc
-                false);
-        mv.visitInsn(Opcodes.ATHROW);
-    }
-
-    private Label addLabel(MethodVisitor mv) {
-        mNextLineNumber += 5;
-        Label l = new Label();
-        mv.visitLabel(l);
-        mv.visitLineNumber(mNextLineNumber, l);
-        return l;
-    }
-
-    private static String typeToPath(String typeDesc) {
-        if (typeDesc == null) {
-            return null;
-        }
-        String name = Type.getType(typeDesc).getClassName();
-        return name.replace('.', '/');
-    }
-
-    private static boolean isPrivate(Member member) {
-        return (member.getAccessFlags() & Opcodes.ACC_PRIVATE) == Opcodes.ACC_PRIVATE;
-    }
-
-    private static Set<? extends AnnotationElement> findAnnotation(
-            Annotatable annotatable, String type) {
-        for (Annotation a : annotatable.getAnnotations()) {
-            if (type.equals(a.getType())) {
-                return a.getElements();
-            }
-        }
-        return Collections.emptySet();
-    }
-
-    private static final class InnerClassData {
-        final String className;
-        final String parent;
-        final String child;
-        final int code;
-
-        InnerClassData(String className, int code) {
-            this.className = className;
-            this.code = code;
-
-            int lastIndex = className.lastIndexOf('$');
-            parent = className.substring(0, lastIndex);
-            child = className.substring(lastIndex + 1, className.length());
-        }
-
-        public void write(ClassWriter cw) {
-            cw.visitInnerClass(className, parent, child, code);
-        }
-    }
-}
diff --git a/studio-dev/StubGenerator/src/main/java/com/android/development/ProgressBar.java b/studio-dev/StubGenerator/src/main/java/com/android/development/ProgressBar.java
deleted file mode 100644
index eb0479b6..00000000
--- a/studio-dev/StubGenerator/src/main/java/com/android/development/ProgressBar.java
+++ /dev/null
@@ -1,55 +0,0 @@
-package com.android.development;
-
-public class ProgressBar {
-
-    private final String mLabel;
-    private final long mMax;
-    private final Thread mThread;
-
-    private final Object lock = new Object();
-
-    private volatile int mCurPercent = 0;
-    private volatile boolean mRunning = true;
-
-    public ProgressBar(String label, long max) {
-        mLabel = label;
-        mMax = max;
-        mThread = new Thread(this::loop);
-        mThread.start();
-    }
-
-    public void update(long value) {
-        synchronized (lock) {
-            int p = (int) ((100 * value) / mMax);
-
-            if (p != mCurPercent) {
-                mCurPercent = p;
-                lock.notify();
-            }
-        }
-    }
-
-    public void finish() {
-        mRunning = false;
-        synchronized (lock) {
-            lock.notify();
-        }
-        try {
-            mThread.join();
-        } catch (InterruptedException e) { }
-    }
-
-    private void loop() {
-        while (mRunning) {
-            synchronized (lock) {
-                System.out.print('\r');
-                System.out.print(mLabel + ": " + mCurPercent + "%");
-                try {
-                    lock.wait();
-                } catch (InterruptedException e) { }
-            }
-        }
-        System.out.print('\r');
-        System.out.println(mLabel + ": Done");
-    }
-}
diff --git a/studio-dev/StubGenerator/src/main/java/com/android/development/SdkGenerator.java b/studio-dev/StubGenerator/src/main/java/com/android/development/SdkGenerator.java
deleted file mode 100644
index 761ee30e..00000000
--- a/studio-dev/StubGenerator/src/main/java/com/android/development/SdkGenerator.java
+++ /dev/null
@@ -1,150 +0,0 @@
-package com.android.development;
-
-import org.jf.dexlib2.DexFileFactory;
-import org.jf.dexlib2.dexbacked.DexBackedClassDef;
-import org.jf.dexlib2.dexbacked.DexBackedDexFile;
-import org.jf.dexlib2.iface.MultiDexContainer;
-
-import java.io.BufferedReader;
-import java.io.File;
-import java.io.FileInputStream;
-import java.io.FileOutputStream;
-import java.io.FileReader;
-import java.io.IOException;
-import java.io.InputStream;
-import java.io.OutputStream;
-import java.io.PrintStream;
-import java.nio.channels.FileChannel;
-import java.util.ArrayList;
-import java.util.HashSet;
-import java.util.List;
-import java.util.zip.ZipEntry;
-import java.util.zip.ZipInputStream;
-import java.util.zip.ZipOutputStream;
-
-public class SdkGenerator {
-
-    public static void main(String[] args) throws Exception {
-        List<DexBackedClassDef> dexClasses = new ArrayList<>();
-        List<File> zipFiles = new ArrayList<>();
-        File outFile = null;
-        File aidlFile = null;
-
-        for (int i = 0; i < args.length; i++) {
-            switch (args[i]) {
-                case "-h":
-                case "--help":
-                    printHelp();
-                    return;
-                case "--dex":
-                case "-d": {
-                    MultiDexContainer<? extends DexBackedDexFile> dexContainers =
-                            DexFileFactory.loadDexContainer(verifyExists(args[++i]), null);
-                    for (String name : dexContainers.getDexEntryNames()) {
-                        dexClasses.addAll(dexContainers.getEntry(name).getClasses());
-                    }
-                    break;
-                }
-                case "--zip":
-                case "-z":
-                    zipFiles.add(verifyExists(args[++i]));
-                    break;
-                case "--out":
-                case "-o":
-                    outFile = new File(args[++i]);
-                    break;
-                case "--aidl":
-                case "-a":
-                    aidlFile = new File(args[++i]);
-                    break;
-            }
-        }
-
-        if (outFile == null) {
-            throw new IllegalArgumentException("Out not specified");
-        }
-
-        HashSet<String> classAdded = new HashSet<>();
-        int count = 0;
-        DexToStubConverter converter;
-        try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(outFile))) {
-            converter = new DexToStubConverter(out);
-
-            // First loop to initialize inner class map
-            for (DexBackedClassDef classDef : dexClasses) {
-                converter.expectClass(classDef);
-            }
-
-            ProgressBar progress = new ProgressBar("Converting classes", dexClasses.size());
-            for (DexBackedClassDef classDef : dexClasses) {
-                classAdded.add(converter.writeClass(classDef));
-                count++;
-                progress.update(count);
-            }
-            progress.finish();
-
-            for (File zip : zipFiles) {
-                try (FileInputStream fin = new FileInputStream(zip);
-                     FileChannel channel = fin.getChannel();
-                     ZipInputStream zipin = new ZipInputStream(fin)) {
-                    progress = new ProgressBar("Merging " + zip.getName(), channel.size());
-                    ZipEntry nextEntry;
-                    while ((nextEntry = zipin.getNextEntry()) != null) {
-                        if (classAdded.contains(nextEntry.getName())) {
-                            // Skip
-                        } else {
-                            out.putNextEntry(new ZipEntry(nextEntry.getName()));
-                            classAdded.add(nextEntry.getName());
-                            copyStream(zipin, out);
-                        }
-                        progress.update(channel.position());
-                    }
-                    progress.finish();
-                }
-            }
-            System.out.println("Writing final sdk");
-        }
-
-        if (aidlFile != null && aidlFile.exists()) {
-            System.out.println("Merging Aidl");
-
-            try (BufferedReader in = new BufferedReader(new FileReader(aidlFile))) {
-                String l;
-                while ((l = in.readLine()) != null) {
-                    converter.expectAidlDef(l);
-                }
-            }
-
-            try (PrintStream out = new PrintStream(new FileOutputStream(aidlFile, true))) {
-                out.println();
-                out.println();
-                converter.printInterfaces(out);
-            }
-        }
-    }
-
-    private static void copyStream(InputStream in, OutputStream out) throws IOException {
-        byte[] buffer = new byte[1024];
-        int len;
-        while ((len = in.read(buffer)) != -1) {
-            out.write(buffer, 0, len);
-        }
-    }
-
-    private static File verifyExists(String path) {
-        File file = new File(path);
-        if (!file.exists() || file.isDirectory()) {
-            throw new IllegalArgumentException("Invalid file argument " + file);
-        }
-        return file;
-    }
-
-    private static void printHelp() {
-        System.out.println("SdkGenerator [options]");
-        System.out.println("  --help | -h: Print this message");
-        System.out.println("  --dex | -d: Decompile and add a dex file to the sdk jar");
-        System.out.println("  --zip | -z: Unzip's and adds the content to the sdk jar");
-        System.out.println("  --aidl | -a: Aidl file to append any missing definitions");
-        System.out.println("  --out | -o: The output zip file");
-    }
-}
diff --git a/studio-dev/development/sdk/sdk.properties b/studio-dev/development/sdk/sdk.properties
deleted file mode 100644
index c22e3e3d..00000000
--- a/studio-dev/development/sdk/sdk.properties
+++ /dev/null
@@ -1,5 +0,0 @@
-# SDK properties
-# This file is copied in the root folder of each platform component.
-# If it used by various tools to figure out what the platform can do.
-sdk.ant.templates.revision=1
-sdk.skin.default=WVGA800
\ No newline at end of file
diff --git a/studio-dev/development/studio/AndroidStyle.xml b/studio-dev/development/studio/AndroidStyle.xml
deleted file mode 100644
index 23e15d04..00000000
--- a/studio-dev/development/studio/AndroidStyle.xml
+++ /dev/null
@@ -1,321 +0,0 @@
-<code_scheme name="AndroidStyle" version="173">
-  <option name="RIGHT_MARGIN" value="100" />
-  <JetCodeStyleSettings>
-    <option name="PACKAGES_TO_USE_STAR_IMPORTS">
-      <value />
-    </option>
-    <option name="NAME_COUNT_TO_USE_STAR_IMPORT" value="2147483647" />
-    <option name="NAME_COUNT_TO_USE_STAR_IMPORT_FOR_MEMBERS" value="2147483647" />
-  </JetCodeStyleSettings>
-  <JavaCodeStyleSettings>
-    <option name="FIELD_NAME_PREFIX" value="m" />
-    <option name="STATIC_FIELD_NAME_PREFIX" value="s" />
-    <option name="CLASS_COUNT_TO_USE_IMPORT_ON_DEMAND" value="9999" />
-    <option name="NAMES_COUNT_TO_USE_IMPORT_ON_DEMAND" value="9999" />
-    <option name="IMPORT_LAYOUT_TABLE">
-      <value>
-        <package name="android" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="androidx" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="com.android" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="dalvik" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="libcore" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="com" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="gov" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="junit" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="net" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="org" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="java" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="javax" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="" withSubpackages="true" static="true" />
-        <emptyLine />
-        <package name="android" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="androidx" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="com.android" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="dalvik" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="libcore" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="com" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="gov" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="junit" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="net" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="org" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="java" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="javax" withSubpackages="true" static="false" />
-        <emptyLine />
-        <package name="" withSubpackages="true" static="false" />
-      </value>
-    </option>
-    <option name="JD_P_AT_EMPTY_LINES" value="false" />
-    <option name="JD_DO_NOT_WRAP_ONE_LINE_COMMENTS" value="true" />
-    <option name="JD_KEEP_EMPTY_PARAMETER" value="false" />
-    <option name="JD_KEEP_EMPTY_EXCEPTION" value="false" />
-    <option name="JD_KEEP_EMPTY_RETURN" value="false" />
-    <option name="JD_PRESERVE_LINE_FEEDS" value="true" />
-  </JavaCodeStyleSettings>
-  <Objective-C-extensions>
-    <file>
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="Import" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="Macro" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="Typedef" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="Enum" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="Constant" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="Global" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="Struct" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="FunctionPredecl" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="Function" />
-    </file>
-    <class>
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="Property" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="Synthesize" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="InitMethod" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="StaticMethod" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="InstanceMethod" />
-      <option name="com.jetbrains.cidr.lang.util.OCDeclarationKind" value="DeallocMethod" />
-    </class>
-    <extensions>
-      <pair source="cpp" header="h" fileNamingConvention="NONE" />
-      <pair source="c" header="h" fileNamingConvention="NONE" />
-    </extensions>
-  </Objective-C-extensions>
-  <XML>
-    <option name="XML_LEGACY_SETTINGS_IMPORTED" value="true" />
-  </XML>
-  <ADDITIONAL_INDENT_OPTIONS fileType="java">
-    <option name="TAB_SIZE" value="8" />
-  </ADDITIONAL_INDENT_OPTIONS>
-  <ADDITIONAL_INDENT_OPTIONS fileType="js">
-    <option name="CONTINUATION_INDENT_SIZE" value="4" />
-  </ADDITIONAL_INDENT_OPTIONS>
-  <codeStyleSettings language="JAVA">
-    <option name="ALIGN_MULTILINE_PARAMETERS" value="false" />
-    <option name="ALIGN_MULTILINE_FOR" value="false" />
-    <option name="CALL_PARAMETERS_WRAP" value="1" />
-    <option name="PREFER_PARAMETERS_WRAP" value="true" />
-    <option name="METHOD_PARAMETERS_WRAP" value="1" />
-    <option name="RESOURCE_LIST_WRAP" value="1" />
-    <option name="EXTENDS_LIST_WRAP" value="1" />
-    <option name="THROWS_LIST_WRAP" value="1" />
-    <option name="THROWS_KEYWORD_WRAP" value="1" />
-    <option name="BINARY_OPERATION_WRAP" value="1" />
-    <option name="BINARY_OPERATION_SIGN_ON_NEXT_LINE" value="true" />
-    <option name="TERNARY_OPERATION_WRAP" value="1" />
-    <option name="TERNARY_OPERATION_SIGNS_ON_NEXT_LINE" value="true" />
-    <option name="FOR_STATEMENT_WRAP" value="1" />
-    <option name="ARRAY_INITIALIZER_WRAP" value="1" />
-    <option name="ASSIGNMENT_WRAP" value="1" />
-    <option name="WRAP_COMMENTS" value="true" />
-    <option name="IF_BRACE_FORCE" value="1" />
-    <option name="DOWHILE_BRACE_FORCE" value="1" />
-    <option name="WHILE_BRACE_FORCE" value="1" />
-    <option name="FOR_BRACE_FORCE" value="1" />
-    <option name="WRAP_LONG_LINES" value="true" />
-  </codeStyleSettings>
-  <codeStyleSettings language="JavaScript">
-    <option name="KEEP_CONTROL_STATEMENT_IN_ONE_LINE" value="false" />
-    <option name="KEEP_BLANK_LINES_IN_CODE" value="1" />
-    <option name="BLANK_LINES_AROUND_FIELD" value="1" />
-    <option name="BLANK_LINES_AFTER_CLASS_HEADER" value="1" />
-    <option name="ALIGN_MULTILINE_PARAMETERS" value="false" />
-    <option name="ALIGN_MULTILINE_FOR" value="false" />
-    <option name="CALL_PARAMETERS_WRAP" value="1" />
-    <option name="METHOD_PARAMETERS_WRAP" value="1" />
-    <option name="EXTENDS_LIST_WRAP" value="1" />
-    <option name="THROWS_LIST_WRAP" value="1" />
-    <option name="EXTENDS_KEYWORD_WRAP" value="1" />
-    <option name="THROWS_KEYWORD_WRAP" value="1" />
-    <option name="METHOD_CALL_CHAIN_WRAP" value="1" />
-    <option name="BINARY_OPERATION_WRAP" value="1" />
-    <option name="BINARY_OPERATION_SIGN_ON_NEXT_LINE" value="true" />
-    <option name="TERNARY_OPERATION_WRAP" value="1" />
-    <option name="TERNARY_OPERATION_SIGNS_ON_NEXT_LINE" value="true" />
-    <option name="FOR_STATEMENT_WRAP" value="1" />
-    <option name="ARRAY_INITIALIZER_WRAP" value="1" />
-    <option name="ASSIGNMENT_WRAP" value="1" />
-    <option name="PLACE_ASSIGNMENT_SIGN_ON_NEXT_LINE" value="true" />
-    <option name="WRAP_COMMENTS" value="true" />
-    <option name="IF_BRACE_FORCE" value="3" />
-    <option name="DOWHILE_BRACE_FORCE" value="3" />
-    <option name="WHILE_BRACE_FORCE" value="3" />
-    <option name="FOR_BRACE_FORCE" value="3" />
-    <option name="PARENT_SETTINGS_INSTALLED" value="true" />
-  </codeStyleSettings>
-  <codeStyleSettings language="XML">
-    <option name="FORCE_REARRANGE_MODE" value="1" />
-    <indentOptions>
-      <option name="CONTINUATION_INDENT_SIZE" value="4" />
-    </indentOptions>
-    <arrangement>
-      <rules>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>xmlns:android</NAME>
-                <XML_NAMESPACE>^$</XML_NAMESPACE>
-              </AND>
-            </match>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>xmlns:.*</NAME>
-                <XML_NAMESPACE>^$</XML_NAMESPACE>
-              </AND>
-            </match>
-            <order>BY_NAME</order>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>.*:id</NAME>
-                <XML_NAMESPACE>http://schemas.android.com/apk/res/android</XML_NAMESPACE>
-              </AND>
-            </match>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>.*:name</NAME>
-                <XML_NAMESPACE>http://schemas.android.com/apk/res/android</XML_NAMESPACE>
-              </AND>
-            </match>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>name</NAME>
-                <XML_NAMESPACE>^$</XML_NAMESPACE>
-              </AND>
-            </match>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>style</NAME>
-                <XML_NAMESPACE>^$</XML_NAMESPACE>
-              </AND>
-            </match>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>.*</NAME>
-                <XML_NAMESPACE>^$</XML_NAMESPACE>
-              </AND>
-            </match>
-            <order>BY_NAME</order>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>.*:layout_width</NAME>
-                <XML_NAMESPACE>http://schemas.android.com/apk/res/android</XML_NAMESPACE>
-              </AND>
-            </match>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>.*:layout_height</NAME>
-                <XML_NAMESPACE>http://schemas.android.com/apk/res/android</XML_NAMESPACE>
-              </AND>
-            </match>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>.*:layout_.*</NAME>
-                <XML_NAMESPACE>http://schemas.android.com/apk/res/android</XML_NAMESPACE>
-              </AND>
-            </match>
-            <order>BY_NAME</order>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>.*:width</NAME>
-                <XML_NAMESPACE>http://schemas.android.com/apk/res/android</XML_NAMESPACE>
-              </AND>
-            </match>
-            <order>BY_NAME</order>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>.*:height</NAME>
-                <XML_NAMESPACE>http://schemas.android.com/apk/res/android</XML_NAMESPACE>
-              </AND>
-            </match>
-            <order>BY_NAME</order>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>.*</NAME>
-                <XML_NAMESPACE>http://schemas.android.com/apk/res/android</XML_NAMESPACE>
-              </AND>
-            </match>
-            <order>BY_NAME</order>
-          </rule>
-        </section>
-        <section>
-          <rule>
-            <match>
-              <AND>
-                <NAME>.*</NAME>
-                <XML_NAMESPACE>.*</XML_NAMESPACE>
-              </AND>
-            </match>
-            <order>BY_NAME</order>
-          </rule>
-        </section>
-      </rules>
-    </arrangement>
-  </codeStyleSettings>
-</code_scheme>
diff --git a/studio-dev/development/studio/code.style.schemes.xml b/studio-dev/development/studio/code.style.schemes.xml
deleted file mode 100644
index 85b8bcd6..00000000
--- a/studio-dev/development/studio/code.style.schemes.xml
+++ /dev/null
@@ -1,5 +0,0 @@
-<application>
-  <component name="CodeStyleSchemeSettings">
-    <option name="CURRENT_SCHEME_NAME" value="AndroidStyle" />
-  </component>
-</application>
\ No newline at end of file
diff --git a/studio-dev/development/studio/idea.properties b/studio-dev/development/studio/idea.properties
deleted file mode 100644
index 13c8d17f..00000000
--- a/studio-dev/development/studio/idea.properties
+++ /dev/null
@@ -1,173 +0,0 @@
-# Use ${idea.home.path} macro to specify location relative to IDE installation home.
-# Use ${xxx} where xxx is any Java property (including defined in previous lines of this file) to refer to its value.
-# Note for Windows users: please make sure you're using forward slashes (e.g. c:/idea/system).
-#---------------------------------------------------------------------
-# Uncomment this option if you want to customize path to IDE config folder. Make sure you're using forward slashes.
-#---------------------------------------------------------------------
-idea.config.path=${SYSUI_STUDIO_SETTINGS_DIR}/config
-#---------------------------------------------------------------------
-# Uncomment this option if you want to customize path to IDE system folder. Make sure you're using forward slashes.
-#---------------------------------------------------------------------
-idea.system.path=${SYSUI_STUDIO_SETTINGS_DIR}/system
-#---------------------------------------------------------------------
-# Uncomment this option if you want to customize path to IDE log folder. Make sure you're using forward slashes.
-#---------------------------------------------------------------------
-idea.log.path=${SYSUI_STUDIO_SETTINGS_DIR}/log
-#---------------------------------------------------------------------
-# Uncomment this option if you want to customize path to IDE plugins folder. Make sure you're using forward slashes.
-#---------------------------------------------------------------------
-idea.plugins.path=${SYSUI_STUDIO_SETTINGS_DIR}/plugins
-#---------------------------------------------------------------------
-# Disable first run wizard as we use out own sdk
-#---------------------------------------------------------------------
-disable.android.first.run=true
-#---------------------------------------------------------------------
-# Uncomment this option if you want to customize path to user installed plugins folder. Make sure you're using forward slashes.
-#---------------------------------------------------------------------
-# idea.plugins.path=${idea.config.path}/plugins
-#---------------------------------------------------------------------
-# Uncomment this option if you want to customize path to IDE logs folder. Make sure you're using forward slashes.
-#---------------------------------------------------------------------
-# idea.log.path=${idea.system.path}/log
-#---------------------------------------------------------------------
-# Maximum file size (kilobytes) IDE should provide code assistance for.
-# The larger file is the slower its editor works and higher overall system memory requirements are
-# if code assistance is enabled. Remove this property or set to very large number if you need
-# code assistance for any files available regardless their size.
-#---------------------------------------------------------------------
-idea.max.intellisense.filesize=2500
-#---------------------------------------------------------------------
-# Maximum file size (kilobytes) IDE is able to open.
-#---------------------------------------------------------------------
-idea.max.content.load.filesize=20000
-#---------------------------------------------------------------------
-# This option controls console cyclic buffer: keeps the console output size not higher than the specified buffer size (Kb).
-# Older lines are deleted. In order to disable cycle buffer use idea.cycle.buffer.size=disabled
-#---------------------------------------------------------------------
-idea.cycle.buffer.size=1024
-#---------------------------------------------------------------------
-# Configure if a special launcher should be used when running processes from within IDE.
-# Using Launcher enables "soft exit" and "thread dump" features
-#---------------------------------------------------------------------
-idea.no.launcher=false
-#---------------------------------------------------------------------
-# To avoid too long classpath
-#---------------------------------------------------------------------
-idea.dynamic.classpath=false
-#---------------------------------------------------------------------
-# Uncomment this property to prevent IDE from throwing ProcessCanceledException when user activity
-# detected. This option is only useful for plugin developers, while debugging PSI related activities
-# performed in background error analysis thread.
-# DO NOT UNCOMMENT THIS UNLESS YOU'RE DEBUGGING IDE ITSELF. Significant slowdowns and lockups will happen otherwise.
-#---------------------------------------------------------------------
-#idea.ProcessCanceledException=disabled
-#---------------------------------------------------------------------
-# There are two possible values of idea.popup.weight property: "heavy" and "medium".
-# If you have WM configured as "Focus follows mouse with Auto Raise" then you have to
-# set this property to "medium". It prevents problems with popup menus on some
-# configurations.
-#---------------------------------------------------------------------
-idea.popup.weight=heavy
-#---------------------------------------------------------------------
-# Removing this property may lead to editor performance degradation under Windows.
-#---------------------------------------------------------------------
-sun.java2d.d3d=false
-#---------------------------------------------------------------------
-# Set swing.bufferPerWindow=false to workaround a slow scrolling in JDK6 (see IDEA-35883),
-# But this may lead to performance degradation in JDK8, because it disables a double buffering,
-# which is needed to eliminate tearing on blit-accelerated scrolling and to restore
-# a frame buffer content without the usual repainting, even when the EDT is blocked.
-#---------------------------------------------------------------------
-swing.bufferPerWindow=true
-#---------------------------------------------------------------------
-# Removing this property may lead to editor performance degradation under X Window.
-#---------------------------------------------------------------------
-sun.java2d.pmoffscreen=false
-#---------------------------------------------------------------------
-# Enables HiDPI support in JBRE
-#---------------------------------------------------------------------
-sun.java2d.uiScale.enabled=true
-#---------------------------------------------------------------------
-# Applicable to the Swing text components displaying HTML (except JEditorPane).
-# Rebases CSS size map depending on the component's font size to let relative
-# font size values (smaller, larger) scale properly. JBRE only.
-#---------------------------------------------------------------------
-javax.swing.rebaseCssSizeMap=true
-#---------------------------------------------------------------------
-# Workaround to avoid long hangs while accessing clipboard under Mac OS X.
-#---------------------------------------------------------------------
-#ide.mac.useNativeClipboard=True
-#---------------------------------------------------------------------
-# Maximum size (kilobytes) IDEA will load for showing past file contents -
-# in Show Diff or when calculating Digest Diff
-#---------------------------------------------------------------------
-#idea.max.vcs.loaded.size.kb=20480
-#---------------------------------------------------------------------
-# IDEA file chooser peeks inside directories to detect whether they contain a valid project
-# (to mark such directories with a corresponding icon).
-# Uncommenting the option prevents this behavior outside of user home directory.
-#---------------------------------------------------------------------
-#idea.chooser.lookup.for.project.dirs=false
-#-----------------------------------------------------------------------
-# Experimental option that does a number of things to make truly smooth scrolling possible:
-#
-# * Enables hardware-accelerated scrolling.
-#     Blit-acceleration copies as much of the rendered area as possible and then repaints only newly exposed region.
-#     This helps to improve scrolling performance and to reduce CPU usage (especially if drawing is compute-intensive).
-#
-# * Enables "true double buffering".
-#     True double buffering is needed to eliminate tearing on blit-accelerated scrolling and to restore
-#     frame buffer content without the usual repainting, even when the EDT is blocked.
-#
-# * Adds "idea.true.smooth.scrolling.debug" option.
-#     Checks whether blit-accelerated scrolling is feasible, and if so, checks whether true double buffering is available.
-#
-# * Enables handling of high-precision mouse wheel events.
-#     Although Java 7 introduced MouseWheelEven.getPreciseWheelRotation() method, JScrollPane doesn't use it so far.
-#     Depends on the Editor / General / Smooth Scrolling setting, remote desktop detection and power save mode state.
-#     Ideally, we need to patch the runtime (on Windows, Linux and Mac OS) to improve handling of the fine-grained input data.
-#     This feature can be toggled via "idea.true.smooth.scrolling.high.precision" option.
-#
-# * Enables handling of pixel-perfect scrolling events.
-#     Currently this mode is available only under Mac OS with JetBrains Runtime.
-#     This feature can be toggled via "idea.true.smooth.scrolling.pixel.perfect" option.
-#
-# * Enables interpolation of scrolling input (scrollbar, mouse wheel, touchpad, keys, etc).
-#     Smooths input which lacks both spatial and temporal resolution, performs the rendering asynchronously.
-#     Depends on the Editor / General / Smooth Scrolling setting, remote desktop detection and power save mode state.
-#     The feature can be tweaked using the following options:
-#       "idea.true.smooth.scrolling.interpolation" - the main switch
-#       "idea.true.smooth.scrolling.interpolation.scrollbar" - scrollbar interpolation
-#       "idea.true.smooth.scrolling.interpolation.scrollbar.delay" - initial delay for scrollbar interpolation (ms)
-#       "idea.true.smooth.scrolling.interpolation.mouse.wheel" - mouse wheel / touchpad interpolation
-#       "idea.true.smooth.scrolling.interpolation.mouse.wheel.delay.min" - minimum initial delay for mouse wheel interpolation (ms)
-#       "idea.true.smooth.scrolling.interpolation.mouse.wheel.delay.max" - maximum initial delay for mouse wheel interpolation (ms)
-#       "idea.true.smooth.scrolling.interpolation.precision.touchpad" - precision touchpad interpolation
-#       "idea.true.smooth.scrolling.interpolation.precision.touchpad.delay" - initial delay for precision touchpad interpolation (ms)
-#       "idea.true.smooth.scrolling.interpolation.other" - interpolation of other input sources
-#       "idea.true.smooth.scrolling.interpolation.other.delay" - initial delay for other input source interpolation (ms)
-#
-# * Adds on-demand horizontal scrollbar in editor.
-#     The horizontal scrollbar is shown only when it's actually needed for currently visible content.
-#     This helps to save editor space and to prevent occasional horizontal "jitter" on vertical touchpad scrolling.
-#     This feature can be toggled via "idea.true.smooth.scrolling.dynamic.scrollbars" option.
-#-----------------------------------------------------------------------
-#idea.true.smooth.scrolling=true
-#---------------------------------------------------------------------
-# IDEA can copy library .jar files to prevent their locking.
-# By default this behavior is enabled on Windows and disabled on other platforms.
-# Uncomment this property to override.
-#---------------------------------------------------------------------
-# idea.jars.nocopy=false
-#---------------------------------------------------------------------
-# The VM option value to be used to start a JVM in debug mode.
-# Some JREs define it in a different way (-XXdebug in Oracle VM)
-#---------------------------------------------------------------------
-idea.xdebug.key=-Xdebug
-#-----------------------------------------------------------------------
-# Change to 'disabled' if you don't want to receive instant visual notifications
-# about fatal errors that happen to an IDE or plugins installed.
-#-----------------------------------------------------------------------
-idea.fatal.error.notification=enabled
-# Stop the IDE from notifying the user about IDE updates
-idea.updates.url=file:///${SYSUI_STUDIO_SETTINGS_DIR}/updates.xml
diff --git a/studio-dev/development/studio/instant-run.xml b/studio-dev/development/studio/instant-run.xml
deleted file mode 100644
index d5a8a6a8..00000000
--- a/studio-dev/development/studio/instant-run.xml
+++ /dev/null
@@ -1,5 +0,0 @@
-<application>
-  <component name="InstantRunConfiguration">
-    <option name="INSTANT_RUN" value="false" />
-  </component>
-</application>
\ No newline at end of file
diff --git a/studio-dev/development/studio/jdk.table.xml b/studio-dev/development/studio/jdk.table.xml
deleted file mode 100644
index 063e5a4b..00000000
--- a/studio-dev/development/studio/jdk.table.xml
+++ /dev/null
@@ -1,32 +0,0 @@
-<application>
-  <component name="ProjectJdkTable">
-    <jdk version="2">
-      <name value="Generated SDK for IDE Integrations" />
-      <type value="Android SDK" />
-      <homePath value="__SDK_DIR_PLACEHOLDER__" />
-      <roots>
-        <annotationsPath>
-          <root type="composite">
-            <root url="jar://$APPLICATION_HOME_DIR$/plugins/android/resources/androidAnnotations.jar!/" type="simple" />
-          </root>
-        </annotationsPath>
-        <classPath>
-          <root type="composite">
-            <root url="jar://__SDK_DIR_PLACEHOLDER__/platforms/__SDK_VERSION_NAME_PLACEHOLDER__/android.jar!/" type="simple" />
-            <root url="file://__SDK_DIR_PLACEHOLDER__/platforms/__SDK_VERSION_NAME_PLACEHOLDER__/data/res" type="simple" />
-          </root>
-        </classPath>
-        <javadocPath>
-          <root type="composite">
-            <root url="http://developer.android.com/reference/" type="simple" />
-          </root>
-        </javadocPath>
-        <sourcePath>
-          <root type="composite">
-            <root url="file://__SDK_DIR_PLACEHOLDER__/platforms/__SDK_VERSION_NAME_PLACEHOLDER__/sources" type="simple" />
-          </root>
-        </sourcePath>
-      </roots>
-    </jdk>
-  </component>
-</application>
diff --git a/studio-dev/development/studio/notifications.xml b/studio-dev/development/studio/notifications.xml
deleted file mode 100644
index 369188c3..00000000
--- a/studio-dev/development/studio/notifications.xml
+++ /dev/null
@@ -1,5 +0,0 @@
-<application>
-  <component name="NotificationConfiguration">
-    <notification groupId="Android Gradle Upgrade Notification" displayType="NONE" />
-  </component>
-</application>
diff --git a/studio-dev/development/studio/studio.vmoptions b/studio-dev/development/studio/studio.vmoptions
deleted file mode 100644
index 16f89e4e..00000000
--- a/studio-dev/development/studio/studio.vmoptions
+++ /dev/null
@@ -1,2 +0,0 @@
--Xmx8g
--Dgradle.ide.internal.build.injection.device.serial.number=true
\ No newline at end of file
diff --git a/studio-dev/development/studio/trusted-paths.xml b/studio-dev/development/studio/trusted-paths.xml
deleted file mode 100644
index 89af85db..00000000
--- a/studio-dev/development/studio/trusted-paths.xml
+++ /dev/null
@@ -1,9 +0,0 @@
-<application>
-  <component name="Trusted.Paths">
-    <option name="TRUSTED_PROJECT_PATHS">
-      <map>
-        <entry key="__PROJECT_DIR_PLACEHOLDER__" value="true" />
-      </map>
-    </option>
-  </component>
-</application>
\ No newline at end of file
diff --git a/studio-dev/development/studio/updates.xml b/studio-dev/development/studio/updates.xml
deleted file mode 100644
index 92b2daae..00000000
--- a/studio-dev/development/studio/updates.xml
+++ /dev/null
@@ -1,5 +0,0 @@
-<products>
-<product name="Android Studio (ASwB compat)">
-<code>AI</code>
-</product>
-</products>
diff --git a/studio-dev/studiow b/studio-dev/studiow
deleted file mode 100755
index 442ebaa1..00000000
--- a/studio-dev/studiow
+++ /dev/null
@@ -1,1118 +0,0 @@
-#!/bin/bash
-set -e
-set -m
-
-# This is a wrapper script that runs the specific version of Android Studio that is recommended for developing in this repository.
-# (This serves a similar purpose to gradlew)
-
-# Get the property value by a properties file
-function getProperyValue() {
-  getProperyValueAbs ${scriptDir}/$1 $2
-}
-
-function getProperyValueAbs() {
-  # Use --no-messages to suppress error messages about non-existant files
-  echo "$(grep --no-messages "$2[[:space:]]*=[[:space:]]*" ${1} | sed 's/[^=]*=[[:space:]]*//')"
-}
-
-# Get the studio version corresponding to the gradle version defined in gradle.properties
-function fetchStudioUrl() {
-  local cache_file=.studio_version_cache
-  local studioVersion="$(echo "$(getProperyValue ManagedProvisioningGradleProject/gradle/libs.versions.toml android-studio)" | sed 's/"//g')"
-  local cachedVersion="$(getProperyValue $cache_file cached_studio_version)"
-
-  if [ ! "$studioVersion" == "$cachedVersion" ]; then
-    local content="$(curl -L https://developer.android.com/studio/archive.html)"
-    local iframe_url="$(echo $content | egrep -o 'iframe src="[^"]+"' | cut -d '"' -f 2)"
-    content="$(curl -L $iframe_url)"
-
-    if [ "$osName" == "mac" ]; then
-      content="$(echo $content | egrep -o "Android Studio [^0-9]+$studioVersion.+?section")"
-    else
-      content="$(echo $content | grep -Po "Android Studio [^0-9]+$studioVersion.+?section")"
-    fi
-
-    local mac_url
-    if [ "$arch" == "arm" ]; then
-      mac_url="$(echo $content | egrep -o '"[^"]+mac_arm.zip"' | cut -d '"' -f 2)"
-    else
-      mac_url="$(echo $content | egrep -o '"[^"]+mac.zip"' | cut -d '"' -f 2)"
-    fi
-    mac_url="$(echo $mac_url | cut -d " " -f 1)"
-
-    local linux_url="$(echo $content | egrep -o '"[^"]+linux[^"]*"' | cut -d '"' -f 2 | cut -d " " -f 1)"
-    linux_url="$(echo $linux_url | cut -d " " -f 1)"
-
-    echo cached_studio_version=$studioVersion > ${scriptDir}/$cache_file
-    echo mac=$mac_url >> ${scriptDir}/$cache_file
-    echo linux=$linux_url >> ${scriptDir}/$cache_file
-  fi
-  studioUrl="https://dl.google.com/dl/android/studio/$(getProperyValue $cache_file $osName | egrep -o  'ide-zips/.*')"
-}
-
-# Escape sequence to print bold colors
-RED='\033[1;31m'
-GREEN='\033[1;32m'
-YELLOW='\033[1;33m'
-# Escape sequence to clear formatting
-NC='\033[0m'
-
-printError() {
-  local logMessage="$1"
-  echo -e "${RED}ERROR:${NC} ${logMessage}"
-}
-
-printWarning() {
-  local logMessage="$1"
-  echo -e "${YELLOW}WARNING:${NC} ${logMessage}"
-}
-
-printInfo() {
-  local logMessage="$1"
-  echo -e "${GREEN}INFO:${NC} ${logMessage}"
-}
-
-
-acceptsLicenseAgreement="false"
-runStudio="true"
-downloadStudioZip="true"
-cleanProjectFiles="false"
-scriptDir="$(cd $(dirname $0) && pwd)"
-projectDir=$scriptDir/ManagedProvisioningGradleProject
-androidBuildTop="$(cd "${scriptDir}/../../../../"; pwd)"
-
-gradleOutDir="${androidBuildTop}/out/gradle"
-usingDefaultSettingsDir='true'
-androidStudioSettingsDir="${gradleOutDir}/AndroidStudio"
-# Where to put the generated idea.properties file relative to $androidStudioSettingsDir, used for
-# STUDIO_PROPERTIES
-ideaPropRelPath="bin/idea.properties"
-
-# TODO(b/249826650): Maybe we shouldn't write to ~/.AndroidStudio* named directories. Android Studio
-# searches for these directories and tries to use them when opening for the first time elsewhere.
-# See:
-#  - Implementation details: http://shortn/_Q0gp64FPj3
-#  - Screenshot: http://screen/4sCQBhNyVTMPPf3.png
-studioHomeDir="${HOME}/.AndroidStudioSystemUI"
-studioSetupDir="${studioHomeDir}/bin"
-function getOsName() {
-  local unameOutput="$(uname)"
-  local osName=""
-  if [ "${unameOutput}" == "Linux" ]; then
-    osName="linux"
-  else
-    osName="mac"
-  fi
-  echo "${osName}"
-}
-osName="$(getOsName)"
-arch="$(uname -p)"
-studioUrl=
-# If empty string, don't update the SDK. Otherwise, the string indicates the method used for
-# fetching the artifacts needed to generate the SDK. Currently, either 'adb' or 'soong'
-updateSdk=''
-copySdkSourceDir=''
-
-function setupBuildSrcSymlinks() {
-  # Builtbots can't write to the source dirs, and there is no gradle option to overwrite the .gradle
-  # location of buildSrc, so we use symlinks. The dirs must be created before running the build.
-  #
-  # Alternatively, we could migrate from buildSrc/ to a composite build to avoid needing the
-  # symlinks. See: http://go/gh/gradle/gradle/issues/2472#issuecomment-315376378
-  cd "${scriptDir}/ManagedProvisioningGradleProject/buildSrc"
-  mkdir -p $(readlink .gradle)
-  mkdir -p $(readlink build)
-  cd - > /dev/null
-}
-
-# Used to keep track of whether we confirmed adb root works. We only want to check once.
-adbChecked='false'
-function assertHasAdbRoot() {
-  if [[ "${adbChecked}" == 'false' && "${updateSdk}" == 'adb' ]]; then
-    adb root || {
-      printError 'adb root failed. You must have a rooted device attached to use "--update-sdk adb".'
-      if [ "${osName}" != "mac" ]; then
-        echo 'NOTE: On Linux, you can use "--update-sdk soong" to compile the SDK from source.'
-      fi
-      exit 1
-    }
-    adb wait-for-device
-    adbChecked='true'
-  fi
-}
-
-function getUpstreamGitBranch() {
-  echo "$(git -C "${androidBuildTop}/.repo/manifests" for-each-ref --format='%(upstream:short)' refs/heads | sed 's/origin\///')"
-}
-function toUpperCase() {
-  local dashedName="$1"
-  IFS='-'
-  local words=($dashedName)
-  unset IFS
-  local upperCaseName=''
-  for word in "${words[@]}"; do
-    upperCaseName="${upperCaseName}$(echo "$word" | sed 's/[a-z]/\U&/')"
-  done
-  echo "$upperCaseName"
-}
-# Find the name of the branch (e.g. udc-dev) and change it to camel-case (e.g. UdcDev)
-# (e.g. udc-dev)
-branchName="$(getUpstreamGitBranch)"
-# (e.g. UdcDev)
-upperCaseBranchName="$(toUpperCase "$branchName")"
-
-sdkVersionInt="$(getProperyValue ManagedProvisioningGradleProject/gradle.properties TARGET_SDK)"
-# Use the first 4 chars of the SHA of $ANDROID_BUILD_TOP as a unique ID for this Android tree.
-# We will use this to associate this tree with the generated SDK so that all platform SDK can share
-# the same SDK home. This is just for preventing collisions if someone has the same branch checked
-# out twice. Otherwise, we'd just use $upperCaseBranchName
-androidTreeUniqueId="$(echo "$androidBuildTop" | shasum -a 256 | head -c 4)"
-
-# ---- ---- ---- ----
-# The following variables are to correspond with the Android Gradle DSL property of the same name:
-# Public docs: http://go/android-reference/tools/gradle-api/8.0/com/android/build/api/dsl/SettingsExtension#compileSdkPreview()
-# Parsing code: http://go/aocs/android/platform/superproject/+/studio-main:tools/base/build-system/gradle-core/src/main/java/com/android/build/gradle/internal/dsl/CommonExtensionImpl.kt
-compileSdkPreview="${upperCaseBranchName}ForTree${androidTreeUniqueId}"
-compileSdkVersion="android-${compileSdkPreview}"
-# ---- ---- ---- ----
-
-prebuiltsDir="${androidBuildTop}/prebuilts"
-function getLegacySdkDir() {
-  if [ "${osName}" == "mac" ]; then
-    echo "${prebuiltsDir}/fullsdk-darwin"
-  else
-    echo "${prebuiltsDir}/fullsdk-linux"
-  fi
-}
-function getLegacySdkDir2() {
-  if [ "${osName}" == "mac" ]; then
-    echo "${studioHomeDir}/fullsdk-darwin"
-  else
-    echo "${studioHomeDir}/fullsdk-linux"
-  fi
-}
-function getSdkDir() {
-  echo "${gradleOutDir}/MockSdk"
-}
-sdkDir="$(getSdkDir)"
-platformDir="$sdkDir/platforms/$compileSdkVersion"
-
-function printHelpAndExit() {
-  local message=(
-    'Usage: studiow [OPTION...]'
-    '\n'
-    '\n  -y, --accept-license-agreement'
-    '\n  --update-only'
-    '\n  --no-download'
-    '\n  --update-sdk [ARTIFACT SOURCE (adb, soong, or copy)]'
-    '\n  --project-dir'
-    '\n  --settings-dir'
-    '\n  --clean'
-    '\n  --uninstall'
-  )
-  local fmt_cmd=(fmt -w 100 --split-only)
-  if [ "$osName" == "mac" ]; then
-    fmt_cmd=(fmt -w 100)
-  fi
-  printf "$(printf %s "${message[@]}")" | ${fmt_cmd[@]}
-  exit 1
-}
-
-
-function parseOptions() {
-  while :; do
-    case "$1" in
-      -y|--accept-license-agreement)
-        acceptsLicenseAgreement="true"
-        ;;
-      --update-only)
-        runStudio="false"
-        ;;
-      --no-download)
-        downloadStudioZip="false"
-        runStudio="false"
-        ;;
-      --update-sdk)
-        if [[ -n "$2" && "$2" != -* ]]; then
-          updateSdk="$2"
-          shift
-        fi
-        case "$updateSdk" in
-          adb)
-            ;;
-          soong)
-            if [[ "${osName}" == "mac" ]]; then
-              printError 'MacOS does not support soong builds'
-              exit 1
-            elif [[ ! -f "$androidBuildTop/build/soong/soong_ui.bash" ]]; then
-              printError 'You must have a full platform branch to compile the SDK. Minimal checkouts (e.g. *-sysui-studio-dev) do not support soong builds.'
-              exit 1
-            fi
-            ;;
-          copy)
-            if [[ -n "$2" && "$2" != -* ]]; then
-              copySdkSourceDir="$2"
-              shift
-            else
-              printError 'You must specify a directoy to copy the SDK from'
-              echo ''
-              echo 'Usage: ./studiow --update-sdk copy [DIR]'
-              echo ''
-              echo 'Directory can be local or remote in the form of [user@]host:[path].'
-              echo ''
-              echo 'For example, to copy the SDK from a remote host, run the following:'
-              echo ''
-              echo '  ./studiow --update-sdk copy example.corp.google.com:/path/to/out/gradle/MockSdk/platforms/android-31'
-              echo ''
-              exit 1
-            fi
-            ;;
-          *)
-            if [[ -z "${updateSdk}" ]]; then
-              printError 'You must specify artifact source when using --update-sdk.'
-            else
-              printError "Unknown SDK artifact source: $updateSdk"
-            fi
-            echo ''
-            echo 'Usage: ./studiow --update-sdk [ARTIFACT SOURCE]'
-            echo ''
-            echo 'Available options are:'
-            echo '  adb: Pull the artifacts from attached device (default)'
-            echo '  soong: Build the artifacts using soong (recommended)'
-            echo '  copy: Copy android.jar and framework.aidl from the given directory'
-            echo ''
-            echo 'NOTE: soong option can only be used on Linux with a full checkout'
-            exit 1
-            ;;
-        esac
-        ;;
-      --pull-sdk)
-        printWarning "--pull-sdk is deprecated. It is equivalent to '--update-sdk adb'"
-        updateSdk='adb'
-        ;;
-      --project-dir)
-        shift
-        projectDir="$1"
-        ;;
-      --settings-dir)
-        shift
-        usingDefaultSettingsDir='false'
-        if [[ -z "$1" ]] ; then
-          echo "--settings-dir expects a directory. Usage: --settings-dir [dir name]"
-          exit 1
-        elif [[ ! -d "$1" ]] ; then
-          echo "Invalid --settings-dir: $1 does not exist or is not a directory"
-          exit 1
-        fi
-        androidStudioSettingsDir="$(cd "$1"; pwd)"
-        ;;
-      --clean)
-        cleanProjectFiles="true"
-        ;;
-      --uninstall)
-        uninstallAndroidStudio="true"
-        ;;
-      -h|--help|-?)
-        printHelpAndExit
-        ;;
-      *)
-        if [ -z "$1" ]; then
-          # If $1 is an empty string, it means we reached the end of the passed arguments
-          break
-        else
-          echo "Unknown option: $1"
-          exit
-        fi
-    esac
-
-    shift
-  done
-}
-
-# $1 - string to print
-# $2 - default, either 'y' or 'n'
-function yesNo() {
-  local question="$1"
-  local defaultResponse="${2:-y}"
-  local yesNoPrompt=''
-
-  if [[ "${defaultResponse::1}" =~ [yY] ]]; then
-    yesNoPrompt='[Y/n]'
-  else
-    yesNoPrompt='[y/N]'
-  fi
-
-  read -r -n 1 -p "$question ${yesNoPrompt}? " -s reply
-  if [ -z "${reply}" ]; then
-    # Replace the empty string with the default response
-    reply="${defaultResponse::1}"
-  fi
-
-  # Print the response so there is no confusion
-  echo "${reply::1}"
-
-  case "${reply::1}" in
-    [yY])
-      true
-      ;;
-    *)
-      false
-      ;;
-  esac
-}
-
-function downloadFile() {
-  fromUrl="$1"
-  destPath="$2"
-  tempPath="${destPath}.tmp"
-  if [ -f "${destPath}" ]; then
-    if yesNo "File already exists. Do you want to delete and re-download?"; then
-      rm "${destPath}"
-    fi
-  fi
-
-  if [ -f "${destPath}" ]; then
-    echo "Using existing file from ${destPath}"
-  else
-    echo "Downloading ${fromUrl} to ${destPath}"
-    curl "${fromUrl}" > "${tempPath}"
-    mv "${tempPath}" "${destPath}"
-  fi
-}
-
-function findStudioMacAppPath() {
-  echo "$(find "${studioUnzippedPath}" -type d -depth 1 -name "Android Studio*.app")"
-}
-
-function getLicensePath() {
-  if [ "${osName}" == "mac" ]; then
-    appPath="$(findStudioMacAppPath)"
-    echo "${appPath}/Contents/Resources/LICENSE.txt"
-  else
-    echo "${studioUnzippedPath}/android-studio/LICENSE.txt"
-  fi
-}
-
-function checkLicenseAgreement() {
-  # TODO: Is there a more official way to check that the user accepts the license?
-
-  licenseAcceptedPath="${studioUnzippedPath}/STUDIOW_LICENSE_ACCEPTED"
-
-  if [ ! -f "${licenseAcceptedPath}" ]; then
-    if [ "${acceptsLicenseAgreement}" == "true" ]; then
-      touch "${licenseAcceptedPath}"
-    else
-      if yesNo "Do you accept the license agreement at $(getLicensePath)"; then
-        touch "${licenseAcceptedPath}"
-      else
-        exit 1
-      fi
-    fi
-  fi
-}
-
-# Inserts a snippet into the studio.sh launch script that prevents it from running if
-# STUDIO_LAUNCHED_WITH_WRAPPER is not set. This is to prevent people from launching studio.sh
-# directly, which can result in build errors. This only works on Linux. Unfortunately, there is no
-# equivalent for Mac OS.
-#
-# Inputs:
-#   osName - Either mac or linux
-#   studioPath - Path to the studio.sh script on Linux
-function updateStudioLaunchScript() {
-  # Only Linux uses the studio.sh script
-  if [ "${osName}" == "mac" ]; then
-    return
-  fi
-  # If studio.sh already contains 'STUDIO_LAUNCHED_WITH_WRAPPER', don't do anything
-  grep -qF 'STUDIO_LAUNCHED_WITH_WRAPPER' "$studioPath" && return
-
-  local tmpStudioSh="$(mktemp)"
-
-  # Find the first line OS_TYPE, and use this as our insertion point.
-  local insertionPoint="$(grep --line-number OS_TYPE "$studioPath" | head -n 1 | cut -d ':' -f 1)"
-
-  # Dump everything from line 0 through $insertionPoint-1 into the tmp file
-  head -n "$(("$insertionPoint"-1))" "$studioPath" > "$tmpStudioSh"
-
-  # Insert a conditional to prevent launching studiow when STUDIO_LAUNCHED_WITH_WRAPPER is unset
-  ( cat <<'EOF'
-if [ -z "$STUDIO_LAUNCHED_WITH_WRAPPER" ]; then
-  message 'This installation of Android Studio must be launched using the studiow script found in $ANDROID_BUILD_TOP/packages/apps/ManagedProvisioning/studio-dev/studiow.'
-  exit 1
-fi
-EOF
-) >> "$tmpStudioSh"
-
-  # Dump everything from $insertionPoint until the end studio.sh into the tmp file
-  tail -n +"$insertionPoint" "$studioPath" >> "$tmpStudioSh"
-
-  # Ensure that the tmp file has the same permissions as the original studio.sh
-  chmod --reference="$studioPath" "$tmpStudioSh"
-
-  echo "Inserting the following snippet into studio.sh to prevent launching it outside of studiow:"
-  diff "$studioPath" "$tmpStudioSh" || :
-  mv "$tmpStudioSh" "$studioPath"
-}
-
-# Creates an idea.properties file where all the configs are specific to this checkout of the Android
-# tree and not shared between different branches.
-#
-# Inputs:
-#  scriptDir - The path to this script (studiow)
-#  androidStudioSettingsDir - The common dir for Android Studio settings per checkout
-#  studioPropertiesFile - Where to put the generated idea.properties file, used for STUDIO_PROPERTIES
-function updateIdeaProperties() {
-  local ideaPropRefFile="${scriptDir}/development/studio/idea.properties"
-  mkdir -p "$(dirname "$studioPropertiesFile")"
-  echo "SYSUI_STUDIO_SETTINGS_DIR=$androidStudioSettingsDir" > "$studioPropertiesFile"
-  chmod 640 "$studioPropertiesFile"
-  cat "${ideaPropRefFile}" >> "$studioPropertiesFile"
-}
-
-# Creates the DO_NOT_RUN_ANDROID_STUDIO_FROM_HERE file
-#
-# Inputs:
-#   studioSetupDir - Path to Android Studio bin dir. Assumes the dir already exists.
-function createWarningTextFile() {
-  ( cat <<'EOF'
-The installations of Android Studio found in this directory MUST be launched using the studiow
-script found in:
-$ANDROID_BUILD_TOP/packages/apps/ManagedProvisioning/studio-dev/studiow
-
-Do NOT launch Android Studio by running studio.sh (on Linux) or by opening Android Studio.app (on
-MacOS). Otherwise, you won't be able to work on multiple branches of Android simultaneously.
-EOF
-) > "${studioSetupDir}/DO_NOT_RUN_ANDROID_STUDIO_FROM_HERE"
-}
-
-function updateStudio() {
-
-  # skip if already up-to-date
-  if stat "${studioUnzippedPath}" >/dev/null 2>/dev/null; then
-    # already up-to-date
-    createWarningTextFile
-    return
-  fi
-
-  mkdir -p "${studioSetupDir}"
-  downloadFile "${studioUrl}" "${studioZipPath}"
-  echo
-
-  echo "Unzipping"
-  if [[ $studioZipPath = *.zip ]]; then
-    unzip "${studioZipPath}" -d "${studioUnzippedPath}"
-  elif [[ $studioZipPath = *.tar.gz ]]; then
-    mkdir -p $studioUnzippedPath
-    tar -xf $studioZipPath -C $studioUnzippedPath
-  fi
-
-  createWarningTextFile
-}
-
-# ANDROID_LINT_NULLNESS_IGNORE_DEPRECATED environment variable prevents Studio from showing IDE
-# inspection warnings for nullability issues, if the context is deprecated
-# This environment variable is consumed by InteroperabilityDetector.kt
-
-function runStudioLinux() {
-  studioPath="${studioUnzippedPath}/android-studio/bin/studio.sh"
-  updateStudioLaunchScript
-  echo "$studioPath &"
-  env LAUNCHED_VIA_STUDIOW='true' \
-    STUDIO_PROPERTIES="${studioPropertiesFile}" \
-    STUDIO_VM_OPTIONS="${scriptDir}/development/studio/studio.vmoptions" \
-    ANDROID_LINT_NULLNESS_IGNORE_DEPRECATED="true" \
-    "${studioPath}" "${projectDir}" &>/dev/null &
-}
-
-function runStudioMac() {
-  appPath="$(findStudioMacAppPath)"
-  echo "open ${appPath}"
-  env STUDIO_PROPERTIES="${studioPropertiesFile}" \
-    STUDIO_VM_OPTIONS="${scriptDir}/development/studio/studio.vmoptions" \
-    ANDROID_LINT_NULLNESS_IGNORE_DEPRECATED="true" \
-    open -a "${appPath}" "${projectDir}"
-}
-
-function runStudio() {
-  local studioPropertiesFile="${androidStudioSettingsDir}/${ideaPropRelPath}"
-  updateIdeaProperties
-  # Export an env var so the gradle script can check that Android Studio was launched using this
-  # script. Launching Android Studio and then opening the Gradle project after-the-fact IS
-  # UNSUPPORTED. Android Studio needs to be lunched using studiow so that it can validate settings
-  # and update the build environment.
-  export STUDIO_LAUNCHED_WITH_WRAPPER='true'
-  if [ "${osName}" == "mac" ]; then
-    runStudioMac
-  else
-    runStudioLinux
-  fi
-}
-
-function runCleanProjectFiles() {
-  local projects=(
-    //external/setupcompat
-    //external/setupdesign
-    //frameworks/base
-    //frameworks/libs/systemui
-    //packages/apps/Launcher3
-    //platform_testing
-    //vendor/unbundled_google/libraries
-    //vendor/unbundled_google/packages/NexusLauncher
-    //packages/apps/ManagedProvisioning
-  )
-  local gitPath
-  for gitPath in "${projects[@]}"; do
-    cleanProjectFiles "$gitPath"
-  done
-  removeDirIfExists "${gradleOutDir}/build" || :
-}
-
-function cleanProjectFiles() {
-  local projectPath="$1"
-  local gitPath="${androidBuildTop}/${gitPath:1}"
-  local cleanPreview="$(git -C "$gitPath" clean --dry-run --force -X -d .)"
-  if [[ -z "$cleanPreview" ]]; then
-    echo "$projectPath already clean. Nothing to do."
-  else
-    echo "$projectPath cleaning:"
-    echo "$cleanPreview"
-    if yesNo 'Do you want to delete these files?' 'n'; then
-      git -C "$gitPath" clean --force -X -d .
-    else
-      echo "Clean operation cancelled."
-    fi
-  fi
-}
-
-function removeDirIfExists() {
-  local dir="$1"
-  if [[ -z "${dir}" ]] ; then
-    echo 'script error: removeDirIfExists expects 1 arg'
-    exit 1
-  fi
-  if [[ -d "${dir}" ]] ; then
-    if yesNo "Remove ${dir}?" 'n'; then
-      rm -rf "${dir}"
-    fi
-    return 0
-  fi
-  return 1
-}
-
-function runUninstallAndroidStudio() {
-  if ! yesNo 'This will remove the local Android Studio installation, local SDK, and project gradle files. Proceed?'; then
-    echo "Uninstall operation cancelled."
-    return
-  fi
-  removeDirIfExists "$studioHomeDir" || echo "Android Studio installation not found."
-  removeDirIfExists "$(getLegacySdkDir)" || :
-  removeDirIfExists "$(getLegacySdkDir2)" || :
-  removeDirIfExists "${gradleOutDir}" || :
-
-  runCleanProjectFiles
-}
-
-function adbGetProp() {
-  local prop="$1"
-  echo "$(adb shell getprop $prop 2>/dev/null || true)"
-}
-
-function askToUpdateSdkUsingAdb() {
-  echo ''
-  if yesNo "Update SDK using adb?"; then
-    updateSdk="adb"
-  fi
-}
-
-function checkSdkNeedsUpdate() {
-  printInfo "Android SDK Location: $sdkDir"
-  local localSdkTime="$(getProperyValueAbs $platformDir/build.prop ro.system.build.date.utc)"
-  local localSdkFingerprint="$(getProperyValueAbs $platformDir/build.prop ro.system.build.fingerprint)"
-  local utcTimeOneWeekAgo="$(expr $(date +%s) - 604800)"
-  if [[ -z "$localSdkFingerprint" ]]; then
-    localSdkFingerprint='<Unknown>'
-  fi
-
-  local sdkGenSrc="$(getProperyValueAbs $platformDir/build.prop ro.sdk.gensrc)"
-  sdkGenSrc="${sdkGenSrc:-adb}"
-  printInfo "Android SDK Fingerprint: $localSdkFingerprint"
-  printInfo "Android SDK was last updated using \"--update-sdk ${sdkGenSrc}\""
-  if [[ -z "$localSdkTime" ]]; then
-    printWarning 'Could not determine age of Android SDK. This means your SDK is corrupt or out of date.'
-    askToUpdateSdkUsingAdb
-  elif [[ "$utcTimeOneWeekAgo" -gt "$localSdkTime" ]]; then
-    printWarning 'Android SDK is more than 7 days old.'
-    askToUpdateSdkUsingAdb
-  else
-    local serial="$(adb get-serialno 2> /dev/null)"
-    if [[ -z "$serial" ]]; then
-      local noDeviceMessage='Skipping adb build check. No devices/emulators found.'
-      if [[ "$sdkGenSrc" == 'adb' ]]; then
-        printWarning "$noDeviceMessage"
-      else
-        printInfo "$noDeviceMessage"
-      fi
-    else
-      local adbSdkBuildTime="$(adbGetProp ro.system.build.date.utc)"
-      if [ "${updateSdk}" != "true" ]; then
-        if [ $adbSdkBuildTime -gt $localSdkTime ]; then
-          printWarning "Attached device has newer SDK."
-          askToUpdateSdkUsingAdb
-        fi
-      fi
-    fi
-  fi
-}
-
-function createPackageXml() {
-  local targetFile="$1"
-  local localPackage="$2"
-  local buildToolsVersion="$3"
-  local typeDetails="$4"
-  local displayName="$5"
-
-  # Split X.Y.Z-rcN into an array of X, Y, Z, and rcN
-  IFS='.-'
-  local versionNumbers=($buildToolsVersion)
-  unset IFS
-  local majorVersionString=""
-  local minorVersionString=""
-  local microVersionString=""
-  local previewVersionString=""
-  if [[ -n "${versionNumbers[0]}" ]]; then
-    majorVersionString="<major>${versionNumbers[0]}</major>"
-  fi
-  if [[ -n "${versionNumbers[1]}" ]]; then
-    minorVersionString="<minor>${versionNumbers[1]}</minor>"
-  fi
-  if [[ -n "${versionNumbers[2]}" ]]; then
-    microVersionString="<micro>${versionNumbers[2]}</micro>"
-  fi
-  # preview version includes rc if it's set, e.g. rc1. It could also be an empty string if it's not
-  # a preview version at all
-  if [[ -n "${versionNumbers[3]}" ]]; then
-    # Remove rc from the preview version number
-    previewVersionString="<preview>${versionNumbers[3]#rc}</preview>"
-  fi
-
-  ( cat <<'EOF'
-<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns2:repository xmlns:ns2="http://schemas.android.com/repository/android/common/02" xmlns:ns3="http://schemas.android.com/repository/android/common/01" xmlns:ns4="http://schemas.android.com/repository/android/generic/01" xmlns:ns5="http://schemas.android.com/repository/android/generic/02" xmlns:ns6="http://schemas.android.com/sdk/android/repo/addon2/01" xmlns:ns7="http://schemas.android.com/sdk/android/repo/addon2/02" xmlns:ns8="http://schemas.android.com/sdk/android/repo/addon2/03" xmlns:ns9="http://schemas.android.com/sdk/android/repo/repository2/01" xmlns:ns10="http://schemas.android.com/sdk/android/repo/repository2/02" xmlns:ns11="http://schemas.android.com/sdk/android/repo/repository2/03" xmlns:ns12="http://schemas.android.com/sdk/android/repo/sys-img2/03" xmlns:ns13="http://schemas.android.com/sdk/android/repo/sys-img2/02" xmlns:ns14="http://schemas.android.com/sdk/android/repo/sys-img2/01"><license id="android-sdk-license" type="text">Terms and Conditions
-
-This is the Android Software Development Kit License Agreement
-</license>
-EOF
-) > "$targetFile"
-echo "<localPackage path=\"$localPackage\" obsolete=\"false\">
-    <type-details xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ns11:platformDetailsType\">$typeDetails</type-details>
-    <revision>
-      $majorVersionString
-      $minorVersionString
-      $microVersionString
-      $previewVersionString
-    </revision>
-    <display-name>$displayName</display-name>
-    <uses-license ref=\"android-sdk-license\"/>
-  </localPackage>
-</ns2:repository>
-" >> $targetFile
-}
-
-function appendLineIfNotExists() {
-  grep -qxF "$1" $2 || echo "$1" >> $2
-}
-
-function setupMockSdk() {
-  rm -rf $sdkDir
-  mkdir -p $sdkDir
-
-  local toolsName
-  if [ "${osName}" == "mac" ]; then
-    toolsName="darwin"
-  else
-    toolsName="linux"
-  fi
-
-  # e.g. 33.0.1 OR 34.0.0-rc1
-  # In Gradle, there's a space before 'rc', but when packaged in Android/Sdk, there's a dash.
-  # To work with that, replace ' ' with '-' for usage in the script
-  local buildToolsVersion="$(getProperyValue ManagedProvisioningGradleProject/gradle.properties BUILD_TOOLS_VERSION | sed 's/ /-/')"
-
-  local adbRelPath="out/host/$toolsName-x86/bin/adb"
-  local compiledAdb="$androidBuildTop/$adbRelPath"
-  # platform tools
-  if [ ! -f $compiledAdb ]; then
-    # Check if adb exists in path (don't exit if `which` fails)
-    compiledAdb="$(which adb || true)"
-    if [ ! -f $compiledAdb ]; then
-      printError "Could not find adb at $adbRelPath or in the environment path"
-      echo "Did you build system image once?"
-      exit 1
-    fi
-  fi
-  printInfo "Using adb binary found at $compiledAdb"
-  mkdir $sdkDir/platform-tools
-  ln -s $compiledAdb $sdkDir/platform-tools/adb
-  createPackageXml $sdkDir/platform-tools/package.xml "platform-tools" "$buildToolsVersion" "" "Android SDK Platform-Tools"
-
-  # Setup build tools
-  mkdir -p $sdkDir/build-tools
-  cp -r $prebuiltsDir/sdk/tools/$toolsName/bin $sdkDir/build-tools/$buildToolsVersion
-  cp -r $prebuiltsDir/sdk/tools/$toolsName/lib $sdkDir/build-tools/$buildToolsVersion/lib
-  cp -r $prebuiltsDir/sdk/tools/$toolsName/lib64 $sdkDir/build-tools/$buildToolsVersion/lib64
-  ln -s $prebuiltsDir/sdk/renderscript $sdkDir/build-tools/$buildToolsVersion/renderscript
-  # All tools are now validated by studio, so we need to collect them all
-  cp -r $prebuiltsDir/sdk/tools/lib/* $sdkDir/build-tools/$buildToolsVersion/lib
-  cp $prebuiltsDir/sdk/tools/dx $sdkDir/build-tools/$buildToolsVersion
-
-  cp -r $prebuiltsDir/build-tools/$toolsName-x86/bin/* $sdkDir/build-tools/$buildToolsVersion/
-  cp -r $prebuiltsDir/build-tools/$toolsName-x86/lib64/* $sdkDir/build-tools/$buildToolsVersion/lib64/
-  createPackageXml $sdkDir/build-tools/$buildToolsVersion/package.xml "build-tools;$buildToolsVersion" "$buildToolsVersion" "" "Android SDK Build-Tools $buildToolsVersion"
-
-  # Setup platforms
-  mkdir -p $platformDir
-  createPackageXml $platformDir/package.xml "platforms;$compileSdkVersion" "1" "<api-level>$sdkVersionInt</api-level><codename>$compileSdkPreview</codename><layoutlib api=\"15\" />" "Android SDK Platform $upperCaseBranchName for SysUiStudio (tree=$androidBuildTop, branch=$branchName, treeId=$androidTreeUniqueId)"
-
-  prebuiltAndroidJar=$prebuiltsDir/sdk/current/system/android.jar
-
-  # Setup test and optional packages
-  mkdir $platformDir/optional
-  cp -r $prebuiltsDir/sdk/current/test/*.*.jar $platformDir/optional/
-  list=
-  for f in $platformDir/optional/*.jar; do
-    filename=$(basename -- "$f")
-    libname="${filename%.*}"
-
-    [ ! -z "$list" ] && list="$list,"
-    br=$'\n'
-    list="$list$br{ \"name\": \"$libname\", \"jar\": \"$filename\", \"manifest\": false }"
-  done
-  echo "[$list]" > $platformDir/optional/optional.json
-}
-
-function createPlatformSdk() {
-  assertHasAdbRoot
-  echo "Setting up SDK from scratch"
-  setupMockSdk
-
-  echo "Updating private apis sdk"
-  local android_jar_outfile="$platformDir/android.jar"
-  local framework_aidl="$platformDir/framework.aidl"
-  rm -rf $android_jar_outfile
-
-  local buildPropFile="$platformDir/build.prop"
-  local buildDate=
-  local buildFingerprint=
-
-  if [[ "$updateSdk" == 'adb' ]]; then
-    local tempFiles="$(mktemp -d)"
-
-    buildDate="$(adbGetProp ro.system.build.date.utc)"
-    buildFingerprint="$(adbGetProp ro.system.build.fingerprint)"
-
-    printInfo "Pulling SDK artifacts from device $buildFingerprint using adb"
-    adb pull /system/framework/framework-res.apk $tempFiles/
-    adb pull /system/framework/framework.jar $tempFiles/
-    adb pull /system/framework/framework-location.jar $tempFiles/
-
-    local dexList="--dex $tempFiles/framework.jar"
-    dexList="$dexList --dex $tempFiles/framework-location.jar"
-    local apexJars=($(adb shell ls /apex/*/javalib/*.jar))
-    for f in "${apexJars[@]}"
-    do
-      local fileBasename="$(basename $f)"
-      if [[ ! $f = *@* ]] && [[ "$fileBasename" != service-* ]]; then
-        local target="$tempFiles/$(basename $f)"
-        adb pull $f $target
-        dexList="$dexList --dex $target"
-      fi
-    done
-
-    cp $prebuiltsDir/sdk/current/public/framework.aidl $framework_aidl
-
-    java -jar $scriptDir/StubGenerator/StubGenerator.jar -o $android_jar_outfile \
-        $dexList \
-        --zip $tempFiles/framework-res.apk \
-        --zip $prebuiltAndroidJar \
-        --aidl $framework_aidl
-
-    echo "Removing temp files"
-    rm -rf $tempFiles
-
-    cp $prebuiltsDir/sdk/current/module-lib/core-for-system-modules.jar "$platformDir"
-  elif [[ "$updateSdk" == 'soong' ]]; then
-    printInfo "Building SDK artifacts using soong"
-
-    # TODO(b/251871740): Replace these steps with the output of a soong target
-    #
-    # ---- begin ----
-    #
-    local frameworks_deps=(
-      out/soong/.intermediates/build/soong/java/core-libraries/legacy.core.platform.api.stubs/android_common/turbine-combined/legacy.core.platform.api.stubs.jar
-      out/soong/.intermediates/libcore/core-lambda-stubs-for-system-modules/android_common/turbine-combined/core-lambda-stubs-for-system-modules.jar
-      out/soong/.intermediates/libcore/core-generated-annotation-stubs/android_common/turbine-combined/core-generated-annotation-stubs.jar
-      out/soong/.intermediates/frameworks/base/framework/android_common/turbine-combined/framework.jar
-      out/soong/.intermediates/frameworks/base/ext/android_common/turbine-combined/ext.jar
-      out/soong/.intermediates/frameworks/base/core/res/framework-res/android_common/package-res.apk
-      out/soong/.intermediates/tools/metalava/private-stub-annotations-jar/android_common/turbine-combined/private-stub-annotations-jar.jar
-    )
-
-    cd $androidBuildTop
-
-    . ./build/envsetup.sh
-    if [[ -n "$TARGET_PRODUCT" && -n "$TARGET_BUILD_VARIANT" ]]; then
-      if [[ -n "$TARGET_RELEASE" ]]; then
-        lunch "$TARGET_PRODUCT-$TARGET_RELEASE-$TARGET_BUILD_VARIANT"
-      else
-        lunch "$TARGET_PRODUCT-$TARGET_BUILD_VARIANT"
-      fi
-    else
-      lunch aosp_arm64-trunk_staging-userdebug
-    fi
-
-    m merge_zips sdkparcelables ${frameworks_deps[@]}
-
-    echo "Updating private apis sdk"
-    merge_zips --ignore-duplicates $android_jar_outfile ${frameworks_deps[@]}
-
-    sdkparcelables "$android_jar_outfile" "$framework_aidl"
-    # TODO(b/259594098): sdkparcelables output aidl file doesn't include all the interfaces we need
-    appendLineIfNotExists "interface android.app.IApplicationThread;" "$framework_aidl"
-    appendLineIfNotExists "interface android.view.IRecentsAnimationController;" "$framework_aidl"
-    appendLineIfNotExists "interface android.view.IRecentsAnimationRunner;" "$framework_aidl"
-    appendLineIfNotExists "interface android.view.IRemoteAnimationRunner;" "$framework_aidl"
-    appendLineIfNotExists "interface android.window.IOnBackInvokedCallback;" "$framework_aidl"
-
-    cp $prebuiltsDir/sdk/current/module-lib/core-for-system-modules.jar "$platformDir"
-    #
-    # ---- end ----
-    #
-    buildDate="$(date +%s)"
-    buildFingerprint="$(cat $ANDROID_PRODUCT_OUT/build_fingerprint.txt)"
-
-    printInfo "If you'd like to use this SDK on your laptop too, run ./studiow --update-sdk copy $(hostname):$platformDir"
-  elif [[ "${updateSdk}" == 'copy' ]]; then
-    scp "${copySdkSourceDir}"/{framework.aidl,android.jar,build.prop,core-for-system-modules.jar} "$platformDir/."
-    # Copy the build date and fingerprint from build.prop, then delete the file
-    buildDate="$(getProperyValueAbs $buildPropFile ro.system.build.date.utc)"
-    buildFingerprint="$(getProperyValueAbs $buildPropFile ro.system.build.fingerprint)"
-    rm "$buildPropFile"
-  else
-    printError "Internal error. Unknown SDK update source: $updateSdk"
-    exit 1
-  fi
-
-  {
-    echo "ro.system.build.version.sdk=$sdkVersionInt"
-    echo "ro.build.version.codename=$compileSdkPreview"
-    echo "ro.system.build.date.utc=$buildDate"
-    echo "ro.system.build.fingerprint=$buildFingerprint"
-    echo "ro.sdk.gensrc=$updateSdk"
-  } > "$buildPropFile"
-
-  cp "${scriptDir}/development/sdk/sdk.properties" "${platformDir}"
-
-  ( cat <<EOF
-Pkg.Desc=Android SDK Platform $upperCaseBranchName
-Pkg.UserSrc=false
-Platform.Version=$compileSdkPreview
-Platform.CodeName=$compileSdkPreview
-Pkg.Revision=1
-AndroidVersion.ApiLevel=$sdkVersionInt
-AndroidVersion.CodeName=$compileSdkPreview
-AndroidVersion.ExtensionLevel=5
-AndroidVersion.IsBaseSdk=true
-Layoutlib.Api=15
-Layoutlib.Revision=1
-Platform.MinToolsRev=22
-EOF
-) > "${platformDir}/source.properties"
-
-
-  echo "Generating sdk data"
-  # Sympolic link does not work here with android
-  mkdir -p $platformDir/data
-  cp -r $androidBuildTop/frameworks/base/core/res/res $platformDir/data/
-  mv $platformDir/data/res/values/public-final.xml $platformDir/data/res/values/public.xml
-
-  echo "Removing build cache"
-  rm -rf "${scriptDir}/ManagedProvisioningGradleProject/.build-cache"
-
-  echo "Accepting license"
-  cp -r ${prebuiltsDir}/cmdline-tools $sdkDir/
-  yes | $sdkDir/cmdline-tools/tools/bin/sdkmanager --licenses >/dev/null
-  rm -rf $sdkDir/cmdline-tools
-
-  echo "Linking sources"
-  ln -s $androidBuildTop/frameworks/base/core/java $platformDir/sources
-
-  echo "Done"
-}
-
-function copyFileIfAbsent() {
-  SRC=$1
-  DEST=$2
-  if [ ! -f $DEST ]; then
-    mkdir -p $(dirname $DEST)
-    cp $SRC $DEST
-  fi
-}
-
-# On mac, a newer JDK must be installed manually.
-function checkJdkVersion() {
-  if [ "${osName}" == "mac" ]; then
-    local javaHome
-    javaHome="$(/usr/libexec/java_home -v 17)"
-    if [[ "$?" -eq 0 && -n "$javaHome" ]]; then
-      return 0
-    else
-      printError "Compatible JDK not found. studiow requires JDK 17 to run Android's command-line tools for generating the SDK. Install the JDK using 'mule install jdk19' and re-run this script."
-      exit
-    fi
-  fi
-}
-
-function updateLocalGradleProperties() {
-  export ANDROID_HOME="${sdkDir}"
-  ( cat <<EOF
-sdk.dir=${sdkDir}
-EOF
-) > "$projectDir/local.properties"
-  ( cat <<EOF
-compile.sdk.preview=${compileSdkPreview}
-compile.sdk.version=${compileSdkVersion}
-EOF
-) > "$projectDir/studiow.properties"
-}
-
-function updateStudioConfig() {
-  local legacy_config_dir="${studioHomeDir}/config"
-  local config_dir="${androidStudioSettingsDir}/config"
-  if [[ "${usingDefaultSettingsDir}" == 'true' && -d "$legacy_config_dir" ]]; then
-    local message=(
-      '\n-------------------------------------------------------------------------------------\n\n'
-      "${YELLOW}WARNING:${NC} You have config files stored in ~/.AndroidStudioSystemUI/config "
-      'which will NOT be used by this instance of sysui-studio. '
-      'To support multi-branch development, '
-      "the config directory has moved to \$TOP${config_dir#"$androidBuildTop"}"
-      '\n\n'
-      'Each tree now has its own config directory. This means you may need to change your '
-      'settings for Android Studio multiple times (per branch) if, for example, you want to '
-      'change the default keymap.'
-      '\n\n'
-      'Your existing configs have NOT been automatically moved or deleted for the following '
-      'reasons:'
-      '\n\n'
-      '  1) You may want to inspect your old settings\n'
-      '  2) The old config may still be used by branches on revisions predate this change.'
-      '\n\n'
-      'For more info, see http://b/249826650'
-      '\n\n'
-      'To make this warning go away, delete ~/.AndroidStudioSystemUI/config'
-      '\n\n'
-      'To launch Android Studio with the old config, run the following:'
-      '\n'
-      '\n    studiow --settings-dir ~/.AndroidStudioSystemUI'
-      '\n'
-      '\nYou can then export your old settings using File > Manage IDE Settings > Export Settings'
-      '\n'
-      '\n-------------------------------------------------------------------------------------\n\n'
-
-    )
-    local fmt_cmd=(fmt -w 100 --split-only)
-    if [ "$osName" == "mac" ]; then
-      fmt_cmd=(fmt -w 100)
-    fi
-    printf "$(printf %s "${message[@]}")" | ${fmt_cmd[@]}
-  fi
-
-  mkdir -p "${config_dir}"
-  # Disable update checks
-  copyFileIfAbsent $scriptDir/development/studio/updates.xml "${androidStudioSettingsDir}/updates.xml"
-  # Disable instant run
-  copyFileIfAbsent $scriptDir/development/studio/instant-run.xml $config_dir/options/instant-run.xml
-  # Copy android code style
-  copyFileIfAbsent $scriptDir/development/studio/AndroidStyle.xml $config_dir/codestyles/AndroidStyle.xml
-  copyFileIfAbsent $scriptDir/development/studio/code.style.schemes.xml $config_dir/options/code.style.schemes.xml
-  # Disable notification to update gradle
-  copyFileIfAbsent $scriptDir/development/studio/notifications.xml $config_dir/options/notifications.xml
-
-  # Disable dialog that asks to trust the project
-  local trustedPathsFile="$config_dir/options/trusted-paths.xml"
-  if [ ! -f $trustedPathsFile ]; then
-    sed "s|__PROJECT_DIR_PLACEHOLDER__|$projectDir|" $scriptDir/development/studio/trusted-paths.xml > $trustedPathsFile
-  fi
-
-  # Disable dialog that asks whether to use Studio SDK or Project SDK
-  local jdkPathsFile="$config_dir/options/jdk.table.xml"
-  if [ ! -f $jdkPathsFile ]; then
-    sed "s|__SDK_DIR_PLACEHOLDER__|$sdkDir|g;s|__SDK_VERSION_NAME_PLACEHOLDER__|$compileSdkVersion|g;" $scriptDir/development/studio/jdk.table.xml > $jdkPathsFile
-  fi
-}
-
-function main() {
-  parseOptions "$@"
-
-  if [ "${uninstallAndroidStudio}" == "true" ]; then
-    runUninstallAndroidStudio
-    exit
-  fi
-
-  if [ "${cleanProjectFiles}" == "true" ]; then
-    runCleanProjectFiles
-    exit
-  fi
-
-  assertHasAdbRoot
-  setupBuildSrcSymlinks
-
-  if [ "${downloadStudioZip}" == "true" ]; then
-    fetchStudioUrl
-
-    studioDestName="$(basename ${studioUrl})"
-    studioZipPath="${studioSetupDir}/${studioDestName}"
-    studioUnzippedPath="$(echo ${studioZipPath} | sed 's/\.zip$//' | sed 's/\.tar\.gz$//')"
-  fi
-
-  # Checks if a platform SDK already exists. If it doesn't, automatically adjust the flags so that
-  # an SDK is generated by pulling files off the device.
-  if [[ -z "$updateSdk" ]]; then
-    if [[ ! -f $platformDir/android.jar ]]; then
-      printInfo "Android SDK not found. Automatically appending '--update-sdk adb' to the argument list."
-      updateSdk='adb'
-    else
-      checkSdkNeedsUpdate
-    fi
-  fi
-
-  checkJdkVersion
-
-  if [ -n "${updateSdk}" ]; then
-    createPlatformSdk
-    updateLocalGradleProperties
-  fi
-
-  if [ "${downloadStudioZip}" == "true" ]; then
-    updateStudio
-    createDesktopEntry
-  fi
-  if [ "${runStudio}" == "true" ]; then
-    checkLicenseAgreement
-    updateLocalGradleProperties
-    updateStudioConfig
-    runStudio
-  fi
-}
-
-function createDesktopEntry() {
-  studiow_path="${scriptDir}/studiow"
-  studiow_icon="${studioUnzippedPath}/android-studio/bin/studio.png"
-  targetDir="${HOME}/.local/share/applications"
-  mkdir -p "$targetDir"
-  cat "${scriptDir}/MPStudio.desktop" | \
-    sed "s|%STUDIOW_PATH%|${studiow_path}|g" | \
-    sed "s|%ANDROID_TOP%|${androidBuildTop}|g" | \
-    sed "s|%STUDIOW_ICON%|${studiow_icon}|g" > "${targetDir}/MPStudio.desktop"
-}
-
-main "$@"
diff --git a/studio-dev/test_gradle_build.sh b/studio-dev/test_gradle_build.sh
deleted file mode 100755
index 5e2dcead..00000000
--- a/studio-dev/test_gradle_build.sh
+++ /dev/null
@@ -1,85 +0,0 @@
-#!/usr/bin/env sh
-
-# Copyright 2022 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-# Script to test the SysUI-Studio gradle build.
-# The script assumes `m` has already run
-# TODO: Be more specific about which modules are dependencies
-
-print_error() {
-  local RED='\033[0;31m'
-  local NC='\033[0m'
-  printf "${RED}$1${NC}\n"
-}
-
-print_good() {
-  local GREEN='\033[0;32m'
-  local NC='\033[0m'
-  printf "${GREEN}$1${NC}\n"
-}
-
-# The default list of Gradle tasks to run if no args are passed
-DEFAULT_TASKS=(
-  :SystemUI:assemble
-  :SystemUILib:assembleAndroidTest
-  :ComposeGallery:assemble
-  :ComposeGallery:assembleAndroidTest
-  :NexusLauncher:assembleGoogleWithQuickstepDebug
-  :NexusLauncher:assembleGoogleWithQuickstepDebugAndroidTest
-  :WallpaperPickerGoogle:assembleGoogleDebug
-  :PlatformScenarioTests:assembleDebug
-)
-
-GRADLE_TASKS="$@"
-if [[ -z "$GRADLE_TASKS" ]]; then
-  GRADLE_TASKS="${DEFAULT_TASKS[@]}"
-fi
-
-SCRIPT_DIR="$(cd $(dirname $0) && pwd)"
-ANDROID_BUILD_TOP="$(cd "${SCRIPT_DIR}/../../../../../"; pwd)"
-STUDIO_DEV_DIR="${ANDROID_BUILD_TOP}/vendor/unbundled_google/packages/SystemUIGoogle/studio-dev"
-
-# The temporary artifacts directory.
-GRADLE_BUILD_DIR="${ANDROID_BUILD_TOP}/out/gradle"
-mkdir -p "${GRADLE_BUILD_DIR}"
-
-export ANDROID_HOME="${GRADLE_BUILD_DIR}/MockSdk"
-
-# Sets the path to the user preferences directory for tools that are part of the Android SDK.
-export ANDROID_USER_HOME="${GRADLE_BUILD_DIR}/.android"
-
-export JAVA_HOME="${ANDROID_BUILD_TOP}/prebuilts/jdk/jdk17/linux-x86"
-export PATH="${JAVA_HOME}/bin:${ANDROID_BUILD_TOP}/out/host/linux-x86/bin:$PATH"
-
-"${STUDIO_DEV_DIR}"/studiow --no-download --update-sdk soong || exit $?
-
-export GRADLE_USER_HOME="${GRADLE_BUILD_DIR}/gradle-user-home"
-
-export STUDIO_LAUNCHED_WITH_WRAPPER=true
-
-cd "${STUDIO_DEV_DIR}/SysUIGradleProject"
-./gradlew \
-    --refresh-dependencies \
-    --project-cache-dir="${GRADLE_BUILD_DIR}"/gradle-project-cache \
-    $GRADLE_TASKS
-
-return_code=$?
-
-if [ "${return_code}" -eq 0 ]; then
-  print_good 'Success'
-else
-  print_error 'failed to build using gradlew'
-fi
-exit "${return_code}"
diff --git a/tests/instrumentation/Android.bp b/tests/instrumentation/Android.bp
index 833bb2fe..a2ffad92 100644
--- a/tests/instrumentation/Android.bp
+++ b/tests/instrumentation/Android.bp
@@ -29,9 +29,9 @@ android_library {
     ],
     manifest: "AndroidManifest.xml",
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
     static_libs: [
         "androidx.test.rules",
diff --git a/tests/instrumentation/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityControllerTest.java b/tests/instrumentation/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityControllerTest.java
index fe5bcd79..a926a2c8 100644
--- a/tests/instrumentation/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityControllerTest.java
+++ b/tests/instrumentation/src/com/android/managedprovisioning/preprovisioning/PreProvisioningActivityControllerTest.java
@@ -90,6 +90,8 @@ import android.os.Parcelable;
 import android.os.PersistableBundle;
 import android.os.UserHandle;
 import android.os.UserManager;
+import android.platform.test.annotations.EnableFlags;
+import android.platform.test.flag.junit.SetFlagsRule;
 import android.service.persistentdata.PersistentDataBlockManager;
 import android.telephony.TelephonyManager;
 import android.text.TextUtils;
@@ -110,6 +112,7 @@ import com.android.managedprovisioning.common.PolicyComplianceUtils;
 import com.android.managedprovisioning.common.RoleGranter;
 import com.android.managedprovisioning.common.SettingsFacade;
 import com.android.managedprovisioning.common.Utils;
+import com.android.managedprovisioning.flags.Flags;
 import com.android.managedprovisioning.model.DisclaimersParam;
 import com.android.managedprovisioning.model.PackageDownloadInfo;
 import com.android.managedprovisioning.model.ProvisioningParams;
@@ -119,6 +122,7 @@ import com.android.managedprovisioning.preprovisioning.PreProvisioningActivityCo
 import com.android.managedprovisioning.util.LazyStringResource;
 
 import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
@@ -144,8 +148,8 @@ public class PreProvisioningActivityControllerTest {
                     .setCookieHeader("COOKIE_HEADER")
                     .setLocation("LOCATION")
                     .setMinVersion(1)
-                    .setPackageChecksum(new byte[] {1})
-                    .setSignatureChecksum(new byte[] {1})
+                    .setPackageChecksum(new byte[]{1})
+                    .setSignatureChecksum(new byte[]{1})
                     .build();
     public static final ProvisioningParams DOWNLOAD_ROLE_HOLDER_PARAMS_WITH_ALLOW_OFFLINE =
             ProvisioningParams.Builder.builder()
@@ -289,6 +293,8 @@ public class PreProvisioningActivityControllerTest {
     private TelephonyManager mTelephonyManager;
     @Mock
     private ContentInterface mContentInterface;
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
 
     private ProvisioningParams mParams;
     private PreProvisioningViewModel mViewModel;
@@ -301,6 +307,7 @@ public class PreProvisioningActivityControllerTest {
     static {
         TEST_ADMIN_BUNDLE.putInt("someKey", 123);
     }
+
     private Handler mHandler = new Handler(Looper.getMainLooper());
 
     @Before
@@ -400,6 +407,65 @@ public class PreProvisioningActivityControllerTest {
         verifyNoMoreInteractions(mUi);
     }
 
+    @Test
+    @EnableFlags({Flags.FLAG_BAD_STATE_V3_EARLY_RH_DOWNLOAD_ENABLED})
+    public void testInitiateProvisioning_earlyRoleHolderDownloadEnabled_preConditionChecksSkipped()
+            throws Exception {
+        enableRoleHolderDelegation();
+        mController = createControllerWithRoleHolderUpdaterInstalled();
+        // GIVEN an intent to provision a managed profile
+        prepareMocksForManagedProfileIntent(false);
+        // WHEN initiating provisioning
+        InstrumentationRegistry.getInstrumentation().runOnMainSync(() ->
+                mController.initiateProvisioning(mIntent, TEST_MDM_PACKAGE));
+
+        verify(mUi).onParamsValidated(mParams);
+        // Verify that platform call is not made here
+        verify(mDevicePolicyManager, never()).checkProvisioningPrecondition(any(), any());
+        verify(mUi).startRoleHolderUpdater(/* isRoleHolderRequestedUpdate= */ false);
+        verifyNoMoreInteractions(mUi);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_BAD_STATE_V3_EARLY_RH_DOWNLOAD_ENABLED})
+    public void testInitiateProvisioning_earlyRoleHolderDownloadEnabled_preConditionChecksSuccess()
+            throws Exception {
+        // GIVEN an intent to provision a managed profile
+        prepareMocksForManagedProfileIntent(false);
+        // WHEN initiating provisioning
+        InstrumentationRegistry.getInstrumentation().runOnMainSync(() ->
+                mController.initiateProvisioning(mIntent, TEST_MDM_PACKAGE));
+
+        verify(mUi).onParamsValidated(mParams);
+        verify(mDevicePolicyManager, times(2)).checkProvisioningPrecondition(any(), any());
+        verify(mUi).initiateUi(any(UiParams.class));
+        verifyNoMoreInteractions(mUi);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_BAD_STATE_V3_EARLY_RH_DOWNLOAD_ENABLED})
+    public void testInitiateProvisioning_earlyRoleHolderDownloadEnabled_preConditionChecksFailed()
+            throws Exception {
+        // GIVEN an intent to provision a managed profile, but provisioning mode is not allowed
+        prepareMocksForManagedProfileIntent(false);
+        when(mDevicePolicyManager.checkProvisioningPrecondition(
+                ACTION_PROVISION_MANAGED_PROFILE, TEST_MDM_PACKAGE))
+                .thenReturn(STATUS_MANAGED_USERS_NOT_SUPPORTED);
+        when(mContext.getContentResolver()).thenReturn(mContentResolver);
+        when(mContentInterface.call(anyString(), anyString(), any(), any()))
+                .thenReturn(GET_DEVICE_NAME_BUNDLE);
+        // WHEN initiating provisioning
+        mController.initiateProvisioning(mIntent, TEST_MDM_PACKAGE);
+        // THEN show an error dialog
+        verify(mUi).showErrorAndClose(
+                eq(LazyStringResource.of(R.string.cant_add_work_profile)),
+                eq(LazyStringResource.of(
+                        R.string.work_profile_cant_be_added_contact_admin, DEFAULT_DEVICE_NAME)),
+                any());
+        verify(mUi).onParamsValidated(mParams);
+        verifyNoMoreInteractions(mUi);
+    }
+
     @Test
     public void testManagedProfile_hasRoleHolderUpdaterInstalled_startsRoleHolderUpdater()
             throws Exception {
@@ -748,6 +814,7 @@ public class PreProvisioningActivityControllerTest {
     }
 
     @Test
+    @EnableFlags({Flags.FLAG_BAD_STATE_V3_EARLY_RH_DOWNLOAD_ENABLED})
     public void testManagedProfile_provisioningNotAllowed() throws Exception {
         // GIVEN an intent to provision a managed profile, but provisioning mode is not allowed
         prepareMocksForManagedProfileIntent(false);
@@ -760,6 +827,7 @@ public class PreProvisioningActivityControllerTest {
         // WHEN initiating provisioning
         mController.initiateProvisioning(mIntent, TEST_MDM_PACKAGE);
         // THEN show an error dialog
+        verify(mUi).onParamsValidated(any());
         verify(mUi).showErrorAndClose(
                 eq(LazyStringResource.of(R.string.cant_add_work_profile)),
                 eq(LazyStringResource.of(
@@ -769,24 +837,28 @@ public class PreProvisioningActivityControllerTest {
     }
 
     @Test
+    @EnableFlags({Flags.FLAG_BAD_STATE_V3_EARLY_RH_DOWNLOAD_ENABLED})
     public void testManagedProfile_nullCallingPackage() throws Exception {
         // GIVEN a device that is not currently encrypted
         prepareMocksForManagedProfileIntent(false);
         // WHEN initiating provisioning
         mController.initiateProvisioning(mIntent, null);
         // THEN error is shown
+        verify(mUi).onParamsValidated(any());
         verify(mUi).showErrorAndClose(eq(R.string.cant_set_up_device),
                 eq(R.string.contact_your_admin_for_help), any(String.class));
         verifyNoMoreInteractions(mUi);
     }
 
     @Test
+    @EnableFlags({Flags.FLAG_BAD_STATE_V3_EARLY_RH_DOWNLOAD_ENABLED})
     public void testManagedProfile_invalidCallingPackage() throws Exception {
         // GIVEN a device that is not currently encrypted
         prepareMocksForManagedProfileIntent(false);
         // WHEN initiating provisioning
         mController.initiateProvisioning(mIntent, "com.android.invalid.dpc");
         // THEN error is shown
+        verify(mUi).onParamsValidated(any());
         verify(mUi).showErrorAndClose(eq(R.string.cant_set_up_device),
                 eq(R.string.contact_your_admin_for_help), any(String.class));
         verifyNoMoreInteractions(mUi);
@@ -850,6 +922,7 @@ public class PreProvisioningActivityControllerTest {
     }
 
     @Test
+    @EnableFlags({Flags.FLAG_BAD_STATE_V3_EARLY_RH_DOWNLOAD_ENABLED})
     public void testManagedProfile_wrongPackage() throws Exception {
         // GIVEN that the provisioning intent tries to set a package different from the caller
         // as owner of the profile
@@ -857,12 +930,14 @@ public class PreProvisioningActivityControllerTest {
         // WHEN initiating managed profile provisioning
         mController.initiateProvisioning(mIntent, TEST_BOGUS_PACKAGE);
         // THEN show an error dialog and do not continue
+        verify(mUi).onParamsValidated(any());
         verify(mUi).showErrorAndClose(eq(R.string.cant_set_up_device),
                 eq(R.string.contact_your_admin_for_help), any());
         verifyNoMoreInteractions(mUi);
     }
 
     @Test
+    @EnableFlags({Flags.FLAG_BAD_STATE_V3_EARLY_RH_DOWNLOAD_ENABLED})
     public void testManagedProfile_frp() throws Exception {
         // GIVEN managed profile provisioning is invoked from SUW with FRP active
         prepareMocksForManagedProfileIntent(false);
@@ -875,6 +950,7 @@ public class PreProvisioningActivityControllerTest {
         // WHEN initiating managed profile provisioning
         mController.initiateProvisioning(mIntent, TEST_MDM_PACKAGE);
         // THEN show an error dialog and do not continue
+        verify(mUi).onParamsValidated(any());
         verify(mUi).showErrorAndClose(
                 eq(LazyStringResource.of(R.string.cant_set_up_device)),
                 eq(LazyStringResource.of(R.string.device_has_reset_protection_contact_admin,
@@ -1993,6 +2069,7 @@ public void testDeviceOwner_frp() throws Exception {
     }
 
     @Test
+    @EnableFlags({Flags.FLAG_BAD_STATE_V3_EARLY_RH_DOWNLOAD_ENABLED})
     public void testInitiateProvisioning_withActionProvisionManagedDevice_failsSilently()
             throws Exception {
         prepareMocksForDoIntent(/* skipEncryption= */ false);
@@ -2001,16 +2078,18 @@ public void testDeviceOwner_frp() throws Exception {
             mController.initiateProvisioning(mIntent, TEST_MDM_PACKAGE);
         });
 
+        verify(mUi).onParamsValidated(any());
         verify(mUi, never()).initiateUi(any());
         verify(mUi).abortProvisioning();
         verifyNoMoreInteractions(mUi);
     }
+
     private static Parcelable[] createDisclaimersExtra() {
         Bundle disclaimer = new Bundle();
         disclaimer.putString(
                 EXTRA_PROVISIONING_DISCLAIMER_HEADER, DISCLAIMER_HEADER);
         disclaimer.putParcelable(EXTRA_PROVISIONING_DISCLAIMER_CONTENT, DISCLAIMER_CONTENT_URI);
-        return new Parcelable[]{ disclaimer };
+        return new Parcelable[]{disclaimer};
     }
 
     private ProvisioningParams.Builder createProvisioningParamsBuilderForInitiateProvisioning() {
```

