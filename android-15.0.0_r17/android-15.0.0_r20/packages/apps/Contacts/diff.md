```diff
diff --git a/README b/README
new file mode 100644
index 000000000..1372f2874
--- /dev/null
+++ b/README
@@ -0,0 +1,4 @@
+This app is not actively supported and the source is only available as a
+reference. This project will be removed from the source manifest sometime in the
+future.
+
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index ffcd2ea1b..a145823dd 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -280,7 +280,7 @@
     <string name="clearFrequentsProgress_title" msgid="8271935295080659743">"Brisanje često kontaktiranih osoba…"</string>
     <string name="status_available" msgid="8081626460682959098">"Dostupno"</string>
     <string name="status_away" msgid="2677693194455091315">"Odsutan"</string>
-    <string name="status_busy" msgid="2759339190187696727">"Zauzeto"</string>
+    <string name="status_busy" msgid="2759339190187696727">"Zauzet/a"</string>
     <string name="local_invisible_directory" msgid="5936234374879813300">"Ostalo"</string>
     <string name="directory_search_label" msgid="2602118204885565153">"Direktorij"</string>
     <string name="directory_search_label_work" msgid="2392128956332931231">"Poslovni imenik"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 8b5bf865c..e982ebf91 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -100,7 +100,7 @@
     <string name="contactSavedErrorToast" msgid="3213619905154956918">"No s\'han pogut desar els canvis al contacte"</string>
     <string name="contactUnlinkErrorToast" msgid="7289356996668886841">"No s\'ha pogut desenllaçar el contacte"</string>
     <string name="contactJoinErrorToast" msgid="1222155997933362787">"No s\'ha pogut enllaçar el contacte"</string>
-    <string name="contactGenericErrorToast" msgid="5689457475864876100">"S\'ha produït un error en desar el contacte"</string>
+    <string name="contactGenericErrorToast" msgid="5689457475864876100">"Hi ha hagut un error en desar el contacte"</string>
     <string name="contactPhotoSavedErrorToast" msgid="8568460180541397272">"No s\'han pogut desar els canvis de la foto de contacte"</string>
     <string name="groupLoadErrorToast" msgid="4141488223976370583">"L\'etiqueta no s\'ha pogut carregar"</string>
     <string name="groupDeletedToast" msgid="7774363940327847515">"L\'etiqueta s\'ha suprimit"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 6d33fc5b9..b74caff5e 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -70,7 +70,7 @@
     <string name="contacts_count_with_account" msgid="3921405666045433256">"{count,plural, =1{# contacto · {account}}other{# contactos · {account}}}"</string>
     <string name="title_from_google" msgid="2554633992366572820">"De Google"</string>
     <string name="title_from_other_accounts" msgid="7813596336566711843">"De <xliff:g id="ACCOUNT">%s</xliff:g>"</string>
-    <string name="menu_set_ring_tone" msgid="8876328286439724181">"Establecer tono"</string>
+    <string name="menu_set_ring_tone" msgid="8876328286439724181">"Establecer tono de llamada"</string>
     <string name="menu_redirect_calls_to_vm" msgid="3027178444991878913">"Redirigir al buzón de voz"</string>
     <string name="menu_unredirect_calls_to_vm" msgid="2294919685954790892">"No redirigir al buzón de voz"</string>
     <string name="readOnlyContactWarning" msgid="4158660823025751201">"Este contacto es de solo lectura. No se puede eliminar, pero sí ocultar."</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 72880ac60..6a271a6e0 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -411,7 +411,7 @@
     <string name="caching_vcard_message" msgid="1879339732783666517">"در حال ذخیره کارت‌های ویزیت در حافظه موقت محلی است. وارد کردن واقعی به زودی آغاز خواهد شد."</string>
     <string name="vcard_import_failed" msgid="37313715326741013">"وارد کردن کارت ویزیت انجام نشد."</string>
     <string name="nfc_vcard_file_name" msgid="2113518216329123152">"‏مخاطب از طریق NFC رسید"</string>
-    <string name="caching_vcard_title" msgid="6333926052524937628">"در حال ذخیره در حافظهٔ پنهان"</string>
+    <string name="caching_vcard_title" msgid="6333926052524937628">"در حال ذخیره در حافظه نهان"</string>
     <string name="progress_notifier_message" msgid="8522060892889599746">"وارد کردن <xliff:g id="CURRENT_NUMBER">%1$s</xliff:g>/<xliff:g id="TOTAL_NUMBER">%2$s</xliff:g>: <xliff:g id="NAME">%3$s</xliff:g>"</string>
     <string name="export_to_vcf_file" msgid="3096479544575798192">"‏صادر کردن به فایل ‎.vcf"</string>
     <string name="display_options_sort_list_by" msgid="4333658089057400431">"به‌ترتیب"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index e1c08ccec..639c1f115 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -355,7 +355,7 @@
     <string name="announce_expanded_fields" msgid="8410808184164186871">"વિસ્તૃત કર્યું"</string>
     <string name="announce_collapsed_fields" msgid="7611318715383228182">"સંકુચિત કર્યું"</string>
     <string name="list_filter_all_accounts" msgid="6173785387972096770">"તમામ સંપર્કો"</string>
-    <string name="list_filter_all_starred" msgid="2582865760150432568">"તારાંકિત કરેલ"</string>
+    <string name="list_filter_all_starred" msgid="2582865760150432568">"સ્ટાર આપેલા"</string>
     <string name="list_filter_customize" msgid="2368900508906139537">"કસ્ટમાઇઝ કરો"</string>
     <string name="list_filter_single" msgid="6003845379327432129">"સંપર્ક"</string>
     <string name="display_ungrouped" msgid="4823012484407759332">"તમામ અન્ય સંપર્કો"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 3cb8a024d..f59d617fd 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -71,7 +71,7 @@
     <string name="title_from_google" msgid="2554633992366572820">"Google से"</string>
     <string name="title_from_other_accounts" msgid="7813596336566711843">"<xliff:g id="ACCOUNT">%s</xliff:g> से"</string>
     <string name="menu_set_ring_tone" msgid="8876328286439724181">"रिंगटोन सेट करें"</string>
-    <string name="menu_redirect_calls_to_vm" msgid="3027178444991878913">"वॉइसमेल पर रूट करें"</string>
+    <string name="menu_redirect_calls_to_vm" msgid="3027178444991878913">"वॉइसमेल पर डायरेक्ट करें"</string>
     <string name="menu_unredirect_calls_to_vm" msgid="2294919685954790892">"वॉइसमेल से रूट हटाएं"</string>
     <string name="readOnlyContactWarning" msgid="4158660823025751201">"यह संपर्क केवल पढ़ने के लिए है. इसे हटाया नहीं जा सकता है, लेकिन आप इसे छिपा सकते हैं."</string>
     <string name="readOnlyContactWarning_positive_button" msgid="2602676689104338036">"संपर्क छिपाएं"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index d868cea86..a087d99a6 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -389,7 +389,7 @@
     <string name="exporting_vcard_finished_title" msgid="1984393609140969504">"הייצוא של <xliff:g id="FILENAME">%s</xliff:g> הסתיים."</string>
     <string name="exporting_vcard_finished_title_fallback" msgid="9029067439586573959">"הייצוא של אנשי הקשר הסתיים."</string>
     <string name="exporting_vcard_finished_toast" msgid="5463125514187187782">"היצוא של אנשי הקשר הסתיים. לחץ על ההודעה כדי לשתף אנשי קשר."</string>
-    <string name="touch_to_share_contacts" msgid="7678194978416052577">"הקש כדי לשתף אנשי קשר."</string>
+    <string name="touch_to_share_contacts" msgid="7678194978416052577">"יש ללחוץ כדי לשתף אנשי קשר."</string>
     <string name="exporting_vcard_canceled_title" msgid="1287529222628052526">"הייצוא של <xliff:g id="FILENAME">%s</xliff:g> בוטל."</string>
     <string name="exporting_contact_list_title" msgid="6599904516394311592">"מייצא נתונים של אנשי קשר"</string>
     <string name="exporting_contact_list_message" msgid="6253904938452184387">"ייצוא הנתונים של אנשי הקשר מתבצע."</string>
@@ -477,9 +477,9 @@
     <string name="sim_import_failed_toast" msgid="358117391138073786">"‏לא ניתן היה לייבא את אנשי הקשר מכרטיס ה-SIM"</string>
     <string name="sim_import_title" msgid="8202961146093040684">"‏ייבוא מכרטיס SIM"</string>
     <string name="sim_import_cancel_content_description" msgid="4746065462808862682">"ביטול"</string>
-    <string name="auto_sync_off" msgid="7039314601316227882">"הסינכרון האוטומטי מושבת. הקש כדי להפעיל אותו."</string>
+    <string name="auto_sync_off" msgid="7039314601316227882">"הסינכרון האוטומטי מושבת. יש ללחוץ כדי להפעיל אותו."</string>
     <string name="dismiss_sync_alert" msgid="4057176963960104786">"ביטול"</string>
-    <string name="account_sync_off" msgid="6187683798342006021">"סנכרון החשבון מושבת. הקש כדי להפעיל אותו."</string>
+    <string name="account_sync_off" msgid="6187683798342006021">"סנכרון החשבון מושבת. יש ללחוץ כדי להפעיל אותו."</string>
     <string name="turn_auto_sync_on_dialog_title" msgid="3812155064863594938">"האם להשבית את הסנכרון האוטומטי?"</string>
     <string name="turn_auto_sync_on_dialog_body" msgid="5386810641905184682">"‏השינויים שתבצע בכל האפליקציות והחשבונות, לא רק באנשי הקשר מחשבון Google, יסונכרנו בין האינטרנט לבין המכשירים שלך."</string>
     <string name="turn_auto_sync_on_dialog_confirm_btn" msgid="5575717918836806519">"הפעלה"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 13a3f98cc..29bdd1d90 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -76,12 +76,12 @@
     <string name="readOnlyContactWarning" msgid="4158660823025751201">"ಈ ಸಂಪರ್ಕವು ಓದಲು-ಮಾತ್ರ ಆಗಿದೆ. ಇದನ್ನು ಅಳಿಸಲಾಗುವುದಿಲ್ಲ ಆದರೆ ನೀವು ಇದನ್ನು ಮರೆಮಾಡಬಹುದಾಗಿದೆ."</string>
     <string name="readOnlyContactWarning_positive_button" msgid="2602676689104338036">"ಸಂಪರ್ಕವನ್ನು ಮರೆಮಾಡಿ"</string>
     <string name="readOnlyContactDeleteConfirmation" msgid="2759786078454970110">"ಈ ಸಂಪರ್ಕದಲ್ಲಿ ಓದಲು-ಮಾತ್ರ ಖಾತೆಗಳನ್ನು ಮರೆಮಾಡಲಾಗುತ್ತದೆ, ಅಳಿಸಲಾಗುವುದಿಲ್ಲ."</string>
-    <string name="single_delete_confirmation" msgid="8260949300855537648">"ಈ ಸಂಪರ್ಕವನ್ನು ಅಳಿಸುವುದೇ?"</string>
-    <string name="batch_delete_confirmation" msgid="4149615167210863403">"ಆಯ್ಕೆ ಮಾಡಲಾದ ಸಂಪರ್ಕಗಳನ್ನು ಅಳಿಸುವುದೇ?"</string>
+    <string name="single_delete_confirmation" msgid="8260949300855537648">"ಈ ಸಂಪರ್ಕವನ್ನು ಅಳಿಸಬೇಕೆ?"</string>
+    <string name="batch_delete_confirmation" msgid="4149615167210863403">"ಆಯ್ಕೆ ಮಾಡಲಾದ ಸಂಪರ್ಕಗಳನ್ನು ಅಳಿಸಬೇಕೆ?"</string>
     <string name="batch_delete_read_only_contact_confirmation" msgid="381691735715182700">"ನಿಮ್ಮ ಓದಲು-ಮಾತ್ರ ಖಾತೆಗಳಿಂದ ಸಂಪರ್ಕಗಳನ್ನು ಅಳಿಸಲಾಗುವುದಿಲ್ಲ, ಆದರೆ ಅವುಗಳನ್ನು ಮರೆಮಾಡಬಹುದು."</string>
     <string name="batch_delete_multiple_accounts_confirmation" msgid="4547718538924570984">"ಬಹು ಖಾತೆಗಳಿಂದ ವಿವರಗಳನ್ನು ಹೊಂದಿರುವ ಸಂಪರ್ಕಗಳನ್ನು ಅಳಿಸಲಾಗುತ್ತದೆ. ಓದಲು-ಮಾತ್ರ ಖಾತೆಗಳಿಂದ ವಿವರಗಳನ್ನು ಮರೆಮಾಡಲಾಗುತ್ತದೆ, ಅಳಿಸಲಾಗುವುದಿಲ್ಲ."</string>
     <string name="multipleContactDeleteConfirmation" msgid="2970218685653877287">"ಈ ಸಂಪರ್ಕವನ್ನು ಅಳಿಸುವುದರಿಂದ ಅದಕ್ಕೆ ಸಂಬಂಧಿಸಿದ ವಿವರಗಳನ್ನು ಬಹು ಖಾತೆಗಳಿಂದ ಅಳಿಸಲಾಗುತ್ತದೆ."</string>
-    <string name="deleteConfirmation" msgid="3727809366015979585">"ಈ ಸಂಪರ್ಕವನ್ನು ಅಳಿಸುವುದೇ?"</string>
+    <string name="deleteConfirmation" msgid="3727809366015979585">"ಈ ಸಂಪರ್ಕವನ್ನು ಅಳಿಸಬೇಕೆ?"</string>
     <string name="deleteConfirmation_positive_button" msgid="1604511403421785160">"ಅಳಿಸಿ"</string>
     <string name="invalidContactMessage" msgid="6204402264821083362">"ಸಂಪರ್ಕವು ಅಸ್ತಿತ್ವದಲ್ಲಿಲ್ಲ."</string>
     <string name="createContactShortcutSuccessful_NoName" msgid="532242135930208299">"ಸಂಪರ್ಕವನ್ನು ಹೋಮ್ ಸ್ಕ್ರೀನ್‌ಗೆ ಸೇರಿಸಲಾಗಿದೆ."</string>
@@ -162,10 +162,10 @@
     <string name="contacts_unavailable_add_account" msgid="5196453892411710750">"ಖಾತೆ ಸೇರಿಸಿ"</string>
     <string name="contacts_unavailable_import_contacts" msgid="4914180876114104054">"ಆಮದು ಮಾಡಿ"</string>
     <string name="create_group_item_label" msgid="921929508079162463">"ಹೊಸದನ್ನು ರಚಿಸಿ…"</string>
-    <string name="delete_group_dialog_message" msgid="754082019928025404">"\"<xliff:g id="GROUP_LABEL">%1$s</xliff:g>\" ಲೇಬಲ್ ಅಳಿಸುವುದೇ? (ಸಂಪರ್ಕಗಳು ತಾವಾಗಿ ಅಳಿಸಿ ಹೋಗುವುದಿಲ್ಲ.)"</string>
+    <string name="delete_group_dialog_message" msgid="754082019928025404">"\"<xliff:g id="GROUP_LABEL">%1$s</xliff:g>\" ಲೇಬಲ್ ಅಳಿಸಬೇಕೆ? (ಸಂಪರ್ಕಗಳು ತಾವಾಗಿ ಅಳಿಸಿ ಹೋಗುವುದಿಲ್ಲ.)"</string>
     <string name="toast_join_with_empty_contact" msgid="3886468280665325350">"ಮತ್ತೊಬ್ಬರೊಂದಿಗೆ ಲಿಂಕ್ ಮಾಡುವ ಮೊದಲು ಸಂಪರ್ಕದ ಹೆಸರನ್ನು ಟೈಪ್‌ ಮಾಡಿ."</string>
     <string name="copy_text" msgid="6835250673373028909">"ಕ್ಲಿಪ್‌ಬೋರ್ಡ್‌ಗೆ ನಕಲಿಸಿ"</string>
-    <string name="set_default" msgid="3704074175618702225">"ಡೀಫಾಲ್ಟ್ ಹೊಂದಿಸಿ"</string>
+    <string name="set_default" msgid="3704074175618702225">"ಡೀಫಾಲ್ಟ್ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="clear_default" msgid="2055883863621491533">"ಡಿಫಾಲ್ಟ್‌ ತೆರವುಗೊಳಿಸಿ"</string>
     <string name="toast_text_copied" msgid="845906090076228771">"ಪಠ್ಯವನ್ನು ನಕಲಿಸಲಾಗಿದೆ"</string>
     <string name="cancel_confirmation_dialog_message" msgid="7486892574762212762">"ಬದಲಾವಣೆಗಳನ್ನು ತ್ಯಜಿಸುವುದೇ?"</string>
@@ -426,7 +426,7 @@
     <string name="settings_accounts" msgid="119582613811929994">"ಖಾತೆಗಳು"</string>
     <string name="default_editor_account" msgid="4810392921888877149">"ಹೊಸ ಸಂಪರ್ಕಗಳಿಗೆ ಡಿಫಾಲ್ಟ್‌ ಖಾತೆ"</string>
     <string name="settings_my_info_title" msgid="6236848378653551341">"ನನ್ನ ಮಾಹಿತಿ"</string>
-    <string name="set_up_profile" msgid="3554999219868611431">"ನಿಮ್ಮ ಪ್ರೊಫೈಲ್ ಹೊಂದಿಸಿ"</string>
+    <string name="set_up_profile" msgid="3554999219868611431">"ನಿಮ್ಮ ಪ್ರೊಫೈಲ್ ಸೆಟಪ್ ಮಾಡಿ"</string>
     <string name="setting_about" msgid="2941859292287597555">"ಸಂಪರ್ಕಗಳ ಕುರಿತು"</string>
     <string name="share_favorite_contacts" msgid="8208444020721686178">"ಮೆಚ್ಚಿನ ಸಂಪರ್ಕಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಿ"</string>
     <string name="share_contacts" msgid="2377773269568609796">"ಎಲ್ಲ ಸಂಪರ್ಕಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಿ"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index ccba17350..8b807ef27 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -70,7 +70,7 @@
     <string name="contacts_count_with_account" msgid="3921405666045433256">"{count,plural, =1{# kontaktpersona · {account}}zero{# kontaktpersonu · {account}}one{# kontaktpersona · {account}}other{# kontaktpersonas · {account}}}"</string>
     <string name="title_from_google" msgid="2554633992366572820">"No Google"</string>
     <string name="title_from_other_accounts" msgid="7813596336566711843">"No konta <xliff:g id="ACCOUNT">%s</xliff:g>"</string>
-    <string name="menu_set_ring_tone" msgid="8876328286439724181">"Iestatīt zv. signālu"</string>
+    <string name="menu_set_ring_tone" msgid="8876328286439724181">"Iestatīt zvana signālu"</string>
     <string name="menu_redirect_calls_to_vm" msgid="3027178444991878913">"Maršrutēt uz balss pastu"</string>
     <string name="menu_unredirect_calls_to_vm" msgid="2294919685954790892">"Atcelt maršrutēšanu"</string>
     <string name="readOnlyContactWarning" msgid="4158660823025751201">"Šī kontaktpersona ir tikai lasāma. To nevar dzēst, bet var paslēpt."</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 55c2b447d..6ad222e46 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -192,7 +192,7 @@
     <string name="action_menu_add_new_contact_button" msgid="1201339383074001291">"Создај нов контакт"</string>
     <string name="expanding_entry_card_view_see_more" msgid="6636033205952561590">"Прикажи повеќе"</string>
     <string name="expanding_entry_card_view_see_less" msgid="6399603072579278030">"Погледни помалку"</string>
-    <string name="about_card_title" msgid="6635849009952435700">"За"</string>
+    <string name="about_card_title" msgid="6635849009952435700">"Информации"</string>
     <string name="toast_making_personal_copy" msgid="9053129410039312386">"Се создава лична копија..."</string>
     <string name="date_time_set" msgid="8526160894146496334">"Постави"</string>
     <string name="header_im_entry" msgid="3581797653862294826">"IM"</string>
@@ -478,7 +478,7 @@
     <string name="sim_import_title" msgid="8202961146093040684">"Увоз од SIM"</string>
     <string name="sim_import_cancel_content_description" msgid="4746065462808862682">"Откажи"</string>
     <string name="auto_sync_off" msgid="7039314601316227882">"Автоматското синхронизирање е исклучено. Допрете за да го вклучите."</string>
-    <string name="dismiss_sync_alert" msgid="4057176963960104786">"Отфрлете"</string>
+    <string name="dismiss_sync_alert" msgid="4057176963960104786">"Отфрли"</string>
     <string name="account_sync_off" msgid="6187683798342006021">"Автоматското синхронизирање е исклучено. Допрете за да го вклучите."</string>
     <string name="turn_auto_sync_on_dialog_title" msgid="3812155064863594938">"Да се вклучи автоматско синхронизирање?"</string>
     <string name="turn_auto_sync_on_dialog_body" msgid="5386810641905184682">"Промените што ги правите на сите апликации и сметки, не само на „Контакти на Google“, ќе се ажурираат и на интернет и на вашите уреди."</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 287ea0ce8..81d69de48 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -58,7 +58,7 @@
     <string name="menu_save" msgid="7204524700499687371">"Simpan"</string>
     <string name="titleJoinContactDataWith" msgid="7342386037654890242">"Paut kenalan"</string>
     <string name="blurbJoinContactDataWith" msgid="132105056919797709">"Pilih kenalan yang anda mahu pautkan dengan <xliff:g id="NAME">%s</xliff:g>:"</string>
-    <string name="separatorJoinAggregateSuggestions" msgid="8347769365870796983">"Kenalan cadangan"</string>
+    <string name="separatorJoinAggregateSuggestions" msgid="8347769365870796983">"Cadangan kenalan"</string>
     <string name="separatorJoinAggregateAll" msgid="5378346138684490784">"Semua kenalan"</string>
     <string name="contactsJoinedNamedMessage" msgid="8732933595873458166">"<xliff:g id="NAME">%s</xliff:g> dipaut"</string>
     <string name="contactsJoinedMessage" msgid="7605856897709458707">"Kenalan dipaut"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 989371fe2..91e8b3334 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -290,7 +290,7 @@
     <string name="favoritesFrequentContacted" msgid="2885862854079966676">"लगातार सम्पर्क गरिएको"</string>
     <string name="list_filter_phones" msgid="6839133198968393843">"फोन नम्बर भएका सबै कन्ट्याक्टहरू"</string>
     <string name="list_filter_phones_work" msgid="5583425697781385616">"कार्य प्रोफाइलका कन्ट्याक्टहरू"</string>
-    <string name="view_updates_from_group" msgid="6233444629074835594">"अद्यावधिकहरू हेर्नुहोस्"</string>
+    <string name="view_updates_from_group" msgid="6233444629074835594">"अपडेटहरू हेर्नुहोस्"</string>
     <string name="account_phone" msgid="8044426231251817556">"यन्त्र"</string>
     <string name="account_sim" msgid="3200457113308694663">"SIM"</string>
     <string name="nameLabelsGroup" msgid="513809148312046843">"नाम"</string>
@@ -477,9 +477,9 @@
     <string name="sim_import_failed_toast" msgid="358117391138073786">"SIM को कन्ट्याक्टहरू इम्पोर्ट गर्न सकिएन"</string>
     <string name="sim_import_title" msgid="8202961146093040684">"SIM बाट इम्पोर्ट गर्नुहोस्"</string>
     <string name="sim_import_cancel_content_description" msgid="4746065462808862682">"रद्द गर्नुहोस्"</string>
-    <string name="auto_sync_off" msgid="7039314601316227882">"स्वत:सिङ्क गर्ने सेवा निष्क्रिय छ। सक्रिय गर्न ट्याप गर्नुहोस्।"</string>
+    <string name="auto_sync_off" msgid="7039314601316227882">"स्वत:सिङ्क गर्ने सेवा अफ छ। सक्रिय गर्न ट्याप गर्नुहोस्।"</string>
     <string name="dismiss_sync_alert" msgid="4057176963960104786">"खारेज गर्नुहोस्"</string>
-    <string name="account_sync_off" msgid="6187683798342006021">"खाता सिङ्क गर्ने सेवा निष्क्रिय छ। सक्रिय पार्न ट्याप गर्नुहोस्।"</string>
+    <string name="account_sync_off" msgid="6187683798342006021">"खाता सिङ्क गर्ने सेवा अफ छ। सक्रिय पार्न ट्याप गर्नुहोस्।"</string>
     <string name="turn_auto_sync_on_dialog_title" msgid="3812155064863594938">"स्वत: सिंक सेवा सक्रिय गर्ने हो?"</string>
     <string name="turn_auto_sync_on_dialog_body" msgid="5386810641905184682">"तपाईंले Google सम्पर्कहरूमा मात्र नभई, सबै एप र खाताहरूमा गरेका परिवर्तनहरू वेब र तपाईंका अन्य यन्त्रहरूका बीचमा अद्यावधिक हुने छन्।"</string>
     <string name="turn_auto_sync_on_dialog_confirm_btn" msgid="5575717918836806519">"अन गर्नुहोस्"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 4a5a55d2e..056ed3539 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -203,7 +203,7 @@
     <string name="header_event_entry" msgid="70962228694476731">"ଇଭେଣ୍ଟ"</string>
     <string name="header_relation_entry" msgid="993618132732521944">"ସମ୍ପର୍କ"</string>
     <string name="header_name_entry" msgid="2516776099121101578">"ନାମ"</string>
-    <string name="header_email_entry" msgid="8653569770962542178">"ଇମେଲ୍"</string>
+    <string name="header_email_entry" msgid="8653569770962542178">"ଇମେଲ"</string>
     <string name="header_phone_entry" msgid="7092868248113091293">"ଫୋନ୍"</string>
     <string name="content_description_directions" msgid="860179347986211929">"ଲୋକେସନ୍ ପାଇଁ ଦିଗନିର୍ଦ୍ଦେଶ"</string>
     <string name="editor_more_fields" msgid="6158558083947445518">"ଅଧିକ କ୍ଷେତ୍ର"</string>
@@ -305,7 +305,7 @@
     <string name="name_phonetic_middle" msgid="6528822054594516485">"ଫୋନେଟିକ୍ ମଧ୍ୟ ନାମ"</string>
     <string name="name_phonetic_family" msgid="1690852801039809448">"ଫୋନେଟିକ୍‍ ଶେଷ ନାମ"</string>
     <string name="phoneLabelsGroup" msgid="2746758650001801885">"ଫୋନ୍"</string>
-    <string name="emailLabelsGroup" msgid="3360719560200449554">"ଇମେଲ୍"</string>
+    <string name="emailLabelsGroup" msgid="3360719560200449554">"ଇମେଲ"</string>
     <string name="postalLabelsGroup" msgid="7534317297587527570">"ଠିକଣା"</string>
     <string name="imLabelsGroup" msgid="2113398976789806432">"IM"</string>
     <string name="organizationLabelsGroup" msgid="2342482097897299099">"ସଂସ୍ଥା"</string>
@@ -324,9 +324,9 @@
     <string name="email_home" msgid="1102791500866910269">"ଘର ଇମେଲ୍ ଠିକଣାରେ ଇମେଲ୍ କରନ୍ତୁ"</string>
     <string name="email_mobile" msgid="6461172430397598705">"ମୋବାଇଲ୍‍‍‍‍କୁ ଇମେଲ୍ ପଠାନ୍ତୁ"</string>
     <string name="email_work" msgid="24992619164533704">"କାର୍ଯ୍ୟସ୍ଥଳୀକୁ ଇମେଲ୍‍ ପଠାନ୍ତୁ"</string>
-    <string name="email_other" msgid="9200478615023952240">"ଇମେଲ୍"</string>
+    <string name="email_other" msgid="9200478615023952240">"ଇମେଲ"</string>
     <string name="email_custom" msgid="4614140345586842953">"<xliff:g id="CUSTOM_LABEL">%s</xliff:g>କୁ ଇମେଲ୍ କରନ୍ତୁ"</string>
-    <string name="email" msgid="7367975425670798827">"ଇମେଲ୍"</string>
+    <string name="email" msgid="7367975425670798827">"ଇମେଲ"</string>
     <string name="postal_street" msgid="43809570436400749">"ମାର୍ଗ"</string>
     <string name="postal_city" msgid="3571927981675393150">"ସହର"</string>
     <string name="postal_region" msgid="6130239447563491435">"ରାଜ୍ୟ"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index aa9fa60ac..e6cb4f8af 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -70,7 +70,7 @@
     <string name="contacts_count_with_account" msgid="3921405666045433256">"{count,plural, =1{# persoană de contact · {account}}few{# persoane de contact · {account}}other{# de persoane de contact · {account}}}"</string>
     <string name="title_from_google" msgid="2554633992366572820">"Din Google"</string>
     <string name="title_from_other_accounts" msgid="7813596336566711843">"Din <xliff:g id="ACCOUNT">%s</xliff:g>"</string>
-    <string name="menu_set_ring_tone" msgid="8876328286439724181">"Setați ton apel"</string>
+    <string name="menu_set_ring_tone" msgid="8876328286439724181">"Setează ton apel"</string>
     <string name="menu_redirect_calls_to_vm" msgid="3027178444991878913">"Trimiteți la mesageria vocală"</string>
     <string name="menu_unredirect_calls_to_vm" msgid="2294919685954790892">"Nu mai trimiteți la mesagerie"</string>
     <string name="readOnlyContactWarning" msgid="4158660823025751201">"Această intrare în Agendă este numai în citire. Nu poate fi ștearsă, dar o puteți ascunde."</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 66694dba8..e7a0a0554 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -180,7 +180,7 @@
     <string name="contact_editor_prompt_one_account" msgid="765343809177951169">"Mase-save ang mga bagong contact sa <xliff:g id="ACCOUNT_NAME">%1$s</xliff:g>."</string>
     <string name="contact_editor_prompt_multiple_accounts" msgid="1543322760761168351">"Pumili ng default na account para sa mga bagong contact:"</string>
     <string name="contact_editor_title_new_contact" msgid="7534775011591770343">"Gumawa ng bagong contact"</string>
-    <string name="contact_editor_title_existing_contact" msgid="3647774955741654029">"I-edit"</string>
+    <string name="contact_editor_title_existing_contact" msgid="3647774955741654029">"I-edit ang contact"</string>
     <string name="contact_editor_title_read_only_contact" msgid="5494810291515292596">"Pagtingin lang"</string>
     <string name="contact_editor_pick_raw_contact_to_edit_dialog_title" msgid="4478782370280424187">"Pumili ng contact upang i-edit"</string>
     <string name="contact_editor_pick_linked_contact_dialog_title" msgid="3332134735168016293">"Mga naka-link na contact"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index f0b06a39c..4a6e213c8 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -28,7 +28,7 @@
     <string name="groupMemberPickerActivityTitle" msgid="8745419913947478380">"選取"</string>
     <string name="header_entry_contact_list_adapter_header_title" msgid="4098233078586958762">"建立新聯絡人"</string>
     <string name="searchHint" msgid="1487501532610025473">"搜尋聯絡人"</string>
-    <string name="menu_addStar" msgid="4903812703386825130">"加到我的收藏"</string>
+    <string name="menu_addStar" msgid="4903812703386825130">"新增至我的最愛"</string>
     <string name="menu_removeStar" msgid="3707373931808303701">"從我的收藏中移除"</string>
     <string name="description_action_menu_remove_star" msgid="4044390281910122890">"已從我的最愛中移除"</string>
     <string name="description_action_menu_add_star" msgid="7316521132809388851">"已加到我的最愛"</string>
diff --git a/src/com/android/contacts/vcard/ImportVCardDialogFragment.java b/src/com/android/contacts/vcard/ImportVCardDialogFragment.java
index 7ad67d135..bd7f33f98 100644
--- a/src/com/android/contacts/vcard/ImportVCardDialogFragment.java
+++ b/src/com/android/contacts/vcard/ImportVCardDialogFragment.java
@@ -57,6 +57,7 @@ public class ImportVCardDialogFragment extends DialogFragment {
 
         final ImportVCardDialogFragment dialog = new ImportVCardDialogFragment();
         dialog.setArguments(args);
+        dialog.setCancelable(false);
         dialog.show(activity.getFragmentManager(), TAG);
     }
 
```

