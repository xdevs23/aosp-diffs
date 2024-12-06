```diff
diff --git a/aconfig/FeatureFlags.aconfig b/aconfig/FeatureFlags.aconfig
index 71974cf8..8396bc24 100644
--- a/aconfig/FeatureFlags.aconfig
+++ b/aconfig/FeatureFlags.aconfig
@@ -5,23 +5,6 @@ container: "system"
 # namespace: intentresolver
 # bug: "Feature_Bug_#" or "<none>"
 
-flag {
-  name: "fix_target_list_footer"
-  namespace: "intentresolver"
-  description: "Update app target grid footer on window insets change"
-  bug: "324011248"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
-flag {
-  name: "target_data_caching"
-  namespace: "intentresolver"
-  description: "Enables caching target icons and labels in a local DB"
-  bug: "285314844"
-}
-
 flag {
   name: "modular_framework"
   namespace: "intentresolver"
@@ -29,13 +12,6 @@ flag {
   bug: "302113519"
 }
 
-flag {
-  name: "bespoke_label_view"
-  namespace: "intentresolver"
-  description: "Use a custom view to draw target labels"
-  bug: "302188527"
-}
-
 flag {
   name: "enable_private_profile"
   namespace: "intentresolver"
@@ -53,6 +29,16 @@ flag {
   }
 }
 
+flag {
+  name: "fix_drawer_offset_on_config_change"
+  namespace: "intentresolver"
+  description: "Fix drawer offset calculation after rotating when in a non-initial tab"
+  bug: "344057117"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
 flag {
   name: "fix_empty_state_padding"
   namespace: "intentresolver"
@@ -71,10 +57,10 @@ flag {
 }
 
 flag {
-  name: "fix_partial_image_edit_transition"
+  name: "fix_missing_drawer_offset_calculation"
   namespace: "intentresolver"
-  description: "Do not run the shared element transition animation for a partially visible image"
-  bug: "339583191"
+  description: "Recalculate drawer offset upon the preview size change when the targets list remains unchanged"
+  bug: "347316548"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
@@ -89,3 +75,51 @@ flag {
     purpose: PURPOSE_BUGFIX
   }
 }
+
+flag {
+  name: "fix_shortcut_loader_job_leak"
+  namespace: "intentresolver"
+  description: "User a nested coroutine scope for shortcut loader instances"
+  bug: "358135601"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+flag {
+  name: "fix_shortcuts_flashing"
+  namespace: "intentresolver"
+  description: "Do not flash shortcuts on payload selection change"
+  bug: "343300158"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+flag {
+  name: "preview_image_loader"
+  namespace: "intentresolver"
+  description: "Use the unified preview image loader for all preview variations; support variable preview sizes."
+  bug: "348665058"
+}
+
+flag {
+  name: "shareousel_update_exclude_components_extra"
+  namespace: "intentresolver"
+  description: "Allow Shareousel selection change callback to update Intent#EXTRA_EXCLUDE_COMPONENTS"
+  bug: "352496527"
+}
+
+flag {
+  name: "unselect_final_item"
+  namespace: "intentresolver"
+  description: "Allow toggling of final Shareousel item"
+  bug: "349468879"
+}
+
+flag {
+  name: "shareousel_scroll_offscreen_selections"
+  namespace: "intentresolver"
+  description: "Whether to scroll items onscreen when they are partially offscreen and selected/unselected."
+  bug: "351883537"
+}
diff --git a/java/res/values-af/strings.xml b/java/res/values-af/strings.xml
index bfe3e7dc..55d84dfa 100644
--- a/java/res/values-af/strings.xml
+++ b/java/res/values-af/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Deel tans prent}other{Deel tans # prente}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Deel tans video}other{Deel tans # video’s}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Deel tans # lêer}other{Deel tans # lêers}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Kies items om te deel"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Deel tans prent met teks}other{Deel tans # prente met teks}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Deel tans prent met skakel}other{Deel tans # prente met skakel}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Deel tans video met teks}other{Deel tans # video’s met teks}}"</string>
diff --git a/java/res/values-am/strings.xml b/java/res/values-am/strings.xml
index 6daccad9..a7b5922b 100644
--- a/java/res/values-am/strings.xml
+++ b/java/res/values-am/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ምስልን በማጋራት ላይ}one{# ምስልን በማጋራት ላይ}other{# ምስሎችን በማጋራት ላይ}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ቪድዮ በማጋራት ላይ}one{# ቪድዮ በማጋራት ላይ}other{# ቪድዮዎችን በማጋራት ላይ}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ፋይልን በማጋራት ላይ}one{# ፋይልን በማጋራት ላይ}other{# ፋይሎችን በማጋራት ላይ}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"ለማጋራት ንጥሎችን ምረጥ"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{ምስልን ከጽሑፍ ጋር በማጋራት ላይ}one{# ምስልን ከጽሑፍ ጋር በማጋራት ላይ}other{# ምስሎችን ከጽሑፍ ጋር በማጋራት ላይ}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{ምስልን ከአገናኝ ጋር በማጋራት ላይ}one{# ምስልን ከአገናኝ ጋር በማጋራት ላይ}other{# ምስሎችን ከአገናኝ ጋር በማጋራት ላይ}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{ቪድዮ ከጽሑፍ ጋር በማጋራት ላይ}one{# ቪድዮ ከጽሑፍ ጋር በማጋራት ላይ}other{# ቪድዮዎችን ከጽሑፍ ጋር በማጋራት ላይ}}"</string>
diff --git a/java/res/values-ar/strings.xml b/java/res/values-ar/strings.xml
index fa9bd2c2..49769c57 100644
--- a/java/res/values-ar/strings.xml
+++ b/java/res/values-ar/strings.xml
@@ -45,8 +45,8 @@
     <string name="use_a_different_app" msgid="2062380818535918975">"استخدام تطبيق آخر"</string>
     <string name="chooseActivity" msgid="6659724877523973446">"اختيار إجراء"</string>
     <string name="noApplications" msgid="1139487441772284671">"ليست هناك تطبيقات يمكنها تنفيذ هذا الإجراء."</string>
-    <string name="forward_intent_to_owner" msgid="6454987608971162379">"أنت تستخدم هذا التطبيق خارج ملفك الشخصي للعمل"</string>
-    <string name="forward_intent_to_work" msgid="2906094223089139419">"أنت تستخدم هذا التطبيق في ملفك الشخصي للعمل"</string>
+    <string name="forward_intent_to_owner" msgid="6454987608971162379">"أنت تستخدم هذا التطبيق خارج ملف العمل الخاص بك"</string>
+    <string name="forward_intent_to_work" msgid="2906094223089139419">"أنت تستخدم هذا التطبيق في ملف العمل الخاص بك"</string>
     <string name="activity_resolver_use_always" msgid="8674194687637555245">"دائمًا"</string>
     <string name="activity_resolver_use_once" msgid="594173435998892989">"مرة واحدة فقط"</string>
     <string name="activity_resolver_work_profiles_support" msgid="8228711455685203580">"لا يتوافق تطبيق \"<xliff:g id="APP">%1$s</xliff:g>\" مع ملف العمل."</string>
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{جارٍ مشاركة صورة واحدة}zero{جارٍ مشاركة # صورة}two{جارٍ مشاركة صورتَين}few{جارٍ مشاركة # صور}many{جارٍ مشاركة # صورة}other{جارٍ مشاركة # صورة}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{جارٍ مشاركة فيديو واحد}zero{جارٍ مشاركة # فيديو}two{جارٍ مشاركة فيديوهَين}few{جارٍ مشاركة # فيديوهات}many{جارٍ مشاركة # فيديو}other{جارٍ مشاركة # فيديو}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{مشاركة ملف واحد}zero{مشاركة # ملف}two{مشاركة ملفَّين}few{مشاركة # ملفات}many{مشاركة # ملفًّا}other{مشاركة # ملف}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"اختيار العناصر المراد مشاركتها"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{مشاركة صورة واحدة ونص}zero{مشاركة # صورة ونص}two{مشاركة صورتَين ونص}few{مشاركة # صور ونص}many{مشاركة # صورة ونص}other{مشاركة # صورة ونص}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{مشاركة صورة واحدة ورابط}zero{مشاركة # صورة ورابط}two{مشاركة # صورتَين ورابط}few{مشاركة # صور ورابط}many{مشاركة # صورة ورابط}other{مشاركة # صورة ورابط}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{مشاركة فيديو واحد ونص}zero{مشاركة # فيديو ونص}two{مشاركة فيديوهَين ونص}few{مشاركة # فيديوهات ونص}many{مشاركة # فيديو ونص}other{مشاركة # فيديو ونص}}"</string>
@@ -75,7 +76,7 @@
     <string name="file_preview_a11y_description" msgid="7397224827802410602">"صورة مصغّرة لمعاينة ملف"</string>
     <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"ما مِن أشخاص مقترحين للمشاركة معهم"</string>
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"‏لم يتم منح هذا التطبيق إذن تسجيل، ولكن يمكنه تسجيل الصوت من خلال جهاز USB هذا."</string>
-    <string name="resolver_personal_tab" msgid="1381052735324320565">"مساحة شخصية"</string>
+    <string name="resolver_personal_tab" msgid="1381052735324320565">"المساحة الشخصية"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"مساحة العمل"</string>
     <string name="resolver_private_tab" msgid="3707548826254095157">"المساحة الخاصّة"</string>
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"عرض المحتوى الشخصي"</string>
@@ -94,7 +95,7 @@
     <string name="resolver_no_personal_apps_available" msgid="8479033344701050767">"ما مِن تطبيقات شخصية."</string>
     <string name="resolver_no_private_apps_available" msgid="4164473548027417456">"ما مِن تطبيقات خاصة"</string>
     <string name="miniresolver_open_in_personal" msgid="8397377137465016575">"هل تريد فتح <xliff:g id="APP">%s</xliff:g> في ملفك الشخصي؟"</string>
-    <string name="miniresolver_open_in_work" msgid="4271638122142624693">"هل تريد فتح <xliff:g id="APP">%s</xliff:g> في ملفك الشخصي للعمل؟"</string>
+    <string name="miniresolver_open_in_work" msgid="4271638122142624693">"هل تريد فتح <xliff:g id="APP">%s</xliff:g> في ملف العمل الخاص بك؟"</string>
     <string name="miniresolver_use_personal_browser" msgid="1428911732509069292">"استخدام المتصفّح الشخصي"</string>
     <string name="miniresolver_use_work_browser" msgid="7892699758493230342">"استخدام متصفّح العمل"</string>
     <string name="exclude_text" msgid="5508128757025928034">"استثناء النص"</string>
diff --git a/java/res/values-as/strings.xml b/java/res/values-as/strings.xml
index d2b3cb69..1983e4fe 100644
--- a/java/res/values-as/strings.xml
+++ b/java/res/values-as/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{প্ৰতিচ্ছবি শ্বেয়াৰ কৰি থকা হৈছে}one{# খন প্ৰতিচ্ছবি শ্বেয়াৰ কৰি থকা হৈছে}other{# খন প্ৰতিচ্ছবি শ্বেয়াৰ কৰি থকা হৈছে}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ভিডিঅ’ শ্বেয়াৰ কৰি থকা হৈছে}one{# টা ভিডিঅ’ শ্বেয়াৰ কৰি থকা হৈছে}other{# টা ভিডিঅ’ শ্বেয়াৰ কৰি থকা হৈছে}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# টা ফাইল শ্বেয়াৰ কৰি থকা হৈছে}one{# টা ফাইল শ্বেয়াৰ কৰি থকা হৈছে}other{# টা ফাইল শ্বেয়াৰ কৰি থকা হৈছে}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"শ্বেয়াৰ কৰাৰ বাবে বস্তু বাছনি কৰক"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{পাঠৰ সৈতে প্ৰতিচ্ছবি শ্বেয়াৰ কৰি থকা হৈছে}one{পাঠৰ সৈতে # টা প্ৰতিচ্ছবি শ্বেয়াৰ কৰি থকা হৈছে}other{পাঠৰ সৈতে # টা প্ৰতিচ্ছবি শ্বেয়াৰ কৰি থকা হৈছে}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{লিংকৰ সৈতে প্ৰতিচ্ছবি শ্বেয়াৰ কৰি থকা হৈছে}one{লিংকৰ সৈতে # টা প্ৰতিচ্ছবি শ্বেয়াৰ কৰি থকা হৈছে}other{লিংকৰ সৈতে # টা প্ৰতিচ্ছবি শ্বেয়াৰ কৰি থকা হৈছে}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{পাঠৰ সৈতে ভিডিঅ’ শ্বেয়াৰ কৰি থকা হৈছে}one{পাঠৰ সৈতে # টা ভিডিঅ’ শ্বেয়াৰ কৰি থকা হৈছে}other{পাঠৰ সৈতে # টা ভিডিঅ’ শ্বেয়াৰ কৰি থকা হৈছে}}"</string>
diff --git a/java/res/values-az/strings.xml b/java/res/values-az/strings.xml
index e8915892..c5674b86 100644
--- a/java/res/values-az/strings.xml
+++ b/java/res/values-az/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Şəkil paylaşılır}other{# şəkil paylaşılır}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Video paylaşılır}other{# video paylaşılır}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# fayl paylaşılır}other{# fayl paylaşılır}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Paylaşmaq üçün elementlər seçin"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Mətn olan şəkil paylaşılır}other{Mətn olan # şəkil paylaşılır}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Link olan şəkil paylaşılır}other{Link olan # şəkil paylaşılır}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Mətn olan video paylaşılır}other{Mətn olan # video paylaşılır}}"</string>
diff --git a/java/res/values-b+sr+Latn/strings.xml b/java/res/values-b+sr+Latn/strings.xml
index 228576f6..6d9dbd87 100644
--- a/java/res/values-b+sr+Latn/strings.xml
+++ b/java/res/values-b+sr+Latn/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Deljenje slike}one{Deljenje # slike}few{Deljenje # slike}other{Deljenje # slika}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Deli se video}one{Deli se # video}few{Dele se # video snimka}other{Deli se # videa}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Deli se # fajl}one{Deli se # fajl}few{Dele se # fajla}other{Deli se # fajlova}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Izaberite stavke za deljenje"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Deli se slika sa tekstom}one{Deli se # slika sa tekstom}few{Dele se # slike sa tekstom}other{Deli se # slika sa tekstom}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Deli se slika sa linkom}one{Deli se # slika sa linkom}few{Dele se # slike sa linkom}other{Deli se # slika sa linkom}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Deli se video sa tekstom}one{Deli se # video sa tekstom}few{Dele se # video snimka sa tekstom}other{Deli se # videa sa tekstom}}"</string>
diff --git a/java/res/values-be/strings.xml b/java/res/values-be/strings.xml
index 22079a0d..2724855b 100644
--- a/java/res/values-be/strings.xml
+++ b/java/res/values-be/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Абагульванне відарыса}one{Абагульванне # відарыса}few{Абагульванне # відарысаў}many{Абагульванне # відарысаў}other{Абагульванне # відарыса}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Абагульванне відэа}one{Абагульванне # відэа}few{Абагульванне # відэа}many{Абагульванне # відэа}other{Абагульванне # відэа}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Абагульваецца # файл}one{Абагульваецца # файл}few{Абагульваюцца # файлы}many{Абагульваюцца # файлаў}other{Абагульваюцца # файла}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Выберыце элементы для абагульвання"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Абагульванне відарыса з тэкстам}one{Абагульванне # відарыса з тэкстам}few{Абагульванне # відарысаў з тэкстам}many{Абагульванне # відарысаў з тэкстам}other{Абагульванне # відарыса з тэкстам}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Абагульванне відарыса са спасылкай}one{Абагульванне # відарыса са спасылкай}few{Абагульванне # відарысаў са спасылкай}many{Абагульванне # відарысаў са спасылкай}other{Абагульванне # відарыса са спасылкай}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Абагульванне відэа з тэкстам}one{Абагульванне # відэа з тэкстам}few{Абагульванне # відэа з тэкстам}many{Абагульванне # відэа з тэкстам}other{Абагульванне # відэа з тэкстам}}"</string>
diff --git a/java/res/values-bg/strings.xml b/java/res/values-bg/strings.xml
index 0b5fcad5..450712b1 100644
--- a/java/res/values-bg/strings.xml
+++ b/java/res/values-bg/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Изображението се споделя}other{# изображения се споделят}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Видеоклипът се споделя}other{# видеоклипа се споделят}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# файл се споделя}other{# файла се споделят}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Изберете елементи за споделяне"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Споделяне на изображението чрез SMS съобщение}other{Споделяне на # изображения чрез SMS съобщение}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Споделяне на изображението чрез връзка}other{Споделяне на # изображения чрез връзка}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Споделяне на видеоклипа чрез SMS съобщение}other{Споделяне на # видеоклипа чрез SMS съобщение}}"</string>
diff --git a/java/res/values-bn/strings.xml b/java/res/values-bn/strings.xml
index b0d433c1..2d33eb29 100644
--- a/java/res/values-bn/strings.xml
+++ b/java/res/values-bn/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ছবি শেয়ার করা হচ্ছে}one{#টি ছবি শেয়ার করা হচ্ছে}other{#টি ছবি শেয়ার করা হচ্ছে}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ভিডিও শেয়ার করা হচ্ছে}one{#টি ভিডিও শেয়ার করা হচ্ছে}other{#টি ভিডিও শেয়ার করা হচ্ছে}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{#টি ফাইল শেয়ার করা হচ্ছে}one{#টি ফাইল শেয়ার করা হচ্ছে}other{#টি ফাইল শেয়ার করা হচ্ছে}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"শেয়ার করার জন্য আইটেম বেছে নিন"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{টেক্সট সহ ছবি শেয়ার করা হচ্ছে}one{টেক্সট সহ #টি ছবি শেয়ার করা হচ্ছে}other{টেক্সট সহ #টি ছবি শেয়ার করা হচ্ছে}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{লিঙ্ক সহ ছবি শেয়ার করা হচ্ছে}one{লিঙ্ক সহ #টি ছবি শেয়ার করা হচ্ছে}other{লিঙ্ক সহ #টি ছবি শেয়ার করা হচ্ছে}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{টেক্সট সহ ভিডিও শেয়ার করা হচ্ছে}one{টেক্সট সহ #টি ভিডিও শেয়ার করা হচ্ছে}other{টেক্সট সহ #টি ভিডিও শেয়ার করা হচ্ছে}}"</string>
diff --git a/java/res/values-bs/strings.xml b/java/res/values-bs/strings.xml
index 97d3e7cf..10335fab 100644
--- a/java/res/values-bs/strings.xml
+++ b/java/res/values-bs/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Podijelite sliku}one{Podijelite # sliku}few{Podijelite # slike}other{Podijelite # slika}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Dijeljenje videozapisa}one{Dijeljenje # videozapisa}few{Dijeljenje # videozapisa}other{Dijeljenje # videozapisa}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Dijeljenje # fajla}one{Dijeljenje # fajla}few{Dijeljenje # fajla}other{Dijeljenje # fajlova}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Odaberite stavke za dijeljenje"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Dijeljenje slike putem poruke}one{Dijeljenje # slike putem poruke}few{Dijeljenje # slike putem poruke}other{Dijeljenje # slika putem poruke}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Dijeljenje slike putem linka}one{Dijeljenje # slike putem linka}few{Dijeljenje # slike putem linka}other{Dijeljenje # slika putem linka}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Dijeljenje videozapisa putem poruke}one{Dijeljenje # videozapisa putem poruke}few{Dijeljenje # videozapisa putem poruke}other{Dijeljenje # videozapisa putem poruke}}"</string>
diff --git a/java/res/values-ca/strings.xml b/java/res/values-ca/strings.xml
index 4cc905ba..11029365 100644
--- a/java/res/values-ca/strings.xml
+++ b/java/res/values-ca/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Comparteix una imatge}many{Comparteix # d\'imatges}other{Comparteix # imatges}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{S\'està compartint un vídeo}many{S\'estan compartint # de vídeos}other{S\'estan compartint # vídeos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{S\'està compartint # fitxer}many{S\'estan compartint # de fitxers}other{S\'estan compartint # fitxers}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Selecciona els elements que vols compartir"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{S\'està compartint la imatge amb text}many{S\'estan compartint # d\'imatges amb text}other{S\'estan compartint # imatges amb text}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{S\'està compartint la imatge amb un enllaç}many{S\'estan compartint # d\'imatges amb un enllaç}other{S\'estan compartint # imatges amb un enllaç}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{S\'està compartint el vídeo amb un enllaç}many{S\'estan compartint # de vídeos amb un enllaç}other{S\'estan compartint # vídeos amb un enllaç}}"</string>
diff --git a/java/res/values-cs/strings.xml b/java/res/values-cs/strings.xml
index cca5091d..0ce7e140 100644
--- a/java/res/values-cs/strings.xml
+++ b/java/res/values-cs/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Sdílení obrázku}few{Sdílení # obrázků}many{Sdílení # obrázku}other{Sdílení # obrázků}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Sdílení videa}few{Sdílení # videí}many{Sdílení # videa}other{Sdílení # videí}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Sdílení # souboru}few{Sdílení # souborů}many{Sdílení # souboru}other{Sdílení # souborů}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Vyberte položky, které chcete sdílet"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Sdílení obrázku s textem}few{Sdílení # obrázků s textem}many{Sdílení # obrázku s textem}other{Sdílení # obrázků s textem}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Sdílení obrázku s odkazem}few{Sdílení # obrázků s odkazem}many{Sdílení # obrázku s odkazem}other{Sdílení # obrázků s odkazem}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Sdílení videa s textem}few{Sdílení # videí s textem}many{Sdílení # videa s textem}other{Sdílení # videí s textem}}"</string>
diff --git a/java/res/values-da/strings.xml b/java/res/values-da/strings.xml
index f0d27442..3a3e2062 100644
--- a/java/res/values-da/strings.xml
+++ b/java/res/values-da/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Deler billede}one{Deler # billede}other{Deler # billeder}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Deler video}one{Deler # video}other{Deler # videoer}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Deler # fil}one{Deler # fil}other{Deler # filer}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Vælg elementer til deling"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Deler billede med tekst}one{Deler # billede med tekst}other{Deler # billeder med tekst}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Deler billede med et link}one{Deler # billede med et link}other{Deler # billeder med et link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Deler video med tekst}one{Deler # video med tekst}other{Deler # videoer med tekst}}"</string>
diff --git a/java/res/values-de/strings.xml b/java/res/values-de/strings.xml
index c6d26eb2..3a561101 100644
--- a/java/res/values-de/strings.xml
+++ b/java/res/values-de/strings.xml
@@ -46,7 +46,7 @@
     <string name="chooseActivity" msgid="6659724877523973446">"Aktion auswählen"</string>
     <string name="noApplications" msgid="1139487441772284671">"Diese Aktion kann von keiner App ausgeführt werden."</string>
     <string name="forward_intent_to_owner" msgid="6454987608971162379">"Du verwendest diese App außerhalb deines Arbeitsprofils"</string>
-    <string name="forward_intent_to_work" msgid="2906094223089139419">"Du verwendest diese App in deinem Arbeitsprofil."</string>
+    <string name="forward_intent_to_work" msgid="2906094223089139419">"Du verwendest diese App in deinem Arbeitsprofil"</string>
     <string name="activity_resolver_use_always" msgid="8674194687637555245">"Immer"</string>
     <string name="activity_resolver_use_once" msgid="594173435998892989">"Nur diesmal"</string>
     <string name="activity_resolver_work_profiles_support" msgid="8228711455685203580">"<xliff:g id="APP">%1$s</xliff:g> unterstützt das Arbeitsprofil nicht"</string>
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Bild wird geteilt}other{# Bilder werden geteilt}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Video wird geteilt}other{# Videos werden geteilt}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# Datei wird freigegeben}other{# Dateien werden freigegeben}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Elemente zum Teilen auswählen"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Bild wird mit Text geteilt}other{# Bilder werden mit Text geteilt}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Bild wird per Link geteilt}other{# Bilder werden per Link geteilt}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Video wird per SMS geteilt}other{# Videos werden per SMS geteilt}}"</string>
@@ -81,7 +82,7 @@
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"Private Ansicht"</string>
     <string name="resolver_work_tab_accessibility" msgid="7581878836587799920">"Geschäftliche Ansicht"</string>
     <string name="resolver_private_tab_accessibility" msgid="2513122834337197252">"Private Ansicht"</string>
-    <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"Von deinem IT-Administrator blockiert"</string>
+    <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"Vom IT‑Administrator blockiert"</string>
     <string name="resolver_cant_share_with_work_apps_explanation" msgid="2984105853145456723">"Diese Art von Inhalt kann nicht über geschäftliche Apps geteilt werden"</string>
     <string name="resolver_cant_access_work_apps_explanation" msgid="1463093773348988122">"Diese Art von Inhalt kann nicht mit geschäftlichen Apps geöffnet werden"</string>
     <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"Diese Art von Inhalt kann nicht über private Apps geteilt werden"</string>
diff --git a/java/res/values-el/strings.xml b/java/res/values-el/strings.xml
index ed09f127..8903eec1 100644
--- a/java/res/values-el/strings.xml
+++ b/java/res/values-el/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Κοινοποίηση εικόνας}other{Κοινοποίηση # εικόνων}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Κοινοποίηση βίντεο}other{Κοινοποίηση # βίντεο}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Κοινή χρήση # αρχείου}other{Κοινή χρήση # αρχείων}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Επιλογή στοιχείων για κοινή χρήση"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Κοινοποίηση εικόνας με κείμενο}other{Κοινοποίηση # εικόνων με κείμενο}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Κοινοποίηση εικόνας με σύνδεσμο}other{Κοινοποίηση # εικόνων με σύνδεσμο}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Κοινοποίηση βίντεο με κείμενο}other{Κοινοποίηση # βίντεο με κείμενο}}"</string>
diff --git a/java/res/values-en-rAU/strings.xml b/java/res/values-en-rAU/strings.xml
index 88e86718..53e64659 100644
--- a/java/res/values-en-rAU/strings.xml
+++ b/java/res/values-en-rAU/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Sharing image}other{Sharing # images}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Sharing video}other{Sharing # videos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Sharing # file}other{Sharing # files}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Select items to share"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Sharing image with text}other{Sharing # images with text}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Sharing image with link}other{Sharing # images with link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Sharing video with text}other{Sharing # videos with text}}"</string>
diff --git a/java/res/values-en-rCA/strings.xml b/java/res/values-en-rCA/strings.xml
index 978da764..1c44b945 100644
--- a/java/res/values-en-rCA/strings.xml
+++ b/java/res/values-en-rCA/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Sharing image}other{Sharing # images}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Sharing video}other{Sharing # videos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Sharing # file}other{Sharing # files}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Select items to share"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Sharing image with text}other{Sharing # images with text}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Sharing image with link}other{Sharing # images with link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Sharing video with text}other{Sharing # videos with text}}"</string>
diff --git a/java/res/values-en-rGB/strings.xml b/java/res/values-en-rGB/strings.xml
index 88e86718..53e64659 100644
--- a/java/res/values-en-rGB/strings.xml
+++ b/java/res/values-en-rGB/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Sharing image}other{Sharing # images}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Sharing video}other{Sharing # videos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Sharing # file}other{Sharing # files}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Select items to share"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Sharing image with text}other{Sharing # images with text}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Sharing image with link}other{Sharing # images with link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Sharing video with text}other{Sharing # videos with text}}"</string>
diff --git a/java/res/values-en-rIN/strings.xml b/java/res/values-en-rIN/strings.xml
index 88e86718..53e64659 100644
--- a/java/res/values-en-rIN/strings.xml
+++ b/java/res/values-en-rIN/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Sharing image}other{Sharing # images}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Sharing video}other{Sharing # videos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Sharing # file}other{Sharing # files}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Select items to share"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Sharing image with text}other{Sharing # images with text}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Sharing image with link}other{Sharing # images with link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Sharing video with text}other{Sharing # videos with text}}"</string>
diff --git a/java/res/values-en-rXC/strings.xml b/java/res/values-en-rXC/strings.xml
index 7447d83b..4fc18b62 100644
--- a/java/res/values-en-rXC/strings.xml
+++ b/java/res/values-en-rXC/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‎‏‎‎‎‏‏‏‎‎‎‎‎‏‏‏‎‎‎‎‎‎‎‏‏‏‏‎‏‏‏‏‏‎‎‏‎‏‏‏‎‏‎‎‎‏‎‏‏‎‏‎‎‎‏‎‏‎‏‏‎‎Sharing image‎‏‎‎‏‎}other{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‎‏‎‎‎‏‏‏‎‎‎‎‎‏‏‏‎‎‎‎‎‎‎‏‏‏‏‎‏‏‏‏‏‎‎‏‎‏‏‏‎‏‎‎‎‏‎‏‏‎‏‎‎‎‏‎‏‎‏‏‎‎Sharing # images‎‏‎‎‏‎}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‎‎‎‏‏‎‏‏‏‎‏‎‏‏‏‎‎‎‎‎‎‏‏‎‎‏‏‏‏‏‎‏‏‎‏‎‏‎‏‏‏‏‏‏‎‏‎‏‏‎‎‎‏‏‏‏‏‎‏‎‎Sharing video‎‏‎‎‏‎}other{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‎‎‎‏‏‎‏‏‏‎‏‎‏‏‏‎‎‎‎‎‎‏‏‎‎‏‏‏‏‏‎‏‏‎‏‎‏‎‏‏‏‏‏‏‎‏‎‏‏‎‎‎‏‏‏‏‏‎‏‎‎Sharing # videos‎‏‎‎‏‎}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‎‎‎‏‏‎‏‏‎‏‎‎‎‎‎‎‎‎‎‏‏‏‎‎‎‏‎‏‏‎‎‎‎‎‎‏‏‎‎‎‎‏‏‏‏‎‏‎‎‏‏‎‎‎‎‏‎‏‏‏‎Sharing # file‎‏‎‎‏‎}other{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‎‎‎‏‏‎‏‏‎‏‎‎‎‎‎‎‎‎‎‏‏‏‎‎‎‏‎‏‏‎‎‎‎‎‎‏‏‎‎‎‎‏‏‏‏‎‏‎‎‏‏‎‎‎‎‏‎‏‏‏‎Sharing # files‎‏‎‎‏‎}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‎‏‏‏‎‎‎‏‏‏‏‎‏‎‏‎‏‎‏‏‎‏‏‎‏‏‎‎‎‎‏‎‏‎‏‏‎‏‎‎‎‏‎‎‎‎‎‎‎‏‏‎‎‏‏‏‏‎‎‏‏‎Select items to share‎‏‎‎‏‎"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‏‏‏‏‎‏‎‏‎‏‏‏‏‎‎‎‏‎‎‏‎‏‎‏‏‎‏‎‏‎‎‏‎‏‎‎‎‏‎‎‎‏‏‎‏‎‏‏‏‎‎‎‎‏‎‎Sharing image with text‎‏‎‎‏‎}other{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‏‏‏‏‎‏‎‏‎‏‏‏‏‎‎‎‏‎‎‏‎‏‎‏‏‎‏‎‏‎‎‏‎‏‎‎‎‏‎‎‎‏‏‎‏‎‏‏‏‎‎‎‎‏‎‎Sharing # images with text‎‏‎‎‏‎}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‎‏‏‏‎‎‏‏‏‏‏‎‎‏‏‎‎‎‏‏‎‏‏‏‎‏‎‏‏‎‏‎‎‎‎‎‎‏‎‎‏‎‎‏‎‏‏‏‏‏‏‎‏‏‎‎‏‎‏‎Sharing image with link‎‏‎‎‏‎}other{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‎‏‏‏‎‎‏‏‏‏‏‎‎‏‏‎‎‎‏‏‎‏‏‏‎‏‎‏‏‎‏‎‎‎‎‎‎‏‎‎‏‎‎‏‎‏‏‏‏‏‏‎‏‏‎‎‏‎‏‎Sharing # images with link‎‏‎‎‏‎}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‏‎‎‏‏‏‎‏‏‏‏‎‎‏‏‏‎‏‎‎‏‎‎‎‏‎‏‎‎‏‎‏‎‏‎‏‏‎‎‏‏‎‎‏‏‏‏‎‏‏‏‎‎‎‎‎‎‎‏‎‎Sharing video with text‎‏‎‎‏‎}other{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‏‎‎‏‏‏‎‏‏‏‏‎‎‏‏‏‎‏‎‎‏‎‎‎‏‎‏‎‎‏‎‏‎‏‎‏‏‎‎‏‏‎‎‏‏‏‏‎‏‏‏‎‎‎‎‎‎‎‏‎‎Sharing # videos with text‎‏‎‎‏‎}}"</string>
diff --git a/java/res/values-es-rUS/strings.xml b/java/res/values-es-rUS/strings.xml
index a76fba3a..f3b7fe85 100644
--- a/java/res/values-es-rUS/strings.xml
+++ b/java/res/values-es-rUS/strings.xml
@@ -59,7 +59,8 @@
     <string name="sharing_link" msgid="2307694372813942916">"Compartir vínculo"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Compartir la imagen}many{Compartir # de imágenes}other{Compartir # imágenes}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Compartiendo video}many{Compartiendo # de videos}other{Compartiendo # videos}}"</string>
-    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Se compartirá # archivo}many{Se compartirán # de archivos}other{Se compartirán # archivos}}"</string>
+    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Compartiendo # archivo}many{Compartiendo # de archivos}other{Compartiendo # archivos}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Selecciona los elementos para compartir"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Compartir imagen con texto}many{Compartir # de imágenes con texto}other{Compartir # imágenes con texto}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Compartir imagen con vínculo}many{Compartir # de imágenes con vínculo}other{Compartir # imágenes con vínculo}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Compartir video con texto}many{Compartir # de videos con texto}other{Compartir # videos con texto}}"</string>
diff --git a/java/res/values-es/strings.xml b/java/res/values-es/strings.xml
index 5e63be7e..460de896 100644
--- a/java/res/values-es/strings.xml
+++ b/java/res/values-es/strings.xml
@@ -57,9 +57,10 @@
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{y # archivo más}many{y # archivos más}other{y # archivos más}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Compartiendo texto"</string>
     <string name="sharing_link" msgid="2307694372813942916">"Compartiendo enlace"</string>
-    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Compartir imagen}many{Compartir # imágenes}other{Compartir # imágenes}}"</string>
+    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Compartiendo imagen}many{Compartiendo # imágenes}other{Compartiendo # imágenes}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Compartiendo vídeo}many{Compartiendo # vídeos}other{Compartiendo # vídeos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Compartiendo # archivo}many{Compartiendo # archivos}other{Compartiendo # archivos}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Selecciona los elementos que quieres compartir"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Compartiendo imagen con texto}many{Compartiendo # imágenes con texto}other{Compartiendo # imágenes con texto}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Compartiendo imagen con enlace}many{Compartiendo # imágenes con enlace}other{Compartiendo # imágenes con enlace}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Compartiendo vídeo con texto}many{Compartiendo # vídeos con texto}other{Compartiendo # vídeos con texto}}"</string>
diff --git a/java/res/values-et/strings.xml b/java/res/values-et/strings.xml
index ab849b2c..85fca08f 100644
--- a/java/res/values-et/strings.xml
+++ b/java/res/values-et/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Pildi jagamine}other{# pildi jagamine}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Video jagamine}other{# video jagamine}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# faili jagamine}other{# faili jagamine}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Jagatavate üksuste valimine"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Teksti sisaldava pildi jagamine}other{# teksti sisaldava pildi jagamine}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Linki sisaldava pildi jagamine}other{# linki sisaldava pildi jagamine}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Teksti sisaldava video jagamine}other{# teksti sisaldava video jagamine}}"</string>
diff --git a/java/res/values-eu/strings.xml b/java/res/values-eu/strings.xml
index a3269d72..5020f62d 100644
--- a/java/res/values-eu/strings.xml
+++ b/java/res/values-eu/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Irudia partekatuko da}other{# irudi partekatuko dira}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Bideoa partekatzen}other{# bideo partekatzen}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# fitxategi partekatuko da}other{# fitxategi partekatuko dira}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Hautatu partekatu beharreko elementuak"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Irudi testudun bat partekatuko da}other{# irudi testudun partekatuko dira}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Irudi estekadun bat partekatuko da}other{# irudi estekadun partekatuko dira}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Bideo testudun bat partekatuko da}other{# bideo testudun partekatuko dira}}"</string>
diff --git a/java/res/values-fa/strings.xml b/java/res/values-fa/strings.xml
index 0119fe69..7b3dc6ea 100644
--- a/java/res/values-fa/strings.xml
+++ b/java/res/values-fa/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{هم‌رسانی تصویر}one{هم‌رسانی ‍# تصویر}other{هم‌رسانی ‍# تصویر}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{درحال هم‌رسانی ویدیو}one{درحال هم‌رسانی # ویدیو}other{درحال هم‌رسانی # ویدیو}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{هم‌رسانی # فایل}one{هم‌رسانی # فایل}other{هم‌رسانی # فایل}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"انتخاب کردن موارد برای هم‌رسانی"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{درحال هم‌رسانی تصویر با نوشتار}one{درحال هم‌رسانی # تصویر با نوشتار}other{درحال هم‌رسانی # تصویر با نوشتار}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{درحال هم‌رسانی تصویر با پیوند}one{درحال هم‌رسانی # تصویر با پیوند}other{درحال هم‌رسانی # تصویر با پیوند}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{درحال هم‌رسانی ویدیو با نوشتار}one{درحال هم‌رسانی # ویدیو با نوشتار}other{درحال هم‌رسانی # ویدیو با نوشتار}}"</string>
@@ -70,9 +71,9 @@
     <string name="sharing_images_only" msgid="7762589767189955438">"{count,plural, =1{فقط تصویر}one{فقط تصویر}other{فقط تصویر}}"</string>
     <string name="sharing_videos_only" msgid="5549729252364968606">"{count,plural, =1{فقط ویدیو}one{فقط ویدیو}other{فقط ویدیو}}"</string>
     <string name="sharing_files_only" msgid="6603666533766964768">"{count,plural, =1{فقط فایل}one{فقط فایل}other{فقط فایل}}"</string>
-    <string name="image_preview_a11y_description" msgid="297102643932491797">"تصویر کوچک پیش‌نمای تصویر"</string>
-    <string name="video_preview_a11y_description" msgid="683440858811095990">"تصویر کوچک پیش‌نمای ویدیو"</string>
-    <string name="file_preview_a11y_description" msgid="7397224827802410602">"تصویر کوچک پیش‌نمای فایل"</string>
+    <string name="image_preview_a11y_description" msgid="297102643932491797">"ریزعکس پیش‌نمای تصویر"</string>
+    <string name="video_preview_a11y_description" msgid="683440858811095990">"ریزعکس پیش‌نمای ویدیو"</string>
+    <string name="file_preview_a11y_description" msgid="7397224827802410602">"ریزعکس پیش‌نمای فایل"</string>
     <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"هیچ فردی که با او هم‌رسانی کنید توصیه نشده است"</string>
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"‏مجوز ضبط به این برنامه داده نشده است اما می‌تواند صدا را ازطریق این دستگاه USB ضبط کند."</string>
     <string name="resolver_personal_tab" msgid="1381052735324320565">"شخصی"</string>
diff --git a/java/res/values-fi/strings.xml b/java/res/values-fi/strings.xml
index ee740f13..65244293 100644
--- a/java/res/values-fi/strings.xml
+++ b/java/res/values-fi/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Jaetaan kuvaa}other{Jaetaan # kuvaa}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Jaetaan videota}other{Jaetaan # videota}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Jaetaan # tiedosto}other{Jaetaan # tiedostoa}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Valitse jaettavat kohteet"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Kuvaa ja tekstiä jaetaan}other{# kuvaa ja tekstiä jaetaan}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Kuvaa ja linkkiä jaetaan}other{# kuvaa ja linkkiä jaetaan}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Videota ja tekstiä jaetaan}other{# videota ja tekstiä jaetaan}}"</string>
diff --git a/java/res/values-fr-rCA/strings.xml b/java/res/values-fr-rCA/strings.xml
index 7d2716c2..b2ae5f5c 100644
--- a/java/res/values-fr-rCA/strings.xml
+++ b/java/res/values-fr-rCA/strings.xml
@@ -53,13 +53,14 @@
     <string name="pin_specific_target" msgid="5057063421361441406">"Épingler <xliff:g id="LABEL">%1$s</xliff:g>"</string>
     <string name="unpin_specific_target" msgid="3115158908159857777">"Annuler l\'épinglage de <xliff:g id="LABEL">%1$s</xliff:g>"</string>
     <string name="screenshot_edit" msgid="3857183660047569146">"Modifier"</string>
-    <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # fichier}one{+ # fichier}many{+ # de fichiers}other{+ # fichiers}}"</string>
+    <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # fichier}one{+ # fichier}many{+ # de fichiers}other{+ # fichiers}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{et # fichier supplémentaire}one{et # fichier supplémentaire}many{et # de fichiers supplémentaires}other{et # fichiers supplémentaires}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Partage de texte"</string>
     <string name="sharing_link" msgid="2307694372813942916">"Partage d\'un lien"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Partage d\'une image}one{Partage de # image}many{Partage de # d\'images}other{Partage de # images}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Partage de la vidéo…}one{Partage de # vidéo…}many{Partage de # de vidéos…}other{Partage de # vidéos…}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Partage de # fichier en cours…}one{Partage de # fichier en cours…}many{Partage de # de fichiers en cours…}other{Partage de # fichiers en cours…}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Sélectionner les éléments à partager"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Partage d\'une image avec du texte}one{Partage de # image avec du texte}many{Partage de # d\'images avec du texte}other{Partage de # images avec du texte}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Partage d\'une image avec un lien}one{Partage de # image avec un lien}many{Partage de # d\'images avec un lien}other{Partage de # images avec un lien}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Partage d\'une vidéo avec du texte}one{Partage de # vidéo avec du texte}many{Partage de # de vidéos avec du texte}other{Partage de # vidéos avec du texte}}"</string>
diff --git a/java/res/values-fr/strings.xml b/java/res/values-fr/strings.xml
index 6f55cbf9..2b96c92f 100644
--- a/java/res/values-fr/strings.xml
+++ b/java/res/values-fr/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Partager l\'image}one{Partager # image}many{Partager # d\'images}other{Partager # images}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Partage de la vidéo…}one{Partage de # vidéo…}many{Partage de # de vidéos…}other{Partage de # vidéos…}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Partage de # fichier}one{Partage de # fichier}many{Partage de # fichiers}other{Partage de # fichiers}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Sélectionner les éléments à partager"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Partager 1 image avec du texte}one{Partager # image avec du texte}many{Partager # images avec du texte}other{Partager # images avec du texte}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Partager 1 image avec un lien}one{Partager # image avec un lien}many{Partager # images avec un lien}other{Partager # images avec un lien}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Partager 1 vidéo avec du texte}one{Partager # vidéo avec du texte}many{Partager # vidéos avec du texte}other{Partager # vidéos avec du texte}}"</string>
diff --git a/java/res/values-gl/strings.xml b/java/res/values-gl/strings.xml
index fe59eaa6..a8caf6f3 100644
--- a/java/res/values-gl/strings.xml
+++ b/java/res/values-gl/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Compartindo imaxe}other{Compartindo # imaxes}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Compartindo vídeo}other{Compartindo # vídeos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Compartindo # ficheiro}other{Compartindo # ficheiros}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Seleccionar elementos para compartir"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Compartindo imaxe con texto}other{Compartindo # imaxes con texto}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Compartindo imaxe con ligazón}other{Compartindo # imaxes con ligazón}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Compartindo vídeo con texto}other{Compartindo # vídeos con texto}}"</string>
diff --git a/java/res/values-gu/strings.xml b/java/res/values-gu/strings.xml
index 70d84bc8..a70a1b0f 100644
--- a/java/res/values-gu/strings.xml
+++ b/java/res/values-gu/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{છબી શેર કરી રહ્યાં છીએ}one{# છબી શેર કરી રહ્યાં છીએ}other{# છબી શેર કરી રહ્યાં છીએ}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{વીડિયો શેર કરીએ છીએ}one{# વીડિયો શેર કરીએ છીએ}other{# વીડિયો શેર કરીએ છીએ}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ફાઇલ શેર કરી રહ્યાં છીએ}one{# ફાઇલ શેર કરી રહ્યાં છીએ}other{# ફાઇલ શેર કરી રહ્યાં છીએ}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"શેર કરવા માટે આઇટમ પસંદ કરો"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{ટેક્સ્ટ સાથે છબી શેર કરી રહ્યાં છીએ}one{ટેક્સ્ટ સાથે # છબી શેર કરી રહ્યાં છીએ}other{ટેક્સ્ટ સાથે # છબી શેર કરી રહ્યાં છીએ}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{લિંક સાથે છબી શેર કરી રહ્યાં છીએ}one{લિંક સાથે # છબી શેર કરી રહ્યાં છીએ}other{લિંક સાથે # છબી શેર કરી રહ્યાં છીએ}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{ટેક્સ્ટ સાથે વીડિયો શેર કરી રહ્યાં છીએ}one{ટેક્સ્ટ સાથે # વીડિયો શેર કરી રહ્યાં છીએ}other{ટેક્સ્ટ સાથે # વીડિયો શેર કરી રહ્યાં છીએ}}"</string>
diff --git a/java/res/values-hi/strings.xml b/java/res/values-hi/strings.xml
index fcf484b9..3f6db1be 100644
--- a/java/res/values-hi/strings.xml
+++ b/java/res/values-hi/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{इमेज शेयर की जा रही है}one{# इमेज शेयर की जा रही है}other{# इमेज शेयर की जा रही हैं}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{वीडियो शेयर किया जा रहा है}one{# वीडियो शेयर किया जा रहा है}other{# वीडियो शेयर किए जा रहे हैं}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# फ़ाइल शेयर की जा रही है}one{# फ़ाइल शेयर की जा रही है}other{# फ़ाइलें शेयर की जा रही हैं}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"शेयर करने के लिए आइटम चुनें"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{टेक्स्ट के साथ इमेज शेयर की जा रही है}one{टेक्स्ट के साथ # इमेज शेयर की जा रही है}other{टेक्स्ट के साथ # इमेज शेयर की जा रही हैं}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{लिंक के साथ इमेज शेयर की जा रही है}one{लिंक के साथ # इमेज शेयर की जा रही है}other{लिंक के साथ # इमेज शेयर की जा रही हैं}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{टेक्स्ट के साथ वीडियो शेयर किया जा रहा है}one{टेक्स्ट के साथ # वीडियो शेयर किया जा रहा है}other{टेक्स्ट के साथ # वीडियो शेयर किए जा रहे हैं}}"</string>
@@ -75,7 +76,7 @@
     <string name="file_preview_a11y_description" msgid="7397224827802410602">"फ़ाइल के थंबनेल की झलक"</string>
     <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"शेयर करने के लिए, किसी व्यक्ति का सुझाव नहीं दिया गया है"</string>
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"इस ऐप्लिकेशन को रिकॉर्ड करने की अनुमति नहीं दी गई है. हालांकि, ऐप्लिकेशन इस यूएसबी डिवाइस से ऐसा कर सकता है."</string>
-    <string name="resolver_personal_tab" msgid="1381052735324320565">"निजी प्रोफ़ाइल"</string>
+    <string name="resolver_personal_tab" msgid="1381052735324320565">"निजी"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"वर्क प्रोफ़ाइल"</string>
     <string name="resolver_private_tab" msgid="3707548826254095157">"प्राइवेट"</string>
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"निजी व्यू"</string>
diff --git a/java/res/values-hr/strings.xml b/java/res/values-hr/strings.xml
index ca62036d..85858303 100644
--- a/java/res/values-hr/strings.xml
+++ b/java/res/values-hr/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Podijelite sliku}one{Podijelite # sliku}few{Podijelite # slike}other{Podijelite # slika}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Dijeli se videozapis}one{Dijeli se # videozapis}few{Dijele se # videozapisa}other{Dijeli se # videozapisa}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Dijeli se # datoteka}one{Dijeli se # datoteka}few{Dijele se # datoteke}other{Dijeli se # datoteka}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Odaberite stavke za dijeljenje"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Dijeli se slika s tekstom}one{Dijeli se # slika s tekstom}few{Dijele se # slike s tekstom}other{Dijeli se # slika s tekstom}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Dijeli se slika s vezom}one{Dijeli se # slika s vezom}few{Dijele se # slike s vezom}other{Dijeli se # slika s vezom}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Dijeli se videozapis s tekstom}one{Dijeli se # videozapis s tekstom}few{Dijele se # videozapisa s tekstom}other{Dijeli se # videozapisa s tekstom}}"</string>
diff --git a/java/res/values-hu/strings.xml b/java/res/values-hu/strings.xml
index a0bce668..792b07e2 100644
--- a/java/res/values-hu/strings.xml
+++ b/java/res/values-hu/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Kép megosztása}other{# kép megosztása}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Videó megosztása}other{# videó megosztása}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# fájl megosztása}other{# fájl megosztása}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Válassza ki a megosztani kívánt elemeket"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Kép megosztása szöveggel}other{# kép megosztása szöveggel}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Kép megosztása linkkel}other{# kép megosztása linkkel}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Videó megosztása szöveggel}other{# videó megosztása szöveggel}}"</string>
diff --git a/java/res/values-hy/strings.xml b/java/res/values-hy/strings.xml
index 2ee335da..f9232a5a 100644
--- a/java/res/values-hy/strings.xml
+++ b/java/res/values-hy/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Պատկերի ուղարկում}one{# պատկերի ուղարկում}other{# պատկերի ուղարկում}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Տեսանյութի ուղարկում}one{# տեսանյութի ուղարկում}other{# տեսանյութի ուղարկում}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Ուղարկվում է # ֆայլ}one{Ուղարկվում է # ֆայլ}other{Ուղարկվում է # ֆայլ}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Ընտրեք տարրեր՝ կիսվելու համար"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Պատկերի ուղարկում տեքստային հաղորդագրության միջոցով}one{# պատկերի ուղարկում տեքստային հաղորդագրության միջոցով}other{# պատկերի ուղարկում տեքստային հաղորդագրության միջոցով}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Պատկերի ուղարկում հղման միջոցով}one{# պատկերի ուղարկում հղման միջոցով}other{# պատկերի ուղարկում հղման միջոցով}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Տեսանյութի ուղարկում տեքստային հաղորդագրության միջոցով}one{# տեսանյութի ուղարկում տեքստային հաղորդագրության միջոցով}other{# տեսանյութի ուղարկում տեքստային հաղորդագրության միջոցով}}"</string>
diff --git a/java/res/values-in/strings.xml b/java/res/values-in/strings.xml
index 1efaf920..df05fdd0 100644
--- a/java/res/values-in/strings.xml
+++ b/java/res/values-in/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Berbagi gambar}other{Berbagi # gambar}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Membagikan video}other{Membagikan # video}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Membagikan # file}other{Membagikan # file}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Pilih item untuk dibagikan"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Membagikan gambar dengan teks}other{Membagikan # gambar dengan teks}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Membagikan gambar dengan link}other{Membagikan # gambar dengan link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Membagikan video dengan teks}other{Membagikan # video dengan teks}}"</string>
diff --git a/java/res/values-is/strings.xml b/java/res/values-is/strings.xml
index 9bc4f5cb..680ed17a 100644
--- a/java/res/values-is/strings.xml
+++ b/java/res/values-is/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Deilir mynd}one{Deilir # mynd}other{Deilir # myndum}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Deilir myndskeiði}one{Deilir # myndskeiði}other{Deilir # myndskeiðum}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Deilir # skrá}one{Deilir # skrá}other{Deilir # skrám}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Veldu atriði til að deila"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Deilir mynd með texta}one{Deilir # mynd með texta}other{Deilir # myndum með texta}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Deilir mynd með tengli}one{Deilir # mynd með tengli}other{Deilir # myndum með tengli}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Deilir myndskeiði með texta}one{Deilir # myndskeiði með texta}other{Deilir # myndskeiðum með texta}}"</string>
diff --git a/java/res/values-it/strings.xml b/java/res/values-it/strings.xml
index 75fe0b77..3762f58b 100644
--- a/java/res/values-it/strings.xml
+++ b/java/res/values-it/strings.xml
@@ -53,19 +53,20 @@
     <string name="pin_specific_target" msgid="5057063421361441406">"Fissa <xliff:g id="LABEL">%1$s</xliff:g>"</string>
     <string name="unpin_specific_target" msgid="3115158908159857777">"Sblocca <xliff:g id="LABEL">%1$s</xliff:g>"</string>
     <string name="screenshot_edit" msgid="3857183660047569146">"Modifica"</string>
-    <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # file}many{+ # file}other{+ # file}}"</string>
-    <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ # altro file}many{+ altri # file}other{+ altri # file}}"</string>
+    <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # file}many{+ # di file}other{+ # file}}"</string>
+    <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ # altro file}many{+ altri # di file}other{+ altri # file}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Condivisione del testo"</string>
     <string name="sharing_link" msgid="2307694372813942916">"Condivisione del link"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Condivisione dell\'immagine}many{Condivisione di # immagini}other{Condivisione di # immagini}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Condivisione del video…}many{Condivisione di # video…}other{Condivisione di # video…}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Condivisione di # file in corso…}many{Condivisione di # file in corso…}other{Condivisione di # file in corso…}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Seleziona gli elementi da condividere"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Condivisione immagine con testo in corso…}many{Condivisione # immagini con testo in corso…}other{Condivisione # immagini con testo in corso…}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Condivisione immagine con link}many{Condivisione # immagini con link}other{Condivisione # immagini con link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Condivisione video con messaggio in corso…}many{Condivisione # video con messaggio in corso…}other{Condivisione # video con messaggio in corso…}}"</string>
     <string name="sharing_videos_with_link" msgid="6383290441403042321">"{count,plural, =1{Condivisione video con link in corso…}many{Condivisione # video con link in corso…}other{Condivisione # video con link in corso…}}"</string>
     <string name="sharing_files_with_text" msgid="7331187260405018080">"{count,plural, =1{Condivisione file con messaggio in corso…}many{Condivisione # file con messaggio in corso…}other{Condivisione # file con messaggio in corso…}}"</string>
-    <string name="sharing_files_with_link" msgid="6052797122358827239">"{count,plural, =1{Condivisione file con link in corso…}many{Condivisione # file con link in corso…}other{Condivisione # file con link in corso…}}"</string>
+    <string name="sharing_files_with_link" msgid="6052797122358827239">"{count,plural, =1{Condivisione file con link in corso…}many{Condivisione # di file con link in corso…}other{Condivisione # file con link in corso…}}"</string>
     <string name="sharing_album" msgid="191743129899503345">"Condivisione album"</string>
     <string name="sharing_images_only" msgid="7762589767189955438">"{count,plural, =1{Soltanto l\'immagine}many{Soltanto le immagini}other{Soltanto le immagini}}"</string>
     <string name="sharing_videos_only" msgid="5549729252364968606">"{count,plural, =1{Soltanto il video}many{Soltanto i video}other{Soltanto i video}}"</string>
diff --git a/java/res/values-iw/strings.xml b/java/res/values-iw/strings.xml
index 7c13ebd3..bed01ff0 100644
--- a/java/res/values-iw/strings.xml
+++ b/java/res/values-iw/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{שיתוף של תמונה}one{שיתוף של # תמונות}two{שיתוף של # תמונות}other{שיתוף של # תמונות}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{מתבצע שיתוף של סרטון}one{מתבצע שיתוף של # סרטונים}two{מתבצע שיתוף של # סרטונים}other{מתבצע שיתוף של # סרטונים}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{מתבצע שיתוף של קובץ אחד}one{מתבצע שיתוף של # קבצים}two{מתבצע שיתוף של # קבצים}other{מתבצע שיתוף של # קבצים}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"בחירת פריטים לשיתוף"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{שיתוף תמונה עם טקסט}one{שיתוף # תמונות עם טקסט}two{שיתוף # תמונות עם טקסט}other{שיתוף # תמונות עם טקסט}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{שיתוף תמונה עם קישור}one{שיתוף # תמונות עם קישור}two{שיתוף # תמונות עם קישור}other{שיתוף # תמונות עם קישור}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{שיתוף סרטון עם טקסט}one{שיתוף # סרטונים עם טקסט}two{שיתוף # סרטונים עם טקסט}other{שיתוף # סרטונים עם טקסט}}"</string>
@@ -77,7 +78,7 @@
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"‏לאפליקציה זו לא ניתנה הרשאת הקלטה, אבל אפשר להקליט אודיו באמצעות התקן ה-USB הזה."</string>
     <string name="resolver_personal_tab" msgid="1381052735324320565">"אישי"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"עבודה"</string>
-    <string name="resolver_private_tab" msgid="3707548826254095157">"פרטי"</string>
+    <string name="resolver_private_tab" msgid="3707548826254095157">"מרחב פרטי"</string>
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"תצוגה אישית"</string>
     <string name="resolver_work_tab_accessibility" msgid="7581878836587799920">"תצוגת עבודה"</string>
     <string name="resolver_private_tab_accessibility" msgid="2513122834337197252">"תצוגה פרטית"</string>
diff --git a/java/res/values-ja/strings.xml b/java/res/values-ja/strings.xml
index 0c97d64a..1d2a2f06 100644
--- a/java/res/values-ja/strings.xml
+++ b/java/res/values-ja/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{1 枚の画像を共有します}other{# 枚の画像を共有します}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{動画を共有中}other{# 個の動画を共有中}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# 個のファイルを共有中}other{# 個のファイルを共有中}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"共有するアイテムの選択"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{テキスト付き画像を共有しています}other{テキスト付き画像を # 件共有しています}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{リンク付き画像を共有しています}other{リンク付き画像を # 件共有しています}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{テキスト付き動画を共有中}other{テキスト付き動画を # 件共有中}}"</string>
diff --git a/java/res/values-ka/strings.xml b/java/res/values-ka/strings.xml
index 46d1f1e7..4675734b 100644
--- a/java/res/values-ka/strings.xml
+++ b/java/res/values-ka/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ზიარდება სურათი}other{ზიარდება # სურათი}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ზიარდება ვიდეო}other{ზიარდება # ვიდეო}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{ზიარდება # ფაილი}other{ზიარდება # ფაილი}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"გასაზიარებელი ერთეულების არჩევა"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{სურათი ზიარდება ტექსტით}other{# სურათი ზიარდება ტექსტით}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{სურათი ზიარდება ბმულით}other{# სურათი ზიარდება ბმულით}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{ვიდეო ზიარდება ტექსტით}other{# ვიდეო ზიარდება ტექსტით}}"</string>
diff --git a/java/res/values-kk/strings.xml b/java/res/values-kk/strings.xml
index ee3135fa..362db640 100644
--- a/java/res/values-kk/strings.xml
+++ b/java/res/values-kk/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Сурет бөлісіп жатырсыз}other{# сурет бөлісіп жатырсыз}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Бейне бөлісіліп жатыр}other{# бейне бөлісіліп жатыр}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# файлды бөлісіп жатыр}other{# файлды бөлісіп жатыр}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Бөлісетін элементтерді таңдау"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Мәтіні бар сурет жіберу}other{Мәтіні бар # сурет жіберу}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Сілтемесі бар сурет жіберу}other{Сілтемесі бар # сурет жіберу}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Мәтіні бар бейне жіберу}other{Мәтіні бар # бейне жіберу}}"</string>
diff --git a/java/res/values-km/strings.xml b/java/res/values-km/strings.xml
index eb2ef8a0..cee11e26 100644
--- a/java/res/values-km/strings.xml
+++ b/java/res/values-km/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{កំពុងចែក​រំលែករូបភាព}other{កំពុងចែក​រំលែករូបភាព #}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{កំពុងចែករំលែកវីដេអូ}other{កំពុងចែករំលែកវីដេអូ #}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{កំពុង​ចែករំលែកឯកសារ #}other{កំពុង​ចែករំលែកឯកសារ #}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"ជ្រើសរើសធាតុដែលត្រូវចែករំលែក"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{ចែករំលែករូបភាពជាមួយអក្សរ}other{ចែករំលែករូបភាព # ជាមួយអក្សរ}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{ចែករំលែករូបភាពជាមួយតំណ}other{ចែករំលែករូបភាព # ជាមួយតំណ}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{ចែករំលែកវីដេអូជាមួយអក្សរ}other{ចែករំលែក # វីដេអូជាមួយអក្សរ}}"</string>
diff --git a/java/res/values-kn/strings.xml b/java/res/values-kn/strings.xml
index 17f3b295..35bf148c 100644
--- a/java/res/values-kn/strings.xml
+++ b/java/res/values-kn/strings.xml
@@ -45,8 +45,8 @@
     <string name="use_a_different_app" msgid="2062380818535918975">"ಬೇರೊಂದು ಆ್ಯಪ್ ಬಳಸಿ"</string>
     <string name="chooseActivity" msgid="6659724877523973446">"ಕ್ರಿಯೆಯನ್ನು ಆಯ್ಕೆಮಾಡಿ"</string>
     <string name="noApplications" msgid="1139487441772284671">"ಯಾವುದೇ ಅಪ್ಲಿಕೇಶನ್‌ಗಳು ಈ ಕ್ರಿಯೆಗಾಗಿ ಬದ್ಧತೆ ತೋರಿಸುವುದಿಲ್ಲ."</string>
-    <string name="forward_intent_to_owner" msgid="6454987608971162379">"ನಿಮ್ಮ ಕೆಲಸದ ಪ್ರೊಫೈಲ್‌ನ ಹೊರಗೆ ನೀವು ಈ ಅಪ್ಲಿಕೇಶನ್‌ ಅನ್ನು ಬಳಸುತ್ತಿರುವಿರಿ"</string>
-    <string name="forward_intent_to_work" msgid="2906094223089139419">"ನಿಮ್ಮ ಕೆಲಸದ ಪ್ರೊಫೈಲ್‌ನಲ್ಲಿ ನೀವು ಈ ಅಪ್ಲಿಕೇಶನ್‌ ಅನ್ನು ಬಳಸುತ್ತಿರುವಿರಿ"</string>
+    <string name="forward_intent_to_owner" msgid="6454987608971162379">"ನಿಮ್ಮ ಕೆಲಸದ ಪ್ರೊಫೈಲ್‌ನ ಹೊರಗೆ ನೀವು ಈ ಆ್ಯಪ್ ಅನ್ನು ಬಳಸುತ್ತಿರುವಿರಿ"</string>
+    <string name="forward_intent_to_work" msgid="2906094223089139419">"ನಿಮ್ಮ ಕೆಲಸದ ಪ್ರೊಫೈಲ್‌ನಲ್ಲಿ ನೀವು ಈ ಆ್ಯಪ್ ಅನ್ನು ಬಳಸುತ್ತಿರುವಿರಿ"</string>
     <string name="activity_resolver_use_always" msgid="8674194687637555245">"ಯಾವಾಗಲೂ"</string>
     <string name="activity_resolver_use_once" msgid="594173435998892989">"ಒಮ್ಮೆ ಮಾತ್ರ"</string>
     <string name="activity_resolver_work_profiles_support" msgid="8228711455685203580">"<xliff:g id="APP">%1$s</xliff:g> ಉದ್ಯೋಗದ ಪ್ರೊಫೈಲ್ ಅನ್ನು ಬೆಂಬಲಿಸುವುದಿಲ್ಲ"</string>
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ಚಿತ್ರವನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}one{# ಚಿತ್ರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}other{# ಚಿತ್ರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ವೀಡಿಯೊವನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}one{# ವೀಡಿಯೊಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}other{# ವೀಡಿಯೊಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ಫೈಲ್ ಅನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}one{# ಫೈಲ್‌ಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}other{# ಫೈಲ್‌ಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"ಹಂಚಿಕೊಳ್ಳಲು ಐಟಂಗಳನ್ನು ಆಯ್ಕೆಮಾಡಿ"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{ಪಠ್ಯದೊಂದಿಗೆ ಚಿತ್ರವನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}one{ಪಠ್ಯದೊಂದಿಗೆ # ಚಿತ್ರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}other{ಪಠ್ಯದೊಂದಿಗೆ # ಚಿತ್ರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{ಲಿಂಕ್‌ನೊಂದಿಗೆ ಚಿತ್ರವನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}one{ಲಿಂಕ್‌ನೊಂದಿಗೆ # ಚಿತ್ರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}other{ಲಿಂಕ್‌ನೊಂದಿಗೆ # ಚಿತ್ರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{ಪಠ್ಯದೊಂದಿಗೆ ವೀಡಿಯೊವನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}one{ಪಠ್ಯದೊಂದಿಗೆ # ವೀಡಿಯೊಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}other{ಪಠ್ಯದೊಂದಿಗೆ # ವೀಡಿಯೊಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}}"</string>
diff --git a/java/res/values-ko/strings.xml b/java/res/values-ko/strings.xml
index b75b9bdd..094f09b0 100644
--- a/java/res/values-ko/strings.xml
+++ b/java/res/values-ko/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{이미지 공유}other{이미지 #개 공유}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{동영상 1개 공유 중}other{동영상 #개 공유 중}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{파일 #개 공유 중}other{파일 #개 공유 중}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"공유할 항목 선택"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{텍스트로 이미지 공유 중}other{텍스트로 이미지 #개 공유 중}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{링크로 이미지 공유 중}other{링크로 이미지 #개 공유 중}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{텍스트로 동영상 공유 중}other{텍스트로 동영상 #개 공유 중}}"</string>
diff --git a/java/res/values-ky/strings.xml b/java/res/values-ky/strings.xml
index 6f84e1bf..610adaf2 100644
--- a/java/res/values-ky/strings.xml
+++ b/java/res/values-ky/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Сүрөт бөлүшүү}other{# сүрөт бөлүшүлүүдө}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Видео бөлүшүлүүдө}other{# видео бөлүшүлүүдө}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# файл бөлүшүлүүдө}other{# файл бөлүшүлүүдө}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Бөлүшө турган нерселерди тандаңыз"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Сүрөттү текст менен жөнөтүү}other{# cүрөттү текст менен жөнөтүү}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Сүрөттү шилтеме менен жөнөтүү}other{# сүрөттү шилтеме менен жөнөтүү}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Видеону текст менен жөнөтүү}other{# видеону текст менен жөнөтүү}}"</string>
diff --git a/java/res/values-lo/strings.xml b/java/res/values-lo/strings.xml
index 2a65f486..2cdea91f 100644
--- a/java/res/values-lo/strings.xml
+++ b/java/res/values-lo/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ກຳລັງແບ່ງປັນຮູບ}other{ກຳລັງແບ່ງປັນ # ຮູບ}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ກຳລັງແບ່ງປັນວິດີໂອ}other{ກຳລັງແບ່ງປັນ # ວິດີໂອ}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{ກຳລັງຈະແບ່ງປັນ # ໄຟລ໌}other{ກຳລັງຈະແບ່ງປັນ # ໄຟລ໌}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"ເລືອກລາຍການທີ່ຈະແບ່ງປັນ"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{ກຳລັງແບ່ງປັນຮູບພ້ອມຂໍ້ຄວາມ}other{ກຳລັງແບ່ງປັນ # ຮູບພ້ອມຂໍ້ຄວາມ}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{ກຳລັງແບ່ງປັນຮູບພ້ອມລິ້ງ}other{ກຳລັງແບ່ງປັນ # ຮູບພ້ອມລິ້ງ}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{ກຳລັງແບ່ງປັນວິດີໂອພ້ອມຂໍ້ຄວາມ}other{ກຳລັງແບ່ງປັນ # ວິດີໂອພ້ອມຂໍ້ຄວາມ}}"</string>
diff --git a/java/res/values-lt/strings.xml b/java/res/values-lt/strings.xml
index bb495311..7b0c6695 100644
--- a/java/res/values-lt/strings.xml
+++ b/java/res/values-lt/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Bendrinamas vaizdas}one{Bendrinamas # vaizdas}few{Bendrinami # vaizdai}many{Bendrinama # vaizdo}other{Bendrinama # vaizdų}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Bendrinamas vaizdo įrašas}one{Bendrinamas # vaizdo įrašas}few{Bendrinami # vaizdo įrašai}many{Bendrinama # vaizdo įrašo}other{Bendrinama # vaizdo įrašų}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Bendrinamas # failas}one{Bendrinamas # failas}few{Bendrinami # failai}many{Bendrinama # failo}other{Bendrinama # failų}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Norimų bendrinti elementų pasirinkimas"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Bendrinamas vaizdas su tekstu}one{Bendrinamas # vaizdas su tekstu}few{Bendrinami # vaizdai su tekstu}many{Bendrinama # vaizdo su tekstu}other{Bendrinama # vaizdų su tekstu}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Bendrinamas vaizdas su nuoroda}one{Bendrinamas # vaizdas su nuoroda}few{Bendrinami # vaizdai su nuoroda}many{Bendrinama # vaizdo su nuoroda}other{Bendrinama # vaizdų su nuoroda}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Bendrinamas vaizdo įrašas su tekstu}one{Bendrinamas # vaizdo įrašas su tekstu}few{Bendrinami # vaizdo įrašai su tekstu}many{Bendrinama # vaizdo įrašo su tekstu}other{Bendrinama # vaizdo įrašų su tekstu}}"</string>
diff --git a/java/res/values-lv/strings.xml b/java/res/values-lv/strings.xml
index 7dd6cac9..1c14c2b8 100644
--- a/java/res/values-lv/strings.xml
+++ b/java/res/values-lv/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Tiek kopīgots attēls}zero{Tiek kopīgoti # attēli}one{Tiek kopīgots # attēls}other{Tiek kopīgoti # attēli}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Tiek kopīgots video}zero{Tiek kopīgoti # video}one{Tiek kopīgots # video}other{Tiek kopīgoti # video}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Notiek # faila kopīgošana}zero{Notiek # failu kopīgošana}one{Notiek # faila kopīgošana}other{Notiek # failu kopīgošana}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Atlasiet kopīgojamos vienumus"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Tiek kopīgots attēls ar tekstu}zero{Tiek kopīgoti # attēli ar tekstu}one{Tiek kopīgots # attēls ar tekstu}other{Tiek kopīgoti # attēli ar tekstu}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Tiek kopīgots attēls ar saiti}zero{Tiek kopīgoti # attēli ar saitēm}one{Tiek kopīgots # attēls ar saitēm}other{Tiek kopīgoti # attēli ar saitēm}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Tiek kopīgots videoklips ar tekstu}zero{Tiek kopīgoti # videoklipi ar tekstu}one{Tiek kopīgots # videoklips ar tekstu}other{Tiek kopīgoti # videoklipi ar tekstu}}"</string>
diff --git a/java/res/values-mk/strings.xml b/java/res/values-mk/strings.xml
index 45fb82e3..19ff3c67 100644
--- a/java/res/values-mk/strings.xml
+++ b/java/res/values-mk/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Споделување слика}one{Споделување # слика}other{Споделување # слики}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Се споделува видео}one{Се споделува # видео}other{Се споделуваат # видеа}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Се споделува # датотека}one{Се споделуваат # датотека}other{Се споделуваат # датотеки}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Изберете ставки за споделување"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Се споделува слика со SMS}one{Се споделуваат # слика со SMS}other{Се споделуваат # слики со SMS}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Се споделува слика со линк}one{Се споделуваат # слика со линк}other{Се споделуваат # слики со линк}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Се споделува видео со SMS}one{Се споделуваат # видео со SMS}other{Се споделуваат # видеа со SMS}}"</string>
diff --git a/java/res/values-ml/strings.xml b/java/res/values-ml/strings.xml
index ce466e8f..bcd07dd7 100644
--- a/java/res/values-ml/strings.xml
+++ b/java/res/values-ml/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ചിത്രം പങ്കിടുന്നു}other{# ചിത്രങ്ങൾ പങ്കിടുന്നു}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{വീഡിയോ പങ്കിടുന്നു}other{# വീഡിയോകൾ പങ്കിടുന്നു}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ഫയൽ പങ്കിടുന്നു}other{# ഫയലുകൾ പങ്കിടുന്നു}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"പങ്കിടാൻ ഇനങ്ങൾ തിരഞ്ഞെടുക്കുക"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{ടെക്സ്റ്റിനൊപ്പം ചിത്രം പങ്കിടുന്നു}other{ടെക്സ്റ്റിനൊപ്പം # ചിത്രം പങ്കിടുന്നു}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{ലിങ്കിനൊപ്പം ചിത്രം പങ്കിടുന്നു}other{ലിങ്കിനൊപ്പം # ചിത്രങ്ങൾ പങ്കിടുന്നു}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{ടെക്സ്റ്റിനൊപ്പം വീഡിയോ പങ്കിടുന്നു}other{ടെക്സ്റ്റിനൊപ്പം # വീഡിയോകൾ പങ്കിടുന്നു}}"</string>
diff --git a/java/res/values-mn/strings.xml b/java/res/values-mn/strings.xml
index 30686c51..81d97d99 100644
--- a/java/res/values-mn/strings.xml
+++ b/java/res/values-mn/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Зураг хуваалцаж байна}other{# зураг хуваалцаж байна}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Видео хуваалцаж байна}other{# видео хуваалцаж байна}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# файл хуваалцаж байна}other{# файл хуваалцаж байна}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Хуваалцах зүйлс сонгох"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Тексттэй зураг хуваалцаж байна}other{Тексттэй # зураг хуваалцаж байна}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Холбоостой зураг хуваалцаж байна}other{Холбоостой # зураг хуваалцаж байна}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Тексттэй видео хуваалцаж байна}other{Тексттэй # видео хуваалцаж байна}}"</string>
diff --git a/java/res/values-mr/strings.xml b/java/res/values-mr/strings.xml
index 9ad4a4c8..4a061601 100644
--- a/java/res/values-mr/strings.xml
+++ b/java/res/values-mr/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{इमेज शेअर करत आहे}other{# इमेज शेअर करत आहे}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{व्हिडिओ शेअर करत आहे}other{# व्हिडिओ शेअर करत आहे}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# फाइल शेअर करत आहे}other{# फाइल शेअर करत आहे}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"शेअर करण्यासाठी आयटम निवडा"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{मजकुरासह इमेज शेअर करत आहे}other{मजकुरासह # इमेज शेअर करत आहे}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{लिंकसह इमेज शेअर करत आहे}other{लिंकसह # इमेज शेअर करत आहे}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{मजकुरासह व्हिडिओ शेअर करत आहे}other{मजकुरासह # व्हिडिओ शेअर करत आहे}}"</string>
diff --git a/java/res/values-ms/strings.xml b/java/res/values-ms/strings.xml
index 92e7a26f..a01376c6 100644
--- a/java/res/values-ms/strings.xml
+++ b/java/res/values-ms/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Berkongsi imej}other{Berkongsi # imej}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Berkongsi video}other{Berkongsi # video}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Berkongsi # fail}other{Berkongsi # fail}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Pilih item untuk dikongsi"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Berkongsi imej dengan teks}other{Berkongsi # imej dengan teks}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Berkongsi imej dengan pautan}other{Berkongsi # imej dengan pautan}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Berkongsi video dengan teks}other{Berkongsi # video dengan teks}}"</string>
diff --git a/java/res/values-my/strings.xml b/java/res/values-my/strings.xml
index 1f78c7f1..9eeda078 100644
--- a/java/res/values-my/strings.xml
+++ b/java/res/values-my/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ပုံ မျှဝေနေသည်}other{ပုံ # ပုံ မျှဝေနေသည်}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ဗီဒီယို မျှဝေနေသည်}other{ဗီဒီယို # ခု မျှဝေနေသည်}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ဖိုင် မျှဝေနေသည်}other{# ဖိုင် မျှဝေနေသည်}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"မျှဝေမည့်အရာများ ရွေးခြင်း"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{စာသားပါသောပုံကို မျှဝေနေသည်}other{စာသားပါသောပုံ # ပုံကို မျှဝေနေသည်}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{လင့်ခ်ပါသောပုံကို မျှဝေနေသည်}other{လင့်ခ်ပါသောပုံ # ပုံကို မျှဝေနေသည်}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{စာသားပါသောဗီဒီယိုကို မျှဝေနေသည်}other{စာသားပါသောဗီဒီယို # ခုကို မျှဝေနေသည်}}"</string>
diff --git a/java/res/values-nb/strings.xml b/java/res/values-nb/strings.xml
index f9b91f7a..7a67bc34 100644
--- a/java/res/values-nb/strings.xml
+++ b/java/res/values-nb/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Deler bildet}other{Deler # bilder}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Deler videoen}other{Deler # videoer}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Deler # fil}other{Deler # filer}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Velg elementene du vil dele"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Deler bildet med tekst}other{Deler # bilder med tekst}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Deler bildet med link}other{Deler # bilder med link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Deler videoen med tekst}other{Deler # videoer med tekst}}"</string>
diff --git a/java/res/values-ne/strings.xml b/java/res/values-ne/strings.xml
index 61c7fe17..76365455 100644
--- a/java/res/values-ne/strings.xml
+++ b/java/res/values-ne/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{फोटो सेयर गरिँदै छ}other{# वटा फोटो सेयर गरिँदै छ}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{भिडियो सेयर गरिँदै छ}other{# वटा भिडियो सेयर गरिँदै छ}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# वटा फाइल सेयर गरिँदै छ}other{# वटा फाइल सेयर गरिँदै छ}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"आफूले सेयर गर्न चाहेका सामग्री चयन गर्नुहोस्"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{टेक्स्ट भएको फोटो सेयर गरिँदै छ}other{टेक्स्ट भएका # वटा फोटो सेयर गरिँदै छन्}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{लिंक भएको फोटो सेयर गरिँदै छ}other{लिंक भएका # वटा फोटो सेयर गरिँदै छन्}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{टेक्स्ट भएको भिडियो सेयर गरिँदै छ}other{टेक्स्ट भएका # वटा भिडियो सेयर गरिँदै छन्}}"</string>
diff --git a/java/res/values-nl/strings.xml b/java/res/values-nl/strings.xml
index a259a205..e452e98e 100644
--- a/java/res/values-nl/strings.xml
+++ b/java/res/values-nl/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Afbeelding delen}other{# afbeeldingen delen}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Video delen}other{# video\'s delen}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# bestand delen}other{# bestanden delen}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Items selecteren om te delen"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Afbeelding met tekst wordt gedeeld}other{# afbeeldingen met tekst worden gedeeld}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Afbeelding delen via link}other{# afbeeldingen delen via link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Video delen via tekstbericht}other{# video\'s delen via tekstbericht}}"</string>
diff --git a/java/res/values-or/strings.xml b/java/res/values-or/strings.xml
index 7586ae91..0e2ece56 100644
--- a/java/res/values-or/strings.xml
+++ b/java/res/values-or/strings.xml
@@ -32,7 +32,7 @@
     <string name="whichEditApplicationLabel" msgid="5992662938338600364">"ଏଡିଟ କରନ୍ତୁ"</string>
     <string name="whichSendApplication" msgid="59510564281035884">"ସେୟାର କରନ୍ତୁ"</string>
     <string name="whichSendApplicationNamed" msgid="495577664218765855">"<xliff:g id="APP">%1$s</xliff:g> ସହ ସେୟାର କରନ୍ତୁ"</string>
-    <string name="whichSendApplicationLabel" msgid="2391198069286568035">"ସେୟାର୍‌ କରନ୍ତୁ"</string>
+    <string name="whichSendApplicationLabel" msgid="2391198069286568035">"ସେୟାର କରନ୍ତୁ"</string>
     <string name="whichSendToApplication" msgid="2724450540348806267">"ଏହା ଜରିଆରେ ପଠାନ୍ତୁ"</string>
     <string name="whichSendToApplicationNamed" msgid="1996548940365954543">"<xliff:g id="APP">%1$s</xliff:g> ବ୍ୟବହାର କରି ପଠାନ୍ତୁ"</string>
     <string name="whichSendToApplicationLabel" msgid="6909037198280591110">"ପଠାନ୍ତୁ"</string>
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ଇମେଜ ସେୟାର କରାଯାଉଛି}other{#ଟିି ଇମେଜ ସେୟାର କରାଯାଉଛି}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ଭିଡିଓ ସେୟାର କରାଯାଉଛି}other{#ଟି ଭିଡିଓ ସେୟାର କରାଯାଉଛି}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{#ଟି ଫାଇଲ ସେୟାର କରାଯାଉଛି}other{#ଟି ଫାଇଲ ସେୟାର କରାଯାଉଛି}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"ସେୟାର କରିବା ପାଇଁ ଆଇଟମଗୁଡ଼ିକ ଚୟନ କରନ୍ତୁ"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{ଟେକ୍ସଟ ସହ ଇମେଜ ସେୟାର କରାଯାଉଛି}other{ଟେକ୍ସଟ ସହ #ଟି ଇମେଜ ସେୟାର କରାଯାଉଛି}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{ଲିଙ୍କ ସହ ଇମେଜ ସେୟାର କରାଯାଉଛି}other{ଲିଙ୍କ ସହ #ଟି ଇମେଜ ସେୟାର କରାଯାଉଛି}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{ଟେକ୍ସଟ ସହ ଭିଡିଓ ସେୟାର କରାଯାଉଛି}other{ଟେକ୍ସଟ ସହ #ଟି ଭିଡିଓ ସେୟାର କରାଯାଉଛି}}"</string>
diff --git a/java/res/values-pa/strings.xml b/java/res/values-pa/strings.xml
index 04565373..607f7d26 100644
--- a/java/res/values-pa/strings.xml
+++ b/java/res/values-pa/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ਚਿੱਤਰ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}one{# ਚਿੱਤਰ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}other{# ਚਿੱਤਰ ਸਾਂਝੇ ਕੀਤੇ ਜਾ ਰਹੇ ਹਨ}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ਵੀਡੀਓ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}one{# ਵੀਡੀਓ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}other{# ਵੀਡੀਓ ਸਾਂਝੇ ਕੀਤੇ ਜਾ ਰਹੇ ਹਨ}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ਫ਼ਾਈਲ ਸਾਂਝੀ ਕੀਤੀ ਜਾ ਰਹੀ ਹੈ}one{# ਫ਼ਾਈਲ ਸਾਂਝੀ ਕੀਤੀ ਜਾ ਰਹੀ ਹੈ}other{# ਫ਼ਾਈਲਾਂ ਸਾਂਝੀਆਂ ਕੀਤੀਆਂ ਜਾ ਰਹੀਆਂ ਹਨ}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"ਸਾਂਝਾ ਕਰਨ ਲਈ ਆਈਟਮਾਂ ਚੁਣੋ"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{ਲਿਖਤ ਸੁਨੇਹੇ ਨਾਲ ਚਿੱਤਰ ਨੂੰ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}one{ਲਿਖਤ ਸੁਨੇਹੇ ਨਾਲ # ਚਿੱਤਰ ਨੂੰ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}other{ਲਿਖਤ ਸੁਨੇਹੇ ਨਾਲ # ਚਿੱਤਰਾਂ ਨੂੰ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{ਲਿੰਕ ਨਾਲ ਚਿੱਤਰ ਨੂੰ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}one{ਲਿੰਕ ਨਾਲ # ਚਿੱਤਰ ਨੂੰ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}other{ਲਿੰਕ ਨਾਲ # ਚਿੱਤਰਾਂ ਨੂੰ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{ਲਿਖਤ ਸੁਨੇਹੇ ਨਾਲ ਵੀਡੀਓ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}one{ਲਿਖਤ ਸੁਨੇਹੇ ਨਾਲ # ਵੀਡੀਓ ਸਾਂਝਾ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ}other{ਲਿਖਤ ਸੁਨੇਹੇ ਨਾਲ # ਵੀਡੀਓ ਸਾਂਝੇ ਕੀਤੇ ਜਾ ਰਹੇ ਹਨ}}"</string>
diff --git a/java/res/values-pl/strings.xml b/java/res/values-pl/strings.xml
index e67510e3..10dda621 100644
--- a/java/res/values-pl/strings.xml
+++ b/java/res/values-pl/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Udostępniam obraz}few{Udostępniam # obrazy}many{Udostępniam # obrazów}other{Udostępniam # obrazu}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Udostępnianie filmu}few{Udostępnianie # filmów}many{Udostępnianie # filmów}other{Udostępnianie # filmu}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Udostępnianie # pliku}few{Udostępnianie # plików}many{Udostępnianie # plików}other{Udostępnianie # pliku}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Wybierz elementy do udostępnienia"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Udostępnianie obrazu przez SMS}few{Udostępnianie # obrazów przez SMS}many{Udostępnianie # obrazów przez SMS}other{Udostępnianie # obrazu przez SMS}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Udostępnianie obrazu przez link}few{Udostępnianie # obrazów przez link}many{Udostępnianie # obrazów przez link}other{Udostępnianie # obrazu przez link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Udostępnianie filmu przez SMS}few{Udostępnianie # filmów przez SMS}many{Udostępnianie # filmów przez SMS}other{Udostępnianie # filmu przez SMS}}"</string>
diff --git a/java/res/values-pt-rBR/strings.xml b/java/res/values-pt-rBR/strings.xml
index b5778cf6..c8ce55a8 100644
--- a/java/res/values-pt-rBR/strings.xml
+++ b/java/res/values-pt-rBR/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Compartilhar imagem}one{Compartilhar # imagem}many{Compartilhar # de imagens}other{Compartilhar # imagens}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Compartilhando vídeo}one{Compartilhando # vídeo}many{Compartilhando # de vídeos}other{Compartilhando # vídeos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Compartilhando # arquivo}one{Compartilhando # arquivo}many{Compartilhando # de arquivos}other{Compartilhando # arquivos}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Selecione os itens para compartilhar"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Compartilhando imagem com texto}one{Compartilhando # imagem com texto}many{Compartilhando # de imagens com texto}other{Compartilhando # imagens com texto}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Compartilhando imagem com link}one{Compartilhando # imagem com link}many{Compartilhando # de imagens com link}other{Compartilhando # imagens com link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Compartilhando vídeo com texto}one{Compartilhando # vídeo com texto}many{Compartilhando # de vídeos com texto}other{Compartilhando # vídeos com texto}}"</string>
diff --git a/java/res/values-pt-rPT/strings.xml b/java/res/values-pt-rPT/strings.xml
index 0abb79be..ffcf9a1e 100644
--- a/java/res/values-pt-rPT/strings.xml
+++ b/java/res/values-pt-rPT/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Partilhar imagem}many{Partilhar # imagens}other{Partilhar # imagens}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{A partilhar vídeo}many{A partilhar # vídeos}other{A partilhar # vídeos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{A partilhar # ficheiro}many{A partilhar # ficheiros}other{A partilhar # ficheiros}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Selecione itens para partilhar"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{A partilhar imagem com texto}many{A partilhar # imagens com texto}other{A partilhar # imagens com texto}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{A partilhar imagem com link}many{A partilhar # imagens com link}other{A partilhar # imagens com link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{A partilhar vídeo com texto}many{A partilhar # vídeos com texto}other{A partilhar # vídeos com texto}}"</string>
diff --git a/java/res/values-pt/strings.xml b/java/res/values-pt/strings.xml
index b5778cf6..c8ce55a8 100644
--- a/java/res/values-pt/strings.xml
+++ b/java/res/values-pt/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Compartilhar imagem}one{Compartilhar # imagem}many{Compartilhar # de imagens}other{Compartilhar # imagens}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Compartilhando vídeo}one{Compartilhando # vídeo}many{Compartilhando # de vídeos}other{Compartilhando # vídeos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Compartilhando # arquivo}one{Compartilhando # arquivo}many{Compartilhando # de arquivos}other{Compartilhando # arquivos}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Selecione os itens para compartilhar"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Compartilhando imagem com texto}one{Compartilhando # imagem com texto}many{Compartilhando # de imagens com texto}other{Compartilhando # imagens com texto}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Compartilhando imagem com link}one{Compartilhando # imagem com link}many{Compartilhando # de imagens com link}other{Compartilhando # imagens com link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Compartilhando vídeo com texto}one{Compartilhando # vídeo com texto}many{Compartilhando # de vídeos com texto}other{Compartilhando # vídeos com texto}}"</string>
diff --git a/java/res/values-ro/strings.xml b/java/res/values-ro/strings.xml
index 02d5df12..c2843bab 100644
--- a/java/res/values-ro/strings.xml
+++ b/java/res/values-ro/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Se trimite imaginea}few{Se trimit # imagini}other{Se trimit # de imagini}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Se trimite videoclipul}few{Se trimit # videoclipuri}other{Se trimit # de videoclipuri}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Se trimite un fișier}few{Se trimit # fișiere}other{Se trimit # de fișiere}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Selectează articole de trimis"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Se trimite imaginea cu text}few{Se trimit # imagini cu text}other{Se trimit # de imagini cu text}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Se trimite imaginea cu linkul}few{Se trimit # imagini cu linkul}other{Se trimit # de imagini cu linkul}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Se trimite videoclipul cu text}few{Se trimit # videoclipuri cu text}other{Se trimit # de videoclipuri cu text}}"</string>
diff --git a/java/res/values-ru/strings.xml b/java/res/values-ru/strings.xml
index fa8a06a3..9b4c2d20 100644
--- a/java/res/values-ru/strings.xml
+++ b/java/res/values-ru/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Отправка изображения}one{Отправка # изображения}few{Отправка # изображений}many{Отправка # изображений}other{Отправка # изображения}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Отправка видео}one{Отправка # видео}few{Отправка # видео}many{Отправка # видео}other{Отправка # видео}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Предоставляется доступ к # файлу}one{Предоставляется доступ к # файлу}few{Предоставляется доступ к # файлам}many{Предоставляется доступ к # файлам}other{Предоставляется доступ к # файла}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Выберите объекты для отправки"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Отправка изображения с текстом}one{Отправка # изображения с текстом}few{Отправка # изображений с текстом}many{Отправка # изображений с текстом}other{Отправка # изображения с текстом}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Отправка изображения со ссылкой}one{Отправка # изображения со ссылкой}few{Отправка # изображений со ссылкой}many{Отправка # изображений со ссылкой}other{Отправка # изображения со ссылкой}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Отправка видео с текстом}one{Отправка # видео с текстом}few{Отправка # видео с текстом}many{Отправка # видео с текстом}other{Отправка # видео с текстом}}"</string>
diff --git a/java/res/values-si/strings.xml b/java/res/values-si/strings.xml
index 6f5be5f5..1fc87e4d 100644
--- a/java/res/values-si/strings.xml
+++ b/java/res/values-si/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{රූපය බෙදා ගැනීම}one{රූප #ක් බෙදා ගැනීම}other{රූප #ක් බෙදා ගැනීම}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{වීඩියෝව බෙදා ගැනීම}one{වීඩියෝ #ක් බෙදා ගැනීම}other{වීඩියෝ #ක් බෙදා ගැනීම}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ගොනුවක් බෙදා ගැනීම}one{ගොනු #ක් බෙදා ගැනීම}other{ගොනු #ක් බෙදා ගැනීම}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"බෙදා ගැනීමට අයිතම තෝරන්න"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{පෙළ සමග රූපය බෙදා ගැනීම}one{පෙළ සමග රූප #ක් බෙදා ගැනීම}other{පෙළ සමග රූප #ක් බෙදා ගැනීම}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{සබැඳිය සමග රූපය බෙදා ගැනීම}one{සබැඳිය සමග රූප #ක් බෙදා ගැනීම}other{සබැඳිය සමග රූප #ක් බෙදා ගැනීම}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{පෙළ සමග වීඩියෝව බෙදා ගැනීම}one{පෙළ සමග වීඩියෝ #ක් බෙදා ගැනීම}other{පෙළ සමග වීඩියෝ #ක් බෙදා ගැනීම}}"</string>
diff --git a/java/res/values-sk/strings.xml b/java/res/values-sk/strings.xml
index 926d9d50..9119aaa0 100644
--- a/java/res/values-sk/strings.xml
+++ b/java/res/values-sk/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Zdieľanie obrázku}few{Zdieľanie # obrázkov}many{Sharing # images}other{Zdieľanie # obrázkov}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Zdieľa sa video}few{Zdieľajú sa # videá}many{Sharing # videos}other{Zdieľa sa # videí}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Zdieľa sa # súbor}few{Zdieľajú sa # súbory}many{Sharing # files}other{Zdieľa sa # súborov}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Vyberte položky na zdieľanie"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Zdieľa sa obrázok s textom}few{Zdieľajú sa # obrázky s textom}many{Sharing # images with text}other{Zdieľa sa # obrázkov s textom}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Zdieľa sa obrázok s odkazom}few{Zdieľajú sa # obrázky s odkazom}many{Sharing # images with link}other{Zdieľa sa # obrázkov s odkazom}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Zdieľa sa video s textom}few{Zdieľajú sa # videá s textom}many{Sharing # videos with text}other{Zdieľa sa # videí s textom}}"</string>
diff --git a/java/res/values-sl/strings.xml b/java/res/values-sl/strings.xml
index afa61945..78e07ad1 100644
--- a/java/res/values-sl/strings.xml
+++ b/java/res/values-sl/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Deljenje slike}one{Deljenje # slike}two{Deljenje # slik}few{Deljenje # slik}other{Deljenje # slik}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Deljenje videoposnetka}one{Deljenje # videoposnetka}two{Deljenje # videoposnetkov}few{Deljenje # videoposnetkov}other{Deljenje # videoposnetkov}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Deljenje # datoteke}one{Deljenje # datoteke}two{Deljenje # datotek}few{Deljenje # datotek}other{Deljenje # datotek}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Izbira elementov za deljenje"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Deljenje slike z besedilom}one{Deljenje # slike z besedilom}two{Deljenje # slik z besedilom}few{Deljenje # slik z besedilom}other{Deljenje # slik z besedilom}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Deljenje slike s povezavo}one{Deljenje # slike s povezavo}two{Deljenje # slik s povezavo}few{Deljenje # slik s povezavo}other{Deljenje # slik s povezavo}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Deljenje videoposnetka z besedilom}one{Deljenje # videoposnetka z besedilom}two{Deljenje # videoposnetkov z besedilom}few{Deljenje # videoposnetkov z besedilom}other{Deljenje # videoposnetkov z besedilom}}"</string>
diff --git a/java/res/values-sq/strings.xml b/java/res/values-sq/strings.xml
index faf27da5..374b2e0a 100644
--- a/java/res/values-sq/strings.xml
+++ b/java/res/values-sq/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Po ndahet imazh}other{Po ndahen # imazhe}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Po ndahet videoja}other{Po ndahen # video}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Po ndahet # skedar}other{Po ndahen # skedarë}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Zgjidh artikujt për t\'i ndarë"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Po ndahet një imazh me tekst}other{Po ndahen # imazhe me tekst}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Po ndahet një imazh me lidhje}other{Po ndahen # imazhe me lidhje}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Po ndahet një video me tekst}other{Po ndahen # video me tekst}}"</string>
diff --git a/java/res/values-sr/strings.xml b/java/res/values-sr/strings.xml
index 1a9834d9..8e7c57d1 100644
--- a/java/res/values-sr/strings.xml
+++ b/java/res/values-sr/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Дељење слике}one{Дељење # слике}few{Дељење # слике}other{Дељење # слика}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Дели се видео}one{Дели се # видео}few{Деле се # видео снимка}other{Дели се # видеа}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Дели се # фајл}one{Дели се # фајл}few{Деле се # фајла}other{Дели се # фајлова}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Изаберите ставке за дељење"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Дели се слика са текстом}one{Дели се # слика са текстом}few{Деле се # слике са текстом}other{Дели се # слика са текстом}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Дели се слика са линком}one{Дели се # слика са линком}few{Деле се # слике са линком}other{Дели се # слика са линком}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Дели се видео са текстом}one{Дели се # видео са текстом}few{Деле се # видео снимка са текстом}other{Дели се # видеа са текстом}}"</string>
diff --git a/java/res/values-sv/strings.xml b/java/res/values-sv/strings.xml
index c20b2a43..d48cc781 100644
--- a/java/res/values-sv/strings.xml
+++ b/java/res/values-sv/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Delar bild}other{Delar # bilder}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Delar video}other{Delar # videor}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Delar # fil}other{Delar # filer}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Välj objekt att dela"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Delar bild med text}other{Delar # bilder med text}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Delar bild med länk}other{Delar # bilder med länk}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Delar video med text}other{Delar # videor med text}}"</string>
@@ -75,7 +76,7 @@
     <string name="file_preview_a11y_description" msgid="7397224827802410602">"Miniatyr av förhandsgranskning av fil"</string>
     <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"Inga rekommenderade personer att dela med"</string>
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"Appen har inte fått inspelningsbehörighet men kan spela in ljud via denna USB-enhet."</string>
-    <string name="resolver_personal_tab" msgid="1381052735324320565">"Privat"</string>
+    <string name="resolver_personal_tab" msgid="1381052735324320565">"Personlig"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"Jobb"</string>
     <string name="resolver_private_tab" msgid="3707548826254095157">"Privat"</string>
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"Personlig vy"</string>
diff --git a/java/res/values-sw/strings.xml b/java/res/values-sw/strings.xml
index 3f99f9e7..2f63e887 100644
--- a/java/res/values-sw/strings.xml
+++ b/java/res/values-sw/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Inashiriki picha}other{Inashiriki picha #}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Inashiriki video}other{Inashiriki video #}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Inashiriki faili #}other{Inashiriki faili #}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Chagua vipengee vya kutuma"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Inashiriki picha na maandishi}other{Inashiriki picha # na maandishi}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Inashiriki picha na kiungo}other{Inashiriki picha # na kiungo}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Inashiriki video na maandishi}other{Inashiriki video # na maandishi}}"</string>
diff --git a/java/res/values-ta/strings.xml b/java/res/values-ta/strings.xml
index f2fbb6e3..f1df5cba 100644
--- a/java/res/values-ta/strings.xml
+++ b/java/res/values-ta/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{படத்தைப் பகிர்கிறது}other{# படங்களைப் பகிர்கிறது}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{வீடியோவைப் பகிர்கிறது}other{# வீடியோக்களை பகிர்கிறது}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ஃபைலைப் பகிர்கிறது}other{# ஃபைல்களைப் பகிர்கிறது}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"பகிர விரும்புபவற்றைத் தேர்ந்தெடுத்தல்"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{வார்த்தைகளுடன் படத்தைப் பகிர்கிறது}other{வார்த்தைகளுடன் # படங்களைப் பகிர்கிறது}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{இணைப்பைக் கொண்ட படத்தைப் பகிர்கிறது}other{இணைப்பைக் கொண்ட # படங்களைப் பகிர்கிறது}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{வார்த்தைகளைக் கொண்ட வீடியோவைப் பகிர்கிறது}other{வார்த்தைகளைக் கொண்ட # வீடியோக்களைப் பகிர்கிறது}}"</string>
diff --git a/java/res/values-te/strings.xml b/java/res/values-te/strings.xml
index 840279f3..b88d7d4e 100644
--- a/java/res/values-te/strings.xml
+++ b/java/res/values-te/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ఈ ఇమేజ్‌ను షేర్ చేస్తున్నారు}other{ఈ # ఇమేజ్‌లను షేర్ చేస్తున్నారు}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{వీడియోను షేర్ చేయడం}other{# వీడియోలను షేర్ చేయడం}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ఫైల్‌ను షేర్ చేస్తోంది}other{# ఫైళ్లను షేర్ చేస్తోంది}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"షేర్ చేయడానికి ఐటెమ్‌లను ఎంచుకోండి"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{టెక్స్ట్ మెసేజ్ పంపడం ద్వారా ఇమేజ్‌ను షేర్ చేయడం}other{టెక్స్ట్ మెసేజ్ పంపడం ద్వారా # ఇమేజ్‌లను షేర్ చేయడం}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{లింక్ చేయడం ద్వారా ఇమేజ్‌ను షేర్ చేయడం}other{లింక్ చేయడం ద్వారా # ఇమేజ్‌లను షేర్ చేయడం}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{టెక్స్ట్ మెసేజ్ పంపడం ద్వారా వీడియోను షేర్ చేయడం}other{టెక్స్ట్ మెసేజ్ పంపడం ద్వారా # వీడియోలను షేర్ చేయడం}}"</string>
diff --git a/java/res/values-th/strings.xml b/java/res/values-th/strings.xml
index 29a97978..5effd16c 100644
--- a/java/res/values-th/strings.xml
+++ b/java/res/values-th/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{กำลังแชร์รูปภาพ}other{กำลังแชร์รูปภาพ # รายการ}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{กำลังแชร์วิดีโอ}other{กำลังแชร์วิดีโอ # รายการ}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{กำลังจะแชร์ # ไฟล์}other{กำลังจะแชร์ # ไฟล์}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"เลือกรายการที่จะแชร์"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{กำลังแชร์รูปภาพพร้อมข้อความ}other{กำลังแชร์รูปภาพ # รายการพร้อมข้อความ}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{กำลังแชร์รูปภาพพร้อมลิงก์}other{กำลังแชร์รูปภาพ # รายการพร้อมลิงก์}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{กำลังแชร์วิดีโอพร้อมข้อความ}other{กำลังแชร์วิดีโอ # รายการพร้อมข้อความ}}"</string>
diff --git a/java/res/values-tl/strings.xml b/java/res/values-tl/strings.xml
index b085b46b..67782253 100644
--- a/java/res/values-tl/strings.xml
+++ b/java/res/values-tl/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Shine-share ang larawan}one{Shine-share ang # larawan}other{Shine-share ang # na larawan}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Ibinabahagi ang video}one{Ibinabahagi ang # video}other{Ibinabahagi ang # na video}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Nagshe-share ng # file}one{Nagshe-share ng # file}other{Nagshe-share ng # na file}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Pumili ng mga item na ibabahagi"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Nagbabahagi ng larawang may text}one{Nagbabahagi ng # larawang may text}other{Nagbabahagi ng # na larawang may text}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Nagbabahagi ng larawang may link}one{Nagbabahagi ng # larawang may link}other{Nagbabahagi ng # na larawang may link}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Nagbabahagi ng video na may text}one{Nagbabahagi ng # video na may text}other{Nagbabahagi ng # na video na may text}}"</string>
diff --git a/java/res/values-tr/strings.xml b/java/res/values-tr/strings.xml
index 22024818..5dee9296 100644
--- a/java/res/values-tr/strings.xml
+++ b/java/res/values-tr/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Resim paylaşılıyor}other{# resim paylaşılıyor}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Video paylaşılıyor}other{# video paylaşılıyor}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# dosya paylaşılıyor}other{# dosya paylaşılıyor}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Paylaşılacak öğeleri seçin"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Metin ekli resim paylaşılıyor}other{Metin ekli # resim paylaşılıyor}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Bağlantı ekli resim paylaşılıyor}other{Bağlantı ekli # resim paylaşılıyor}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Metin ekli video paylaşılıyor}other{Metin ekli # video paylaşılıyor}}"</string>
diff --git a/java/res/values-uk/strings.xml b/java/res/values-uk/strings.xml
index b5f91741..293696fd 100644
--- a/java/res/values-uk/strings.xml
+++ b/java/res/values-uk/strings.xml
@@ -57,9 +57,10 @@
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{і ще # файл}one{і ще # файл}few{і ще # файли}many{і ще # файлів}other{і ще # файлу}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Надсилається текст"</string>
     <string name="sharing_link" msgid="2307694372813942916">"Надсилається посилання"</string>
-    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Надсилається зображення}one{Надсилається # зображення}few{Надсилаються # зображення}many{Надсилаються # зображень}other{Надсилається # зображення}}"</string>
+    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Надсилання зображення}one{Надсилання # зображення}few{Надсилання # зображень}many{Надсилання # зображень}other{Надсилання # зображення}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Надсилається відео}one{Надсилається # відео}few{Надсилаються # відео}many{Надсилаються # відео}other{Надсилається # відео}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Надсилається # файл}one{Надсилається # файл}few{Надсилаються # файли}many{Надсилаються # файлів}other{Надсилається # файлу}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Виберіть об’єкти, якими хочете поділитися"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Надсилання зображення з текстом}one{Надсилання # зображення з текстом}few{Надсилання # зображень із текстом}many{Надсилання # зображень із текстом}other{Надсилання # зображення з текстом}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Надсилання зображення з посиланням}one{Надсилання # зображення з посиланням}few{Надсилання # зображень із посиланням}many{Надсилання # зображень із посиланням}other{Надсилання # зображення з посиланням}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Надсилання відео з текстом}one{Надсилання # відео з текстом}few{Надсилання # відео з текстом}many{Надсилання # відео з текстом}other{Надсилання # відео з текстом}}"</string>
diff --git a/java/res/values-ur/strings.xml b/java/res/values-ur/strings.xml
index f6eb8612..9ecc8443 100644
--- a/java/res/values-ur/strings.xml
+++ b/java/res/values-ur/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{تصویر کا اشتراک کیا جا رہا ہے}other{# تصاویر کا اشتراک کیا جا رہا ہے}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ویڈیو کا اشتراک کیا جا رہا ہے}other{# ویڈیوز کا اشتراک کیا جا رہا ہے}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# فائل کا اشتراک کیا جا رہا ہے}other{# فائلز کا اشتراک کیا جا رہا ہے}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"اشتراک کرنے کے لیے آئٹمز منتخب کریں"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{ٹیکسٹ کے ساتھ تصویر کا اشتراک کیا جا رہا ہے}other{ٹیکسٹ کے ساتھ # تصاویر کا اشتراک کیا جا رہا ہے}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{لنک کے ساتھ تصویر کا اشتراک کیا جا رہا ہے}other{لنک کے ساتھ # تصاویر کا اشتراک کیا جا رہا ہے}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{ٹیکسٹ کے ساتھ ویڈیو کا اشتراک کیا جا رہا ہے}other{ٹیکسٹ کے ساتھ # ویڈیوز کا اشتراک کیا جا رہا ہے}}"</string>
diff --git a/java/res/values-uz/strings.xml b/java/res/values-uz/strings.xml
index 96439147..f9434b18 100644
--- a/java/res/values-uz/strings.xml
+++ b/java/res/values-uz/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Rasm ulashilmoqda}other{# ta rasm ulashilmoqda}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Video ulashilmoqda}other{# ta video ulashilmoqda}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ta fayl ulashilmoqda}other{# ta fayl ulashilmoqda}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Ulashish uchun elementlarni tanlang"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Matnli havolani yuborish}other{# ta matnli havolani yuborish}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Havolali rasmni yuborish}other{# ta havolali rasmni yuborish}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Matnli videoni yuborish}other{# ta matnli videoni yuborish}}"</string>
diff --git a/java/res/values-vi/strings.xml b/java/res/values-vi/strings.xml
index 0645d052..4c84256e 100644
--- a/java/res/values-vi/strings.xml
+++ b/java/res/values-vi/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Chia sẻ hình ảnh}other{Chia sẻ # hình ảnh}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Đang chia sẻ video}other{Đang chia sẻ # video}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Đang chia sẻ # tệp}other{Đang chia sẻ # tệp}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Chọn mục muốn chia sẻ"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Đang chia sẻ hình ảnh có văn bản}other{Đang chia sẻ # hình ảnh có văn bản}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Đang chia sẻ hình ảnh có đường liên kết}other{Đang chia sẻ # hình ảnh có đường liên kết}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Đang chia sẻ video có văn bản}other{Đang chia sẻ # video có văn bản}}"</string>
@@ -88,7 +89,7 @@
     <string name="resolver_cant_access_personal_apps_explanation" msgid="6209543716289792706">"Bạn không thể mở nội dung này bằng ứng dụng cá nhân"</string>
     <string name="resolver_cant_share_with_private_apps_explanation" msgid="1781980997411434697">"Không chia sẻ được nội dung này bằng ứng dụng riêng tư"</string>
     <string name="resolver_cant_access_private_apps_explanation" msgid="5978609934961648342">"Không mở được nội dung này bằng ứng dụng riêng tư"</string>
-    <string name="resolver_turn_on_work_apps" msgid="7115260573975624516">"Các ứng dụng công việc đã bị tạm dừng"</string>
+    <string name="resolver_turn_on_work_apps" msgid="7115260573975624516">"Các ứng dụng trong hồ sơ Công việc đã bị tạm dừng"</string>
     <string name="resolver_switch_on_work" msgid="8678893259344318807">"Tiếp tục"</string>
     <string name="resolver_no_work_apps_available" msgid="6139818641313189903">"Không có ứng dụng công việc"</string>
     <string name="resolver_no_personal_apps_available" msgid="8479033344701050767">"Không có ứng dụng cá nhân"</string>
diff --git a/java/res/values-zh-rCN/strings.xml b/java/res/values-zh-rCN/strings.xml
index 9fea3097..c2fa444f 100644
--- a/java/res/values-zh-rCN/strings.xml
+++ b/java/res/values-zh-rCN/strings.xml
@@ -60,13 +60,14 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{分享图片}other{分享 # 张图片}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{正在分享视频}other{正在分享 # 个视频}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{正在分享 # 个文件}other{正在分享 # 个文件}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"选择要分享的内容"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{正在分享带有文本的图片}other{正在分享带有文本的 # 个图片}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{正在分享带有链接的图片}other{正在分享带有链接的 # 个图片}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{正在分享带有文本的视频}other{正在分享带有文本的 # 个视频}}"</string>
     <string name="sharing_videos_with_link" msgid="6383290441403042321">"{count,plural, =1{正在分享带有链接的视频}other{正在分享带有链接的 # 个视频}}"</string>
     <string name="sharing_files_with_text" msgid="7331187260405018080">"{count,plural, =1{正在分享带有文本的文件}other{正在分享带有文本的 # 个文件}}"</string>
     <string name="sharing_files_with_link" msgid="6052797122358827239">"{count,plural, =1{正在分享带有链接的文件}other{正在分享带有链接的 # 个文件}}"</string>
-    <string name="sharing_album" msgid="191743129899503345">"分享影集"</string>
+    <string name="sharing_album" msgid="191743129899503345">"分享相册"</string>
     <string name="sharing_images_only" msgid="7762589767189955438">"{count,plural, =1{仅限图片}other{仅限图片}}"</string>
     <string name="sharing_videos_only" msgid="5549729252364968606">"{count,plural, =1{仅限视频}other{仅限视频}}"</string>
     <string name="sharing_files_only" msgid="6603666533766964768">"{count,plural, =1{仅限文件}other{仅限文件}}"</string>
diff --git a/java/res/values-zh-rHK/strings.xml b/java/res/values-zh-rHK/strings.xml
index 65f73d0a..54a61c7e 100644
--- a/java/res/values-zh-rHK/strings.xml
+++ b/java/res/values-zh-rHK/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{分享圖片}other{分享 # 張圖片}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{正在分享影片}other{正在分享 # 部影片}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{正在分享 # 個檔案}other{正在分享 # 個檔案}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"選取要分享的項目"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{正在分享圖片 (含有文字)}other{正在分享 # 張圖片 (含有文字)}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{正在分享圖片 (含有連結)}other{正在分享 # 張圖片 (含有連結)}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{正在分享影片 (含有文字)}other{正在分享 # 部影片 (含有文字)}}"</string>
diff --git a/java/res/values-zh-rTW/strings.xml b/java/res/values-zh-rTW/strings.xml
index bade791a..0d369318 100644
--- a/java/res/values-zh-rTW/strings.xml
+++ b/java/res/values-zh-rTW/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{分享圖片}other{分享 # 張圖片}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{正在分享影片}other{正在分享 # 部影片}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{正在分享 # 個檔案}other{正在分享 # 個檔案}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"選取要分享的項目"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{分享含有文字的圖片}other{分享 # 張含有文字的圖片}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{分享含有連結的圖片}other{分享 # 張含有連結的圖片}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{分享含有文字的影片}other{分享 # 部含有文字的影片}}"</string>
diff --git a/java/res/values-zu/strings.xml b/java/res/values-zu/strings.xml
index 38e62f88..9d6d13dc 100644
--- a/java/res/values-zu/strings.xml
+++ b/java/res/values-zu/strings.xml
@@ -60,6 +60,7 @@
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Yabelana ngomfanekiso}one{Yabelana ngemifanekiso engu-#}other{Yabelana ngemifanekiso engu-#}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Yabelana ngevidiyo}one{Yabelana ngamavidiyo angu-#}other{Yabelana ngamavidiyo angu-#}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Yabelana ngefayela eli-#}one{Yabelana ngamafayela angu-#}other{Yabelana ngamafayela angu-#}}"</string>
+    <string name="select_items_to_share" msgid="1026071777275022579">"Khetha izinto ongabelana ngazo"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Yabelana ngomfanekiso ngombhalo}one{Yabelana ngemifanekiso engu-# ngombhalo}other{Yabelana ngemifanekiso engu-# ngombhalo}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Yabelana ngomfanekiso ngelinki}one{Yabelana ngemifanekiso engu-# ngelinki}other{Yabelana ngemifanekiso engu-# ngelinki}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Yabelana ngevidiyo ngombhalo}one{Yabelana ngamavidiyo angu-# ngombhalo}other{Yabelana ngamavidiyo angu-# ngombhalo}}"</string>
diff --git a/java/res/values/strings.xml b/java/res/values/strings.xml
index c026ee59..4f77d248 100644
--- a/java/res/values/strings.xml
+++ b/java/res/values/strings.xml
@@ -162,6 +162,9 @@
         }
     </string>
 
+    <!-- Title atop a sharing UI indicating that a selection needs to be made for sharing -->
+    <string name="select_items_to_share">Select items to share</string>
+
     <!-- Title atop a sharing UI indicating that some number of images are being shared
          along with text [CHAR_LIMIT=50] -->
     <string name="sharing_images_with_text">{count, plural,
diff --git a/java/src/com/android/intentresolver/ChooserActionFactory.java b/java/src/com/android/intentresolver/ChooserActionFactory.java
index cc7091e4..21ca3b73 100644
--- a/java/src/com/android/intentresolver/ChooserActionFactory.java
+++ b/java/src/com/android/intentresolver/ChooserActionFactory.java
@@ -133,8 +133,7 @@ public final class ChooserActionFactory implements ChooserContentPreviewUi.Actio
             ActionActivityStarter activityStarter,
             @Nullable ShareResultSender shareResultSender,
             Consumer</* @Nullable */ Integer> finishCallback,
-            ClipboardManager clipboardManager,
-            FeatureFlags featureFlags) {
+            ClipboardManager clipboardManager) {
         this(
                 context,
                 makeCopyButtonRunnable(
@@ -150,8 +149,7 @@ public final class ChooserActionFactory implements ChooserContentPreviewUi.Actio
                                 imageEditor),
                         firstVisibleImageQuery,
                         activityStarter,
-                        log,
-                        featureFlags.fixPartialImageEditTransition()),
+                        log),
                 chooserActions,
                 onUpdateSharedTextIsExcluded,
                 log,
@@ -340,8 +338,7 @@ public final class ChooserActionFactory implements ChooserContentPreviewUi.Actio
             @Nullable TargetInfo editSharingTarget,
             Callable</* @Nullable */ View> firstVisibleImageQuery,
             ActionActivityStarter activityStarter,
-            EventLog log,
-            boolean requireFullVisibility) {
+            EventLog log) {
         if (editSharingTarget == null) return null;
         return () -> {
             // Log share completion via edit.
@@ -352,8 +349,7 @@ public final class ChooserActionFactory implements ChooserContentPreviewUi.Actio
                 firstImageView = firstVisibleImageQuery.call();
             } catch (Exception e) { /* ignore */ }
             // Action bar is user-independent; always start as primary.
-            if (firstImageView == null
-                    || (requireFullVisibility && !isFullyVisible(firstImageView))) {
+            if (firstImageView == null || !isFullyVisible(firstImageView)) {
                 activityStarter.safelyStartActivityAsPersonalProfileUser(editSharingTarget);
             } else {
                 activityStarter.safelyStartActivityAsPersonalProfileUserWithSharedElementTransition(
diff --git a/java/src/com/android/intentresolver/ChooserActivity.java b/java/src/com/android/intentresolver/ChooserActivity.java
index a5516fde..4fc8fd9d 100644
--- a/java/src/com/android/intentresolver/ChooserActivity.java
+++ b/java/src/com/android/intentresolver/ChooserActivity.java
@@ -23,6 +23,9 @@ import static android.view.WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTE
 import static androidx.lifecycle.LifecycleKt.getCoroutineScope;
 
 import static com.android.intentresolver.ChooserActionFactory.EDIT_SOURCE;
+import static com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra;
+import static com.android.intentresolver.Flags.fixShortcutsFlashing;
+import static com.android.intentresolver.Flags.unselectFinalItem;
 import static com.android.intentresolver.ext.CreationExtrasExtKt.addDefaultArgs;
 import static com.android.intentresolver.profiles.MultiProfilePagerAdapter.PROFILE_PERSONAL;
 import static com.android.intentresolver.profiles.MultiProfilePagerAdapter.PROFILE_WORK;
@@ -96,10 +99,8 @@ import com.android.intentresolver.ChooserRefinementManager.RefinementType;
 import com.android.intentresolver.chooser.DisplayResolveInfo;
 import com.android.intentresolver.chooser.MultiDisplayResolveInfo;
 import com.android.intentresolver.chooser.TargetInfo;
-import com.android.intentresolver.contentpreview.BasePreviewViewModel;
 import com.android.intentresolver.contentpreview.ChooserContentPreviewUi;
 import com.android.intentresolver.contentpreview.HeadlineGeneratorImpl;
-import com.android.intentresolver.contentpreview.PreviewViewModel;
 import com.android.intentresolver.data.model.ChooserRequest;
 import com.android.intentresolver.data.repository.DevicePolicyResources;
 import com.android.intentresolver.domain.interactor.UserInteractor;
@@ -154,8 +155,10 @@ import kotlinx.coroutines.CoroutineDispatcher;
 
 import java.util.ArrayList;
 import java.util.Arrays;
+import java.util.Collection;
 import java.util.Collections;
 import java.util.HashMap;
+import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
@@ -206,7 +209,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     private static final String TAB_TAG_PERSONAL = "personal";
     private static final String TAB_TAG_WORK = "work";
 
-    private static final String LAST_SHOWN_TAB_KEY = "last_shown_tab_key";
+    private static final String LAST_SHOWN_PROFILE = "last_shown_tab_key";
     public static final String METRICS_CATEGORY_CHOOSER = "intent_chooser";
 
     private int mLayoutId;
@@ -306,7 +309,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     private final EnterTransitionAnimationDelegate mEnterTransitionAnimationDelegate =
             new EnterTransitionAnimationDelegate(this, () -> mResolverDrawerLayout);
 
-    private final Map<Integer, ProfileRecord> mProfileRecords = new HashMap<>();
+    private final Map<Integer, ProfileRecord> mProfileRecords = new LinkedHashMap<>();
 
     private boolean mExcludeSharedText = false;
     /**
@@ -349,8 +352,12 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         if (mChooserServiceFeatureFlags.chooserPayloadToggling()) {
             mChooserHelper.setOnChooserRequestChanged(this::onChooserRequestChanged);
             mChooserHelper.setOnPendingSelection(this::onPendingSelection);
+            if (unselectFinalItem()) {
+                mChooserHelper.setOnHasSelections(this::onHasSelections);
+            }
         }
     }
+    private int mInitialProfile = -1;
 
     @Override
     protected final void onStart() {
@@ -412,7 +419,8 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     protected final void onSaveInstanceState(Bundle outState) {
         super.onSaveInstanceState(outState);
         if (mViewPager != null) {
-            outState.putInt(LAST_SHOWN_TAB_KEY, mViewPager.getCurrentItem());
+            outState.putInt(
+                    LAST_SHOWN_PROFILE, mChooserMultiProfilePagerAdapter.getActiveProfile());
         }
     }
 
@@ -517,6 +525,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 mProfilePagerResources,
                 mRequest,
                 mProfiles,
+                mProfileRecords.values(),
                 mProfileAvailability,
                 mRequest.getInitialIntents(),
                 mMaxTargetsPerRow);
@@ -633,21 +642,14 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 finish();
             }
         });
-        BasePreviewViewModel previewViewModel =
-                new ViewModelProvider(this, createPreviewViewModelFactory())
-                        .get(BasePreviewViewModel.class);
-        previewViewModel.init(
-                mRequest.getTargetIntent(),
-                mRequest.getAdditionalContentUri(),
-                mChooserServiceFeatureFlags.chooserPayloadToggling());
         ChooserContentPreviewUi.ActionFactory actionFactory =
                 decorateActionFactoryWithRefinement(
                         createChooserActionFactory(mRequest.getTargetIntent()));
         mChooserContentPreviewUi = new ChooserContentPreviewUi(
                 getCoroutineScope(getLifecycle()),
-                previewViewModel.getPreviewDataProvider(),
-                mRequest.getTargetIntent(),
-                previewViewModel.getImageLoader(),
+                mViewModel.getPreviewDataProvider(),
+                mRequest,
+                mViewModel.getImageLoader(),
                 actionFactory,
                 createModifyShareActionFactory(),
                 mEnterTransitionAnimationDelegate,
@@ -688,6 +690,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 mRequest.getModifyShareAction() != null
         );
         mEnterTransitionAnimationDelegate.postponeTransition();
+        mInitialProfile = findSelectedProfile();
         Tracer.INSTANCE.markLaunched();
     }
 
@@ -706,7 +709,6 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     }
 
     private void onChooserRequestChanged(ChooserRequest chooserRequest) {
-        // intentional reference comparison
         if (mRequest == chooserRequest) {
             return;
         }
@@ -725,6 +727,10 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         setTabsViewEnabled(false);
     }
 
+    private void onHasSelections(boolean hasSelections) {
+        mChooserMultiProfilePagerAdapter.setTargetsEnabled(hasSelections);
+    }
+
     private void onAppTargetsLoaded(ResolverListAdapter listAdapter) {
         Log.d(TAG, "onAppTargetsLoaded("
                 + "listAdapter.userHandle=" + listAdapter.getUserHandle() + ")");
@@ -755,10 +761,15 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         Intent newTargetIntent = newChooserRequest.getTargetIntent();
         List<Intent> oldAltIntents = oldChooserRequest.getAdditionalTargets();
         List<Intent> newAltIntents = newChooserRequest.getAdditionalTargets();
+        List<ComponentName> oldExcluded = oldChooserRequest.getFilteredComponentNames();
+        List<ComponentName> newExcluded = newChooserRequest.getFilteredComponentNames();
 
         // TODO: a workaround for the unnecessary target reloading caused by multiple flow updates -
         //  an artifact of the current implementation; revisit.
-        return !oldTargetIntent.equals(newTargetIntent) || !oldAltIntents.equals(newAltIntents);
+        return !oldTargetIntent.equals(newTargetIntent)
+                || !oldAltIntents.equals(newAltIntents)
+                || (shareouselUpdateExcludeComponentsExtra()
+                        && !oldExcluded.equals(newExcluded));
     }
 
     private void recreatePagerAdapter() {
@@ -782,11 +793,14 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         }
         // Update the pager adapter but do not attach it to the view till the targets are reloaded,
         // see onChooserAppTargetsLoaded method.
+        ChooserMultiProfilePagerAdapter oldPagerAdapter =
+                mChooserMultiProfilePagerAdapter;
         mChooserMultiProfilePagerAdapter = createMultiProfilePagerAdapter(
                 /* context = */ this,
                 mProfilePagerResources,
                 mRequest,
                 mProfiles,
+                mProfileRecords.values(),
                 mProfileAvailability,
                 mRequest.getInitialIntents(),
                 mMaxTargetsPerRow);
@@ -820,6 +834,19 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         postRebuildList(
                 mChooserMultiProfilePagerAdapter.rebuildTabs(
                     mProfiles.getWorkProfilePresent() || mProfiles.getPrivateProfilePresent()));
+        if (fixShortcutsFlashing() && oldPagerAdapter != null) {
+            for (int i = 0, count = mChooserMultiProfilePagerAdapter.getCount(); i < count; i++) {
+                ChooserListAdapter listAdapter =
+                        mChooserMultiProfilePagerAdapter.getPageAdapterForIndex(i)
+                                .getListAdapter();
+                ChooserListAdapter oldListAdapter =
+                        oldPagerAdapter.getListAdapterForUserHandle(listAdapter.getUserHandle());
+                if (oldListAdapter != null) {
+                    listAdapter.copyDirectTargetsFrom(oldListAdapter);
+                    listAdapter.setDirectTargetsEnabled(false);
+                }
+            }
+        }
         setTabsViewEnabled(false);
     }
 
@@ -837,7 +864,12 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     @Override
     protected void onRestoreInstanceState(@NonNull Bundle savedInstanceState) {
         if (mViewPager != null) {
-            mViewPager.setCurrentItem(savedInstanceState.getInt(LAST_SHOWN_TAB_KEY));
+            int profile = savedInstanceState.getInt(LAST_SHOWN_PROFILE);
+            int profileNumber = mChooserMultiProfilePagerAdapter.getPageNumberForProfile(profile);
+            if (profileNumber != -1) {
+                mViewPager.setCurrentItem(profileNumber);
+                mInitialProfile = profile;
+            }
         }
         mChooserMultiProfilePagerAdapter.clearInactiveProfileCache();
     }
@@ -1088,7 +1120,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
             if (cti.startAsCaller(this, options, user.getIdentifier())) {
                 // Prevent sending a second chooser result when starting the edit action intent.
                 if (!cti.getTargetIntent().hasExtra(EDIT_SOURCE)) {
-                    maybeSendShareResult(cti);
+                    maybeSendShareResult(cti, user);
                 }
                 maybeLogCrossProfileTargetLaunch(cti, user);
             }
@@ -1346,26 +1378,32 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
 
     private void createProfileRecords(
             AppPredictorFactory factory, IntentFilter targetIntentFilter) {
-        UserHandle mainUserHandle = mProfiles.getPersonalHandle();
-        ProfileRecord record = createProfileRecord(mainUserHandle, targetIntentFilter, factory);
-        if (record.shortcutLoader == null) {
-            Tracer.INSTANCE.endLaunchToShortcutTrace();
-        }
-
-        UserHandle workUserHandle = mProfiles.getWorkHandle();
-        if (workUserHandle != null) {
-            createProfileRecord(workUserHandle, targetIntentFilter, factory);
-        }
 
-        UserHandle privateUserHandle = mProfiles.getPrivateHandle();
-        if (privateUserHandle != null && mProfileAvailability.isAvailable(
-                requireNonNull(mProfiles.getPrivateProfile()))) {
-            createProfileRecord(privateUserHandle, targetIntentFilter, factory);
+        Profile launchedAsProfile = mProfiles.getLaunchedAsProfile();
+        for (Profile profile : mProfiles.getProfiles()) {
+            if (profile.getType() == Profile.Type.PRIVATE
+                    && !mProfileAvailability.isAvailable(profile)) {
+                continue;
+            }
+            ProfileRecord record = createProfileRecord(
+                    profile,
+                    targetIntentFilter,
+                    launchedAsProfile.equals(profile)
+                            ? mRequest.getCallerChooserTargets()
+                            : Collections.emptyList(),
+                    factory);
+            if (profile.equals(launchedAsProfile) && record.shortcutLoader == null) {
+                Tracer.INSTANCE.endLaunchToShortcutTrace();
+            }
         }
     }
 
     private ProfileRecord createProfileRecord(
-            UserHandle userHandle, IntentFilter targetIntentFilter, AppPredictorFactory factory) {
+            Profile profile,
+            IntentFilter targetIntentFilter,
+            List<ChooserTarget> callerTargets,
+            AppPredictorFactory factory) {
+        UserHandle userHandle = profile.getPrimary().getHandle();
         AppPredictor appPredictor = factory.create(userHandle);
         ShortcutLoader shortcutLoader = ActivityManager.isLowRamDeviceStatic()
                     ? null
@@ -1375,7 +1413,8 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                             userHandle,
                             targetIntentFilter,
                             shortcutsResult -> onShortcutsLoaded(userHandle, shortcutsResult));
-        ProfileRecord record = new ProfileRecord(appPredictor, shortcutLoader);
+        ProfileRecord record = new ProfileRecord(
+                profile, appPredictor, shortcutLoader, callerTargets);
         mProfileRecords.put(userHandle.getIdentifier(), record);
         return record;
     }
@@ -1410,6 +1449,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
             ProfilePagerResources profilePagerResources,
             ChooserRequest request,
             ProfileHelper profileHelper,
+            Collection<ProfileRecord> profileRecords,
             ProfileAvailability profileAvailability,
             List<Intent> initialIntents,
             int maxTargetsPerRow) {
@@ -1421,11 +1461,8 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         List<Intent> payloadIntents = request.getPayloadIntents();
 
         List<TabConfig<ChooserGridAdapter>> tabs = new ArrayList<>();
-        for (Profile profile : profileHelper.getProfiles()) {
-            if (profile.getType() == Profile.Type.PRIVATE
-                    && !profileAvailability.isAvailable(profile)) {
-                continue;
-            }
+        for (ProfileRecord record : profileRecords) {
+            Profile profile = record.profile;
             ChooserGridAdapter adapter = createChooserGridAdapter(
                     context,
                     payloadIntents,
@@ -1640,26 +1677,29 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         return result;
     }
 
-    private void maybeSendShareResult(TargetInfo cti) {
+    private void maybeSendShareResult(TargetInfo cti, UserHandle launchedAsUser) {
         if (mShareResultSender != null) {
             final ComponentName target = cti.getResolvedComponentName();
             if (target != null) {
-                mShareResultSender.onComponentSelected(target, cti.isChooserTargetInfo());
+                boolean crossProfile = !UserHandle.of(UserHandle.myUserId()).equals(launchedAsUser);
+                mShareResultSender.onComponentSelected(
+                        target, cti.isChooserTargetInfo(), crossProfile);
             }
         }
     }
 
-    private void addCallerChooserTargets() {
-        if (!mRequest.getCallerChooserTargets().isEmpty()) {
-            // Send the caller's chooser targets only to the default profile.
-            if (mChooserMultiProfilePagerAdapter.getActiveProfile() == findSelectedProfile()) {
-                mChooserMultiProfilePagerAdapter.getActiveListAdapter().addServiceResults(
-                        /* origTarget */ null,
-                        new ArrayList<>(mRequest.getCallerChooserTargets()),
-                        TARGET_TYPE_DEFAULT,
-                        /* directShareShortcutInfoCache */ Collections.emptyMap(),
-                        /* directShareAppTargetCache */ Collections.emptyMap());
-            }
+    private void addCallerChooserTargets(ChooserListAdapter adapter) {
+        ProfileRecord record = getProfileRecord(adapter.getUserHandle());
+        List<ChooserTarget> callerTargets = record == null
+                ? Collections.emptyList()
+                : record.callerTargets;
+        if (!callerTargets.isEmpty()) {
+            adapter.addServiceResults(
+                    /* origTarget */ null,
+                    new ArrayList<>(mRequest.getCallerChooserTargets()),
+                    TARGET_TYPE_DEFAULT,
+                    /* directShareShortcutInfoCache */ Collections.emptyMap(),
+                    /* directShareAppTargetCache */ Collections.emptyMap());
         }
     }
 
@@ -2037,7 +2077,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 initialIntents,
                 rList,
                 filterLastUsed,
-                createListController(userHandle),
+                resolverListController,
                 userHandle,
                 targetIntent,
                 referrerFillInIntent,
@@ -2052,8 +2092,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                     if (record != null && record.shortcutLoader != null) {
                         record.shortcutLoader.reset();
                     }
-                },
-                mFeatureFlags);
+                });
     }
 
     private void onWorkProfileStatusUpdated() {
@@ -2108,11 +2147,6 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 mPinnedSharedPrefs);
     }
 
-    @VisibleForTesting
-    protected ViewModelProvider.Factory createPreviewViewModelFactory() {
-        return PreviewViewModel.Companion.getFactory();
-    }
-
     private ChooserContentPreviewUi.ActionFactory decorateActionFactoryWithRefinement(
             ChooserContentPreviewUi.ActionFactory originalFactory) {
         if (!mFeatureFlags.refineSystemActions()) {
@@ -2123,6 +2157,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
             @Override
             @Nullable
             public Runnable getEditButtonRunnable() {
+                if (originalFactory.getEditButtonRunnable() == null) return null;
                 return () -> {
                     if (!mRefinementManager.maybeHandleSelection(
                             RefinementType.EDIT_ACTION,
@@ -2139,6 +2174,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
             @Override
             @Nullable
             public Runnable getCopyButtonRunnable() {
+                if (originalFactory.getCopyButtonRunnable() == null) return null;
                 return () -> {
                     if (!mRefinementManager.maybeHandleSelection(
                             RefinementType.COPY_ACTION,
@@ -2208,8 +2244,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 },
                 mShareResultSender,
                 this::finishWithStatus,
-                mClipboardManager,
-                mFeatureFlags);
+                mClipboardManager);
     }
 
     private Supplier<ActionRow.Action> createModifyShareActionFactory() {
@@ -2258,7 +2293,8 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
 
         if (isLayoutUpdated
                 || insetsChanged
-                || mLastNumberOfChildren != recyclerView.getChildCount()) {
+                || mLastNumberOfChildren != recyclerView.getChildCount()
+                || mFeatureFlags.fixMissingDrawerOffsetCalculation()) {
             mCurrAvailableWidth = availableWidth;
             if (isLayoutUpdated) {
                 // It is very important we call setAdapter from here. Otherwise in some cases
@@ -2272,12 +2308,15 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
             }
 
             int currentProfile = mChooserMultiProfilePagerAdapter.getActiveProfile();
-            int initialProfile = findSelectedProfile();
+            int initialProfile = Flags.fixDrawerOffsetOnConfigChange()
+                    ? mInitialProfile
+                    : findSelectedProfile();
             if (currentProfile != initialProfile) {
                 return;
             }
 
-            if (mLastNumberOfChildren == recyclerView.getChildCount() && !insetsChanged) {
+            if (mLastNumberOfChildren == recyclerView.getChildCount() && !insetsChanged
+                    && !mFeatureFlags.fixMissingDrawerOffsetCalculation()) {
                 return;
             }
 
@@ -2404,7 +2443,9 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
             if (duration >= 0) {
                 Log.d(TAG, "app target loading time " + duration + " ms");
             }
-            addCallerChooserTargets();
+            if (!fixShortcutsFlashing()) {
+                addCallerChooserTargets(chooserListAdapter);
+            }
             getEventLog().logSharesheetAppLoadComplete();
             maybeQueryAdditionalPostProcessingTargets(
                     listProfileUserHandle,
@@ -2434,6 +2475,10 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         ChooserListAdapter adapter =
                 mChooserMultiProfilePagerAdapter.getListAdapterForUserHandle(userHandle);
         if (adapter != null) {
+            if (fixShortcutsFlashing()) {
+                adapter.setDirectTargetsEnabled(true);
+                addCallerChooserTargets(adapter);
+            }
             for (ShortcutLoader.ShortcutResultInfo resultInfo : result.getShortcutsByApp()) {
                 adapter.addServiceResults(
                         resultInfo.getAppTarget(),
@@ -2675,6 +2720,8 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     }
 
     private static class ProfileRecord {
+        public final Profile profile;
+
         /** The {@link AppPredictor} for this profile, if any. */
         @Nullable
         public final AppPredictor appPredictor;
@@ -2683,19 +2730,27 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
          */
         @Nullable
         public final ShortcutLoader shortcutLoader;
+        public final List<ChooserTarget> callerTargets;
         public long loadingStartTime;
 
         private ProfileRecord(
+                Profile profile,
                 @Nullable AppPredictor appPredictor,
-                @Nullable ShortcutLoader shortcutLoader) {
+                @Nullable ShortcutLoader shortcutLoader,
+                List<ChooserTarget> callerTargets) {
+            this.profile = profile;
             this.appPredictor = appPredictor;
             this.shortcutLoader = shortcutLoader;
+            this.callerTargets = callerTargets;
         }
 
         public void destroy() {
             if (appPredictor != null) {
                 appPredictor.destroy();
             }
+            if (shortcutLoader != null) {
+                shortcutLoader.destroy();
+            }
         }
     }
 }
diff --git a/java/src/com/android/intentresolver/ChooserHelper.kt b/java/src/com/android/intentresolver/ChooserHelper.kt
index 312911a6..c26dd77c 100644
--- a/java/src/com/android/intentresolver/ChooserHelper.kt
+++ b/java/src/com/android/intentresolver/ChooserHelper.kt
@@ -27,7 +27,9 @@ import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
+import com.android.intentresolver.Flags.unselectFinalItem
 import com.android.intentresolver.annotation.JavaInterop
+import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_PAYLOAD_SELECTION
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.ActivityResultRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.PendingSelectionCallbackRepository
 import com.android.intentresolver.data.model.ChooserRequest
@@ -39,6 +41,8 @@ import com.android.intentresolver.validation.log
 import dagger.hilt.android.scopes.ActivityScoped
 import java.util.function.Consumer
 import javax.inject.Inject
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.filter
@@ -46,6 +50,7 @@ import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.flow.onEach
+import kotlinx.coroutines.flow.stateIn
 import kotlinx.coroutines.launch
 
 private const val TAG: String = "ChooserHelper"
@@ -98,6 +103,7 @@ constructor(
     var onChooserRequestChanged: Consumer<ChooserRequest> = Consumer {}
     /** Invoked when there are a new change to payload selection */
     var onPendingSelection: Runnable = Runnable {}
+    var onHasSelections: Consumer<Boolean> = Consumer {}
 
     init {
         activity.lifecycle.addObserver(this)
@@ -144,22 +150,39 @@ constructor(
         }
 
         activity.lifecycleScope.launch {
-            val hasPendingCallbackFlow =
+            val hasPendingIntentFlow =
                 pendingSelectionCallbackRepo.pendingTargetIntent
                     .map { it != null }
                     .distinctUntilChanged()
-                    .onEach { hasPendingCallback ->
-                        if (hasPendingCallback) {
+                    .onEach { hasPendingIntent ->
+                        if (hasPendingIntent) {
                             onPendingSelection.run()
                         }
                     }
             activity.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
-                viewModel.request
-                    .combine(hasPendingCallbackFlow) { request, hasPendingCallback ->
-                        request to hasPendingCallback
+                val hasSelectionFlow =
+                    if (
+                        unselectFinalItem() &&
+                            viewModel.previewDataProvider.previewType ==
+                                CONTENT_PREVIEW_PAYLOAD_SELECTION
+                    ) {
+                        viewModel.shareouselViewModel.hasSelectedItems.stateIn(scope = this).also {
+                            flow ->
+                            launch { flow.collect { onHasSelections.accept(it) } }
+                        }
+                    } else {
+                        MutableStateFlow(true).asStateFlow()
                     }
+                val requestControlFlow =
+                    hasSelectionFlow
+                        .combine(hasPendingIntentFlow) { hasSelections, hasPendingIntent ->
+                            hasSelections && !hasPendingIntent
+                        }
+                        .distinctUntilChanged()
+                viewModel.request
+                    .combine(requestControlFlow) { request, isReady -> request to isReady }
                     // only take ChooserRequest if there are no pending callbacks
-                    .filter { !it.second }
+                    .filter { it.second }
                     .map { it.first }
                     .distinctUntilChanged(areEquivalent = { old, new -> old === new })
                     .collect { onChooserRequestChanged.accept(it) }
diff --git a/java/src/com/android/intentresolver/ChooserListAdapter.java b/java/src/com/android/intentresolver/ChooserListAdapter.java
index ff0c40d7..016eb714 100644
--- a/java/src/com/android/intentresolver/ChooserListAdapter.java
+++ b/java/src/com/android/intentresolver/ChooserListAdapter.java
@@ -111,7 +111,6 @@ public class ChooserListAdapter extends ResolverListAdapter {
     // Reserve spots for incoming direct share targets by adding placeholders
     private final TargetInfo mPlaceHolderTargetInfo;
     private final TargetDataLoader mTargetDataLoader;
-    private final boolean mUseBadgeTextViewForLabels;
     private final List<TargetInfo> mServiceTargets = new ArrayList<>();
     private final List<DisplayResolveInfo> mCallerTargets = new ArrayList<>();
 
@@ -154,6 +153,8 @@ public class ChooserListAdapter extends ResolverListAdapter {
             };
 
     private boolean mAnimateItems = true;
+    private boolean mTargetsEnabled = true;
+    private boolean mDirectTargetsEnabled = true;
 
     public ChooserListAdapter(
             Context context,
@@ -171,8 +172,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
             int maxRankedTargets,
             UserHandle initialIntentsUserSpace,
             TargetDataLoader targetDataLoader,
-            @Nullable PackageChangeCallback packageChangeCallback,
-            FeatureFlags featureFlags) {
+            @Nullable PackageChangeCallback packageChangeCallback) {
         this(
                 context,
                 payloadIntents,
@@ -191,8 +191,8 @@ public class ChooserListAdapter extends ResolverListAdapter {
                 targetDataLoader,
                 packageChangeCallback,
                 AsyncTask.SERIAL_EXECUTOR,
-                context.getMainExecutor(),
-                featureFlags);
+                context.getMainExecutor()
+        );
     }
 
     @VisibleForTesting
@@ -214,8 +214,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
             TargetDataLoader targetDataLoader,
             @Nullable PackageChangeCallback packageChangeCallback,
             Executor bgExecutor,
-            Executor mainExecutor,
-            FeatureFlags featureFlags) {
+            Executor mainExecutor) {
         // Don't send the initial intents through the shared ResolverActivity path,
         // we want to separate them into a different section.
         super(
@@ -239,7 +238,6 @@ public class ChooserListAdapter extends ResolverListAdapter {
         mPlaceHolderTargetInfo = NotSelectableTargetInfo.newPlaceHolderTargetInfo(context);
         mTargetDataLoader = targetDataLoader;
         mPackageChangeCallback = packageChangeCallback;
-        mUseBadgeTextViewForLabels = featureFlags.bespokeLabelView();
         createPlaceHolders();
         mEventLog = eventLog;
         mShortcutSelectionLogic = new ShortcutSelectionLogic(
@@ -310,6 +308,28 @@ public class ChooserListAdapter extends ResolverListAdapter {
         }
     }
 
+    /**
+     * Set the enabled state for all targets.
+     */
+    public void setTargetsEnabled(boolean isEnabled) {
+        if (mTargetsEnabled != isEnabled) {
+            mTargetsEnabled = isEnabled;
+            notifyDataSetChanged();
+        }
+    }
+
+    /**
+     * Set the enabled state for direct targets.
+     */
+    public void setDirectTargetsEnabled(boolean isEnabled) {
+        if (mDirectTargetsEnabled != isEnabled) {
+            mDirectTargetsEnabled = isEnabled;
+            if (!mServiceTargets.isEmpty() && !isDirectTargetRowEmptyState()) {
+                notifyDataSetChanged();
+            }
+        }
+    }
+
     public void setAnimateItems(boolean animateItems) {
         mAnimateItems = animateItems;
     }
@@ -345,12 +365,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
 
     @Override
     View onCreateView(ViewGroup parent) {
-        return mInflater.inflate(
-                mUseBadgeTextViewForLabels
-                        ? R.layout.chooser_grid_item
-                        : R.layout.resolve_grid_item,
-                parent,
-                false);
+        return mInflater.inflate(R.layout.chooser_grid_item, parent, false);
     }
 
     @Override
@@ -362,7 +377,8 @@ public class ChooserListAdapter extends ResolverListAdapter {
     @VisibleForTesting
     @Override
     public void onBindView(View view, TargetInfo info, int position) {
-        view.setEnabled(!isDestroyed());
+        final boolean isEnabled = !isDestroyed() && mTargetsEnabled;
+        view.setEnabled(isEnabled);
         final ViewHolder holder = (ViewHolder) view.getTag();
 
         resetViewHolder(holder);
@@ -387,6 +403,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
         }
 
         if (info.isSelectableTargetInfo()) {
+            view.setEnabled(isEnabled && mDirectTargetsEnabled);
             // direct share targets should append the application name for a better readout
             DisplayResolveInfo rInfo = info.getDisplayResolveInfo();
             CharSequence appName =
@@ -421,7 +438,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
             }
         }
 
-        holder.bindIcon(info);
+        holder.bindIcon(info, mTargetsEnabled);
         if (mAnimateItems && info.hasDisplayIcon()) {
             mAnimationTracker.animateIcon(holder.icon, info);
         }
@@ -448,9 +465,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
         holder.reset();
         holder.itemView.setBackground(holder.defaultItemViewBackground);
 
-        if (mUseBadgeTextViewForLabels) {
-            ((BadgeTextView) holder.text).setBadgeDrawable(null);
-        }
+        ((BadgeTextView) holder.text).setBadgeDrawable(null);
         holder.text.setBackground(null);
         holder.text.setPaddingRelative(0, 0, 0, 0);
     }
@@ -464,12 +479,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
     }
 
     private void bindGroupIndicator(ViewHolder holder, Drawable indicator) {
-        if (mUseBadgeTextViewForLabels) {
-            ((BadgeTextView) holder.text).setBadgeDrawable(indicator);
-        } else {
-            holder.text.setPaddingRelative(0, 0, /*end = */indicator.getIntrinsicWidth(), 0);
-            holder.text.setBackground(indicator);
-        }
+        ((BadgeTextView) holder.text).setBadgeDrawable(indicator);
     }
 
     private void bindPinnedIndicator(ViewHolder holder, Drawable indicator) {
@@ -748,7 +758,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
             Map<ChooserTarget, ShortcutInfo> directShareToShortcutInfos,
             Map<ChooserTarget, AppTarget> directShareToAppTargets) {
         // Avoid inserting any potentially late results.
-        if ((mServiceTargets.size() == 1) && mServiceTargets.get(0).isEmptyTargetInfo()) {
+        if (isDirectTargetRowEmptyState()) {
             return;
         }
         boolean isShortcutResult = targetType == TARGET_TYPE_SHORTCUTS_FROM_SHORTCUT_MANAGER
@@ -770,6 +780,22 @@ public class ChooserListAdapter extends ResolverListAdapter {
         }
     }
 
+    /**
+     * Copy direct targets from another ChooserListAdapter instance
+     */
+    public void copyDirectTargetsFrom(ChooserListAdapter adapter) {
+        if (adapter.isDirectTargetRowEmptyState()) {
+            return;
+        }
+
+        mServiceTargets.clear();
+        mServiceTargets.addAll(adapter.mServiceTargets);
+    }
+
+    private boolean isDirectTargetRowEmptyState() {
+        return (mServiceTargets.size() == 1) && mServiceTargets.get(0).isEmptyTargetInfo();
+    }
+
     /**
      * Use the scoring system along with artificial boosts to create up to 4 distinct buckets:
      * <ol>
diff --git a/java/src/com/android/intentresolver/ChooserRequestParameters.java b/java/src/com/android/intentresolver/ChooserRequestParameters.java
deleted file mode 100644
index 06f56e3b..00000000
--- a/java/src/com/android/intentresolver/ChooserRequestParameters.java
+++ /dev/null
@@ -1,504 +0,0 @@
-/*
- * Copyright (C) 2008 The Android Open Source Project
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
-package com.android.intentresolver;
-
-
-import android.content.ComponentName;
-import android.content.Intent;
-import android.content.IntentFilter;
-import android.content.IntentSender;
-import android.net.Uri;
-import android.os.Bundle;
-import android.os.Parcelable;
-import android.os.PatternMatcher;
-import android.service.chooser.ChooserAction;
-import android.service.chooser.ChooserTarget;
-import android.text.TextUtils;
-import android.util.Log;
-import android.util.Pair;
-
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
-
-import com.android.intentresolver.util.UriFilters;
-
-import com.google.common.collect.ImmutableList;
-
-import java.net.URISyntaxException;
-import java.util.ArrayList;
-import java.util.Arrays;
-import java.util.List;
-import java.util.Optional;
-import java.util.stream.Collector;
-import java.util.stream.Collectors;
-import java.util.stream.Stream;
-
-/**
- * Utility to parse and validate parameters from the client-supplied {@link Intent} that launched
- * the Sharesheet {@link ChooserActivity}. The validated parameters are stored as immutable ivars.
- *
- * TODO: field nullability in this class reflects legacy use, and typically would indicate that the
- * client's intent didn't provide the respective data. In some cases we may be able to provide
- * defaults instead of nulls -- especially for methods that return nullable lists or arrays, if the
- * client code could instead handle empty collections equally well.
- *
- * TODO: some of these fields (especially getTargetIntent() and any other getters that delegate to
- * it internally) differ from the legacy model because they're computed directly from the initial
- * Chooser intent, where in the past they've been relayed up to ResolverActivity and then retrieved
- * through methods on the base class. The base always seems to return them exactly as they were
- * provided, so this should be safe -- and clients can reasonably switch to retrieving through these
- * parameters instead. For now, the other convention is still used in some places. Ideally we'd like
- * to normalize on a single source of truth, but we'll have to clean up the delegation up to the
- * resolver (or perhaps this needs to be a subclass of some `ResolverRequestParameters` class?).
- */
-public class ChooserRequestParameters {
-    private static final String TAG = "ChooserActivity";
-
-    private static final int LAUNCH_FLAGS_FOR_SEND_ACTION =
-            Intent.FLAG_ACTIVITY_NEW_DOCUMENT | Intent.FLAG_ACTIVITY_MULTIPLE_TASK;
-    private static final int MAX_CHOOSER_ACTIONS = 5;
-
-    private final Intent mTarget;
-    private final String mReferrerPackageName;
-    private final Pair<CharSequence, Integer> mTitleSpec;
-    private final Intent mReferrerFillInIntent;
-    private final ImmutableList<ComponentName> mFilteredComponentNames;
-    private final ImmutableList<ChooserTarget> mCallerChooserTargets;
-    private final @NonNull ImmutableList<ChooserAction> mChooserActions;
-    private final ChooserAction mModifyShareAction;
-    private final boolean mRetainInOnStop;
-
-    @Nullable
-    private final ImmutableList<Intent> mAdditionalTargets;
-
-    @Nullable
-    private final Bundle mReplacementExtras;
-
-    @Nullable
-    private final ImmutableList<Intent> mInitialIntents;
-
-    @Nullable
-    private final IntentSender mChosenComponentSender;
-
-    @Nullable
-    private final IntentSender mRefinementIntentSender;
-
-    @Nullable
-    private final String mSharedText;
-
-    @Nullable
-    private final IntentFilter mTargetIntentFilter;
-
-    @Nullable
-    private final CharSequence mMetadataText;
-
-    public ChooserRequestParameters(
-            final Intent clientIntent,
-            String referrerPackageName,
-            final Uri referrer) {
-        final Intent requestedTarget = parseTargetIntentExtra(
-                clientIntent.getParcelableExtra(Intent.EXTRA_INTENT));
-        mTarget = intentWithModifiedLaunchFlags(requestedTarget);
-
-        mReferrerPackageName = referrerPackageName;
-
-        mAdditionalTargets = intentsWithModifiedLaunchFlagsFromExtraIfPresent(
-                clientIntent, Intent.EXTRA_ALTERNATE_INTENTS);
-
-        mReplacementExtras = clientIntent.getBundleExtra(Intent.EXTRA_REPLACEMENT_EXTRAS);
-
-        mTitleSpec = makeTitleSpec(
-                clientIntent.getCharSequenceExtra(Intent.EXTRA_TITLE),
-                isSendAction(mTarget.getAction()));
-
-        mInitialIntents = intentsWithModifiedLaunchFlagsFromExtraIfPresent(
-                clientIntent, Intent.EXTRA_INITIAL_INTENTS);
-
-        mReferrerFillInIntent = new Intent().putExtra(Intent.EXTRA_REFERRER, referrer);
-
-        mChosenComponentSender =
-                Optional.ofNullable(
-                        clientIntent.getParcelableExtra(Intent.EXTRA_CHOSEN_COMPONENT_INTENT_SENDER,
-                                IntentSender.class))
-                        .orElse(clientIntent.getParcelableExtra(
-                                Intent.EXTRA_CHOOSER_RESULT_INTENT_SENDER,
-                                IntentSender.class));
-
-        mRefinementIntentSender = clientIntent.getParcelableExtra(
-                Intent.EXTRA_CHOOSER_REFINEMENT_INTENT_SENDER);
-
-        ComponentName[] filteredComponents = clientIntent.getParcelableArrayExtra(
-                Intent.EXTRA_EXCLUDE_COMPONENTS, ComponentName.class);
-        mFilteredComponentNames = filteredComponents != null
-                ? ImmutableList.copyOf(filteredComponents)
-                : ImmutableList.of();
-
-        mCallerChooserTargets = parseCallerTargetsFromClientIntent(clientIntent);
-
-        mRetainInOnStop = clientIntent.getBooleanExtra(
-                ChooserActivity.EXTRA_PRIVATE_RETAIN_IN_ON_STOP, false);
-
-        mSharedText = mTarget.getStringExtra(Intent.EXTRA_TEXT);
-
-        mTargetIntentFilter = getTargetIntentFilter(mTarget);
-
-        mChooserActions = getChooserActions(clientIntent);
-        mModifyShareAction = getModifyShareAction(clientIntent);
-
-        if (android.service.chooser.Flags.enableSharesheetMetadataExtra()) {
-            mMetadataText = clientIntent.getCharSequenceExtra(Intent.EXTRA_METADATA_TEXT);
-        } else {
-            mMetadataText = null;
-        }
-    }
-
-    public Intent getTargetIntent() {
-        return mTarget;
-    }
-
-    @Nullable
-    public String getTargetAction() {
-        return getTargetIntent().getAction();
-    }
-
-    public boolean isSendActionTarget() {
-        return isSendAction(getTargetAction());
-    }
-
-    @Nullable
-    public String getTargetType() {
-        return getTargetIntent().getType();
-    }
-
-    public String getReferrerPackageName() {
-        return mReferrerPackageName;
-    }
-
-    @Nullable
-    public CharSequence getTitle() {
-        return mTitleSpec.first;
-    }
-
-    public int getDefaultTitleResource() {
-        return mTitleSpec.second;
-    }
-
-    public Intent getReferrerFillInIntent() {
-        return mReferrerFillInIntent;
-    }
-
-    public ImmutableList<ComponentName> getFilteredComponentNames() {
-        return mFilteredComponentNames;
-    }
-
-    public ImmutableList<ChooserTarget> getCallerChooserTargets() {
-        return mCallerChooserTargets;
-    }
-
-    @NonNull
-    public ImmutableList<ChooserAction> getChooserActions() {
-        return mChooserActions;
-    }
-
-    @Nullable
-    public ChooserAction getModifyShareAction() {
-        return mModifyShareAction;
-    }
-
-    /**
-     * Whether the {@link ChooserActivity#EXTRA_PRIVATE_RETAIN_IN_ON_STOP} behavior was requested.
-     */
-    public boolean shouldRetainInOnStop() {
-        return mRetainInOnStop;
-    }
-
-    /**
-     * TODO: this returns a nullable array for convenience, but if the legacy APIs can be
-     * refactored, returning {@link #mAdditionalTargets} directly is simpler and safer.
-     */
-    @Nullable
-    public Intent[] getAdditionalTargets() {
-        return (mAdditionalTargets == null) ? null : mAdditionalTargets.toArray(new Intent[0]);
-    }
-
-    @Nullable
-    public Bundle getReplacementExtras() {
-        return mReplacementExtras;
-    }
-
-    /**
-     * TODO: this returns a nullable array for convenience, but if the legacy APIs can be
-     * refactored, returning {@link #mInitialIntents} directly is simpler and safer.
-     */
-    @Nullable
-    public Intent[] getInitialIntents() {
-        return (mInitialIntents == null) ? null : mInitialIntents.toArray(new Intent[0]);
-    }
-
-    @Nullable
-    public IntentSender getChosenComponentSender() {
-        return mChosenComponentSender;
-    }
-
-    @Nullable
-    public IntentSender getRefinementIntentSender() {
-        return mRefinementIntentSender;
-    }
-
-    @Nullable
-    public String getSharedText() {
-        return mSharedText;
-    }
-
-    @Nullable
-    public IntentFilter getTargetIntentFilter() {
-        return mTargetIntentFilter;
-    }
-
-    @Nullable
-    public CharSequence getMetadataText() {
-        return mMetadataText;
-    }
-
-    private static boolean isSendAction(@Nullable String action) {
-        return (Intent.ACTION_SEND.equals(action) || Intent.ACTION_SEND_MULTIPLE.equals(action));
-    }
-
-    private static Intent parseTargetIntentExtra(@Nullable Parcelable targetParcelable) {
-        if (targetParcelable instanceof Uri) {
-            try {
-                targetParcelable = Intent.parseUri(targetParcelable.toString(),
-                        Intent.URI_INTENT_SCHEME);
-            } catch (URISyntaxException ex) {
-                throw new IllegalArgumentException("Failed to parse EXTRA_INTENT from URI", ex);
-            }
-        }
-
-        if (!(targetParcelable instanceof Intent)) {
-            throw new IllegalArgumentException(
-                    "EXTRA_INTENT is neither an Intent nor a Uri: " + targetParcelable);
-        }
-
-        return ((Intent) targetParcelable);
-    }
-
-    private static Intent intentWithModifiedLaunchFlags(Intent intent) {
-        if (isSendAction(intent.getAction())) {
-            intent.addFlags(LAUNCH_FLAGS_FOR_SEND_ACTION);
-        }
-        return intent;
-    }
-
-    /**
-     * Build a pair of values specifying the title to use from the client request. The first
-     * ({@link CharSequence}) value is the client-specified title, if there was one and their
-     * requested target <em>wasn't</em> a send action; otherwise it is null. The second value is
-     * the resource ID of a default title string; this is nonzero only if the first value is null.
-     *
-     * TODO: change the API for how these are passed up to {@link ResolverActivity#onCreate}, or
-     * create a real type (not {@link Pair}) to express the semantics described in this comment.
-     */
-    private static Pair<CharSequence, Integer> makeTitleSpec(
-            @Nullable CharSequence requestedTitle, boolean hasSendActionTarget) {
-        if (hasSendActionTarget && (requestedTitle != null)) {
-            // Do not allow the title to be changed when sharing content
-            Log.w(TAG, "Ignoring intent's EXTRA_TITLE, deprecated in P. You may wish to set a"
-                    + " preview title by using EXTRA_TITLE property of the wrapped"
-                    + " EXTRA_INTENT.");
-            requestedTitle = null;
-        }
-
-        int defaultTitleRes = (requestedTitle == null) ? R.string.chooseActivity : 0;
-
-        return Pair.create(requestedTitle, defaultTitleRes);
-    }
-
-    private static ImmutableList<ChooserTarget> parseCallerTargetsFromClientIntent(
-            Intent clientIntent) {
-        return
-                streamParcelableArrayExtra(
-                        clientIntent, Intent.EXTRA_CHOOSER_TARGETS, ChooserTarget.class, true, true)
-                .collect(toImmutableList());
-    }
-
-    @NonNull
-    private static ImmutableList<ChooserAction> getChooserActions(Intent intent) {
-        return streamParcelableArrayExtra(
-                intent,
-                Intent.EXTRA_CHOOSER_CUSTOM_ACTIONS,
-                ChooserAction.class,
-                true,
-                true)
-                .filter(UriFilters::hasValidIcon)
-                .limit(MAX_CHOOSER_ACTIONS)
-                .collect(toImmutableList());
-    }
-
-    @Nullable
-    private static ChooserAction getModifyShareAction(Intent intent) {
-        try {
-            return intent.getParcelableExtra(
-                    Intent.EXTRA_CHOOSER_MODIFY_SHARE_ACTION,
-                    ChooserAction.class);
-        } catch (Throwable t) {
-            Log.w(
-                    TAG,
-                    "Unable to retrieve Intent.EXTRA_CHOOSER_MODIFY_SHARE_ACTION argument",
-                    t);
-            return null;
-        }
-    }
-
-    private static <T> Collector<T, ?, ImmutableList<T>> toImmutableList() {
-        return Collectors.collectingAndThen(Collectors.toList(), ImmutableList::copyOf);
-    }
-
-    @Nullable
-    private static ImmutableList<Intent> intentsWithModifiedLaunchFlagsFromExtraIfPresent(
-            Intent clientIntent, String extra) {
-        Stream<Intent> intents =
-                streamParcelableArrayExtra(clientIntent, extra, Intent.class, true, false);
-        if (intents == null) {
-            return null;
-        }
-        return intents
-                .map(ChooserRequestParameters::intentWithModifiedLaunchFlags)
-                .collect(toImmutableList());
-    }
-
-    /**
-     * Make a {@link Stream} of the {@link Parcelable} objects given in the provided {@link Intent}
-     * as the optional parcelable array extra with key {@code extra}. The stream elements, if any,
-     * are all of the type specified by {@code clazz}.
-     *
-     * @param intent The intent that may contain the optional extras.
-     * @param extra The extras key to identify the parcelable array.
-     * @param clazz A class that is assignable from any elements in the result stream.
-     * @param warnOnTypeError Whether to log a warning (and ignore) if the client extra doesn't have
-     * the required type. If false, throw an {@link IllegalArgumentException} if the extra is
-     * non-null but can't be assigned to variables of type {@code T}.
-     * @param streamEmptyIfNull Whether to return an empty stream if the optional extra isn't
-     * present in the intent (or if it had the wrong type, but <em>warnOnTypeError</em> is true).
-     * If false, return null in these cases, and only return an empty stream if the intent
-     * explicitly provided an empty array for the specified extra.
-     */
-    @Nullable
-    private static <T extends Parcelable> Stream<T> streamParcelableArrayExtra(
-            final Intent intent,
-            String extra,
-            @NonNull Class<T> clazz,
-            boolean warnOnTypeError,
-            boolean streamEmptyIfNull) {
-        T[] result = null;
-
-        try {
-            result = getParcelableArrayExtraIfPresent(intent, extra, clazz);
-        } catch (IllegalArgumentException e) {
-            if (warnOnTypeError) {
-                Log.w(TAG, "Ignoring client-requested " + extra, e);
-            } else {
-                throw e;
-            }
-        }
-
-        if (result != null) {
-            return Arrays.stream(result);
-        } else if (streamEmptyIfNull) {
-            return Stream.empty();
-        } else {
-            return null;
-        }
-    }
-
-    /**
-     * If the specified {@code extra} is provided in the {@code intent}, cast it to type {@code T[]}
-     * or throw an {@code IllegalArgumentException} if the cast fails. If the {@code extra} isn't
-     * present in the {@code intent}, return null.
-     */
-    @Nullable
-    private static <T extends Parcelable> T[] getParcelableArrayExtraIfPresent(
-            final Intent intent, String extra, @NonNull Class<T> clazz) throws
-                    IllegalArgumentException {
-        if (!intent.hasExtra(extra)) {
-            return null;
-        }
-
-        T[] castResult = intent.getParcelableArrayExtra(extra, clazz);
-        if (castResult == null) {
-            Parcelable[] actualExtrasArray = intent.getParcelableArrayExtra(extra);
-            if (actualExtrasArray != null) {
-                throw new IllegalArgumentException(
-                        String.format(
-                                "%s is not of type %s[]: %s",
-                                extra,
-                                clazz.getSimpleName(),
-                                Arrays.toString(actualExtrasArray)));
-            } else if (intent.getParcelableExtra(extra) != null) {
-                throw new IllegalArgumentException(
-                        String.format(
-                                "%s is not of type %s[] (or any array type): %s",
-                                extra,
-                                clazz.getSimpleName(),
-                                intent.getParcelableExtra(extra)));
-            } else {
-                throw new IllegalArgumentException(
-                        String.format(
-                                "%s is not of type %s (or any Parcelable type): %s",
-                                extra,
-                                clazz.getSimpleName(),
-                                intent.getExtras().get(extra)));
-            }
-        }
-
-        return castResult;
-    }
-
-    private static IntentFilter getTargetIntentFilter(final Intent intent) {
-        try {
-            String dataString = intent.getDataString();
-            if (intent.getType() == null) {
-                if (!TextUtils.isEmpty(dataString)) {
-                    return new IntentFilter(intent.getAction(), dataString);
-                }
-                Log.e(TAG, "Failed to get target intent filter: intent data and type are null");
-                return null;
-            }
-            IntentFilter intentFilter = new IntentFilter(intent.getAction(), intent.getType());
-            List<Uri> contentUris = new ArrayList<>();
-            if (Intent.ACTION_SEND.equals(intent.getAction())) {
-                Uri uri = (Uri) intent.getParcelableExtra(Intent.EXTRA_STREAM);
-                if (uri != null) {
-                    contentUris.add(uri);
-                }
-            } else {
-                List<Uri> uris = intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM);
-                if (uris != null) {
-                    contentUris.addAll(uris);
-                }
-            }
-            for (Uri uri : contentUris) {
-                intentFilter.addDataScheme(uri.getScheme());
-                intentFilter.addDataAuthority(uri.getAuthority(), null);
-                intentFilter.addDataPath(uri.getPath(), PatternMatcher.PATTERN_LITERAL);
-            }
-            return intentFilter;
-        } catch (Exception e) {
-            Log.e(TAG, "Failed to get target intent filter", e);
-            return null;
-        }
-    }
-}
diff --git a/java/src/com/android/intentresolver/ResolverListAdapter.java b/java/src/com/android/intentresolver/ResolverListAdapter.java
index 5fd37d43..fc5514b6 100644
--- a/java/src/com/android/intentresolver/ResolverListAdapter.java
+++ b/java/src/com/android/intentresolver/ResolverListAdapter.java
@@ -16,14 +16,15 @@
 
 package com.android.intentresolver;
 
+import static com.android.intentresolver.Flags.unselectFinalItem;
+import static com.android.intentresolver.util.graphics.SuspendedMatrixColorFilter.getSuspendedColorMatrix;
+
 import android.content.Context;
 import android.content.Intent;
 import android.content.pm.ActivityInfo;
 import android.content.pm.LabeledIntent;
 import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
-import android.graphics.ColorMatrix;
-import android.graphics.ColorMatrixColorFilter;
 import android.graphics.drawable.Drawable;
 import android.os.AsyncTask;
 import android.os.RemoteException;
@@ -63,9 +64,6 @@ import java.util.concurrent.atomic.AtomicBoolean;
 public class ResolverListAdapter extends BaseAdapter {
     private static final String TAG = "ResolverListAdapter";
 
-    @Nullable  // TODO: other model for lazy computation? Or just precompute?
-    private static ColorMatrixColorFilter sSuspendedMatrixColorFilter;
-
     protected final Context mContext;
     protected final LayoutInflater mInflater;
     protected final ResolverListCommunicator mResolverListCommunicator;
@@ -797,29 +795,6 @@ public class ResolverListAdapter extends BaseAdapter {
         return mDestroyed.get();
     }
 
-    private static ColorMatrixColorFilter getSuspendedColorMatrix() {
-        if (sSuspendedMatrixColorFilter == null) {
-
-            int grayValue = 127;
-            float scale = 0.5f; // half bright
-
-            ColorMatrix tempBrightnessMatrix = new ColorMatrix();
-            float[] mat = tempBrightnessMatrix.getArray();
-            mat[0] = scale;
-            mat[6] = scale;
-            mat[12] = scale;
-            mat[4] = grayValue;
-            mat[9] = grayValue;
-            mat[14] = grayValue;
-
-            ColorMatrix matrix = new ColorMatrix();
-            matrix.setSaturation(0.0f);
-            matrix.preConcat(tempBrightnessMatrix);
-            sSuspendedMatrixColorFilter = new ColorMatrixColorFilter(matrix);
-        }
-        return sSuspendedMatrixColorFilter;
-    }
-
     protected final Drawable loadIconPlaceholder() {
         return mContext.getDrawable(R.drawable.resolver_icon_placeholder);
     }
@@ -999,13 +974,26 @@ public class ResolverListAdapter extends BaseAdapter {
         /**
          * Bind view holder to a TargetInfo.
          */
-        public void bindIcon(TargetInfo info) {
+        public final void bindIcon(TargetInfo info) {
+            bindIcon(info, true);
+        }
+
+        /**
+         * Bind view holder to a TargetInfo.
+         */
+        public void bindIcon(TargetInfo info, boolean isEnabled) {
             Drawable displayIcon = info.getDisplayIconHolder().getDisplayIcon();
             icon.setImageDrawable(displayIcon);
-            if (info.isSuspended()) {
+            if (info.isSuspended() || !isEnabled) {
                 icon.setColorFilter(getSuspendedColorMatrix());
             } else {
                 icon.setColorFilter(null);
+                if (unselectFinalItem() && displayIcon != null) {
+                    // For some reason, ImageView.setColorFilter() not always propagate the call
+                    // to the drawable and the icon remains grayscale when rebound; reset the filter
+                    // explicitly.
+                    displayIcon.setColorFilter(null);
+                }
             }
         }
     }
diff --git a/java/src/com/android/intentresolver/contentpreview/BasePreviewViewModel.kt b/java/src/com/android/intentresolver/contentpreview/BasePreviewViewModel.kt
deleted file mode 100644
index dc36e584..00000000
--- a/java/src/com/android/intentresolver/contentpreview/BasePreviewViewModel.kt
+++ /dev/null
@@ -1,35 +0,0 @@
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
-package com.android.intentresolver.contentpreview
-
-import android.content.Intent
-import android.net.Uri
-import androidx.annotation.MainThread
-import androidx.lifecycle.ViewModel
-
-/** A contract for the preview view model. Added for testing. */
-abstract class BasePreviewViewModel : ViewModel() {
-    @get:MainThread abstract val previewDataProvider: PreviewDataProvider
-    @get:MainThread abstract val imageLoader: ImageLoader
-
-    @MainThread
-    abstract fun init(
-        targetIntent: Intent,
-        additionalContentUri: Uri?,
-        isPayloadTogglingEnabled: Boolean,
-    )
-}
diff --git a/java/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoader.kt b/java/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoader.kt
index 2e2aa938..847fcc82 100644
--- a/java/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoader.kt
+++ b/java/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoader.kt
@@ -19,10 +19,10 @@ package com.android.intentresolver.contentpreview
 import android.graphics.Bitmap
 import android.net.Uri
 import android.util.Log
+import android.util.Size
 import androidx.core.util.lruCache
 import com.android.intentresolver.inject.Background
 import com.android.intentresolver.inject.ViewModelOwned
-import java.util.function.Consumer
 import javax.inject.Inject
 import javax.inject.Qualifier
 import kotlinx.coroutines.CoroutineDispatcher
@@ -31,7 +31,6 @@ import kotlinx.coroutines.Deferred
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.async
 import kotlinx.coroutines.ensureActive
-import kotlinx.coroutines.launch
 import kotlinx.coroutines.sync.Semaphore
 import kotlinx.coroutines.sync.withPermit
 import kotlinx.coroutines.withContext
@@ -74,15 +73,11 @@ constructor(
             }
         )
 
-    override fun loadImage(callerScope: CoroutineScope, uri: Uri, callback: Consumer<Bitmap?>) {
-        callerScope.launch { callback.accept(loadCachedImage(uri)) }
+    override fun prePopulate(uriSizePairs: List<Pair<Uri, Size>>) {
+        uriSizePairs.take(cache.maxSize()).map { cache[it.first] }
     }
 
-    override fun prePopulate(uris: List<Uri>) {
-        uris.take(cache.maxSize()).map { cache[it] }
-    }
-
-    override suspend fun invoke(uri: Uri, caching: Boolean): Bitmap? {
+    override suspend fun invoke(uri: Uri, size: Size, caching: Boolean): Bitmap? {
         return if (caching) {
             loadCachedImage(uri)
         } else {
@@ -92,7 +87,7 @@ constructor(
 
     private suspend fun loadUncachedImage(uri: Uri): Bitmap? =
         withContext(bgDispatcher) {
-            runCatching { semaphore.withPermit { thumbnailLoader.invoke(uri) } }
+            runCatching { semaphore.withPermit { thumbnailLoader.loadThumbnail(uri) } }
                 .onFailure {
                     ensureActive()
                     Log.d(TAG, "Failed to load preview for $uri", it)
diff --git a/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
index 4b955c49..1128ec5d 100644
--- a/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
@@ -22,7 +22,6 @@ import static com.android.intentresolver.contentpreview.ContentPreviewType.CONTE
 import static com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_TEXT;
 
 import android.content.ClipData;
-import android.content.Intent;
 import android.content.res.Resources;
 import android.net.Uri;
 import android.text.TextUtils;
@@ -34,6 +33,7 @@ import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 
 import com.android.intentresolver.ContentTypeHint;
+import com.android.intentresolver.data.model.ChooserRequest;
 import com.android.intentresolver.widget.ActionRow;
 import com.android.intentresolver.widget.ImagePreviewView.TransitionElementStatusCallback;
 
@@ -102,7 +102,7 @@ public final class ChooserContentPreviewUi {
     public ChooserContentPreviewUi(
             CoroutineScope scope,
             PreviewDataProvider previewData,
-            Intent targetIntent,
+            ChooserRequest chooserRequest,
             ImageLoader imageLoader,
             ActionFactory actionFactory,
             Supplier</*@Nullable*/ActionRow.Action> modifyShareActionFactory,
@@ -117,7 +117,7 @@ public final class ChooserContentPreviewUi {
         mModifyShareActionFactory = modifyShareActionFactory;
         mContentPreviewUi = createContentPreview(
                 previewData,
-                targetIntent,
+                chooserRequest,
                 DefaultMimeTypeClassifier.INSTANCE,
                 imageLoader,
                 actionFactory,
@@ -133,7 +133,7 @@ public final class ChooserContentPreviewUi {
 
     private ContentPreviewUi createContentPreview(
             PreviewDataProvider previewData,
-            Intent targetIntent,
+            ChooserRequest chooserRequest,
             MimeTypeClassifier typeClassifier,
             ImageLoader imageLoader,
             ActionFactory actionFactory,
@@ -146,7 +146,9 @@ public final class ChooserContentPreviewUi {
         if (previewType == CONTENT_PREVIEW_TEXT) {
             return createTextPreview(
                     mScope,
-                    targetIntent,
+                    chooserRequest.getTargetIntent().getClipData(),
+                    chooserRequest.getSharedText(),
+                    chooserRequest.getSharedTextTitle(),
                     actionFactory,
                     imageLoader,
                     headlineGenerator,
@@ -174,15 +176,14 @@ public final class ChooserContentPreviewUi {
 
         boolean isSingleImageShare = previewData.getUriCount() == 1
                 && typeClassifier.isImageType(previewData.getFirstFileInfo().getMimeType());
-        CharSequence text = targetIntent.getCharSequenceExtra(Intent.EXTRA_TEXT);
-        if (!TextUtils.isEmpty(text)) {
+        if (!TextUtils.isEmpty(chooserRequest.getSharedText())) {
             FilesPlusTextContentPreviewUi previewUi =
                     new FilesPlusTextContentPreviewUi(
                             mScope,
                             isSingleImageShare,
                             previewData.getUriCount(),
-                            targetIntent.getCharSequenceExtra(Intent.EXTRA_TEXT),
-                            targetIntent.getType(),
+                            chooserRequest.getSharedText(),
+                            chooserRequest.getTargetType(),
                             actionFactory,
                             imageLoader,
                             typeClassifier,
@@ -201,7 +202,7 @@ public final class ChooserContentPreviewUi {
         return new UnifiedContentPreviewUi(
                 mScope,
                 isSingleImageShare,
-                targetIntent.getType(),
+                chooserRequest.getTargetType(),
                 actionFactory,
                 imageLoader,
                 typeClassifier,
@@ -243,16 +244,15 @@ public final class ChooserContentPreviewUi {
 
     private static TextContentPreviewUi createTextPreview(
             CoroutineScope scope,
-            Intent targetIntent,
+            ClipData previewData,
+            @Nullable CharSequence sharingText,
+            @Nullable CharSequence previewTitle,
             ChooserContentPreviewUi.ActionFactory actionFactory,
             ImageLoader imageLoader,
             HeadlineGenerator headlineGenerator,
             ContentTypeHint contentTypeHint,
             @Nullable CharSequence metadata
     ) {
-        CharSequence sharingText = targetIntent.getCharSequenceExtra(Intent.EXTRA_TEXT);
-        CharSequence previewTitle = targetIntent.getCharSequenceExtra(Intent.EXTRA_TITLE);
-        ClipData previewData = targetIntent.getClipData();
         Uri previewThumbnail = null;
         if (previewData != null) {
             if (previewData.getItemCount() > 0) {
diff --git a/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java
index b50f5bc8..30161cfb 100644
--- a/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java
@@ -23,6 +23,7 @@ import android.content.res.Resources;
 import android.net.Uri;
 import android.text.util.Linkify;
 import android.util.PluralsMessageFormatter;
+import android.util.Size;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
@@ -68,6 +69,7 @@ class FilesPlusTextContentPreviewUi extends ContentPreviewUi {
     private Uri mFirstFilePreviewUri;
     private boolean mAllImages;
     private boolean mAllVideos;
+    private int mPreviewSize;
     // TODO(b/285309527): make this a flag
     private static final boolean SHOW_TOGGLE_CHECKMARK = false;
 
@@ -109,6 +111,7 @@ class FilesPlusTextContentPreviewUi extends ContentPreviewUi {
             LayoutInflater layoutInflater,
             ViewGroup parent,
             View headlineViewParent) {
+        mPreviewSize = resources.getDimensionPixelSize(R.dimen.width_text_image_preview_size);
         return displayInternal(layoutInflater, parent, headlineViewParent);
     }
 
@@ -164,12 +167,12 @@ class FilesPlusTextContentPreviewUi extends ContentPreviewUi {
     private void updateUiWithMetadata(ViewGroup contentPreviewView, View headlineView) {
         prepareTextPreview(contentPreviewView, headlineView, mActionFactory);
         updateHeadline(headlineView, mFileCount, mAllImages, mAllVideos);
-
         ImageView imagePreview = mContentPreviewView.requireViewById(R.id.image_view);
         if (mIsSingleImage && mFirstFilePreviewUri != null) {
             mImageLoader.loadImage(
                     mScope,
                     mFirstFilePreviewUri,
+                    new Size(mPreviewSize, mPreviewSize),
                     bitmap -> {
                         if (bitmap == null) {
                             imagePreview.setVisibility(View.GONE);
diff --git a/java/src/com/android/intentresolver/contentpreview/HeadlineGenerator.kt b/java/src/com/android/intentresolver/contentpreview/HeadlineGenerator.kt
index 21308341..059ee083 100644
--- a/java/src/com/android/intentresolver/contentpreview/HeadlineGenerator.kt
+++ b/java/src/com/android/intentresolver/contentpreview/HeadlineGenerator.kt
@@ -36,4 +36,6 @@ interface HeadlineGenerator {
     fun getVideosHeadline(count: Int): String
 
     fun getFilesHeadline(count: Int): String
+
+    fun getNotItemsSelectedHeadline(): String
 }
diff --git a/java/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImpl.kt b/java/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImpl.kt
index e92d9bc6..822d3097 100644
--- a/java/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImpl.kt
+++ b/java/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImpl.kt
@@ -93,6 +93,9 @@ constructor(
         return getPluralString(R.string.sharing_files, count)
     }
 
+    override fun getNotItemsSelectedHeadline(): String =
+        context.getString(R.string.select_items_to_share)
+
     private fun getPluralString(@StringRes templateResource: Int, count: Int): String {
         return PluralsMessageFormatter.format(
             context.resources,
diff --git a/java/src/com/android/intentresolver/contentpreview/ImageLoader.kt b/java/src/com/android/intentresolver/contentpreview/ImageLoader.kt
index 81913a8e..ac34f552 100644
--- a/java/src/com/android/intentresolver/contentpreview/ImageLoader.kt
+++ b/java/src/com/android/intentresolver/contentpreview/ImageLoader.kt
@@ -18,28 +18,39 @@ package com.android.intentresolver.contentpreview
 
 import android.graphics.Bitmap
 import android.net.Uri
+import android.util.Size
 import java.util.function.Consumer
 import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.isActive
+import kotlinx.coroutines.launch
 
 /** A content preview image loader. */
-interface ImageLoader : suspend (Uri) -> Bitmap?, suspend (Uri, Boolean) -> Bitmap? {
+interface ImageLoader : suspend (Uri, Size) -> Bitmap?, suspend (Uri, Size, Boolean) -> Bitmap? {
     /**
      * Load preview image asynchronously; caching is allowed.
      *
      * @param uri content URI
+     * @param size target bitmap size
      * @param callback a callback that will be invoked with the loaded image or null if loading has
      *   failed.
      */
-    fun loadImage(callerScope: CoroutineScope, uri: Uri, callback: Consumer<Bitmap?>)
+    fun loadImage(callerScope: CoroutineScope, uri: Uri, size: Size, callback: Consumer<Bitmap?>) {
+        callerScope.launch {
+            val bitmap = invoke(uri, size)
+            if (isActive) {
+                callback.accept(bitmap)
+            }
+        }
+    }
 
     /** Prepopulate the image loader cache. */
-    fun prePopulate(uris: List<Uri>)
+    fun prePopulate(uriSizePairs: List<Pair<Uri, Size>>)
 
     /** Returns a bitmap for the given URI if it's already cached, otherwise null */
     fun getCachedBitmap(uri: Uri): Bitmap? = null
 
     /** Load preview image; caching is allowed. */
-    override suspend fun invoke(uri: Uri) = invoke(uri, true)
+    override suspend fun invoke(uri: Uri, size: Size) = invoke(uri, size, true)
 
     /**
      * Load preview image.
@@ -47,5 +58,5 @@ interface ImageLoader : suspend (Uri) -> Bitmap?, suspend (Uri, Boolean) -> Bitm
      * @param uri content URI
      * @param caching indicates if the loaded image could be cached.
      */
-    override suspend fun invoke(uri: Uri, caching: Boolean): Bitmap?
+    override suspend fun invoke(uri: Uri, size: Size, caching: Boolean): Bitmap?
 }
diff --git a/java/src/com/android/intentresolver/contentpreview/ImageLoaderModule.kt b/java/src/com/android/intentresolver/contentpreview/ImageLoaderModule.kt
index 7035f765..27e817db 100644
--- a/java/src/com/android/intentresolver/contentpreview/ImageLoaderModule.kt
+++ b/java/src/com/android/intentresolver/contentpreview/ImageLoaderModule.kt
@@ -17,27 +17,33 @@
 package com.android.intentresolver.contentpreview
 
 import android.content.res.Resources
+import com.android.intentresolver.Flags
 import com.android.intentresolver.R
 import com.android.intentresolver.inject.ApplicationOwned
 import dagger.Binds
 import dagger.Module
 import dagger.Provides
 import dagger.hilt.InstallIn
-import dagger.hilt.android.components.ActivityRetainedComponent
-import dagger.hilt.android.scopes.ActivityRetainedScoped
+import dagger.hilt.android.components.ViewModelComponent
+import javax.inject.Provider
 
 @Module
-@InstallIn(ActivityRetainedComponent::class)
+@InstallIn(ViewModelComponent::class)
 interface ImageLoaderModule {
-    @Binds
-    @ActivityRetainedScoped
-    fun imageLoader(previewImageLoader: ImagePreviewImageLoader): ImageLoader
-
-    @Binds
-    @ActivityRetainedScoped
-    fun thumbnailLoader(thumbnailLoader: ThumbnailLoaderImpl): ThumbnailLoader
+    @Binds fun thumbnailLoader(thumbnailLoader: ThumbnailLoaderImpl): ThumbnailLoader
 
     companion object {
+        @Provides
+        fun imageLoader(
+            imagePreviewImageLoader: Provider<ImagePreviewImageLoader>,
+            previewImageLoader: Provider<PreviewImageLoader>
+        ): ImageLoader =
+            if (Flags.previewImageLoader()) {
+                previewImageLoader.get()
+            } else {
+                imagePreviewImageLoader.get()
+            }
+
         @Provides
         @ThumbnailSize
         fun thumbnailSize(@ApplicationOwned resources: Resources): Int =
diff --git a/java/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoader.kt b/java/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoader.kt
index fab7203e..379bdb37 100644
--- a/java/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoader.kt
+++ b/java/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoader.kt
@@ -25,7 +25,6 @@ import androidx.annotation.GuardedBy
 import androidx.annotation.VisibleForTesting
 import androidx.collection.LruCache
 import com.android.intentresolver.inject.Background
-import java.util.function.Consumer
 import javax.inject.Inject
 import javax.inject.Qualifier
 import kotlinx.coroutines.CancellationException
@@ -36,7 +35,6 @@ import kotlinx.coroutines.CoroutineName
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Deferred
 import kotlinx.coroutines.SupervisorJob
-import kotlinx.coroutines.isActive
 import kotlinx.coroutines.launch
 import kotlinx.coroutines.sync.Semaphore
 
@@ -100,19 +98,11 @@ constructor(
     @GuardedBy("lock") private val cache = LruCache<Uri, RequestRecord>(cacheSize)
     @GuardedBy("lock") private val runningRequests = HashMap<Uri, RequestRecord>()
 
-    override suspend fun invoke(uri: Uri, caching: Boolean): Bitmap? = loadImageAsync(uri, caching)
+    override suspend fun invoke(uri: Uri, size: Size, caching: Boolean): Bitmap? =
+        loadImageAsync(uri, caching)
 
-    override fun loadImage(callerScope: CoroutineScope, uri: Uri, callback: Consumer<Bitmap?>) {
-        callerScope.launch {
-            val image = loadImageAsync(uri, caching = true)
-            if (isActive) {
-                callback.accept(image)
-            }
-        }
-    }
-
-    override fun prePopulate(uris: List<Uri>) {
-        uris.asSequence().take(cache.maxSize()).forEach { uri ->
+    override fun prePopulate(uriSizePairs: List<Pair<Uri, Size>>) {
+        uriSizePairs.asSequence().take(cache.maxSize()).forEach { (uri, _) ->
             scope.launch { loadImageAsync(uri, caching = true) }
         }
     }
diff --git a/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt b/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt
index 96bb8258..9b2dbebf 100644
--- a/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt
+++ b/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt
@@ -32,6 +32,7 @@ import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREV
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_IMAGE
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_PAYLOAD_SELECTION
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_TEXT
+import com.android.intentresolver.inject.ChooserServiceFlags
 import com.android.intentresolver.measurements.runTracing
 import com.android.intentresolver.util.ownedByCurrentUser
 import java.util.concurrent.atomic.AtomicInteger
@@ -76,9 +77,7 @@ constructor(
     private val targetIntent: Intent,
     private val additionalContentUri: Uri?,
     private val contentResolver: ContentInterface,
-    // TODO: replace with the ChooserServiceFlags ref when PreviewViewModel dependencies are sorted
-    // out
-    private val isPayloadTogglingEnabled: Boolean,
+    private val featureFlags: ChooserServiceFlags,
     private val typeClassifier: MimeTypeClassifier = DefaultMimeTypeClassifier,
 ) {
 
@@ -129,7 +128,7 @@ constructor(
              * IMAGE, FILE, TEXT. */
             if (!targetIntent.isSend || records.isEmpty()) {
                 CONTENT_PREVIEW_TEXT
-            } else if (isPayloadTogglingEnabled && shouldShowPayloadSelection()) {
+            } else if (featureFlags.chooserPayloadToggling() && shouldShowPayloadSelection()) {
                 // TODO: replace with the proper flags injection
                 CONTENT_PREVIEW_PAYLOAD_SELECTION
             } else {
@@ -275,13 +274,16 @@ constructor(
         val mimeType: String? by lazy { contentResolver.getTypeSafe(uri) }
         val isImageType: Boolean
             get() = typeClassifier.isImageType(mimeType)
+
         val supportsImageType: Boolean by lazy {
             contentResolver.getStreamTypesSafe(uri).firstOrNull(typeClassifier::isImageType) != null
         }
         val supportsThumbnail: Boolean
             get() = query.supportsThumbnail
+
         val title: String
             get() = query.title
+
         val iconUri: Uri?
             get() = query.iconUri
 
@@ -326,8 +328,7 @@ constructor(
                     }
 
                 QueryResult(supportsThumbnail, title, iconUri)
-            }
-                ?: QueryResult()
+            } ?: QueryResult()
     }
 
     private class QueryResult(
diff --git a/java/src/com/android/intentresolver/contentpreview/PreviewImageLoader.kt b/java/src/com/android/intentresolver/contentpreview/PreviewImageLoader.kt
new file mode 100644
index 00000000..b10f7ef9
--- /dev/null
+++ b/java/src/com/android/intentresolver/contentpreview/PreviewImageLoader.kt
@@ -0,0 +1,197 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.intentresolver.contentpreview
+
+import android.graphics.Bitmap
+import android.net.Uri
+import android.util.Log
+import android.util.Size
+import androidx.collection.lruCache
+import com.android.intentresolver.inject.Background
+import com.android.intentresolver.inject.ViewModelOwned
+import javax.annotation.concurrent.GuardedBy
+import javax.inject.Inject
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.filter
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.firstOrNull
+import kotlinx.coroutines.flow.mapLatest
+import kotlinx.coroutines.flow.update
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.sync.Semaphore
+import kotlinx.coroutines.sync.withPermit
+
+private const val TAG = "PayloadSelImageLoader"
+
+/**
+ * Implements preview image loading for the payload selection UI. Cancels preview loading for items
+ * that has been evicted from the cache at the expense of a possible request duplication (deemed
+ * unlikely).
+ */
+class PreviewImageLoader
+@Inject
+constructor(
+    @ViewModelOwned private val scope: CoroutineScope,
+    @PreviewCacheSize private val cacheSize: Int,
+    @ThumbnailSize private val defaultPreviewSize: Int,
+    private val thumbnailLoader: ThumbnailLoader,
+    @Background private val bgDispatcher: CoroutineDispatcher,
+    @PreviewMaxConcurrency maxSimultaneousRequests: Int = 4,
+) : ImageLoader {
+
+    private val contentResolverSemaphore = Semaphore(maxSimultaneousRequests)
+
+    private val lock = Any()
+    @GuardedBy("lock") private val runningRequests = hashMapOf<Uri, RequestRecord>()
+    @GuardedBy("lock")
+    private val cache =
+        lruCache<Uri, RequestRecord>(
+            maxSize = cacheSize,
+            onEntryRemoved = { _, _, oldRec, newRec ->
+                if (oldRec !== newRec) {
+                    onRecordEvictedFromCache(oldRec)
+                }
+            }
+        )
+
+    override suspend fun invoke(uri: Uri, size: Size, caching: Boolean): Bitmap? =
+        loadImageInternal(uri, size, caching)
+
+    override fun prePopulate(uriSizePairs: List<Pair<Uri, Size>>) {
+        uriSizePairs.asSequence().take(cacheSize).forEach { uri ->
+            scope.launch { loadImageInternal(uri.first, uri.second, caching = true) }
+        }
+    }
+
+    private suspend fun loadImageInternal(uri: Uri, size: Size, caching: Boolean): Bitmap? {
+        return withRequestRecord(uri, caching) { record ->
+            val newSize = sanitize(size)
+            val newMetric = newSize.metric
+            record
+                .also {
+                    // set the requested size to the max of the new and the previous value; input
+                    // will emit if the resulted value is greater than the old one
+                    it.input.update { oldSize ->
+                        if (oldSize == null || oldSize.metric < newSize.metric) newSize else oldSize
+                    }
+                }
+                .output
+                // filter out bitmaps of a lower resolution than that we're requesting
+                .filter { it is BitmapLoadingState.Loaded && newMetric <= it.size.metric }
+                .firstOrNull()
+                ?.let { (it as BitmapLoadingState.Loaded).bitmap }
+        }
+    }
+
+    private suspend fun withRequestRecord(
+        uri: Uri,
+        caching: Boolean,
+        block: suspend (RequestRecord) -> Bitmap?
+    ): Bitmap? {
+        val record = trackRecordRunning(uri, caching)
+        return try {
+            block(record)
+        } finally {
+            untrackRecordRunning(uri, record)
+        }
+    }
+
+    private fun trackRecordRunning(uri: Uri, caching: Boolean): RequestRecord =
+        synchronized(lock) {
+            runningRequests
+                .getOrPut(uri) { cache[uri] ?: createRecord(uri) }
+                .also { record ->
+                    record.clientCount++
+                    if (caching) {
+                        cache.put(uri, record)
+                    }
+                }
+        }
+
+    private fun untrackRecordRunning(uri: Uri, record: RequestRecord) {
+        synchronized(lock) {
+            record.clientCount--
+            if (record.clientCount <= 0) {
+                runningRequests.remove(uri)
+                val result = record.output.value
+                if (cache[uri] == null) {
+                    record.loadingJob.cancel()
+                } else if (result is BitmapLoadingState.Loaded && result.bitmap == null) {
+                    cache.remove(uri)
+                }
+            }
+        }
+    }
+
+    private fun onRecordEvictedFromCache(record: RequestRecord) {
+        synchronized(lock) {
+            if (record.clientCount <= 0) {
+                record.loadingJob.cancel()
+            }
+        }
+    }
+
+    @OptIn(ExperimentalCoroutinesApi::class)
+    private fun createRecord(uri: Uri): RequestRecord {
+        // use a StateFlow with sentinel values to avoid using SharedFlow that is deemed dangerous
+        val input = MutableStateFlow<Size?>(null)
+        val output = MutableStateFlow<BitmapLoadingState>(BitmapLoadingState.Loading)
+        val job =
+            scope.launch(bgDispatcher) {
+                // the image loading pipeline: input -- a desired image size, output -- a bitmap
+                input
+                    .filterNotNull()
+                    .mapLatest { size -> BitmapLoadingState.Loaded(size, loadBitmap(uri, size)) }
+                    .collect { output.tryEmit(it) }
+            }
+        return RequestRecord(input, output, job, clientCount = 0)
+    }
+
+    private suspend fun loadBitmap(uri: Uri, size: Size): Bitmap? =
+        contentResolverSemaphore.withPermit {
+            runCatching { thumbnailLoader.loadThumbnail(uri, size) }
+                .onFailure { Log.d(TAG, "failed to load $uri preview", it) }
+                .getOrNull()
+        }
+
+    private class RequestRecord(
+        /** The image loading pipeline input: desired preview size */
+        val input: MutableStateFlow<Size?>,
+        /** The image loading pipeline output */
+        val output: MutableStateFlow<BitmapLoadingState>,
+        /** The image loading pipeline job */
+        val loadingJob: Job,
+        @GuardedBy("lock") var clientCount: Int,
+    )
+
+    private sealed interface BitmapLoadingState {
+        data object Loading : BitmapLoadingState
+
+        data class Loaded(val size: Size, val bitmap: Bitmap?) : BitmapLoadingState
+    }
+
+    private fun sanitize(size: Size?): Size =
+        size?.takeIf { it.width > 0 && it.height > 0 }
+            ?: Size(defaultPreviewSize, defaultPreviewSize)
+}
+
+private val Size.metric
+    get() = maxOf(width, height)
diff --git a/java/src/com/android/intentresolver/contentpreview/PreviewViewModel.kt b/java/src/com/android/intentresolver/contentpreview/PreviewViewModel.kt
deleted file mode 100644
index 6a729945..00000000
--- a/java/src/com/android/intentresolver/contentpreview/PreviewViewModel.kt
+++ /dev/null
@@ -1,98 +0,0 @@
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
-package com.android.intentresolver.contentpreview
-
-import android.app.Application
-import android.content.ContentResolver
-import android.content.Intent
-import android.net.Uri
-import androidx.annotation.MainThread
-import androidx.lifecycle.ViewModel
-import androidx.lifecycle.ViewModelProvider
-import androidx.lifecycle.ViewModelProvider.AndroidViewModelFactory.Companion.APPLICATION_KEY
-import androidx.lifecycle.viewModelScope
-import androidx.lifecycle.viewmodel.CreationExtras
-import com.android.intentresolver.R
-import com.android.intentresolver.inject.Background
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.plus
-
-/** A view model for the preview logic */
-class PreviewViewModel(
-    private val contentResolver: ContentResolver,
-    // TODO: inject ImageLoader instead
-    private val thumbnailSize: Int,
-    @Background private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
-) : BasePreviewViewModel() {
-    private var targetIntent: Intent? = null
-    private var additionalContentUri: Uri? = null
-    private var isPayloadTogglingEnabled = false
-
-    override val previewDataProvider by lazy {
-        val targetIntent = requireNotNull(this.targetIntent) { "Not initialized" }
-        PreviewDataProvider(
-            viewModelScope + dispatcher,
-            targetIntent,
-            additionalContentUri,
-            contentResolver,
-            isPayloadTogglingEnabled,
-        )
-    }
-
-    override val imageLoader by lazy {
-        ImagePreviewImageLoader(
-            viewModelScope + dispatcher,
-            thumbnailSize,
-            contentResolver,
-            cacheSize = 16
-        )
-    }
-
-    // TODO: make the view model injectable and inject these dependencies instead
-    @MainThread
-    override fun init(
-        targetIntent: Intent,
-        additionalContentUri: Uri?,
-        isPayloadTogglingEnabled: Boolean,
-    ) {
-        if (this.targetIntent != null) return
-        this.targetIntent = targetIntent
-        this.additionalContentUri = additionalContentUri
-        this.isPayloadTogglingEnabled = isPayloadTogglingEnabled
-    }
-
-    companion object {
-        val Factory: ViewModelProvider.Factory =
-            object : ViewModelProvider.Factory {
-                @Suppress("UNCHECKED_CAST")
-                override fun <T : ViewModel> create(
-                    modelClass: Class<T>,
-                    extras: CreationExtras
-                ): T {
-                    val application: Application = checkNotNull(extras[APPLICATION_KEY])
-                    return PreviewViewModel(
-                        application.contentResolver,
-                        application.resources.getDimensionPixelSize(
-                            R.dimen.chooser_preview_image_max_dimen
-                        )
-                    )
-                        as T
-                }
-            }
-    }
-}
diff --git a/java/src/com/android/intentresolver/contentpreview/ShareouselContentPreviewUi.kt b/java/src/com/android/intentresolver/contentpreview/ShareouselContentPreviewUi.kt
index 57a51239..ff52556a 100644
--- a/java/src/com/android/intentresolver/contentpreview/ShareouselContentPreviewUi.kt
+++ b/java/src/com/android/intentresolver/contentpreview/ShareouselContentPreviewUi.kt
@@ -39,7 +39,7 @@ import kotlinx.coroutines.launch
 @VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
 class ShareouselContentPreviewUi : ContentPreviewUi() {
 
-    override fun getType(): Int = ContentPreviewType.CONTENT_PREVIEW_IMAGE
+    override fun getType(): Int = ContentPreviewType.CONTENT_PREVIEW_PAYLOAD_SELECTION
 
     override fun display(
         resources: Resources,
diff --git a/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
index ae7ddcd9..b12eb8cf 100644
--- a/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
@@ -22,6 +22,7 @@ import android.content.res.Resources;
 import android.net.Uri;
 import android.text.SpannableStringBuilder;
 import android.text.TextUtils;
+import android.util.Size;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
@@ -50,6 +51,7 @@ class TextContentPreviewUi extends ContentPreviewUi {
     private final ChooserContentPreviewUi.ActionFactory mActionFactory;
     private final HeadlineGenerator mHeadlineGenerator;
     private final ContentTypeHint mContentTypeHint;
+    private int mPreviewSize;
 
     TextContentPreviewUi(
             CoroutineScope scope,
@@ -83,6 +85,7 @@ class TextContentPreviewUi extends ContentPreviewUi {
             LayoutInflater layoutInflater,
             ViewGroup parent,
             View headlineViewParent) {
+        mPreviewSize = resources.getDimensionPixelSize(R.dimen.width_text_image_preview_size);
         return displayInternal(layoutInflater, parent, headlineViewParent);
     }
 
@@ -119,7 +122,7 @@ class TextContentPreviewUi extends ContentPreviewUi {
             previewTitleView.setText(mPreviewTitle);
         }
 
-        ImageView previewThumbnailView = contentPreviewLayout.findViewById(
+        final ImageView previewThumbnailView = contentPreviewLayout.requireViewById(
                 com.android.internal.R.id.content_preview_thumbnail);
         if (!isOwnedByCurrentUser(mPreviewThumbnail)) {
             previewThumbnailView.setVisibility(View.GONE);
@@ -127,9 +130,9 @@ class TextContentPreviewUi extends ContentPreviewUi {
             mImageLoader.loadImage(
                     mScope,
                     mPreviewThumbnail,
+                    new Size(mPreviewSize, mPreviewSize),
                     (bitmap) -> updateViewWithImage(
-                            contentPreviewLayout.findViewById(
-                                    com.android.internal.R.id.content_preview_thumbnail),
+                            previewThumbnailView,
                             bitmap));
         }
 
diff --git a/java/src/com/android/intentresolver/contentpreview/ThumbnailLoader.kt b/java/src/com/android/intentresolver/contentpreview/ThumbnailLoader.kt
index 9f1d50da..e8afa480 100644
--- a/java/src/com/android/intentresolver/contentpreview/ThumbnailLoader.kt
+++ b/java/src/com/android/intentresolver/contentpreview/ThumbnailLoader.kt
@@ -20,10 +20,25 @@ import android.content.ContentResolver
 import android.graphics.Bitmap
 import android.net.Uri
 import android.util.Size
+import com.android.intentresolver.util.withCancellationSignal
 import javax.inject.Inject
 
 /** Interface for objects that can attempt load a [Bitmap] from a [Uri]. */
-interface ThumbnailLoader : suspend (Uri) -> Bitmap?
+interface ThumbnailLoader {
+    /**
+     * Loads a thumbnail for the given [uri].
+     *
+     * The size of the thumbnail is determined by the implementation.
+     */
+    suspend fun loadThumbnail(uri: Uri): Bitmap?
+
+    /**
+     * Loads a thumbnail for the given [uri] and [size].
+     *
+     * The [size] is the size of the thumbnail in pixels.
+     */
+    suspend fun loadThumbnail(uri: Uri, size: Size): Bitmap?
+}
 
 /** Default implementation of [ThumbnailLoader]. */
 class ThumbnailLoaderImpl
@@ -35,6 +50,11 @@ constructor(
 
     private val size = Size(thumbnailSize, thumbnailSize)
 
-    override suspend fun invoke(uri: Uri): Bitmap =
-        contentResolver.loadThumbnail(uri, size, /* signal = */ null)
+    override suspend fun loadThumbnail(uri: Uri): Bitmap =
+        contentResolver.loadThumbnail(uri, size, /* signal= */ null)
+
+    override suspend fun loadThumbnail(uri: Uri, size: Size): Bitmap =
+        withCancellationSignal { signal ->
+            contentResolver.loadThumbnail(uri, size, signal)
+        }
 }
diff --git a/java/src/com/android/intentresolver/contentpreview/UnifiedContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/UnifiedContentPreviewUi.java
index 88311016..7de988c4 100644
--- a/java/src/com/android/intentresolver/contentpreview/UnifiedContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/UnifiedContentPreviewUi.java
@@ -20,6 +20,7 @@ import static com.android.intentresolver.contentpreview.ContentPreviewType.CONTE
 
 import android.content.res.Resources;
 import android.util.Log;
+import android.util.Size;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
@@ -31,6 +32,8 @@ import com.android.intentresolver.widget.ActionRow;
 import com.android.intentresolver.widget.ImagePreviewView.TransitionElementStatusCallback;
 import com.android.intentresolver.widget.ScrollableImagePreviewView;
 
+import kotlin.Pair;
+
 import kotlinx.coroutines.CoroutineScope;
 import kotlinx.coroutines.flow.Flow;
 
@@ -55,6 +58,7 @@ class UnifiedContentPreviewUi extends ContentPreviewUi {
     @Nullable
     private ViewGroup mContentPreviewView;
     private View mHeadlineView;
+    private int mPreviewSize;
 
     UnifiedContentPreviewUi(
             CoroutineScope scope,
@@ -93,14 +97,18 @@ class UnifiedContentPreviewUi extends ContentPreviewUi {
             LayoutInflater layoutInflater,
             ViewGroup parent,
             View headlineViewParent) {
+        mPreviewSize = resources.getDimensionPixelSize(R.dimen.chooser_preview_image_max_dimen);
         return displayInternal(layoutInflater, parent, headlineViewParent);
     }
 
     private void setFiles(List<FileInfo> files) {
-        mImageLoader.prePopulate(files.stream()
-                .map(FileInfo::getPreviewUri)
-                .filter(Objects::nonNull)
-                .toList());
+        Size previewSize = new Size(mPreviewSize, mPreviewSize);
+        mImageLoader.prePopulate(
+                files.stream()
+                        .map(FileInfo::getPreviewUri)
+                        .filter(Objects::nonNull)
+                        .map((uri -> new Pair<>(uri, previewSize)))
+                        .toList());
         mFiles = files;
         if (mContentPreviewView != null) {
             updatePreviewWithFiles(mContentPreviewView, mHeadlineView, files);
@@ -121,6 +129,7 @@ class UnifiedContentPreviewUi extends ContentPreviewUi {
 
         ScrollableImagePreviewView imagePreview =
                 mContentPreviewView.requireViewById(R.id.scrollable_image_preview);
+        imagePreview.setPreviewHeight(mPreviewSize);
         imagePreview.setImageLoader(mImageLoader);
         imagePreview.setOnNoPreviewCallback(() -> imagePreview.setVisibility(View.GONE));
         imagePreview.setTransitionElementStatusCallback(mTransitionElementStatusCallback);
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/data/repository/PreviewSelectionsRepository.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/data/repository/PreviewSelectionsRepository.kt
index 81c56d1e..0688ce02 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/data/repository/PreviewSelectionsRepository.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/data/repository/PreviewSelectionsRepository.kt
@@ -18,12 +18,12 @@ package com.android.intentresolver.contentpreview.payloadtoggle.data.repository
 
 import android.net.Uri
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
-import dagger.hilt.android.scopes.ViewModelScoped
+import dagger.hilt.android.scopes.ActivityRetainedScoped
 import javax.inject.Inject
 import kotlinx.coroutines.flow.MutableStateFlow
 
 /** Stores set of selected previews. */
-@ViewModelScoped
+@ActivityRetainedScoped
 class PreviewSelectionsRepository @Inject constructor() {
     val selections = MutableStateFlow(emptyMap<Uri, PreviewModel>())
 }
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/PayloadToggleCursorResolver.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/PayloadToggleCursorResolver.kt
index 148310e6..2b14cdea 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/PayloadToggleCursorResolver.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/PayloadToggleCursorResolver.kt
@@ -20,6 +20,8 @@ import android.content.ContentInterface
 import android.content.Intent
 import android.database.Cursor
 import android.net.Uri
+import android.provider.MediaStore.MediaColumns.HEIGHT
+import android.provider.MediaStore.MediaColumns.WIDTH
 import android.service.chooser.AdditionalContentContract.Columns.URI
 import androidx.core.os.bundleOf
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.CursorRow
@@ -48,8 +50,7 @@ constructor(
         runCatching {
                 contentResolver.query(
                     cursorUri,
-                    // TODO: uncomment to start using that data
-                    arrayOf(URI /*, WIDTH, HEIGHT*/),
+                    arrayOf(URI, WIDTH, HEIGHT),
                     bundleOf(Intent.EXTRA_INTENT to chooserIntent),
                     signal,
                 )
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractor.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractor.kt
index a475263c..7d658209 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractor.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractor.kt
@@ -20,6 +20,7 @@ package com.android.intentresolver.contentpreview.payloadtoggle.domain.interacto
 
 import android.net.Uri
 import android.service.chooser.AdditionalContentContract.CursorExtraKeys.POSITION
+import android.util.Log
 import com.android.intentresolver.contentpreview.UriMetadataReader
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.CursorRow
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.LoadDirection
@@ -51,6 +52,8 @@ import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.mapLatest
 
+private const val TAG = "CursorPreviewsIntr"
+
 /** Queries data from a remote cursor, and caches it locally for presentation in Shareousel. */
 class CursorPreviewsInteractor
 @Inject
@@ -273,8 +276,7 @@ constructor(
         pagedCursor
             .getPageRows(pageNum) // TODO: what do we do if the load fails?
             ?.filter { it.uri !in state.merged }
-            ?.toPage(this, unclaimedRecords)
-            ?: this
+            ?.toPage(this, unclaimedRecords) ?: this
 
     private suspend fun <M : MutablePreviewMap> Sequence<CursorRow>.toPage(
         destination: M,
@@ -288,26 +290,32 @@ constructor(
     private fun createPreviewModel(
         row: CursorRow,
         unclaimedRecords: MutableUnclaimedMap,
-    ): PreviewModel = uriMetadataReader.getMetadata(row.uri).let { metadata ->
-            val size =
-                row.previewSize
-                    ?: metadata.previewUri?.let { uriMetadataReader.readPreviewSize(it) }
-            PreviewModel(
-                uri = row.uri,
-                previewUri = metadata.previewUri,
-                mimeType = metadata.mimeType,
-                aspectRatio = size.aspectRatioOrDefault(1f),
-                order = row.position,
-            )
-        }.also { updated ->
-            if (unclaimedRecords.remove(row.uri) != null) {
-                // unclaimedRecords contains initially shared (and thus selected) items with unknown
-                // cursor position. Update selection records when any of those items is encountered
-                // in the cursor to maintain proper selection order should other items also be
-                // selected.
-                selectionInteractor.updateSelection(updated)
+    ): PreviewModel =
+        uriMetadataReader
+            .getMetadata(row.uri)
+            .let { metadata ->
+                val size =
+                    row.previewSize
+                        ?: metadata.previewUri?.let { uriMetadataReader.readPreviewSize(it) }
+                PreviewModel(
+                    uri = row.uri,
+                    previewUri = metadata.previewUri,
+                    mimeType = metadata.mimeType,
+                    aspectRatio = size.aspectRatioOrDefault(1f),
+                    order = row.position,
+                )
+            }
+            .also { updated ->
+                if (unclaimedRecords.remove(row.uri) != null) {
+                    // unclaimedRecords contains initially shared (and thus selected) items with
+                    // unknown
+                    // cursor position. Update selection records when any of those items is
+                    // encountered
+                    // in the cursor to maintain proper selection order should other items also be
+                    // selected.
+                    selectionInteractor.updateSelection(updated)
+                }
             }
-        }
 
     private fun <M : MutablePreviewMap> M.putAllUnclaimedRight(unclaimed: UnclaimedMap): M =
         putAllUnclaimedWhere(unclaimed) { it >= focusedItemIdx }
@@ -343,7 +351,28 @@ private fun <M : MutablePreviewMap> M.putAllUnclaimedWhere(
         .toMap(this)
 
 private fun PagedCursor<CursorRow?>.getPageRows(pageNum: Int): Sequence<CursorRow>? =
-    get(pageNum)?.filterNotNull()
+    runCatching { get(pageNum) }
+        .onFailure { Log.e(TAG, "Failed to read additional content cursor page #$pageNum", it) }
+        .getOrNull()
+        ?.asSafeSequence()
+        ?.filterNotNull()
+
+private fun <T> Sequence<T>.asSafeSequence(): Sequence<T> {
+    return if (this is SafeSequence) this else SafeSequence(this)
+}
+
+private class SafeSequence<T>(private val sequence: Sequence<T>) : Sequence<T> {
+    override fun iterator(): Iterator<T> =
+        sequence.iterator().let { if (it is SafeIterator) it else SafeIterator(it) }
+}
+
+private class SafeIterator<T>(private val iterator: Iterator<T>) : Iterator<T> by iterator {
+    override fun hasNext(): Boolean {
+        return runCatching { iterator.hasNext() }
+            .onFailure { Log.e(TAG, "Failed to read cursor", it) }
+            .getOrDefault(false)
+    }
+}
 
 @Qualifier @MustBeDocumented @Retention(AnnotationRetention.RUNTIME) annotation class PageSize
 
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractor.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractor.kt
index d52a71a1..8f18ebe0 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractor.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractor.kt
@@ -18,6 +18,7 @@ package com.android.intentresolver.contentpreview.payloadtoggle.domain.interacto
 
 import android.net.Uri
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
+import com.android.intentresolver.logging.EventLog
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.map
 
@@ -25,6 +26,7 @@ import kotlinx.coroutines.flow.map
 class SelectablePreviewInteractor(
     private val key: PreviewModel,
     private val selectionInteractor: SelectionInteractor,
+    private val eventLog: EventLog,
 ) {
     val uri: Uri = key.uri
 
@@ -33,6 +35,7 @@ class SelectablePreviewInteractor(
 
     /** Sets whether this preview is selected by the user. */
     fun setSelected(isSelected: Boolean) {
+        eventLog.logPayloadSelectionChanged()
         if (isSelected) {
             selectionInteractor.select(key)
         } else {
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewsInteractor.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewsInteractor.kt
index a578d0e2..d0ac8d4a 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewsInteractor.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewsInteractor.kt
@@ -19,6 +19,7 @@ package com.android.intentresolver.contentpreview.payloadtoggle.domain.interacto
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.CursorPreviewsRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewsModel
+import com.android.intentresolver.logging.EventLog
 import javax.inject.Inject
 import kotlinx.coroutines.flow.Flow
 
@@ -27,6 +28,7 @@ class SelectablePreviewsInteractor
 constructor(
     private val previewsRepo: CursorPreviewsRepository,
     private val selectionInteractor: SelectionInteractor,
+    private val eventLog: EventLog,
 ) {
     /** Keys of previews available for display in Shareousel. */
     val previews: Flow<PreviewsModel?>
@@ -36,5 +38,5 @@ constructor(
      * Returns a [SelectablePreviewInteractor] that can be used to interact with the individual
      * preview associated with [key].
      */
-    fun preview(key: PreviewModel) = SelectablePreviewInteractor(key, selectionInteractor)
+    fun preview(key: PreviewModel) = SelectablePreviewInteractor(key, selectionInteractor, eventLog)
 }
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractor.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractor.kt
index 97d9fa66..2d02e4fd 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractor.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractor.kt
@@ -17,6 +17,7 @@
 package com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor
 
 import android.net.Uri
+import com.android.intentresolver.Flags.unselectFinalItem
 import com.android.intentresolver.contentpreview.MimeTypeClassifier
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.PreviewSelectionsRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.TargetIntentModifier
@@ -60,8 +61,12 @@ constructor(
     }
 
     fun unselect(model: PreviewModel) {
-        if (selectionsRepo.selections.value.size > 1) {
-            updateChooserRequest(selectionsRepo.selections.updateAndGet { it - model.uri }.values)
+        if (selectionsRepo.selections.value.size > 1 || unselectFinalItem()) {
+            selectionsRepo.selections
+                .updateAndGet { it - model.uri }
+                .values
+                .takeIf { it.isNotEmpty() }
+                ?.let { updateChooserRequest(it) }
         }
     }
 
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractor.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractor.kt
index dd16f0c1..4fe5e8d5 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractor.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractor.kt
@@ -17,6 +17,7 @@
 package com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor
 
 import android.content.Intent
+import com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.CustomAction
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.PendingIntentSender
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.toCustomActionModel
@@ -49,6 +50,12 @@ constructor(
                     update.refinementIntentSender.getOrDefault(current.refinementIntentSender),
                 metadataText = update.metadataText.getOrDefault(current.metadataText),
                 chooserActions = update.customActions.getOrDefault(current.chooserActions),
+                filteredComponentNames =
+                    if (shareouselUpdateExcludeComponentsExtra()) {
+                        update.excludeComponents.getOrDefault(current.filteredComponentNames)
+                    } else {
+                        current.filteredComponentNames
+                    }
             )
         }
         update.customActions.onValue { actions ->
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/model/ShareouselUpdate.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/model/ShareouselUpdate.kt
index 821e88a5..77f196e6 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/model/ShareouselUpdate.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/model/ShareouselUpdate.kt
@@ -16,6 +16,7 @@
 
 package com.android.intentresolver.contentpreview.payloadtoggle.domain.model
 
+import android.content.ComponentName
 import android.content.Intent
 import android.content.IntentSender
 import android.service.chooser.ChooserAction
@@ -31,4 +32,5 @@ data class ShareouselUpdate(
     val refinementIntentSender: ValueUpdate<IntentSender?> = ValueUpdate.Absent,
     val resultIntentSender: ValueUpdate<IntentSender?> = ValueUpdate.Absent,
     val metadataText: ValueUpdate<CharSequence?> = ValueUpdate.Absent,
+    val excludeComponents: ValueUpdate<List<ComponentName>> = ValueUpdate.Absent,
 )
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallback.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallback.kt
index 1d34dc75..184cc027 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallback.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallback.kt
@@ -16,6 +16,7 @@
 
 package com.android.intentresolver.contentpreview.payloadtoggle.domain.update
 
+import android.content.ComponentName
 import android.content.ContentInterface
 import android.content.Intent
 import android.content.Intent.EXTRA_ALTERNATE_INTENTS
@@ -24,6 +25,7 @@ import android.content.Intent.EXTRA_CHOOSER_MODIFY_SHARE_ACTION
 import android.content.Intent.EXTRA_CHOOSER_REFINEMENT_INTENT_SENDER
 import android.content.Intent.EXTRA_CHOOSER_RESULT_INTENT_SENDER
 import android.content.Intent.EXTRA_CHOOSER_TARGETS
+import android.content.Intent.EXTRA_EXCLUDE_COMPONENTS
 import android.content.Intent.EXTRA_INTENT
 import android.content.Intent.EXTRA_METADATA_TEXT
 import android.content.IntentSender
@@ -32,11 +34,11 @@ import android.os.Bundle
 import android.service.chooser.AdditionalContentContract.MethodNames.ON_SELECTION_CHANGED
 import android.service.chooser.ChooserAction
 import android.service.chooser.ChooserTarget
+import com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ShareouselUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
 import com.android.intentresolver.inject.AdditionalContent
 import com.android.intentresolver.inject.ChooserIntent
-import com.android.intentresolver.inject.ChooserServiceFlags
 import com.android.intentresolver.ui.viewmodel.readAlternateIntents
 import com.android.intentresolver.ui.viewmodel.readChooserActions
 import com.android.intentresolver.validation.Invalid
@@ -70,7 +72,6 @@ constructor(
     @AdditionalContent private val uri: Uri,
     @ChooserIntent private val chooserIntent: Intent,
     private val contentResolver: ContentInterface,
-    private val flags: ChooserServiceFlags,
 ) : SelectionChangeCallback {
     private val mutex = Mutex()
 
@@ -90,7 +91,7 @@ constructor(
                 )
             }
             ?.let { bundle ->
-                return when (val result = readCallbackResponse(bundle, flags)) {
+                return when (val result = readCallbackResponse(bundle)) {
                     is Valid -> {
                         result.warnings.forEach { it.log(TAG) }
                         result.value
@@ -105,7 +106,6 @@ constructor(
 
 private fun readCallbackResponse(
     bundle: Bundle,
-    flags: ChooserServiceFlags
 ): ValidationResult<ShareouselUpdate> {
     return validateFrom(bundle::get) {
         // An error is treated as an empty collection or null as the presence of a value indicates
@@ -136,9 +136,13 @@ private fun readCallbackResponse(
                 optional(value<IntentSender>(key))
             }
         val metadataText =
-            if (flags.enableSharesheetMetadataExtra()) {
-                bundle.readValueUpdate(EXTRA_METADATA_TEXT) { key ->
-                    optional(value<CharSequence>(key))
+            bundle.readValueUpdate(EXTRA_METADATA_TEXT) { key ->
+                optional(value<CharSequence>(key))
+            }
+        val excludedComponents: ValueUpdate<List<ComponentName>> =
+            if (shareouselUpdateExcludeComponentsExtra()) {
+                bundle.readValueUpdate(EXTRA_EXCLUDE_COMPONENTS) { key ->
+                    optional(array<ComponentName>(key)) ?: emptyList()
                 }
             } else {
                 ValueUpdate.Absent
@@ -152,6 +156,7 @@ private fun readCallbackResponse(
             refinementIntentSender,
             resultIntentSender,
             metadataText,
+            excludedComponents,
         )
     }
 }
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
index c40ed266..4b87d227 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
@@ -27,6 +27,7 @@ import androidx.compose.foundation.layout.PaddingValues
 import androidx.compose.foundation.layout.Spacer
 import androidx.compose.foundation.layout.aspectRatio
 import androidx.compose.foundation.layout.fillMaxHeight
+import androidx.compose.foundation.layout.fillMaxSize
 import androidx.compose.foundation.layout.fillMaxWidth
 import androidx.compose.foundation.layout.height
 import androidx.compose.foundation.layout.padding
@@ -44,21 +45,27 @@ import androidx.compose.material3.LocalContentColor
 import androidx.compose.material3.MaterialTheme
 import androidx.compose.material3.Text
 import androidx.compose.runtime.Composable
+import androidx.compose.runtime.LaunchedEffect
 import androidx.compose.runtime.derivedStateOf
 import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableStateOf
 import androidx.compose.runtime.remember
 import androidx.compose.runtime.rememberCoroutineScope
+import androidx.compose.runtime.setValue
 import androidx.compose.ui.Modifier
 import androidx.compose.ui.draw.clip
 import androidx.compose.ui.graphics.ColorFilter
 import androidx.compose.ui.graphics.asImageBitmap
 import androidx.compose.ui.layout.ContentScale
+import androidx.compose.ui.layout.layout
 import androidx.compose.ui.res.dimensionResource
 import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.semantics.contentDescription
 import androidx.compose.ui.semantics.semantics
 import androidx.compose.ui.unit.dp
 import androidx.lifecycle.compose.collectAsStateWithLifecycle
+import com.android.intentresolver.Flags.shareouselScrollOffscreenSelections
+import com.android.intentresolver.Flags.unselectFinalItem
 import com.android.intentresolver.R
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.getOrDefault
@@ -67,6 +74,8 @@ import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.Prev
 import com.android.intentresolver.contentpreview.payloadtoggle.ui.viewmodel.ShareouselPreviewViewModel
 import com.android.intentresolver.contentpreview.payloadtoggle.ui.viewmodel.ShareouselViewModel
 import kotlin.math.abs
+import kotlin.math.min
+import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.launch
 
 @Composable
@@ -100,48 +109,158 @@ private fun PreviewCarousel(
     previews: PreviewsModel,
     viewModel: ShareouselViewModel,
 ) {
-    val centerIdx = previews.startIdx
-    val carouselState =
-        rememberLazyListState(
-            initialFirstVisibleItemIndex = centerIdx,
-            prefetchStrategy = remember { ShareouselLazyListPrefetchStrategy() }
-        )
-    // TODO: start item needs to be centered, check out ScalingLazyColumn impl or see if
-    //  HorizontalPager works for our use-case
-    LazyRow(
-        state = carouselState,
-        horizontalArrangement = Arrangement.spacedBy(4.dp),
-        contentPadding = PaddingValues(start = 16.dp, end = 16.dp),
+    var maxAspectRatio by remember { mutableStateOf(0f) }
+    var viewportHeight by remember { mutableStateOf(0) }
+    var viewportCenter by remember { mutableStateOf(0) }
+    var horizontalPadding by remember { mutableStateOf(0.dp) }
+    Box(
         modifier =
             Modifier.fillMaxWidth()
                 .height(dimensionResource(R.dimen.chooser_preview_image_height_tall))
-                .systemGestureExclusion()
+                .layout { measurable, constraints ->
+                    val placeable = measurable.measure(constraints)
+                    val (minItemWidth, maxAR) =
+                        if (placeable.height <= 0) {
+                            0f to 0f
+                        } else {
+                            val minItemWidth = (MIN_ASPECT_RATIO * placeable.height)
+                            val maxItemWidth = maxOf(0, placeable.width - 32.dp.roundToPx())
+                            val maxAR =
+                                (maxItemWidth.toFloat() / placeable.height).coerceIn(
+                                    0f,
+                                    MAX_ASPECT_RATIO
+                                )
+                            minItemWidth to maxAR
+                        }
+                    viewportCenter = placeable.width / 2
+                    maxAspectRatio = maxAR
+                    viewportHeight = placeable.height
+                    horizontalPadding = ((placeable.width - minItemWidth) / 2).toDp()
+                    layout(placeable.width, placeable.height) { placeable.place(0, 0) }
+                },
     ) {
-        itemsIndexed(previews.previewModels, key = { _, model -> model.uri }) { index, model ->
+        if (maxAspectRatio <= 0 && previews.previewModels.isNotEmpty()) {
+            // Do not compose the list until we know the viewport size
+            return@Box
+        }
+
+        var firstSelectedIndex by remember { mutableStateOf(null as Int?) }
+
+        val carouselState =
+            rememberLazyListState(
+                prefetchStrategy = remember { ShareouselLazyListPrefetchStrategy() },
+            )
 
-            // Index if this is the element in the center of the viewing area, otherwise null
-            val previewIndex by remember {
-                derivedStateOf {
-                    carouselState.layoutInfo.visibleItemsInfo
-                        .firstOrNull { it.index == index }
-                        ?.let {
-                            val viewportCenter = carouselState.layoutInfo.viewportEndOffset / 2
+        LazyRow(
+            state = carouselState,
+            horizontalArrangement = Arrangement.spacedBy(4.dp),
+            contentPadding = PaddingValues(start = horizontalPadding, end = horizontalPadding),
+            modifier = Modifier.fillMaxSize().systemGestureExclusion(),
+        ) {
+            itemsIndexed(previews.previewModels, key = { _, model -> model.uri }) { index, model ->
+                val visibleItem by remember {
+                    derivedStateOf {
+                        carouselState.layoutInfo.visibleItemsInfo.firstOrNull { it.index == index }
+                    }
+                }
+
+                // Index if this is the element in the center of the viewing area, otherwise null
+                val previewIndex by remember {
+                    derivedStateOf {
+                        visibleItem?.let {
                             val halfPreviewWidth = it.size / 2
                             val previewCenter = it.offset + halfPreviewWidth
                             val previewDistanceToViewportCenter =
                                 abs(previewCenter - viewportCenter)
-                            if (previewDistanceToViewportCenter <= halfPreviewWidth) index else null
+                            if (previewDistanceToViewportCenter <= halfPreviewWidth) {
+                                index
+                            } else {
+                                null
+                            }
+                        }
+                    }
+                }
+
+                val previewModel =
+                    viewModel.preview(model, viewportHeight, previewIndex, rememberCoroutineScope())
+                val selected by
+                    previewModel.isSelected.collectAsStateWithLifecycle(initialValue = false)
+
+                if (selected) {
+                    firstSelectedIndex = min(index, firstSelectedIndex ?: Int.MAX_VALUE)
+                }
+
+                if (shareouselScrollOffscreenSelections()) {
+                    LaunchedEffect(index, model.uri) {
+                        var current: Boolean? = null
+                        previewModel.isSelected.collect { selected ->
+                            when {
+                                // First update will always be the current state, so we just want to
+                                // record the state and do nothing else.
+                                current == null -> current = selected
+
+                                // We only want to act when the state changes
+                                current != selected -> {
+                                    current = selected
+                                    with(carouselState.layoutInfo) {
+                                        visibleItemsInfo
+                                            .firstOrNull { it.index == index }
+                                            ?.let { item ->
+                                                when {
+                                                    // Item is partially past start of viewport
+                                                    item.offset < viewportStartOffset ->
+                                                        -viewportStartOffset
+                                                    // Item is partially past end of viewport
+                                                    (item.offset + item.size) > viewportEndOffset ->
+                                                        item.size - viewportEndOffset
+                                                    // Item is fully within viewport
+                                                    else -> null
+                                                }?.let { scrollOffset ->
+                                                    carouselState.animateScrollToItem(
+                                                        index = index,
+                                                        scrollOffset = scrollOffset,
+                                                    )
+                                                }
+                                            }
+                                    }
+                                }
+                            }
                         }
+                    }
                 }
+
+                ShareouselCard(
+                    viewModel.preview(
+                        model,
+                        viewportHeight,
+                        previewIndex,
+                        rememberCoroutineScope()
+                    ),
+                    maxAspectRatio,
+                )
             }
+        }
+
+        firstSelectedIndex?.let { index ->
+            LaunchedEffect(Unit) {
+                val visibleItem =
+                    carouselState.layoutInfo.visibleItemsInfo.firstOrNull { it.index == index }
+                val center =
+                    with(carouselState.layoutInfo) {
+                        ((viewportEndOffset - viewportStartOffset) / 2) + viewportStartOffset
+                    }
 
-            ShareouselCard(viewModel.preview(model, previewIndex, rememberCoroutineScope()))
+                carouselState.scrollToItem(
+                    index = index,
+                    scrollOffset = visibleItem?.size?.div(2)?.minus(center) ?: 0,
+                )
+            }
         }
     }
 }
 
 @Composable
-private fun ShareouselCard(viewModel: ShareouselPreviewViewModel) {
+private fun ShareouselCard(viewModel: ShareouselPreviewViewModel, maxAspectRatio: Float) {
     val bitmapLoadState by viewModel.bitmapLoadState.collectAsStateWithLifecycle()
     val selected by viewModel.isSelected.collectAsStateWithLifecycle(initialValue = false)
     val borderColor = MaterialTheme.colorScheme.primary
@@ -162,8 +281,7 @@ private fun ShareouselCard(viewModel: ShareouselPreviewViewModel) {
                     onValueChange = { scope.launch { viewModel.setSelected(it) } },
                 )
     ) { state ->
-        // TODO: max ratio is actually equal to the viewport ratio
-        val aspectRatio = viewModel.aspectRatio.coerceIn(MIN_ASPECT_RATIO, MAX_ASPECT_RATIO)
+        val aspectRatio = minOf(maxAspectRatio, maxOf(MIN_ASPECT_RATIO, viewModel.aspectRatio))
         if (state is ValueUpdate.Value) {
             state.getOrDefault(null).let { bitmap ->
                 ShareouselCard(
@@ -210,30 +328,46 @@ private fun ActionCarousel(viewModel: ShareouselViewModel) {
     val actions by viewModel.actions.collectAsStateWithLifecycle(initialValue = emptyList())
     if (actions.isNotEmpty()) {
         Spacer(Modifier.height(16.dp))
-        LazyRow(
-            horizontalArrangement = Arrangement.spacedBy(4.dp),
-            modifier = Modifier.height(32.dp),
-        ) {
-            itemsIndexed(actions) { idx, actionViewModel ->
-                if (idx == 0) {
-                    Spacer(Modifier.width(dimensionResource(R.dimen.chooser_edge_margin_normal)))
-                }
-                ShareouselAction(
-                    label = actionViewModel.label,
-                    onClick = { actionViewModel.onClicked() },
-                ) {
-                    actionViewModel.icon?.let {
-                        Image(
-                            icon = it,
-                            modifier = Modifier.size(16.dp),
-                            colorFilter = ColorFilter.tint(LocalContentColor.current)
+        val visibilityFlow =
+            if (unselectFinalItem()) {
+                viewModel.hasSelectedItems
+            } else {
+                MutableStateFlow(true)
+            }
+        val visibility by visibilityFlow.collectAsStateWithLifecycle(true)
+        val height = 32.dp
+        if (visibility) {
+            LazyRow(
+                horizontalArrangement = Arrangement.spacedBy(4.dp),
+                modifier = Modifier.height(height),
+            ) {
+                itemsIndexed(actions) { idx, actionViewModel ->
+                    if (idx == 0) {
+                        Spacer(
+                            Modifier.width(dimensionResource(R.dimen.chooser_edge_margin_normal))
+                        )
+                    }
+                    ShareouselAction(
+                        label = actionViewModel.label,
+                        onClick = { actionViewModel.onClicked() },
+                    ) {
+                        actionViewModel.icon?.let {
+                            Image(
+                                icon = it,
+                                modifier = Modifier.size(16.dp),
+                                colorFilter = ColorFilter.tint(LocalContentColor.current)
+                            )
+                        }
+                    }
+                    if (idx == actions.size - 1) {
+                        Spacer(
+                            Modifier.width(dimensionResource(R.dimen.chooser_edge_margin_normal))
                         )
                     }
-                }
-                if (idx == actions.size - 1) {
-                    Spacer(Modifier.width(dimensionResource(R.dimen.chooser_edge_margin_normal)))
                 }
             }
+        } else {
+            Spacer(modifier = Modifier.height(height))
         }
     }
 }
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt
index d0b89860..ebcd58d1 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt
@@ -15,10 +15,14 @@
  */
 package com.android.intentresolver.contentpreview.payloadtoggle.ui.viewmodel
 
+import android.util.Size
+import com.android.intentresolver.Flags
+import com.android.intentresolver.Flags.unselectFinalItem
 import com.android.intentresolver.contentpreview.CachingImagePreviewImageLoader
 import com.android.intentresolver.contentpreview.HeadlineGenerator
 import com.android.intentresolver.contentpreview.ImageLoader
 import com.android.intentresolver.contentpreview.MimeTypeClassifier
+import com.android.intentresolver.contentpreview.PreviewImageLoader
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor.PayloadToggle
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.ChooserRequestInteractor
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.CustomActionsInteractor
@@ -29,14 +33,15 @@ import com.android.intentresolver.contentpreview.payloadtoggle.shared.ContentTyp
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewsModel
 import com.android.intentresolver.inject.ViewModelOwned
-import dagger.Binds
 import dagger.Module
 import dagger.Provides
 import dagger.hilt.InstallIn
 import dagger.hilt.android.components.ViewModelComponent
+import javax.inject.Provider
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.flow.stateIn
@@ -55,95 +60,123 @@ data class ShareouselViewModel(
     val previews: Flow<PreviewsModel?>,
     /** List of action chips presented underneath Shareousel. */
     val actions: Flow<List<ActionChipViewModel>>,
+    /** Indicates whether there are any selected items */
+    val hasSelectedItems: Flow<Boolean>,
     /** Creates a [ShareouselPreviewViewModel] for a [PreviewModel] present in [previews]. */
     val preview:
-        (key: PreviewModel, index: Int?, scope: CoroutineScope) -> ShareouselPreviewViewModel,
+        (
+            key: PreviewModel, previewHeight: Int, index: Int?, scope: CoroutineScope
+        ) -> ShareouselPreviewViewModel,
 )
 
 @Module
 @InstallIn(ViewModelComponent::class)
-interface ShareouselViewModelModule {
+object ShareouselViewModelModule {
 
-    @Binds @PayloadToggle fun imageLoader(imageLoader: CachingImagePreviewImageLoader): ImageLoader
+    @Provides
+    @PayloadToggle
+    fun imageLoader(
+        cachingImageLoader: Provider<CachingImagePreviewImageLoader>,
+        previewImageLoader: Provider<PreviewImageLoader>
+    ): ImageLoader =
+        if (Flags.previewImageLoader()) {
+            previewImageLoader.get()
+        } else {
+            cachingImageLoader.get()
+        }
 
-    companion object {
-        @Provides
-        fun create(
-            interactor: SelectablePreviewsInteractor,
-            @PayloadToggle imageLoader: ImageLoader,
-            actionsInteractor: CustomActionsInteractor,
-            headlineGenerator: HeadlineGenerator,
-            selectionInteractor: SelectionInteractor,
-            chooserRequestInteractor: ChooserRequestInteractor,
-            mimeTypeClassifier: MimeTypeClassifier,
-            // TODO: remove if possible
-            @ViewModelOwned scope: CoroutineScope,
-        ): ShareouselViewModel {
-            val keySet =
-                interactor.previews.stateIn(
-                    scope,
-                    SharingStarted.Eagerly,
-                    initialValue = null,
-                )
-            return ShareouselViewModel(
-                headline =
-                    selectionInteractor.aggregateContentType.zip(
-                        selectionInteractor.amountSelected
-                    ) { contentType, numItems ->
+    @Provides
+    fun create(
+        interactor: SelectablePreviewsInteractor,
+        @PayloadToggle imageLoader: ImageLoader,
+        actionsInteractor: CustomActionsInteractor,
+        headlineGenerator: HeadlineGenerator,
+        selectionInteractor: SelectionInteractor,
+        chooserRequestInteractor: ChooserRequestInteractor,
+        mimeTypeClassifier: MimeTypeClassifier,
+        // TODO: remove if possible
+        @ViewModelOwned scope: CoroutineScope,
+    ): ShareouselViewModel {
+        val keySet =
+            interactor.previews.stateIn(
+                scope,
+                SharingStarted.Eagerly,
+                initialValue = null,
+            )
+        return ShareouselViewModel(
+            headline =
+                selectionInteractor.aggregateContentType.zip(selectionInteractor.amountSelected) {
+                    contentType,
+                    numItems ->
+                    if (unselectFinalItem() && numItems == 0) {
+                        headlineGenerator.getNotItemsSelectedHeadline()
+                    } else {
                         when (contentType) {
                             ContentType.Other -> headlineGenerator.getFilesHeadline(numItems)
                             ContentType.Image -> headlineGenerator.getImagesHeadline(numItems)
                             ContentType.Video -> headlineGenerator.getVideosHeadline(numItems)
                         }
-                    },
-                metadataText = chooserRequestInteractor.metadataText,
-                previews = keySet,
-                actions =
-                    actionsInteractor.customActions.map { actions ->
-                        actions.mapIndexedNotNull { i, model ->
-                            val icon = model.icon
-                            val label = model.label
-                            if (icon == null && label.isBlank()) {
-                                null
-                            } else {
-                                ActionChipViewModel(
-                                    label = label.toString(),
-                                    icon = model.icon,
-                                    onClicked = { model.performAction(i) },
-                                )
-                            }
-                        }
-                    },
-                preview = { key, index, previewScope ->
-                    keySet.value?.maybeLoad(index)
-                    val previewInteractor = interactor.preview(key)
-                    val contentType =
-                        when {
-                            mimeTypeClassifier.isImageType(key.mimeType) -> ContentType.Image
-                            mimeTypeClassifier.isVideoType(key.mimeType) -> ContentType.Video
-                            else -> ContentType.Other
+                    }
+                },
+            metadataText = chooserRequestInteractor.metadataText,
+            previews = keySet,
+            actions =
+                actionsInteractor.customActions.map { actions ->
+                    actions.mapIndexedNotNull { i, model ->
+                        val icon = model.icon
+                        val label = model.label
+                        if (icon == null && label.isBlank()) {
+                            null
+                        } else {
+                            ActionChipViewModel(
+                                label = label.toString(),
+                                icon = model.icon,
+                                onClicked = { model.performAction(i) },
+                            )
                         }
-                    val initialBitmapValue =
-                        key.previewUri?.let {
-                            imageLoader.getCachedBitmap(it)?.let { ValueUpdate.Value(it) }
-                        } ?: ValueUpdate.Absent
-                    ShareouselPreviewViewModel(
-                        bitmapLoadState =
-                            flow {
-                                    emit(
-                                        key.previewUri?.let { ValueUpdate.Value(imageLoader(it)) }
-                                            ?: ValueUpdate.Absent
-                                    )
-                                }
-                                .stateIn(previewScope, SharingStarted.Eagerly, initialBitmapValue),
-                        contentType = contentType,
-                        isSelected = previewInteractor.isSelected,
-                        setSelected = previewInteractor::setSelected,
-                        aspectRatio = key.aspectRatio,
-                    )
+                    }
                 },
-            )
-        }
+            hasSelectedItems =
+                selectionInteractor.selections.map { it.isNotEmpty() }.distinctUntilChanged(),
+            preview = { key, previewHeight, index, previewScope ->
+                keySet.value?.maybeLoad(index)
+                val previewInteractor = interactor.preview(key)
+                val contentType =
+                    when {
+                        mimeTypeClassifier.isImageType(key.mimeType) -> ContentType.Image
+                        mimeTypeClassifier.isVideoType(key.mimeType) -> ContentType.Video
+                        else -> ContentType.Other
+                    }
+                val initialBitmapValue =
+                    key.previewUri?.let {
+                        imageLoader.getCachedBitmap(it)?.let { ValueUpdate.Value(it) }
+                    } ?: ValueUpdate.Absent
+                ShareouselPreviewViewModel(
+                    bitmapLoadState =
+                        flow {
+                                val previewWidth =
+                                    if (key.aspectRatio > 0) {
+                                            previewHeight.toFloat() / key.aspectRatio
+                                        } else {
+                                            previewHeight
+                                        }
+                                        .toInt()
+                                emit(
+                                    key.previewUri?.let {
+                                        ValueUpdate.Value(
+                                            imageLoader(it, Size(previewWidth, previewHeight))
+                                        )
+                                    } ?: ValueUpdate.Absent
+                                )
+                            }
+                            .stateIn(previewScope, SharingStarted.Eagerly, initialBitmapValue),
+                    contentType = contentType,
+                    isSelected = previewInteractor.isSelected,
+                    setSelected = previewInteractor::setSelected,
+                    aspectRatio = key.aspectRatio,
+                )
+            },
+        )
     }
 }
 
diff --git a/java/src/com/android/intentresolver/data/model/ChooserRequest.kt b/java/src/com/android/intentresolver/data/model/ChooserRequest.kt
index 045a17f6..c4aa2b98 100644
--- a/java/src/com/android/intentresolver/data/model/ChooserRequest.kt
+++ b/java/src/com/android/intentresolver/data/model/ChooserRequest.kt
@@ -156,6 +156,8 @@ data class ChooserRequest(
      * TODO: Constrain length?
      */
     val sharedText: CharSequence? = null,
+    /** Contains title to the text content to share supplied by the source app. */
+    val sharedTextTitle: CharSequence? = null,
 
     /**
      * Supplied to
diff --git a/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java b/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java
index 7cf9d2e9..1dd83566 100644
--- a/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java
+++ b/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java
@@ -150,11 +150,9 @@ public final class ChooserGridAdapter extends RecyclerView.Adapter<RecyclerView.
     public void setFooterHeight(int height) {
         if (mFooterHeight != height) {
             mFooterHeight = height;
-            if (mFeatureFlags.fixTargetListFooter()) {
-                // we always have at least one view, the footer, see getItemCount() and
-                // getFooterRowCount()
-                notifyItemChanged(getItemCount() - 1);
-            }
+            // we always have at least one view, the footer, see getItemCount() and
+            // getFooterRowCount()
+            notifyItemChanged(getItemCount() - 1);
         }
     }
 
diff --git a/java/src/com/android/intentresolver/logging/EventLog.kt b/java/src/com/android/intentresolver/logging/EventLog.kt
index 476bd4bf..b92f0732 100644
--- a/java/src/com/android/intentresolver/logging/EventLog.kt
+++ b/java/src/com/android/intentresolver/logging/EventLog.kt
@@ -47,6 +47,7 @@ interface EventLog {
     )
 
     fun logCustomActionSelected(positionPicked: Int)
+
     fun logShareTargetSelected(
         targetType: Int,
         packageName: String?,
@@ -60,15 +61,29 @@ interface EventLog {
     )
 
     fun logDirectShareTargetReceived(category: Int, latency: Int)
+
     fun logActionShareWithPreview(previewType: Int)
+
     fun logActionSelected(targetType: Int)
+
     fun logContentPreviewWarning(uri: Uri?)
+
     fun logSharesheetTriggered()
+
     fun logSharesheetAppLoadComplete()
+
     fun logSharesheetDirectLoadComplete()
+
     fun logSharesheetDirectLoadTimeout()
+
     fun logSharesheetProfileChanged()
+
     fun logSharesheetExpansionChanged(isCollapsed: Boolean)
+
     fun logSharesheetAppShareRankingTimeout()
+
     fun logSharesheetEmptyDirectShareRow()
+
+    /** Log payload selection */
+    fun logPayloadSelectionChanged()
 }
diff --git a/java/src/com/android/intentresolver/logging/EventLogImpl.java b/java/src/com/android/intentresolver/logging/EventLogImpl.java
index 39d23865..8e9543bc 100644
--- a/java/src/com/android/intentresolver/logging/EventLogImpl.java
+++ b/java/src/com/android/intentresolver/logging/EventLogImpl.java
@@ -273,6 +273,11 @@ public class EventLogImpl implements EventLog {
         log(SharesheetStandardEvent.SHARESHEET_EMPTY_DIRECT_SHARE_ROW, mInstanceId);
     }
 
+    @Override
+    public void logPayloadSelectionChanged() {
+        log(SharesheetStandardEvent.SHARESHEET_PAYLOAD_TOGGLED, mInstanceId);
+    }
+
     /**
      * Logs a UiEventReported event for a given share activity
      * @param event
@@ -402,6 +407,9 @@ public class EventLogImpl implements EventLog {
             case ContentPreviewType.CONTENT_PREVIEW_FILE:
                 return FrameworkStatsLog.SHARESHEET_STARTED__PREVIEW_TYPE__CONTENT_PREVIEW_FILE;
             case ContentPreviewType.CONTENT_PREVIEW_TEXT:
+            case ContentPreviewType.CONTENT_PREVIEW_PAYLOAD_SELECTION:
+                return FrameworkStatsLog
+                        .SHARESHEET_STARTED__PREVIEW_TYPE__CONTENT_PREVIEW_TOGGLEABLE_MEDIA;
             default:
                 return FrameworkStatsLog
                         .SHARESHEET_STARTED__PREVIEW_TYPE__CONTENT_PREVIEW_TYPE_UNKNOWN;
diff --git a/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java b/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java
index 8aee0da1..9176cd35 100644
--- a/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java
+++ b/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java
@@ -112,6 +112,15 @@ public class ChooserMultiProfilePagerAdapter extends MultiProfilePagerAdapter<
         }
     }
 
+    /**
+     * Set enabled status for all targets in all profiles.
+     */
+    public void setTargetsEnabled(boolean isEnabled) {
+        for (int i = 0, size = getItemCount(); i < size; i++) {
+            getPageAdapterForIndex(i).getListAdapter().setTargetsEnabled(isEnabled);
+        }
+    }
+
     private static ViewGroup makeProfileView(Context context) {
         LayoutInflater inflater = LayoutInflater.from(context);
         ViewGroup rootView =
diff --git a/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt b/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt
index 08230d90..828d8561 100644
--- a/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt
+++ b/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt
@@ -35,16 +35,23 @@ import androidx.annotation.MainThread
 import androidx.annotation.OpenForTesting
 import androidx.annotation.VisibleForTesting
 import androidx.annotation.WorkerThread
+import com.android.intentresolver.Flags.fixShortcutLoaderJobLeak
+import com.android.intentresolver.Flags.fixShortcutsFlashing
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.measurements.Tracer
 import com.android.intentresolver.measurements.runTracing
 import java.util.concurrent.Executor
+import java.util.concurrent.atomic.AtomicReference
 import java.util.function.Consumer
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.CoroutineStart
 import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.Job
 import kotlinx.coroutines.asExecutor
+import kotlinx.coroutines.cancel
 import kotlinx.coroutines.channels.BufferOverflow
+import kotlinx.coroutines.delay
 import kotlinx.coroutines.flow.MutableSharedFlow
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.filter
@@ -65,29 +72,35 @@ open class ShortcutLoader
 @VisibleForTesting
 constructor(
     private val context: Context,
-    private val scope: CoroutineScope,
+    parentScope: CoroutineScope,
     private val appPredictor: AppPredictorProxy?,
     private val userHandle: UserHandle,
     private val isPersonalProfile: Boolean,
     private val targetIntentFilter: IntentFilter?,
     private val dispatcher: CoroutineDispatcher,
-    private val callback: Consumer<Result>
+    private val callback: Consumer<Result>,
 ) {
+    private val scope =
+        if (fixShortcutLoaderJobLeak()) parentScope.createChildScope() else parentScope
     private val shortcutToChooserTargetConverter = ShortcutToChooserTargetConverter()
     private val userManager = context.getSystemService(Context.USER_SERVICE) as UserManager
+    private val appPredictorWatchdog = AtomicReference<Job?>(null)
     private val appPredictorCallback =
         ScopedAppTargetListCallback(scope) { onAppPredictorCallback(it) }.toAppPredictorCallback()
 
     private val appTargetSource =
         MutableSharedFlow<Array<DisplayResolveInfo>?>(
             replay = 1,
-            onBufferOverflow = BufferOverflow.DROP_OLDEST
+            onBufferOverflow = BufferOverflow.DROP_OLDEST,
         )
     private val shortcutSource =
         MutableSharedFlow<ShortcutData?>(replay = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)
     private val isDestroyed
         get() = !scope.isActive
 
+    private val id
+        get() = System.identityHashCode(this).toString(Character.MAX_RADIX)
+
     @MainThread
     constructor(
         context: Context,
@@ -95,7 +108,7 @@ constructor(
         appPredictor: AppPredictor?,
         userHandle: UserHandle,
         targetIntentFilter: IntentFilter?,
-        callback: Consumer<Result>
+        callback: Consumer<Result>,
     ) : this(
         context,
         scope,
@@ -104,7 +117,7 @@ constructor(
         userHandle == UserHandle.of(ActivityManager.getCurrentUser()),
         targetIntentFilter,
         Dispatchers.IO,
-        callback
+        callback,
     )
 
     init {
@@ -121,7 +134,7 @@ constructor(
                                     appTargets,
                                     shortcutData.shortcuts,
                                     shortcutData.isFromAppPredictor,
-                                    shortcutData.appPredictorTargets
+                                    shortcutData.appPredictorTargets,
                                 )
                             }
                         }
@@ -132,7 +145,7 @@ constructor(
             }
             .invokeOnCompletion {
                 runCatching { appPredictor?.unregisterPredictionUpdates(appPredictorCallback) }
-                Log.d(TAG, "destroyed, user: $userHandle")
+                Log.d(TAG, "[$id] destroyed, user: $userHandle")
             }
         reset()
     }
@@ -140,7 +153,7 @@ constructor(
     /** Clear application targets (see [updateAppTargets] and initiate shortcuts loading. */
     @OpenForTesting
     open fun reset() {
-        Log.d(TAG, "reset shortcut loader for user $userHandle")
+        Log.d(TAG, "[$id] reset shortcut loader for user $userHandle")
         appTargetSource.tryEmit(null)
         shortcutSource.tryEmit(null)
         scope.launch(dispatcher) { loadShortcuts() }
@@ -155,14 +168,21 @@ constructor(
         appTargetSource.tryEmit(appTargets)
     }
 
+    @OpenForTesting
+    open fun destroy() {
+        if (fixShortcutLoaderJobLeak()) {
+            scope.cancel()
+        }
+    }
+
     @WorkerThread
     private fun loadShortcuts() {
         // no need to query direct share for work profile when its locked or disabled
         if (!shouldQueryDirectShareTargets()) {
-            Log.d(TAG, "skip shortcuts loading for user $userHandle")
+            Log.d(TAG, "[$id] skip shortcuts loading for user $userHandle")
             return
         }
-        Log.d(TAG, "querying direct share targets for user $userHandle")
+        Log.d(TAG, "[$id] querying direct share targets for user $userHandle")
         queryDirectShareTargets(false)
     }
 
@@ -170,9 +190,30 @@ constructor(
     private fun queryDirectShareTargets(skipAppPredictionService: Boolean) {
         if (!skipAppPredictionService && appPredictor != null) {
             try {
-                Log.d(TAG, "query AppPredictor for user $userHandle")
+                Log.d(TAG, "[$id] query AppPredictor for user $userHandle")
+
+                val watchdogJob =
+                    if (fixShortcutsFlashing()) {
+                        scope
+                            .launch(start = CoroutineStart.LAZY) {
+                                delay(APP_PREDICTOR_RESPONSE_TIMEOUT_MS)
+                                Log.w(TAG, "AppPredictor response timeout for user: $userHandle")
+                                appPredictorCallback.onTargetsAvailable(emptyList())
+                            }
+                            .also { job ->
+                                appPredictorWatchdog.getAndSet(job)?.cancel()
+                                job.invokeOnCompletion {
+                                    appPredictorWatchdog.compareAndSet(job, null)
+                                }
+                            }
+                    } else {
+                        null
+                    }
+
                 Tracer.beginAppPredictorQueryTrace(userHandle)
                 appPredictor.requestPredictionUpdate()
+
+                watchdogJob?.start()
                 return
             } catch (e: Throwable) {
                 endAppPredictorQueryTrace(userHandle)
@@ -180,25 +221,25 @@ constructor(
                 if (isDestroyed) {
                     return
                 }
-                Log.e(TAG, "Failed to query AppPredictor for user $userHandle", e)
+                Log.e(TAG, "[$id] failed to query AppPredictor for user $userHandle", e)
             }
         }
         // Default to just querying ShortcutManager if AppPredictor not present.
         if (targetIntentFilter == null) {
-            Log.d(TAG, "skip querying ShortcutManager for $userHandle")
+            Log.d(TAG, "[$id] skip querying ShortcutManager for $userHandle")
             sendShareShortcutInfoList(
                 emptyList(),
                 isFromAppPredictor = false,
-                appPredictorTargets = null
+                appPredictorTargets = null,
             )
             return
         }
-        Log.d(TAG, "query ShortcutManager for user $userHandle")
+        Log.d(TAG, "[$id] query ShortcutManager for user $userHandle")
         val shortcuts =
             runTracing("shortcut-mngr-${userHandle.identifier}") {
                 queryShortcutManager(targetIntentFilter)
             }
-        Log.d(TAG, "receive shortcuts from ShortcutManager for user $userHandle")
+        Log.d(TAG, "[$id] receive shortcuts from ShortcutManager for user $userHandle")
         sendShareShortcutInfoList(shortcuts, false, null)
     }
 
@@ -210,14 +251,14 @@ constructor(
         val pm = context.createContextAsUser(userHandle, 0 /* flags */).packageManager
         return sm?.getShareTargets(targetIntentFilter)?.filter {
             pm.isPackageEnabled(it.targetComponent.packageName)
-        }
-            ?: emptyList()
+        } ?: emptyList()
     }
 
     @WorkerThread
     private fun onAppPredictorCallback(appPredictorTargets: List<AppTarget>) {
+        appPredictorWatchdog.get()?.cancel()
         endAppPredictorQueryTrace(userHandle)
-        Log.d(TAG, "receive app targets from AppPredictor")
+        Log.d(TAG, "[$id] receive app targets from AppPredictor")
         if (appPredictorTargets.isEmpty() && shouldQueryDirectShareTargets()) {
             // APS may be disabled, so try querying targets ourselves.
             queryDirectShareTargets(true)
@@ -247,7 +288,7 @@ constructor(
     private fun sendShareShortcutInfoList(
         shortcuts: List<ShareShortcutInfo>,
         isFromAppPredictor: Boolean,
-        appPredictorTargets: List<AppTarget>?
+        appPredictorTargets: List<AppTarget>?,
     ) {
         shortcutSource.tryEmit(ShortcutData(shortcuts, isFromAppPredictor, appPredictorTargets))
     }
@@ -256,7 +297,7 @@ constructor(
         appTargets: Array<DisplayResolveInfo>,
         shortcuts: List<ShareShortcutInfo>,
         isFromAppPredictor: Boolean,
-        appPredictorTargets: List<AppTarget>?
+        appPredictorTargets: List<AppTarget>?,
     ): Result {
         if (appPredictorTargets != null && appPredictorTargets.size != shortcuts.size) {
             throw RuntimeException(
@@ -283,7 +324,7 @@ constructor(
                     shortcuts,
                     appPredictorTargets,
                     directShareAppTargetCache,
-                    directShareShortcutInfoCache
+                    directShareShortcutInfoCache,
                 )
             val resultRecord = ShortcutResultInfo(displayResolveInfo, chooserTargets)
             resultRecords.add(resultRecord)
@@ -293,7 +334,7 @@ constructor(
             appTargets,
             resultRecords.toTypedArray(),
             directShareAppTargetCache,
-            directShareShortcutInfoCache
+            directShareShortcutInfoCache,
         )
     }
 
@@ -313,7 +354,7 @@ constructor(
     private class ShortcutData(
         val shortcuts: List<ShareShortcutInfo>,
         val isFromAppPredictor: Boolean,
-        val appPredictorTargets: List<AppTarget>?
+        val appPredictorTargets: List<AppTarget>?,
     )
 
     /** Resolved shortcuts with corresponding app targets. */
@@ -327,18 +368,23 @@ constructor(
         /** Shortcuts grouped by app target. */
         val shortcutsByApp: Array<ShortcutResultInfo>,
         val directShareAppTargetCache: Map<ChooserTarget, AppTarget>,
-        val directShareShortcutInfoCache: Map<ChooserTarget, ShortcutInfo>
+        val directShareShortcutInfoCache: Map<ChooserTarget, ShortcutInfo>,
     )
 
+    private fun endAppPredictorQueryTrace(userHandle: UserHandle) {
+        val duration = Tracer.endAppPredictorQueryTrace(userHandle)
+        Log.d(TAG, "[$id] AppPredictor query duration for user $userHandle: $duration ms")
+    }
+
     /** Shortcuts grouped by app. */
     class ShortcutResultInfo(
         val appTarget: DisplayResolveInfo,
-        val shortcuts: List<ChooserTarget?>
+        val shortcuts: List<ChooserTarget?>,
     )
 
     private class ShortcutsAppTargetsPair(
         val shortcuts: List<ShareShortcutInfo>,
-        val appTargets: List<AppTarget>?
+        val appTargets: List<AppTarget>?,
     )
 
     /** A wrapper around AppPredictor to facilitate unit-testing. */
@@ -347,7 +393,7 @@ constructor(
         /** [AppPredictor.registerPredictionUpdates] */
         open fun registerPredictionUpdates(
             callbackExecutor: Executor,
-            callback: AppPredictor.Callback
+            callback: AppPredictor.Callback,
         ) = mAppPredictor.registerPredictionUpdates(callbackExecutor, callback)
 
         /** [AppPredictor.unregisterPredictionUpdates] */
@@ -359,6 +405,7 @@ constructor(
     }
 
     companion object {
+        @VisibleForTesting const val APP_PREDICTOR_RESPONSE_TIMEOUT_MS = 2_000L
         private const val TAG = "ShortcutLoader"
 
         private fun PackageManager.isPackageEnabled(packageName: String): Boolean {
@@ -371,16 +418,19 @@ constructor(
                             packageName,
                             PackageManager.ApplicationInfoFlags.of(
                                 PackageManager.GET_META_DATA.toLong()
-                            )
+                            ),
                         )
                     appInfo.enabled && (appInfo.flags and ApplicationInfo.FLAG_SUSPENDED) == 0
                 }
                 .getOrDefault(false)
         }
 
-        private fun endAppPredictorQueryTrace(userHandle: UserHandle) {
-            val duration = Tracer.endAppPredictorQueryTrace(userHandle)
-            Log.d(TAG, "AppPredictor query duration for user $userHandle: $duration ms")
-        }
+        /**
+         * Creates a new coroutine scope and makes its job a child of the given, `this`, coroutine
+         * scope's job. This ensures that the new scope will be canceled when the parent scope is
+         * canceled (but not vice versa).
+         */
+        private fun CoroutineScope.createChildScope() =
+            CoroutineScope(coroutineContext + Job(parent = coroutineContext[Job]))
     }
 }
diff --git a/java/src/com/android/intentresolver/ui/ShareResultSender.kt b/java/src/com/android/intentresolver/ui/ShareResultSender.kt
index 7be2076e..dce477ec 100644
--- a/java/src/com/android/intentresolver/ui/ShareResultSender.kt
+++ b/java/src/com/android/intentresolver/ui/ShareResultSender.kt
@@ -47,7 +47,7 @@ private const val TAG = "ShareResultSender"
 /** Reports the result of a share to another process across binder, via an [IntentSender] */
 interface ShareResultSender {
     /** Reports user selection of an activity to launch from the provided choices. */
-    fun onComponentSelected(component: ComponentName, directShare: Boolean)
+    fun onComponentSelected(component: ComponentName, directShare: Boolean, crossProfile: Boolean)
 
     /** Reports user invocation of a built-in system action. See [ShareAction]. */
     fun onActionSelected(action: ShareAction)
@@ -88,11 +88,15 @@ class ShareResultSenderImpl(
         IntentSenderDispatcher { sender, intent -> sender.dispatchIntent(context, intent) }
     )
 
-    override fun onComponentSelected(component: ComponentName, directShare: Boolean) {
-        Log.i(TAG, "onComponentSelected: $component directShare=$directShare")
+    override fun onComponentSelected(
+        component: ComponentName,
+        directShare: Boolean,
+        crossProfile: Boolean
+    ) {
+        Log.i(TAG, "onComponentSelected: $component directShare=$directShare cross=$crossProfile")
         scope.launch {
-            val intent = createChosenComponentIntent(component, directShare)
-            intentDispatcher.dispatchIntent(resultSender, intent)
+            val intent = createChosenComponentIntent(component, directShare, crossProfile)
+            intent?.let { intentDispatcher.dispatchIntent(resultSender, it) }
         }
     }
 
@@ -112,20 +116,38 @@ class ShareResultSenderImpl(
     private suspend fun createChosenComponentIntent(
         component: ComponentName,
         direct: Boolean,
-    ): Intent {
-        // Add extra with component name for backwards compatibility.
-        val intent: Intent = Intent().putExtra(Intent.EXTRA_CHOSEN_COMPONENT, component)
-
-        // Add ChooserResult value for Android V+
+        crossProfile: Boolean,
+    ): Intent? {
         if (flags.enableChooserResult() && chooserResultSupported(callerUid)) {
-            intent.putExtra(
-                Intent.EXTRA_CHOOSER_RESULT,
-                ChooserResult(CHOOSER_RESULT_SELECTED_COMPONENT, component, direct)
-            )
+            if (crossProfile) {
+                Log.i(TAG, "Redacting package from cross-profile ${Intent.EXTRA_CHOOSER_RESULT}")
+                return Intent()
+                    .putExtra(
+                        Intent.EXTRA_CHOOSER_RESULT,
+                        ChooserResult(CHOOSER_RESULT_UNKNOWN, null, direct)
+                    )
+            } else {
+                // Add extra with component name for backwards compatibility.
+                val intent: Intent = Intent().putExtra(Intent.EXTRA_CHOSEN_COMPONENT, component)
+
+                // Add ChooserResult value for Android V+
+                intent.putExtra(
+                    Intent.EXTRA_CHOOSER_RESULT,
+                    ChooserResult(CHOOSER_RESULT_SELECTED_COMPONENT, component, direct)
+                )
+                return intent
+            }
         } else {
-            Log.i(TAG, "Not including ${Intent.EXTRA_CHOOSER_RESULT}")
+            if (crossProfile) {
+                // We can only send cross-profile results in the new ChooserResult format.
+                Log.i(TAG, "Omitting selection callback for cross-profile target")
+                return null
+            } else {
+                val intent: Intent = Intent().putExtra(Intent.EXTRA_CHOSEN_COMPONENT, component)
+                Log.i(TAG, "Not including ${Intent.EXTRA_CHOOSER_RESULT}")
+                return intent
+            }
         }
-        return intent
     }
 
     @ResultType
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt b/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
index a9b6de7e..4a194db9 100644
--- a/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
+++ b/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
@@ -18,7 +18,10 @@ package com.android.intentresolver.ui.viewmodel
 import android.content.ComponentName
 import android.content.Intent
 import android.content.Intent.EXTRA_ALTERNATE_INTENTS
+import android.content.Intent.EXTRA_CHOOSER_ADDITIONAL_CONTENT_URI
+import android.content.Intent.EXTRA_CHOOSER_CONTENT_TYPE_HINT
 import android.content.Intent.EXTRA_CHOOSER_CUSTOM_ACTIONS
+import android.content.Intent.EXTRA_CHOOSER_FOCUSED_ITEM_POSITION
 import android.content.Intent.EXTRA_CHOOSER_MODIFY_SHARE_ACTION
 import android.content.Intent.EXTRA_CHOOSER_REFINEMENT_INTENT_SENDER
 import android.content.Intent.EXTRA_CHOOSER_RESULT_INTENT_SENDER
@@ -95,8 +98,7 @@ fun readChooserRequest(
         val initialIntents =
             optional(array<Intent>(EXTRA_INITIAL_INTENTS))?.take(MAX_INITIAL_INTENTS)?.map {
                 it.maybeAddSendActionFlags()
-            }
-                ?: emptyList()
+            } ?: emptyList()
 
         val chosenComponentSender =
             optional(value<IntentSender>(EXTRA_CHOOSER_RESULT_INTENT_SENDER))
@@ -115,7 +117,8 @@ fun readChooserRequest(
         val retainInOnStop =
             optional(value<Boolean>(ChooserActivity.EXTRA_PRIVATE_RETAIN_IN_ON_STOP)) ?: false
 
-        val sharedText = optional(value<CharSequence>(EXTRA_TEXT))
+        val sharedTextTitle = targetIntent.getCharSequenceExtra(EXTRA_TITLE)
+        val sharedText = targetIntent.getCharSequenceExtra(EXTRA_TEXT)
 
         val chooserActions = readChooserActions() ?: emptyList()
 
@@ -124,29 +127,20 @@ fun readChooserRequest(
         val additionalContentUri: Uri?
         val focusedItemPos: Int
         if (isSendAction && flags.chooserPayloadToggling()) {
-            additionalContentUri = optional(value<Uri>(Intent.EXTRA_CHOOSER_ADDITIONAL_CONTENT_URI))
-            focusedItemPos = optional(value<Int>(Intent.EXTRA_CHOOSER_FOCUSED_ITEM_POSITION)) ?: 0
+            additionalContentUri = optional(value<Uri>(EXTRA_CHOOSER_ADDITIONAL_CONTENT_URI))
+            focusedItemPos = optional(value<Int>(EXTRA_CHOOSER_FOCUSED_ITEM_POSITION)) ?: 0
         } else {
             additionalContentUri = null
             focusedItemPos = 0
         }
 
         val contentTypeHint =
-            if (flags.chooserAlbumText()) {
-                when (optional(value<Int>(Intent.EXTRA_CHOOSER_CONTENT_TYPE_HINT))) {
-                    Intent.CHOOSER_CONTENT_TYPE_ALBUM -> ContentTypeHint.ALBUM
-                    else -> ContentTypeHint.NONE
-                }
-            } else {
-                ContentTypeHint.NONE
+            when (optional(value<Int>(EXTRA_CHOOSER_CONTENT_TYPE_HINT))) {
+                Intent.CHOOSER_CONTENT_TYPE_ALBUM -> ContentTypeHint.ALBUM
+                else -> ContentTypeHint.NONE
             }
 
-        val metadataText =
-            if (flags.enableSharesheetMetadataExtra()) {
-                optional(value<CharSequence>(EXTRA_METADATA_TEXT))
-            } else {
-                null
-            }
+        val metadataText = optional(value<CharSequence>(EXTRA_METADATA_TEXT))
 
         ChooserRequest(
             targetIntent = targetIntent,
@@ -171,6 +165,7 @@ fun readChooserRequest(
             chosenComponentSender = chosenComponentSender,
             refinementIntentSender = refinementIntentSender,
             sharedText = sharedText,
+            sharedTextTitle = sharedTextTitle,
             shareTargetFilter = targetIntent.toShareTargetFilter(),
             additionalContentUri = additionalContentUri,
             focusedItemPosition = focusedItemPos,
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt b/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
index c9cae3db..619e118a 100644
--- a/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
+++ b/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
@@ -15,10 +15,13 @@
  */
 package com.android.intentresolver.ui.viewmodel
 
+import android.content.ContentInterface
 import android.util.Log
 import androidx.lifecycle.SavedStateHandle
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
+import com.android.intentresolver.contentpreview.ImageLoader
+import com.android.intentresolver.contentpreview.PreviewDataProvider
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.FetchPreviewsInteractor
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.ProcessTargetIntentUpdatesInteractor
 import com.android.intentresolver.contentpreview.payloadtoggle.ui.viewmodel.ShareouselViewModel
@@ -38,6 +41,7 @@ import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.launch
+import kotlinx.coroutines.plus
 
 private const val TAG = "ChooserViewModel"
 
@@ -58,6 +62,8 @@ constructor(
      */
     val initialRequest: ValidationResult<ChooserRequest>,
     private val chooserRequestRepository: Lazy<ChooserRequestRepository>,
+    private val contentResolver: ContentInterface,
+    val imageLoader: ImageLoader,
 ) : ViewModel() {
 
     /** Parcelable-only references provided from the creating Activity */
@@ -86,6 +92,17 @@ constructor(
     val request: StateFlow<ChooserRequest>
         get() = chooserRequestRepository.get().chooserRequest.asStateFlow()
 
+    val previewDataProvider by lazy {
+        val chooserRequest = (initialRequest as Valid<ChooserRequest>).value
+        PreviewDataProvider(
+            viewModelScope + bgDispatcher,
+            chooserRequest.targetIntent,
+            chooserRequest.additionalContentUri,
+            contentResolver,
+            flags,
+        )
+    }
+
     init {
         if (initialRequest is Invalid) {
             Log.w(TAG, "initialRequest is Invalid, initialization failed")
diff --git a/java/src/com/android/intentresolver/util/graphics/SuspendedMatrixColorFilter.kt b/java/src/com/android/intentresolver/util/graphics/SuspendedMatrixColorFilter.kt
new file mode 100644
index 00000000..3e2d8e2a
--- /dev/null
+++ b/java/src/com/android/intentresolver/util/graphics/SuspendedMatrixColorFilter.kt
@@ -0,0 +1,46 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+@file:JvmName("SuspendedMatrixColorFilter")
+
+package com.android.intentresolver.util.graphics
+
+import android.graphics.ColorMatrix
+import android.graphics.ColorMatrixColorFilter
+
+val suspendedColorMatrix by lazy {
+    val grayValue = 127f
+    val scale = 0.5f // half bright
+
+    val tempBrightnessMatrix =
+        ColorMatrix().apply {
+            array.let { m ->
+                m[0] = scale
+                m[6] = scale
+                m[12] = scale
+                m[4] = grayValue
+                m[9] = grayValue
+                m[14] = grayValue
+            }
+        }
+
+    val matrix =
+        ColorMatrix().apply {
+            setSaturation(0.0f)
+            preConcat(tempBrightnessMatrix)
+        }
+    ColorMatrixColorFilter(matrix)
+}
diff --git a/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt b/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt
index 7fe16091..c706e3ee 100644
--- a/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt
+++ b/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt
@@ -22,6 +22,7 @@ import android.graphics.Rect
 import android.net.Uri
 import android.util.AttributeSet
 import android.util.PluralsMessageFormatter
+import android.util.Size
 import android.util.TypedValue
 import android.view.LayoutInflater
 import android.view.View
@@ -60,11 +61,13 @@ private const val MIN_ASPECT_RATIO_STRING = "2:5"
 private const val MAX_ASPECT_RATIO = 2.5f
 private const val MAX_ASPECT_RATIO_STRING = "5:2"
 
-private typealias CachingImageLoader = suspend (Uri, Boolean) -> Bitmap?
+private typealias CachingImageLoader = suspend (Uri, Size, Boolean) -> Bitmap?
 
 class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
     constructor(context: Context) : this(context, null)
+
     constructor(context: Context, attrs: AttributeSet?) : this(context, attrs, 0)
+
     constructor(
         context: Context,
         attrs: AttributeSet?,
@@ -121,12 +124,19 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
      * A hint about the maximum width this view can grow to, this helps to optimize preview loading.
      */
     var maxWidthHint: Int = -1
+
     private var requestedHeight: Int = 0
     private var isMeasured = false
     private var maxAspectRatio = MAX_ASPECT_RATIO
     private var maxAspectRatioString = MAX_ASPECT_RATIO_STRING
     private var outerSpacing: Int = 0
 
+    var previewHeight: Int
+        get() = previewAdapter.previewHeight
+        set(value) {
+            previewAdapter.previewHeight = value
+        }
+
     override fun onMeasure(widthSpec: Int, heightSpec: Int) {
         super.onMeasure(widthSpec, heightSpec)
         if (!isMeasured) {
@@ -198,6 +208,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
             BatchPreviewLoader(
                 previewAdapter.imageLoader ?: error("Image loader is not set"),
                 previews,
+                Size(previewHeight, previewHeight),
                 totalItemCount,
                 onUpdate = previewAdapter::addPreviews,
                 onCompletion = {
@@ -303,11 +314,19 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
         private var isLoading = false
         private val hasOtherItem
             get() = previews.size < totalItemCount
+
         val hasPreviews: Boolean
             get() = previews.isNotEmpty()
 
         var transitionStatusElementCallback: TransitionElementStatusCallback? = null
 
+        private var previewSize: Size = Size(0, 0)
+        var previewHeight: Int
+            get() = previewSize.height
+            set(value) {
+                previewSize = Size(value, value)
+            }
+
         fun reset(totalItemCount: Int) {
             firstImagePos = -1
             previews.clear()
@@ -387,6 +406,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                     vh.bind(
                         previews[position],
                         imageLoader ?: error("ImageLoader is missing"),
+                        previewSize,
                         fadeInDurationMs,
                         isSharedTransitionElement = position == firstImagePos,
                         previewReadyCallback =
@@ -438,6 +458,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
         fun bind(
             preview: Preview,
             imageLoader: CachingImageLoader,
+            previewSize: Size,
             fadeInDurationMs: Long,
             isSharedTransitionElement: Boolean,
             previewReadyCallback: ((String) -> Unit)?
@@ -477,7 +498,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                 }
             }
             resetScope().launch {
-                loadImage(preview, imageLoader)
+                loadImage(preview, previewSize, imageLoader)
                 if (preview.type == PreviewType.Image && previewReadyCallback != null) {
                     image.waitForPreDraw()
                     previewReadyCallback(TRANSITION_NAME)
@@ -487,12 +508,16 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
             }
         }
 
-        private suspend fun loadImage(preview: Preview, imageLoader: CachingImageLoader) {
+        private suspend fun loadImage(
+            preview: Preview,
+            previewSize: Size,
+            imageLoader: CachingImageLoader,
+        ) {
             val bitmap =
                 runCatching {
                         // it's expected for all loading/caching optimizations to be implemented by
                         // the loader
-                        imageLoader(preview.uri, true)
+                        imageLoader(preview.uri, previewSize, true)
                     }
                     .getOrNull()
             image.setImageBitmap(bitmap)
@@ -507,6 +532,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                         setAnimationListener(
                             object : AnimationListener {
                                 override fun onAnimationStart(animation: Animation?) = Unit
+
                                 override fun onAnimationRepeat(animation: Animation?) = Unit
 
                                 override fun onAnimationEnd(animation: Animation?) {
@@ -551,6 +577,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
 
     private class LoadingItemViewHolder(view: View) : ViewHolder(view) {
         fun bind() = Unit
+
         override fun unbind() = Unit
     }
 
@@ -638,6 +665,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
     class BatchPreviewLoader(
         private val imageLoader: CachingImageLoader,
         private val previews: Flow<Preview>,
+        private val previewSize: Size,
         val totalItemCount: Int,
         private val onUpdate: (List<Preview>) -> Unit,
         private val onCompletion: () -> Unit,
@@ -701,10 +729,10 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                                     //  imagine is one of the first images never loads so we never
                                     //  fill the initial viewport and does not show the previews at
                                     //  all.
-                                    imageLoader(preview.uri, isFirstBlock)?.let { bitmap ->
+                                    imageLoader(preview.uri, previewSize, isFirstBlock)?.let {
+                                        bitmap ->
                                         previewSizeUpdater(preview, bitmap.width, bitmap.height)
-                                    }
-                                        ?: 0
+                                    } ?: 0
                                 }
                                 .getOrDefault(0)
 
diff --git a/tests/activity/Android.bp b/tests/activity/Android.bp
index b718a430..9d673b4c 100644
--- a/tests/activity/Android.bp
+++ b/tests/activity/Android.bp
@@ -28,9 +28,9 @@ android_test {
     ],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs",
+        "android.test.base.stubs",
+        "android.test.mock.stubs",
         "framework",
         "framework-res",
     ],
diff --git a/tests/activity/src/com/android/intentresolver/ChooserActivityOverrideData.java b/tests/activity/src/com/android/intentresolver/ChooserActivityOverrideData.java
index 507ce3d7..311201cf 100644
--- a/tests/activity/src/com/android/intentresolver/ChooserActivityOverrideData.java
+++ b/tests/activity/src/com/android/intentresolver/ChooserActivityOverrideData.java
@@ -26,7 +26,6 @@ import android.database.Cursor;
 import android.os.UserHandle;
 
 import com.android.intentresolver.chooser.TargetInfo;
-import com.android.intentresolver.contentpreview.ImageLoader;
 import com.android.intentresolver.emptystate.CrossProfileIntentsChecker;
 import com.android.intentresolver.shortcuts.ShortcutLoader;
 
@@ -58,7 +57,6 @@ public class ChooserActivityOverrideData {
     public Boolean isVoiceInteraction;
     public Cursor resolverCursor;
     public boolean resolverForceException;
-    public ImageLoader imageLoader;
     public Resources resources;
     public boolean hasCrossProfileIntents;
     public boolean isQuietModeEnabled;
@@ -68,7 +66,6 @@ public class ChooserActivityOverrideData {
     public void reset() {
         onSafelyStartInternalCallback = null;
         isVoiceInteraction = null;
-        imageLoader = null;
         resolverCursor = null;
         resolverForceException = false;
         resolverListController = mock(ChooserListController.class);
diff --git a/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java b/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java
index a8b8b2e9..e103e57b 100644
--- a/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java
+++ b/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java
@@ -124,6 +124,7 @@ import com.android.intentresolver.contentpreview.ImageLoaderModule;
 import com.android.intentresolver.contentpreview.PreviewCacheSize;
 import com.android.intentresolver.contentpreview.PreviewMaxConcurrency;
 import com.android.intentresolver.contentpreview.ThumbnailLoader;
+import com.android.intentresolver.contentpreview.ThumbnailSize;
 import com.android.intentresolver.data.repository.FakeUserRepository;
 import com.android.intentresolver.data.repository.UserRepository;
 import com.android.intentresolver.data.repository.UserRepositoryModule;
@@ -284,6 +285,10 @@ public class ChooserActivityTest {
     @PreviewMaxConcurrency
     int mPreviewMaxConcurrency = 4;
 
+    @BindValue
+    @ThumbnailSize
+    int mPreviewThumbnailSize = 500;
+
     @BindValue
     ThumbnailLoader mThumbnailLoader = new FakeThumbnailLoader();
 
@@ -305,9 +310,6 @@ public class ChooserActivityTest {
         // values to the dependency graph at activity launch time. This allows replacing
         // arbitrary bindings per-test case if needed.
         mPackageManager = mContext.getPackageManager();
-
-        // TODO: inject image loader in the prod code and remove this override
-        ChooserActivityOverrideData.getInstance().imageLoader = mFakeImageLoader;
     }
 
     public ChooserActivityTest(boolean appPredictionAvailable) {
diff --git a/tests/activity/src/com/android/intentresolver/ChooserWrapperActivity.java b/tests/activity/src/com/android/intentresolver/ChooserWrapperActivity.java
index 4b71aa29..6ff7af3f 100644
--- a/tests/activity/src/com/android/intentresolver/ChooserWrapperActivity.java
+++ b/tests/activity/src/com/android/intentresolver/ChooserWrapperActivity.java
@@ -30,8 +30,6 @@ import android.net.Uri;
 import android.os.Bundle;
 import android.os.UserHandle;
 
-import androidx.lifecycle.ViewModelProvider;
-
 import com.android.intentresolver.chooser.DisplayResolveInfo;
 import com.android.intentresolver.chooser.TargetInfo;
 import com.android.intentresolver.emptystate.CrossProfileIntentsChecker;
@@ -67,7 +65,7 @@ public class ChooserWrapperActivity extends ChooserActivity implements IChooserW
                 initialIntents,
                 rList,
                 filterLastUsed,
-                createListController(userHandle),
+                resolverListController,
                 userHandle,
                 targetIntent,
                 referrerFillInIntent,
@@ -77,8 +75,7 @@ public class ChooserWrapperActivity extends ChooserActivity implements IChooserW
                 maxTargetsPerRow,
                 userHandle,
                 mTargetDataLoader,
-                null,
-                mFeatureFlags);
+                null);
     }
 
     @Override
@@ -151,13 +148,6 @@ public class ChooserWrapperActivity extends ChooserActivity implements IChooserW
         return super.getResources();
     }
 
-    @Override
-    protected ViewModelProvider.Factory createPreviewViewModelFactory() {
-        return TestContentPreviewViewModel.Companion.wrap(
-                super.createPreviewViewModelFactory(),
-                sOverrides.imageLoader);
-    }
-
     @Override
     public Cursor queryResolver(ContentResolver resolver, Uri uri) {
         if (sOverrides.resolverCursor != null) {
diff --git a/tests/integration/Android.bp b/tests/integration/Android.bp
index 4c8fc37a..c968c128 100644
--- a/tests/integration/Android.bp
+++ b/tests/integration/Android.bp
@@ -27,8 +27,8 @@ android_test {
     ],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
         "framework",
     ],
     resource_dirs: ["res"],
diff --git a/tests/shared/Android.bp b/tests/shared/Android.bp
index 041e1ccc..0f501c4f 100644
--- a/tests/shared/Android.bp
+++ b/tests/shared/Android.bp
@@ -25,7 +25,7 @@ java_library {
         "src/**/*.kt",
     ],
     libs: [
-        "android.test.mock",
+        "android.test.mock.stubs.system",
         "framework",
     ],
     static_libs: [
diff --git a/tests/shared/src/com/android/intentresolver/FakeImageLoader.kt b/tests/shared/src/com/android/intentresolver/FakeImageLoader.kt
index c57ea78b..76eb5e0d 100644
--- a/tests/shared/src/com/android/intentresolver/FakeImageLoader.kt
+++ b/tests/shared/src/com/android/intentresolver/FakeImageLoader.kt
@@ -18,6 +18,7 @@ package com.android.intentresolver
 
 import android.graphics.Bitmap
 import android.net.Uri
+import android.util.Size
 import com.android.intentresolver.contentpreview.ImageLoader
 import java.util.function.Consumer
 import kotlinx.coroutines.CoroutineScope
@@ -25,13 +26,18 @@ import kotlinx.coroutines.CoroutineScope
 class FakeImageLoader(initialBitmaps: Map<Uri, Bitmap> = emptyMap()) : ImageLoader {
     private val bitmaps = HashMap<Uri, Bitmap>().apply { putAll(initialBitmaps) }
 
-    override fun loadImage(callerScope: CoroutineScope, uri: Uri, callback: Consumer<Bitmap?>) {
+    override fun loadImage(
+        callerScope: CoroutineScope,
+        uri: Uri,
+        size: Size,
+        callback: Consumer<Bitmap?>,
+    ) {
         callback.accept(bitmaps[uri])
     }
 
-    override suspend fun invoke(uri: Uri, caching: Boolean): Bitmap? = bitmaps[uri]
+    override suspend fun invoke(uri: Uri, size: Size, caching: Boolean): Bitmap? = bitmaps[uri]
 
-    override fun prePopulate(uris: List<Uri>) = Unit
+    override fun prePopulate(uriSizePairs: List<Pair<Uri, Size>>) = Unit
 
     fun setBitmap(uri: Uri, bitmap: Bitmap) {
         bitmaps[uri] = bitmap
diff --git a/tests/shared/src/com/android/intentresolver/TestContentPreviewViewModel.kt b/tests/shared/src/com/android/intentresolver/TestContentPreviewViewModel.kt
deleted file mode 100644
index 8f246424..00000000
--- a/tests/shared/src/com/android/intentresolver/TestContentPreviewViewModel.kt
+++ /dev/null
@@ -1,64 +0,0 @@
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
-package com.android.intentresolver
-
-import android.content.Intent
-import android.net.Uri
-import androidx.lifecycle.ViewModel
-import androidx.lifecycle.ViewModelProvider
-import androidx.lifecycle.viewmodel.CreationExtras
-import com.android.intentresolver.contentpreview.BasePreviewViewModel
-import com.android.intentresolver.contentpreview.ImageLoader
-
-/** A test content preview model that supports image loader override. */
-class TestContentPreviewViewModel(
-    private val viewModel: BasePreviewViewModel,
-    override val imageLoader: ImageLoader,
-) : BasePreviewViewModel() {
-
-    override val previewDataProvider
-        get() = viewModel.previewDataProvider
-
-    override fun init(
-        targetIntent: Intent,
-        additionalContentUri: Uri?,
-        isPayloadTogglingEnabled: Boolean,
-    ) {
-        viewModel.init(targetIntent, additionalContentUri, isPayloadTogglingEnabled)
-    }
-
-    companion object {
-        fun wrap(
-            factory: ViewModelProvider.Factory,
-            imageLoader: ImageLoader?,
-        ): ViewModelProvider.Factory =
-            object : ViewModelProvider.Factory {
-                @Suppress("UNCHECKED_CAST")
-                override fun <T : ViewModel> create(
-                    modelClass: Class<T>,
-                    extras: CreationExtras
-                ): T {
-                    val wrapped = factory.create(modelClass, extras) as BasePreviewViewModel
-                    return TestContentPreviewViewModel(
-                        wrapped,
-                        imageLoader ?: wrapped.imageLoader,
-                    )
-                        as T
-                }
-            }
-    }
-}
diff --git a/tests/shared/src/com/android/intentresolver/contentpreview/FakeThumbnailLoader.kt b/tests/shared/src/com/android/intentresolver/contentpreview/FakeThumbnailLoader.kt
index d3fdf17d..33969eb7 100644
--- a/tests/shared/src/com/android/intentresolver/contentpreview/FakeThumbnailLoader.kt
+++ b/tests/shared/src/com/android/intentresolver/contentpreview/FakeThumbnailLoader.kt
@@ -18,18 +18,23 @@ package com.android.intentresolver.contentpreview
 
 import android.graphics.Bitmap
 import android.net.Uri
+import android.util.Size
 
 /** Fake implementation of [ThumbnailLoader] for use in testing. */
-class FakeThumbnailLoader : ThumbnailLoader {
+class FakeThumbnailLoader(private val defaultSize: Size = Size(100, 100)) : ThumbnailLoader {
 
-    val fakeInvoke = mutableMapOf<Uri, suspend () -> Bitmap?>()
+    val fakeInvoke = mutableMapOf<Uri, suspend (Size) -> Bitmap?>()
     val invokeCalls = mutableListOf<Uri>()
     var unfinishedInvokeCount = 0
 
-    override suspend fun invoke(uri: Uri): Bitmap? {
+    override suspend fun loadThumbnail(uri: Uri): Bitmap? = getBitmap(uri, defaultSize)
+
+    override suspend fun loadThumbnail(uri: Uri, size: Size): Bitmap? = getBitmap(uri, size)
+
+    private suspend fun getBitmap(uri: Uri, size: Size): Bitmap? {
         invokeCalls.add(uri)
         unfinishedInvokeCount++
-        val result = fakeInvoke[uri]?.invoke()
+        val result = fakeInvoke[uri]?.invoke(size)
         unfinishedInvokeCount--
         return result
     }
diff --git a/tests/shared/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/PayloadToggleInteractorKosmos.kt b/tests/shared/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/PayloadToggleInteractorKosmos.kt
index cb88cd9e..7cca414f 100644
--- a/tests/shared/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/PayloadToggleInteractorKosmos.kt
+++ b/tests/shared/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/PayloadToggleInteractorKosmos.kt
@@ -91,6 +91,7 @@ val Kosmos.selectablePreviewsInteractor
         SelectablePreviewsInteractor(
             previewsRepo = cursorPreviewsRepository,
             selectionInteractor = selectionInteractor,
+            eventLog = eventLog,
         )
 
 val Kosmos.selectionInteractor
diff --git a/tests/shared/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackKosmos.kt b/tests/shared/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackKosmos.kt
index 548b1f37..b26b562e 100644
--- a/tests/shared/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackKosmos.kt
+++ b/tests/shared/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackKosmos.kt
@@ -19,7 +19,6 @@ package com.android.intentresolver.contentpreview.payloadtoggle.domain.update
 import com.android.intentresolver.contentInterface
 import com.android.intentresolver.inject.additionalContentUri
 import com.android.intentresolver.inject.chooserIntent
-import com.android.intentresolver.inject.chooserServiceFlags
 import com.android.systemui.kosmos.Kosmos
 
 val Kosmos.selectionChangeCallbackImpl by
@@ -28,7 +27,6 @@ val Kosmos.selectionChangeCallbackImpl by
             additionalContentUri,
             chooserIntent,
             contentInterface,
-            chooserServiceFlags,
         )
     }
 var Kosmos.selectionChangeCallback: SelectionChangeCallback by
diff --git a/tests/shared/src/com/android/intentresolver/logging/FakeEventLog.kt b/tests/shared/src/com/android/intentresolver/logging/FakeEventLog.kt
index 9ed47db6..c2d13f1e 100644
--- a/tests/shared/src/com/android/intentresolver/logging/FakeEventLog.kt
+++ b/tests/shared/src/com/android/intentresolver/logging/FakeEventLog.kt
@@ -164,14 +164,22 @@ class FakeEventLog @Inject constructor(private val instanceId: InstanceId) : Eve
         log { "logSharesheetEmptyDirectShareRow()" }
     }
 
+    override fun logPayloadSelectionChanged() {
+        log { "logPayloadSelectionChanged" }
+    }
+
     data class ActionSelected(val targetType: Int)
+
     data class CustomActionSelected(val positionPicked: Int)
+
     data class ActionShareWithPreview(val previewType: Int)
+
     data class ChooserActivityShown(
         val isWorkProfile: Boolean,
         val targetMimeType: String?,
         val systemCost: Long
     )
+
     data class ShareStarted(
         val packageName: String?,
         val mimeType: String?,
@@ -183,6 +191,7 @@ class FakeEventLog @Inject constructor(private val instanceId: InstanceId) : Eve
         val customActionCount: Int,
         val modifyShareActionProvided: Boolean
     )
+
     data class ShareTargetSelected(
         val targetType: Int,
         val packageName: String?,
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index 1ae8d883..850c447f 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -28,11 +28,12 @@ android_test {
     ],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
         "framework",
         "framework-res",
+        "flag-junit",
     ],
 
     resource_dirs: ["res"],
diff --git a/tests/unit/src/com/android/intentresolver/ChooserActionFactoryTest.kt b/tests/unit/src/com/android/intentresolver/ChooserActionFactoryTest.kt
index c8e17de4..8dfbdbdd 100644
--- a/tests/unit/src/com/android/intentresolver/ChooserActionFactoryTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ChooserActionFactoryTest.kt
@@ -69,8 +69,6 @@ class ChooserActionFactoryTest {
                 latestReturn = resultCode
             }
         }
-    private val featureFlags =
-        FakeFeatureFlagsImpl().apply { setFlag(Flags.FLAG_FIX_PARTIAL_IMAGE_EDIT_TRANSITION, true) }
 
     @Before
     fun setup() {
@@ -121,7 +119,6 @@ class ChooserActionFactoryTest {
                 /* shareResultSender = */ null,
                 /* finishCallback = */ {},
                 /* clipboardManager = */ mock(),
-                /* featureFlags = */ featureFlags,
             )
         assertThat(testSubject.copyButtonRunnable).isNull()
     }
@@ -143,7 +140,6 @@ class ChooserActionFactoryTest {
                 /* shareResultSender = */ null,
                 /* finishCallback = */ {},
                 /* clipboardManager = */ mock(),
-                /* featureFlags = */ featureFlags,
             )
         assertThat(testSubject.copyButtonRunnable).isNull()
     }
@@ -166,7 +162,6 @@ class ChooserActionFactoryTest {
                 /* shareResultSender = */ resultSender,
                 /* finishCallback = */ {},
                 /* clipboardManager = */ mock(),
-                /* featureFlags = */ featureFlags,
             )
         assertThat(testSubject.copyButtonRunnable).isNotNull()
 
@@ -199,7 +194,6 @@ class ChooserActionFactoryTest {
             /* shareResultSender = */ null,
             /* finishCallback = */ resultConsumer,
             /* clipboardManager = */ mock(),
-            /* featureFlags = */ featureFlags,
         )
     }
 }
diff --git a/tests/unit/src/com/android/intentresolver/ChooserListAdapterDataTest.kt b/tests/unit/src/com/android/intentresolver/ChooserListAdapterDataTest.kt
index df0c5e5e..bbef6c0c 100644
--- a/tests/unit/src/com/android/intentresolver/ChooserListAdapterDataTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ChooserListAdapterDataTest.kt
@@ -66,8 +66,6 @@ class ChooserListAdapterDataTest {
     private val immediateExecutor = TestExecutor(immediate = true)
     private val referrerFillInIntent =
         Intent().putExtra(Intent.EXTRA_REFERRER, "org.referrer.package")
-    private val featureFlags =
-        FakeFeatureFlagsImpl().apply { setFlag(Flags.FLAG_BESPOKE_LABEL_VIEW, false) }
 
     @Test
     fun test_twoTargetsWithNonOverlappingInitialIntent_threeTargetsInResolverAdapter() {
@@ -86,7 +84,7 @@ class ChooserListAdapterDataTest {
                     userHandle
                 )
             )
-            .thenReturn(resolvedTargets)
+            .thenReturn(ArrayList(resolvedTargets))
         val initialActivityInfo = createActivityInfo(3)
         val initialIntents =
             arrayOf(
@@ -119,7 +117,6 @@ class ChooserListAdapterDataTest {
                 null,
                 backgroundExecutor,
                 immediateExecutor,
-                featureFlags,
             )
         val doPostProcessing = true
 
@@ -152,7 +149,7 @@ class ChooserListAdapterDataTest {
                     userHandle
                 )
             )
-            .thenReturn(resolvedTargets)
+            .thenReturn(ArrayList(resolvedTargets))
         val activityInfo = resolvedTargets[1].getResolveInfoAt(0).activityInfo
         val initialIntents =
             arrayOf(Intent(Intent.ACTION_SEND).apply { component = activityInfo.componentName })
@@ -183,7 +180,6 @@ class ChooserListAdapterDataTest {
                 null,
                 backgroundExecutor,
                 immediateExecutor,
-                featureFlags,
             )
         val doPostProcessing = true
 
diff --git a/tests/unit/src/com/android/intentresolver/ChooserListAdapterTest.kt b/tests/unit/src/com/android/intentresolver/ChooserListAdapterTest.kt
index bad3b18c..cdc84ba8 100644
--- a/tests/unit/src/com/android/intentresolver/ChooserListAdapterTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ChooserListAdapterTest.kt
@@ -61,7 +61,6 @@ class ChooserListAdapterTest {
     private val mEventLog = mock<EventLogImpl>()
     private val mTargetDataLoader = mock<TargetDataLoader>()
     private val mPackageChangeCallback = mock<ChooserListAdapter.PackageChangeCallback>()
-    private val featureFlags = FeatureFlagsImpl()
 
     private val testSubject by lazy {
         ChooserListAdapter(
@@ -81,7 +80,6 @@ class ChooserListAdapterTest {
             null,
             mTargetDataLoader,
             mPackageChangeCallback,
-            featureFlags,
         )
     }
 
@@ -222,15 +220,10 @@ class ChooserListAdapterTest {
 
     private fun createView(): View {
         val view = FrameLayout(context)
-        if (featureFlags.bespokeLabelView()) {
-                BadgeTextView(context)
-            } else {
-                TextView(context)
-            }
-            .apply {
-                id = R.id.text1
-                view.addView(this)
-            }
+        BadgeTextView(context).apply {
+            id = R.id.text1
+            view.addView(this)
+        }
         TextView(context).apply {
             id = R.id.text2
             view.addView(this)
diff --git a/tests/unit/src/com/android/intentresolver/ResolverListAdapterTest.kt b/tests/unit/src/com/android/intentresolver/ResolverListAdapterTest.kt
index d8cb7adc..23ea33b2 100644
--- a/tests/unit/src/com/android/intentresolver/ResolverListAdapterTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ResolverListAdapterTest.kt
@@ -79,7 +79,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
             }
         val testSubject =
             ResolverListAdapter(
@@ -128,7 +128,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
                 on { lastChosen } doReturn resolvedTargets[0].getResolveInfoAt(0)
             }
         val testSubject =
@@ -177,7 +177,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
                 on { lastChosen } doReturn createResolveInfo(PKG_NAME_TWO, CLASS_NAME, userHandle)
             }
         val testSubject =
@@ -228,7 +228,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
                 on { lastChosen } doReturn resolvedTargets[0].getResolveInfoAt(0)
             }
         val testSubject =
@@ -302,7 +302,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
                 if (hasLastChosen) {
                     on { lastChosen } doReturn resolvedTargets[0].getResolveInfoAt(0)
                 }
@@ -379,7 +379,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
                 on { lastChosen } doReturn createResolveInfo(PKG_NAME, CLASS_NAME + "2", userHandle)
             }
         val testSubject =
@@ -434,7 +434,6 @@ class ResolverListAdapterTest {
                 ComponentName(PKG_NAME_TWO, CLASS_NAME),
             )
         resolvedTargets[1].getResolveInfoAt(0).targetUserId = 10
-        // whenever(resolvedTargets[1].getResolveInfoAt(0).loadLabel(any())).thenReturn("Label")
         val resolverListController =
             mock<ResolverListController> {
                 on { filterIneligibleActivities(any(), any()) } doReturn null
@@ -447,7 +446,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
                 on { lastChosen } doReturn resolvedTargets[0].getResolveInfoAt(0)
             }
         val testSubject =
@@ -477,7 +476,9 @@ class ResolverListAdapterTest {
         assertThat(testSubject.hasFilteredItem()).isFalse()
         assertThat(testSubject.filteredItem).isNull()
         assertThat(testSubject.filteredPosition).isLessThan(0)
-        assertThat(testSubject.unfilteredResolveList).containsExactlyElementsIn(resolvedTargets)
+        // The following must be an old bug i.e. unfilteredResolveList should be equal to
+        // resolvedTargets. Also see comments in the code.
+        assertThat(testSubject.unfilteredResolveList).containsExactly(resolvedTargets[0])
         assertThat(testSubject.isTabLoaded).isTrue()
         assertThat(backgroundExecutor.pendingCommandCount).isEqualTo(0)
     }
@@ -502,7 +503,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
                 on { sort(any()) } doAnswer
                     {
                         val components = it.arguments[0] as MutableList<ResolvedComponentInfo>
@@ -532,11 +533,10 @@ class ResolverListAdapterTest {
 
         backgroundExecutor.runUntilIdle()
 
-        // we don't reset placeholder count (legacy logic, likely an oversight?)
         assertThat(testSubject.count).isEqualTo(resolvedTargets.size)
-        assertThat(resolvedTargets[0].getResolveInfoAt(0).activityInfo.packageName)
+        assertThat(testSubject.getDisplayResolveInfo(0).resolveInfo.activityInfo.packageName)
             .isEqualTo(PKG_NAME_TWO)
-        assertThat(resolvedTargets[1].getResolveInfoAt(0).activityInfo.packageName)
+        assertThat(testSubject.getDisplayResolveInfo(1).resolveInfo.activityInfo.packageName)
             .isEqualTo(PKG_NAME)
     }
 
@@ -560,7 +560,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
                 on { filterIneligibleActivities(any(), any()) } doAnswer
                     {
                         val components = it.arguments[0] as MutableList<ResolvedComponentInfo>
@@ -646,7 +646,6 @@ class ResolverListAdapterTest {
 
         backgroundExecutor.runUntilIdle()
 
-        // we don't reset placeholder count (legacy logic, likely an oversight?)
         assertThat(testSubject.count).isEqualTo(2)
         assertThat(testSubject.unfilteredResolveList).hasSize(2)
     }
@@ -670,7 +669,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
                 on { filterLowPriority(any(), any()) } doAnswer
                     {
                         val components = it.arguments[0] as MutableList<ResolvedComponentInfo>
@@ -730,7 +729,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
             }
         whenever(packageManager.getActivityInfo(eq(initialComponent), eq(0)))
             .thenReturn(createActivityInfo(initialComponent))
@@ -801,7 +800,7 @@ class ResolverListAdapterTest {
                         payloadIntents,
                         userHandle
                     )
-                } doReturn resolvedTargets
+                } doReturn ArrayList(resolvedTargets)
             }
         val initialComponent = ComponentName(PKG_NAME_TWO, CLASS_NAME)
         val initialIntents =
@@ -896,7 +895,7 @@ class ResolverListAdapterTest {
                 on { filterIneligibleActivities(any(), any()) } doReturn null
                 on { filterLowPriority(any(), any()) } doReturn null
                 on { getResolversForIntentAsUser(any(), any(), any(), any(), any()) } doReturn
-                    resolvedTargets
+                    ArrayList(resolvedTargets)
             }
         val communicator =
             mock<ResolverListCommunicator> {
@@ -944,7 +943,7 @@ class ResolverListAdapterTest {
                 on { filterIneligibleActivities(any(), any()) } doReturn null
                 on { filterLowPriority(any(), any()) } doReturn null
                 on { getResolversForIntentAsUser(any(), any(), any(), any(), any()) } doReturn
-                    resolvedTargets
+                    ArrayList(resolvedTargets)
             }
         val communicator =
             mock<ResolverListCommunicator> {
@@ -999,7 +998,7 @@ class ResolverListAdapterTest {
                 on { filterIneligibleActivities(any(), any()) } doReturn null
                 on { filterLowPriority(any(), any()) } doReturn null
                 on { getResolversForIntentAsUser(any(), any(), any(), any(), any()) } doReturn
-                    resolvedTargets
+                    ArrayList(resolvedTargets)
             }
         val communicator =
             mock<ResolverListCommunicator> {
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoaderTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoaderTest.kt
index 331f9f64..d5a569aa 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoaderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoaderTest.kt
@@ -18,6 +18,7 @@ package com.android.intentresolver.contentpreview
 
 import android.graphics.Bitmap
 import android.net.Uri
+import android.util.Size
 import com.google.common.truth.Truth.assertThat
 import kotlin.math.ceil
 import kotlin.math.roundToInt
@@ -43,6 +44,7 @@ class CachingImagePreviewImageLoaderTest {
         testJobTime * ceil((testCacheSize).toFloat() / testMaxConcurrency.toFloat()).roundToInt()
     private val testUris =
         List(5) { Uri.fromParts("TestScheme$it", "TestSsp$it", "TestFragment$it") }
+    private val previewSize = Size(500, 500)
     private val testTimeToLoadAllUris =
         testJobTime * ceil((testUris.size).toFloat() / testMaxConcurrency.toFloat()).roundToInt()
     private val testBitmap = Bitmap.createBitmap(10, 10, Bitmap.Config.ALPHA_8)
@@ -72,7 +74,7 @@ class CachingImagePreviewImageLoaderTest {
             var result: Bitmap? = null
 
             // Act
-            imageLoader.loadImage(testScope, testUris[0]) { result = it }
+            imageLoader.loadImage(testScope, testUris[0], previewSize) { result = it }
             advanceTimeBy(testJobTime)
             runCurrent()
 
@@ -85,14 +87,14 @@ class CachingImagePreviewImageLoaderTest {
     fun loadImage_cached_usesCachedValue() =
         testScope.runTest {
             // Arrange
-            imageLoader.loadImage(testScope, testUris[0]) {}
+            imageLoader.loadImage(testScope, testUris[0], previewSize) {}
             advanceTimeBy(testJobTime)
             runCurrent()
             fakeThumbnailLoader.invokeCalls.clear()
             var result: Bitmap? = null
 
             // Act
-            imageLoader.loadImage(testScope, testUris[0]) { result = it }
+            imageLoader.loadImage(testScope, testUris[0], previewSize) { result = it }
             advanceTimeBy(testJobTime)
             runCurrent()
 
@@ -112,7 +114,7 @@ class CachingImagePreviewImageLoaderTest {
             var result: Bitmap? = testBitmap
 
             // Act
-            imageLoader.loadImage(testScope, testUris[0]) { result = it }
+            imageLoader.loadImage(testScope, testUris[0], previewSize) { result = it }
             advanceTimeBy(testJobTime)
             runCurrent()
 
@@ -130,7 +132,7 @@ class CachingImagePreviewImageLoaderTest {
 
             // Act
             testUris.take(testMaxConcurrency + 1).forEach { uri ->
-                imageLoader.loadImage(testScope, uri) { results.add(it) }
+                imageLoader.loadImage(testScope, uri, previewSize) { results.add(it) }
             }
 
             // Assert
@@ -153,10 +155,10 @@ class CachingImagePreviewImageLoaderTest {
             assertThat(testUris.size).isGreaterThan(testCacheSize)
 
             // Act
-            imageLoader.loadImage(testScope, testUris[0]) { results[0] = it }
+            imageLoader.loadImage(testScope, testUris[0], previewSize) { results[0] = it }
             runCurrent()
             testUris.indices.drop(1).take(testCacheSize).forEach { i ->
-                imageLoader.loadImage(testScope, testUris[i]) { results[i] = it }
+                imageLoader.loadImage(testScope, testUris[i], previewSize) { results[i] = it }
             }
             advanceTimeBy(testTimeToFillCache)
             runCurrent()
@@ -179,7 +181,7 @@ class CachingImagePreviewImageLoaderTest {
             assertThat(fullCacheUris).hasSize(testCacheSize)
 
             // Act
-            imageLoader.prePopulate(fullCacheUris)
+            imageLoader.prePopulate(fullCacheUris.map { it to previewSize })
             advanceTimeBy(testTimeToFillCache)
             runCurrent()
 
@@ -188,7 +190,7 @@ class CachingImagePreviewImageLoaderTest {
 
             // Act
             fakeThumbnailLoader.invokeCalls.clear()
-            imageLoader.prePopulate(fullCacheUris)
+            imageLoader.prePopulate(fullCacheUris.map { it to previewSize })
             advanceTimeBy(testTimeToFillCache)
             runCurrent()
 
@@ -203,7 +205,7 @@ class CachingImagePreviewImageLoaderTest {
             assertThat(testUris.size).isGreaterThan(testCacheSize)
 
             // Act
-            imageLoader.prePopulate(testUris)
+            imageLoader.prePopulate(testUris.map { it to previewSize })
             advanceTimeBy(testTimeToLoadAllUris)
             runCurrent()
 
@@ -213,7 +215,7 @@ class CachingImagePreviewImageLoaderTest {
 
             // Act
             fakeThumbnailLoader.invokeCalls.clear()
-            imageLoader.prePopulate(testUris)
+            imageLoader.prePopulate(testUris.map { it to previewSize })
             advanceTimeBy(testTimeToLoadAllUris)
             runCurrent()
 
@@ -229,7 +231,7 @@ class CachingImagePreviewImageLoaderTest {
             assertThat(unfilledCacheUris.size).isLessThan(testCacheSize)
 
             // Act
-            imageLoader.prePopulate(unfilledCacheUris)
+            imageLoader.prePopulate(unfilledCacheUris.map { it to previewSize })
             advanceTimeBy(testJobTime)
             runCurrent()
 
@@ -238,7 +240,7 @@ class CachingImagePreviewImageLoaderTest {
 
             // Act
             fakeThumbnailLoader.invokeCalls.clear()
-            imageLoader.prePopulate(unfilledCacheUris)
+            imageLoader.prePopulate(unfilledCacheUris.map { it to previewSize })
             advanceTimeBy(testJobTime)
             runCurrent()
 
@@ -252,8 +254,8 @@ class CachingImagePreviewImageLoaderTest {
             // Arrange
 
             // Act
-            imageLoader.invoke(testUris[0], caching = false)
-            imageLoader.invoke(testUris[0], caching = false)
+            imageLoader.invoke(testUris[0], previewSize, caching = false)
+            imageLoader.invoke(testUris[0], previewSize, caching = false)
             advanceTimeBy(testJobTime)
             runCurrent()
 
@@ -267,8 +269,8 @@ class CachingImagePreviewImageLoaderTest {
             // Arrange
 
             // Act
-            imageLoader.invoke(testUris[0], caching = true)
-            imageLoader.invoke(testUris[0], caching = true)
+            imageLoader.invoke(testUris[0], previewSize, caching = true)
+            imageLoader.invoke(testUris[0], previewSize, caching = true)
             advanceTimeBy(testJobTime)
             runCurrent()
 
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUiTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUiTest.kt
index 27d98ece..905c8517 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUiTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUiTest.kt
@@ -23,6 +23,7 @@ import android.platform.test.flag.junit.DeviceFlagsValueProvider
 import com.android.intentresolver.ContentTypeHint
 import com.android.intentresolver.FakeImageLoader
 import com.android.intentresolver.contentpreview.ChooserContentPreviewUi.ActionFactory
+import com.android.intentresolver.data.model.ChooserRequest
 import com.android.intentresolver.widget.ActionRow
 import com.android.intentresolver.widget.ImagePreviewView
 import com.google.common.truth.Truth.assertThat
@@ -61,13 +62,18 @@ class ChooserContentPreviewUiTest {
     @get:Rule val checkFlagsRule: CheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule()
 
     private fun createContentPreviewUi(
-        targetIntent: Intent,
+        action: String,
+        sharedText: CharSequence? = null,
         isPayloadTogglingEnabled: Boolean = false
     ) =
         ChooserContentPreviewUi(
             testScope,
             previewData,
-            targetIntent,
+            ChooserRequest(
+                targetIntent = Intent(action),
+                sharedText = sharedText,
+                launchedFromPackage = "org.pkg",
+            ),
             imageLoader,
             actionFactory,
             { null },
@@ -81,7 +87,7 @@ class ChooserContentPreviewUiTest {
     @Test
     fun test_textPreviewType_useTextPreviewUi() {
         whenever(previewData.previewType).thenReturn(ContentPreviewType.CONTENT_PREVIEW_TEXT)
-        val testSubject = createContentPreviewUi(targetIntent = Intent(Intent.ACTION_VIEW))
+        val testSubject = createContentPreviewUi(action = Intent.ACTION_VIEW)
 
         assertThat(testSubject.preferredContentPreview)
             .isEqualTo(ContentPreviewType.CONTENT_PREVIEW_TEXT)
@@ -92,7 +98,7 @@ class ChooserContentPreviewUiTest {
     @Test
     fun test_filePreviewType_useFilePreviewUi() {
         whenever(previewData.previewType).thenReturn(ContentPreviewType.CONTENT_PREVIEW_FILE)
-        val testSubject = createContentPreviewUi(targetIntent = Intent(Intent.ACTION_SEND))
+        val testSubject = createContentPreviewUi(action = Intent.ACTION_SEND)
         assertThat(testSubject.preferredContentPreview)
             .isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
         assertThat(testSubject.mContentPreviewUi).isInstanceOf(FileContentPreviewUi::class.java)
@@ -109,8 +115,8 @@ class ChooserContentPreviewUiTest {
         whenever(previewData.imagePreviewFileInfoFlow).thenReturn(MutableSharedFlow())
         val testSubject =
             createContentPreviewUi(
-                targetIntent =
-                    Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_TEXT, "Shared text") }
+                action = Intent.ACTION_SEND,
+                sharedText = "Shared text",
             )
         assertThat(testSubject.mContentPreviewUi)
             .isInstanceOf(FilesPlusTextContentPreviewUi::class.java)
@@ -126,7 +132,7 @@ class ChooserContentPreviewUiTest {
         whenever(previewData.firstFileInfo)
             .thenReturn(FileInfo.Builder(uri).withPreviewUri(uri).withMimeType("image/png").build())
         whenever(previewData.imagePreviewFileInfoFlow).thenReturn(MutableSharedFlow())
-        val testSubject = createContentPreviewUi(targetIntent = Intent(Intent.ACTION_SEND))
+        val testSubject = createContentPreviewUi(action = Intent.ACTION_SEND)
         assertThat(testSubject.preferredContentPreview)
             .isEqualTo(ContentPreviewType.CONTENT_PREVIEW_IMAGE)
         assertThat(testSubject.mContentPreviewUi).isInstanceOf(UnifiedContentPreviewUi::class.java)
@@ -146,10 +152,12 @@ class ChooserContentPreviewUiTest {
         whenever(previewData.imagePreviewFileInfoFlow).thenReturn(MutableSharedFlow())
         val testSubject =
             createContentPreviewUi(
-                targetIntent = Intent(Intent.ACTION_SEND),
-                isPayloadTogglingEnabled = true
+                action = Intent.ACTION_SEND,
+                isPayloadTogglingEnabled = true,
             )
         assertThat(testSubject.mContentPreviewUi)
             .isInstanceOf(ShareouselContentPreviewUi::class.java)
+        assertThat(testSubject.preferredContentPreview)
+            .isEqualTo(ContentPreviewType.CONTENT_PREVIEW_PAYLOAD_SELECTION)
     }
 }
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoaderTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoaderTest.kt
index 3a45e2f6..d78e6665 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoaderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoaderTest.kt
@@ -77,24 +77,25 @@ class ImagePreviewImageLoaderTest {
             contentResolver,
             cacheSize = 1,
         )
+    private val previewSize = Size(500, 500)
 
     @Test
     fun prePopulate_cachesImagesUpToTheCacheSize() =
         scope.runTest {
-            testSubject.prePopulate(listOf(uriOne, uriTwo))
+            testSubject.prePopulate(listOf(uriOne to previewSize, uriTwo to previewSize))
 
             verify(contentResolver, times(1)).loadThumbnail(uriOne, imageSize, null)
             verify(contentResolver, never()).loadThumbnail(uriTwo, imageSize, null)
 
-            testSubject(uriOne)
+            testSubject(uriOne, previewSize)
             verify(contentResolver, times(1)).loadThumbnail(uriOne, imageSize, null)
         }
 
     @Test
     fun invoke_returnCachedImageWhenCalledTwice() =
         scope.runTest {
-            testSubject(uriOne)
-            testSubject(uriOne)
+            testSubject(uriOne, previewSize)
+            testSubject(uriOne, previewSize)
 
             verify(contentResolver, times(1)).loadThumbnail(any(), any(), anyOrNull())
         }
@@ -102,8 +103,8 @@ class ImagePreviewImageLoaderTest {
     @Test
     fun invoke_whenInstructed_doesNotCache() =
         scope.runTest {
-            testSubject(uriOne, false)
-            testSubject(uriOne, false)
+            testSubject(uriOne, previewSize, false)
+            testSubject(uriOne, previewSize, false)
 
             verify(contentResolver, times(2)).loadThumbnail(any(), any(), anyOrNull())
         }
@@ -120,8 +121,8 @@ class ImagePreviewImageLoaderTest {
                     cacheSize = 1,
                 )
             coroutineScope {
-                launch(start = UNDISPATCHED) { testSubject(uriOne, false) }
-                launch(start = UNDISPATCHED) { testSubject(uriOne, false) }
+                launch(start = UNDISPATCHED) { testSubject(uriOne, previewSize, false) }
+                launch(start = UNDISPATCHED) { testSubject(uriOne, previewSize, false) }
                 scheduler.advanceUntilIdle()
             }
 
@@ -131,10 +132,10 @@ class ImagePreviewImageLoaderTest {
     @Test
     fun invoke_oldRecordsEvictedFromTheCache() =
         scope.runTest {
-            testSubject(uriOne)
-            testSubject(uriTwo)
-            testSubject(uriTwo)
-            testSubject(uriOne)
+            testSubject(uriOne, previewSize)
+            testSubject(uriTwo, previewSize)
+            testSubject(uriTwo, previewSize)
+            testSubject(uriOne, previewSize)
 
             verify(contentResolver, times(2)).loadThumbnail(uriOne, imageSize, null)
             verify(contentResolver, times(1)).loadThumbnail(uriTwo, imageSize, null)
@@ -144,8 +145,8 @@ class ImagePreviewImageLoaderTest {
     fun invoke_doNotCacheNulls() =
         scope.runTest {
             whenever(contentResolver.loadThumbnail(any(), any(), anyOrNull())).thenReturn(null)
-            testSubject(uriOne)
-            testSubject(uriOne)
+            testSubject(uriOne, previewSize)
+            testSubject(uriOne, previewSize)
 
             verify(contentResolver, times(2)).loadThumbnail(uriOne, imageSize, null)
         }
@@ -162,7 +163,7 @@ class ImagePreviewImageLoaderTest {
                     cacheSize = 1,
                 )
             imageLoaderScope.cancel()
-            testSubject(uriOne)
+            testSubject(uriOne, previewSize)
         }
 
     @Test(expected = CancellationException::class)
@@ -178,7 +179,8 @@ class ImagePreviewImageLoaderTest {
                     cacheSize = 1,
                 )
             coroutineScope {
-                val deferred = async(start = UNDISPATCHED) { testSubject(uriOne, false) }
+                val deferred =
+                    async(start = UNDISPATCHED) { testSubject(uriOne, previewSize, false) }
                 imageLoaderScope.cancel()
                 scheduler.advanceUntilIdle()
                 deferred.await()
@@ -198,11 +200,11 @@ class ImagePreviewImageLoaderTest {
                     cacheSize = 1,
                 )
             coroutineScope {
-                launch(start = UNDISPATCHED) { testSubject(uriOne, false) }
-                launch(start = UNDISPATCHED) { testSubject(uriOne, true) }
+                launch(start = UNDISPATCHED) { testSubject(uriOne, previewSize, false) }
+                launch(start = UNDISPATCHED) { testSubject(uriOne, previewSize, true) }
                 scheduler.advanceUntilIdle()
             }
-            testSubject(uriOne, true)
+            testSubject(uriOne, previewSize, true)
 
             verify(contentResolver, times(1)).loadThumbnail(uriOne, imageSize, null)
         }
@@ -243,7 +245,7 @@ class ImagePreviewImageLoaderTest {
                     cacheSize = 1,
                     testSemaphore,
                 )
-            testSubject(uriOne, false)
+            testSubject(uriOne, previewSize, false)
 
             verify(contentResolver, times(1)).loadThumbnail(uriOne, imageSize, null)
             assertThat(acquireCount.get()).isEqualTo(1)
@@ -281,7 +283,7 @@ class ImagePreviewImageLoaderTest {
                     cacheSize = 1,
                     testSemaphore,
                 )
-            launch(start = UNDISPATCHED) { testSubject(uriOne, false) }
+            launch(start = UNDISPATCHED) { testSubject(uriOne, previewSize, false) }
 
             verify(contentResolver, never()).loadThumbnail(any(), any(), anyOrNull())
 
@@ -324,7 +326,9 @@ class ImagePreviewImageLoaderTest {
                 )
             coroutineScope {
                 repeat(requestCount) {
-                    launch { testSubject(Uri.parse("content://org.pkg.app/image-$it.png")) }
+                    launch {
+                        testSubject(Uri.parse("content://org.pkg.app/image-$it.png"), previewSize)
+                    }
                 }
                 yield()
                 // wait for all requests to be dispatched
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt
index a2fb9693..370ee044 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt
@@ -21,9 +21,9 @@ import android.content.Intent
 import android.database.MatrixCursor
 import android.media.MediaMetadata
 import android.net.Uri
-import android.platform.test.flag.junit.CheckFlagsRule
-import android.platform.test.flag.junit.DeviceFlagsValueProvider
 import android.provider.DocumentsContract
+import android.service.chooser.FakeFeatureFlagsImpl
+import android.service.chooser.Flags
 import com.google.common.truth.Truth.assertThat
 import kotlin.coroutines.EmptyCoroutineContext
 import kotlinx.coroutines.CoroutineScope
@@ -32,7 +32,6 @@ import kotlinx.coroutines.flow.toList
 import kotlinx.coroutines.test.TestScope
 import kotlinx.coroutines.test.UnconfinedTestDispatcher
 import kotlinx.coroutines.test.runTest
-import org.junit.Rule
 import org.junit.Test
 import org.mockito.kotlin.any
 import org.mockito.kotlin.mock
@@ -46,7 +45,8 @@ class PreviewDataProviderTest {
     private val contentResolver = mock<ContentInterface>()
     private val mimeTypeClassifier = DefaultMimeTypeClassifier
     private val testScope = TestScope(EmptyCoroutineContext + UnconfinedTestDispatcher())
-    @get:Rule val checkFlagsRule: CheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule()
+    private val featureFlags =
+        FakeFeatureFlagsImpl().apply { setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, false) }
 
     private fun createDataProvider(
         targetIntent: Intent,
@@ -54,14 +54,13 @@ class PreviewDataProviderTest {
         additionalContentUri: Uri? = null,
         resolver: ContentInterface = contentResolver,
         typeClassifier: MimeTypeClassifier = mimeTypeClassifier,
-        isPayloadTogglingEnabled: Boolean = false
     ) =
         PreviewDataProvider(
             scope,
             targetIntent,
             additionalContentUri,
             resolver,
-            isPayloadTogglingEnabled,
+            featureFlags,
             typeClassifier,
         )
 
@@ -377,11 +376,11 @@ class PreviewDataProviderTest {
         val uri = Uri.parse("content://org.pkg.app/image.png")
         val targetIntent = Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_STREAM, uri) }
         whenever(contentResolver.getType(uri)).thenReturn("image/png")
+        featureFlags.setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, true)
         val testSubject =
             createDataProvider(
                 targetIntent,
                 additionalContentUri = Uri.parse("content://org.pkg.app.extracontent"),
-                isPayloadTogglingEnabled = true,
             )
 
         assertThat(testSubject.previewType)
@@ -415,11 +414,11 @@ class PreviewDataProviderTest {
         val uri = Uri.parse("content://org.pkg.app/image.png")
         val targetIntent = Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_STREAM, uri) }
         whenever(contentResolver.getType(uri)).thenReturn("image/png")
+        featureFlags.setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, true)
         val testSubject =
             createDataProvider(
                 targetIntent,
                 additionalContentUri = Uri.parse("content://org.pkg.app/extracontent"),
-                isPayloadTogglingEnabled = true,
             )
 
         assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_IMAGE)
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/PreviewImageLoaderTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/PreviewImageLoaderTest.kt
new file mode 100644
index 00000000..8c810058
--- /dev/null
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/PreviewImageLoaderTest.kt
@@ -0,0 +1,496 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.intentresolver.contentpreview
+
+import android.graphics.Bitmap
+import android.net.Uri
+import android.util.Size
+import com.google.common.truth.Truth.assertThat
+import java.util.concurrent.atomic.AtomicInteger
+import kotlinx.coroutines.CancellationException
+import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.CoroutineStart
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.async
+import kotlinx.coroutines.awaitCancellation
+import kotlinx.coroutines.cancel
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.test.StandardTestDispatcher
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.runCurrent
+import kotlinx.coroutines.test.runTest
+import org.junit.Test
+
+@OptIn(ExperimentalCoroutinesApi::class)
+class PreviewImageLoaderTest {
+    private val scope = TestScope()
+
+    @Test
+    fun test_cachingImageRequest_imageCached() =
+        scope.runTest {
+            val uri = createUri(0)
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = { size -> createBitmap(size.width, size.height) }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            val b1 = testSubject.invoke(uri, Size(200, 100))
+            val b2 = testSubject.invoke(uri, Size(200, 100), caching = false)
+            assertThat(b1).isEqualTo(b2)
+            assertThat(thumbnailLoader.invokeCalls).hasSize(1)
+        }
+
+    @Test
+    fun test_nonCachingImageRequest_imageNotCached() =
+        scope.runTest {
+            val uri = createUri(0)
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = { size -> createBitmap(size.width, size.height) }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            testSubject.invoke(uri, Size(200, 100), caching = false)
+            testSubject.invoke(uri, Size(200, 100), caching = false)
+            assertThat(thumbnailLoader.invokeCalls).hasSize(2)
+        }
+
+    @Test
+    fun test_twoSimultaneousImageRequests_requestsDeduplicated() =
+        scope.runTest {
+            val uri = createUri(0)
+            val loadingStartedDeferred = CompletableDeferred<Unit>()
+            val bitmapDeferred = CompletableDeferred<Bitmap>()
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = {
+                        loadingStartedDeferred.complete(Unit)
+                        bitmapDeferred.await()
+                    }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            val b1Deferred = async { testSubject.invoke(uri, Size(200, 100), caching = false) }
+            loadingStartedDeferred.await()
+            val b2Deferred =
+                async(start = CoroutineStart.UNDISPATCHED) {
+                    testSubject.invoke(uri, Size(200, 100), caching = true)
+                }
+            bitmapDeferred.complete(createBitmap(200, 200))
+
+            val b1 = b1Deferred.await()
+            val b2 = b2Deferred.await()
+            assertThat(b1).isEqualTo(b2)
+            assertThat(thumbnailLoader.invokeCalls).hasSize(1)
+        }
+
+    @Test
+    fun test_cachingRequestCancelledAndEvoked_imageLoadingCancelled() =
+        scope.runTest {
+            val uriOne = createUri(1)
+            val uriTwo = createUri(2)
+            val loadingStartedDeferred = CompletableDeferred<Unit>()
+            val cancelledRequests = mutableSetOf<Uri>()
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uriOne] = {
+                        loadingStartedDeferred.complete(Unit)
+                        try {
+                            awaitCancellation()
+                        } catch (e: CancellationException) {
+                            cancelledRequests.add(uriOne)
+                            throw e
+                        }
+                    }
+                    fakeInvoke[uriTwo] = { createBitmap(200, 200) }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    cacheSize = 1,
+                    defaultPreviewSize = 100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            val jobOne = launch { testSubject.invoke(uriOne, Size(200, 100)) }
+            loadingStartedDeferred.await()
+            jobOne.cancel()
+            scope.runCurrent()
+
+            assertThat(cancelledRequests).isEmpty()
+
+            // second URI should evict the first item from the cache
+            testSubject.invoke(uriTwo, Size(200, 100))
+
+            assertThat(thumbnailLoader.invokeCalls).hasSize(2)
+            assertThat(cancelledRequests).containsExactly(uriOne)
+        }
+
+    @Test
+    fun test_nonCachingRequestClientCancels_imageLoadingCancelled() =
+        scope.runTest {
+            val uri = createUri(1)
+            val loadingStartedDeferred = CompletableDeferred<Unit>()
+            val cancelledRequests = mutableSetOf<Uri>()
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = {
+                        loadingStartedDeferred.complete(Unit)
+                        try {
+                            awaitCancellation()
+                        } catch (e: CancellationException) {
+                            cancelledRequests.add(uri)
+                            throw e
+                        }
+                    }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    cacheSize = 1,
+                    defaultPreviewSize = 100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            val job = launch { testSubject.invoke(uri, Size(200, 100), caching = false) }
+            loadingStartedDeferred.await()
+            job.cancel()
+            scope.runCurrent()
+
+            assertThat(cancelledRequests).containsExactly(uri)
+        }
+
+    @Test
+    fun test_requestHigherResImage_newImageLoaded() =
+        scope.runTest {
+            val uri = createUri(0)
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = { size -> createBitmap(size.width, size.height) }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            val b1 = testSubject.invoke(uri, Size(100, 100))
+            val b2 = testSubject.invoke(uri, Size(200, 200))
+            assertThat(b1).isNotNull()
+            assertThat(b1!!.width).isEqualTo(100)
+            assertThat(b2).isNotNull()
+            assertThat(b2!!.width).isEqualTo(200)
+            assertThat(thumbnailLoader.invokeCalls).hasSize(2)
+        }
+
+    @Test
+    fun test_imageLoadingThrowsException_returnsNull() =
+        scope.runTest {
+            val uri = createUri(0)
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = { throw SecurityException("test") }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            val bitmap = testSubject.invoke(uri, Size(100, 100))
+            assertThat(bitmap).isNull()
+        }
+
+    @Test
+    fun test_requestHigherResImage_cancelsLowerResLoading() =
+        scope.runTest {
+            val uri = createUri(0)
+            val cancelledRequestCount = AtomicInteger(0)
+            val imageLoadingStarted = CompletableDeferred<Unit>()
+            val bitmapDeferred = CompletableDeferred<Bitmap>()
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = {
+                        imageLoadingStarted.complete(Unit)
+                        try {
+                            bitmapDeferred.await()
+                        } catch (e: CancellationException) {
+                            cancelledRequestCount.getAndIncrement()
+                            throw e
+                        }
+                    }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            val lowResSize = 100
+            val highResSize = 200
+            launch(start = CoroutineStart.UNDISPATCHED) {
+                testSubject.invoke(uri, Size(lowResSize, lowResSize))
+            }
+            imageLoadingStarted.await()
+            val result = async { testSubject.invoke(uri, Size(highResSize, highResSize)) }
+            runCurrent()
+            assertThat(cancelledRequestCount.get()).isEqualTo(1)
+
+            bitmapDeferred.complete(createBitmap(highResSize, highResSize))
+            val bitmap = result.await()
+            assertThat(bitmap).isNotNull()
+            assertThat(bitmap!!.width).isEqualTo(highResSize)
+            assertThat(thumbnailLoader.invokeCalls).hasSize(2)
+        }
+
+    @Test
+    fun test_requestLowerResImage_cachedHigherResImageReturned() =
+        scope.runTest {
+            val uri = createUri(0)
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = { size -> createBitmap(size.width, size.height) }
+                }
+            val lowResSize = 100
+            val highResSize = 200
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            val b1 = testSubject.invoke(uri, Size(highResSize, highResSize))
+            val b2 = testSubject.invoke(uri, Size(lowResSize, lowResSize))
+            assertThat(b1).isEqualTo(b2)
+            assertThat(b2!!.width).isEqualTo(highResSize)
+            assertThat(thumbnailLoader.invokeCalls).hasSize(1)
+        }
+
+    @Test
+    fun test_incorrectSizeRequested_defaultSizeIsUsed() =
+        scope.runTest {
+            val uri = createUri(0)
+            val defaultPreviewSize = 100
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = { size -> createBitmap(size.width, size.height) }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    cacheSize = 1,
+                    defaultPreviewSize,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            val b1 = testSubject(uri, Size(0, 0))
+            assertThat(b1!!.width).isEqualTo(defaultPreviewSize)
+
+            val largerImageSize = 200
+            val b2 = testSubject(uri, Size(largerImageSize, largerImageSize))
+            assertThat(b2!!.width).isEqualTo(largerImageSize)
+        }
+
+    @Test
+    fun test_prePopulateImages_cachesImagesUpToTheCacheSize() =
+        scope.runTest {
+            val previewSize = Size(100, 100)
+            val uris = List(2) { createUri(it) }
+            val loadingCount = AtomicInteger(0)
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    for (uri in uris) {
+                        fakeInvoke[uri] = { size ->
+                            loadingCount.getAndIncrement()
+                            createBitmap(size.width, size.height)
+                        }
+                    }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            testSubject.prePopulate(uris.map { it to previewSize })
+            runCurrent()
+
+            assertThat(loadingCount.get()).isEqualTo(1)
+            assertThat(thumbnailLoader.invokeCalls).containsExactly(uris[0])
+
+            testSubject(uris[0], previewSize)
+            runCurrent()
+
+            assertThat(loadingCount.get()).isEqualTo(1)
+        }
+
+    @Test
+    fun test_oldRecordEvictedFromTheCache() =
+        scope.runTest {
+            val previewSize = Size(100, 100)
+            val uriOne = createUri(1)
+            val uriTwo = createUri(2)
+            val requestsPerUri = HashMap<Uri, AtomicInteger>()
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    for (uri in arrayOf(uriOne, uriTwo)) {
+                        fakeInvoke[uri] = { size ->
+                            requestsPerUri.getOrPut(uri) { AtomicInteger() }.incrementAndGet()
+                            createBitmap(size.width, size.height)
+                        }
+                    }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            testSubject(uriOne, previewSize)
+            testSubject(uriTwo, previewSize)
+            testSubject(uriTwo, previewSize)
+            testSubject(uriOne, previewSize)
+
+            assertThat(requestsPerUri[uriOne]?.get()).isEqualTo(2)
+            assertThat(requestsPerUri[uriTwo]?.get()).isEqualTo(1)
+        }
+
+    @Test
+    fun test_doNotCacheNulls() =
+        scope.runTest {
+            val previewSize = Size(100, 100)
+            val uri = createUri(1)
+            val loadingCount = AtomicInteger(0)
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = {
+                        loadingCount.getAndIncrement()
+                        null
+                    }
+                }
+            val testSubject =
+                PreviewImageLoader(
+                    backgroundScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            testSubject(uri, previewSize)
+            testSubject(uri, previewSize)
+
+            assertThat(loadingCount.get()).isEqualTo(2)
+        }
+
+    @Test(expected = CancellationException::class)
+    fun invoke_onClosedImageLoaderScope_throwsCancellationException() =
+        scope.runTest {
+            val uri = createUri(1)
+            val thumbnailLoader = FakeThumbnailLoader().apply { fakeInvoke[uri] = { null } }
+            val imageLoaderScope = CoroutineScope(coroutineContext)
+            val testSubject =
+                PreviewImageLoader(
+                    imageLoaderScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+            imageLoaderScope.cancel()
+            testSubject(uri, Size(200, 200))
+        }
+
+    @Test(expected = CancellationException::class)
+    fun invoke_imageLoaderScopeClosedMidflight_throwsCancellationException() =
+        scope.runTest {
+            val uri = createUri(1)
+            val loadingStarted = CompletableDeferred<Unit>()
+            val bitmapDeferred = CompletableDeferred<Bitmap?>()
+            val thumbnailLoader =
+                FakeThumbnailLoader().apply {
+                    fakeInvoke[uri] = {
+                        loadingStarted.complete(Unit)
+                        bitmapDeferred.await()
+                    }
+                }
+            val imageLoaderScope = CoroutineScope(coroutineContext)
+            val testSubject =
+                PreviewImageLoader(
+                    imageLoaderScope,
+                    1,
+                    100,
+                    thumbnailLoader,
+                    StandardTestDispatcher(scope.testScheduler),
+                )
+
+            launch {
+                loadingStarted.await()
+                imageLoaderScope.cancel()
+            }
+            testSubject(uri, Size(200, 200))
+        }
+}
+
+private fun createUri(id: Int) = Uri.parse("content://org.pkg.app/image-$id.png")
+
+private fun createBitmap(width: Int, height: Int) =
+    Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/PayloadToggleCursorResolverTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/PayloadToggleCursorResolverTest.kt
index 5d81ec2a..f0813623 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/PayloadToggleCursorResolverTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/PayloadToggleCursorResolverTest.kt
@@ -30,9 +30,12 @@ import com.google.common.truth.Truth.assertWithMessage
 import kotlinx.coroutines.test.runTest
 import org.junit.Test
 import org.mockito.kotlin.any
+import org.mockito.kotlin.argumentCaptor
+import org.mockito.kotlin.capture
 import org.mockito.kotlin.doReturn
 import org.mockito.kotlin.eq
 import org.mockito.kotlin.mock
+import org.mockito.kotlin.verify
 
 class PayloadToggleCursorResolverTest {
     private val cursorUri = Uri.parse("content://org.pkg.app.extra")
@@ -101,6 +104,9 @@ class PayloadToggleCursorResolverTest {
             assertThat(row!!.uri).isEqualTo(uri)
             assertThat(row.previewSize).isEqualTo(Size(100, 50))
         }
+        val columnsCaptor = argumentCaptor<Array<String>>()
+        verify(fakeContentProvider).query(eq(cursorUri), columnsCaptor.capture(), any(), any())
+        assertThat(columnsCaptor.firstValue.toList()).containsExactly(URI, WIDTH, HEIGHT)
     }
 
     @Test
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractorTest.kt
index 48e43190..c4ba8105 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractorTest.kt
@@ -18,10 +18,13 @@
 
 package com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor
 
+import android.database.Cursor
 import android.database.MatrixCursor
 import android.net.Uri
 import android.provider.MediaStore.MediaColumns.HEIGHT
 import android.provider.MediaStore.MediaColumns.WIDTH
+import android.service.chooser.AdditionalContentContract.Columns.URI
+import android.service.chooser.AdditionalContentContract.CursorExtraKeys.POSITION
 import android.util.Size
 import androidx.core.os.bundleOf
 import com.android.intentresolver.contentpreview.FileInfo
@@ -39,6 +42,7 @@ import com.android.intentresolver.util.cursor.CursorView
 import com.android.intentresolver.util.cursor.viewBy
 import com.android.intentresolver.util.runTest
 import com.android.systemui.kosmos.Kosmos
+import com.google.common.truth.Correspondence
 import com.google.common.truth.Truth.assertThat
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.launch
@@ -93,9 +97,9 @@ class CursorPreviewsInteractorTest {
         private val cursorSizes: Map<Int, Size>,
     ) {
         val cursor: CursorView<CursorRow?> =
-            MatrixCursor(arrayOf("uri", WIDTH, HEIGHT))
+            MatrixCursor(arrayOf(URI, WIDTH, HEIGHT))
                 .apply {
-                    extras = bundleOf("position" to cursorStartPosition)
+                    extras = bundleOf(POSITION to cursorStartPosition)
                     for (i in cursorRange) {
                         val size = cursorSizes[i]
                         addRow(
@@ -279,22 +283,83 @@ class CursorPreviewsInteractorTest {
         ) { deps ->
             previewSelectionsRepository.selections.value =
                 PreviewModel(
-                    uri = uri(1),
-                    mimeType = "image/png",
-                    order = 0,
-                ).let { mapOf(it.uri to it) }
+                        uri = uri(1),
+                        mimeType = "image/png",
+                        order = 0,
+                    )
+                    .let { mapOf(it.uri to it) }
             backgroundScope.launch {
                 cursorPreviewsInteractor.launch(deps.cursor, deps.initialPreviews)
             }
             runCurrent()
 
-            assertThat(previewSelectionsRepository.selections.value.values).containsExactly(
-                PreviewModel(
-                    uri = uri(1),
-                    mimeType = "image/bitmap",
-                    order = 1,
+            assertThat(previewSelectionsRepository.selections.value.values)
+                .containsExactly(
+                    PreviewModel(
+                        uri = uri(1),
+                        mimeType = "image/bitmap",
+                        order = 1,
+                    )
+                )
+        }
+
+    @Test
+    fun testReadFailedPages() =
+        runTestWithDeps(
+            initialSelection = listOf(4),
+            cursor = emptyList(),
+            cursorStartPosition = 0,
+            pageSize = 2,
+            maxLoadedPages = 5,
+        ) { deps ->
+            val cursor =
+                MatrixCursor(arrayOf(URI)).apply {
+                    extras = bundleOf(POSITION to 4)
+                    for (i in 0 until 10) {
+                        addRow(arrayOf(uri(i)))
+                    }
+                }
+            val failingPositions = setOf(1, 5, 8)
+            val failingCursor =
+                object : Cursor by cursor {
+                        override fun move(offset: Int): Boolean = moveToPosition(position + offset)
+
+                        override fun moveToPosition(position: Int): Boolean {
+                            if (failingPositions.contains(position)) {
+                                throw RuntimeException(
+                                    "A test exception when moving the cursor to position $position"
+                                )
+                            }
+                            return cursor.moveToPosition(position)
+                        }
+
+                        override fun moveToFirst(): Boolean = moveToPosition(0)
+
+                        override fun moveToLast(): Boolean = moveToPosition(count - 1)
+
+                        override fun moveToNext(): Boolean = move(1)
+
+                        override fun moveToPrevious(): Boolean = move(-1)
+                    }
+                    .viewBy {
+                        getString(0)?.let { uriStr ->
+                            CursorRow(Uri.parse(uriStr), readSize(), position)
+                        }
+                    }
+            backgroundScope.launch {
+                cursorPreviewsInteractor.launch(failingCursor, deps.initialPreviews)
+            }
+            runCurrent()
+
+            assertThat(cursorPreviewsRepository.previewsModel.value).isNotNull()
+            assertThat(cursorPreviewsRepository.previewsModel.value!!.previewModels)
+                .comparingElementsUsing<PreviewModel, Uri>(
+                    Correspondence.transforming({ it.uri }, "has a Uri of")
+                )
+                .containsExactlyElementsIn(
+                    (0..7).filterNot { failingPositions.contains(it) }.map { uri(it) }
                 )
-            )
+                .inOrder()
         }
 }
 
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractorTest.kt
index f329b8a7..5d9ddbb6 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractorTest.kt
@@ -26,13 +26,16 @@ import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.Tar
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.targetIntentModifier
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.data.repository.chooserRequestRepository
+import com.android.intentresolver.logging.FakeEventLog
 import com.android.intentresolver.util.runKosmosTest
+import com.android.internal.logging.InstanceId
 import com.google.common.truth.Truth.assertThat
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.flow.first
 import org.junit.Test
 
 class SelectablePreviewInteractorTest {
+    private val eventLog = FakeEventLog(InstanceId.fakeInstanceId(0))
 
     @Test
     fun reflectPreviewRepo_initState() = runKosmosTest {
@@ -46,6 +49,7 @@ class SelectablePreviewInteractorTest {
                         order = 0,
                     ),
                 selectionInteractor = selectionInteractor,
+                eventLog = eventLog,
             )
         runCurrent()
 
@@ -64,6 +68,7 @@ class SelectablePreviewInteractorTest {
                         order = 0,
                     ),
                 selectionInteractor = selectionInteractor,
+                eventLog = eventLog,
             )
 
         assertThat(underTest.isSelected.first()).isFalse()
@@ -93,6 +98,7 @@ class SelectablePreviewInteractorTest {
                         order = 0,
                     ),
                 selectionInteractor = selectionInteractor,
+                eventLog = eventLog,
             )
 
         underTest.setSelected(true)
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt
index 87db243d..c8242333 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt
@@ -18,16 +18,24 @@ package com.android.intentresolver.contentpreview.payloadtoggle.domain.interacto
 
 import android.content.Intent
 import android.net.Uri
+import android.platform.test.annotations.DisableFlags
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
+import com.android.intentresolver.Flags
 import com.android.intentresolver.contentpreview.mimetypeClassifier
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.previewSelectionsRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.util.runKosmosTest
 import com.google.common.truth.Truth.assertThat
 import kotlinx.coroutines.flow.first
+import org.junit.Rule
 import org.junit.Test
 
 class SelectionInteractorTest {
+    @get:Rule val flagsRule = SetFlagsRule()
+
     @Test
+    @DisableFlags(Flags.FLAG_UNSELECT_FINAL_ITEM)
     fun singleSelection_removalPrevented() = runKosmosTest {
         val initialPreview =
             PreviewModel(
@@ -53,6 +61,33 @@ class SelectionInteractorTest {
         assertThat(underTest.selections.first()).containsExactly(initialPreview.uri)
     }
 
+    @Test
+    @EnableFlags(Flags.FLAG_UNSELECT_FINAL_ITEM)
+    fun singleSelection_itemRemovedNoPendingIntentUpdates() = runKosmosTest {
+        val initialPreview =
+            PreviewModel(
+                uri = Uri.fromParts("scheme", "ssp", "fragment"),
+                mimeType = null,
+                order = 0
+            )
+        previewSelectionsRepository.selections.value = mapOf(initialPreview.uri to initialPreview)
+
+        val underTest =
+            SelectionInteractor(
+                previewSelectionsRepository,
+                { Intent() },
+                updateTargetIntentInteractor,
+                mimetypeClassifier,
+            )
+
+        assertThat(underTest.selections.first()).containsExactly(initialPreview.uri)
+
+        underTest.unselect(initialPreview)
+
+        assertThat(underTest.selections.first()).isEmpty()
+        assertThat(previewSelectionsRepository.selections.value).isEmpty()
+    }
+
     @Test
     fun multipleSelections_removalAllowed() = runKosmosTest {
         val first =
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractorTest.kt
index 570c346c..32d040fe 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractorTest.kt
@@ -18,7 +18,11 @@
 
 package com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor
 
+import android.content.ComponentName
 import android.content.Intent
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
+import com.android.intentresolver.Flags.FLAG_SHAREOUSEL_UPDATE_EXCLUDE_COMPONENTS_EXTRA
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.pendingSelectionCallbackRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ShareouselUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
@@ -29,9 +33,12 @@ import com.android.intentresolver.util.runKosmosTest
 import com.google.common.truth.Truth.assertThat
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.launch
+import org.junit.Rule
 import org.junit.Test
 
 class UpdateChooserRequestInteractorTest {
+    @get:Rule val setFlagsRule = SetFlagsRule()
+
     @Test
     fun updateTargetIntentWithSelection() = runKosmosTest {
         val selectionCallbackResult = ShareouselUpdate(metadataText = ValueUpdate.Value("update"))
@@ -45,4 +52,21 @@ class UpdateChooserRequestInteractorTest {
         assertThat(pendingSelectionCallbackRepository.pendingTargetIntent.value).isNull()
         assertThat(chooserRequestRepository.chooserRequest.value.metadataText).isEqualTo("update")
     }
+
+    @Test
+    @EnableFlags(FLAG_SHAREOUSEL_UPDATE_EXCLUDE_COMPONENTS_EXTRA)
+    fun testSelectionResultWithExcludedComponents_chooserRequestIsUpdated() = runKosmosTest {
+        val excludedComponent = ComponentName("org.pkg.app", "Class")
+        val selectionCallbackResult =
+            ShareouselUpdate(excludeComponents = ValueUpdate.Value(listOf(excludedComponent)))
+        selectionChangeCallback = SelectionChangeCallback { selectionCallbackResult }
+
+        backgroundScope.launch { processTargetIntentUpdatesInteractor.activate() }
+
+        updateTargetIntentInteractor.updateTargetIntent(Intent())
+        runCurrent()
+
+        assertThat(chooserRequestRepository.chooserRequest.value.filteredComponentNames)
+            .containsExactly(excludedComponent)
+    }
 }
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackImplTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackImplTest.kt
index 91bbd151..c1a1833a 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackImplTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackImplTest.kt
@@ -29,32 +29,34 @@ import android.content.Intent.EXTRA_CHOOSER_MODIFY_SHARE_ACTION
 import android.content.Intent.EXTRA_CHOOSER_REFINEMENT_INTENT_SENDER
 import android.content.Intent.EXTRA_CHOOSER_RESULT_INTENT_SENDER
 import android.content.Intent.EXTRA_CHOOSER_TARGETS
+import android.content.Intent.EXTRA_EXCLUDE_COMPONENTS
 import android.content.Intent.EXTRA_INTENT
 import android.content.Intent.EXTRA_METADATA_TEXT
 import android.content.Intent.EXTRA_STREAM
 import android.graphics.drawable.Icon
 import android.net.Uri
 import android.os.Bundle
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
 import android.service.chooser.AdditionalContentContract.MethodNames.ON_SELECTION_CHANGED
 import android.service.chooser.ChooserAction
 import android.service.chooser.ChooserTarget
-import android.service.chooser.Flags
 import androidx.test.ext.junit.runners.AndroidJUnit4
 import androidx.test.platform.app.InstrumentationRegistry
+import com.android.intentresolver.Flags.FLAG_SHAREOUSEL_UPDATE_EXCLUDE_COMPONENTS_EXTRA
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate.Absent
-import com.android.intentresolver.inject.FakeChooserServiceFlags
 import com.google.common.truth.Correspondence
 import com.google.common.truth.Correspondence.BinaryPredicate
 import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.Truth.assertWithMessage
 import java.lang.IllegalArgumentException
 import kotlinx.coroutines.test.runTest
+import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
 import org.mockito.kotlin.any
 import org.mockito.kotlin.argumentCaptor
-import org.mockito.kotlin.capture
 import org.mockito.kotlin.mock
 import org.mockito.kotlin.times
 import org.mockito.kotlin.verify
@@ -62,20 +64,16 @@ import org.mockito.kotlin.whenever
 
 @RunWith(AndroidJUnit4::class)
 class SelectionChangeCallbackImplTest {
+    @get:Rule val setFlagsRule = SetFlagsRule()
+
     private val uri = Uri.parse("content://org.pkg/content-provider")
     private val chooserIntent = Intent(ACTION_CHOOSER)
     private val contentResolver = mock<ContentInterface>()
     private val context = InstrumentationRegistry.getInstrumentation().context
-    private val flags =
-        FakeChooserServiceFlags().apply {
-            setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, false)
-            setFlag(Flags.FLAG_CHOOSER_ALBUM_TEXT, false)
-            setFlag(Flags.FLAG_ENABLE_SHARESHEET_METADATA_EXTRA, false)
-        }
 
     @Test
     fun testPayloadChangeCallbackContact() = runTest {
-        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver, flags)
+        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver)
 
         val u1 = createUri(1)
         val u2 = createUri(2)
@@ -170,7 +168,7 @@ class SelectionChangeCallbackImplTest {
                 Bundle().apply { putParcelableArray(EXTRA_CHOOSER_CUSTOM_ACTIONS, arrayOf(a1, a2)) }
             )
 
-        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver, flags)
+        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver)
 
         val targetIntent = Intent(ACTION_SEND_MULTIPLE)
         val result = testSubject.onSelectionChanged(targetIntent)
@@ -187,6 +185,7 @@ class SelectionChangeCallbackImplTest {
         assertThat(result.refinementIntentSender).isEqualTo(Absent)
         assertThat(result.resultIntentSender).isEqualTo(Absent)
         assertThat(result.metadataText).isEqualTo(Absent)
+        assertThat(result.excludeComponents).isEqualTo(Absent)
     }
 
     @Test
@@ -208,7 +207,7 @@ class SelectionChangeCallbackImplTest {
                 Bundle().apply { putParcelable(EXTRA_CHOOSER_MODIFY_SHARE_ACTION, modifyShare) }
             )
 
-        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver, flags)
+        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver)
 
         val targetIntent = Intent(ACTION_SEND)
         val result = testSubject.onSelectionChanged(targetIntent)
@@ -227,6 +226,7 @@ class SelectionChangeCallbackImplTest {
         assertThat(result.refinementIntentSender).isEqualTo(Absent)
         assertThat(result.resultIntentSender).isEqualTo(Absent)
         assertThat(result.metadataText).isEqualTo(Absent)
+        assertThat(result.excludeComponents).isEqualTo(Absent)
     }
 
     @Test
@@ -243,7 +243,7 @@ class SelectionChangeCallbackImplTest {
                 Bundle().apply { putParcelableArray(EXTRA_ALTERNATE_INTENTS, alternateIntents) }
             )
 
-        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver, flags)
+        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver)
 
         val targetIntent = Intent(ACTION_SEND)
         val result = testSubject.onSelectionChanged(targetIntent)
@@ -268,6 +268,7 @@ class SelectionChangeCallbackImplTest {
         assertThat(result.refinementIntentSender).isEqualTo(Absent)
         assertThat(result.resultIntentSender).isEqualTo(Absent)
         assertThat(result.metadataText).isEqualTo(Absent)
+        assertThat(result.excludeComponents).isEqualTo(Absent)
     }
 
     @Test
@@ -293,7 +294,7 @@ class SelectionChangeCallbackImplTest {
                 Bundle().apply { putParcelableArray(EXTRA_CHOOSER_TARGETS, arrayOf(t1, t2)) }
             )
 
-        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver, flags)
+        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver)
 
         val targetIntent = Intent(ACTION_SEND)
         val result = testSubject.onSelectionChanged(targetIntent)
@@ -321,6 +322,7 @@ class SelectionChangeCallbackImplTest {
         assertThat(result.refinementIntentSender).isEqualTo(Absent)
         assertThat(result.resultIntentSender).isEqualTo(Absent)
         assertThat(result.metadataText).isEqualTo(Absent)
+        assertThat(result.excludeComponents).isEqualTo(Absent)
     }
 
     @Test
@@ -335,7 +337,7 @@ class SelectionChangeCallbackImplTest {
                 }
             )
 
-        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver, flags)
+        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver)
 
         val targetIntent = Intent(ACTION_SEND)
         val result = testSubject.onSelectionChanged(targetIntent)
@@ -348,6 +350,7 @@ class SelectionChangeCallbackImplTest {
         assertThat(result.refinementIntentSender.getOrThrow()).isNotNull()
         assertThat(result.resultIntentSender).isEqualTo(Absent)
         assertThat(result.metadataText).isEqualTo(Absent)
+        assertThat(result.excludeComponents).isEqualTo(Absent)
     }
 
     @Test
@@ -362,7 +365,7 @@ class SelectionChangeCallbackImplTest {
                 }
             )
 
-        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver, flags)
+        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver)
 
         val targetIntent = Intent(ACTION_SEND)
         val result = testSubject.onSelectionChanged(targetIntent)
@@ -375,15 +378,16 @@ class SelectionChangeCallbackImplTest {
         assertThat(result.refinementIntentSender).isEqualTo(Absent)
         assertThat(result.resultIntentSender.getOrThrow()).isNotNull()
         assertThat(result.metadataText).isEqualTo(Absent)
+        assertThat(result.excludeComponents).isEqualTo(Absent)
     }
 
     @Test
-    fun testPayloadChangeCallbackUpdatesMetadataTextWithDisabledFlag_noUpdates() = runTest {
+    fun testPayloadChangeCallbackUpdatesMetadataTextWithEnabledFlag_valueUpdated() = runTest {
         val metadataText = "[Metadata]"
         whenever(contentResolver.call(any<String>(), any(), any(), any()))
             .thenReturn(Bundle().apply { putCharSequence(EXTRA_METADATA_TEXT, metadataText) })
 
-        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver, flags)
+        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver)
 
         val targetIntent = Intent(ACTION_SEND)
         val result = testSubject.onSelectionChanged(targetIntent)
@@ -395,20 +399,26 @@ class SelectionChangeCallbackImplTest {
         assertThat(result.callerTargets).isEqualTo(Absent)
         assertThat(result.refinementIntentSender).isEqualTo(Absent)
         assertThat(result.resultIntentSender).isEqualTo(Absent)
-        assertThat(result.metadataText).isEqualTo(Absent)
+        assertThat(result.metadataText.getOrThrow()).isEqualTo(metadataText)
+        assertThat(result.excludeComponents).isEqualTo(Absent)
     }
 
     @Test
-    fun testPayloadChangeCallbackUpdatesMetadataTextWithEnabledFlag_valueUpdated() = runTest {
-        val metadataText = "[Metadata]"
-        flags.setFlag(Flags.FLAG_ENABLE_SHARESHEET_METADATA_EXTRA, true)
+    @EnableFlags(FLAG_SHAREOUSEL_UPDATE_EXCLUDE_COMPONENTS_EXTRA)
+    fun testPayloadChangeCallbackUpdatesExcludedComponents_valueUpdated() = runTest {
+        val excludedComponent = ComponentName("org.pkg.app", "org.pkg.app.TheClass")
         whenever(contentResolver.call(any<String>(), any(), any(), any()))
-            .thenReturn(Bundle().apply { putCharSequence(EXTRA_METADATA_TEXT, metadataText) })
+            .thenReturn(
+                Bundle().apply {
+                    putParcelableArray(EXTRA_EXCLUDE_COMPONENTS, arrayOf(excludedComponent))
+                }
+            )
 
-        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver, flags)
+        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver)
 
         val targetIntent = Intent(ACTION_SEND)
         val result = testSubject.onSelectionChanged(targetIntent)
+
         assertWithMessage("Callback result should not be null").that(result).isNotNull()
         requireNotNull(result)
         assertThat(result.customActions).isEqualTo(Absent)
@@ -417,12 +427,12 @@ class SelectionChangeCallbackImplTest {
         assertThat(result.callerTargets).isEqualTo(Absent)
         assertThat(result.refinementIntentSender).isEqualTo(Absent)
         assertThat(result.resultIntentSender).isEqualTo(Absent)
-        assertThat(result.metadataText.getOrThrow()).isEqualTo(metadataText)
+        assertThat(result.metadataText).isEqualTo(Absent)
+        assertThat(result.excludeComponents.getOrThrow()).containsExactly(excludedComponent)
     }
 
     @Test
     fun testPayloadChangeCallbackProvidesInvalidData_invalidDataIgnored() = runTest {
-        flags.setFlag(Flags.FLAG_ENABLE_SHARESHEET_METADATA_EXTRA, true)
         whenever(contentResolver.call(any<String>(), any(), any(), any()))
             .thenReturn(
                 Bundle().apply {
@@ -436,7 +446,7 @@ class SelectionChangeCallbackImplTest {
                 }
             )
 
-        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver, flags)
+        val testSubject = SelectionChangeCallbackImpl(uri, chooserIntent, contentResolver)
 
         val targetIntent = Intent(ACTION_SEND)
         val result = testSubject.onSelectionChanged(targetIntent)
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt
index bb67e084..fc7ac751 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt
@@ -76,23 +76,25 @@ class ShareouselViewModelTest {
             scope = viewModelScope,
         )
     }
+    private val previewHeight = 500
 
     @Test
     fun headline_images() = runTest {
         assertThat(shareouselViewModel.headline.first()).isEqualTo("FILES: 1")
         previewSelectionsRepository.selections.value =
             listOf(
-                PreviewModel(
-                    uri = Uri.fromParts("scheme", "ssp", "fragment"),
-                    mimeType = "image/png",
-                    order = 0,
-                ),
-                PreviewModel(
-                    uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
-                    mimeType = "image/jpeg",
-                    order = 1,
+                    PreviewModel(
+                        uri = Uri.fromParts("scheme", "ssp", "fragment"),
+                        mimeType = "image/png",
+                        order = 0,
+                    ),
+                    PreviewModel(
+                        uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
+                        mimeType = "image/jpeg",
+                        order = 1,
+                    )
                 )
-            ).associateBy { it.uri }
+                .associateBy { it.uri }
         runCurrent()
         assertThat(shareouselViewModel.headline.first()).isEqualTo("IMAGES: 2")
     }
@@ -101,17 +103,18 @@ class ShareouselViewModelTest {
     fun headline_videos() = runTest {
         previewSelectionsRepository.selections.value =
             listOf(
-                PreviewModel(
-                    uri = Uri.fromParts("scheme", "ssp", "fragment"),
-                    mimeType = "video/mpeg",
-                    order = 0,
-                ),
-                PreviewModel(
-                    uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
-                    mimeType = "video/mpeg",
-                    order = 1,
+                    PreviewModel(
+                        uri = Uri.fromParts("scheme", "ssp", "fragment"),
+                        mimeType = "video/mpeg",
+                        order = 0,
+                    ),
+                    PreviewModel(
+                        uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
+                        mimeType = "video/mpeg",
+                        order = 1,
+                    )
                 )
-            ).associateBy { it.uri }
+                .associateBy { it.uri }
         runCurrent()
         assertThat(shareouselViewModel.headline.first()).isEqualTo("VIDEOS: 2")
     }
@@ -120,17 +123,18 @@ class ShareouselViewModelTest {
     fun headline_mixed() = runTest {
         previewSelectionsRepository.selections.value =
             listOf(
-                PreviewModel(
-                    uri = Uri.fromParts("scheme", "ssp", "fragment"),
-                    mimeType = "image/jpeg",
-                    order = 0,
-                ),
-                PreviewModel(
-                    uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
-                    mimeType = "video/mpeg",
-                    order = 1,
+                    PreviewModel(
+                        uri = Uri.fromParts("scheme", "ssp", "fragment"),
+                        mimeType = "image/jpeg",
+                        order = 0,
+                    ),
+                    PreviewModel(
+                        uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
+                        mimeType = "video/mpeg",
+                        order = 1,
+                    )
                 )
-            ).associateBy { it.uri }
+                .associateBy { it.uri }
         runCurrent()
         assertThat(shareouselViewModel.headline.first()).isEqualTo("FILES: 2")
     }
@@ -194,6 +198,7 @@ class ShareouselViewModelTest {
                         mimeType = "video/mpeg",
                         order = 0,
                     ),
+                    previewHeight,
                     /* index = */ 1,
                     viewModelScope,
                 )
@@ -245,6 +250,7 @@ class ShareouselViewModelTest {
                         mimeType = "video/mpeg",
                         order = 1,
                     ),
+                    previewHeight,
                     /* index = */ 1,
                     viewModelScope,
                 )
@@ -308,10 +314,11 @@ class ShareouselViewModelTest {
         this.targetIntentModifier = targetIntentModifier
         previewSelectionsRepository.selections.value =
             PreviewModel(
-                uri = Uri.fromParts("scheme", "ssp", "fragment"),
-                mimeType = null,
-                order = 0,
-            ).let { mapOf(it.uri to it) }
+                    uri = Uri.fromParts("scheme", "ssp", "fragment"),
+                    mimeType = null,
+                    order = 0,
+                )
+                .let { mapOf(it.uri to it) }
         payloadToggleImageLoader =
             FakeImageLoader(
                 initialBitmaps =
@@ -340,6 +347,8 @@ class ShareouselViewModelTest {
                 override fun getVideosHeadline(count: Int): String = "VIDEOS: $count"
 
                 override fun getFilesHeadline(count: Int): String = "FILES: $count"
+
+                override fun getNotItemsSelectedHeadline() = "Select items to share"
             }
         // instantiate the view model, and then runCurrent() so that it is fully hydrated before
         // starting the test
diff --git a/tests/unit/src/com/android/intentresolver/logging/EventLogImplTest.java b/tests/unit/src/com/android/intentresolver/logging/EventLogImplTest.java
index feb277ea..528c4613 100644
--- a/tests/unit/src/com/android/intentresolver/logging/EventLogImplTest.java
+++ b/tests/unit/src/com/android/intentresolver/logging/EventLogImplTest.java
@@ -151,6 +151,45 @@ public final class EventLogImplTest {
                 /* reselection action provided */ eq(modifyShareProvided));
     }
 
+    @Test
+    public void shareStartedWithShareouselAndEnabledReportingFlag_imagePreviewTypeReported() {
+        final String packageName = "com.test.foo";
+        final String mimeType = "text/plain";
+        final int appProvidedDirectTargets = 123;
+        final int appProvidedAppTargets = 456;
+        final boolean workProfile = true;
+        final int previewType = ContentPreviewType.CONTENT_PREVIEW_PAYLOAD_SELECTION;
+        final String intentAction = Intent.ACTION_SENDTO;
+        final int numCustomActions = 3;
+        final boolean modifyShareProvided = true;
+
+        mChooserLogger.logShareStarted(
+                packageName,
+                mimeType,
+                appProvidedDirectTargets,
+                appProvidedAppTargets,
+                workProfile,
+                previewType,
+                intentAction,
+                numCustomActions,
+                modifyShareProvided);
+
+        verify(mFrameworkLog).write(
+                eq(FrameworkStatsLog.SHARESHEET_STARTED),
+                eq(SharesheetStartedEvent.SHARE_STARTED.getId()),
+                eq(packageName),
+                /* instanceId=*/ gt(0),
+                eq(mimeType),
+                eq(appProvidedDirectTargets),
+                eq(appProvidedAppTargets),
+                eq(workProfile),
+                eq(FrameworkStatsLog
+                        .SHARESHEET_STARTED__PREVIEW_TYPE__CONTENT_PREVIEW_TOGGLEABLE_MEDIA),
+                eq(FrameworkStatsLog.SHARESHEET_STARTED__INTENT_TYPE__INTENT_ACTION_SENDTO),
+                /* custom actions provided */ eq(numCustomActions),
+                /* reselection action provided */ eq(modifyShareProvided));
+    }
+
     @Test
     public void testLogShareTargetSelected() {
         final int targetType = EventLogImpl.SELECTION_TYPE_SERVICE;
diff --git a/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt b/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt
index fbdc062b..d11cb460 100644
--- a/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt
@@ -26,7 +26,12 @@ import android.content.pm.PackageManager.ApplicationInfoFlags
 import android.content.pm.ShortcutManager
 import android.os.UserHandle
 import android.os.UserManager
+import android.platform.test.annotations.DisableFlags
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
 import androidx.test.filters.SmallTest
+import com.android.intentresolver.Flags.FLAG_FIX_SHORTCUTS_FLASHING
+import com.android.intentresolver.Flags.FLAG_FIX_SHORTCUT_LOADER_JOB_LEAK
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.createAppTarget
 import com.android.intentresolver.createShareShortcutInfo
@@ -42,6 +47,7 @@ import org.junit.Assert.assertArrayEquals
 import org.junit.Assert.assertEquals
 import org.junit.Assert.assertFalse
 import org.junit.Assert.assertTrue
+import org.junit.Rule
 import org.junit.Test
 import org.mockito.kotlin.any
 import org.mockito.kotlin.argumentCaptor
@@ -56,6 +62,8 @@ import org.mockito.kotlin.whenever
 @OptIn(ExperimentalCoroutinesApi::class)
 @SmallTest
 class ShortcutLoaderTest {
+    @get:Rule val flagRule = SetFlagsRule()
+
     private val appInfo =
         ApplicationInfo().apply {
             enabled = true
@@ -316,6 +324,143 @@ class ShortcutLoaderTest {
             }
         }
 
+    @Test
+    @DisableFlags(FLAG_FIX_SHORTCUTS_FLASHING)
+    fun test_appPredictorNotResponding_noCallbackFromShortcutLoader() {
+        scope.runTest {
+            val shortcutManagerResult =
+                listOf(
+                    ShortcutManager.ShareShortcutInfo(matchingShortcutInfo, componentName),
+                    // mismatching shortcut
+                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
+                )
+            val shortcutManager =
+                mock<ShortcutManager> {
+                    on { getShareTargets(intentFilter) } doReturn shortcutManagerResult
+                }
+            whenever(context.getSystemService(Context.SHORTCUT_SERVICE)).thenReturn(shortcutManager)
+            val testSubject =
+                ShortcutLoader(
+                    context,
+                    backgroundScope,
+                    appPredictor,
+                    UserHandle.of(0),
+                    true,
+                    intentFilter,
+                    dispatcher,
+                    callback
+                )
+
+            testSubject.updateAppTargets(appTargets)
+
+            verify(appPredictor, times(1)).requestPredictionUpdate()
+
+            scheduler.advanceTimeBy(ShortcutLoader.APP_PREDICTOR_RESPONSE_TIMEOUT_MS * 2)
+            verify(callback, never()).accept(any())
+        }
+    }
+
+    @Test
+    @EnableFlags(FLAG_FIX_SHORTCUTS_FLASHING)
+    fun test_appPredictorNotResponding_timeoutAndFallbackToShortcutManager() {
+        scope.runTest {
+            val testSubject =
+                ShortcutLoader(
+                    context,
+                    backgroundScope,
+                    appPredictor,
+                    UserHandle.of(0),
+                    true,
+                    intentFilter,
+                    dispatcher,
+                    callback
+                )
+
+            testSubject.updateAppTargets(appTargets)
+
+            val matchingAppTarget = createAppTarget(matchingShortcutInfo)
+            val shortcuts =
+                listOf(
+                    matchingAppTarget,
+                    // an AppTarget that does not belong to any resolved application; should be
+                    // ignored
+                    createAppTarget(
+                        createShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
+                    )
+                )
+            val appPredictorCallbackCaptor = argumentCaptor<AppPredictor.Callback>()
+            verify(appPredictor, atLeastOnce())
+                .registerPredictionUpdates(any(), appPredictorCallbackCaptor.capture())
+            appPredictorCallbackCaptor.firstValue.onTargetsAvailable(shortcuts)
+
+            scheduler.advanceTimeBy(ShortcutLoader.APP_PREDICTOR_RESPONSE_TIMEOUT_MS * 2)
+            verify(callback, times(1)).accept(any())
+        }
+    }
+
+    @Test
+    @EnableFlags(FLAG_FIX_SHORTCUTS_FLASHING)
+    fun test_appPredictorResponding_appPredictorTimeoutJobIsCancelled() {
+        scope.runTest {
+            val shortcutManagerResult =
+                listOf(
+                    ShortcutManager.ShareShortcutInfo(matchingShortcutInfo, componentName),
+                    // mismatching shortcut
+                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
+                )
+            val shortcutManager =
+                mock<ShortcutManager> {
+                    on { getShareTargets(intentFilter) } doReturn shortcutManagerResult
+                }
+            whenever(context.getSystemService(Context.SHORTCUT_SERVICE)).thenReturn(shortcutManager)
+            val testSubject =
+                ShortcutLoader(
+                    context,
+                    backgroundScope,
+                    appPredictor,
+                    UserHandle.of(0),
+                    true,
+                    intentFilter,
+                    dispatcher,
+                    callback
+                )
+
+            testSubject.updateAppTargets(appTargets)
+
+            verify(appPredictor, times(1)).requestPredictionUpdate()
+
+            scheduler.advanceTimeBy(ShortcutLoader.APP_PREDICTOR_RESPONSE_TIMEOUT_MS / 2)
+            verify(callback, never()).accept(any())
+
+            val resultCaptor = argumentCaptor<ShortcutLoader.Result>()
+            scheduler.advanceTimeBy(ShortcutLoader.APP_PREDICTOR_RESPONSE_TIMEOUT_MS)
+            verify(callback, times(1)).accept(resultCaptor.capture())
+            val result = resultCaptor.firstValue
+            assertWithMessage("An ShortcutManager result is expected")
+                .that(result.isFromAppPredictor)
+                .isFalse()
+            assertWithMessage("Wrong input app targets in the result")
+                .that(appTargets)
+                .asList()
+                .containsExactlyElementsIn(result.appTargets)
+                .inOrder()
+            assertWithMessage("Wrong shortcut count").that(result.shortcutsByApp).hasLength(1)
+            assertWithMessage("Wrong app target")
+                .that(appTarget)
+                .isEqualTo(result.shortcutsByApp[0].appTarget)
+            for (shortcut in result.shortcutsByApp[0].shortcuts) {
+                assertWithMessage(
+                        "AppTargets are not expected the cache of a ShortcutManager result"
+                    )
+                    .that(result.directShareAppTargetCache)
+                    .isEmpty()
+                assertWithMessage("Wrong ShortcutInfo in the cache")
+                    .that(matchingShortcutInfo)
+                    .isEqualTo(result.directShareShortcutInfoCache[shortcut])
+            }
+        }
+    }
+
     @Test
     fun test_ShortcutLoader_shortcutsRequestedIndependentlyFromAppTargets() =
         scope.runTest {
@@ -465,6 +610,30 @@ class ShortcutLoaderTest {
         testAlwaysCallSystemForMainProfile(isQuietModeEnabled = true)
     }
 
+    @Test
+    @EnableFlags(FLAG_FIX_SHORTCUT_LOADER_JOB_LEAK)
+    fun test_ShortcutLoaderDestroyed_appPredictorCallbackUnregisteredAndWatchdogCancelled() {
+        scope.runTest {
+            val testSubject =
+                ShortcutLoader(
+                    context,
+                    backgroundScope,
+                    appPredictor,
+                    UserHandle.of(0),
+                    true,
+                    intentFilter,
+                    dispatcher,
+                    callback
+                )
+
+            testSubject.updateAppTargets(appTargets)
+            testSubject.destroy()
+
+            verify(appPredictor, times(1)).registerPredictionUpdates(any(), any())
+            verify(appPredictor, times(1)).unregisterPredictionUpdates(any())
+        }
+    }
+
     private fun testDisabledWorkProfileDoNotCallSystem(
         isUserRunning: Boolean = true,
         isUserUnlocked: Boolean = true,
diff --git a/tests/unit/src/com/android/intentresolver/ui/ShareResultSenderImplTest.kt b/tests/unit/src/com/android/intentresolver/ui/ShareResultSenderImplTest.kt
index c254a856..7b43360a 100644
--- a/tests/unit/src/com/android/intentresolver/ui/ShareResultSenderImplTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ui/ShareResultSenderImplTest.kt
@@ -68,7 +68,7 @@ class ShareResultSenderImplTest {
                 intentDispatcher = intentDispatcher
             )
 
-        resultSender.onComponentSelected(ComponentName("example.com", "Foo"), true)
+        resultSender.onComponentSelected(ComponentName("example.com", "Foo"), true, false)
         runCurrent()
 
         val intentReceived = deferred.await()
@@ -83,6 +83,43 @@ class ShareResultSenderImplTest {
         assertThat(chooserResult?.isShortcut).isTrue()
     }
 
+    @OptIn(ExperimentalCoroutinesApi::class)
+    @EnableCompatChanges(ChooserResult.SEND_CHOOSER_RESULT)
+    @Test
+    fun onComponentSelected_crossProfile_chooserResultEnabled() = runTest {
+        val pi = PendingIntent.getBroadcast(context, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
+        val deferred = CompletableDeferred<Intent>()
+        val intentDispatcher = IntentSenderDispatcher { _, intent -> deferred.complete(intent) }
+
+        flags.setFlag(Flags.FLAG_ENABLE_CHOOSER_RESULT, true)
+
+        val resultSender =
+            ShareResultSenderImpl(
+                flags = flags,
+                scope = this,
+                backgroundDispatcher = UnconfinedTestDispatcher(testScheduler),
+                callerUid = Process.myUid(),
+                resultSender = pi.intentSender,
+                intentDispatcher = intentDispatcher
+            )
+
+        // Invoke as in the previous test, but this time say that the selection was cross-profile.
+        resultSender.onComponentSelected(ComponentName("example.com", "Foo"), true, true)
+        runCurrent()
+
+        val intentReceived = deferred.await()
+        val chooserResult =
+            intentReceived.getParcelableExtra(
+                Intent.EXTRA_CHOOSER_RESULT,
+                ChooserResult::class.java
+            )
+        assertThat(chooserResult).isNotNull()
+        assertThat(chooserResult?.type).isEqualTo(ChooserResult.CHOOSER_RESULT_UNKNOWN)
+        assertThat(chooserResult?.selectedComponent).isNull()
+        assertThat(chooserResult?.isShortcut).isTrue()
+        assertThat(intentReceived.hasExtra(Intent.EXTRA_CHOSEN_COMPONENT)).isFalse()
+    }
+
     @DisableCompatChanges(ChooserResult.SEND_CHOOSER_RESULT)
     @Test
     fun onComponentSelected_chooserResultDisabled() = runTest {
@@ -102,7 +139,7 @@ class ShareResultSenderImplTest {
                 intentDispatcher = intentDispatcher
             )
 
-        resultSender.onComponentSelected(ComponentName("example.com", "Foo"), true)
+        resultSender.onComponentSelected(ComponentName("example.com", "Foo"), true, false)
         runCurrent()
 
         val intentReceived = deferred.await()
@@ -121,6 +158,33 @@ class ShareResultSenderImplTest {
             .isFalse()
     }
 
+    @DisableCompatChanges(ChooserResult.SEND_CHOOSER_RESULT)
+    @Test
+    fun onComponentSelected_crossProfile_chooserResultDisabled() = runTest {
+        val pi = PendingIntent.getBroadcast(context, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
+        val deferred = CompletableDeferred<Intent>()
+        val intentDispatcher = IntentSenderDispatcher { _, intent -> deferred.complete(intent) }
+
+        flags.setFlag(Flags.FLAG_ENABLE_CHOOSER_RESULT, true)
+
+        val resultSender =
+            ShareResultSenderImpl(
+                flags = flags,
+                scope = this,
+                backgroundDispatcher = UnconfinedTestDispatcher(testScheduler),
+                callerUid = Process.myUid(),
+                resultSender = pi.intentSender,
+                intentDispatcher = intentDispatcher
+            )
+
+        // Invoke as in the previous test, but this time say that the selection was cross-profile.
+        resultSender.onComponentSelected(ComponentName("example.com", "Foo"), true, true)
+        runCurrent()
+
+        // In the pre-ChooserResult API, no callback intent is sent for cross-profile selections.
+        assertWithMessage("deferred result isComplete").that(deferred.isCompleted).isFalse()
+    }
+
     @EnableCompatChanges(ChooserResult.SEND_CHOOSER_RESULT)
     @Test
     fun onActionSelected_chooserResultEnabled() = runTest {
diff --git a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
index 56c019fd..01904c7f 100644
--- a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
@@ -25,6 +25,8 @@ import android.content.Intent.EXTRA_CHOOSER_ADDITIONAL_CONTENT_URI
 import android.content.Intent.EXTRA_CHOOSER_FOCUSED_ITEM_POSITION
 import android.content.Intent.EXTRA_INTENT
 import android.content.Intent.EXTRA_REFERRER
+import android.content.Intent.EXTRA_TEXT
+import android.content.Intent.EXTRA_TITLE
 import android.net.Uri
 import android.service.chooser.Flags
 import androidx.core.net.toUri
@@ -58,11 +60,7 @@ private fun createActivityModel(
 class ChooserRequestTest {
 
     private val fakeChooserServiceFlags =
-        FakeChooserServiceFlags().apply {
-            setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, false)
-            setFlag(Flags.FLAG_CHOOSER_ALBUM_TEXT, false)
-            setFlag(Flags.FLAG_ENABLE_SHARESHEET_METADATA_EXTRA, false)
-        }
+        FakeChooserServiceFlags().apply { setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, false) }
 
     @Test
     fun missingIntent() {
@@ -244,7 +242,6 @@ class ChooserRequestTest {
 
     @Test
     fun testAlbumType() {
-        fakeChooserServiceFlags.setFlag(Flags.FLAG_CHOOSER_ALBUM_TEXT, true)
         val model = createActivityModel(Intent(ACTION_SEND))
         model.intent.putExtra(
             Intent.EXTRA_CHOOSER_CONTENT_TYPE_HINT,
@@ -261,8 +258,8 @@ class ChooserRequestTest {
     }
 
     @Test
-    fun metadataText_whenFlagFalse_isNull() {
-        fakeChooserServiceFlags.setFlag(Flags.FLAG_ENABLE_SHARESHEET_METADATA_EXTRA, false)
+    fun metadataText_isPassedText() {
+        // Arrange
         val metadataText: CharSequence = "Test metadata text"
         val model =
             createActivityModel(targetIntent = Intent()).apply {
@@ -274,24 +271,26 @@ class ChooserRequestTest {
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
 
-        assertThat(result.value.metadataText).isNull()
+        assertThat(result.value.metadataText).isEqualTo(metadataText)
     }
 
     @Test
-    fun metadataText_whenFlagTrue_isPassedText() {
-        // Arrange
-        fakeChooserServiceFlags.setFlag(Flags.FLAG_ENABLE_SHARESHEET_METADATA_EXTRA, true)
-        val metadataText: CharSequence = "Test metadata text"
-        val model =
-            createActivityModel(targetIntent = Intent()).apply {
-                intent.putExtra(Intent.EXTRA_METADATA_TEXT, metadataText)
+    fun textSharedTextAndTitle() {
+        val text: CharSequence = "Shared text"
+        val title: CharSequence = "Title"
+        val targetIntent =
+            Intent().apply {
+                putExtra(EXTRA_TITLE, title)
+                putExtra(EXTRA_TEXT, text)
             }
+        val model = createActivityModel(targetIntent)
 
         val result = readChooserRequest(model, fakeChooserServiceFlags)
 
         assertThat(result).isInstanceOf(Valid::class.java)
-        result as Valid<ChooserRequest>
-
-        assertThat(result.value.metadataText).isEqualTo(metadataText)
+        (result as Valid<ChooserRequest>).value.let { request ->
+            assertThat(request.sharedText).isEqualTo(text)
+            assertThat(request.sharedTextTitle).isEqualTo(title)
+        }
     }
 }
diff --git a/tests/unit/src/com/android/intentresolver/widget/BatchPreviewLoaderTest.kt b/tests/unit/src/com/android/intentresolver/widget/BatchPreviewLoaderTest.kt
index 4f4223c0..b1e8593d 100644
--- a/tests/unit/src/com/android/intentresolver/widget/BatchPreviewLoaderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/widget/BatchPreviewLoaderTest.kt
@@ -18,6 +18,7 @@ package com.android.intentresolver.widget
 
 import android.graphics.Bitmap
 import android.net.Uri
+import android.util.Size
 import com.android.intentresolver.captureMany
 import com.android.intentresolver.mock
 import com.android.intentresolver.widget.ScrollableImagePreviewView.BatchPreviewLoader
@@ -49,6 +50,7 @@ class BatchPreviewLoaderTest {
     private val testScope = CoroutineScope(dispatcher)
     private val onCompletion = mock<() -> Unit>()
     private val onUpdate = mock<(List<Preview>) -> Unit>()
+    private val previewSize = Size(500, 500)
 
     @Before
     fun setup() {
@@ -71,6 +73,7 @@ class BatchPreviewLoaderTest {
             BatchPreviewLoader(
                 imageLoader,
                 previews(uriOne, uriTwo),
+                previewSize,
                 totalItemCount = 2,
                 onUpdate,
                 onCompletion
@@ -94,6 +97,7 @@ class BatchPreviewLoaderTest {
             BatchPreviewLoader(
                 imageLoader,
                 previews(uriOne, uriTwo, uriThree),
+                previewSize,
                 totalItemCount = 3,
                 onUpdate,
                 onCompletion
@@ -122,7 +126,14 @@ class BatchPreviewLoaderTest {
             }
         imageLoader.setUriLoadingOrder(*loadingOrder)
         val testSubject =
-            BatchPreviewLoader(imageLoader, previews(*uris), uris.size, onUpdate, onCompletion)
+            BatchPreviewLoader(
+                imageLoader,
+                previews(*uris),
+                previewSize,
+                uris.size,
+                onUpdate,
+                onCompletion
+            )
         testSubject.loadAspectRatios(200) { _, _, _ -> 100 }
         dispatcher.scheduler.advanceUntilIdle()
 
@@ -151,7 +162,14 @@ class BatchPreviewLoaderTest {
         val expectedUris = Array(uris.size / 2) { createUri(it * 2 + 1) }
         imageLoader.setUriLoadingOrder(*loadingOrder)
         val testSubject =
-            BatchPreviewLoader(imageLoader, previews(*uris), uris.size, onUpdate, onCompletion)
+            BatchPreviewLoader(
+                imageLoader,
+                previews(*uris),
+                previewSize,
+                uris.size,
+                onUpdate,
+                onCompletion
+            )
         testSubject.loadAspectRatios(200) { _, _, _ -> 100 }
         dispatcher.scheduler.advanceUntilIdle()
 
@@ -166,7 +184,9 @@ class BatchPreviewLoaderTest {
     private fun createUri(idx: Int): Uri = Uri.parse("content://org.pkg.app/image-$idx.png")
 
     private fun fail(uri: Uri) = uri to false
+
     private fun succeed(uri: Uri) = uri to true
+
     private fun previews(vararg uris: Uri) =
         uris
             .fold(ArrayList<Preview>(uris.size)) { acc, uri ->
@@ -175,7 +195,7 @@ class BatchPreviewLoaderTest {
             .asFlow()
 }
 
-private class TestImageLoader(scope: CoroutineScope) : suspend (Uri, Boolean) -> Bitmap? {
+private class TestImageLoader(scope: CoroutineScope) : suspend (Uri, Size, Boolean) -> Bitmap? {
     private val loadingOrder = ArrayDeque<Pair<Uri, Boolean>>()
     private val pendingRequests = LinkedHashMap<Uri, CompletableDeferred<Bitmap?>>()
     private val flow = MutableSharedFlow<Unit>(replay = 1)
@@ -203,7 +223,7 @@ private class TestImageLoader(scope: CoroutineScope) : suspend (Uri, Boolean) ->
         loadingOrder.addAll(uris)
     }
 
-    override suspend fun invoke(uri: Uri, cache: Boolean): Bitmap? {
+    override suspend fun invoke(uri: Uri, size: Size, cache: Boolean): Bitmap? {
         val deferred = pendingRequests.getOrPut(uri) { CompletableDeferred() }
         flow.tryEmit(Unit)
         return deferred.await()
```

