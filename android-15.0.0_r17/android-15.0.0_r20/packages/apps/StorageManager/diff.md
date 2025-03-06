```diff
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index f26a473..7700c94 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -57,11 +57,11 @@
     <string name="deletion_helper_photos_loading_title" msgid="2768067991066779772">"Babeskopiak dituzten argazki eta bideoak"</string>
     <string name="deletion_helper_photos_loading_summary" msgid="8203033249458245854">"Elementuak bilatzen…"</string>
     <string name="deletion_helper_no_threshold" msgid="6943179204098250444">"Erakutsi elementu guztiak"</string>
-    <string name="deletion_helper_default_threshold" msgid="8410389370069021113">"Ezkutatu azken elementuak"</string>
+    <string name="deletion_helper_default_threshold" msgid="8410389370069021113">"Ezkutatu azkenaldiko elementuak"</string>
     <string name="deletion_helper_clear_dialog_message_first_time" msgid="686530413183529901">"<xliff:g id="CLEARABLE_BYTES">%1$s</xliff:g> hartzen dituen edukia kenduko da gailutik"</string>
     <string name="automatic_storage_manager_activation_warning" msgid="7657017408180001078">"Biltegi-kudeatzailea ari da biltegia kudeatzen"</string>
     <string name="empty_state_title" msgid="4033285438176545309">"Ez dago kentzeko ezer"</string>
-    <string name="empty_state_review_items_link" msgid="8411186441239304545">"Berrikusi azken elementuak"</string>
+    <string name="empty_state_review_items_link" msgid="8411186441239304545">"Berrikusi azkenaldiko elementuak"</string>
     <string name="empty_state_summary" msgid="8439893007424243790">"Ez dago kentzeko fitxategi zaharrik. Tokia egiteko, kendu argazki, bideo edo aplikazio berriagoak."</string>
     <string name="app_requesting_space" msgid="857425181289960167">"<xliff:g id="APP">%1$s</xliff:g> aplikazioak <xliff:g id="CLEARABLE_BYTES">%2$s</xliff:g> behar ditu"</string>
 </resources>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 3fdfb52..c924ba1 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -24,7 +24,7 @@
     <!-- no translation found for deletion_helper_app_summary_item_size (3770886184921427886) -->
     <skip />
     <string name="deletion_helper_app_summary_never_used" msgid="2695210890063792461">"ଗତ ବର୍ଷ ବ୍ୟବହାର ହୋଇନାହିଁ"</string>
-    <string name="deletion_helper_app_summary_unknown_used" msgid="8576377054665785558">"ଶେଷଥର କେବେ ବ୍ୟବହାର ହୋଇଛି କହି ହେଉନାହିଁ"</string>
+    <string name="deletion_helper_app_summary_unknown_used" msgid="8576377054665785558">"ଗତଥର କେବେ ବ୍ୟବହାର ହୋଇଛି କହି ହେଉନାହିଁ"</string>
     <string name="deletion_helper_free_button" msgid="1760529213407548661">"<xliff:g id="FREEABLE">%1$s</xliff:g> ଜାଗା ଖାଲି କରନ୍ତୁ"</string>
     <string name="deletion_helper_photos_title" msgid="2602723121486729972">"ବ୍ୟାକଅପ୍‌ ନିଆଯାଇଥିବା ଫଟୋ ଓ ଭିଡିଓ"</string>
     <string name="deletion_helper_photos_age_summary" msgid="1820871709448371984">"30 ଦିନରୁ ଅଧିକ ପୁରୁଣା"</string>
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index cd33396..2b68b7a 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -3,6 +3,11 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+filegroup {
+    name: "StorageManagerUnitTests_src",
+    srcs: ["src/**/*.java"],
+}
+
 android_test {
     name: "StorageManagerUnitTests",
 
```

