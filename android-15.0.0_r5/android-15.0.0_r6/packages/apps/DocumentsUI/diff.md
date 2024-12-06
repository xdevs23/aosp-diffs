```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 76802342e..be98d1d08 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -33,6 +33,7 @@
     <uses-permission android:name="android.permission.MODIFY_QUIET_MODE" />
     <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
     <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
+    <uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS"/>
 
     <!-- Permissions required for reading and logging compat changes -->
     <uses-permission android:name="android.permission.LOG_COMPAT_CHANGE"/>
diff --git a/app-perf-tests/Android.bp b/app-perf-tests/Android.bp
index 5a4bf72a4..2d4bc0611 100644
--- a/app-perf-tests/Android.bp
+++ b/app-perf-tests/Android.bp
@@ -12,8 +12,8 @@ android_test {
     ],
 
     libs: [
-        "android.test.base",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.runner.stubs.system",
     ],
 
     static_libs: [
diff --git a/perf-tests/Android.bp b/perf-tests/Android.bp
index 4cf6c6508..1559227b6 100644
--- a/perf-tests/Android.bp
+++ b/perf-tests/Android.bp
@@ -16,9 +16,9 @@ android_test {
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
diff --git a/proguard.flags b/proguard.flags
index 2390e8f56..a0f96ae09 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -25,10 +25,178 @@
 # To prevent class not found exception in org.brotli.dec.Dictionary
 -keep final class org.brotli.dec.DictionaryData
 
-# To prevent resource fields not found exception on running DocumentsUIGoogleTests module
--keepclassmembers class com.android.documentsui.R$* {
-    public static <fields>;
+# keep rule generated after running trace references on the test app against DocumentsUIGoogle.jar
+# TODO(b/339312616): Remove after a more permanent fix is available
+# On modifying or adding new test run the following command to generate new keep rules and replace
+# the once listed below with the newly generated keep rules:
+# java -cp prebuilts/r8/r8.jar com.android.tools.r8.tracereferences.TraceReferences \
+# --lib out/soong/.intermediates/frameworks/base/framework/android_common/<some_hash>/combined/framework.jar \
+# --source out/target/product/panther/testcases/DocumentsUIGoogleTests/arm64/DocumentsUIGoogleTests.apk \
+# --target  out/soong/.intermediates/vendor/unbundled_google/packages/DocumentsUIGoogle/DocumentsUIGoogle/android_common/<some_hash>/javac/DocumentsUIGoogle.jar \
+# --keep-rules \
+# --output /tmp/keep.txt
+
+-keep class androidx.appcompat.R$id {
+  int search_src_text;
+}
+-keep class com.android.documentsui.R$bool {
+  int feature_notification_channel;
+  int full_bar_search_view;
+  int is_launcher_enabled;
+  int show_search_bar;
+}
+-keep class com.android.documentsui.R$color {
+  int app_background_color;
+  int primary;
+}
+-keep class com.android.documentsui.R$dimen {
+  int grid_item_radius;
+}
+-keep class com.android.documentsui.R$drawable {
+  int ic_briefcase;
+  int ic_cab_cancel;
+  int ic_eject;
+  int ic_menu_copy;
+  int ic_root_download;
+  int ic_sd_storage;
+  int root_list_selector;
+  int work_off;
+}
+-keep class com.android.documentsui.R$id {
+  int action_menu_compress;
+  int action_menu_copy_to;
+  int action_menu_delete;
+  int action_menu_deselect_all;
+  int action_menu_extract_to;
+  int action_menu_inspect;
+  int action_menu_move_to;
+  int action_menu_open_with;
+  int action_menu_rename;
+  int action_menu_select;
+  int action_menu_select_all;
+  int action_menu_share;
+  int action_menu_sort;
+  int action_menu_view_in_owner;
+  int apps_group;
+  int apps_row;
+  int button;
+  int content;
+  int cross_profile;
+  int cross_profile_content;
+  int cross_profile_progress;
+  int dir_menu_copy_to_clipboard;
+  int dir_menu_create_dir;
+  int dir_menu_cut_to_clipboard;
+  int dir_menu_delete;
+  int dir_menu_deselect_all;
+  int dir_menu_inspect;
+  int dir_menu_open;
+  int dir_menu_open_in_new_window;
+  int dir_menu_open_with;
+  int dir_menu_paste_from_clipboard;
+  int dir_menu_paste_into_folder;
+  int dir_menu_rename;
+  int dir_menu_select_all;
+  int dir_menu_share;
+  int dir_menu_view_in_owner;
+  int drawer_layout;
+  int inspector_details_view;
+  int option_menu_create_dir;
+  int option_menu_debug;
+  int option_menu_inspect;
+  int option_menu_launcher;
+  int option_menu_new_window;
+  int option_menu_search;
+  int option_menu_select_all;
+  int option_menu_settings;
+  int option_menu_show_hidden_files;
+  int option_menu_sort;
+  int root_menu_eject_root;
+  int root_menu_open_in_new_window;
+  int root_menu_paste_into_folder;
+  int root_menu_settings;
+  int sub_menu_grid;
+  int sub_menu_list;
+  int table_header;
+  int tabs;
+  int tabs_container;
+  int toolbar;
+}
+-keep class com.android.documentsui.R$layout {
+  int apps_row;
+  int directory_header;
+  int files_activity;
+  int fixed_layout;
+  int item_doc_list;
+}
+-keep class com.android.documentsui.R$menu {
+  int dir_context_menu;
+  int file_context_menu;
+  int mixed_context_menu;
+}
+-keep class com.android.documentsui.R$plurals {
+  int copy_error_notification_title;
+  int elements_dragged;
+}
+-keep class com.android.documentsui.R$string {
+  int cant_select_work_files_error_message;
+  int cant_select_work_files_error_title;
+  int copy_notification_title;
+  int copy_preparing;
+  int copy_remaining;
+  int debug_content_uri;
+  int default_root_uri;
+  int directory_items;
+  int empty;
+  int menu_copy;
+  int menu_move;
+  int menu_rename;
+  int menu_select;
+  int menu_select_all;
+  int menu_sort;
+  int menu_view_in_owner;
+  int metadata_address;
+  int metadata_album;
+  int metadata_altitude;
+  int metadata_aperture;
+  int metadata_aperture_format;
+  int metadata_artist;
+  int metadata_camera;
+  int metadata_camera_format;
+  int metadata_composer;
+  int metadata_coordinates;
+  int metadata_coordinates_format;
+  int metadata_date_time;
+  int metadata_dimensions;
+  int metadata_dimensions_format;
+  int metadata_duration;
+  int metadata_focal_format;
+  int metadata_focal_length;
+  int metadata_iso_format;
+  int metadata_iso_speed_ratings;
+  int metadata_shutter_speed;
+  int name_conflict;
+  int no_results;
+  int personal_tab;
+  int preferred_root_package;
+  int quiet_mode_button;
+  int quiet_mode_error_title;
+  int rename_error;
+  int search_bar_hint;
+  int share_via;
+  int sort_dimension_date;
+  int sort_dimension_file_type;
+  int sort_dimension_name;
+  int sort_dimension_size;
+  int sort_direction_ascending;
+  int sort_direction_descending;
+  int trusted_quick_viewer_package;
+  int work_tab;
+}
+-keep class com.android.documentsui.R$style {
+  int DocumentsDefaultTheme;
+  int DocumentsTheme;
 }
 
 # Keep Apache Commons Compress classes
--keep class org.apache.commons.compress.** { *; }
\ No newline at end of file
+-keep class org.apache.commons.compress.** { *; }
diff --git a/res/layout-sw720dp/item_doc_list.xml b/res/layout-sw720dp/item_doc_list.xml
index 3013f3173..01cdd8c66 100644
--- a/res/layout-sw720dp/item_doc_list.xml
+++ b/res/layout-sw720dp/item_doc_list.xml
@@ -34,7 +34,7 @@
         android:orientation="horizontal" >
 
         <FrameLayout
-            android:id="@android:id/icon"
+            android:id="@+id/icon"
             android:pointerIcon="hand"
             android:layout_width="@dimen/list_item_width"
             android:layout_height="@dimen/list_item_height"
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 71fd03ef5..84917168f 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -103,7 +103,7 @@
     <string name="cant_select_cross_profile_files_error_title" msgid="17010948874969413">"يتعذّر اختيار ملفات <xliff:g id="PROFILE">%1$s</xliff:g>."</string>
     <string name="cant_select_cross_profile_files_error_message" msgid="3815829574883844944">"لا يسمح لك مشرف تكنولوجيا المعلومات في مؤسستك بالوصول إلى ملفات <xliff:g id="PROFILE_0">%1$s</xliff:g> من خلال تطبيق <xliff:g id="PROFILE_1">%2$s</xliff:g>."</string>
     <string name="cant_save_to_work_error_title" msgid="1351323070040641358">"لا يمكن حفظ الملفات في ملف العمل"</string>
-    <string name="cant_save_to_work_error_message" msgid="4975583233814059890">"لا يسمح لك مشرف تكنولوجيا المعلومات بحفظ الملفات الشخصية في ملفك الشخصي للعمل."</string>
+    <string name="cant_save_to_work_error_message" msgid="4975583233814059890">"لا يسمح لك مشرف تكنولوجيا المعلومات بحفظ الملفات الشخصية في ملف العمل الخاص بك."</string>
     <string name="cant_save_to_personal_error_title" msgid="858327493694069780">"لا يمكن حفظ الملفات في الملف الشخصي"</string>
     <string name="cant_save_to_personal_error_message" msgid="6991758723736381751">"لا يسمح لك مشرف تكنولوجيا المعلومات بحفظ ملفات العمل في ملفك الشخصي."</string>
     <string name="cant_save_to_cross_profile_error_title" msgid="5158984057654779022">"يتعذّر الحفظ في ملف <xliff:g id="PROFILE">%1$s</xliff:g>."</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 2313b503e..e1444b40b 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -94,7 +94,7 @@
     <string name="query_error" msgid="6625421453613879336">"Понастоящем съдържанието не може да се зареди"</string>
     <string name="quiet_mode_error_title" msgid="554319751414657910">"Служебните приложения са поставени на пауза"</string>
     <string name="quiet_mode_button" msgid="8051436551926677305">"Включване на служебните приложения"</string>
-    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"<xliff:g id="PROFILE">%1$s</xliff:g> приложения са поставени на пауза"</string>
+    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Приложенията от „<xliff:g id="PROFILE">%1$s</xliff:g>“ са поставени на пауза"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"Включване на <xliff:g id="PROFILE">%1$s</xliff:g> приложения"</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"Избирането на служебни файлове не е възможно"</string>
     <string name="cant_select_work_files_error_message" msgid="683480676150690641">"Системният ви администратор не разрешава достъпа до служебните ви файлове от лично приложение"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 645188d27..bb5627dbe 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -94,7 +94,7 @@
     <string name="query_error" msgid="6625421453613879336">"Trenutno nije moguće učitati sadržaj"</string>
     <string name="quiet_mode_error_title" msgid="554319751414657910">"Poslovne aplikacije su pauzirane"</string>
     <string name="quiet_mode_button" msgid="8051436551926677305">"Uključi poslovne aplikacije"</string>
-    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Aplikacije profila \"<xliff:g id="PROFILE">%1$s</xliff:g>\" su pauzirane"</string>
+    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Aplikacije profila <xliff:g id="PROFILE">%1$s</xliff:g> su pauzirane"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"Uključi aplikacije profila \"<xliff:g id="PROFILE">%1$s</xliff:g>\""</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"Nije moguće odabrati poslovne fajlove"</string>
     <string name="cant_select_work_files_error_message" msgid="683480676150690641">"IT administrator vam ne dozvoljava da pristupate poslovnim fajlovima iz lične aplikacije"</string>
diff --git a/res/values-es-rUS/inspector_strings.xml b/res/values-es-rUS/inspector_strings.xml
index f35859315..a5a479ca4 100644
--- a/res/values-es-rUS/inspector_strings.xml
+++ b/res/values-es-rUS/inspector_strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="inspector_title" msgid="1924760928091740238">"Información"</string>
     <string name="inspector_load_error" msgid="7522190243413249291">"No se pudo cargar la información del archivo"</string>
-    <string name="inspector_debug_section" msgid="2576052661505700421">"Información de depuración (solo programadores)"</string>
+    <string name="inspector_debug_section" msgid="2576052661505700421">"Información de depuración (solo desarrolladores)"</string>
     <string name="inspector_debug_metadata_section" msgid="5875140675600744846">"Metadatos RAW: <xliff:g id="METADATATYPE">%1$s</xliff:g>"</string>
     <string name="inspector_metadata_section" msgid="6077622515328240575">"Detalles del contenido multimedia"</string>
     <string name="handler_app_file_opens_with" msgid="5272329600389613550">"Este tipo de archivo se abre con"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 77f30a2ac..c7f1e717e 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -30,7 +30,7 @@
     <string name="menu_grid" msgid="1453636521731880680">"Vista de cuadrícula"</string>
     <string name="menu_list" msgid="6714267452146410402">"Vista de lista"</string>
     <string name="menu_search" msgid="1876699106790719849">"Buscar"</string>
-    <string name="menu_settings" msgid="6520844520117939047">"Opciones almacenamiento"</string>
+    <string name="menu_settings" msgid="6520844520117939047">"Opciones de almacenamiento"</string>
     <string name="menu_open" msgid="9092138100049759315">"Abrir"</string>
     <string name="menu_open_with" msgid="5507647065467520229">"Abrir con"</string>
     <string name="menu_open_in_new_window" msgid="6686563636123311276">"Abrir en ventana nueva"</string>
@@ -131,29 +131,29 @@
     <string name="delete_notification_title" msgid="2512757431856830792">"Borrando los archivos"</string>
     <string name="copy_remaining" msgid="5390517377265177727">"<xliff:g id="DURATION">%s</xliff:g> restantes"</string>
     <plurals name="copy_begin" formatted="false" msgid="151184708996738192">
-      <item quantity="many">Copiando <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
-      <item quantity="other">Copiando <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
-      <item quantity="one">Copiando <xliff:g id="COUNT_0">%1$d</xliff:g> elemento</item>
+      <item quantity="many">Copiando <xliff:g id="COUNT_1">%1$d</xliff:g> de elementos.</item>
+      <item quantity="other">Copiando <xliff:g id="COUNT_1">%1$d</xliff:g> elementos.</item>
+      <item quantity="one">Copiando <xliff:g id="COUNT_0">%1$d</xliff:g> elemento.</item>
     </plurals>
     <plurals name="compress_begin" formatted="false" msgid="3534158317098678895">
-      <item quantity="many">Comprimiendo <xliff:g id="COUNT_1">%1$d</xliff:g> archivos</item>
-      <item quantity="other">Comprimiendo <xliff:g id="COUNT_1">%1$d</xliff:g> archivos</item>
-      <item quantity="one">Comprimiendo <xliff:g id="COUNT_0">%1$d</xliff:g> archivo</item>
+      <item quantity="many">Comprimiendo <xliff:g id="COUNT_1">%1$d</xliff:g> de archivos.</item>
+      <item quantity="other">Comprimiendo <xliff:g id="COUNT_1">%1$d</xliff:g> archivos.</item>
+      <item quantity="one">Comprimiendo <xliff:g id="COUNT_0">%1$d</xliff:g> archivo.</item>
     </plurals>
     <plurals name="extract_begin" formatted="false" msgid="1006380679562903749">
-      <item quantity="many">Extrayendo <xliff:g id="COUNT_1">%1$d</xliff:g> archivos</item>
-      <item quantity="other">Extrayendo <xliff:g id="COUNT_1">%1$d</xliff:g> archivos</item>
-      <item quantity="one">Extrayendo <xliff:g id="COUNT_0">%1$d</xliff:g> archivo</item>
+      <item quantity="many">Extrayendo <xliff:g id="COUNT_1">%1$d</xliff:g> de archivos.</item>
+      <item quantity="other">Extrayendo <xliff:g id="COUNT_1">%1$d</xliff:g> archivos.</item>
+      <item quantity="one">Extrayendo <xliff:g id="COUNT_0">%1$d</xliff:g> archivo.</item>
     </plurals>
     <plurals name="move_begin" formatted="false" msgid="1464229874265756956">
-      <item quantity="many">Moviendo <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
-      <item quantity="other">Moviendo <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
-      <item quantity="one">Moviendo <xliff:g id="COUNT_0">%1$d</xliff:g> elemento</item>
+      <item quantity="many">Moviendo <xliff:g id="COUNT_1">%1$d</xliff:g> de elementos.</item>
+      <item quantity="other">Moviendo <xliff:g id="COUNT_1">%1$d</xliff:g> elementos.</item>
+      <item quantity="one">Moviendo <xliff:g id="COUNT_0">%1$d</xliff:g> elemento.</item>
     </plurals>
     <plurals name="deleting" formatted="false" msgid="1729138001178158901">
-      <item quantity="many">Borrando <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
-      <item quantity="other">Borrando <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
-      <item quantity="one">Borrando <xliff:g id="COUNT_0">%1$d</xliff:g> elemento</item>
+      <item quantity="many">Borrando <xliff:g id="COUNT_1">%1$d</xliff:g> de elementos.</item>
+      <item quantity="other">Borrando <xliff:g id="COUNT_1">%1$d</xliff:g> elementos.</item>
+      <item quantity="one">Borrando <xliff:g id="COUNT_0">%1$d</xliff:g> elemento.</item>
     </plurals>
     <string name="undo" msgid="2902438994196400565">"Deshacer"</string>
     <string name="copy_preparing" msgid="4759516490222449324">"Preparando…"</string>
@@ -163,22 +163,22 @@
     <string name="delete_preparing" msgid="7339349837842802508">"Preparando…"</string>
     <string name="delete_progress" msgid="2627631054702306423">"<xliff:g id="COUNT_0">%1$d</xliff:g>/<xliff:g id="TOTALCOUNT">%2$d</xliff:g>"</string>
     <plurals name="copy_error_notification_title" formatted="false" msgid="3188432450429390963">
-      <item quantity="many">No se pudieron copiar <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
+      <item quantity="many">No se pudieron copiar <xliff:g id="COUNT_1">%1$d</xliff:g> de elementos</item>
       <item quantity="other">No se pudieron copiar <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
       <item quantity="one">No se pudo copiar <xliff:g id="COUNT_0">%1$d</xliff:g> elemento</item>
     </plurals>
     <plurals name="compress_error_notification_title" formatted="false" msgid="3043630066678213644">
-      <item quantity="many">No fue posible comprimir <xliff:g id="COUNT_1">%1$d</xliff:g> archivos</item>
-      <item quantity="other">No fue posible comprimir <xliff:g id="COUNT_1">%1$d</xliff:g> archivos</item>
-      <item quantity="one">No fue posible comprimir <xliff:g id="COUNT_0">%1$d</xliff:g> archivo</item>
+      <item quantity="many">No se pudieron comprimir <xliff:g id="COUNT_1">%1$d</xliff:g> de archivos</item>
+      <item quantity="other">No se pudieron comprimir <xliff:g id="COUNT_1">%1$d</xliff:g> archivos</item>
+      <item quantity="one">No se pudo comprimir <xliff:g id="COUNT_0">%1$d</xliff:g> archivo</item>
     </plurals>
     <plurals name="move_error_notification_title" formatted="false" msgid="2185736082411854754">
-      <item quantity="many">No se pudieron mover <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
+      <item quantity="many">No se pudieron mover <xliff:g id="COUNT_1">%1$d</xliff:g> de elementos</item>
       <item quantity="other">No se pudieron mover <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
       <item quantity="one">No se pudo mover <xliff:g id="COUNT_0">%1$d</xliff:g> elemento</item>
     </plurals>
     <plurals name="delete_error_notification_title" formatted="false" msgid="7568122018481625267">
-      <item quantity="many">No se pudieron borrar <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
+      <item quantity="many">No se pudieron borrar <xliff:g id="COUNT_1">%1$d</xliff:g> de elementos</item>
       <item quantity="other">No se pudieron borrar <xliff:g id="COUNT_1">%1$d</xliff:g> elementos</item>
       <item quantity="one">No se pudo borrar <xliff:g id="COUNT_0">%1$d</xliff:g> elemento</item>
     </plurals>
@@ -195,9 +195,9 @@
       <item quantity="one">No se comprimió el siguiente archivo: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="extract_failure_alert_content" formatted="false" msgid="7572748127571720803">
-      <item quantity="many">No se extrajeron los siguientes archivos: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="other">No se extrajeron los siguientes archivos: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="one">No se extrajo el siguiente archivo: <xliff:g id="LIST_0">%1$s</xliff:g></item>
+      <item quantity="many">No se extrajeron estos archivos: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="other">No se extrajeron estos archivos: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="one">No se extrajo este archivo: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="move_failure_alert_content" formatted="false" msgid="2747390342670799196">
       <item quantity="many">No se movieron los siguientes archivos: <xliff:g id="LIST_1">%1$s</xliff:g></item>
@@ -210,9 +210,9 @@
       <item quantity="one">No se borró el siguiente archivo: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="copy_converted_warning_content" formatted="false" msgid="7433742181712126588">
-      <item quantity="many">Los siguientes archivos se convirtieron a otro formato: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="other">Los siguientes archivos se convirtieron a otro formato: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="one">El siguiente archivo se convirtió a otro formato: <xliff:g id="LIST_0">%1$s</xliff:g></item>
+      <item quantity="many">Estos archivos se convirtieron a otro formato: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="other">Estos archivos se convirtieron a otro formato: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="one">Este archivo se convirtió a otro formato: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="clipboard_files_clipped" formatted="false" msgid="4847061634862926902">
       <item quantity="many">Se copiaron <xliff:g id="COUNT_1">%1$d</xliff:g> elementos al portapapeles.</item>
@@ -242,19 +242,19 @@
     <string name="delete_filename_confirmation_message" msgid="8338069763240613258">"¿Deseas borrar el archivo \"<xliff:g id="NAME">%1$s</xliff:g>\"?"</string>
     <string name="delete_foldername_confirmation_message" msgid="9084085260877704140">"¿Deseas borrar la carpeta \"<xliff:g id="NAME">%1$s</xliff:g>\" y su contenido?"</string>
     <plurals name="delete_files_confirmation_message" formatted="false" msgid="4866664063250034142">
-      <item quantity="many">¿Deseas borrar <xliff:g id="COUNT_1">%1$d</xliff:g> archivos?</item>
-      <item quantity="other">¿Deseas borrar <xliff:g id="COUNT_1">%1$d</xliff:g> archivos?</item>
-      <item quantity="one">¿Deseas borrar <xliff:g id="COUNT_0">%1$d</xliff:g> archivo?</item>
+      <item quantity="many">¿Quieres borrar <xliff:g id="COUNT_1">%1$d</xliff:g> de archivos?</item>
+      <item quantity="other">¿Quieres borrar <xliff:g id="COUNT_1">%1$d</xliff:g> archivos?</item>
+      <item quantity="one">¿Quieres borrar <xliff:g id="COUNT_0">%1$d</xliff:g> archivo?</item>
     </plurals>
     <plurals name="delete_folders_confirmation_message" formatted="false" msgid="1028946402799686388">
-      <item quantity="many">¿Deseas borrar <xliff:g id="COUNT_1">%1$d</xliff:g> carpetas y su contenido?</item>
-      <item quantity="other">¿Deseas borrar <xliff:g id="COUNT_1">%1$d</xliff:g> carpetas y su contenido?</item>
-      <item quantity="one">¿Deseas borrar <xliff:g id="COUNT_0">%1$d</xliff:g> carpeta y su contenido?</item>
+      <item quantity="many">¿Quieres borrar <xliff:g id="COUNT_1">%1$d</xliff:g> de carpetas y su contenido?</item>
+      <item quantity="other">¿Quieres borrar <xliff:g id="COUNT_1">%1$d</xliff:g> carpetas y su contenido?</item>
+      <item quantity="one">¿Quieres borrar <xliff:g id="COUNT_0">%1$d</xliff:g> carpeta y su contenido?</item>
     </plurals>
     <plurals name="delete_items_confirmation_message" formatted="false" msgid="7285090426511028179">
-      <item quantity="many">¿Deseas borrar <xliff:g id="COUNT_1">%1$d</xliff:g> elementos?</item>
-      <item quantity="other">¿Deseas borrar <xliff:g id="COUNT_1">%1$d</xliff:g> elementos?</item>
-      <item quantity="one">¿Deseas borrar <xliff:g id="COUNT_0">%1$d</xliff:g> elemento?</item>
+      <item quantity="many">¿Borrar <xliff:g id="COUNT_1">%1$d</xliff:g> de elementos?</item>
+      <item quantity="other">¿Borrar <xliff:g id="COUNT_1">%1$d</xliff:g> elementos?</item>
+      <item quantity="one">¿Borrar <xliff:g id="COUNT_0">%1$d</xliff:g> elemento?</item>
     </plurals>
     <string name="images_shortcut_label" msgid="2545168016070493574">"Imágenes"</string>
     <string name="archive_loading_failed" msgid="7243436722828766996">"No es posible abrir el archivo para navegar, ya que el archivo está dañado o el formato no es compatible."</string>
diff --git a/res/values-es/inspector_strings.xml b/res/values-es/inspector_strings.xml
index 2e12fdc09..2dcaddc7f 100644
--- a/res/values-es/inspector_strings.xml
+++ b/res/values-es/inspector_strings.xml
@@ -33,7 +33,7 @@
     <string name="metadata_camera" msgid="2363009732801281319">"Cámara"</string>
     <string name="metadata_camera_format" msgid="1494489751904311612">"<xliff:g id="MAKE">%1$s</xliff:g> <xliff:g id="MODEL">%2$s</xliff:g>"</string>
     <string name="metadata_aperture" msgid="6538741952698935357">"Apertura"</string>
-    <string name="metadata_shutter_speed" msgid="8204739885103326131">"Velocidad del obturador"</string>
+    <string name="metadata_shutter_speed" msgid="8204739885103326131">"Velocidad de disparo"</string>
     <string name="metadata_duration" msgid="3115494422055472715">"Duración"</string>
     <string name="metadata_date_time" msgid="1090351199248114406">"Fecha de la foto"</string>
     <string name="metadata_focal_length" msgid="3440735161407699893">"Longitud focal"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 57e5b14cb..573a6768b 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -141,9 +141,9 @@
       <item quantity="one">Comprimiendo <xliff:g id="COUNT_0">%1$d</xliff:g> archivo.</item>
     </plurals>
     <plurals name="extract_begin" formatted="false" msgid="1006380679562903749">
-      <item quantity="many">Se están extrayendo <xliff:g id="COUNT_1">%1$d</xliff:g> archivos.</item>
-      <item quantity="other">Se están extrayendo <xliff:g id="COUNT_1">%1$d</xliff:g> archivos.</item>
-      <item quantity="one">Se está extrayendo <xliff:g id="COUNT_0">%1$d</xliff:g> archivo.</item>
+      <item quantity="many">Extrayendo <xliff:g id="COUNT_1">%1$d</xliff:g> archivos.</item>
+      <item quantity="other">Extrayendo <xliff:g id="COUNT_1">%1$d</xliff:g> archivos.</item>
+      <item quantity="one">Extrayendo <xliff:g id="COUNT_0">%1$d</xliff:g> archivo.</item>
     </plurals>
     <plurals name="move_begin" formatted="false" msgid="1464229874265756956">
       <item quantity="many">Moviendo <xliff:g id="COUNT_1">%1$d</xliff:g> elementos.</item>
@@ -195,14 +195,14 @@
       <item quantity="one">No se ha podido comprimir este archivo: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="extract_failure_alert_content" formatted="false" msgid="7572748127571720803">
-      <item quantity="many">No se han podido extraer estos archivos: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="other">No se han podido extraer estos archivos: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="one">No se ha podido extraer este archivo: <xliff:g id="LIST_0">%1$s</xliff:g></item>
+      <item quantity="many">Estos archivos no se han extraído: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="other">Estos archivos no se han extraído: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="one">Este archivo no se ha extraído: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="move_failure_alert_content" formatted="false" msgid="2747390342670799196">
-      <item quantity="many">No se han podido mover estos archivos: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="other">No se han podido mover estos archivos: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="one">No se ha podido mover este archivo: <xliff:g id="LIST_0">%1$s</xliff:g></item>
+      <item quantity="many">Estos archivos no se han movido: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="other">Estos archivos no se han movido: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="one">Este archivo no se ha movido: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="delete_failure_alert_content" formatted="false" msgid="6122372614839711711">
       <item quantity="many">No se han podido eliminar estos archivos: <xliff:g id="LIST_1">%1$s</xliff:g></item>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 7843dd54a..c8dbc0577 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -94,7 +94,7 @@
     <string name="query_error" msgid="6625421453613879336">"Une honetan ezin da kargatu edukia"</string>
     <string name="quiet_mode_error_title" msgid="554319751414657910">"Pausatuta daude laneko aplikazioak"</string>
     <string name="quiet_mode_button" msgid="8051436551926677305">"Aktibatu laneko aplikazioak"</string>
-    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Profil honetako (<xliff:g id="PROFILE">%1$s</xliff:g>) aplikazioak pausatuta daude"</string>
+    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"\"<xliff:g id="PROFILE">%1$s</xliff:g>\" profileko aplikazioak pausatuta daude"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"Aktibatu profil honetako (<xliff:g id="PROFILE">%1$s</xliff:g>) aplikazioak"</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"Ezin dira hautatu laneko fitxategiak"</string>
     <string name="cant_select_work_files_error_message" msgid="683480676150690641">"IKT saileko administratzaileak ez dizu ematen baimenik laneko fitxategiak aplikazio pertsonal batetik atzitzeko"</string>
@@ -110,7 +110,7 @@
     <string name="cant_save_to_cross_profile_error_message" msgid="5845240315510422749">"IKT saileko administratzaileak ez dizu eman baimenik profil bateko (<xliff:g id="PROFILE_0">%1$s</xliff:g>) fitxategiak beste profil batean (<xliff:g id="PROFILE_1">%2$s</xliff:g>) gordetzeko"</string>
     <string name="cross_profile_action_not_allowed_title" msgid="6611281348716476478">"Ez da onartzen ekintza"</string>
     <string name="cross_profile_action_not_allowed_message" msgid="7331275433061690947">"Informazio gehiago lortzeko, jarri IKT saileko administratzailearekin harremanetan"</string>
-    <string name="root_recent" msgid="1080156975424341623">"Azkenak"</string>
+    <string name="root_recent" msgid="1080156975424341623">"Azkenaldikoak"</string>
     <string name="root_available_bytes" msgid="8269870862691408864">"<xliff:g id="SIZE">%1$s</xliff:g> erabilgarri"</string>
     <string name="root_type_service" msgid="6521366147466512289">"Biltegiratze-zerbitzuak"</string>
     <string name="root_type_shortcut" msgid="6059343175525442279">"Lasterbideak"</string>
@@ -248,14 +248,14 @@
       <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g> hautatuta</item>
       <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g> hautatuta</item>
     </plurals>
-    <string name="root_info_header_recent" msgid="5654901877295332262">"Azken fitxategiak"</string>
+    <string name="root_info_header_recent" msgid="5654901877295332262">"Azkenaldiko fitxategiak"</string>
     <string name="root_info_header_global_search" msgid="4904078222280496152">"Fitxategiak"</string>
     <string name="root_info_header_downloads" msgid="8848161246921154115">"Deskargak karpetako fitxategiak"</string>
     <string name="root_info_header_storage" msgid="2989014130584927442">"<xliff:g id="DEVICE">%1$s</xliff:g> gailuko fitxategiak"</string>
     <string name="root_info_header_folder" msgid="5851172222368049864">"<xliff:g id="FOLDER">%1$s</xliff:g> karpetako fitxategiak"</string>
     <string name="root_info_header_app" msgid="2125422047558420885">"<xliff:g id="LABEL">%1$s</xliff:g> zerbitzuko fitxategiak"</string>
     <string name="root_info_header_app_with_summary" msgid="3223302581236069702">"<xliff:g id="LABEL">%1$s</xliff:g> zerbitzuko fitxategiak / <xliff:g id="SUMMARY">%2$s</xliff:g>"</string>
-    <string name="root_info_header_image_recent" msgid="7494373563753926014">"Azken irudiak"</string>
+    <string name="root_info_header_image_recent" msgid="7494373563753926014">"Azkenaldiko irudiak"</string>
     <string name="root_info_header_image_global_search" msgid="7307009823489854697">"Irudiak"</string>
     <string name="root_info_header_image_downloads" msgid="7072252612657612307">"Deskargak ataleko irudiak"</string>
     <string name="root_info_header_image_storage" msgid="5086740886360075930">"<xliff:g id="DEVICE">%1$s</xliff:g> gailuko irudiak"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 7162acf7b..f5a469861 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -28,7 +28,7 @@
     <string name="title_save" msgid="4384490653102710025">"ذخیره در"</string>
     <string name="menu_create_dir" msgid="2413624798689091042">"پوشهٔ جدید"</string>
     <string name="menu_grid" msgid="1453636521731880680">"نمای جدولی"</string>
-    <string name="menu_list" msgid="6714267452146410402">"نمای فهرست"</string>
+    <string name="menu_list" msgid="6714267452146410402">"نمای فهرستی"</string>
     <string name="menu_search" msgid="1876699106790719849">"جستجو"</string>
     <string name="menu_settings" msgid="6520844520117939047">"تنظیمات فضای ذخیره‌سازی"</string>
     <string name="menu_open" msgid="9092138100049759315">"باز"</string>
diff --git a/res/values-fr-rCA/inspector_strings.xml b/res/values-fr-rCA/inspector_strings.xml
index fc49cbe37..2cf15925f 100644
--- a/res/values-fr-rCA/inspector_strings.xml
+++ b/res/values-fr-rCA/inspector_strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="inspector_title" msgid="1924760928091740238">"Renseignements"</string>
     <string name="inspector_load_error" msgid="7522190243413249291">"Impossible de charger les renseignements sur le fichier"</string>
-    <string name="inspector_debug_section" msgid="2576052661505700421">"Données de débogage (concepteurs uniquement)"</string>
+    <string name="inspector_debug_section" msgid="2576052661505700421">"Données de débogage (développeurs uniquement)"</string>
     <string name="inspector_debug_metadata_section" msgid="5875140675600744846">"Métadonnées brutes : <xliff:g id="METADATATYPE">%1$s</xliff:g>"</string>
     <string name="inspector_metadata_section" msgid="6077622515328240575">"Détails des médias"</string>
     <string name="handler_app_file_opens_with" msgid="5272329600389613550">"Ce type de fichier s\'ouvre avec"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 07634981a..c61478375 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -67,7 +67,7 @@
     <string name="button_clear" msgid="5412304437764369441">"Effacer"</string>
     <string name="button_show_provider" msgid="6905880493806292753">"Afficher dans l\'appli du fournisseur"</string>
     <string name="button_back" msgid="1888621708934742182">"Retour"</string>
-    <string name="not_sorted" msgid="7813496644889115530">"Non trié"</string>
+    <string name="not_sorted" msgid="7813496644889115530">"Non triés"</string>
     <string name="sort_dimension_name" msgid="6325591541414177579">"Nom"</string>
     <string name="sort_dimension_summary" msgid="7724534446881397860">"Résumé"</string>
     <string name="sort_dimension_file_type" msgid="5779709622922085381">"Type"</string>
@@ -131,9 +131,9 @@
     <string name="delete_notification_title" msgid="2512757431856830792">"Suppression des fichiers"</string>
     <string name="copy_remaining" msgid="5390517377265177727">"Temps restant : <xliff:g id="DURATION">%s</xliff:g>"</string>
     <plurals name="copy_begin" formatted="false" msgid="151184708996738192">
-      <item quantity="one">Copie de <xliff:g id="COUNT_1">%1$d</xliff:g> élément en cours.</item>
-      <item quantity="many">Copie de <xliff:g id="COUNT_1">%1$d</xliff:g> éléments en cours.</item>
-      <item quantity="other">Copie de <xliff:g id="COUNT_1">%1$d</xliff:g> éléments en cours.</item>
+      <item quantity="one">Copie de <xliff:g id="COUNT_1">%1$d</xliff:g> élément en cours…</item>
+      <item quantity="many">Copie de <xliff:g id="COUNT_1">%1$d</xliff:g> d\'éléments en cours…</item>
+      <item quantity="other">Copie de <xliff:g id="COUNT_1">%1$d</xliff:g> éléments en cours…</item>
     </plurals>
     <plurals name="compress_begin" formatted="false" msgid="3534158317098678895">
       <item quantity="one">Compression de <xliff:g id="COUNT_1">%1$d</xliff:g> fichier en cours.</item>
@@ -146,9 +146,9 @@
       <item quantity="other">Extraction de <xliff:g id="COUNT_1">%1$d</xliff:g> fichiers en cours.</item>
     </plurals>
     <plurals name="move_begin" formatted="false" msgid="1464229874265756956">
-      <item quantity="one">Déplacement de <xliff:g id="COUNT_1">%1$d</xliff:g> élément en cours.</item>
-      <item quantity="many">Déplacement de <xliff:g id="COUNT_1">%1$d</xliff:g> éléments en cours.</item>
-      <item quantity="other">Déplacement de <xliff:g id="COUNT_1">%1$d</xliff:g> éléments en cours.</item>
+      <item quantity="one">Déplacement de <xliff:g id="COUNT_1">%1$d</xliff:g> élément en cours…</item>
+      <item quantity="many">Déplacement de <xliff:g id="COUNT_1">%1$d</xliff:g> d\'éléments en cours…</item>
+      <item quantity="other">Déplacement de <xliff:g id="COUNT_1">%1$d</xliff:g> éléments en cours…</item>
     </plurals>
     <plurals name="deleting" formatted="false" msgid="1729138001178158901">
       <item quantity="one">Suppression de <xliff:g id="COUNT_1">%1$d</xliff:g> élément en cours.</item>
@@ -216,7 +216,7 @@
     </plurals>
     <plurals name="clipboard_files_clipped" formatted="false" msgid="4847061634862926902">
       <item quantity="one"><xliff:g id="COUNT_1">%1$d</xliff:g> élément copié dans le presse-papiers.</item>
-      <item quantity="many"><xliff:g id="COUNT_1">%1$d</xliff:g> éléments copiés dans le presse-papiers.</item>
+      <item quantity="many"><xliff:g id="COUNT_1">%1$d</xliff:g> d\'éléments copiés dans le presse-papiers.</item>
       <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g> éléments copiés dans le presse-papiers.</item>
     </plurals>
     <string name="file_operation_rejected" msgid="4301554203329008794">"Opération relative au fichier non prise en charge"</string>
@@ -242,19 +242,19 @@
     <string name="delete_filename_confirmation_message" msgid="8338069763240613258">"Supprimer « <xliff:g id="NAME">%1$s</xliff:g> »?"</string>
     <string name="delete_foldername_confirmation_message" msgid="9084085260877704140">"Supprimer le dossier « <xliff:g id="NAME">%1$s</xliff:g> » et son contenu?"</string>
     <plurals name="delete_files_confirmation_message" formatted="false" msgid="4866664063250034142">
-      <item quantity="one">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> fichier?</item>
-      <item quantity="many">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> fichiers?</item>
-      <item quantity="other">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> fichiers?</item>
+      <item quantity="one">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> fichier?</item>
+      <item quantity="many">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> de fichiers?</item>
+      <item quantity="other">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> fichiers?</item>
     </plurals>
     <plurals name="delete_folders_confirmation_message" formatted="false" msgid="1028946402799686388">
-      <item quantity="one">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> dossier et son contenu?</item>
-      <item quantity="many">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> dossiers et leur contenu?</item>
-      <item quantity="other">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> dossiers et leur contenu?</item>
+      <item quantity="one">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> dossier et son contenu?</item>
+      <item quantity="many">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> de dossiers et leurs contenus?</item>
+      <item quantity="other">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> dossiers et leurs contenus?</item>
     </plurals>
     <plurals name="delete_items_confirmation_message" formatted="false" msgid="7285090426511028179">
-      <item quantity="one">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> élément?</item>
-      <item quantity="many">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> éléments?</item>
-      <item quantity="other">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> éléments?</item>
+      <item quantity="one">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> élément?</item>
+      <item quantity="many">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> d\'éléments?</item>
+      <item quantity="other">Supprimer <xliff:g id="COUNT_1">%1$d</xliff:g> éléments?</item>
     </plurals>
     <string name="images_shortcut_label" msgid="2545168016070493574">"Images"</string>
     <string name="archive_loading_failed" msgid="7243436722828766996">"Impossible d\'ouvrir l\'archive pour la navigation. Le fichier pourrait être corrompu ou être dans un format incompatible."</string>
@@ -299,7 +299,7 @@
     <string name="anonymous_application" msgid="7633027057951625862">"Anonyme"</string>
     <string name="open_tree_button" msgid="6402871398424497776">"Utiliser ce dossier"</string>
     <string name="open_tree_dialog_title" msgid="6339509533852318569">"Autoriser <xliff:g id="APPNAME">%1$s</xliff:g> à accéder aux fichiers dans <xliff:g id="DIRECTORY">%2$s</xliff:g>?"</string>
-    <string name="open_tree_dialog_message" msgid="4120695398430659628">"Cela permettra à <xliff:g id="APPNAME">%1$s</xliff:g> d\'accéder au contenu actuel et futur stocké dans <xliff:g id="DIRECTORY">%2$s</xliff:g>."</string>
+    <string name="open_tree_dialog_message" msgid="4120695398430659628">"Cela permettra à <xliff:g id="APPNAME">%1$s</xliff:g> d\'accéder à partir de maintenant au contenu stocké dans <xliff:g id="DIRECTORY">%2$s</xliff:g>."</string>
     <string name="directory_blocked_header_title" msgid="1164584889578740066">"Impossible d\'utiliser ce dossier"</string>
     <string name="directory_blocked_header_subtitle" msgid="2829150911849033408">"Pour protéger votre confidentialité, choisissez un autre dossier"</string>
     <string name="create_new_folder_button" msgid="8859613309559794890">"Créer un dossier"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 57e1970ad..1b9fe1d2f 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -94,7 +94,7 @@
     <string name="query_error" msgid="6625421453613879336">"Non se pode cargar o contido neste momento"</string>
     <string name="quiet_mode_error_title" msgid="554319751414657910">"Puxéronse en pausa as aplicacións do traballo"</string>
     <string name="quiet_mode_button" msgid="8051436551926677305">"Activar aplicacións do traballo"</string>
-    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"As aplicacións deste perfil (<xliff:g id="PROFILE">%1$s</xliff:g>) están en pausa"</string>
+    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"As aplicacións do perfil <xliff:g id="PROFILE">%1$s</xliff:g> están en pausa"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"Activar aplicacións (<xliff:g id="PROFILE">%1$s</xliff:g>)"</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"Non se puideron seleccionar os ficheiros de traballo"</string>
     <string name="cant_select_work_files_error_message" msgid="683480676150690641">"O teu administrador de TI non permite acceder aos ficheiros do traballo desde unha aplicación persoal"</string>
diff --git a/res/values-it/inspector_strings.xml b/res/values-it/inspector_strings.xml
index 7e81318db..d86da2ecd 100644
--- a/res/values-it/inspector_strings.xml
+++ b/res/values-it/inspector_strings.xml
@@ -43,5 +43,5 @@
     <string name="metadata_artist" msgid="8972421485694988540">"Artista"</string>
     <string name="metadata_composer" msgid="4696926808308256056">"Compositore"</string>
     <string name="metadata_album" msgid="1661699531214720236">"Album"</string>
-    <string name="metadata_address" msgid="1849921023707744640">"Geolocalizzazione"</string>
+    <string name="metadata_address" msgid="1849921023707744640">"Posizione"</string>
 </resources>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 2feb022b6..905815c87 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -94,7 +94,7 @@
     <string name="query_error" msgid="6625421453613879336">"Impossibile caricare i contenuti al momento."</string>
     <string name="quiet_mode_error_title" msgid="554319751414657910">"Le app di lavoro sono in pausa"</string>
     <string name="quiet_mode_button" msgid="8051436551926677305">"Attiva app di lavoro"</string>
-    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Le app <xliff:g id="PROFILE">%1$s</xliff:g> sono in pausa"</string>
+    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Le app del profilo <xliff:g id="PROFILE">%1$s</xliff:g> sono in pausa"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"Attiva le app <xliff:g id="PROFILE">%1$s</xliff:g>"</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"Impossibile selezionare file di lavoro"</string>
     <string name="cant_select_work_files_error_message" msgid="683480676150690641">"L\'amministratore IT non consente l\'accesso ai file di lavoro da un\'app personale"</string>
@@ -131,9 +131,9 @@
     <string name="delete_notification_title" msgid="2512757431856830792">"Eliminazione dei file"</string>
     <string name="copy_remaining" msgid="5390517377265177727">"<xliff:g id="DURATION">%s</xliff:g> rimanenti"</string>
     <plurals name="copy_begin" formatted="false" msgid="151184708996738192">
-      <item quantity="many">Copia di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi.</item>
-      <item quantity="other">Copia di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi.</item>
-      <item quantity="one">Copia di <xliff:g id="COUNT_0">%1$d</xliff:g> elemento.</item>
+      <item quantity="many">Copia di <xliff:g id="COUNT_1">%1$d</xliff:g> di elementi in corso.</item>
+      <item quantity="other">Copia di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi in corso.</item>
+      <item quantity="one">Copia di <xliff:g id="COUNT_0">%1$d</xliff:g> elemento in corso.</item>
     </plurals>
     <plurals name="compress_begin" formatted="false" msgid="3534158317098678895">
       <item quantity="many">Compressione di <xliff:g id="COUNT_1">%1$d</xliff:g> file in corso.</item>
@@ -141,19 +141,19 @@
       <item quantity="one">Compressione di <xliff:g id="COUNT_0">%1$d</xliff:g> file in corso.</item>
     </plurals>
     <plurals name="extract_begin" formatted="false" msgid="1006380679562903749">
-      <item quantity="many">Estrazione di <xliff:g id="COUNT_1">%1$d</xliff:g> file in corso.</item>
+      <item quantity="many">Estrazione di <xliff:g id="COUNT_1">%1$d</xliff:g> di file in corso.</item>
       <item quantity="other">Estrazione di <xliff:g id="COUNT_1">%1$d</xliff:g> file in corso.</item>
       <item quantity="one">Estrazione di <xliff:g id="COUNT_0">%1$d</xliff:g> file in corso.</item>
     </plurals>
     <plurals name="move_begin" formatted="false" msgid="1464229874265756956">
-      <item quantity="many">Spostamento di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi.</item>
-      <item quantity="other">Spostamento di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi.</item>
-      <item quantity="one">Spostamento di <xliff:g id="COUNT_0">%1$d</xliff:g> elemento.</item>
+      <item quantity="many">Spostamento di <xliff:g id="COUNT_1">%1$d</xliff:g> di elementi in corso.</item>
+      <item quantity="other">Spostamento di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi in corso.</item>
+      <item quantity="one">Spostamento di <xliff:g id="COUNT_0">%1$d</xliff:g> elemento in corso.</item>
     </plurals>
     <plurals name="deleting" formatted="false" msgid="1729138001178158901">
-      <item quantity="many">Eliminazione di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi.</item>
-      <item quantity="other">Eliminazione di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi.</item>
-      <item quantity="one">Eliminazione di <xliff:g id="COUNT_0">%1$d</xliff:g> elemento.</item>
+      <item quantity="many">Eliminazione di <xliff:g id="COUNT_1">%1$d</xliff:g> di elementi in corso.</item>
+      <item quantity="other">Eliminazione di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi in corso.</item>
+      <item quantity="one">Eliminazione di <xliff:g id="COUNT_0">%1$d</xliff:g> elemento in corso.</item>
     </plurals>
     <string name="undo" msgid="2902438994196400565">"Annulla"</string>
     <string name="copy_preparing" msgid="4759516490222449324">"Preparazione…"</string>
@@ -163,24 +163,24 @@
     <string name="delete_preparing" msgid="7339349837842802508">"Preparazione…"</string>
     <string name="delete_progress" msgid="2627631054702306423">"<xliff:g id="COUNT_0">%1$d</xliff:g>/<xliff:g id="TOTALCOUNT">%2$d</xliff:g>"</string>
     <plurals name="copy_error_notification_title" formatted="false" msgid="3188432450429390963">
-      <item quantity="many">Copia di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi non riuscita</item>
-      <item quantity="other">Copia di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi non riuscita</item>
-      <item quantity="one">Copia di <xliff:g id="COUNT_0">%1$d</xliff:g> elemento non riuscita</item>
+      <item quantity="many">Impossibile copiare <xliff:g id="COUNT_1">%1$d</xliff:g> di elementi</item>
+      <item quantity="other">Impossibile copiare <xliff:g id="COUNT_1">%1$d</xliff:g> elementi</item>
+      <item quantity="one">Impossibile copiare <xliff:g id="COUNT_0">%1$d</xliff:g> elemento</item>
     </plurals>
     <plurals name="compress_error_notification_title" formatted="false" msgid="3043630066678213644">
-      <item quantity="many">Impossibile comprimere <xliff:g id="COUNT_1">%1$d</xliff:g> file</item>
+      <item quantity="many">Impossibile comprimere <xliff:g id="COUNT_1">%1$d</xliff:g> di file</item>
       <item quantity="other">Impossibile comprimere <xliff:g id="COUNT_1">%1$d</xliff:g> file</item>
       <item quantity="one">Impossibile comprimere <xliff:g id="COUNT_0">%1$d</xliff:g> file</item>
     </plurals>
     <plurals name="move_error_notification_title" formatted="false" msgid="2185736082411854754">
-      <item quantity="many">Spostamento di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi non riuscito</item>
-      <item quantity="other">Spostamento di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi non riuscito</item>
-      <item quantity="one">Spostamento di <xliff:g id="COUNT_0">%1$d</xliff:g> elemento non riuscito</item>
+      <item quantity="many">Impossibile spostare <xliff:g id="COUNT_1">%1$d</xliff:g> di elementi</item>
+      <item quantity="other">Impossibile spostare <xliff:g id="COUNT_1">%1$d</xliff:g> elementi</item>
+      <item quantity="one">Impossibile spostare <xliff:g id="COUNT_0">%1$d</xliff:g> elemento</item>
     </plurals>
     <plurals name="delete_error_notification_title" formatted="false" msgid="7568122018481625267">
-      <item quantity="many">Eliminazione di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi non riuscita</item>
-      <item quantity="other">Eliminazione di <xliff:g id="COUNT_1">%1$d</xliff:g> elementi non riuscita</item>
-      <item quantity="one">Eliminazione di <xliff:g id="COUNT_0">%1$d</xliff:g> elemento non riuscita</item>
+      <item quantity="many">Impossibile eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> di elementi</item>
+      <item quantity="other">Impossibile eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> elementi</item>
+      <item quantity="one">Impossibile eliminare <xliff:g id="COUNT_0">%1$d</xliff:g> elemento</item>
     </plurals>
     <string name="notification_touch_for_details" msgid="2385563502445129570">"Tocca per vedere i dettagli"</string>
     <string name="close" msgid="905969391788869975">"Chiudi"</string>
@@ -200,9 +200,9 @@
       <item quantity="one">Il seguente file non è stato estratto: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="move_failure_alert_content" formatted="false" msgid="2747390342670799196">
-      <item quantity="many">I seguenti file non sono stati spostati: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="other">I seguenti file non sono stati spostati: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="one">Il seguente file non è stato spostato: <xliff:g id="LIST_0">%1$s</xliff:g></item>
+      <item quantity="many">Questi file non sono stati spostati: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="other">Questi file non sono stati spostati: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="one">Questo file non è stato spostato: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="delete_failure_alert_content" formatted="false" msgid="6122372614839711711">
       <item quantity="many">I seguenti file non sono stati eliminati: <xliff:g id="LIST_1">%1$s</xliff:g></item>
@@ -215,7 +215,7 @@
       <item quantity="one">Il seguente file è stato convertito in un altro formato: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="clipboard_files_clipped" formatted="false" msgid="4847061634862926902">
-      <item quantity="many"><xliff:g id="COUNT_1">%1$d</xliff:g> elementi copiati negli appunti.</item>
+      <item quantity="many"><xliff:g id="COUNT_1">%1$d</xliff:g> di elementi copiati negli appunti.</item>
       <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g> elementi copiati negli appunti.</item>
       <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g> elemento copiato negli appunti.</item>
     </plurals>
@@ -230,29 +230,29 @@
     <string name="allow" msgid="1275746941353040309">"Consenti"</string>
     <string name="deny" msgid="5127201668078153379">"Rifiuta"</string>
     <plurals name="elements_selected" formatted="false" msgid="4448165978637163692">
-      <item quantity="many"><xliff:g id="COUNT_1">%1$d</xliff:g> elementi selezionati</item>
-      <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g> elementi selezionati</item>
-      <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g> elemento selezionato</item>
+      <item quantity="many"><xliff:g id="COUNT_1">%1$d</xliff:g> selezionati</item>
+      <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g> selezionati</item>
+      <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g> selezionato</item>
     </plurals>
     <plurals name="elements_dragged" formatted="false" msgid="5932571296037626279">
-      <item quantity="many"><xliff:g id="COUNT_1">%1$d</xliff:g> elementi</item>
+      <item quantity="many"><xliff:g id="COUNT_1">%1$d</xliff:g> di elementi</item>
       <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g> elementi</item>
       <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g> elemento</item>
     </plurals>
     <string name="delete_filename_confirmation_message" msgid="8338069763240613258">"Eliminare \"<xliff:g id="NAME">%1$s</xliff:g>\"?"</string>
     <string name="delete_foldername_confirmation_message" msgid="9084085260877704140">"Eliminare la cartella \"<xliff:g id="NAME">%1$s</xliff:g>\" e i relativi contenuti?"</string>
     <plurals name="delete_files_confirmation_message" formatted="false" msgid="4866664063250034142">
-      <item quantity="many">Eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> file?</item>
+      <item quantity="many">Eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> di file?</item>
       <item quantity="other">Eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> file?</item>
       <item quantity="one">Eliminare <xliff:g id="COUNT_0">%1$d</xliff:g> file?</item>
     </plurals>
     <plurals name="delete_folders_confirmation_message" formatted="false" msgid="1028946402799686388">
-      <item quantity="many">Eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> cartelle e i relativi contenuti?</item>
-      <item quantity="other">Eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> cartelle e i relativi contenuti?</item>
-      <item quantity="one">Eliminare <xliff:g id="COUNT_0">%1$d</xliff:g> cartella e i relativi contenuti?</item>
+      <item quantity="many">Eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> di cartelle e i loro contenuti?</item>
+      <item quantity="other">Eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> cartelle e i loro contenuti?</item>
+      <item quantity="one">Eliminare <xliff:g id="COUNT_0">%1$d</xliff:g> cartella e i suoi contenuti?</item>
     </plurals>
     <plurals name="delete_items_confirmation_message" formatted="false" msgid="7285090426511028179">
-      <item quantity="many">Eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> elementi?</item>
+      <item quantity="many">Eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> di elementi?</item>
       <item quantity="other">Eliminare <xliff:g id="COUNT_1">%1$d</xliff:g> elementi?</item>
       <item quantity="one">Eliminare <xliff:g id="COUNT_0">%1$d</xliff:g> elemento?</item>
     </plurals>
@@ -266,9 +266,9 @@
     <string name="overwrite_file_confirmation_message" msgid="2496109652768222716">"Sovrascrivere <xliff:g id="NAME">%1$s</xliff:g>?"</string>
     <string name="continue_in_background" msgid="1974214559047793331">"Continua in background"</string>
     <plurals name="selected_count" formatted="false" msgid="7555250236512981129">
-      <item quantity="many"><xliff:g id="COUNT_1">%1$d</xliff:g> elementi selezionati</item>
-      <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g> elementi selezionati</item>
-      <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g> elemento selezionato</item>
+      <item quantity="many"><xliff:g id="COUNT_1">%1$d</xliff:g> di selezionati</item>
+      <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g> selezionati</item>
+      <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g> selezionato</item>
     </plurals>
     <string name="root_info_header_recent" msgid="5654901877295332262">"File recenti"</string>
     <string name="root_info_header_global_search" msgid="4904078222280496152">"File"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 33ea19922..1aaacb0a7 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -94,7 +94,7 @@
     <string name="query_error" msgid="6625421453613879336">"לא ניתן כרגע לטעון תוכן"</string>
     <string name="quiet_mode_error_title" msgid="554319751414657910">"האפליקציות לעבודה מושהות"</string>
     <string name="quiet_mode_button" msgid="8051436551926677305">"הפעלה של אפליקציות לעבודה"</string>
-    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"אפליקציות מפרופיל <xliff:g id="PROFILE">%1$s</xliff:g> מושהות"</string>
+    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"אפליקציות של <xliff:g id="PROFILE">%1$s</xliff:g> מושהות"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"הפעלת אפליקציות מפרופיל <xliff:g id="PROFILE">%1$s</xliff:g>"</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"לא ניתן לבחור קובצי עבודה"</string>
     <string name="cant_select_work_files_error_message" msgid="683480676150690641">"‏מנהל ה-IT לא מאפשר לגשת לקובצי עבודה מאפליקציה לשימוש אישי"</string>
@@ -109,7 +109,7 @@
     <string name="cant_save_to_cross_profile_error_title" msgid="5158984057654779022">"אי אפשר לשמור בפרופיל ה<xliff:g id="PROFILE">%1$s</xliff:g>"</string>
     <string name="cant_save_to_cross_profile_error_message" msgid="5845240315510422749">"‏אין אישור מהאדמין ב-IT לשמור קבצים מפרופיל <xliff:g id="PROFILE_0">%1$s</xliff:g> בפרופיל ה<xliff:g id="PROFILE_1">%2$s</xliff:g> שלך"</string>
     <string name="cross_profile_action_not_allowed_title" msgid="6611281348716476478">"הפעולה הזו אסורה"</string>
-    <string name="cross_profile_action_not_allowed_message" msgid="7331275433061690947">"‏כדי לקבל מידע נוסף יש לפנות אל מנהל ה-IT"</string>
+    <string name="cross_profile_action_not_allowed_message" msgid="7331275433061690947">"‏כדי לקבל מידע נוסף, צריך לפנות אל מנהל ה-IT"</string>
     <string name="root_recent" msgid="1080156975424341623">"בשימוש לאחרונה"</string>
     <string name="root_available_bytes" msgid="8269870862691408864">"מקום פנוי: <xliff:g id="SIZE">%1$s</xliff:g>"</string>
     <string name="root_type_service" msgid="6521366147466512289">"שירותי אחסון"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 8049b2248..1cf89f41f 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -25,7 +25,7 @@
     <!-- no translation found for launcher_label (799410258349837668) -->
     <skip />
     <string name="title_open" msgid="3165686459158020921">"ಇಲ್ಲಿಂದ ತೆರೆಯಿರಿ"</string>
-    <string name="title_save" msgid="4384490653102710025">"ಇವುಗಳಲ್ಲಿ ಉಳಿಸಿ"</string>
+    <string name="title_save" msgid="4384490653102710025">"ಇವುಗಳಲ್ಲಿ ಸೇವ್ ಮಾಡಿ"</string>
     <string name="menu_create_dir" msgid="2413624798689091042">"ಹೊಸ ಫೋಲ್ಡರ್"</string>
     <string name="menu_grid" msgid="1453636521731880680">"ಗ್ರಿಡ್ ವೀಕ್ಷಣೆ"</string>
     <string name="menu_list" msgid="6714267452146410402">"ಪಟ್ಟಿ ವೀಕ್ಷಣೆ"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index d8eca9d73..4d3d59831 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -124,15 +124,15 @@
     <string name="toast_share_over_limit" msgid="5805442886537093015">"<xliff:g id="COUNT">%1$d</xliff:g>ଟିରୁ ଅଧିକ ଫାଇଲ୍ ସେୟାର୍ କରାଯାଇପାରିବ ନାହିଁ"</string>
     <string name="toast_action_not_allowed" msgid="1329382474450572415">"କାର୍ଯ୍ୟଟିକୁ ଅନୁମତି ନାହିଁ"</string>
     <string name="share_via" msgid="8725082736005677161">"ଏହା ମାଧ୍ୟମରେ ସେୟାର୍‌ କରନ୍ତୁ"</string>
-    <string name="copy_notification_title" msgid="52256435625098456">"ଫାଇଲ୍‌ଗୁଡ଼ିକ କପୀ କରାଯାଉଛି"</string>
+    <string name="copy_notification_title" msgid="52256435625098456">"ଫାଇଲଗୁଡ଼ିକ କପି କରାଯାଉଛି"</string>
     <string name="compress_notification_title" msgid="6830195148113751021">"ଫାଇଲ୍‍ କମ୍ପ୍ରେସ୍ କରାଯାଉଛି"</string>
     <string name="extract_notification_title" msgid="5067393961754430469">"ଫାଇଲ୍‍ ଏକ୍ସଟ୍ରାକ୍ଟ କରିବା"</string>
     <string name="move_notification_title" msgid="3173424987049347605">"ଫାଇଲ୍‌ଗୁଡ଼ିକ ନିଆଯାଉଛି"</string>
     <string name="delete_notification_title" msgid="2512757431856830792">"ଫାଇଲ୍‍ ଡିଲିଟ୍‌ କରାଯାଉଛି"</string>
     <string name="copy_remaining" msgid="5390517377265177727">"<xliff:g id="DURATION">%s</xliff:g> ଅବଶିଷ୍ଟ"</string>
     <plurals name="copy_begin" formatted="false" msgid="151184708996738192">
-      <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g>ଟି ଆଇଟମ୍ କପୀ କରାଯାଉଛି।</item>
-      <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g>ଟି ଆଇଟମ୍ କପୀ କରାଯାଉଛି।</item>
+      <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g> ଆଇଟମ କପ କରାଯାଉଛି।</item>
+      <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g> ଆଇଟମ କପି କରାଯାଉଛି।</item>
     </plurals>
     <plurals name="compress_begin" formatted="false" msgid="3534158317098678895">
       <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g>ଟି ଫାଇଲ୍‍ କମ୍ପ୍ରେସ୍ କରାଯାଉଛି।</item>
@@ -176,8 +176,8 @@
     <string name="notification_touch_for_details" msgid="2385563502445129570">"ବିବରଣୀ ଦେଖିବା ପାଇଁ ଟାପ୍‍ କରନ୍ତୁ"</string>
     <string name="close" msgid="905969391788869975">"ବନ୍ଦ କରନ୍ତୁ"</string>
     <plurals name="copy_failure_alert_content" formatted="false" msgid="5570549471912990536">
-      <item quantity="other">ଏହି ଫାଇଲ୍‍ କପୀ କରାଯାଇପାରିଲା ନାହିଁ: <xliff:g id="LIST_1">%1$s</xliff:g></item>
-      <item quantity="one">ଏହି ଫାଇଲ୍‍ କପୀ କରାଯାଇପାରିଲା ନାହିଁ: <xliff:g id="LIST_0">%1$s</xliff:g></item>
+      <item quantity="other">ଏହି ଫାଇଲ କପି କରାଯାଇପାରିଲା ନାହିଁ: <xliff:g id="LIST_1">%1$s</xliff:g></item>
+      <item quantity="one">ଏହି ଫାଇଲ କପି କରାଯାଇପାରିଲା ନାହିଁ: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="compress_failure_alert_content" formatted="false" msgid="5760632881868842400">
       <item quantity="other">ଏହି ଫାଇଲଗୁଡ଼ିକ ଛୋଟ କରାଯାଇପାରିଲା ନାହିଁ: <xliff:g id="LIST_1">%1$s</xliff:g></item>
@@ -200,8 +200,8 @@
       <item quantity="one">ଏହି ଫାଇଲ୍‍ ଅନ୍ୟ ଫର୍ମାଟରେ ବଦଳାଗଲା: <xliff:g id="LIST_0">%1$s</xliff:g></item>
     </plurals>
     <plurals name="clipboard_files_clipped" formatted="false" msgid="4847061634862926902">
-      <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g>ଟି ଆଇଟମ୍‍ କ୍ଲିପ୍‌ବୋର୍ଡକୁ କପୀ କରାଗଲା</item>
-      <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g>ଟି ଆଇଟମ୍‍ କ୍ଲିପ୍‌ବୋର୍ଡକୁ କପୀ କରାଗଲା</item>
+      <item quantity="other"><xliff:g id="COUNT_1">%1$d</xliff:g> ଆଇଟମ କ୍ଲିପବୋର୍ଡକୁ କପି କରାଗଲା</item>
+      <item quantity="one"><xliff:g id="COUNT_0">%1$d</xliff:g> ଆଇଟମ କ୍ଲିପବୋର୍ଡକୁ କପି କରାଗଲା</item>
     </plurals>
     <string name="file_operation_rejected" msgid="4301554203329008794">"ଫାଇଲ୍‍ ଅପରେସନ୍‍ ସପୋର୍ଟ କଲାନାହିଁ।"</string>
     <string name="file_operation_error" msgid="2234357335716533795">"ଫାଇଲ୍ ଅପରେସନ୍‍ କରାଯାଇପାରିଲା ନାହିଁ"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index e159e6e0f..03a36e95c 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -94,7 +94,7 @@
     <string name="query_error" msgid="6625421453613879336">"Não é possível carregar o conteúdo neste momento"</string>
     <string name="quiet_mode_error_title" msgid="554319751414657910">"As Apps de trabalho estão suspensas."</string>
     <string name="quiet_mode_button" msgid="8051436551926677305">"Ativar apps de trabalho"</string>
-    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"As apps de <xliff:g id="PROFILE">%1$s</xliff:g> estão pausadas"</string>
+    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"As apps do perfil <xliff:g id="PROFILE">%1$s</xliff:g> estão pausadas"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"Ativar apps de <xliff:g id="PROFILE">%1$s</xliff:g>"</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"Não é possível selecionar ficheiros de trabalho."</string>
     <string name="cant_select_work_files_error_message" msgid="683480676150690641">"O seu administrador de TI não lhe permite aceder a ficheiros de trabalho a partir de uma app pessoal."</string>
diff --git a/res/values-sv/inspector_strings.xml b/res/values-sv/inspector_strings.xml
index b37c48977..b82a50910 100644
--- a/res/values-sv/inspector_strings.xml
+++ b/res/values-sv/inspector_strings.xml
@@ -33,7 +33,7 @@
     <string name="metadata_camera" msgid="2363009732801281319">"Kamera"</string>
     <string name="metadata_camera_format" msgid="1494489751904311612">"<xliff:g id="MAKE">%1$s</xliff:g> <xliff:g id="MODEL">%2$s</xliff:g>"</string>
     <string name="metadata_aperture" msgid="6538741952698935357">"Bländare"</string>
-    <string name="metadata_shutter_speed" msgid="8204739885103326131">"Slutarhastighet"</string>
+    <string name="metadata_shutter_speed" msgid="8204739885103326131">"Slutartid"</string>
     <string name="metadata_duration" msgid="3115494422055472715">"Längd"</string>
     <string name="metadata_date_time" msgid="1090351199248114406">"Taget den"</string>
     <string name="metadata_focal_length" msgid="3440735161407699893">"Brännvidd"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index ef50163e9..281612761 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -94,7 +94,7 @@
     <string name="query_error" msgid="6625421453613879336">"Det går inte att läsa in innehållet just nu"</string>
     <string name="quiet_mode_error_title" msgid="554319751414657910">"Jobbappar har pausats"</string>
     <string name="quiet_mode_button" msgid="8051436551926677305">"Aktivera jobbappar"</string>
-    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"<xliff:g id="PROFILE">%1$s</xliff:g>appar har pausats"</string>
+    <string name="profile_quiet_mode_error_title" msgid="7126962749634841843">"Appar för profilen <xliff:g id="PROFILE">%1$s</xliff:g> har pausats"</string>
     <string name="profile_quiet_mode_button" msgid="6791235010992920102">"Slå på <xliff:g id="PROFILE">%1$s</xliff:g>appar"</string>
     <string name="cant_select_work_files_error_title" msgid="6688716319549644354">"Det går inte att välja jobbfiler"</string>
     <string name="cant_select_work_files_error_message" msgid="683480676150690641">"IT-administratören tillåter inte att du öppnar jobbfiler i en privat app"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 235d3723c..7f922d0fc 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -47,8 +47,8 @@
     <string name="menu_extract" msgid="8171946945982532262">"Trích xuất sang…"</string>
     <string name="menu_rename" msgid="1883113442688817554">"Đổi tên"</string>
     <string name="menu_inspect" msgid="7279855349299446224">"Xem thông tin"</string>
-    <string name="menu_show_hidden_files" msgid="5140676344684492769">"Hiển thị các tệp đã ẩn"</string>
-    <string name="menu_hide_hidden_files" msgid="5654495713350153702">"Không hiển thị các tệp đã ẩn"</string>
+    <string name="menu_show_hidden_files" msgid="5140676344684492769">"Hiện các tệp bị ẩn"</string>
+    <string name="menu_hide_hidden_files" msgid="5654495713350153702">"Không hiện các tệp bị ẩn"</string>
     <string name="menu_view_in_owner" msgid="7228948660557554770">"Xem trong <xliff:g id="SOURCE">%1$s</xliff:g>"</string>
     <string name="menu_new_window" msgid="2947837751796109126">"Cửa sổ mới"</string>
     <string name="menu_cut_to_clipboard" msgid="2878752142015026229">"Cắt"</string>
diff --git a/src/com/android/documentsui/AbstractActionHandler.java b/src/com/android/documentsui/AbstractActionHandler.java
index e348d6b72..2f64ebf64 100644
--- a/src/com/android/documentsui/AbstractActionHandler.java
+++ b/src/com/android/documentsui/AbstractActionHandler.java
@@ -883,6 +883,12 @@ public abstract class AbstractActionHandler<T extends FragmentActivity & CommonA
         public Loader<DirectoryResult> onCreateLoader(int id, Bundle args) {
             Context context = mActivity;
 
+            // If document stack is not initialized, i.e. if the root is null, create "Recents" root
+            // with the selected user.
+            if (!mState.stack.isInitialized()) {
+                mState.stack.changeRoot(mActivity.getCurrentRoot());
+            }
+
             if (mState.stack.isRecents()) {
                 final LockingContentObserver observer = new LockingContentObserver(
                         mContentLock, AbstractActionHandler.this::loadDocumentsForCurrentStack);
diff --git a/src/com/android/documentsui/BaseActivity.java b/src/com/android/documentsui/BaseActivity.java
index a1dc0b99b..31c287393 100644
--- a/src/com/android/documentsui/BaseActivity.java
+++ b/src/com/android/documentsui/BaseActivity.java
@@ -172,6 +172,10 @@ public abstract class BaseActivity
         // Record the time when onCreate is invoked for metric.
         mStartTime = new Date().getTime();
 
+        if (SdkLevel.isAtLeastS()) {
+            getWindow().setHideOverlayWindows(true);
+        }
+
         // ToDo Create tool to check resource version before applyStyle for the theme
         // If version code is not match, we should reset overlay package to default,
         // in case Activity continueusly encounter resource not found exception
@@ -264,11 +268,11 @@ public abstract class BaseActivity
 
             @Override
             public void onSearchViewFocusChanged(boolean hasFocus) {
-                final boolean isInitailSearch
+                final boolean isInitialSearch
                         = !TextUtils.isEmpty(mSearchManager.getCurrentSearch())
                         && TextUtils.isEmpty(mSearchManager.getSearchViewText());
                 if (hasFocus) {
-                    if (!isInitailSearch) {
+                    if (!isInitialSearch) {
                         SearchFragment.showFragment(getSupportFragmentManager(),
                                 mSearchManager.getSearchViewText());
                     }
diff --git a/src/com/android/documentsui/base/State.java b/src/com/android/documentsui/base/State.java
index 7ba77c986..a3d0f9ddc 100644
--- a/src/com/android/documentsui/base/State.java
+++ b/src/com/android/documentsui/base/State.java
@@ -91,7 +91,7 @@ public class State implements android.os.Parcelable {
     public boolean openableOnly;
     public boolean restrictScopeStorage;
     public boolean showHiddenFiles;
-    public ConfigStore configStore;
+    public ConfigStore configStore = new ConfigStore.ConfigStoreImpl();
 
     /**
      * Represents whether the state supports cross-profile file picking.
diff --git a/src/com/android/documentsui/dirlist/Message.java b/src/com/android/documentsui/dirlist/Message.java
index d4c7e7eb3..7b2d6c309 100644
--- a/src/com/android/documentsui/dirlist/Message.java
+++ b/src/com/android/documentsui/dirlist/Message.java
@@ -32,6 +32,7 @@ import static com.android.documentsui.DevicePolicyResources.Strings.WORK_PROFILE
 import static com.android.documentsui.DevicePolicyResources.Strings.WORK_PROFILE_OFF_ERROR_TITLE;
 
 import android.Manifest;
+import android.app.ActivityManager;
 import android.app.AuthenticationRequiredException;
 import android.app.admin.DevicePolicyManager;
 import android.content.pm.PackageManager;
@@ -242,6 +243,11 @@ abstract class Message {
 
         private boolean setCanModifyQuietMode() {
             if (SdkLevel.isAtLeastV() && mConfigStore.isPrivateSpaceInDocsUIEnabled()) {
+                // Quite mode cannot be modified when DocsUi is launched from a non-foreground user
+                if (UserId.CURRENT_USER.getIdentifier() != ActivityManager.getCurrentUser()) {
+                    return false;
+                }
+
                 if (mUserManager == null) {
                     Log.e(TAG, "can not obtain user manager class");
                     return false;
diff --git a/src/com/android/documentsui/picker/ConfirmFragment.java b/src/com/android/documentsui/picker/ConfirmFragment.java
index 94015e930..e1af281bc 100644
--- a/src/com/android/documentsui/picker/ConfirmFragment.java
+++ b/src/com/android/documentsui/picker/ConfirmFragment.java
@@ -32,6 +32,7 @@ import com.android.documentsui.BaseActivity;
 import com.android.documentsui.R;
 import com.android.documentsui.base.DocumentInfo;
 import com.android.documentsui.base.Shared;
+import com.android.modules.utils.build.SdkLevel;
 
 import com.google.android.material.dialog.MaterialAlertDialogBuilder;
 
@@ -102,7 +103,11 @@ public class ConfirmFragment extends DialogFragment {
         builder.setNegativeButton(android.R.string.cancel,
                 (DialogInterface dialog, int id) -> pickResult.increaseActionCount());
 
-        return builder.create();
+        Dialog dialog = builder.create();
+        if (SdkLevel.isAtLeastS()) {
+            dialog.getWindow().setHideOverlayWindows(true);
+        }
+        return dialog;
     }
 
     @Override
diff --git a/src/com/android/documentsui/roots/ProvidersCache.java b/src/com/android/documentsui/roots/ProvidersCache.java
index a0e813e0a..bc54fce83 100644
--- a/src/com/android/documentsui/roots/ProvidersCache.java
+++ b/src/com/android/documentsui/roots/ProvidersCache.java
@@ -62,7 +62,6 @@ import com.android.modules.utils.build.SdkLevel;
 
 import com.google.common.collect.ArrayListMultimap;
 import com.google.common.collect.Multimap;
-import com.google.common.util.concurrent.MoreExecutors;
 
 import java.util.ArrayList;
 import java.util.Collection;
@@ -76,7 +75,6 @@ import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.concurrent.Semaphore;
-import java.util.concurrent.ThreadPoolExecutor;
 import java.util.concurrent.TimeUnit;
 import java.util.function.Function;
 
@@ -95,6 +93,9 @@ public class ProvidersCache implements ProvidersAccess, LookupApplicationName {
             // ArchivesProvider doesn't support any roots.
             ArchivesProvider.AUTHORITY);
     private static final int FIRST_LOAD_TIMEOUT_MS = 5000;
+    private static final int NUM_THREADS = 10;
+    private static final ExecutorService ASYNC_TASKS_THREAD_POOL =
+            Executors.newFixedThreadPool(NUM_THREADS);
 
     private final Context mContext;
 
@@ -562,8 +563,7 @@ public class ProvidersCache implements ProvidersAccess, LookupApplicationName {
 
             if (!taskInfos.isEmpty()) {
                 CountDownLatch updateTaskInternalCountDown = new CountDownLatch(taskInfos.size());
-                ExecutorService executor = MoreExecutors.getExitingExecutorService(
-                        (ThreadPoolExecutor) Executors.newCachedThreadPool());
+                ExecutorService executor = ASYNC_TASKS_THREAD_POOL;
                 for (SingleProviderUpdateTaskInfo taskInfo : taskInfos) {
                     executor.submit(() ->
                             startSingleProviderUpdateTask(
diff --git a/src/com/android/documentsui/sidebar/RootsFragment.java b/src/com/android/documentsui/sidebar/RootsFragment.java
index ee13d8617..76df696ab 100644
--- a/src/com/android/documentsui/sidebar/RootsFragment.java
+++ b/src/com/android/documentsui/sidebar/RootsFragment.java
@@ -29,7 +29,9 @@ import android.graphics.Color;
 import android.graphics.drawable.ColorDrawable;
 import android.os.Build;
 import android.os.Bundle;
+import android.os.ext.SdkExtensions;
 import android.provider.DocumentsContract;
+import android.provider.MediaStore;
 import android.text.TextUtils;
 import android.util.Log;
 import android.view.ContextMenu;
@@ -90,6 +92,7 @@ import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
+import java.util.stream.Collectors;
 
 /**
  * Display list of known storage backend roots.
@@ -521,6 +524,25 @@ public class RootsFragment extends Fragment {
             final List<ResolveInfo> infos = pm.queryIntentActivities(
                     handlerAppIntent, PackageManager.MATCH_DEFAULT_ONLY);
 
+            // In addition to hiding DocumentsUI from possible handler apps, the Android
+            // Photopicker should also be hidden. ACTION_PICK_IMAGES is used to identify
+            // the Photopicker package since that is the primary API.
+            List<ResolveInfo> photopickerActivities;
+            List<String> photopickerPackages;
+
+            if (SdkLevel.isAtLeastR()
+                    && SdkExtensions.getExtensionVersion(Build.VERSION_CODES.R) >= 2) {
+                photopickerActivities = pm.queryIntentActivities(
+                        new Intent(MediaStore.ACTION_PICK_IMAGES),
+                        PackageManager.MATCH_DEFAULT_ONLY);
+                photopickerPackages = photopickerActivities.stream()
+                        .map(info -> info.activityInfo.packageName)
+                .collect(Collectors.toList());
+            } else {
+                photopickerActivities = Collections.emptyList();
+                photopickerPackages = Collections.emptyList();
+            }
+
             // Omit ourselves and maybe calling package from the list
             for (ResolveInfo info : infos) {
                 if (!info.activityInfo.exported) {
@@ -531,6 +553,13 @@ public class RootsFragment extends Fragment {
                 }
 
                 final String packageName = info.activityInfo.packageName;
+
+                // If the package name for the activity is in the list of Photopicker
+                // activities, exclude it.
+                if (photopickerPackages.contains(packageName)) {
+                    continue;
+                }
+
                 if (!myPackageName.equals(packageName)
                         && !TextUtils.equals(excludePackage, packageName)) {
                     UserPackage userPackage = new UserPackage(userId, packageName);
diff --git a/tests/Android.bp b/tests/Android.bp
index 091f2edb3..e412919bd 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -19,9 +19,9 @@ package {
 java_defaults {
     name: "DocumentsUITests-defaults",
     libs: [
-        "android.test.base",
-        "android.test.mock",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+        "android.test.runner.stubs.system",
     ],
 
     static_libs: [
@@ -42,9 +42,9 @@ android_library {
     ],
     resource_dirs: [],
     libs: [
-        "android.test.base",
-        "android.test.mock",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+        "android.test.runner.stubs.system",
         "DocumentsUI-lib",
     ],
 
```

