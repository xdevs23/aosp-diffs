```diff
diff --git a/Android.bp b/Android.bp
index bea5e270..6fd40066 100644
--- a/Android.bp
+++ b/Android.bp
@@ -24,7 +24,6 @@ java_defaults {
     srcs: [
         "java/src/**/*.java",
         "java/src/**/*.kt",
-        "java/aidl/**/I*.aidl",
     ],
     resource_dirs: [
         "java/res",
@@ -54,6 +53,7 @@ android_library {
         "androidx.lifecycle_lifecycle-viewmodel-ktx",
         "dagger2",
         "//frameworks/libs/systemui:com_android_systemui_shared_flags_lib",
+        "//frameworks/libs/systemui:tracinglib-platform",
         "hilt_android",
         "IntentResolverFlagsLib",
         "iconloader",
@@ -78,9 +78,6 @@ android_library {
         "-Adagger.explicitBindingConflictsWithInject=ERROR",
         "-Adagger.strictMultibindingValidation=enabled",
     ],
-    aidl: {
-        local_include_dirs: ["java/aidl"],
-    },
 }
 
 java_defaults {
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index edb73cd1..5059feb1 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -6,8 +6,4 @@ ktfmt = --kotlinlang-style
 
 [Hook Scripts]
 checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
-
 ktlint_hook = ${REPO_ROOT}/prebuilts/ktlint/ktlint.py --no-verify-format -f ${PREUPLOAD_FILES}
-
-[Tool Paths]
-ktfmt = ${REPO_ROOT}/external/ktfmt/ktfmt.sh
diff --git a/aconfig/FeatureFlags.aconfig b/aconfig/FeatureFlags.aconfig
index a5509b22..ae6bcf36 100644
--- a/aconfig/FeatureFlags.aconfig
+++ b/aconfig/FeatureFlags.aconfig
@@ -6,20 +6,10 @@ container: "system"
 # bug: "Feature_Bug_#" or "<none>"
 
 flag {
-  name: "announce_shareousel_item_list_position"
+  name: "badge_shortcut_icon_placeholders"
   namespace: "intentresolver"
-  description: "Add item list position to item content description."
-  bug: "379032721"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
-flag {
-  name: "announce_shortcuts_and_suggested_apps"
-  namespace: "intentresolver"
-  description: "Enable talkback announcement for the app shortcuts and the suggested apps target groups."
-  bug: "379208685"
+  description: "Badge shortcut icon placeholders with app icon."
+  bug: "349847176"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
@@ -35,16 +25,6 @@ flag {
   }
 }
 
-flag {
-  name: "individual_metadata_title_read"
-  namespace: "intentresolver"
-  description: "Enables separate title URI metadata calls"
-  bug: "304686417"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
 flag {
   name: "refine_system_actions"
   namespace: "intentresolver"
@@ -55,33 +35,6 @@ flag {
   }
 }
 
-flag {
-  name: "fix_shortcuts_flashing_fixed"
-  namespace: "intentresolver"
-  description: "Do not flash shortcuts on payload selection change"
-  bug: "343300158"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
-flag {
-  name: "interactive_session"
-  namespace: "intentresolver"
-  description: "Enables interactive chooser session (a.k.a 'Splitti') feature."
-  bug: "358166090"
-}
-
-flag {
-  name: "keyboard_navigation_fix"
-  namespace: "intentresolver"
-  description: "Enable Chooser keyboard navigation bugfix"
-  bug: "325259478"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
 flag {
   name: "rebuild_adapters_on_target_pinning"
   namespace: "intentresolver"
@@ -100,48 +53,54 @@ flag {
 }
 
 flag {
-  name: "save_shareousel_state"
+  name: "synchronous_drawer_offset_calculation"
   namespace: "intentresolver"
-  description: "Preserve Shareousel state over a system-initiated process death."
-  bug: "362347212"
+  description: "Calculate drawer offset synchronously"
+  bug: "401566089"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
 }
 
 flag {
-  name: "shareousel_update_exclude_components_extra"
+  name: "shareousel_scroll_offscreen_selections"
   namespace: "intentresolver"
-  description: "Allow Shareousel selection change callback to update Intent#EXTRA_EXCLUDE_COMPONENTS"
-  bug: "352496527"
+  description: "Whether to scroll items onscreen when they are partially offscreen and selected/unselected."
+  bug: "351883537"
 }
 
 flag {
-  name: "unselect_final_item"
+  name: "shareousel_selection_shrink"
   namespace: "intentresolver"
-  description: "Allow toggling of final Shareousel item"
-  bug: "349468879"
+  description: "Whether to shrink Shareousel items when they are selected."
+  bug: "361792274"
 }
 
 flag {
-  name: "shareousel_scroll_offscreen_selections"
+  name: "sharesheet_esc_exit"
   namespace: "intentresolver"
-  description: "Whether to scroll items onscreen when they are partially offscreen and selected/unselected."
-  bug: "351883537"
+  description: "Whether to ESC exits sharesheet"
+  bug: "409766579"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
 }
 
 flag {
-  name: "shareousel_selection_shrink"
+  name: "use_google_sans_flex"
   namespace: "intentresolver"
-  description: "Whether to shrink Shareousel items when they are selected."
-  bug: "361792274"
+  description: "Use Google Sans Flex font."
+  bug: "393610034"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
 }
 
 flag {
-  name: "shareousel_tap_to_scroll_support"
+  name: "use_resolve_info_user_handle"
   namespace: "intentresolver"
-  description: "Whether to enable tap to scroll."
-  bug: "384656926"
+  description: "Expect that some OEM customizations (Dual apps) may have targets with different user handle in the list."
+  bug: "406053567"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
diff --git a/java/aidl/com/android/intentresolver/IChooserController.aidl b/java/aidl/com/android/intentresolver/IChooserController.aidl
deleted file mode 100644
index a4ce718d..00000000
--- a/java/aidl/com/android/intentresolver/IChooserController.aidl
+++ /dev/null
@@ -1,8 +0,0 @@
-
-package com.android.intentresolver;
-
-import android.content.Intent;
-
-interface IChooserController {
-    oneway void updateIntent(in Intent intent);
-}
diff --git a/java/aidl/com/android/intentresolver/IChooserInteractiveSessionCallback.aidl b/java/aidl/com/android/intentresolver/IChooserInteractiveSessionCallback.aidl
deleted file mode 100644
index 4a6179d9..00000000
--- a/java/aidl/com/android/intentresolver/IChooserInteractiveSessionCallback.aidl
+++ /dev/null
@@ -1,9 +0,0 @@
-
-package com.android.intentresolver;
-
-import com.android.intentresolver.IChooserController;
-
-interface IChooserInteractiveSessionCallback {
-    oneway void registerChooserController(in IChooserController updater);
-    oneway void onDrawerVerticalOffsetChanged(in int offset);
-}
diff --git a/java/res/drawable/chooser_action_button_bg.xml b/java/res/drawable/chooser_action_button_bg.xml
index 88eac4ce..70295ef2 100644
--- a/java/res/drawable/chooser_action_button_bg.xml
+++ b/java/res/drawable/chooser_action_button_bg.xml
@@ -25,7 +25,7 @@
             android:insetBottom="8dp">
             <shape android:shape="rectangle">
                 <corners android:radius="@dimen/chooser_action_corner_radius" />
-                <solid android:color="@androidprv:color/materialColorSurfaceContainerHigh"/>
+                <solid android:color="@color/chooser_action_button_bg_color"/>
             </shape>
         </inset>
     </item>
diff --git a/java/res/drawable/chooser_content_preview_rounded.xml b/java/res/drawable/chooser_content_preview_rounded.xml
index 00aa2912..18ebd73e 100644
--- a/java/res/drawable/chooser_content_preview_rounded.xml
+++ b/java/res/drawable/chooser_content_preview_rounded.xml
@@ -21,7 +21,7 @@
     android:shape="rectangle">
 
     <solid
-        android:color="@androidprv:color/materialColorSurfaceContainerHigh" />
+        android:color="@color/chooser_content_preview_rounded_color" />
 
     <corners android:radius="16dp" />
 </shape>
diff --git a/java/res/drawable/ic_close.xml b/java/res/drawable/ic_close.xml
new file mode 100644
index 00000000..053ee9a1
--- /dev/null
+++ b/java/res/drawable/ic_close.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<!-- This is based off of the chevron_right icon seen elsewhere, but the padding
+     on the right side of the icon has been removed (so the chevron can align with
+     other UI elements. This was done by reducing the viewport width to the maximum
+     extent of the path itself. -->
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
+        android:width="@dimen/chooser_close_icon_size"
+        android:height="@dimen/chooser_close_icon_size"
+        android:viewportWidth="960"
+        android:viewportHeight="960"
+        android:autoMirrored="true"
+        android:tint="@color/icon_tint_color">
+    <path
+        android:fillColor="@android:color/white"
+        android:pathData="M256,760L200,704L424,480L200,256L256,200L480,424L704,200L760,256L536,480L760,704L704,760L480,536L256,760Z"/>
+</vector>
diff --git a/java/res/layout/chooser_action_view.xml b/java/res/layout/chooser_action_view.xml
index 57cc59b7..5489a96b 100644
--- a/java/res/layout/chooser_action_view.xml
+++ b/java/res/layout/chooser_action_view.xml
@@ -22,10 +22,10 @@
     android:paddingHorizontal="@dimen/chooser_edge_margin_normal_half"
     android:clickable="true"
     android:drawablePadding="6dp"
-    android:drawableTint="@androidprv:color/materialColorOnSurface"
+    android:drawableTint="@color/chooser_action_button_drawable_tint_color"
     android:drawableTintMode="src_in"
     android:ellipsize="end"
     android:gravity="center"
     android:maxLines="1"
-    android:textColor="@androidprv:color/materialColorOnSurface"
+    android:textColor="@color/chooser_action_button_text_color"
     android:textSize="@dimen/chooser_action_view_text_size" />
diff --git a/java/res/layout/chooser_grid_item_hover.xml b/java/res/layout/chooser_grid_item_hover.xml
index 2bb94990..224b2630 100644
--- a/java/res/layout/chooser_grid_item_hover.xml
+++ b/java/res/layout/chooser_grid_item_hover.xml
@@ -26,8 +26,8 @@
               android:layout_height="wrap_content"
               android:minHeight="100dp"
               android:gravity="top|center_horizontal"
-              android:paddingVertical="1dp"
-              android:paddingHorizontal="4dp"
+              android:paddingVertical="@dimen/grid_padding_vertical_hover"
+              android:paddingHorizontal="@dimen/grid_padding_horizontal_hover"
               android:focusable="true"
               android:defaultFocusHighlightEnabled="false"
               app:focusOutlineWidth="@dimen/chooser_item_focus_outline_width"
diff --git a/java/res/layout/chooser_grid_preview_files_text.xml b/java/res/layout/chooser_grid_preview_files_text.xml
index b57d1394..60e9e11d 100644
--- a/java/res/layout/chooser_grid_preview_files_text.xml
+++ b/java/res/layout/chooser_grid_preview_files_text.xml
@@ -19,7 +19,6 @@
 <LinearLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
-    xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
diff --git a/java/res/layout/chooser_grid_scrollable_preview.xml b/java/res/layout/chooser_grid_scrollable_preview.xml
index f8c7a541..850e78c0 100644
--- a/java/res/layout/chooser_grid_scrollable_preview.xml
+++ b/java/res/layout/chooser_grid_scrollable_preview.xml
@@ -26,6 +26,7 @@
     app:maxCollapsedHeight="0dp"
     app:maxCollapsedHeightSmall="56dp"
     app:useScrollablePreviewNestedFlingLogic="true"
+    app:showAtTop="@bool/show_preview_at_top"
     android:maxWidth="@dimen/chooser_width"
     android:id="@androidprv:id/contentPanel">
 
@@ -35,6 +36,7 @@
         android:layout_height="wrap_content"
         app:layout_alwaysShow="true"
         android:elevation="0dp"
+        android:visibility="@integer/chooser_header_for_preview_visibility"
         android:background="@drawable/bottomsheet_background">
 
         <View
@@ -60,22 +62,41 @@
                   android:layout_centerHorizontal="true"/>
     </RelativeLayout>
 
-    <FrameLayout
-        android:id="@+id/chooser_headline_row_container"
+    <LinearLayout
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
+        android:layout_marginTop="@dimen/chooser_margin_vertical"
+        android:gravity="center"
         app:layout_alwaysShow="true"
-        android:background="@androidprv:color/materialColorSurfaceContainer">
+        android:background="@color/chooser_grid_layout_background">
 
-        <ViewStub
-            android:id="@+id/chooser_headline_row_stub"
-            android:inflatedId="@+id/chooser_headline_row"
-            android:layout="@layout/chooser_headline_row"
+        <ImageView
+            android:id="@+id/exit_button"
+            android:layout_width="@dimen/chooser_close_icon_size"
+            android:layout_height="@dimen/chooser_close_icon_size"
+            android:src="@drawable/ic_close"
+            android:contentDescription="@string/exit_button_label"
+            android:layout_marginHorizontal="@dimen/chooser_close_icon_size_margin"
+            android:layout_marginVertical="@dimen/chooser_close_icon_size_margin"
+            android:onClick="onExitButtonClicked"
+            android:visibility="@integer/preview_close_button_visibility"/>
+
+        <FrameLayout
+            android:id="@+id/chooser_headline_row_container"
             android:layout_width="match_parent"
             android:layout_height="wrap_content"
-            android:paddingHorizontal="@dimen/chooser_edge_margin_normal"
-            android:layout_marginBottom="@dimen/chooser_view_spacing" />
-    </FrameLayout>
+            android:background="@color/chooser_grid_layout_background">
+
+            <ViewStub
+                android:id="@+id/chooser_headline_row_stub"
+                android:inflatedId="@+id/chooser_headline_row"
+                android:layout="@layout/chooser_headline_row"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:paddingHorizontal="@dimen/chooser_edge_margin_normal"
+                android:layout_marginBottom="@dimen/chooser_view_spacing" />
+        </FrameLayout>
+    </LinearLayout>
 
     <com.android.intentresolver.widget.ChooserNestedScrollView
         android:id="@+id/chooser_scrollable_container"
@@ -85,12 +106,16 @@
         <LinearLayout
             android:layout_width="match_parent"
             android:layout_height="wrap_content"
-            android:orientation="vertical">
+            android:orientation="vertical"
+            android:background="@color/chooser_grid_layout_background">
 
             <FrameLayout
                 android:id="@androidprv:id/content_preview_container"
                 android:layout_width="match_parent"
                 android:layout_height="wrap_content"
+                android:minHeight="@dimen/chooser_content_view_min_height"
+                android:layout_marginTop="@dimen/chooser_content_view_margin_top"
+                android:layout_marginHorizontal="@dimen/chooser_content_view_margin_horizontal"
                 android:visibility="gone" />
 
             <TabHost
@@ -99,7 +124,8 @@
                 android:layout_height="wrap_content"
                 android:layout_alignParentTop="true"
                 android:layout_centerHorizontal="true"
-                android:background="@androidprv:color/materialColorSurfaceContainer">
+                android:layout_marginHorizontal="@dimen/chooser_profile_tabhost_margin_horizontal"
+                android:background="@color/chooser_grid_layout_background">
                 <LinearLayout
                     android:orientation="vertical"
                     android:layout_width="match_parent"
@@ -121,7 +147,7 @@
                     </FrameLayout>
                 </LinearLayout>
             </TabHost>
-    </LinearLayout>
+        </LinearLayout>
 
     </com.android.intentresolver.widget.ChooserNestedScrollView>
 
diff --git a/java/res/values-af/strings.xml b/java/res/values-af/strings.xml
index 12a44b0e..4bab5aa0 100644
--- a/java/res/values-af/strings.xml
+++ b/java/res/values-af/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Applys"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopieer teks"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopieer skakel"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Maak toe"</string>
 </resources>
diff --git a/java/res/values-am/strings.xml b/java/res/values-am/strings.xml
index 64cea88a..8444ce93 100644
--- a/java/res/values-am/strings.xml
+++ b/java/res/values-am/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"የመተግበሪያ ዝርዝር"</string>
     <string name="copy_text" msgid="1341801611046464360">"ጽሑፍ ቅዳ"</string>
     <string name="copy_link" msgid="3822142723771306592">"አገናኝ ቅዳ"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"አሰናብት"</string>
 </resources>
diff --git a/java/res/values-ar/strings.xml b/java/res/values-ar/strings.xml
index b170e7f9..8e3a730f 100644
--- a/java/res/values-ar/strings.xml
+++ b/java/res/values-ar/strings.xml
@@ -55,7 +55,7 @@
     <string name="screenshot_edit" msgid="3857183660047569146">"تعديل"</string>
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ ملف واحد}zero{+ # ملف}two{+ ملفان}few{+ # ملفات}many{+ # ملفًا}other{+ # ملف}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{وملف واحد آخر}zero{و# ملف آخر}two{وملفان آخران}few{و# ملفات أخرى}many{و# ملفًا آخر}other{و# ملف آخر}}"</string>
-    <string name="sharing_text" msgid="8137537443603304062">"جارٍ مشاركة النص"</string>
+    <string name="sharing_text" msgid="8137537443603304062">"مشاركة النص"</string>
     <string name="sharing_link" msgid="2307694372813942916">"جارٍ مشاركة الرابط"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{جارٍ مشاركة صورة واحدة}zero{جارٍ مشاركة # صورة}two{جارٍ مشاركة صورتَين}few{جارٍ مشاركة # صور}many{جارٍ مشاركة # صورة}other{جارٍ مشاركة # صورة}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{جارٍ مشاركة فيديو واحد}zero{جارٍ مشاركة # فيديو}two{جارٍ مشاركة فيديوهَين}few{جارٍ مشاركة # فيديوهات}many{جارٍ مشاركة # فيديو}other{جارٍ مشاركة # فيديو}}"</string>
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"قائمة التطبيقات"</string>
     <string name="copy_text" msgid="1341801611046464360">"نسخ النص"</string>
     <string name="copy_link" msgid="3822142723771306592">"نسخ الرابط"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"إغلاق"</string>
 </resources>
diff --git a/java/res/values-as/strings.xml b/java/res/values-as/strings.xml
index fd0a407e..11e03a0e 100644
--- a/java/res/values-as/strings.xml
+++ b/java/res/values-as/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"এপৰ সূচী"</string>
     <string name="copy_text" msgid="1341801611046464360">"পাঠ প্ৰতিলিপি কৰক"</string>
     <string name="copy_link" msgid="3822142723771306592">"লিংক প্ৰতিলিপি কৰক"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"অগ্ৰাহ্য কৰক"</string>
 </resources>
diff --git a/java/res/values-az/strings.xml b/java/res/values-az/strings.xml
index 46baccee..fc41b897 100644
--- a/java/res/values-az/strings.xml
+++ b/java/res/values-az/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Tətbiq siyahısı"</string>
     <string name="copy_text" msgid="1341801611046464360">"Mətni kopyalayın"</string>
     <string name="copy_link" msgid="3822142723771306592">"Keçidi kopyalayın"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"İmtina edin"</string>
 </resources>
diff --git a/java/res/values-b+sr+Latn/strings.xml b/java/res/values-b+sr+Latn/strings.xml
index 64ae817b..3297d886 100644
--- a/java/res/values-b+sr+Latn/strings.xml
+++ b/java/res/values-b+sr+Latn/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista aplikacija"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopiraj tekst"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopiraj link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Odbaci"</string>
 </resources>
diff --git a/java/res/values-be/strings.xml b/java/res/values-be/strings.xml
index b51e0922..51c5987a 100644
--- a/java/res/values-be/strings.xml
+++ b/java/res/values-be/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Спіс праграм"</string>
     <string name="copy_text" msgid="1341801611046464360">"Скапіраваць тэкст"</string>
     <string name="copy_link" msgid="3822142723771306592">"Скапіраваць спасылку"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Закрыць"</string>
 </resources>
diff --git a/java/res/values-bg/strings.xml b/java/res/values-bg/strings.xml
index 0fcb751e..2472685e 100644
--- a/java/res/values-bg/strings.xml
+++ b/java/res/values-bg/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Списък с приложения"</string>
     <string name="copy_text" msgid="1341801611046464360">"Копиране на текста"</string>
     <string name="copy_link" msgid="3822142723771306592">"Копиране на връзката"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Отхвърляне"</string>
 </resources>
diff --git a/java/res/values-bn/strings.xml b/java/res/values-bn/strings.xml
index 69cbed55..10f4cc3e 100644
--- a/java/res/values-bn/strings.xml
+++ b/java/res/values-bn/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"অ্যাপ তালিকা"</string>
     <string name="copy_text" msgid="1341801611046464360">"টেক্সট কপি করুন"</string>
     <string name="copy_link" msgid="3822142723771306592">"লিঙ্ক কপি করুন"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"বাতিল করুন"</string>
 </resources>
diff --git a/java/res/values-bs/strings.xml b/java/res/values-bs/strings.xml
index 52b9f191..2276ad1d 100644
--- a/java/res/values-bs/strings.xml
+++ b/java/res/values-bs/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista aplikacija"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopiranje teksta"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopiranje linka"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Odbacivanje"</string>
 </resources>
diff --git a/java/res/values-ca/strings.xml b/java/res/values-ca/strings.xml
index dd003124..5f499fa9 100644
--- a/java/res/values-ca/strings.xml
+++ b/java/res/values-ca/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Llista d\'aplicacions"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copia el text"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copia l\'enllaç"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Ignora"</string>
 </resources>
diff --git a/java/res/values-cs/strings.xml b/java/res/values-cs/strings.xml
index 41fec051..1a9eb7ef 100644
--- a/java/res/values-cs/strings.xml
+++ b/java/res/values-cs/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Seznam aplikací"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopírovat text"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopírovat odkaz"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Zavřít"</string>
 </resources>
diff --git a/java/res/values-da/strings.xml b/java/res/values-da/strings.xml
index 1fe8da30..4a7d3728 100644
--- a/java/res/values-da/strings.xml
+++ b/java/res/values-da/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Appliste"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopiér tekst"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopiér link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Luk"</string>
 </resources>
diff --git a/java/res/values-de/strings.xml b/java/res/values-de/strings.xml
index 497f1e71..0c7bbd53 100644
--- a/java/res/values-de/strings.xml
+++ b/java/res/values-de/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App-Liste"</string>
     <string name="copy_text" msgid="1341801611046464360">"Text kopieren"</string>
     <string name="copy_link" msgid="3822142723771306592">"Link kopieren"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Schließen"</string>
 </resources>
diff --git a/java/res/values-el/strings.xml b/java/res/values-el/strings.xml
index d84f7621..9dcc8d08 100644
--- a/java/res/values-el/strings.xml
+++ b/java/res/values-el/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Λίστα εφαρμογών"</string>
     <string name="copy_text" msgid="1341801611046464360">"Αντιγραφή κειμένου"</string>
     <string name="copy_link" msgid="3822142723771306592">"Αντιγραφή συνδέσμου"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Παράβλεψη"</string>
 </resources>
diff --git a/java/res/values-en-rAU/strings.xml b/java/res/values-en-rAU/strings.xml
index d4fb97e0..e18d57c5 100644
--- a/java/res/values-en-rAU/strings.xml
+++ b/java/res/values-en-rAU/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App list"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copy text"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copy link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Dismiss"</string>
 </resources>
diff --git a/java/res/values-en-rCA/strings.xml b/java/res/values-en-rCA/strings.xml
index eca4abcc..241602cf 100644
--- a/java/res/values-en-rCA/strings.xml
+++ b/java/res/values-en-rCA/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App list"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copy text"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copy link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Dismiss"</string>
 </resources>
diff --git a/java/res/values-en-rGB/strings.xml b/java/res/values-en-rGB/strings.xml
index d4fb97e0..e18d57c5 100644
--- a/java/res/values-en-rGB/strings.xml
+++ b/java/res/values-en-rGB/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App list"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copy text"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copy link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Dismiss"</string>
 </resources>
diff --git a/java/res/values-en-rIN/strings.xml b/java/res/values-en-rIN/strings.xml
index d4fb97e0..e18d57c5 100644
--- a/java/res/values-en-rIN/strings.xml
+++ b/java/res/values-en-rIN/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App list"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copy text"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copy link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Dismiss"</string>
 </resources>
diff --git a/java/res/values-es-rUS/strings.xml b/java/res/values-es-rUS/strings.xml
index fa61afab..fa3167d4 100644
--- a/java/res/values-es-rUS/strings.xml
+++ b/java/res/values-es-rUS/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de apps"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copiar texto"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copiar vínculo"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Descartar"</string>
 </resources>
diff --git a/java/res/values-es/strings.xml b/java/res/values-es/strings.xml
index a7fa6a14..d55627df 100644
--- a/java/res/values-es/strings.xml
+++ b/java/res/values-es/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de aplicaciones"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copiar texto"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copiar enlace"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Cerrar"</string>
 </resources>
diff --git a/java/res/values-et/strings.xml b/java/res/values-et/strings.xml
index 67584bec..5e63c795 100644
--- a/java/res/values-et/strings.xml
+++ b/java/res/values-et/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Rakenduste loend"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopeeri tekst"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopeeri link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Loobumine"</string>
 </resources>
diff --git a/java/res/values-eu/strings.xml b/java/res/values-eu/strings.xml
index fab9c44b..c2e0903f 100644
--- a/java/res/values-eu/strings.xml
+++ b/java/res/values-eu/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Aplikazioen zerrenda"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopiatu testua"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopiatu esteka"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Baztertu"</string>
 </resources>
diff --git a/java/res/values-fa/strings.xml b/java/res/values-fa/strings.xml
index 597546b3..1a083a90 100644
--- a/java/res/values-fa/strings.xml
+++ b/java/res/values-fa/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"فهرست برنامه"</string>
     <string name="copy_text" msgid="1341801611046464360">"کپی کردن نوشتار"</string>
     <string name="copy_link" msgid="3822142723771306592">"کپی کردن پیوند"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"بستن"</string>
 </resources>
diff --git a/java/res/values-fi/strings.xml b/java/res/values-fi/strings.xml
index 12003636..9ada0dbd 100644
--- a/java/res/values-fi/strings.xml
+++ b/java/res/values-fi/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Sovelluslista"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopioi teksti"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopioi linkki"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Hylkää"</string>
 </resources>
diff --git a/java/res/values-fr-rCA/strings.xml b/java/res/values-fr-rCA/strings.xml
index aa710ce8..0b71645b 100644
--- a/java/res/values-fr-rCA/strings.xml
+++ b/java/res/values-fr-rCA/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Liste d\'applis"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copier le texte"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copier le lien"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Fermer"</string>
 </resources>
diff --git a/java/res/values-fr/strings.xml b/java/res/values-fr/strings.xml
index 81c54ec2..5304957a 100644
--- a/java/res/values-fr/strings.xml
+++ b/java/res/values-fr/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Liste des applications"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copier le texte"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copier le lien"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Ignorer"</string>
 </resources>
diff --git a/java/res/values-gl/strings.xml b/java/res/values-gl/strings.xml
index b173db33..61397f35 100644
--- a/java/res/values-gl/strings.xml
+++ b/java/res/values-gl/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de aplicacións"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copiar o texto"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copiar a ligazón"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Pechar"</string>
 </resources>
diff --git a/java/res/values-gu/strings.xml b/java/res/values-gu/strings.xml
index 945486eb..5323222e 100644
--- a/java/res/values-gu/strings.xml
+++ b/java/res/values-gu/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ઍપની સૂચિ"</string>
     <string name="copy_text" msgid="1341801611046464360">"ટેક્સ્ટ કૉપિ કરો"</string>
     <string name="copy_link" msgid="3822142723771306592">"લિંક કૉપિ કરો"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"છોડી દો"</string>
 </resources>
diff --git a/java/res/values-hi/strings.xml b/java/res/values-hi/strings.xml
index 06e2030d..d585beee 100644
--- a/java/res/values-hi/strings.xml
+++ b/java/res/values-hi/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ऐप्लिकेशन की सूची"</string>
     <string name="copy_text" msgid="1341801611046464360">"टेक्स्ट कॉपी करें"</string>
     <string name="copy_link" msgid="3822142723771306592">"लिंक कॉपी करें"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"खारिज करें"</string>
 </resources>
diff --git a/java/res/values-hr/strings.xml b/java/res/values-hr/strings.xml
index 1dbbef0a..4afa3429 100644
--- a/java/res/values-hr/strings.xml
+++ b/java/res/values-hr/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Popis aplikacija"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopiraj tekst"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopiraj vezu"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Odbaci"</string>
 </resources>
diff --git a/java/res/values-hu/strings.xml b/java/res/values-hu/strings.xml
index e719ef29..311741be 100644
--- a/java/res/values-hu/strings.xml
+++ b/java/res/values-hu/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Alkalmazáslista"</string>
     <string name="copy_text" msgid="1341801611046464360">"Szöveg másolása"</string>
     <string name="copy_link" msgid="3822142723771306592">"Link másolása"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Elvetés"</string>
 </resources>
diff --git a/java/res/values-hy/strings.xml b/java/res/values-hy/strings.xml
index 751542b9..a0de8148 100644
--- a/java/res/values-hy/strings.xml
+++ b/java/res/values-hy/strings.xml
@@ -74,7 +74,7 @@
     <string name="image_preview_a11y_description" msgid="297102643932491797">"Պատկերի նախադիտման մանրապատկեր"</string>
     <string name="video_preview_a11y_description" msgid="683440858811095990">"Տեսանյութի նախադիտման մանրապատկեր"</string>
     <string name="file_preview_a11y_description" msgid="7397224827802410602">"Ֆայլի նախադիտման մանրապատկեր"</string>
-    <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"Չկան օգտատերեր, որոնց հետ կարող եք կիսվել"</string>
+    <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"Առաջարկվող հասցեատերեր չկան"</string>
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"Հավելվածը ձայնագրելու թույլտվություն չունի, սակայն կկարողանա գրանցել ձայնն այս USB սարքի միջոցով։"</string>
     <string name="resolver_personal_tab" msgid="1381052735324320565">"Անձնական"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"Աշխատանքային"</string>
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Հավելվածների ցուցակ"</string>
     <string name="copy_text" msgid="1341801611046464360">"Պատճենել տեքստ"</string>
     <string name="copy_link" msgid="3822142723771306592">"Պատճենել հղումը"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Փակել"</string>
 </resources>
diff --git a/java/res/values-in/strings.xml b/java/res/values-in/strings.xml
index 059b583e..7aab84fa 100644
--- a/java/res/values-in/strings.xml
+++ b/java/res/values-in/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Daftar aplikasi"</string>
     <string name="copy_text" msgid="1341801611046464360">"Salin teks"</string>
     <string name="copy_link" msgid="3822142723771306592">"Salin link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Tutup"</string>
 </resources>
diff --git a/java/res/values-is/strings.xml b/java/res/values-is/strings.xml
index a53635d1..5a929e7f 100644
--- a/java/res/values-is/strings.xml
+++ b/java/res/values-is/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Forritalisti"</string>
     <string name="copy_text" msgid="1341801611046464360">"Afrita texta"</string>
     <string name="copy_link" msgid="3822142723771306592">"Afrita tengil"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Hunsa"</string>
 </resources>
diff --git a/java/res/values-it/strings.xml b/java/res/values-it/strings.xml
index b97e10f7..a6baca09 100644
--- a/java/res/values-it/strings.xml
+++ b/java/res/values-it/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Elenco di app"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copia testo"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copia link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Ignora"</string>
 </resources>
diff --git a/java/res/values-iw/strings.xml b/java/res/values-iw/strings.xml
index e1971138..06d5f5b0 100644
--- a/java/res/values-iw/strings.xml
+++ b/java/res/values-iw/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"רשימת האפליקציות"</string>
     <string name="copy_text" msgid="1341801611046464360">"העתקת הטקסט"</string>
     <string name="copy_link" msgid="3822142723771306592">"העתקת הקישור"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"סגירה"</string>
 </resources>
diff --git a/java/res/values-ja/strings.xml b/java/res/values-ja/strings.xml
index 666d8297..df15015d 100644
--- a/java/res/values-ja/strings.xml
+++ b/java/res/values-ja/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"アプリリスト"</string>
     <string name="copy_text" msgid="1341801611046464360">"テキストをコピー"</string>
     <string name="copy_link" msgid="3822142723771306592">"リンクをコピー"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"閉じる"</string>
 </resources>
diff --git a/java/res/values-ka/strings.xml b/java/res/values-ka/strings.xml
index ef11a5d4..2e05c712 100644
--- a/java/res/values-ka/strings.xml
+++ b/java/res/values-ka/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"აპების სია"</string>
     <string name="copy_text" msgid="1341801611046464360">"ტექსტის კოპირება"</string>
     <string name="copy_link" msgid="3822142723771306592">"ბმულის კოპირება"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"დახურვა"</string>
 </resources>
diff --git a/java/res/values-kk/strings.xml b/java/res/values-kk/strings.xml
index b7f47e72..c29fc3b3 100644
--- a/java/res/values-kk/strings.xml
+++ b/java/res/values-kk/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Қолданбалар тізімі"</string>
     <string name="copy_text" msgid="1341801611046464360">"Мәтінді көшіру"</string>
     <string name="copy_link" msgid="3822142723771306592">"Сілтемені көшіру"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Жабу"</string>
 </resources>
diff --git a/java/res/values-km/strings.xml b/java/res/values-km/strings.xml
index 81f2c1d2..69ca640c 100644
--- a/java/res/values-km/strings.xml
+++ b/java/res/values-km/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"បញ្ជីកម្មវិធី"</string>
     <string name="copy_text" msgid="1341801611046464360">"ចម្លងអក្សរ"</string>
     <string name="copy_link" msgid="3822142723771306592">"ចម្លង​តំណ"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"ច្រានចោល"</string>
 </resources>
diff --git a/java/res/values-kn/strings.xml b/java/res/values-kn/strings.xml
index 4e6d1007..b9591ced 100644
--- a/java/res/values-kn/strings.xml
+++ b/java/res/values-kn/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ಆ್ಯಪ್ ಪಟ್ಟಿ"</string>
     <string name="copy_text" msgid="1341801611046464360">"ಪಠ್ಯವನ್ನು ಕಾಪಿ ಮಾಡಿ"</string>
     <string name="copy_link" msgid="3822142723771306592">"ಲಿಂಕ್ ಅನ್ನು ಕಾಪಿ ಮಾಡಿ"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"ವಜಾಗೊಳಿಸಿ"</string>
 </resources>
diff --git a/java/res/values-ko/strings.xml b/java/res/values-ko/strings.xml
index 590baa66..88100789 100644
--- a/java/res/values-ko/strings.xml
+++ b/java/res/values-ko/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"앱 목록"</string>
     <string name="copy_text" msgid="1341801611046464360">"텍스트 복사"</string>
     <string name="copy_link" msgid="3822142723771306592">"링크 복사"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"닫기"</string>
 </resources>
diff --git a/java/res/values-ky/strings.xml b/java/res/values-ky/strings.xml
index 0f69ebe9..926fc997 100644
--- a/java/res/values-ky/strings.xml
+++ b/java/res/values-ky/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Колдонмолордун тизмеси"</string>
     <string name="copy_text" msgid="1341801611046464360">"Текстти көчүрүү"</string>
     <string name="copy_link" msgid="3822142723771306592">"Шилтемени көчүрүү"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Жабуу"</string>
 </resources>
diff --git a/java/res/values-lo/strings.xml b/java/res/values-lo/strings.xml
index f8fcbfcc..3abd4d11 100644
--- a/java/res/values-lo/strings.xml
+++ b/java/res/values-lo/strings.xml
@@ -76,7 +76,7 @@
     <string name="file_preview_a11y_description" msgid="7397224827802410602">"ຮູບຕົວຢ່າງຂອງໄຟລ໌"</string>
     <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"ບໍ່ມີຄົນທີ່ແນະນຳໃຫ້ແບ່ງປັນນຳ"</string>
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"ແອັບນີ້ບໍ່ໄດ້ຮັບສິດອະນຸຍາດໃນການບັນທຶກ ແຕ່ສາມາດບັນທຶກສຽງໄດ້ຜ່ານອຸປະກອນ USB ນີ້."</string>
-    <string name="resolver_personal_tab" msgid="1381052735324320565">"ສ່ວນຕົວ"</string>
+    <string name="resolver_personal_tab" msgid="1381052735324320565">"ສ່ວນບຸກຄົນ"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"ວຽກ"</string>
     <string name="resolver_private_tab" msgid="3707548826254095157">"ສ່ວນຕົວ"</string>
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"ມຸມມອງສ່ວນຕົວ"</string>
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ລາຍການແອັບ"</string>
     <string name="copy_text" msgid="1341801611046464360">"ສຳເນົາຂໍ້ຄວາມ"</string>
     <string name="copy_link" msgid="3822142723771306592">"ສຳເນົາລິ້ງ"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"ປິດໄວ້"</string>
 </resources>
diff --git a/java/res/values-lt/strings.xml b/java/res/values-lt/strings.xml
index f46f88e5..607cb34c 100644
--- a/java/res/values-lt/strings.xml
+++ b/java/res/values-lt/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Programų sąrašas"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopijuoti tekstą"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopijuoti nuorodą"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Uždaryti"</string>
 </resources>
diff --git a/java/res/values-lv/strings.xml b/java/res/values-lv/strings.xml
index 649533ab..f454e07f 100644
--- a/java/res/values-lv/strings.xml
+++ b/java/res/values-lv/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lietotņu saraksts"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopēt tekstu"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopēt saiti"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Nerādīt"</string>
 </resources>
diff --git a/java/res/values-mk/strings.xml b/java/res/values-mk/strings.xml
index 3204ff91..6d0ed9ed 100644
--- a/java/res/values-mk/strings.xml
+++ b/java/res/values-mk/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Список со апликации"</string>
     <string name="copy_text" msgid="1341801611046464360">"Копирај го текстот"</string>
     <string name="copy_link" msgid="3822142723771306592">"Копирај го линкот"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Отфрли"</string>
 </resources>
diff --git a/java/res/values-ml/strings.xml b/java/res/values-ml/strings.xml
index 63ddb262..9437476a 100644
--- a/java/res/values-ml/strings.xml
+++ b/java/res/values-ml/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ആപ്പ് ലിസ്റ്റ്"</string>
     <string name="copy_text" msgid="1341801611046464360">"ടെക്‌സ്റ്റ് പകർത്തുക"</string>
     <string name="copy_link" msgid="3822142723771306592">"ലിങ്ക് പകർത്തുക"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"ഡിസ്‌മിസ് ചെയ്യുക"</string>
 </resources>
diff --git a/java/res/values-mn/strings.xml b/java/res/values-mn/strings.xml
index 4ce3b15e..fda15cb8 100644
--- a/java/res/values-mn/strings.xml
+++ b/java/res/values-mn/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Аппын жагсаалт"</string>
     <string name="copy_text" msgid="1341801611046464360">"Текстийг хуулах"</string>
     <string name="copy_link" msgid="3822142723771306592">"Холбоосыг хуулах"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Хаах"</string>
 </resources>
diff --git a/java/res/values-mr/strings.xml b/java/res/values-mr/strings.xml
index dce1241b..b4525167 100644
--- a/java/res/values-mr/strings.xml
+++ b/java/res/values-mr/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"अ‍ॅप सूची"</string>
     <string name="copy_text" msgid="1341801611046464360">"मजकूर कॉपी करा"</string>
     <string name="copy_link" msgid="3822142723771306592">"लिंक कॉपी करा"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"डिसमिस करा"</string>
 </resources>
diff --git a/java/res/values-ms/strings.xml b/java/res/values-ms/strings.xml
index 300a763f..9737ca07 100644
--- a/java/res/values-ms/strings.xml
+++ b/java/res/values-ms/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Senarai apl"</string>
     <string name="copy_text" msgid="1341801611046464360">"Salin teks"</string>
     <string name="copy_link" msgid="3822142723771306592">"Salin pautan"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Ketepikan"</string>
 </resources>
diff --git a/java/res/values-my/strings.xml b/java/res/values-my/strings.xml
index 6a5f559b..695cffcf 100644
--- a/java/res/values-my/strings.xml
+++ b/java/res/values-my/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"အက်ပ်စာရင်း"</string>
     <string name="copy_text" msgid="1341801611046464360">"စာသားကူးရန်"</string>
     <string name="copy_link" msgid="3822142723771306592">"လင့်ခ်ကူးရန်"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"ပယ်ရန်"</string>
 </resources>
diff --git a/java/res/values-nb/strings.xml b/java/res/values-nb/strings.xml
index 7381eaa8..86c5baf5 100644
--- a/java/res/values-nb/strings.xml
+++ b/java/res/values-nb/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Appliste"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopier teksten"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopier linken"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Lukk"</string>
 </resources>
diff --git a/java/res/values-ne/strings.xml b/java/res/values-ne/strings.xml
index 18744d21..7201c765 100644
--- a/java/res/values-ne/strings.xml
+++ b/java/res/values-ne/strings.xml
@@ -45,11 +45,11 @@
     <string name="use_a_different_app" msgid="2062380818535918975">"अर्को एप प्रयोग गर्नुहोस्"</string>
     <string name="chooseActivity" msgid="6659724877523973446">"कारबाही चयन गर्नुहोस्"</string>
     <string name="noApplications" msgid="1139487441772284671">"कुनै पनि एपहरूले यो कार्य गर्न सक्दैनन्।"</string>
-    <string name="forward_intent_to_owner" msgid="6454987608971162379">"तपाईं तपाईंको कार्य प्रोफाइल बाहिर यो एप प्रयोग गरिरहनु भएको छ"</string>
-    <string name="forward_intent_to_work" msgid="2906094223089139419">"तपाईं आफ्नो कार्य प्रोफाइलमा यो एप प्रयोग गरिरहनु भएको छ"</string>
+    <string name="forward_intent_to_owner" msgid="6454987608971162379">"तपाईं तपाईंको वर्क प्रोफाइल बाहिर यो एप प्रयोग गरिरहनु भएको छ"</string>
+    <string name="forward_intent_to_work" msgid="2906094223089139419">"तपाईं आफ्नो वर्क प्रोफाइलमा यो एप प्रयोग गरिरहनु भएको छ"</string>
     <string name="activity_resolver_use_always" msgid="8674194687637555245">"सधैँ"</string>
     <string name="activity_resolver_use_once" msgid="594173435998892989">"एक पटक मात्र"</string>
-    <string name="activity_resolver_work_profiles_support" msgid="8228711455685203580">"<xliff:g id="APP">%1$s</xliff:g> ले कार्य प्रोफाइलमा काम गर्दैन"</string>
+    <string name="activity_resolver_work_profiles_support" msgid="8228711455685203580">"<xliff:g id="APP">%1$s</xliff:g> ले वर्क प्रोफाइलमा काम गर्दैन"</string>
     <string name="pin_specific_target" msgid="5057063421361441406">"<xliff:g id="LABEL">%1$s</xliff:g> पिन गर्नुहोस्"</string>
     <string name="unpin_specific_target" msgid="3115158908159857777">"<xliff:g id="LABEL">%1$s</xliff:g> लाई अनपिन गर्नुहोस्"</string>
     <string name="screenshot_edit" msgid="3857183660047569146">"सम्पादन गर्नुहोस्"</string>
@@ -91,11 +91,11 @@
     <string name="resolver_cant_access_private_apps_explanation" msgid="5978609934961648342">"यो सामग्री निजी एपहरूमार्फत खोल्न मिल्दैन"</string>
     <string name="resolver_turn_on_work_apps" msgid="7115260573975624516">"कामसम्बन्धी एपहरू पज गरिएका छन्"</string>
     <string name="resolver_switch_on_work" msgid="8678893259344318807">"अनपज गर्नुहोस्"</string>
-    <string name="resolver_no_work_apps_available" msgid="6139818641313189903">"यो सामग्री खोल्न मिल्ने कुनै पनि कामसम्बन्धी एप छैन"</string>
+    <string name="resolver_no_work_apps_available" msgid="6139818641313189903">"यो सामग्री खोल्न मिल्ने कुनै पनि वर्क एप छैन"</string>
     <string name="resolver_no_personal_apps_available" msgid="8479033344701050767">"यो सामग्री खोल्न मिल्ने कुनै पनि व्यक्तिगत एप छैन"</string>
     <string name="resolver_no_private_apps_available" msgid="4164473548027417456">"कुनै पनि निजी एप छैन"</string>
     <string name="miniresolver_open_in_personal" msgid="8397377137465016575">"<xliff:g id="APP">%s</xliff:g> तपाईंको व्यक्तिगत प्रोफाइलमा खोल्ने हो?"</string>
-    <string name="miniresolver_open_in_work" msgid="4271638122142624693">"<xliff:g id="APP">%s</xliff:g> तपाईंको कार्य प्रोफाइलमा खोल्ने हो?"</string>
+    <string name="miniresolver_open_in_work" msgid="4271638122142624693">"<xliff:g id="APP">%s</xliff:g> तपाईंको वर्क प्रोफाइलमा खोल्ने हो?"</string>
     <string name="miniresolver_use_personal_browser" msgid="1428911732509069292">"व्यक्तिगत ब्राउजर प्रयोग गर्नुहोस्"</string>
     <string name="miniresolver_use_work_browser" msgid="7892699758493230342">"कार्य ब्राउजर प्रयोग गर्नुहोस्"</string>
     <string name="exclude_text" msgid="5508128757025928034">"टेक्स्ट हटाउनुहोस्"</string>
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"एपहरूको सूची"</string>
     <string name="copy_text" msgid="1341801611046464360">"टेक्स्ट कपी गर्नुहोस्"</string>
     <string name="copy_link" msgid="3822142723771306592">"लिंक कपी गर्नुहोस्"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"बन्द गर्नुहोस्"</string>
 </resources>
diff --git a/java/res/values-nl/strings.xml b/java/res/values-nl/strings.xml
index de8050b9..77128d6f 100644
--- a/java/res/values-nl/strings.xml
+++ b/java/res/values-nl/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App-lijst"</string>
     <string name="copy_text" msgid="1341801611046464360">"Tekst kopiëren"</string>
     <string name="copy_link" msgid="3822142723771306592">"Link kopiëren"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Sluiten"</string>
 </resources>
diff --git a/java/res/values-or/strings.xml b/java/res/values-or/strings.xml
index c724f896..51fb6c99 100644
--- a/java/res/values-or/strings.xml
+++ b/java/res/values-or/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ଆପ ତାଲିକା"</string>
     <string name="copy_text" msgid="1341801611046464360">"ଟେକ୍ସଟ କପି କରନ୍ତୁ"</string>
     <string name="copy_link" msgid="3822142723771306592">"ଲିଙ୍କ କପି କରନ୍ତୁ"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"ଖାରଜ କରନ୍ତୁ"</string>
 </resources>
diff --git a/java/res/values-pa/strings.xml b/java/res/values-pa/strings.xml
index 32dc39de..23785ccf 100644
--- a/java/res/values-pa/strings.xml
+++ b/java/res/values-pa/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ਐਪ ਸੂਚੀ"</string>
     <string name="copy_text" msgid="1341801611046464360">"ਲਿਖਤ ਕਾਪੀ ਕਰੋ"</string>
     <string name="copy_link" msgid="3822142723771306592">"ਲਿੰਕ ਕਾਪੀ ਕਰੋ"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"ਖਾਰਜ ਕਰੋ"</string>
 </resources>
diff --git a/java/res/values-pl/strings.xml b/java/res/values-pl/strings.xml
index e11ffb35..ac40ce57 100644
--- a/java/res/values-pl/strings.xml
+++ b/java/res/values-pl/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista aplikacji"</string>
     <string name="copy_text" msgid="1341801611046464360">"Skopiuj tekst"</string>
     <string name="copy_link" msgid="3822142723771306592">"Skopiuj link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Zamknij"</string>
 </resources>
diff --git a/java/res/values-pt-rBR/strings.xml b/java/res/values-pt-rBR/strings.xml
index fd1f1863..b7b70cd1 100644
--- a/java/res/values-pt-rBR/strings.xml
+++ b/java/res/values-pt-rBR/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de apps"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copiar texto"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copiar link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Dispensar"</string>
 </resources>
diff --git a/java/res/values-pt-rPT/strings.xml b/java/res/values-pt-rPT/strings.xml
index c4be78e4..75cb2015 100644
--- a/java/res/values-pt-rPT/strings.xml
+++ b/java/res/values-pt-rPT/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de apps"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copiar texto"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copiar link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Ignorar"</string>
 </resources>
diff --git a/java/res/values-pt/strings.xml b/java/res/values-pt/strings.xml
index fd1f1863..b7b70cd1 100644
--- a/java/res/values-pt/strings.xml
+++ b/java/res/values-pt/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de apps"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copiar texto"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copiar link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Dispensar"</string>
 </resources>
diff --git a/java/res/values-ro/strings.xml b/java/res/values-ro/strings.xml
index faa360f4..3cd54378 100644
--- a/java/res/values-ro/strings.xml
+++ b/java/res/values-ro/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista cu aplicații"</string>
     <string name="copy_text" msgid="1341801611046464360">"Copiază textul"</string>
     <string name="copy_link" msgid="3822142723771306592">"Copiază linkul"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Închide"</string>
 </resources>
diff --git a/java/res/values-ru/strings.xml b/java/res/values-ru/strings.xml
index 637a6bf8..a77026de 100644
--- a/java/res/values-ru/strings.xml
+++ b/java/res/values-ru/strings.xml
@@ -19,7 +19,7 @@
     <string name="whichApplication" msgid="2309561338625872614">"Что использовать?"</string>
     <string name="whichApplicationNamed" msgid="8514249643796783492">"Выполнить действие с помощью приложения \"<xliff:g id="APP">%1$s</xliff:g>\""</string>
     <string name="whichApplicationLabel" msgid="4312929689807826793">"Выполнить действие"</string>
-    <string name="whichViewApplication" msgid="7660051361612888119">"Открыть с помощью приложения:"</string>
+    <string name="whichViewApplication" msgid="7660051361612888119">"Открыть в приложении"</string>
     <string name="whichViewApplicationNamed" msgid="8231810543224200555">"Открыть с помощью приложения \"<xliff:g id="APP">%1$s</xliff:g>\""</string>
     <string name="whichViewApplicationLabel" msgid="9123647023323311663">"Открыть"</string>
     <string name="whichOpenHostLinksWith" msgid="6664206254809230738">"Открывать ссылки <xliff:g id="HOST">%1$s</xliff:g> с помощью:"</string>
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Список приложений"</string>
     <string name="copy_text" msgid="1341801611046464360">"Копировать текст"</string>
     <string name="copy_link" msgid="3822142723771306592">"Копировать ссылку"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Закрыть"</string>
 </resources>
diff --git a/java/res/values-si/strings.xml b/java/res/values-si/strings.xml
index 482f0510..ac2c8bda 100644
--- a/java/res/values-si/strings.xml
+++ b/java/res/values-si/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"යෙදුම් ලැයිස්තුව"</string>
     <string name="copy_text" msgid="1341801611046464360">"පෙළ පිටපත් කරන්න"</string>
     <string name="copy_link" msgid="3822142723771306592">"සබැඳිය පිටපත් කරන්න"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"අස් කරන්න"</string>
 </resources>
diff --git a/java/res/values-sk/strings.xml b/java/res/values-sk/strings.xml
index c3a08830..04805fa0 100644
--- a/java/res/values-sk/strings.xml
+++ b/java/res/values-sk/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Zoznam aplikácií"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopírovať text"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopírovať odkaz"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Zavrieť"</string>
 </resources>
diff --git a/java/res/values-sl/strings.xml b/java/res/values-sl/strings.xml
index f5f77a1f..f6b04492 100644
--- a/java/res/values-sl/strings.xml
+++ b/java/res/values-sl/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Seznam aplikacij"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopiraj besedilo"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopiraj povezavo"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Opusti"</string>
 </resources>
diff --git a/java/res/values-sq/strings.xml b/java/res/values-sq/strings.xml
index b5383962..1db1bc12 100644
--- a/java/res/values-sq/strings.xml
+++ b/java/res/values-sq/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista e aplikacioneve"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopjo tekstin"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopjo lidhjen"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Hiq"</string>
 </resources>
diff --git a/java/res/values-sr/strings.xml b/java/res/values-sr/strings.xml
index 7a45c4eb..55dc4146 100644
--- a/java/res/values-sr/strings.xml
+++ b/java/res/values-sr/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Листа апликација"</string>
     <string name="copy_text" msgid="1341801611046464360">"Копирај текст"</string>
     <string name="copy_link" msgid="3822142723771306592">"Копирај линк"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Одбаци"</string>
 </resources>
diff --git a/java/res/values-sv/strings.xml b/java/res/values-sv/strings.xml
index ec838aee..7f795028 100644
--- a/java/res/values-sv/strings.xml
+++ b/java/res/values-sv/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Applista"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopiera text"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopiera länk"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Stäng"</string>
 </resources>
diff --git a/java/res/values-sw/strings.xml b/java/res/values-sw/strings.xml
index f6f2c63a..cd1423d2 100644
--- a/java/res/values-sw/strings.xml
+++ b/java/res/values-sw/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Orodha ya programu"</string>
     <string name="copy_text" msgid="1341801611046464360">"Nakili maandishi"</string>
     <string name="copy_link" msgid="3822142723771306592">"Nakili kiungo"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Ondoa"</string>
 </resources>
diff --git a/java/res/values-sw600dp/dimens.xml b/java/res/values-sw600dp/dimens.xml
index e152ba06..4fc63fc3 100644
--- a/java/res/values-sw600dp/dimens.xml
+++ b/java/res/values-sw600dp/dimens.xml
@@ -18,7 +18,6 @@
 */
 -->
 <resources>
-    <dimen name="chooser_width">624dp</dimen>
     <dimen name="modify_share_text_toggle_max_width">250dp</dimen>
     <dimen name="chooser_item_focus_outline_corner_radius">16dp</dimen>
 </resources>
diff --git a/java/res/values-ta/strings.xml b/java/res/values-ta/strings.xml
index fa40446f..8a2c3a0b 100644
--- a/java/res/values-ta/strings.xml
+++ b/java/res/values-ta/strings.xml
@@ -78,7 +78,7 @@
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"இந்த ஆப்ஸிற்கு ரெக்கார்டு செய்வதற்கான அனுமதி வழங்கப்படவில்லை, எனினும் இந்த USB சாதனம் மூலம் ஆடியோவைப் பதிவுசெய்ய முடியும்."</string>
     <string name="resolver_personal_tab" msgid="1381052735324320565">"தனிப்பட்ட சுயவிவரம்"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"பணிச் சுயவிவரம்"</string>
-    <string name="resolver_private_tab" msgid="3707548826254095157">"இரகசியமானவை"</string>
+    <string name="resolver_private_tab" msgid="3707548826254095157">"ரகசியமானவை"</string>
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"தனிப்பட்ட காட்சி"</string>
     <string name="resolver_work_tab_accessibility" msgid="7581878836587799920">"பணிக் காட்சி"</string>
     <string name="resolver_private_tab_accessibility" msgid="2513122834337197252">"ரகசியக் காட்சி"</string>
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ஆப்ஸ் பட்டியல்"</string>
     <string name="copy_text" msgid="1341801611046464360">"வார்த்தைகளை நகலெடுக்கும்"</string>
     <string name="copy_link" msgid="3822142723771306592">"இணைப்பை நகலெடுக்கும்"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"மூடும்"</string>
 </resources>
diff --git a/java/res/values-te/strings.xml b/java/res/values-te/strings.xml
index 267978b8..6120aea9 100644
--- a/java/res/values-te/strings.xml
+++ b/java/res/values-te/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"యాప్ లిస్ట్"</string>
     <string name="copy_text" msgid="1341801611046464360">"టెక్స్ట్‌ను కాపీ చేయండి"</string>
     <string name="copy_link" msgid="3822142723771306592">"లింక్‌ను కాపీ చేయండి"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"విస్మరించండి"</string>
 </resources>
diff --git a/java/res/values-th/strings.xml b/java/res/values-th/strings.xml
index d20d8189..b86e8a5d 100644
--- a/java/res/values-th/strings.xml
+++ b/java/res/values-th/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"รายการแอป"</string>
     <string name="copy_text" msgid="1341801611046464360">"คัดลอกข้อความ"</string>
     <string name="copy_link" msgid="3822142723771306592">"คัดลอกลิงก์"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"ปิด"</string>
 </resources>
diff --git a/java/res/values-tl/strings.xml b/java/res/values-tl/strings.xml
index 13bf4863..d82712ea 100644
--- a/java/res/values-tl/strings.xml
+++ b/java/res/values-tl/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Listahan ng app"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopyahin ang text"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopyahin ang link"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"I-dismiss"</string>
 </resources>
diff --git a/java/res/values-tr/strings.xml b/java/res/values-tr/strings.xml
index 4bfe38b1..b5c5ac26 100644
--- a/java/res/values-tr/strings.xml
+++ b/java/res/values-tr/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Uygulama listesi"</string>
     <string name="copy_text" msgid="1341801611046464360">"Metni kopyala"</string>
     <string name="copy_link" msgid="3822142723771306592">"Bağlantıyı kopyala"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Kapat"</string>
 </resources>
diff --git a/java/res/values-uk/strings.xml b/java/res/values-uk/strings.xml
index db252f2e..57e11d95 100644
--- a/java/res/values-uk/strings.xml
+++ b/java/res/values-uk/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Список додатків"</string>
     <string name="copy_text" msgid="1341801611046464360">"Копіювати текст"</string>
     <string name="copy_link" msgid="3822142723771306592">"Копіювати посилання"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Закрити"</string>
 </resources>
diff --git a/java/res/values-ur/strings.xml b/java/res/values-ur/strings.xml
index 6d52881c..a0bc0a8a 100644
--- a/java/res/values-ur/strings.xml
+++ b/java/res/values-ur/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ایپ کی فہرست"</string>
     <string name="copy_text" msgid="1341801611046464360">"ٹیکسٹ کاپی کریں"</string>
     <string name="copy_link" msgid="3822142723771306592">"لنک کاپی کریں"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"برخاست کریں"</string>
 </resources>
diff --git a/java/res/values-uz/strings.xml b/java/res/values-uz/strings.xml
index 90c1008b..3eb60fa6 100644
--- a/java/res/values-uz/strings.xml
+++ b/java/res/values-uz/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Ilovalar roʻyxati"</string>
     <string name="copy_text" msgid="1341801611046464360">"Matnni nusxalash"</string>
     <string name="copy_link" msgid="3822142723771306592">"Havoladan nusxa olish"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Yopish"</string>
 </resources>
diff --git a/java/res/values-vi/strings.xml b/java/res/values-vi/strings.xml
index a3ad15fa..6404c537 100644
--- a/java/res/values-vi/strings.xml
+++ b/java/res/values-vi/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Danh sách ứng dụng"</string>
     <string name="copy_text" msgid="1341801611046464360">"Sao chép văn bản"</string>
     <string name="copy_link" msgid="3822142723771306592">"Sao chép đường liên kết"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Đóng"</string>
 </resources>
diff --git a/java/res/values-zh-rCN/strings.xml b/java/res/values-zh-rCN/strings.xml
index 761fa8e3..fe553da9 100644
--- a/java/res/values-zh-rCN/strings.xml
+++ b/java/res/values-zh-rCN/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"应用列表"</string>
     <string name="copy_text" msgid="1341801611046464360">"复制文字"</string>
     <string name="copy_link" msgid="3822142723771306592">"复制链接"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"关闭"</string>
 </resources>
diff --git a/java/res/values-zh-rHK/strings.xml b/java/res/values-zh-rHK/strings.xml
index 6a4a37bf..4296cef7 100644
--- a/java/res/values-zh-rHK/strings.xml
+++ b/java/res/values-zh-rHK/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"應用程式清單"</string>
     <string name="copy_text" msgid="1341801611046464360">"複製文字"</string>
     <string name="copy_link" msgid="3822142723771306592">"複製連結"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"關閉"</string>
 </resources>
diff --git a/java/res/values-zh-rTW/strings.xml b/java/res/values-zh-rTW/strings.xml
index 9e8342d8..1e7e31af 100644
--- a/java/res/values-zh-rTW/strings.xml
+++ b/java/res/values-zh-rTW/strings.xml
@@ -85,7 +85,7 @@
     <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"IT 管理員已封鎖這項操作"</string>
     <string name="resolver_cant_share_with_work_apps_explanation" msgid="2984105853145456723">"無法透過工作應用程式分享這項內容"</string>
     <string name="resolver_cant_access_work_apps_explanation" msgid="1463093773348988122">"無法使用工作應用程式開啟這項內容"</string>
-    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"無法與個人應用程式分享這項內容"</string>
+    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"無法透過個人應用程式分享這項內容"</string>
     <string name="resolver_cant_access_personal_apps_explanation" msgid="6209543716289792706">"無法使用個人應用程式開啟這項內容"</string>
     <string name="resolver_cant_share_with_private_apps_explanation" msgid="1781980997411434697">"無法透過私人應用程式分享這項內容"</string>
     <string name="resolver_cant_access_private_apps_explanation" msgid="5978609934961648342">"無法使用私人應用程式開啟這項內容"</string>
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"應用程式清單"</string>
     <string name="copy_text" msgid="1341801611046464360">"複製文字"</string>
     <string name="copy_link" msgid="3822142723771306592">"複製連結"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"關閉"</string>
 </resources>
diff --git a/java/res/values-zu/strings.xml b/java/res/values-zu/strings.xml
index f1644127..47490af2 100644
--- a/java/res/values-zu/strings.xml
+++ b/java/res/values-zu/strings.xml
@@ -113,4 +113,5 @@
     <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Uhlu lwama-app"</string>
     <string name="copy_text" msgid="1341801611046464360">"Kopisha umbhalo"</string>
     <string name="copy_link" msgid="3822142723771306592">"Kopisha ilinki"</string>
+    <string name="exit_button_label" msgid="6396378400527479806">"Chitha"</string>
 </resources>
diff --git a/java/res/values/attrs.xml b/java/res/values/attrs.xml
index 19d85573..b40c671a 100644
--- a/java/res/values/attrs.xml
+++ b/java/res/values/attrs.xml
@@ -33,9 +33,7 @@
              top limit the ignoreOffset elements. -->
         <attr name="ignoreOffsetTopLimit" format="reference" />
         <!-- Specifies whether ResolverDrawerLayout should use an alternative nested fling logic
-        adjusted for the scrollable preview feature.
-        Controlled by the flag com.android.intentresolver.Flags#FLAG_SCROLLABLE_PREVIEW.
-        -->
+        adjusted for the scrollable preview feature. -->
         <attr name="useScrollablePreviewNestedFlingLogic" format="boolean" />
     </declare-styleable>
 
diff --git a/java/res/values-port/dimens.xml b/java/res/values/bools.xml
similarity index 71%
rename from java/res/values-port/dimens.xml
rename to java/res/values/bools.xml
index 100a7e17..71027ae6 100644
--- a/java/res/values-port/dimens.xml
+++ b/java/res/values/bools.xml
@@ -1,5 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
 <!--
-  ~ Copyright (C) 2022 The Android Open Source Project
+  ~ Copyright (C) 2025 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
   ~ you may not use this file except in compliance with the License.
@@ -13,6 +14,7 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-<resources xmlns:android="http://schemas.android.com/apk/res/android">
-    <dimen name="chooser_width">-1px</dimen>
-</resources>
+<resources>
+    <!-- whether to show the chooser grid preview at the top -->
+    <bool name="show_preview_at_top">false</bool>
+</resources>
\ No newline at end of file
diff --git a/java/res/values/colors.xml b/java/res/values/colors.xml
index 966c2d28..e301daf2 100644
--- a/java/res/values/colors.xml
+++ b/java/res/values/colors.xml
@@ -21,6 +21,10 @@
     <color name="chooser_row_divider">@*android:color/list_divider_color_light</color>
     <color name="chooser_gradient_background">@*android:color/loading_gradient_background_color_light</color>
 
+    <color name="chooser_action_button_bg_color">@androidprv:color/materialColorSurfaceContainerHigh</color>
+    <color name="chooser_action_button_drawable_tint_color">@androidprv:color/materialColorOnSurface</color>
+    <color name="chooser_action_button_text_color">@androidprv:color/materialColorOnSurface</color>
+    <color name="chooser_content_preview_rounded_color">@androidprv:color/materialColorSurfaceContainerHigh</color>
     <color name="chooser_grid_layout_background">@androidprv:color/materialColorSurfaceContainer</color>
     <color name="chooser_grid_preview_background">@androidprv:color/materialColorSurfaceContainer</color>
     <color name="chooser_grid_item_text1_color">@androidprv:color/materialColorOnSurface</color>
@@ -30,4 +34,6 @@
     <color name="content_preview_text_color">@androidprv:color/materialColorOnSurfaceVariant</color>
     <color name="content_preview_copy_icon_tint">@androidprv:color/materialColorOnSurfaceVariant</color>
     <color name="chooser_row_text_color">@androidprv:color/materialColorOnSurfaceVariant</color>
+    <color name="icon_tint_color">@androidprv:color/materialColorOnSurface</color>
+    <color name="resolver_common_window_background_color">@android:color/transparent</color>
 </resources>
diff --git a/java/res/values/config.xml b/java/res/values/config.xml
index 1890bc6d..925f1f52 100644
--- a/java/res/values/config.xml
+++ b/java/res/values/config.xml
@@ -34,6 +34,11 @@
          Used by ChooserActivity. -->
     <string translatable="false" name="config_defaultNearbySharingComponent">@*android:string/config_defaultNearbySharingComponent</string>
 
+    <!-- Chooser image editing activity.  Must handle ACTION_EDIT image/png intents.
+         If omitted, image editing will not be offered via Chooser.
+         This name is in the ComponentName flattened format (package/class) [DO NOT TRANSLATE]  -->
+    <string name="config_preferredSystemImageEditor" translatable="false">@*android:string/config_preferredSystemImageEditor</string>
+
     <!-- Chooser image editing activity.  Must handle ACTION_EDIT image/png intents.
          If omitted, image editing will not be offered via Chooser.
          This name is in the ComponentName flattened format (package/class) [DO NOT TRANSLATE]  -->
diff --git a/java/res/values/dimens.xml b/java/res/values/dimens.xml
index 805f00f5..55b75c43 100644
--- a/java/res/values/dimens.xml
+++ b/java/res/values/dimens.xml
@@ -19,7 +19,7 @@
     <!-- chooser/resolver (sharesheet) spacing -->
     <dimen name="chooser_action_corner_radius">28dp</dimen>
     <dimen name="chooser_action_horizontal_margin">2dp</dimen>
-    <dimen name="chooser_width">450dp</dimen>
+    <dimen name="chooser_width">624dp</dimen>
     <dimen name="chooser_corner_radius">28dp</dimen>
     <dimen name="chooser_corner_radius_small">14dp</dimen>
     <dimen name="chooser_row_text_option_translate">25dp</dimen>
@@ -78,15 +78,14 @@
     <dimen name="view_holder_height">200dp</dimen>
     <dimen name="chooser_grid_item_space_height">7dp</dimen>
 
-    <dimen name="chooser_margin_vertical">80dp</dimen>
-    <dimen name="chooser_padding_bottom">80dp</dimen>
-    <dimen name="chooser_padding_start">0dp</dimen>
-    <dimen name="chooser_padding_end">0dp</dimen>
-    <dimen name="chooser_close_icon_size">60dp</dimen>
-    <dimen name="chooser_close_icon_size_margin">16dp</dimen>
-    <dimen name="chooser_content_view_margin_horizontal">200dp</dimen>
-    <dimen name="chooser_content_view_margin_vertical">16dp</dimen>
+    <dimen name="chooser_margin_vertical">0dp</dimen>
+    <dimen name="chooser_close_icon_size">16dp</dimen>
+    <dimen name="chooser_close_icon_size_margin">0dp</dimen>
+    <dimen name="chooser_content_view_margin_horizontal">0dp</dimen>
+    <dimen name="chooser_content_view_margin_vertical">0dp</dimen>
     <dimen name="chooser_content_view_min_height">0dp</dimen>
+    <dimen name="chooser_content_view_margin_top">0dp</dimen>
+    <dimen name="chooser_profile_tabhost_margin_horizontal">0dp</dimen>
 
     <!-- Note that the values in this section are for landscape phones. For screen configs taller
          than 480dp, the values are set in values-h480dp/dimens.xml -->
@@ -94,6 +93,8 @@
     <dimen name="chooser_preview_image_height_tall">124dp</dimen>
     <dimen name="grid_padding_vertical">8dp</dimen>
     <dimen name="grid_padding_horizontal">4dp</dimen>
+    <dimen name="grid_padding_vertical_hover">1dp</dimen>
+    <dimen name="grid_padding_horizontal_hover">4dp</dimen>
     <dimen name="width_text_image_preview_size">46dp</dimen>
     <!-- END SECTION -->
 </resources>
diff --git a/java/res/values/integers.xml b/java/res/values/integers.xml
index 8d203bca..719a3d2a 100644
--- a/java/res/values/integers.xml
+++ b/java/res/values/integers.xml
@@ -18,4 +18,10 @@
     <!-- Note that this is the value for landscape phones, the value for all screens taller than
          480dp is set in values-h480dp/integers.xml -->
     <integer name="text_preview_lines">3</integer>
+    <!-- This is a value used to control whether to show the head for the chooser grid preview on
+         the chooser grid preview page. 0 is visible, 2 is gone. -->
+    <integer name="chooser_header_for_preview_visibility">0</integer>
+    <!-- This is a value used to control whether to show the close button on the chooser grid
+         preview page. 0 is visible, 2 is gone. -->
+    <integer name="preview_close_button_visibility">2</integer>
 </resources>
diff --git a/java/res/values/overlayable.xml b/java/res/values/overlayable.xml
new file mode 100644
index 00000000..5a5e1160
--- /dev/null
+++ b/java/res/values/overlayable.xml
@@ -0,0 +1,80 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<resources>
+  <overlayable name="IntentResolver">
+      <policy type="odm|oem|product|signature|system|vendor">
+          <item type="bool" name="show_preview_at_top"/>
+
+          <item type="color" name="chooser_action_button_bg_color"/>
+          <item type="color" name="chooser_action_button_drawable_tint_color"/>
+          <item type="color" name="chooser_action_button_text_color"/>
+          <item type="color" name="chooser_content_preview_rounded_color"/>
+          <item type="color" name="chooser_grid_preview_background"/>
+          <item type="color" name="chooser_grid_layout_background"/>
+          <item type="color" name="chooser_grid_item_text1_color"/>
+          <item type="color" name="chooser_grid_item_text2_color"/>
+          <item type="color" name="chooser_row_text_color"/>
+          <item type="color" name="content_preview_filename_text_color"/>
+          <item type="color" name="content_preview_more_files_text_color"/>
+          <item type="color" name="content_preview_text_color"/>
+          <item type="color" name="content_preview_copy_icon_tint"/>
+          <item type="color" name="icon_tint_color"/>
+          <item type="color" name="resolver_common_window_background_color"/>
+
+          <item type="dimen" name="chooser_action_view_icon_size"/>
+          <item type="dimen" name="chooser_action_view_text_size"/>
+          <item type="dimen" name="chooser_action_horizontal_margin"/>
+          <item type="dimen" name="chooser_width"/>
+          <item type="dimen" name="chooser_margin_vertical"/>
+          <item type="dimen" name="chooser_list_padding"/>
+          <item type="dimen" name="chooser_close_icon_size"/>
+          <item type="dimen" name="chooser_close_icon_size_margin"/>
+          <item type="dimen" name="chooser_content_view_margin_horizontal"/>
+          <item type="dimen" name="chooser_content_view_margin_vertical"/>
+          <item type="dimen" name="chooser_content_view_min_height"/>
+          <item type="dimen" name="chooser_content_view_margin_top"/>
+          <item type="dimen" name="chooser_edge_margin_normal_half"/>
+          <item type="dimen" name="chooser_edge_margin_normal"/>
+          <item type="dimen" name="chooser_profile_tabhost_margin_horizontal"/>
+          <item type="dimen" name="chooser_grid_target_name_text_size"/>
+          <item type="dimen" name="chooser_grid_activity_name_text_size"/>
+          <item type="dimen" name="chooser_icon_size"/>
+          <item type="dimen" name="chooser_icon_horizontal_padding"/>
+          <item type="dimen" name="chooser_icon_vertical_padding"/>
+          <item type="dimen" name="chooser_icon_height_with_padding"/>
+          <item type="dimen" name="chooser_icon_width_with_padding"/>
+          <item type="dimen" name="chooser_item_focus_outline_corner_radius"/>
+          <item type="dimen" name="chooser_headline_text_size"/>
+          <item type="dimen" name="chooser_row_height"/>
+          <item type="dimen" name="content_preview_copy_icon_size"/>
+          <item type="dimen" name="content_preview_text_size"/>
+          <item type="dimen" name="content_preview_filename_line_size"/>
+          <item type="dimen" name="content_preview_more_files_text_size"/>
+          <item type="dimen" name="content_preview_more_files_line_size"/>
+          <item type="dimen" name="grid_padding_vertical"/>
+          <item type="dimen" name="grid_padding_horizontal"/>
+          <item type="dimen" name="grid_padding_vertical_hover"/>
+          <item type="dimen" name="grid_padding_horizontal_hover"/>
+
+          <item type="integer" name="config_chooser_max_targets_per_row"/>
+          <item type="integer" name="chooser_header_for_preview_visibility"/>
+          <item type="integer" name="preview_close_button_visibility"/>
+          <item type="style" name="Theme.DeviceDefault.ResolverCommon"/>
+          <item type="style" name="TextAppearance.ChooserDefault"/>
+      </policy>
+  </overlayable>
+</resources>
diff --git a/java/res/values/strings.xml b/java/res/values/strings.xml
index c9ee9d80..dc96520b 100644
--- a/java/res/values/strings.xml
+++ b/java/res/values/strings.xml
@@ -360,4 +360,7 @@
     <!-- Content description for an action chip button in the content preview UI when a link is
          shared. The button is used to copy the text into the clipboard. [CHAR_LIMIT=NONE] -->
     <string name="copy_link">Copy link</string>
+
+    <!-- The content description label for the exit button. [CHAR_LIMIT=NONE] -->
+    <string name="exit_button_label">Dismiss</string>
 </resources>
diff --git a/java/res/values/styles.xml b/java/res/values/styles.xml
index 143009d0..383e88dc 100644
--- a/java/res/values/styles.xml
+++ b/java/res/values/styles.xml
@@ -27,7 +27,7 @@
         <item name="android:windowAnimationStyle">@style/ResolverAnimation</item>
         <item name="android:windowIsTranslucent">true</item>
         <item name="android:windowNoTitle">true</item>
-        <item name="android:windowBackground">@android:color/transparent</item>
+        <item name="android:windowBackground">@color/resolver_common_window_background_color</item>
         <item name="android:backgroundDimEnabled">true</item>
         <item name="android:statusBarColor">@android:color/transparent</item>
         <item name="android:windowContentOverlay">@null</item>
diff --git a/java/src/android/service/chooser/ChooserSession.kt b/java/src/android/service/chooser/ChooserSession.kt
deleted file mode 100644
index 3bbe23a4..00000000
--- a/java/src/android/service/chooser/ChooserSession.kt
+++ /dev/null
@@ -1,39 +0,0 @@
-/*
- * Copyright 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      https://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package android.service.chooser
-
-import android.os.Parcel
-import android.os.Parcelable
-import com.android.intentresolver.IChooserInteractiveSessionCallback
-
-/** A stub for the potential future API class. */
-class ChooserSession(val sessionCallbackBinder: IChooserInteractiveSessionCallback) : Parcelable {
-    override fun describeContents() = 0
-
-    override fun writeToParcel(dest: Parcel, flags: Int) {
-        TODO("Not yet implemented")
-    }
-
-    companion object CREATOR : Parcelable.Creator<ChooserSession> {
-        override fun createFromParcel(source: Parcel): ChooserSession? =
-            ChooserSession(
-                IChooserInteractiveSessionCallback.Stub.asInterface(source.readStrongBinder())
-            )
-
-        override fun newArray(size: Int): Array<out ChooserSession?> = arrayOfNulls(size)
-    }
-}
diff --git a/java/src/com/android/intentresolver/ChooserActionFactory.java b/java/src/com/android/intentresolver/ChooserActionFactory.java
index 21ca3b73..c76ba6d6 100644
--- a/java/src/com/android/intentresolver/ChooserActionFactory.java
+++ b/java/src/com/android/intentresolver/ChooserActionFactory.java
@@ -68,22 +68,22 @@ public final class ChooserActionFactory implements ChooserContentPreviewUi.Actio
          * Request an activity launch for the provided target. Implementations may choose to exit
          * the current activity when the target is launched.
          */
-        void safelyStartActivityAsPersonalProfileUser(TargetInfo info);
+        void safelyStartActivityAsLaunchingUser(TargetInfo info);
 
         /**
          * Request an activity launch for the provided target, optionally employing the specified
          * shared element transition. Implementations may choose to exit the current activity when
          * the target is launched.
          */
-        default void safelyStartActivityAsPersonalProfileUserWithSharedElementTransition(
+        default void safelyStartActivityAsLaunchingUserWithSharedElementTransition(
                 TargetInfo info, View sharedElement, String sharedElementName) {
-            safelyStartActivityAsPersonalProfileUser(info);
+            safelyStartActivityAsLaunchingUser(info);
         }
     }
 
     private static final String TAG = "ChooserActions";
 
-    private static final int URI_PERMISSION_INTENT_FLAGS = Intent.FLAG_GRANT_READ_URI_PERMISSION
+    public static final int URI_PERMISSION_INTENT_FLAGS = Intent.FLAG_GRANT_READ_URI_PERMISSION
             | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
             | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
             | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION;
@@ -92,13 +92,13 @@ public final class ChooserActionFactory implements ChooserContentPreviewUi.Actio
     // for the sharesheet editing flow.
     // Note: EDIT_SOURCE is also used as a signal to avoid sending a 'Component Selected'
     // ShareResult for this intent when sent via ChooserActivity#safelyStartActivityAsUser
-    static final String EDIT_SOURCE = "edit_source";
-    private static final String EDIT_SOURCE_SHARESHEET = "sharesheet";
+    public static final String EDIT_SOURCE = "edit_source";
+    public static final String EDIT_SOURCE_SHARESHEET = "sharesheet";
 
     private static final String CHIP_LABEL_METADATA_KEY = "android.service.chooser.chip_label";
     private static final String CHIP_ICON_METADATA_KEY = "android.service.chooser.chip_icon";
 
-    private static final String IMAGE_EDITOR_SHARED_ELEMENT = "screenshot_preview_image";
+    public static final String IMAGE_EDITOR_SHARED_ELEMENT = "screenshot_preview_image";
 
     private final Context mContext;
 
@@ -350,9 +350,9 @@ public final class ChooserActionFactory implements ChooserContentPreviewUi.Actio
             } catch (Exception e) { /* ignore */ }
             // Action bar is user-independent; always start as primary.
             if (firstImageView == null || !isFullyVisible(firstImageView)) {
-                activityStarter.safelyStartActivityAsPersonalProfileUser(editSharingTarget);
+                activityStarter.safelyStartActivityAsLaunchingUser(editSharingTarget);
             } else {
-                activityStarter.safelyStartActivityAsPersonalProfileUserWithSharedElementTransition(
+                activityStarter.safelyStartActivityAsLaunchingUserWithSharedElementTransition(
                         editSharingTarget, firstImageView, IMAGE_EDITOR_SHARED_ELEMENT);
             }
         };
diff --git a/java/src/com/android/intentresolver/ChooserActivity.java b/java/src/com/android/intentresolver/ChooserActivity.java
index aff34580..d1bb4daf 100644
--- a/java/src/com/android/intentresolver/ChooserActivity.java
+++ b/java/src/com/android/intentresolver/ChooserActivity.java
@@ -18,23 +18,23 @@ package com.android.intentresolver;
 
 import static android.app.VoiceInteractor.PickOptionRequest.Option;
 import static android.content.Intent.FLAG_ACTIVITY_NEW_TASK;
+import static android.service.chooser.Flags.interactiveChooser;
 import static android.view.WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS;
 
 import static androidx.lifecycle.LifecycleKt.getCoroutineScope;
 
 import static com.android.intentresolver.ChooserActionFactory.EDIT_SOURCE;
 import static com.android.intentresolver.Flags.delayDrawerOffsetCalculation;
-import static com.android.intentresolver.Flags.fixShortcutsFlashingFixed;
-import static com.android.intentresolver.Flags.interactiveSession;
-import static com.android.intentresolver.Flags.keyboardNavigationFix;
 import static com.android.intentresolver.Flags.rebuildAdaptersOnTargetPinning;
 import static com.android.intentresolver.Flags.refineSystemActions;
-import static com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra;
-import static com.android.intentresolver.Flags.unselectFinalItem;
+import static com.android.intentresolver.Flags.sharesheetEscExit;
+import static com.android.intentresolver.Flags.synchronousDrawerOffsetCalculation;
 import static com.android.intentresolver.ext.CreationExtrasExtKt.replaceDefaultArgs;
 import static com.android.intentresolver.profiles.MultiProfilePagerAdapter.PROFILE_PERSONAL;
 import static com.android.intentresolver.profiles.MultiProfilePagerAdapter.PROFILE_WORK;
+import static com.android.intentresolver.widget.ViewExtensionsKt.isFullyVisible;
 import static com.android.internal.util.LatencyTracker.ACTION_LOAD_SHARE_SHEET;
+import static com.android.systemui.shared.Flags.usePreferredImageEditor;
 
 import static java.util.Objects.requireNonNull;
 
@@ -75,6 +75,7 @@ import android.text.TextUtils;
 import android.util.Log;
 import android.util.Slog;
 import android.view.Gravity;
+import android.view.KeyEvent;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
@@ -101,6 +102,7 @@ import androidx.recyclerview.widget.RecyclerView;
 import androidx.viewpager.widget.ViewPager;
 
 import com.android.intentresolver.ChooserRefinementManager.RefinementType;
+import com.android.intentresolver.actions.ImageEditorActionFactory;
 import com.android.intentresolver.chooser.DisplayResolveInfo;
 import com.android.intentresolver.chooser.MultiDisplayResolveInfo;
 import com.android.intentresolver.chooser.TargetInfo;
@@ -126,7 +128,7 @@ import com.android.intentresolver.model.AbstractResolverComparator;
 import com.android.intentresolver.model.AppPredictionServiceResolverComparator;
 import com.android.intentresolver.model.ResolverRankerServiceResolverComparator;
 import com.android.intentresolver.platform.AppPredictionAvailable;
-import com.android.intentresolver.platform.ImageEditor;
+import com.android.intentresolver.platform.FallbackImageEditor;
 import com.android.intentresolver.platform.NearbyShare;
 import com.android.intentresolver.profiles.ChooserMultiProfilePagerAdapter;
 import com.android.intentresolver.profiles.MultiProfilePagerAdapter.ProfileType;
@@ -141,6 +143,7 @@ import com.android.intentresolver.ui.ActionTitle;
 import com.android.intentresolver.ui.ProfilePagerResources;
 import com.android.intentresolver.ui.ShareResultSender;
 import com.android.intentresolver.ui.ShareResultSenderFactory;
+import com.android.intentresolver.ui.model.ShareAction;
 import com.android.intentresolver.ui.viewmodel.ChooserViewModel;
 import com.android.intentresolver.widget.ActionRow;
 import com.android.intentresolver.widget.ChooserNestedScrollView;
@@ -263,7 +266,10 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     @Inject public ChooserHelper mChooserHelper;
     @Inject public EventLog mEventLog;
     @Inject @AppPredictionAvailable public boolean mAppPredictionAvailable;
-    @Inject @ImageEditor public Optional<ComponentName> mImageEditor;
+    @Inject @FallbackImageEditor
+    public Optional<ComponentName> mImageEditor;
+
+    @Inject public ImageEditorActionFactory mImageEditorActionFactory;
     @Inject @NearbyShare public Optional<ComponentName> mNearbyShare;
     @Inject
     @Caching
@@ -280,7 +286,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     private ChooserRequest mRequest;
     private ProfileHelper mProfiles;
     private ProfileAvailability mProfileAvailability;
-    @Nullable private ShareResultSender mShareResultSender;
+    private ShareResultSender mShareResultSender;
 
     private ChooserRefinementManager mRefinementManager;
 
@@ -329,6 +335,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     }
 
     private ChooserViewModel mViewModel;
+    private int mInitialProfile = -1;
 
     @NonNull
     @Override
@@ -352,11 +359,8 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         mChooserHelper.setInitializer(this::initialize);
         mChooserHelper.setOnChooserRequestChanged(this::onChooserRequestChanged);
         mChooserHelper.setOnPendingSelection(this::onPendingSelection);
-        if (unselectFinalItem()) {
-            mChooserHelper.setOnHasSelections(this::onHasSelections);
-        }
+        mChooserHelper.setOnTargetEnabled(this::onTargetEnabledChanged);
     }
-    private int mInitialProfile = -1;
 
     @Override
     protected final void onStart() {
@@ -467,7 +471,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
 
         if (isFinishing()) {
             mLatencyTracker.onActionCancel(ACTION_LOAD_SHARE_SHEET);
-            if (interactiveSession() && mViewModel != null) {
+            if (interactiveChooser() && mViewModel != null) {
                 mViewModel.getInteractiveSessionInteractor().endSession();
             }
         }
@@ -479,10 +483,12 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
 
     /** DO NOT CALL. Only for use from ChooserHelper as a callback. */
     private void initialize() {
-
         mViewModel = new ViewModelProvider(this).get(ChooserViewModel.class);
         mRequest = mViewModel.getRequest().getValue();
         mActivityModel = mViewModel.getActivityModel();
+        if (isInteractiveSession()) {
+            maybeUpdateColorScheme();
+        }
 
         mProfiles =  new ProfileHelper(
                 mUserInteractor,
@@ -525,7 +531,6 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 mProfiles,
                 mProfileRecords.values(),
                 mProfileAvailability,
-                mRequest.getInitialIntents(),
                 mMaxTargetsPerRow);
 
         maybeDisableRecentsScreenshot(mProfiles, mProfileAvailability);
@@ -630,8 +635,17 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                     break;
 
                     case EDIT_ACTION: {
-                        if (refinedActionFactory.getEditButtonRunnable() != null) {
-                            refinedActionFactory.getEditButtonRunnable().run();
+                        if (usePreferredImageEditor()) {
+                            mShareResultSender.onActionSelected(ShareAction.SYSTEM_EDIT);
+                            mImageEditorActionFactory.getImageEditorTargetInfoAsync(
+                                    getCoroutineScope(getLifecycle()),
+                                    completion.getRefinedIntent(),
+                                    targetInfo -> launchImageEditor(targetInfo));
+                            return;
+                        } else {
+                            if (refinedActionFactory.getEditButtonRunnable() != null) {
+                                refinedActionFactory.getEditButtonRunnable().run();
+                            }
                         }
                     }
                     break;
@@ -655,6 +669,26 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 mRequest.getContentTypeHint(),
                 mRequest.getMetadataText());
         updateStickyContentPreview();
+
+        if (usePreferredImageEditor()) {
+            mImageEditorActionFactory.getImageEditorTargetInfoAsync(
+                    getCoroutineScope(getLifecycle()),
+                    mRequest.getTargetIntent(),
+                    targetInfo -> mChooserContentPreviewUi.setImageEditorCallback(() -> {
+                        if (!mRefinementManager.maybeHandleSelection(
+                                RefinementType.EDIT_ACTION,
+                                List.of(mRequest.getTargetIntent()),
+                                null,
+                                mRequest.getRefinementIntentSender(),
+                                getApplication(),
+                                getMainThreadHandler())) {
+                            // No refinement needed, launch it.
+                            mShareResultSender.onActionSelected(ShareAction.SYSTEM_EDIT);
+                            launchImageEditor(targetInfo);
+                        }
+                    }));
+        }
+
         if (shouldShowStickyContentPreview()) {
             getEventLog().logActionShareWithPreview(
                     mChooserContentPreviewUi.getPreferredContentPreview());
@@ -664,7 +698,12 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         getEventLog().logChooserActivityShown(
                 isWorkProfile(), mRequest.getTargetType(), systemCost);
         if (mResolverDrawerLayout != null) {
-            mResolverDrawerLayout.addOnLayoutChangeListener(this::handleLayoutChange);
+            if (synchronousDrawerOffsetCalculation()) {
+                mResolverDrawerLayout.setCollapsibleHeightReservedDelegate(
+                        this::syncHandleLayoutChange);
+            } else {
+                mResolverDrawerLayout.addOnLayoutChangeListener(this::handleLayoutChange);
+            }
 
             mResolverDrawerLayout.setOnCollapsedChangedListener(
                     isCollapsed -> {
@@ -696,6 +735,63 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         }
     }
 
+    private void maybeUpdateColorScheme() {
+        if (!isInteractiveSession()) {
+            Log.wtf(TAG, "This method should be called for an interactive session");
+            return;
+        }
+        final boolean shouldUseNightMode = switch (mRequest.getColorScheme()) {
+            case SystemDefault ->
+                    // apparently, updating color scheme for an activity invocation can affect
+                    // consequent activity invocations; restore the value from the application
+                    // configuration.
+                    getApplicationContext().getResources().getConfiguration().isNightModeActive();
+            case Dark -> true;
+            case Light -> false;
+        };
+        Configuration currentConfig = getResources().getConfiguration();
+        boolean isNightMode = currentConfig.isNightModeActive();
+        if (isNightMode == shouldUseNightMode) {
+            return;
+        }
+        Configuration newConfig = new Configuration(currentConfig);
+        int nightModeConfig = shouldUseNightMode
+                ? Configuration.UI_MODE_NIGHT_YES
+                : Configuration.UI_MODE_NIGHT_NO;
+        newConfig.uiMode = (~Configuration.UI_MODE_NIGHT_MASK & newConfig.uiMode) | nightModeConfig;
+        getResources().updateConfiguration(newConfig, getResources().getDisplayMetrics());
+    }
+
+    private void launchImageEditor(TargetInfo editorTargetInfo) {
+        if (editorTargetInfo == null) return;
+        mEventLog.logActionSelected(EventLog.SELECTION_TYPE_EDIT);
+        View imageViewForTransition = getFirstVisibleImgPreviewView();
+        if (imageViewForTransition != null && isFullyVisible(imageViewForTransition)) {
+            ActivityOptions options = ActivityOptions.makeSceneTransitionAnimation(
+                    this, imageViewForTransition, ChooserActionFactory.IMAGE_EDITOR_SHARED_ELEMENT);
+            safelyStartActivityAsUser(
+                    editorTargetInfo,
+                    mProfiles.getPersonalHandle(),
+                    options.toBundle());
+        } else {
+            safelyStartActivityAsUser(
+                    editorTargetInfo,
+                    mProfiles.getPersonalHandle()
+            );
+        }
+        finish();
+    }
+
+    @Override
+    public boolean onKeyUp(int keyCode, KeyEvent event) {
+        if (sharesheetEscExit() && keyCode == KeyEvent.KEYCODE_ESCAPE) {
+            finish();
+            return true;
+        }
+
+        return super.onKeyUp(keyCode, event);
+    }
+
     private void maybeDisableRecentsScreenshot(
             ProfileHelper profileHelper, ProfileAvailability profileAvailability) {
         for (Profile profile : profileHelper.getProfiles()) {
@@ -729,8 +825,8 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         setTabsViewEnabled(false);
     }
 
-    private void onHasSelections(boolean hasSelections) {
-        mChooserMultiProfilePagerAdapter.setTargetsEnabled(hasSelections);
+    private void onTargetEnabledChanged(boolean isEnabled) {
+        mChooserMultiProfilePagerAdapter.setTargetsEnabled(isEnabled);
     }
 
     private void configureInteractiveSessionWindow() {
@@ -765,7 +861,14 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
             ResolverDrawerLayoutExt.getVisibleDrawerRect(rdl, rect);
             rect.offset(left, top);
             if (oldTop != rect.top) {
-                mViewModel.getInteractiveSessionInteractor().sendTopDrawerTopOffsetChange(rect.top);
+                Rect r = rect;
+                Window w = getWindow();
+                WindowManager.LayoutParams wa = w == null ? null : w.getAttributes();
+                if (wa != null && (wa.x != 0 || wa.y != 0)) {
+                    r = new Rect(rect);
+                    r.offset(wa.x, wa.y);
+                }
+                mViewModel.getInteractiveSessionInteractor().sendChooserWindowSize(r);
             }
             info.setTouchableInsets(ViewTreeObserver.InternalInsetsInfo.TOUCHABLE_INSETS_REGION);
             info.touchableRegion.set(new Rect(rect));
@@ -788,12 +891,8 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
 
     private void updateShareResultSender() {
         IntentSender chosenComponentSender = mRequest.getChosenComponentSender();
-        if (chosenComponentSender != null) {
-            mShareResultSender = mShareResultSenderFactory.create(
-                    mViewModel.getActivityModel().getLaunchedFromUid(), chosenComponentSender);
-        } else {
-            mShareResultSender = null;
-        }
+        mShareResultSender = mShareResultSenderFactory.create(
+                mViewModel.getActivityModel().getLaunchedFromUid(), chosenComponentSender);
     }
 
     private boolean shouldUpdateAdapters(
@@ -809,8 +908,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         //  an artifact of the current implementation; revisit.
         return !oldTargetIntent.equals(newTargetIntent)
                 || !oldAltIntents.equals(newAltIntents)
-                || (shareouselUpdateExcludeComponentsExtra()
-                        && !oldExcluded.equals(newExcluded));
+                || !oldExcluded.equals(newExcluded);
     }
 
     private void recreatePagerAdapter() {
@@ -840,7 +938,6 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 mProfiles,
                 mProfileRecords.values(),
                 mProfileAvailability,
-                mRequest.getInitialIntents(),
                 mMaxTargetsPerRow);
         mChooserMultiProfilePagerAdapter.setCurrentPage(currentPage);
         for (int i = 0, count = mChooserMultiProfilePagerAdapter.getItemCount(); i < count; i++) {
@@ -872,7 +969,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         postRebuildList(
                 mChooserMultiProfilePagerAdapter.rebuildTabs(
                     mProfiles.getWorkProfilePresent() || mProfiles.getPrivateProfilePresent()));
-        if (fixShortcutsFlashingFixed() && oldPagerAdapter != null) {
+        if (oldPagerAdapter != null) {
             for (int i = 0, count = mChooserMultiProfilePagerAdapter.getCount(); i < count; i++) {
                 ChooserListAdapter listAdapter =
                         mChooserMultiProfilePagerAdapter.getPageAdapterForIndex(i)
@@ -1328,21 +1425,23 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         mChooserMultiProfilePagerAdapter.setupViewPager(mViewPager);
         ChooserNestedScrollView scrollableContainer =
                 requireViewById(R.id.chooser_scrollable_container);
-        if (keyboardNavigationFix()) {
-            scrollableContainer.setRequestChildFocusPredicate((child, focused) ->
-                    // TabHost view will request focus on the newly activated tab. The RecyclerView
-                    // from the tab gets focused and  notifies its parents (including
-                    // NestedScrollView) about it through #requestChildFocus method call.
-                    // NestedScrollView's view implementation of the method  will  scroll to the
-                    // focused view. As we don't want to change drawer's position upon tab change,
-                    // ignore focus requests from tab RecyclerViews.
-                    focused == null || focused.getId() != com.android.internal.R.id.resolver_list);
-        }
+        scrollableContainer.setRequestChildFocusPredicate((child, focused) ->
+                // TabHost view will request focus on the newly activated tab. The RecyclerView
+                // from the tab gets focused and  notifies its parents (including
+                // NestedScrollView) about it through #requestChildFocus method call.
+                // NestedScrollView's view implementation of the method  will  scroll to the
+                // focused view. As we don't want to change drawer's position upon tab change,
+                // ignore focus requests from tab RecyclerViews.
+                focused == null || focused.getId() != com.android.internal.R.id.resolver_list);
         boolean result = postRebuildList(rebuildCompleted);
         Trace.endSection();
         return result;
     }
 
+    protected void onExitButtonClicked(View v) {
+        finish();
+    }
+
     /**
      * Finishing procedures to be performed after the list has been rebuilt.
      * </p>Subclasses must call postRebuildListInternal at the end of postRebuildList.
@@ -1507,22 +1606,23 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
             ProfileHelper profileHelper,
             Collection<ProfileRecord> profileRecords,
             ProfileAvailability profileAvailability,
-            List<Intent> initialIntents,
             int maxTargetsPerRow) {
         Log.d(TAG, "createMultiProfilePagerAdapter");
 
         Profile launchedAs = profileHelper.getLaunchedAsProfile();
 
-        Intent[] initialIntentArray = initialIntents.toArray(new Intent[0]);
-        List<Intent> payloadIntents = request.getPayloadIntents();
+        Intent[] initialIntentArray = request.getInitialIntents().toArray(new Intent[0]);
 
         List<TabConfig<ChooserGridAdapter>> tabs = new ArrayList<>();
         for (ProfileRecord record : profileRecords) {
             Profile profile = record.profile;
+            boolean isCrossProfile = !profile.equals(launchedAs);
             ChooserGridAdapter adapter = createChooserGridAdapter(
                     context,
-                    payloadIntents,
-                    profile.equals(launchedAs) ? initialIntentArray : null,
+                    isCrossProfile
+                            ? request.getCrossProfilePayloadIntents()
+                            : request.getPayloadIntents(),
+                    isCrossProfile ? null : initialIntentArray,
                     profile.getPrimary().getHandle()
             );
             tabs.add(new TabConfig<>(
@@ -1616,10 +1716,9 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         mChooserMultiProfilePagerAdapter.getActiveListAdapter().handlePackagesChanged();
 
         if (mSystemWindowInsets != null) {
-            int topSpacing = isInteractiveSession() ? getInteractiveSessionTopSpacing() : 0;
             mResolverDrawerLayout.setPadding(
                     mSystemWindowInsets.left,
-                    mSystemWindowInsets.top + topSpacing,
+                    mSystemWindowInsets.top,
                     mSystemWindowInsets.right,
                     0);
         }
@@ -1751,13 +1850,10 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     }
 
     private void maybeSendShareResult(TargetInfo cti, UserHandle launchedAsUser) {
-        if (mShareResultSender != null) {
-            final ComponentName target = cti.getResolvedComponentName();
-            if (target != null) {
-                boolean crossProfile = !UserHandle.of(UserHandle.myUserId()).equals(launchedAsUser);
-                mShareResultSender.onComponentSelected(
-                        target, cti.isChooserTargetInfo(), crossProfile);
-            }
+        final ComponentName target = cti.getResolvedComponentName();
+        if (target != null) {
+            boolean crossProfile = !UserHandle.of(UserHandle.myUserId()).equals(launchedAsUser);
+            mShareResultSender.onComponentSelected(target, cti.isChooserTargetInfo(), crossProfile);
         }
     }
 
@@ -2290,10 +2386,10 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 this::getFirstVisibleImgPreviewView,
                 new ChooserActionFactory.ActionActivityStarter() {
                     @Override
-                    public void safelyStartActivityAsPersonalProfileUser(TargetInfo targetInfo) {
+                    public void safelyStartActivityAsLaunchingUser(TargetInfo targetInfo) {
                         safelyStartActivityAsUser(
                                 targetInfo,
-                                mProfiles.getPersonalHandle()
+                                mUserInteractor.getLaunchedAs()
                         );
                         Log.d(TAG, "safelyStartActivityAsPersonalProfileUser("
                                 + targetInfo + "): finishing!");
@@ -2301,13 +2397,13 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                     }
 
                     @Override
-                    public void safelyStartActivityAsPersonalProfileUserWithSharedElementTransition(
+                    public void safelyStartActivityAsLaunchingUserWithSharedElementTransition(
                             TargetInfo targetInfo, View sharedElement, String sharedElementName) {
                         ActivityOptions options = ActivityOptions.makeSceneTransitionAnimation(
                                 ChooserActivity.this, sharedElement, sharedElementName);
                         safelyStartActivityAsUser(
                                 targetInfo,
-                                mProfiles.getPersonalHandle(),
+                                mUserInteractor.getLaunchedAs(),
                                 options.toBundle());
                         // Can't finish right away because the shared element transition may not
                         // be ready to start.
@@ -2343,32 +2439,90 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
      */
     private void handleLayoutChange(View v, int left, int top, int right, int bottom, int oldLeft,
             int oldTop, int oldRight, int oldBottom) {
-        if (mChooserMultiProfilePagerAdapter == null || !isProfilePagerAdapterAttached()) {
+        if (!shouldUpdateDrawerOffset()) {
+            return;
+        }
+
+        final int availableWidth = right - left - v.getPaddingLeft() - v.getPaddingRight();
+        maybeUpdateTabPadding(availableWidth);
+        mCurrAvailableWidth = availableWidth;
+
+        if (mChooserMultiProfilePagerAdapter.getActiveProfile() != mInitialProfile) {
             return;
         }
+
+        RecyclerView recyclerView = mChooserMultiProfilePagerAdapter.getActiveAdapterView();
+        ChooserGridAdapter gridAdapter = mChooserMultiProfilePagerAdapter.getCurrentRootAdapter();
+        getMainThreadHandler().post(() -> {
+            if (mResolverDrawerLayout == null) {
+                return;
+            }
+            int offset = calculateDrawerOffset(top, bottom, recyclerView, gridAdapter);
+            mResolverDrawerLayout.setCollapsibleHeightReserved(offset);
+            mEnterTransitionAnimationDelegate.markOffsetCalculated();
+            mLastAppliedInsets = mSystemWindowInsets;
+        });
+    }
+
+    /*
+     * Need to dynamically adjust how many icons can fit per row before we add them,
+     * which also means setting the correct offset to initially show the content
+     * preview area + 2 rows of targets
+     */
+    private int syncHandleLayoutChange(
+            ResolverDrawerLayout drawer, int left, int top, int right, int bottom, int offset) {
+        if (!shouldUpdateDrawerOffset()) {
+            return offset;
+        }
+
+        final int availableWidth = right - left
+                - drawer.getPaddingLeft() - drawer.getPaddingRight();
+        maybeUpdateTabPadding(availableWidth);
+        mCurrAvailableWidth = availableWidth;
+
+        if (mChooserMultiProfilePagerAdapter.getActiveProfile() != mInitialProfile) {
+            return offset;
+        }
+
+        mLastAppliedInsets = mSystemWindowInsets;
+        getMainThreadHandler().post(mEnterTransitionAnimationDelegate::markOffsetCalculated);
+        RecyclerView recyclerView = mChooserMultiProfilePagerAdapter.getActiveAdapterView();
+        ChooserGridAdapter gridAdapter = mChooserMultiProfilePagerAdapter.getCurrentRootAdapter();
+        return calculateDrawerOffset(top, bottom, recyclerView, gridAdapter);
+    }
+
+    private boolean shouldUpdateDrawerOffset() {
+        if (mChooserMultiProfilePagerAdapter == null || !isProfilePagerAdapterAttached()) {
+            return false;
+        }
         RecyclerView recyclerView = mChooserMultiProfilePagerAdapter.getActiveAdapterView();
         ChooserGridAdapter gridAdapter = mChooserMultiProfilePagerAdapter.getCurrentRootAdapter();
         // Skip height calculation if recycler view was scrolled to prevent it inaccurately
         // calculating the height, as the logic below does not account for the scrolled offset.
         if (gridAdapter == null || recyclerView == null
                 || recyclerView.computeVerticalScrollOffset() != 0) {
-            return;
+            return false;
         }
-        if (delayDrawerOffsetCalculation() && !gridAdapter.getListAdapter().areAppTargetsReady()) {
+        return !delayDrawerOffsetCalculation()
+                || gridAdapter.getListAdapter().isInitialAppTargetLoad()
+                || gridAdapter.getListAdapter().areAppTargetsReady();
+    }
+
+    private void maybeUpdateTabPadding(int availableWidth) {
+        if (mChooserMultiProfilePagerAdapter == null) {
             return;
         }
-
-        final int availableWidth = right - left - v.getPaddingLeft() - v.getPaddingRight();
         final int maxChooserWidth = getResources().getDimensionPixelSize(R.dimen.chooser_width);
+        RecyclerView recyclerView = mChooserMultiProfilePagerAdapter.getActiveAdapterView();
+        ChooserGridAdapter gridAdapter = mChooserMultiProfilePagerAdapter.getCurrentRootAdapter();
         boolean isLayoutUpdated =
                 gridAdapter.calculateChooserTargetWidth(
                         maxChooserWidth >= 0
                                 ? Math.min(maxChooserWidth, availableWidth)
                                 : availableWidth)
-                || recyclerView.getAdapter() == null
-                || availableWidth != mCurrAvailableWidth;
+                        || recyclerView.getAdapter() == null
+                        || availableWidth != mCurrAvailableWidth;
 
-        mCurrAvailableWidth = availableWidth;
         if (isLayoutUpdated) {
             // It is very important we call setAdapter from here. Otherwise in some cases
             // the resolver list doesn't get populated, such as b/150922090, b/150918223
@@ -2379,20 +2533,6 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
 
             updateTabPadding();
         }
-
-        if (mChooserMultiProfilePagerAdapter.getActiveProfile() != mInitialProfile) {
-            return;
-        }
-
-        getMainThreadHandler().post(() -> {
-            if (mResolverDrawerLayout == null) {
-                return;
-            }
-            int offset = calculateDrawerOffset(top, bottom, recyclerView, gridAdapter);
-            mResolverDrawerLayout.setCollapsibleHeightReserved(offset);
-            mEnterTransitionAnimationDelegate.markOffsetCalculated();
-            mLastAppliedInsets = mSystemWindowInsets;
-        });
     }
 
     private int calculateDrawerOffset(
@@ -2495,9 +2635,6 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
             if (duration >= 0) {
                 Log.d(TAG, "app target loading time " + duration + " ms");
             }
-            if (!fixShortcutsFlashingFixed()) {
-                addCallerChooserTargets(chooserListAdapter);
-            }
             getEventLog().logSharesheetAppLoadComplete();
             maybeQueryAdditionalPostProcessingTargets(
                     listProfileUserHandle,
@@ -2527,11 +2664,9 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         ChooserListAdapter adapter =
                 mChooserMultiProfilePagerAdapter.getListAdapterForUserHandle(userHandle);
         if (adapter != null) {
-            if (fixShortcutsFlashingFixed()) {
-                adapter.setDirectTargetsEnabled(true);
-                adapter.resetDirectTargets();
-                addCallerChooserTargets(adapter);
-            }
+            adapter.setDirectTargetsEnabled(true);
+            adapter.resetDirectTargets();
+            addCallerChooserTargets(adapter);
             for (ShortcutLoader.ShortcutResultInfo resultInfo : result.getShortcutsByApp()) {
                 adapter.addServiceResults(
                         resultInfo.getAppTarget(),
@@ -2723,12 +2858,8 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         }
     }
 
-    private int getInteractiveSessionTopSpacing() {
-        return getResources().getDimensionPixelSize(R.dimen.chooser_preview_image_height_tall);
-    }
-
     private boolean isInteractiveSession() {
-        return interactiveSession() && mRequest.getInteractiveSessionCallback() != null
+        return interactiveChooser() && mRequest.getInteractiveSessionCallback() != null
                 && !isTaskRoot();
     }
 
@@ -2737,10 +2868,9 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         mChooserMultiProfilePagerAdapter
                 .setEmptyStateBottomOffset(mSystemWindowInsets.bottom);
 
-        final int topSpacing = isInteractiveSession() ? getInteractiveSessionTopSpacing() : 0;
         mResolverDrawerLayout.setPadding(
                 mSystemWindowInsets.left,
-                mSystemWindowInsets.top + topSpacing,
+                mSystemWindowInsets.top,
                 mSystemWindowInsets.right,
                 0);
 
diff --git a/java/src/com/android/intentresolver/ChooserGridLayoutManager.java b/java/src/com/android/intentresolver/ChooserGridLayoutManager.java
index 5bbb6c24..133d09b4 100644
--- a/java/src/com/android/intentresolver/ChooserGridLayoutManager.java
+++ b/java/src/com/android/intentresolver/ChooserGridLayoutManager.java
@@ -16,8 +16,6 @@
 
 package com.android.intentresolver;
 
-import static com.android.intentresolver.Flags.announceShortcutsAndSuggestedApps;
-
 import android.content.Context;
 import android.util.AttributeSet;
 import android.view.View;
@@ -56,9 +54,7 @@ public class ChooserGridLayoutManager extends GridLayoutManager {
     public ChooserGridLayoutManager(Context context, AttributeSet attrs, int defStyleAttr,
             int defStyleRes) {
         super(context, attrs, defStyleAttr, defStyleRes);
-        if (announceShortcutsAndSuggestedApps()) {
-            readGroupTitles(context);
-        }
+        readGroupTitles(context);
     }
 
     /**
@@ -69,9 +65,7 @@ public class ChooserGridLayoutManager extends GridLayoutManager {
      */
     public ChooserGridLayoutManager(Context context, int spanCount) {
         super(context, spanCount);
-        if (announceShortcutsAndSuggestedApps()) {
-            readGroupTitles(context);
-        }
+        readGroupTitles(context);
     }
 
     /**
@@ -84,9 +78,7 @@ public class ChooserGridLayoutManager extends GridLayoutManager {
     public ChooserGridLayoutManager(Context context, int spanCount, int orientation,
             boolean reverseLayout) {
         super(context, spanCount, orientation, reverseLayout);
-        if (announceShortcutsAndSuggestedApps()) {
-            readGroupTitles(context);
-        }
+        readGroupTitles(context);
     }
 
     private void readGroupTitles(Context context) {
@@ -130,7 +122,7 @@ public class ChooserGridLayoutManager extends GridLayoutManager {
             View host,
             AccessibilityNodeInfoCompat info) {
         super.onInitializeAccessibilityNodeInfoForItem(recycler, state, host, info);
-        if (announceShortcutsAndSuggestedApps() && host instanceof ViewGroup) {
+        if (host instanceof ViewGroup) {
             if (host.getId() == R.id.shortcuts_container) {
                 info.setClassName(GridView.class.getName());
                 info.setContainerTitle(mShortcutGroupTitle);
@@ -158,15 +150,13 @@ public class ChooserGridLayoutManager extends GridLayoutManager {
     public void onInitializeAccessibilityNodeInfo(@NonNull RecyclerView.Recycler recycler,
             @NonNull RecyclerView.State state, @NonNull AccessibilityNodeInfoCompat info) {
         super.onInitializeAccessibilityNodeInfo(recycler, state, info);
-        if (announceShortcutsAndSuggestedApps()) {
-            info.setContainerTitle(mAllAppListGroupTitle);
-        }
+        info.setContainerTitle(mAllAppListGroupTitle);
     }
 
     @Override
     public boolean isLayoutHierarchical(
             @NonNull RecyclerView.Recycler recycler, @NonNull RecyclerView.State state) {
-        return announceShortcutsAndSuggestedApps() || super.isLayoutHierarchical(recycler, state);
+        return true;
     }
 
     private CollectionInfoCompat createShortcutsA11yCollectionInfo(ViewGroup container) {
diff --git a/java/src/com/android/intentresolver/ChooserHelper.kt b/java/src/com/android/intentresolver/ChooserHelper.kt
index 2d015128..0f7751c6 100644
--- a/java/src/com/android/intentresolver/ChooserHelper.kt
+++ b/java/src/com/android/intentresolver/ChooserHelper.kt
@@ -19,6 +19,7 @@ package com.android.intentresolver
 import android.app.Activity
 import android.os.UserHandle
 import android.provider.Settings
+import android.service.chooser.Flags.interactiveChooser
 import android.util.Log
 import androidx.activity.ComponentActivity
 import androidx.activity.viewModels
@@ -27,8 +28,6 @@ import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
-import com.android.intentresolver.Flags.interactiveSession
-import com.android.intentresolver.Flags.unselectFinalItem
 import com.android.intentresolver.annotation.JavaInterop
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_PAYLOAD_SELECTION
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.ActivityResultRepository
@@ -104,7 +103,7 @@ constructor(
     var onChooserRequestChanged: Consumer<ChooserRequest> = Consumer {}
     /** Invoked when there are a new change to payload selection */
     var onPendingSelection: Runnable = Runnable {}
-    var onHasSelections: Consumer<Boolean> = Consumer {}
+    var onTargetEnabled: Consumer<Boolean> = Consumer {}
 
     init {
         activity.lifecycle.addObserver(this)
@@ -163,17 +162,27 @@ constructor(
             activity.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                 val hasSelectionFlow =
                     if (
-                        unselectFinalItem() &&
-                            viewModel.previewDataProvider.previewType ==
-                                CONTENT_PREVIEW_PAYLOAD_SELECTION
+                        viewModel.previewDataProvider.previewType ==
+                            CONTENT_PREVIEW_PAYLOAD_SELECTION
                     ) {
-                        viewModel.shareouselViewModel.hasSelectedItems.stateIn(scope = this).also {
-                            flow ->
-                            launch { flow.collect { onHasSelections.accept(it) } }
-                        }
+                        viewModel.shareouselViewModel.hasSelectedItems.stateIn(scope = this)
                     } else {
                         MutableStateFlow(true).asStateFlow()
                     }
+                launch {
+                    if (interactiveChooser()) {
+                            hasSelectionFlow
+                                .combine(viewModel.interactiveSessionInteractor.isTargetEnabled) {
+                                    hasSelection,
+                                    isEnabled ->
+                                    hasSelection && isEnabled
+                                }
+                                .distinctUntilChanged()
+                        } else {
+                            hasSelectionFlow
+                        }
+                        .collect { onTargetEnabled.accept(it) }
+                }
                 val requestControlFlow =
                     hasSelectionFlow
                         .combine(hasPendingIntentFlow) { hasSelections, hasPendingIntent ->
@@ -190,7 +199,7 @@ constructor(
             }
         }
 
-        if (interactiveSession()) {
+        if (interactiveChooser()) {
             activity.lifecycleScope.launch {
                 viewModel.interactiveSessionInteractor.isSessionActive
                     .filter { !it }
diff --git a/java/src/com/android/intentresolver/ChooserListAdapter.java b/java/src/com/android/intentresolver/ChooserListAdapter.java
index 7e5de74b..2ccf5791 100644
--- a/java/src/com/android/intentresolver/ChooserListAdapter.java
+++ b/java/src/com/android/intentresolver/ChooserListAdapter.java
@@ -19,6 +19,7 @@ package com.android.intentresolver;
 import static com.android.intentresolver.ChooserActivity.TARGET_TYPE_SHORTCUTS_FROM_PREDICTION_SERVICE;
 import static com.android.intentresolver.ChooserActivity.TARGET_TYPE_SHORTCUTS_FROM_SHORTCUT_MANAGER;
 import static com.android.intentresolver.Flags.targetHoverAndKeyboardFocusStates;
+import static com.android.intentresolver.Flags.useGoogleSansFlex;
 
 import android.app.ActivityManager;
 import android.app.prediction.AppTarget;
@@ -30,6 +31,7 @@ import android.content.pm.LabeledIntent;
 import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
 import android.content.pm.ShortcutInfo;
+import android.graphics.Typeface;
 import android.graphics.drawable.Drawable;
 import android.os.AsyncTask;
 import android.os.Trace;
@@ -56,6 +58,7 @@ import com.android.intentresolver.chooser.SelectableTargetInfo;
 import com.android.intentresolver.chooser.TargetInfo;
 import com.android.intentresolver.icons.TargetDataLoader;
 import com.android.intentresolver.logging.EventLog;
+import com.android.intentresolver.ui.FontStyles;
 import com.android.intentresolver.widget.BadgeTextView;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.config.sysui.SystemUiDeviceConfigFlags;
@@ -138,6 +141,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
      * Yeah.
      */
     private boolean mAppTargetsReady = false;
+    private boolean mIsInitialAppTargetLoad = true;
 
     // For pinned direct share labels, if the text spans multiple lines, the TextView will consume
     // the full width, even if the characters actually take up less than that. Measure the actual
@@ -333,6 +337,15 @@ public class ChooserListAdapter extends ResolverListAdapter {
         return mAppTargetsReady;
     }
 
+    public final boolean isInitialAppTargetLoad() {
+        return mIsInitialAppTargetLoad;
+    }
+
+    private void markAppTargetsLoaded() {
+        mAppTargetsReady = true;
+        mIsInitialAppTargetLoad = false;
+    }
+
     /**
      * Set the enabled state for all targets.
      */
@@ -394,7 +407,20 @@ public class ChooserListAdapter extends ResolverListAdapter {
         int layout = targetHoverAndKeyboardFocusStates()
                 ? R.layout.chooser_grid_item_hover
                 : R.layout.chooser_grid_item;
-        return mInflater.inflate(layout, parent, false);
+        View view = mInflater.inflate(layout, parent, false);
+        if (useGoogleSansFlex()) {
+            TextView textOne = view.findViewById(com.android.internal.R.id.text1);
+            TextView textTwo = view.findViewById(com.android.internal.R.id.text2);
+            if (textOne != null) {
+                textOne.setTypeface(
+                        Typeface.create(FontStyles.GSF_TITLE_SMALL_BASELINE, Typeface.NORMAL));
+            }
+            if (textTwo != null) {
+                textTwo.setTypeface(
+                        Typeface.create(FontStyles.GSF_TITLE_SMALL_BASELINE, Typeface.NORMAL));
+            }
+        }
+        return view;
     }
 
     @Override
@@ -545,7 +571,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
         if (getDisplayResolveInfoCount() == 0) {
             Log.d(TAG, "getDisplayResolveInfoCount() == 0");
             if (rebuildComplete) {
-                mAppTargetsReady = true;
+                markAppTargetsLoaded();
                 onCompleted.run();
             }
             notifyDataSetChanged();
@@ -614,7 +640,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
             protected void onPostExecute(List<DisplayResolveInfo> newList) {
                 mSortedList.clear();
                 mSortedList.addAll(newList);
-                mAppTargetsReady = true;
+                markAppTargetsLoaded();
                 notifyDataSetChanged();
                 onCompleted.run();
             }
diff --git a/java/src/com/android/intentresolver/IntentForwarderActivity.java b/java/src/com/android/intentresolver/IntentForwarderActivity.java
index 30e518fa..a16a5f17 100644
--- a/java/src/com/android/intentresolver/IntentForwarderActivity.java
+++ b/java/src/com/android/intentresolver/IntentForwarderActivity.java
@@ -28,7 +28,6 @@ import android.app.ActivityThread;
 import android.app.AppGlobals;
 import android.app.admin.DevicePolicyManager;
 import android.content.ComponentName;
-import android.content.ContentResolver;
 import android.content.Intent;
 import android.content.pm.ActivityInfo;
 import android.content.pm.IPackageManager;
@@ -132,8 +131,9 @@ public class IntentForwarderActivity extends Activity  {
         }
 
         final int callingUserId = getUserId();
+        String resolvedType = intentReceived.resolveTypeIfNeeded(getContentResolver());
         final Intent newIntent = canForward(intentReceived, getUserId(), targetUserId,
-                mInjector.getIPackageManager(), getContentResolver());
+                mInjector.getIPackageManager(), resolvedType);
 
         if (newIntent == null) {
             Slog.wtf(TAG, "the intent: " + intentReceived + " cannot be forwarded from user "
@@ -144,7 +144,9 @@ public class IntentForwarderActivity extends Activity  {
 
         newIntent.prepareToLeaveUser(callingUserId);
         final CompletableFuture<ResolveInfo> targetResolveInfoFuture =
-                mInjector.resolveActivityAsUser(newIntent, MATCH_DEFAULT_ONLY, targetUserId);
+                mInjector.resolveActivityAsUser(newIntent, resolvedType,
+                        MATCH_DEFAULT_ONLY,
+                        targetUserId);
         targetResolveInfoFuture
                 .thenApplyAsync(targetResolveInfo -> {
                     if (isResolverActivityResolveInfo(targetResolveInfo)) {
@@ -222,6 +224,9 @@ public class IntentForwarderActivity extends Activity  {
         // when cross-profile intents are disabled.
         int selectedProfile = findSelectedProfile(className);
         sanitizeIntent(intentReceived);
+        if (intentReceived.getSelector() != null) {
+            sanitizeIntent(intentReceived.getSelector());
+        }
         intentReceived.putExtra(EXTRA_SELECTED_PROFILE, selectedProfile);
         Intent innerIntent = intentReceived.getParcelableExtra(Intent.EXTRA_INTENT);
         if (innerIntent == null) {
@@ -312,14 +317,14 @@ public class IntentForwarderActivity extends Activity  {
      * forwarding if it can be forwarded, {@code null} otherwise.
      */
     public static Intent canForward(Intent incomingIntent, int sourceUserId, int targetUserId,
-            IPackageManager packageManager, ContentResolver contentResolver) {
+            IPackageManager packageManager, String resolvedType) {
         Intent forwardIntent = new Intent(incomingIntent);
         forwardIntent.addFlags(
                 Intent.FLAG_ACTIVITY_FORWARD_RESULT | Intent.FLAG_ACTIVITY_PREVIOUS_IS_TOP);
         sanitizeIntent(forwardIntent);
 
         if (!canForwardInner(forwardIntent, sourceUserId, targetUserId, packageManager,
-                contentResolver)) {
+                resolvedType)) {
             return null;
         }
 
@@ -327,7 +332,7 @@ public class IntentForwarderActivity extends Activity  {
             sanitizeIntent(forwardIntent.getSelector());
 
             if (!canForwardInner(forwardIntent.getSelector(), sourceUserId, targetUserId,
-                    packageManager, contentResolver)) {
+                    packageManager, resolvedType)) {
                 return null;
             }
         }
@@ -335,12 +340,11 @@ public class IntentForwarderActivity extends Activity  {
     }
 
     private static boolean canForwardInner(Intent intent, int sourceUserId, int targetUserId,
-            IPackageManager packageManager, ContentResolver contentResolver) {
+            IPackageManager packageManager, String resolvedType) {
         if (Intent.ACTION_CHOOSER.equals(intent.getAction())) {
             return false;
         }
 
-        String resolvedType = intent.resolveTypeIfNeeded(contentResolver);
         try {
             if (packageManager.canForwardTo(
                     intent, resolvedType, sourceUserId, targetUserId)) {
@@ -423,8 +427,17 @@ public class IntentForwarderActivity extends Activity  {
 
         @Override
         @Nullable
-        public CompletableFuture<ResolveInfo> resolveActivityAsUser(
-                Intent intent, int flags, int userId) {
+        public CompletableFuture<ResolveInfo> resolveActivityAsUser(Intent intent,
+                String resolvedType, int flags, int userId) {
+            return CompletableFuture.supplyAsync(
+                    () -> getPackageManager().resolveActivityAsUser(intent,
+                            resolvedType, flags, userId));
+        }
+
+        @Override
+        @Nullable
+        public CompletableFuture<ResolveInfo> resolveActivityAsUser(Intent intent, int flags,
+                int userId) {
             return CompletableFuture.supplyAsync(
                     () -> getPackageManager().resolveActivityAsUser(intent, flags, userId));
         }
@@ -442,6 +455,9 @@ public class IntentForwarderActivity extends Activity  {
 
         PackageManager getPackageManager();
 
+        CompletableFuture<ResolveInfo> resolveActivityAsUser(Intent intent,
+                String resolvedType, int flags, int userId);
+
         CompletableFuture<ResolveInfo> resolveActivityAsUser(Intent intent, int flags, int userId);
 
         void showToast(String message, int duration);
diff --git a/java/src/com/android/intentresolver/ProfileAvailability.kt b/java/src/com/android/intentresolver/ProfileAvailability.kt
index 43982727..fed53953 100644
--- a/java/src/com/android/intentresolver/ProfileAvailability.kt
+++ b/java/src/com/android/intentresolver/ProfileAvailability.kt
@@ -17,6 +17,7 @@
 package com.android.intentresolver
 
 import androidx.annotation.MainThread
+import com.android.app.tracing.coroutines.runBlockingTraced as runBlocking
 import com.android.intentresolver.annotation.JavaInterop
 import com.android.intentresolver.domain.interactor.UserInteractor
 import com.android.intentresolver.shared.model.Profile
@@ -27,7 +28,6 @@ import kotlinx.coroutines.flow.filter
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.launch
-import kotlinx.coroutines.runBlocking
 
 /** Provides availability status for profiles */
 @JavaInterop
@@ -48,7 +48,7 @@ class ProfileAvailability(
     /** Query current profile availability. An unavailable profile is one which is not active. */
     @MainThread
     fun isAvailable(profile: Profile?): Boolean {
-        return runBlocking(background) {
+        return runBlocking(context = background) {
             userInteractor.availability.map { it[profile] == true }.first()
         }
     }
@@ -58,7 +58,7 @@ class ProfileAvailability(
      * hidden when locked.
      */
     fun visibleProfileCount() =
-        runBlocking(background) {
+        runBlocking(context = background) {
             val availability = userInteractor.availability.first()
             val profiles = userInteractor.profiles.first()
             profiles
diff --git a/java/src/com/android/intentresolver/ProfileHelper.kt b/java/src/com/android/intentresolver/ProfileHelper.kt
index b87f7e3f..fcad5f19 100644
--- a/java/src/com/android/intentresolver/ProfileHelper.kt
+++ b/java/src/com/android/intentresolver/ProfileHelper.kt
@@ -18,6 +18,7 @@ package com.android.intentresolver
 
 import android.os.UserHandle
 import androidx.annotation.MainThread
+import com.android.app.tracing.coroutines.runBlockingTraced as runBlocking
 import com.android.intentresolver.annotation.JavaInterop
 import com.android.intentresolver.domain.interactor.UserInteractor
 import com.android.intentresolver.shared.model.Profile
@@ -25,7 +26,6 @@ import com.android.intentresolver.shared.model.User
 import javax.inject.Inject
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.flow.first
-import kotlinx.coroutines.runBlocking
 
 @JavaInterop
 @MainThread
@@ -35,9 +35,9 @@ constructor(interactor: UserInteractor, private val background: CoroutineDispatc
     private val launchedByHandle: UserHandle = interactor.launchedAs
 
     val launchedAsProfile by lazy {
-        runBlocking(background) { interactor.launchedAsProfile.first() }
+        runBlocking(context = background) { interactor.launchedAsProfile.first() }
     }
-    val profiles by lazy { runBlocking(background) { interactor.profiles.first() } }
+    val profiles by lazy { runBlocking(context = background) { interactor.profiles.first() } }
 
     // Map UserHandle back to a user within launchedByProfile
     private val launchedByUser: User =
diff --git a/java/src/com/android/intentresolver/ResolverListAdapter.java b/java/src/com/android/intentresolver/ResolverListAdapter.java
index f29553eb..9d686d5d 100644
--- a/java/src/com/android/intentresolver/ResolverListAdapter.java
+++ b/java/src/com/android/intentresolver/ResolverListAdapter.java
@@ -16,7 +16,6 @@
 
 package com.android.intentresolver;
 
-import static com.android.intentresolver.Flags.unselectFinalItem;
 import static com.android.intentresolver.util.graphics.SuspendedMatrixColorFilter.getSuspendedColorMatrix;
 
 import android.content.Context;
@@ -992,7 +991,7 @@ public class ResolverListAdapter extends BaseAdapter {
                 icon.setColorFilter(getSuspendedColorMatrix());
             } else {
                 icon.setColorFilter(null);
-                if (unselectFinalItem() && displayIcon != null) {
+                if (displayIcon != null) {
                     // For some reason, ImageView.setColorFilter() not always propagate the call
                     // to the drawable and the icon remains grayscale when rebound; reset the filter
                     // explicitly.
diff --git a/java/src/com/android/intentresolver/actions/ImageEditorActionFactory.kt b/java/src/com/android/intentresolver/actions/ImageEditorActionFactory.kt
new file mode 100644
index 00000000..d9365b0e
--- /dev/null
+++ b/java/src/com/android/intentresolver/actions/ImageEditorActionFactory.kt
@@ -0,0 +1,142 @@
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
+ * limitations under the License.
+ */
+
+package com.android.intentresolver.actions
+
+import android.content.ComponentName
+import android.content.ContentResolver
+import android.content.Context
+import android.content.Intent
+import android.content.pm.PackageManager
+import android.net.Uri
+import com.android.intentresolver.ChooserActionFactory
+import com.android.intentresolver.R
+import com.android.intentresolver.chooser.DisplayResolveInfo
+import com.android.intentresolver.chooser.TargetInfo
+import com.android.intentresolver.inject.Background
+import com.android.intentresolver.platform.FallbackImageEditor
+import com.android.intentresolver.platform.PreferredImageEditor
+import dagger.hilt.android.qualifiers.ApplicationContext
+import java.util.Optional
+import java.util.function.Consumer
+import javax.inject.Inject
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.async
+import kotlinx.coroutines.withContext
+
+/** Creates target info to launch the image editor when appropriate. */
+class ImageEditorActionFactory
+@Inject
+constructor(
+    @ApplicationContext private val context: Context,
+    @Background private val backgroundDispatcher: CoroutineDispatcher,
+    @PreferredImageEditor private val preferredImageEditor: Optional<ComponentName>,
+    @FallbackImageEditor private val fallbackImageEditor: Optional<ComponentName>,
+    private val packageManager: PackageManager,
+    private val contentResolver: ContentResolver,
+) {
+    /**
+     * Get a TargetInfo for the image editor for the given targetIntent. If none is available, call
+     * back with null.
+     */
+    fun getImageEditorTargetInfoAsync(
+        clientScope: CoroutineScope,
+        targetIntent: Intent,
+        editorAvailable: Consumer<TargetInfo?>,
+    ) {
+        clientScope.async { editorAvailable.accept(getImageEditorTargetInfo(targetIntent)) }
+    }
+
+    /**
+     * Get a TargetInfo for the image editor for the given targetIntent. If none is available,
+     * return null.
+     */
+    suspend fun getImageEditorTargetInfo(targetIntent: Intent): TargetInfo? {
+        if (Intent.ACTION_SEND != targetIntent.action) {
+            return null
+        }
+
+        return withContext(backgroundDispatcher) {
+            val resolveIntent = Intent(targetIntent)
+
+            // Retain only URI permission grant flags if present. Other flags may prevent the scene
+            // transition animation from running (i.e FLAG_ACTIVITY_NO_ANIMATION,
+            // FLAG_ACTIVITY_NEW_TASK, FLAG_ACTIVITY_NEW_DOCUMENT) but also not needed.
+            resolveIntent.setFlags(
+                targetIntent.flags and ChooserActionFactory.URI_PERMISSION_INTENT_FLAGS
+            )
+
+            resolveIntent.setAction(Intent.ACTION_EDIT)
+            resolveIntent.putExtra(
+                ChooserActionFactory.EDIT_SOURCE,
+                ChooserActionFactory.EDIT_SOURCE_SHARESHEET,
+            )
+
+            if (resolveIntent.data == null) {
+                val uri = resolveIntent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
+                if (uri != null) {
+                    val mimeType = contentResolver.getType(uri)
+                    resolveIntent.setDataAndType(uri, mimeType)
+                }
+            }
+
+            // Return the target for the preferred editor if found, otherwise the fallback, else
+            // null
+            displayResolveInfoForComponent(preferredImageEditor, targetIntent, resolveIntent)
+                ?: displayResolveInfoForComponent(fallbackImageEditor, targetIntent, resolveIntent)
+        }
+    }
+
+    // If the component is provided, set the resolved intent's component to that and return the
+    // relevant DisplayResolveInfo if available, otherwise null.
+    private fun displayResolveInfoForComponent(
+        editorComponent: Optional<ComponentName>,
+        targetIntent: Intent,
+        resolveIntent: Intent,
+    ): DisplayResolveInfo? =
+        editorComponent.orElse(null)?.let { component ->
+            resolveIntent.setComponent(component)
+            displayResolveInfoForIntent(targetIntent, resolveIntent)
+        }
+
+    private fun displayResolveInfoForIntent(
+        targetIntent: Intent,
+        resolveIntent: Intent,
+    ): DisplayResolveInfo? {
+        val resolveInfo =
+            packageManager.resolveActivity(resolveIntent, PackageManager.GET_META_DATA)
+        if (resolveInfo?.activityInfo == null) {
+            return null
+        }
+
+        val displayResolveInfo =
+            DisplayResolveInfo.newDisplayResolveInfo(
+                targetIntent,
+                resolveInfo,
+                context.getString(R.string.screenshot_edit),
+                "",
+                resolveIntent,
+            )
+        displayResolveInfo.displayIconHolder.displayIcon =
+            context.getDrawable(com.android.internal.R.drawable.ic_screenshot_edit)
+        return displayResolveInfo
+    }
+
+    companion object {
+        const val TAG = "EditActionController"
+    }
+}
diff --git a/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
index 2af5881f..7251b4cc 100644
--- a/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
@@ -215,6 +215,11 @@ public final class ChooserContentPreviewUi {
         return mContentPreviewUi.getType();
     }
 
+    /** Provide callback for image editor invocation. */
+    public void setImageEditorCallback(Runnable callback) {
+        mContentPreviewUi.setImageEditorCallback(callback);
+    }
+
     /**
      * Display a content preview of the specified {@code previewType} to preview the content of the
      * specified {@code intent}.
diff --git a/java/src/com/android/intentresolver/contentpreview/ContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/ContentPreviewUi.java
index 8eaf3568..8b6ee68c 100644
--- a/java/src/com/android/intentresolver/contentpreview/ContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/ContentPreviewUi.java
@@ -16,16 +16,22 @@
 
 package com.android.intentresolver.contentpreview;
 
+import static com.android.intentresolver.Flags.useGoogleSansFlex;
+import static com.android.intentresolver.ui.FontStyles.GSF_LABEL_LARGE_BASELINE;
+import static com.android.intentresolver.ui.FontStyles.GSF_TITLE_LARGE_BASELINE;
+
 import android.animation.ObjectAnimator;
 import android.animation.ValueAnimator;
 import android.content.res.Resources;
 import android.graphics.Bitmap;
+import android.graphics.Typeface;
 import android.text.TextUtils;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.ViewStub;
 import android.view.animation.DecelerateInterpolator;
+import android.widget.Button;
 import android.widget.ImageView;
 import android.widget.TextView;
 
@@ -50,6 +56,12 @@ public abstract class ContentPreviewUi {
             ViewGroup parent,
             View headlineViewParent);
 
+
+    /** Provide callback for image editor invocation. */
+    public void setImageEditorCallback(Runnable imageEditorCallback) {
+        // most implementations don't need.
+    }
+
     protected static void updateViewWithImage(ImageView imageView, Bitmap image) {
         if (image == null) {
             imageView.setVisibility(View.GONE);
@@ -70,6 +82,20 @@ public abstract class ContentPreviewUi {
         if (stub != null) {
             stub.inflate();
         }
+        if (useGoogleSansFlex()) {
+            TextView headline = layout.findViewById(R.id.headline);
+            TextView metadata = layout.findViewById(R.id.metadata);
+            Button action = layout.findViewById(R.id.reselection_action);
+            if (headline != null) {
+                headline.setTypeface(Typeface.create(GSF_TITLE_LARGE_BASELINE, Typeface.NORMAL));
+            }
+            if (metadata != null) {
+                metadata.setTypeface(Typeface.create(GSF_LABEL_LARGE_BASELINE, Typeface.NORMAL));
+            }
+            if (action != null) {
+                action.setTypeface(Typeface.create(GSF_LABEL_LARGE_BASELINE, Typeface.NORMAL));
+            }
+        }
     }
 
     protected static void displayHeadline(View layout, String headline) {
diff --git a/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java
index da701ec4..d75251da 100644
--- a/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java
@@ -16,10 +16,12 @@
 
 package com.android.intentresolver.contentpreview;
 
+import static com.android.intentresolver.Flags.useGoogleSansFlex;
 import static com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_FILE;
 import static com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_IMAGE;
 
 import android.content.res.Resources;
+import android.graphics.Typeface;
 import android.net.Uri;
 import android.text.util.Linkify;
 import android.util.PluralsMessageFormatter;
@@ -34,6 +36,7 @@ import android.widget.TextView;
 import androidx.annotation.Nullable;
 
 import com.android.intentresolver.R;
+import com.android.intentresolver.ui.FontStyles;
 import com.android.intentresolver.widget.ActionRow;
 import com.android.intentresolver.widget.ScrollableImagePreviewView;
 
@@ -217,6 +220,10 @@ class FilesPlusTextContentPreviewUi extends ContentPreviewUi {
             View headlineView,
             ChooserContentPreviewUi.ActionFactory actionFactory) {
         final TextView textView = contentPreview.requireViewById(R.id.content_preview_text);
+        if (useGoogleSansFlex()) {
+            textView.setTypeface(
+                    Typeface.create(FontStyles.GSF_LABEL_MEDIUM_BASELINE, Typeface.NORMAL));
+        }
         CheckBox includeText = headlineView.requireViewById(R.id.include_text_action);
         boolean isLink = HttpUriMatcher.isHttpUri(mText.toString());
         textView.setAutoLinkMask(isLink ? Linkify.WEB_URLS : 0);
diff --git a/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt b/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt
index d7b9077d..fe3ddc5e 100644
--- a/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt
+++ b/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt
@@ -28,7 +28,7 @@ import android.text.TextUtils
 import android.util.Log
 import androidx.annotation.OpenForTesting
 import androidx.annotation.VisibleForTesting
-import com.android.intentresolver.Flags.individualMetadataTitleRead
+import com.android.app.tracing.coroutines.runBlockingTraced as runBlocking
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_FILE
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_IMAGE
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_PAYLOAD_SELECTION
@@ -37,6 +37,7 @@ import com.android.intentresolver.measurements.runTracing
 import com.android.intentresolver.util.ownedByCurrentUser
 import java.util.concurrent.atomic.AtomicInteger
 import java.util.function.Consumer
+import kotlin.getValue
 import kotlinx.coroutines.CancellationException
 import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.CoroutineScope
@@ -48,21 +49,8 @@ import kotlinx.coroutines.flow.SharedFlow
 import kotlinx.coroutines.flow.take
 import kotlinx.coroutines.isActive
 import kotlinx.coroutines.launch
-import kotlinx.coroutines.runBlocking
 import kotlinx.coroutines.withTimeoutOrNull
 
-/**
- * A set of metadata columns we read for a content URI (see
- * [PreviewDataProvider.UriRecord.readQueryResult] method).
- */
-private val METADATA_COLUMNS =
-    arrayOf(
-        DocumentsContract.Document.COLUMN_FLAGS,
-        MediaMetadata.METADATA_KEY_DISPLAY_ICON_URI,
-        OpenableColumns.DISPLAY_NAME,
-        Downloads.Impl.COLUMN_TITLE,
-    )
-
 /** Preview-related metadata columns. */
 @VisibleForTesting
 val ICON_METADATA_COLUMNS =
@@ -137,7 +125,7 @@ constructor(
                 CONTENT_PREVIEW_PAYLOAD_SELECTION
             } else {
                 try {
-                    runBlocking(scope.coroutineContext) {
+                    runBlocking(context = scope.coroutineContext) {
                         withTimeoutOrNull(TIMEOUT_MS) { scope.async { loadPreviewType() }.await() }
                             ?: CONTENT_PREVIEW_FILE
                     }
@@ -178,7 +166,7 @@ constructor(
             records.firstOrNull()?.let { record ->
                 val builder = FileInfo.Builder(record.uri)
                 try {
-                    runBlocking(scope.coroutineContext) {
+                    runBlocking(context = scope.coroutineContext) {
                         withTimeoutOrNull(TIMEOUT_MS) {
                             scope.async { builder.readFromRecord(record) }.await()
                         }
@@ -291,21 +279,14 @@ constructor(
         val supportsThumbnail: Boolean
             get() = query.supportsThumbnail
 
-        val title: String
-            get() = if (individualMetadataTitleRead()) titleFromQuery else query.title
+        val title: String by lazy {
+            readDisplayNameFromQuery().takeIf { !TextUtils.isEmpty(it) } ?: readTitleFromQuery()
+        }
 
         val iconUri: Uri?
             get() = query.iconUri
 
-        private val query by lazy {
-            readQueryResult(
-                if (individualMetadataTitleRead()) ICON_METADATA_COLUMNS else METADATA_COLUMNS
-            )
-        }
-
-        private val titleFromQuery by lazy {
-            readDisplayNameFromQuery().takeIf { !TextUtils.isEmpty(it) } ?: readTitleFromQuery()
-        }
+        private val query by lazy { readQueryResult(ICON_METADATA_COLUMNS) }
 
         private fun readQueryResult(columns: Array<String>): QueryResult =
             contentResolver.querySafe(uri, columns)?.use { cursor ->
@@ -313,15 +294,11 @@ constructor(
 
                 var flagColIdx = -1
                 var displayIconUriColIdx = -1
-                var nameColIndex = -1
-                var titleColIndex = -1
                 // TODO: double-check why Cursor#getColumnInded didn't work
                 cursor.columnNames.forEachIndexed { i, columnName ->
                     when (columnName) {
                         DocumentsContract.Document.COLUMN_FLAGS -> flagColIdx = i
                         MediaMetadata.METADATA_KEY_DISPLAY_ICON_URI -> displayIconUriColIdx = i
-                        OpenableColumns.DISPLAY_NAME -> nameColIndex = i
-                        Downloads.Impl.COLUMN_TITLE -> titleColIndex = i
                     }
                 }
 
@@ -329,14 +306,6 @@ constructor(
                     flagColIdx >= 0 &&
                         ((cursor.getInt(flagColIdx) and FLAG_SUPPORTS_THUMBNAIL) != 0)
 
-                var title = ""
-                if (nameColIndex >= 0) {
-                    title = cursor.getString(nameColIndex) ?: ""
-                }
-                if (TextUtils.isEmpty(title) && titleColIndex >= 0) {
-                    title = cursor.getString(titleColIndex) ?: ""
-                }
-
                 val iconUri =
                     if (displayIconUriColIdx >= 0) {
                         cursor.getString(displayIconUriColIdx)?.let(Uri::parse)
@@ -344,7 +313,7 @@ constructor(
                         null
                     }
 
-                QueryResult(supportsThumbnail, title, iconUri)
+                QueryResult(supportsThumbnail, iconUri)
             } ?: QueryResult()
 
         private fun readTitleFromQuery(): String = readStringColumn(Downloads.Impl.COLUMN_TITLE)
@@ -359,11 +328,7 @@ constructor(
             } ?: ""
     }
 
-    private class QueryResult(
-        val supportsThumbnail: Boolean = false,
-        val title: String = "",
-        val iconUri: Uri? = null,
-    )
+    private class QueryResult(val supportsThumbnail: Boolean = false, val iconUri: Uri? = null)
 }
 
 private val Intent.isSend: Boolean
diff --git a/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
index 8592e6ae..e59f2b7e 100644
--- a/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
@@ -16,9 +16,13 @@
 
 package com.android.intentresolver.contentpreview;
 
+import static com.android.intentresolver.Flags.useGoogleSansFlex;
+import static com.android.intentresolver.ui.FontStyles.GSF_BODY_SMALL_BASELINE;
+import static com.android.intentresolver.ui.FontStyles.GSF_LABEL_MEDIUM_BASELINE;
 import static com.android.intentresolver.util.UriFilters.isOwnedByCurrentUser;
 
 import android.content.res.Resources;
+import android.graphics.Typeface;
 import android.net.Uri;
 import android.text.SpannableStringBuilder;
 import android.text.TextUtils;
@@ -110,14 +114,21 @@ class TextContentPreviewUi extends ContentPreviewUi {
             return contentPreviewLayout;
         }
 
-        TextView textView = contentPreviewLayout.findViewById(
+        TextView textView = contentPreviewLayout.requireViewById(
                 com.android.internal.R.id.content_preview_text);
 
+        if (useGoogleSansFlex()) {
+            textView.setTypeface(Typeface.create(GSF_BODY_SMALL_BASELINE, Typeface.NORMAL));
+        }
         textView.setText(
                 textView.getMaxLines() == 1 ? replaceLineBreaks(mSharingText) : mSharingText);
 
-        TextView previewTitleView = contentPreviewLayout.findViewById(
+        TextView previewTitleView = contentPreviewLayout.requireViewById(
                 com.android.internal.R.id.content_preview_title);
+        if (useGoogleSansFlex()) {
+            previewTitleView.setTypeface(
+                    Typeface.create(GSF_LABEL_MEDIUM_BASELINE, Typeface.NORMAL));
+        }
         if (TextUtils.isEmpty(mPreviewTitle)) {
             previewTitleView.setVisibility(View.GONE);
         } else {
diff --git a/java/src/com/android/intentresolver/contentpreview/UnifiedContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/UnifiedContentPreviewUi.java
index 7de988c4..fe4ae89f 100644
--- a/java/src/com/android/intentresolver/contentpreview/UnifiedContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/UnifiedContentPreviewUi.java
@@ -101,6 +101,15 @@ class UnifiedContentPreviewUi extends ContentPreviewUi {
         return displayInternal(layoutInflater, parent, headlineViewParent);
     }
 
+    @Override
+    public void setImageEditorCallback(Runnable imageEditorCallback) {
+        if (mShowEditAction) {
+            ScrollableImagePreviewView imagePreview =
+                    mContentPreviewView.requireViewById(R.id.scrollable_image_preview);
+            imagePreview.setImageEditorCallback(imageEditorCallback);
+        }
+    }
+
     private void setFiles(List<FileInfo> files) {
         Size previewSize = new Size(mPreviewSize, mPreviewSize);
         mImageLoader.prePopulate(
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractor.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractor.kt
index 2d02e4fd..6796db3a 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractor.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractor.kt
@@ -17,7 +17,6 @@
 package com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor
 
 import android.net.Uri
-import com.android.intentresolver.Flags.unselectFinalItem
 import com.android.intentresolver.contentpreview.MimeTypeClassifier
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.PreviewSelectionsRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.TargetIntentModifier
@@ -61,13 +60,11 @@ constructor(
     }
 
     fun unselect(model: PreviewModel) {
-        if (selectionsRepo.selections.value.size > 1 || unselectFinalItem()) {
-            selectionsRepo.selections
-                .updateAndGet { it - model.uri }
-                .values
-                .takeIf { it.isNotEmpty() }
-                ?.let { updateChooserRequest(it) }
-        }
+        selectionsRepo.selections
+            .updateAndGet { it - model.uri }
+            .values
+            .takeIf { it.isNotEmpty() }
+            ?.let { updateChooserRequest(it) }
     }
 
     private fun updateChooserRequest(selections: Collection<PreviewModel>) {
@@ -76,9 +73,7 @@ constructor(
         updateTargetIntentInteractor.updateTargetIntent(intent)
     }
 
-    private fun aggregateContentType(
-        items: Collection<PreviewModel>,
-    ): ContentType {
+    private fun aggregateContentType(items: Collection<PreviewModel>): ContentType {
         if (items.isEmpty()) {
             return ContentType.Other
         }
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallback.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallback.kt
index 184cc027..c490edde 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallback.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallback.kt
@@ -34,7 +34,6 @@ import android.os.Bundle
 import android.service.chooser.AdditionalContentContract.MethodNames.ON_SELECTION_CHANGED
 import android.service.chooser.ChooserAction
 import android.service.chooser.ChooserTarget
-import com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ShareouselUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
 import com.android.intentresolver.inject.AdditionalContent
@@ -85,9 +84,9 @@ constructor(
                     Bundle().apply {
                         putParcelable(
                             EXTRA_INTENT,
-                            Intent(chooserIntent).apply { putExtra(EXTRA_INTENT, targetIntent) }
+                            Intent(chooserIntent).apply { putExtra(EXTRA_INTENT, targetIntent) },
                         )
-                    }
+                    },
                 )
             }
             ?.let { bundle ->
@@ -104,9 +103,7 @@ constructor(
             }
 }
 
-private fun readCallbackResponse(
-    bundle: Bundle,
-): ValidationResult<ShareouselUpdate> {
+private fun readCallbackResponse(bundle: Bundle): ValidationResult<ShareouselUpdate> {
     return validateFrom(bundle::get) {
         // An error is treated as an empty collection or null as the presence of a value indicates
         // an intention to change the old value implying that the old value is obsolete (and should
@@ -140,12 +137,8 @@ private fun readCallbackResponse(
                 optional(value<CharSequence>(key))
             }
         val excludedComponents: ValueUpdate<List<ComponentName>> =
-            if (shareouselUpdateExcludeComponentsExtra()) {
-                bundle.readValueUpdate(EXTRA_EXCLUDE_COMPONENTS) { key ->
-                    optional(array<ComponentName>(key)) ?: emptyList()
-                }
-            } else {
-                ValueUpdate.Absent
+            bundle.readValueUpdate(EXTRA_EXCLUDE_COMPONENTS) { key ->
+                optional(array<ComponentName>(key)) ?: emptyList()
             }
 
         ShareouselUpdate(
@@ -163,7 +156,7 @@ private fun readCallbackResponse(
 
 private inline fun <reified T> Bundle.readValueUpdate(
     key: String,
-    block: (String) -> T
+    block: (String) -> T,
 ): ValueUpdate<T> =
     if (containsKey(key)) {
         ValueUpdate.Value(block(key))
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
index 015a0490..b8c7d8e2 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
@@ -68,15 +68,13 @@ import androidx.compose.ui.platform.testTag
 import androidx.compose.ui.res.dimensionResource
 import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.semantics.contentDescription
+import androidx.compose.ui.semantics.selected
 import androidx.compose.ui.semantics.semantics
 import androidx.compose.ui.unit.Dp
 import androidx.compose.ui.unit.dp
 import androidx.lifecycle.compose.collectAsStateWithLifecycle
-import com.android.intentresolver.Flags.announceShareouselItemListPosition
 import com.android.intentresolver.Flags.shareouselScrollOffscreenSelections
 import com.android.intentresolver.Flags.shareouselSelectionShrink
-import com.android.intentresolver.Flags.shareouselTapToScrollSupport
-import com.android.intentresolver.Flags.unselectFinalItem
 import com.android.intentresolver.R
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.getOrDefault
@@ -89,7 +87,6 @@ import kotlin.math.abs
 import kotlin.math.min
 import kotlin.math.roundToInt
 import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.launch
 
 @Composable
@@ -176,10 +173,7 @@ private fun PreviewCarouselItems(
                 start = measurements.horizontalPaddingDp,
                 end = measurements.horizontalPaddingDp,
             ),
-        modifier =
-            Modifier.fillMaxSize().conditional(shareouselTapToScrollSupport()) {
-                tapToScroll(scrollableState = state)
-            },
+        modifier = Modifier.fillMaxSize().tapToScroll(scrollableState = state),
     ) {
         itemsIndexed(
             items = previews.previewModels,
@@ -300,7 +294,10 @@ private fun ShareouselCard(
         Crossfade(
             targetState = bitmapLoadState,
             modifier =
-                Modifier.semantics { this.contentDescription = contentDescription }
+                Modifier.semantics {
+                        this.selected = selected
+                        this.contentDescription = contentDescription
+                    }
                     .testTag(viewModel.testTag)
                     .clickable { scope.launch { viewModel.setSelected(!selected) } }
                     .conditional(shareouselSelectionShrink()) {
@@ -328,11 +325,7 @@ private fun buildContentDescription(
     annotateWithPosition: Boolean,
     viewModel: ShareouselPreviewViewModel,
 ): String = buildString {
-    if (
-        announceShareouselItemListPosition() &&
-            annotateWithPosition &&
-            viewModel.cursorPosition >= 0
-    ) {
+    if (annotateWithPosition && viewModel.cursorPosition >= 0) {
         // If item cursor position is not known, do not announce item position.
         // We can have items with an unknown cursor position only when:
         // * when we haven't got the cursor and showing the initially shared items;
@@ -398,12 +391,7 @@ private fun ActionCarousel(viewModel: ShareouselViewModel) {
     val actions by viewModel.actions.collectAsStateWithLifecycle(initialValue = emptyList())
     if (actions.isNotEmpty()) {
         Spacer(Modifier.height(16.dp))
-        val visibilityFlow =
-            if (unselectFinalItem()) {
-                viewModel.hasSelectedItems
-            } else {
-                MutableStateFlow(true)
-            }
+        val visibilityFlow = viewModel.hasSelectedItems
         val visibility by visibilityFlow.collectAsStateWithLifecycle(true)
         val height = 32.dp
         if (visibility) {
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt
index 45e01e9d..36062d89 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt
@@ -16,7 +16,6 @@
 package com.android.intentresolver.contentpreview.payloadtoggle.ui.viewmodel
 
 import android.util.Size
-import com.android.intentresolver.Flags.unselectFinalItem
 import com.android.intentresolver.contentpreview.HeadlineGenerator
 import com.android.intentresolver.contentpreview.ImageLoader
 import com.android.intentresolver.contentpreview.MimeTypeClassifier
@@ -86,7 +85,7 @@ object ShareouselViewModelModule {
                 selectionInteractor.aggregateContentType.zip(selectionInteractor.amountSelected) {
                     contentType,
                     numItems ->
-                    if (unselectFinalItem() && numItems == 0) {
+                    if (numItems == 0) {
                         headlineGenerator.getNotItemsSelectedHeadline()
                     } else {
                         when (contentType) {
diff --git a/java/src/com/android/intentresolver/data/model/ChooserRequest.kt b/java/src/com/android/intentresolver/data/model/ChooserRequest.kt
index ad338103..a154c0e4 100644
--- a/java/src/com/android/intentresolver/data/model/ChooserRequest.kt
+++ b/java/src/com/android/intentresolver/data/model/ChooserRequest.kt
@@ -26,10 +26,11 @@ import android.net.Uri
 import android.os.Bundle
 import android.service.chooser.ChooserAction
 import android.service.chooser.ChooserTarget
+import android.service.chooser.IChooserControllerCallback
 import androidx.annotation.StringRes
 import com.android.intentresolver.ContentTypeHint
-import com.android.intentresolver.IChooserInteractiveSessionCallback
 import com.android.intentresolver.ext.hasAction
+import com.android.intentresolver.util.sanitizePayloadIntents
 import com.android.systemui.shared.Flags.screenshotContextUrl
 
 const val ANDROID_APP_SCHEME = "android-app"
@@ -184,7 +185,8 @@ data class ChooserRequest(
      * Specified by the [Intent.EXTRA_METADATA_TEXT]
      */
     val metadataText: CharSequence? = null,
-    val interactiveSessionCallback: IChooserInteractiveSessionCallback? = null,
+    val interactiveSessionCallback: IChooserControllerCallback? = null,
+    val colorScheme: ColorScheme = ColorScheme.SystemDefault,
 ) {
     val referrerPackage = referrer?.takeIf { it.scheme == ANDROID_APP_SCHEME }?.authority
 
@@ -198,6 +200,24 @@ data class ChooserRequest(
 
     val payloadIntents = listOf(targetIntent) + additionalTargets
 
+    /**
+     * Payload intents that should be used for cross-profile sharing.
+     *
+     * These intents are a copy of `payloadIntents`. For security reasons, explicit targeting
+     * information is removed from each [Intent] in the list, as well as from its
+     * [selector][Intent.getSelector]. Specifically, the values that would be returned by
+     * [Intent.getPackage] and [Intent.getComponent] are cleared for both the main intent and its
+     * selector. This sanitization is performed because explicit intents could otherwise be used to
+     * bypass the device's cross-profile sharing policy settings.
+     */
+    val crossProfilePayloadIntents by lazy { sanitizePayloadIntents(payloadIntents) }
+
     val callerAllowsTextToggle =
         screenshotContextUrl() && "com.android.systemui".equals(referrerPackage)
 }
+
+enum class ColorScheme {
+    SystemDefault,
+    Light,
+    Dark,
+}
diff --git a/java/src/com/android/intentresolver/domain/ChooserRequestExt.kt b/java/src/com/android/intentresolver/domain/ChooserRequestExt.kt
index 5ca3ad20..fbab403c 100644
--- a/java/src/com/android/intentresolver/domain/ChooserRequestExt.kt
+++ b/java/src/com/android/intentresolver/domain/ChooserRequestExt.kt
@@ -28,7 +28,6 @@ import android.content.Intent.EXTRA_EXCLUDE_COMPONENTS
 import android.content.Intent.EXTRA_INTENT
 import android.content.Intent.EXTRA_METADATA_TEXT
 import android.os.Bundle
-import com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ShareouselUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.getOrDefault
 import com.android.intentresolver.data.model.ChooserRequest
@@ -44,12 +43,7 @@ fun ChooserRequest.updateWith(targetIntent: Intent, update: ShareouselUpdate): C
         refinementIntentSender = update.refinementIntentSender.getOrDefault(refinementIntentSender),
         metadataText = update.metadataText.getOrDefault(metadataText),
         chooserActions = update.customActions.getOrDefault(chooserActions),
-        filteredComponentNames =
-            if (shareouselUpdateExcludeComponentsExtra()) {
-                update.excludeComponents.getOrDefault(filteredComponentNames)
-            } else {
-                filteredComponentNames
-            },
+        filteredComponentNames = update.excludeComponents.getOrDefault(filteredComponentNames),
     )
 
 /** Save ChooserRequest values that can be updated by the Shareousel into a Bundle */
@@ -63,8 +57,6 @@ fun ChooserRequest.saveUpdates(bundle: Bundle): Bundle {
     bundle.putParcelable(EXTRA_CHOOSER_REFINEMENT_INTENT_SENDER, refinementIntentSender)
     bundle.putCharSequence(EXTRA_METADATA_TEXT, metadataText)
     bundle.putParcelableArray(EXTRA_CHOOSER_CUSTOM_ACTIONS, chooserActions.toTypedArray())
-    if (shareouselUpdateExcludeComponentsExtra()) {
-        bundle.putParcelableArray(EXTRA_EXCLUDE_COMPONENTS, filteredComponentNames.toTypedArray())
-    }
+    bundle.putParcelableArray(EXTRA_EXCLUDE_COMPONENTS, filteredComponentNames.toTypedArray())
     return bundle
 }
diff --git a/java/src/com/android/intentresolver/emptystate/CrossProfileIntentsChecker.java b/java/src/com/android/intentresolver/emptystate/CrossProfileIntentsChecker.java
index 2164e533..0e4a6350 100644
--- a/java/src/com/android/intentresolver/emptystate/CrossProfileIntentsChecker.java
+++ b/java/src/com/android/intentresolver/emptystate/CrossProfileIntentsChecker.java
@@ -53,7 +53,6 @@ public class CrossProfileIntentsChecker {
             List<Intent> intents, @UserIdInt int source, @UserIdInt int target) {
         return intents.stream().anyMatch(intent ->
                 null != IntentForwarderActivity.canForward(intent, source, target,
-                        mPackageManager, mContentResolver));
+                        mPackageManager, intent.resolveTypeIfNeeded(mContentResolver)));
     }
 }
-
diff --git a/java/src/com/android/intentresolver/icons/CachingTargetDataLoader.kt b/java/src/com/android/intentresolver/icons/CachingTargetDataLoader.kt
index 793b7621..f266e63e 100644
--- a/java/src/com/android/intentresolver/icons/CachingTargetDataLoader.kt
+++ b/java/src/com/android/intentresolver/icons/CachingTargetDataLoader.kt
@@ -24,8 +24,10 @@ import android.graphics.drawable.Drawable
 import android.os.UserHandle
 import androidx.collection.LruCache
 import com.android.intentresolver.Flags.targetHoverAndKeyboardFocusStates
+import com.android.intentresolver.Flags.useResolveInfoUserHandle
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.chooser.SelectableTargetInfo
+import com.android.launcher3.icons.FastBitmapDrawable
 import java.util.function.Consumer
 import javax.annotation.concurrent.GuardedBy
 import javax.inject.Qualifier
@@ -43,10 +45,16 @@ class CachingTargetDataLoader(
 
     override fun getOrLoadAppTargetIcon(
         info: DisplayResolveInfo,
-        userHandle: UserHandle,
+        defaultUserHandle: UserHandle,
         callback: Consumer<Drawable>,
     ): Drawable? {
         val cacheKey = info.toCacheKey()
+        val userHandle =
+            if (useResolveInfoUserHandle()) {
+                info.resolveInfo.userHandle ?: defaultUserHandle
+            } else {
+                defaultUserHandle
+            }
         return getCachedAppIcon(cacheKey, userHandle)?.toDrawable()
             ?: targetDataLoader.getOrLoadAppTargetIcon(info, userHandle) { drawable ->
                 drawable.extractBitmap()?.let { getProfileIconCache(userHandle).put(cacheKey, it) }
@@ -102,7 +110,7 @@ class CachingTargetDataLoader(
 
     private fun Bitmap.toDrawable(): Drawable {
         return if (targetHoverAndKeyboardFocusStates()) {
-            HoverBitmapDrawable(this)
+            FastBitmapDrawable(this)
         } else {
             BitmapDrawable(context.resources, this)
         }
@@ -111,7 +119,7 @@ class CachingTargetDataLoader(
     private fun Drawable.extractBitmap(): Bitmap? {
         return when (this) {
             is BitmapDrawable -> bitmap
-            is HoverBitmapDrawable -> bitmap
+            is FastBitmapDrawable -> bitmapInfo.icon
             else -> null
         }
     }
diff --git a/java/src/com/android/intentresolver/icons/DefaultTargetDataLoader.kt b/java/src/com/android/intentresolver/icons/DefaultTargetDataLoader.kt
index 1ff1ddfa..5b84fe47 100644
--- a/java/src/com/android/intentresolver/icons/DefaultTargetDataLoader.kt
+++ b/java/src/com/android/intentresolver/icons/DefaultTargetDataLoader.kt
@@ -16,24 +16,33 @@
 
 package com.android.intentresolver.icons
 
+import android.content.ComponentName
 import android.content.Context
+import android.content.pm.LauncherApps
+import android.content.pm.ShortcutInfo
 import android.graphics.Bitmap
 import android.graphics.drawable.BitmapDrawable
 import android.graphics.drawable.Drawable
+import android.graphics.drawable.Icon
 import android.os.AsyncTask
 import android.os.UserHandle
+import android.util.Log
 import android.util.SparseArray
 import androidx.annotation.GuardedBy
 import androidx.lifecycle.DefaultLifecycleObserver
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.coroutineScope
+import com.android.intentresolver.Flags.badgeShortcutIconPlaceholders
 import com.android.intentresolver.Flags.targetHoverAndKeyboardFocusStates
-import com.android.intentresolver.R
 import com.android.intentresolver.SimpleIconFactory
 import com.android.intentresolver.TargetPresentationGetter
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.chooser.SelectableTargetInfo
 import com.android.intentresolver.inject.ActivityOwned
+import com.android.intentresolver.inject.Background
+import com.android.intentresolver.util.hasValidIcon
+import com.android.launcher3.icons.FastBitmapDrawable
 import dagger.assisted.Assisted
 import dagger.assisted.AssistedFactory
 import dagger.assisted.AssistedInject
@@ -41,8 +50,19 @@ import dagger.hilt.android.qualifiers.ActivityContext
 import java.util.concurrent.atomic.AtomicInteger
 import java.util.function.Consumer
 import javax.inject.Provider
-import kotlinx.coroutines.Dispatchers
+import javax.inject.Qualifier
+import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.asExecutor
+import kotlinx.coroutines.isActive
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.withContext
+
+private const val TAG = "DefaultTargetDataLoader"
+
+@Qualifier
+@MustBeDocumented
+@Retention(AnnotationRetention.BINARY)
+annotation class IconPlaceholder
 
 /** An actual [TargetDataLoader] implementation. */
 // TODO: replace async tasks with coroutines.
@@ -53,11 +73,13 @@ constructor(
     @ActivityOwned private val lifecycle: Lifecycle,
     private val iconFactoryProvider: Provider<SimpleIconFactory>,
     private val presentationFactory: TargetPresentationGetter.Factory,
+    @Background private val bgDispatcher: CoroutineDispatcher,
+    @IconPlaceholder private val iconPlacehoderProvider: Provider<Drawable>,
     @Assisted private val isAudioCaptureDevice: Boolean,
 ) : TargetDataLoader {
     private val nextTaskId = AtomicInteger(0)
     @GuardedBy("self") private val activeTasks = SparseArray<AsyncTask<*, *, *>>()
-    private val executor = Dispatchers.IO.asExecutor()
+    private val executor = bgDispatcher.asExecutor()
 
     init {
         lifecycle.addObserver(
@@ -72,7 +94,7 @@ constructor(
 
     override fun getOrLoadAppTargetIcon(
         info: DisplayResolveInfo,
-        userHandle: UserHandle,
+        defaultUserHandle: UserHandle,
         callback: Consumer<Drawable>,
     ): Drawable? {
         val taskId = nextTaskId.getAndIncrement()
@@ -90,18 +112,22 @@ constructor(
         userHandle: UserHandle,
         callback: Consumer<Drawable>,
     ): Drawable? {
-        val taskId = nextTaskId.getAndIncrement()
-        LoadDirectShareIconTask(
-                context.createContextAsUser(userHandle, 0),
-                info,
-                presentationFactory,
-                iconFactoryProvider,
-            ) { bitmap ->
-                removeTask(taskId)
-                callback.accept(bitmap?.toDrawable() ?: loadIconPlaceholder())
-            }
-            .also { addTask(taskId, it) }
-            .executeOnExecutor(executor)
+        if (badgeShortcutIconPlaceholders()) {
+            loadDirectShareIcon(context.createContextAsUser(userHandle, 0), info, callback)
+        } else {
+            val taskId = nextTaskId.getAndIncrement()
+            LoadDirectShareIconTask(
+                    context.createContextAsUser(userHandle, 0),
+                    info,
+                    presentationFactory,
+                    iconFactoryProvider,
+                ) { bitmap ->
+                    removeTask(taskId)
+                    callback.accept(bitmap?.toDrawable() ?: loadIconPlaceholder())
+                }
+                .also { addTask(taskId, it) }
+                .executeOnExecutor(executor)
+        }
         return null
     }
 
@@ -132,8 +158,7 @@ constructor(
         synchronized(activeTasks) { activeTasks.remove(id) }
     }
 
-    private fun loadIconPlaceholder(): Drawable =
-        requireNotNull(context.getDrawable(R.drawable.resolver_icon_placeholder))
+    private fun loadIconPlaceholder(): Drawable = iconPlacehoderProvider.get()
 
     private fun destroy() {
         synchronized(activeTasks) {
@@ -146,12 +171,63 @@ constructor(
 
     private fun Bitmap.toDrawable(): Drawable {
         return if (targetHoverAndKeyboardFocusStates()) {
-            HoverBitmapDrawable(this)
+            FastBitmapDrawable(this)
         } else {
             BitmapDrawable(context.resources, this)
         }
     }
 
+    private fun loadDirectShareIcon(
+        userContext: Context,
+        info: SelectableTargetInfo,
+        consumer: Consumer<Drawable>,
+    ) {
+        lifecycle.coroutineScope.launch {
+            val iconDrawable =
+                withContext(bgDispatcher) {
+                    val icon = info.chooserTargetIcon?.takeIf { hasValidIcon(it) }
+                    val iconDrawable =
+                        getDirectTargetIconDrawable(userContext, icon, info.directShareShortcutInfo)
+                    val appIcon =
+                        info.chooserTargetComponentName?.let { getAppIcon(userContext, it) }
+                    if (appIcon != null) {
+                        iconFactoryProvider.get().use { sif ->
+                            sif.createAppBadgedIconBitmap(iconDrawable, appIcon).toDrawable()
+                        }
+                    } else {
+                        iconDrawable
+                    }
+                }
+            if (isActive) {
+                consumer.accept(iconDrawable)
+            }
+        }
+    }
+
+    private fun getDirectTargetIconDrawable(
+        userContext: Context,
+        icon: Icon?,
+        shortcutInfo: ShortcutInfo?,
+    ): Drawable {
+        return (if (icon != null) {
+            icon.loadDrawable(userContext)
+        } else if (shortcutInfo != null) {
+            userContext
+                .getSystemService<LauncherApps?>(LauncherApps::class.java)
+                ?.getShortcutIconDrawable(shortcutInfo, 0)
+        } else {
+            null
+        }) ?: return loadIconPlaceholder()
+    }
+
+    private fun getAppIcon(userContext: Context, targetComponentName: ComponentName): Bitmap? =
+        runCatching {
+                val info = userContext.getPackageManager().getActivityInfo(targetComponentName, 0)
+                presentationFactory.makePresentationGetter(info).getIconBitmap(null)
+            }
+            .onFailure { Log.e(TAG, "Could not find activity associated with ChooserTarget") }
+            .getOrNull()
+
     @AssistedFactory
     interface Factory {
         fun create(isAudioCaptureDevice: Boolean): DefaultTargetDataLoader
diff --git a/java/src/com/android/intentresolver/icons/HoverBitmapDrawable.kt b/java/src/com/android/intentresolver/icons/HoverBitmapDrawable.kt
deleted file mode 100644
index 4a21df92..00000000
--- a/java/src/com/android/intentresolver/icons/HoverBitmapDrawable.kt
+++ /dev/null
@@ -1,41 +0,0 @@
-/*
- * Copyright 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      https://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.intentresolver.icons
-
-import android.graphics.Bitmap
-import com.android.launcher3.icons.FastBitmapDrawable
-
-/** A [FastBitmapDrawable] extension that provides access to the bitmap. */
-class HoverBitmapDrawable(val bitmap: Bitmap) : FastBitmapDrawable(bitmap) {
-
-    override fun newConstantState(): FastBitmapConstantState {
-        return HoverBitmapDrawableState(bitmap, iconColor)
-    }
-
-    private class HoverBitmapDrawableState(private val bitmap: Bitmap, color: Int) :
-        FastBitmapConstantState(bitmap, color) {
-        override fun createDrawable(): FastBitmapDrawable {
-            return HoverBitmapDrawable(bitmap)
-        }
-    }
-
-    companion object {
-        init {
-            setFlagHoverEnabled(true)
-        }
-    }
-}
diff --git a/java/src/com/android/intentresolver/icons/TargetDataLoader.kt b/java/src/com/android/intentresolver/icons/TargetDataLoader.kt
index 7cbd040e..4fc02a5c 100644
--- a/java/src/com/android/intentresolver/icons/TargetDataLoader.kt
+++ b/java/src/com/android/intentresolver/icons/TargetDataLoader.kt
@@ -27,7 +27,7 @@ interface TargetDataLoader {
     /** Load an app target icon */
     fun getOrLoadAppTargetIcon(
         info: DisplayResolveInfo,
-        userHandle: UserHandle,
+        defaultUserHandle: UserHandle,
         callback: Consumer<Drawable>,
     ): Drawable?
 
diff --git a/java/src/com/android/intentresolver/icons/TargetDataLoaderModule.kt b/java/src/com/android/intentresolver/icons/TargetDataLoaderModule.kt
index d6d4aae1..74cd11c5 100644
--- a/java/src/com/android/intentresolver/icons/TargetDataLoaderModule.kt
+++ b/java/src/com/android/intentresolver/icons/TargetDataLoaderModule.kt
@@ -19,6 +19,8 @@ package com.android.intentresolver.icons
 import android.app.ActivityManager
 import android.content.Context
 import android.content.pm.PackageManager
+import android.graphics.drawable.Drawable
+import com.android.intentresolver.R
 import com.android.intentresolver.SimpleIconFactory
 import com.android.intentresolver.TargetPresentationGetter
 import dagger.Module
@@ -32,6 +34,11 @@ import javax.inject.Provider
 @Module
 @InstallIn(ActivityComponent::class)
 object TargetDataLoaderModule {
+    @Provides
+    @IconPlaceholder
+    fun iconPlaceholder(@ActivityContext context: Context): Drawable =
+        requireNotNull(context.getDrawable(R.drawable.resolver_icon_placeholder))
+
     @Provides
     fun simpleIconFactory(@ActivityContext context: Context): SimpleIconFactory =
         SimpleIconFactory.obtain(context)
diff --git a/java/src/com/android/intentresolver/inject/ActivityModelModule.kt b/java/src/com/android/intentresolver/inject/ActivityModelModule.kt
index 60eff925..9323f9f7 100644
--- a/java/src/com/android/intentresolver/inject/ActivityModelModule.kt
+++ b/java/src/com/android/intentresolver/inject/ActivityModelModule.kt
@@ -21,7 +21,6 @@ import android.net.Uri
 import android.os.Bundle
 import android.service.chooser.ChooserAction
 import androidx.lifecycle.SavedStateHandle
-import com.android.intentresolver.Flags.saveShareouselState
 import com.android.intentresolver.data.model.ChooserRequest
 import com.android.intentresolver.data.repository.ActivityModelRepository
 import com.android.intentresolver.ui.viewmodel.CHOOSER_REQUEST_KEY
@@ -130,13 +129,9 @@ private fun restoreChooserRequestExtras(
     initialExtras: Bundle?,
     savedStateHandle: SavedStateHandle,
 ): Bundle =
-    if (saveShareouselState()) {
-        savedStateHandle.get<Bundle>(CHOOSER_REQUEST_KEY)?.let { savedSateBundle ->
-            Bundle().apply {
-                initialExtras?.let { putAll(it) }
-                putAll(savedSateBundle)
-            }
-        } ?: initialExtras
-    } else {
-        initialExtras
-    } ?: Bundle()
+    savedStateHandle.get<Bundle>(CHOOSER_REQUEST_KEY)?.let { savedSateBundle ->
+        Bundle().apply {
+            initialExtras?.let { putAll(it) }
+            putAll(savedSateBundle)
+        }
+    } ?: initialExtras ?: Bundle()
diff --git a/java/src/com/android/intentresolver/interactive/data/repository/InteractiveSessionCallbackRepository.kt b/java/src/com/android/intentresolver/interactive/data/repository/InteractiveSessionCallbackRepository.kt
index f8894de5..6a792dcd 100644
--- a/java/src/com/android/intentresolver/interactive/data/repository/InteractiveSessionCallbackRepository.kt
+++ b/java/src/com/android/intentresolver/interactive/data/repository/InteractiveSessionCallbackRepository.kt
@@ -17,9 +17,9 @@
 package com.android.intentresolver.interactive.data.repository
 
 import android.os.Bundle
+import android.service.chooser.IChooserController
 import androidx.lifecycle.SavedStateHandle
-import com.android.intentresolver.IChooserController
-import com.android.intentresolver.interactive.domain.model.ChooserIntentUpdater
+import com.android.intentresolver.interactive.domain.model.ChooserController
 import dagger.hilt.android.scopes.ViewModelScoped
 import java.util.concurrent.atomic.AtomicReference
 import javax.inject.Inject
@@ -28,27 +28,26 @@ private const val INTERACTIVE_SESSION_CALLBACK_KEY = "interactive-session-callba
 
 @ViewModelScoped
 class InteractiveSessionCallbackRepository @Inject constructor(savedStateHandle: SavedStateHandle) {
-    private val intentUpdaterRef =
-        AtomicReference<ChooserIntentUpdater?>(
+    private val chooserControllerRef =
+        AtomicReference<ChooserController?>(
             savedStateHandle
                 .get<Bundle>(INTERACTIVE_SESSION_CALLBACK_KEY)
-                ?.let { it.getBinder(INTERACTIVE_SESSION_CALLBACK_KEY) }
+                ?.getBinder(INTERACTIVE_SESSION_CALLBACK_KEY)
                 ?.let { binder ->
-                    binder.queryLocalInterface(IChooserController.DESCRIPTOR)
-                        as? ChooserIntentUpdater
+                    binder.queryLocalInterface(IChooserController.DESCRIPTOR) as? ChooserController
                 }
         )
 
-    val intentUpdater: ChooserIntentUpdater?
-        get() = intentUpdaterRef.get()
+    val chooserController: ChooserController?
+        get() = chooserControllerRef.get()
 
     init {
         savedStateHandle.setSavedStateProvider(INTERACTIVE_SESSION_CALLBACK_KEY) {
-            Bundle().apply { putBinder(INTERACTIVE_SESSION_CALLBACK_KEY, intentUpdater) }
+            Bundle().apply { putBinder(INTERACTIVE_SESSION_CALLBACK_KEY, chooserController) }
         }
     }
 
-    fun setChooserIntentUpdater(intentUpdater: ChooserIntentUpdater) {
-        intentUpdaterRef.compareAndSet(null, intentUpdater)
+    fun setChooserController(chooserController: ChooserController) {
+        chooserControllerRef.compareAndSet(null, chooserController)
     }
 }
diff --git a/java/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractor.kt b/java/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractor.kt
index 09b79985..771024ba 100644
--- a/java/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractor.kt
+++ b/java/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractor.kt
@@ -17,6 +17,7 @@
 package com.android.intentresolver.interactive.domain.interactor
 
 import android.content.Intent
+import android.graphics.Rect
 import android.os.Bundle
 import android.os.IBinder
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.PendingSelectionCallbackRepository
@@ -24,7 +25,7 @@ import com.android.intentresolver.data.model.ChooserRequest
 import com.android.intentresolver.data.repository.ActivityModelRepository
 import com.android.intentresolver.data.repository.ChooserRequestRepository
 import com.android.intentresolver.interactive.data.repository.InteractiveSessionCallbackRepository
-import com.android.intentresolver.interactive.domain.model.ChooserIntentUpdater
+import com.android.intentresolver.interactive.domain.model.ChooserController
 import com.android.intentresolver.ui.viewmodel.readChooserRequest
 import com.android.intentresolver.validation.Invalid
 import com.android.intentresolver.validation.Valid
@@ -51,13 +52,15 @@ constructor(
     private val activityModel = activityModelRepo.value
     private val sessionCallback =
         chooserRequestRepository.initialRequest.interactiveSessionCallback?.let {
-            SafeChooserInteractiveSessionCallback(it)
+            SafeChooserControllerCallback(it)
         }
     val isSessionActive = MutableStateFlow(true)
+    val isTargetEnabled = MutableStateFlow(true)
 
     suspend fun activate() = coroutineScope {
         if (sessionCallback == null || activityModel.isTaskRoot) {
             sessionCallback?.registerChooserController(null)
+            sessionCallback?.onClosed()
             return@coroutineScope
         }
         launch {
@@ -74,21 +77,22 @@ constructor(
                 isSessionActive.value = false
             }
         }
-        val chooserIntentUpdater =
-            interactiveCallbackRepo.intentUpdater
-                ?: ChooserIntentUpdater().also {
-                    interactiveCallbackRepo.setChooserIntentUpdater(it)
+        val chooserController =
+            interactiveCallbackRepo.chooserController
+                ?: ChooserController().also {
+                    interactiveCallbackRepo.setChooserController(it)
                     sessionCallback.registerChooserController(it)
                 }
-        chooserIntentUpdater.chooserIntent.collect { onIntentUpdated(it) }
+        launch { chooserController.chooserIntent.collect { onIntentUpdated(it) } }
+        launch { chooserController.targetStatusFlow.collect(isTargetEnabled) }
     }
 
-    fun sendTopDrawerTopOffsetChange(offset: Int) {
-        sessionCallback?.onDrawerVerticalOffsetChanged(offset)
+    fun sendChooserWindowSize(size: Rect) {
+        sessionCallback?.onBoundsChanged(size)
     }
 
     fun endSession() {
-        sessionCallback?.registerChooserController(null)
+        sessionCallback?.onClosed()
     }
 
     private fun onIntentUpdated(chooserIntent: Intent?) {
diff --git a/java/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserInteractiveSessionCallback.kt b/java/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserControllerCallback.kt
similarity index 60%
rename from java/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserInteractiveSessionCallback.kt
rename to java/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserControllerCallback.kt
index d746a3b5..b87150b4 100644
--- a/java/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserInteractiveSessionCallback.kt
+++ b/java/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserControllerCallback.kt
@@ -16,15 +16,17 @@
 
 package com.android.intentresolver.interactive.domain.interactor
 
+import android.graphics.Rect
+import android.service.chooser.IChooserController
+import android.service.chooser.IChooserControllerCallback
 import android.util.Log
-import com.android.intentresolver.IChooserController
-import com.android.intentresolver.IChooserInteractiveSessionCallback
+import java.util.concurrent.atomic.AtomicBoolean
 
 private const val TAG = "SessionCallback"
 
-class SafeChooserInteractiveSessionCallback(
-    private val delegate: IChooserInteractiveSessionCallback
-) : IChooserInteractiveSessionCallback by delegate {
+class SafeChooserControllerCallback(private val delegate: IChooserControllerCallback) :
+    IChooserControllerCallback by delegate {
+    private val isOnCloseReported = AtomicBoolean(false)
 
     override fun registerChooserController(updater: IChooserController?) {
         if (!isAlive) return
@@ -32,12 +34,22 @@ class SafeChooserInteractiveSessionCallback(
             .onFailure { Log.e(TAG, "Failed to invoke registerChooserController", it) }
     }
 
-    override fun onDrawerVerticalOffsetChanged(offset: Int) {
+    override fun onBoundsChanged(size: Rect) {
         if (!isAlive) return
-        runCatching { delegate.onDrawerVerticalOffsetChanged(offset) }
+        runCatching { delegate.onBoundsChanged(size) }
             .onFailure { Log.e(TAG, "Failed to invoke onDrawerVerticalOffsetChanged", it) }
     }
 
+    override fun onClosed() {
+        if (!isAlive) return
+        if (isOnCloseReported.compareAndSet(false, true)) {
+            runCatching { delegate.onClosed() }
+                .onFailure { Log.e(TAG, "Failed to invoke onClosed", it) }
+        } else {
+            Log.d(TAG, "Session closure has already been reported")
+        }
+    }
+
     private val isAlive: Boolean
         get() = delegate.asBinder().isBinderAlive
 }
diff --git a/java/src/com/android/intentresolver/interactive/domain/model/ChooserIntentUpdater.kt b/java/src/com/android/intentresolver/interactive/domain/model/ChooserController.kt
similarity index 62%
rename from java/src/com/android/intentresolver/interactive/domain/model/ChooserIntentUpdater.kt
rename to java/src/com/android/intentresolver/interactive/domain/model/ChooserController.kt
index 5466a95d..08f48121 100644
--- a/java/src/com/android/intentresolver/interactive/domain/model/ChooserIntentUpdater.kt
+++ b/java/src/com/android/intentresolver/interactive/domain/model/ChooserController.kt
@@ -17,20 +17,39 @@
 package com.android.intentresolver.interactive.domain.model
 
 import android.content.Intent
-import com.android.intentresolver.IChooserController
+import android.service.chooser.IChooserController
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.filter
+import kotlinx.coroutines.flow.map
 
 private val NotSet = Intent()
 
-class ChooserIntentUpdater : IChooserController.Stub() {
+class ChooserController : IChooserController.Stub() {
     private val updates = MutableStateFlow<Intent?>(NotSet)
+    private val _targetStatusFlow = MutableStateFlow(TargetStatus.NotSet)
 
     val chooserIntent: Flow<Intent?>
         get() = updates.filter { it !== NotSet }
 
+    val targetStatusFlow: Flow<Boolean> =
+        _targetStatusFlow.filter { it != TargetStatus.NotSet }.map { it == TargetStatus.Enabled }
+
     override fun updateIntent(chooserIntent: Intent?) {
         updates.value = chooserIntent
     }
+
+    override fun collapse() {
+        // TODO (b/404593897)
+    }
+
+    override fun setTargetsEnabled(isEnabled: Boolean) {
+        _targetStatusFlow.value = if (isEnabled) TargetStatus.Enabled else TargetStatus.Disabled
+    }
+
+    private enum class TargetStatus {
+        NotSet,
+        Enabled,
+        Disabled,
+    }
 }
diff --git a/java/src/com/android/intentresolver/platform/ImageEditorModule.kt b/java/src/com/android/intentresolver/platform/ImageEditorModule.kt
index 24257968..01dd58d6 100644
--- a/java/src/com/android/intentresolver/platform/ImageEditorModule.kt
+++ b/java/src/com/android/intentresolver/platform/ImageEditorModule.kt
@@ -34,7 +34,15 @@ internal fun Resources.componentName(@StringRes resId: Int): ComponentName? {
     return ComponentName.unflattenFromString(getString(resId))
 }
 
-@Qualifier @MustBeDocumented @Retention(AnnotationRetention.RUNTIME) annotation class ImageEditor
+@Qualifier
+@MustBeDocumented
+@Retention(AnnotationRetention.RUNTIME)
+annotation class PreferredImageEditor
+
+@Qualifier
+@MustBeDocumented
+@Retention(AnnotationRetention.RUNTIME)
+annotation class FallbackImageEditor
 
 @Module
 @InstallIn(SingletonComponent::class)
@@ -45,7 +53,17 @@ object ImageEditorModule {
      */
     @Provides
     @Singleton
-    @ImageEditor
+    @PreferredImageEditor
+    fun preferredImageEditorComponent(@ApplicationOwned resources: Resources) =
+        Optional.ofNullable(resources.componentName(R.string.config_preferredSystemImageEditor))
+
+    /**
+     * The name of the preferred Activity to launch for editing images. This is added to Intents to
+     * edit images using Intent.ACTION_EDIT.
+     */
+    @Provides
+    @Singleton
+    @FallbackImageEditor
     fun imageEditorComponent(@ApplicationOwned resources: Resources) =
         Optional.ofNullable(resources.componentName(R.string.config_systemImageEditor))
 }
diff --git a/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java b/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java
index 677b6366..9176cd35 100644
--- a/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java
+++ b/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java
@@ -16,8 +16,6 @@
 
 package com.android.intentresolver.profiles;
 
-import static com.android.intentresolver.Flags.keyboardNavigationFix;
-
 import android.content.Context;
 import android.os.UserHandle;
 import android.view.LayoutInflater;
@@ -127,9 +125,6 @@ public class ChooserMultiProfilePagerAdapter extends MultiProfilePagerAdapter<
         LayoutInflater inflater = LayoutInflater.from(context);
         ViewGroup rootView =
                 (ViewGroup) inflater.inflate(R.layout.chooser_list_per_profile_wrap, null, false);
-        if (!keyboardNavigationFix()) {
-            rootView.setDescendantFocusability(ViewGroup.FOCUS_BLOCK_DESCENDANTS);
-        }
         RecyclerView recyclerView = rootView.findViewById(com.android.internal.R.id.resolver_list);
         recyclerView.setAccessibilityDelegateCompat(
                 new ChooserRecyclerViewAccessibilityDelegate(recyclerView));
diff --git a/java/src/com/android/intentresolver/shared/model/Profile.kt b/java/src/com/android/intentresolver/shared/model/Profile.kt
index c557c151..ce705259 100644
--- a/java/src/com/android/intentresolver/shared/model/Profile.kt
+++ b/java/src/com/android/intentresolver/shared/model/Profile.kt
@@ -16,8 +16,6 @@
 
 package com.android.intentresolver.shared.model
 
-import com.android.intentresolver.shared.model.Profile.Type
-
 /**
  * Associates [users][User] into a [Type] instance.
  *
@@ -32,7 +30,7 @@ data class Profile(
      * An optional [User] of which contains second instances of some applications installed for the
      * personal user. This value may only be supplied when creating the PERSONAL profile.
      */
-    val clone: User? = null
+    val clone: User? = null,
 ) {
 
     init {
@@ -47,6 +45,6 @@ data class Profile(
     enum class Type {
         PERSONAL,
         WORK,
-        PRIVATE
+        PRIVATE,
     }
 }
diff --git a/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt b/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt
index aa1f385f..960ef8b8 100644
--- a/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt
+++ b/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt
@@ -35,7 +35,6 @@ import androidx.annotation.MainThread
 import androidx.annotation.OpenForTesting
 import androidx.annotation.VisibleForTesting
 import androidx.annotation.WorkerThread
-import com.android.intentresolver.Flags.fixShortcutsFlashingFixed
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.measurements.Tracer
 import com.android.intentresolver.measurements.runTracing
@@ -189,27 +188,21 @@ constructor(
                 Log.d(TAG, "[$id] query AppPredictor for user $userHandle")
 
                 val watchdogJob =
-                    if (fixShortcutsFlashingFixed()) {
-                        scope
-                            .launch(start = CoroutineStart.LAZY) {
-                                delay(APP_PREDICTOR_RESPONSE_TIMEOUT_MS)
-                                Log.w(TAG, "AppPredictor response timeout for user: $userHandle")
-                                appPredictorCallback.onTargetsAvailable(emptyList())
-                            }
-                            .also { job ->
-                                appPredictorWatchdog.getAndSet(job)?.cancel()
-                                job.invokeOnCompletion {
-                                    appPredictorWatchdog.compareAndSet(job, null)
-                                }
-                            }
-                    } else {
-                        null
-                    }
+                    scope
+                        .launch(start = CoroutineStart.LAZY) {
+                            delay(APP_PREDICTOR_RESPONSE_TIMEOUT_MS)
+                            Log.w(TAG, "AppPredictor response timeout for user: $userHandle")
+                            appPredictorCallback.onTargetsAvailable(emptyList())
+                        }
+                        .also { job ->
+                            appPredictorWatchdog.getAndSet(job)?.cancel()
+                            job.invokeOnCompletion { appPredictorWatchdog.compareAndSet(job, null) }
+                        }
 
                 Tracer.beginAppPredictorQueryTrace(userHandle)
                 appPredictor.requestPredictionUpdate()
 
-                watchdogJob?.start()
+                watchdogJob.start()
                 return
             } catch (e: Throwable) {
                 endAppPredictorQueryTrace(userHandle)
diff --git a/java/src/com/android/intentresolver/ui/FontStyles.kt b/java/src/com/android/intentresolver/ui/FontStyles.kt
new file mode 100644
index 00000000..7b9f7538
--- /dev/null
+++ b/java/src/com/android/intentresolver/ui/FontStyles.kt
@@ -0,0 +1,26 @@
+/*
+ * Copyright 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+@file:JvmName("FontStyles")
+
+package com.android.intentresolver.ui
+
+const val GSF_TITLE_LARGE_BASELINE = "variable-title-large"
+
+const val GSF_TITLE_SMALL_BASELINE = "variable-title-small"
+const val GSF_LABEL_LARGE_BASELINE = "variable-label-large"
+const val GSF_LABEL_MEDIUM_BASELINE = "variable-label-medium"
+const val GSF_BODY_SMALL_BASELINE = "variable-body-small"
diff --git a/java/src/com/android/intentresolver/ui/ShareResultSender.kt b/java/src/com/android/intentresolver/ui/ShareResultSender.kt
index 2684b817..e348aa63 100644
--- a/java/src/com/android/intentresolver/ui/ShareResultSender.kt
+++ b/java/src/com/android/intentresolver/ui/ShareResultSender.kt
@@ -54,7 +54,7 @@ interface ShareResultSender {
 
 @AssistedFactory
 interface ShareResultSenderFactory {
-    fun create(callerUid: Int, chosenComponentSender: IntentSender): ShareResultSenderImpl
+    fun create(callerUid: Int, chosenComponentSender: IntentSender?): ShareResultSenderImpl
 }
 
 /** Dispatches Intents via IntentSender */
@@ -66,8 +66,8 @@ class ShareResultSenderImpl(
     @Main private val scope: CoroutineScope,
     @Background val backgroundDispatcher: CoroutineDispatcher,
     private val callerUid: Int,
-    private val resultSender: IntentSender,
-    private val intentDispatcher: IntentSenderDispatcher
+    private val resultSender: IntentSender?,
+    private val intentDispatcher: IntentSenderDispatcher,
 ) : ShareResultSender {
     @AssistedInject
     constructor(
@@ -75,21 +75,22 @@ class ShareResultSenderImpl(
         @Main scope: CoroutineScope,
         @Background backgroundDispatcher: CoroutineDispatcher,
         @Assisted callerUid: Int,
-        @Assisted chosenComponentSender: IntentSender,
+        @Assisted chosenComponentSender: IntentSender?,
     ) : this(
         scope,
         backgroundDispatcher,
         callerUid,
         chosenComponentSender,
-        IntentSenderDispatcher { sender, intent -> sender.dispatchIntent(context, intent) }
+        IntentSenderDispatcher { sender, intent -> sender.dispatchIntent(context, intent) },
     )
 
     override fun onComponentSelected(
         component: ComponentName,
         directShare: Boolean,
-        crossProfile: Boolean
+        crossProfile: Boolean,
     ) {
         Log.i(TAG, "onComponentSelected: $component directShare=$directShare cross=$crossProfile")
+        resultSender ?: return
         scope.launch {
             val intent = createChosenComponentIntent(component, directShare, crossProfile)
             intent?.let { intentDispatcher.dispatchIntent(resultSender, it) }
@@ -98,13 +99,15 @@ class ShareResultSenderImpl(
 
     override fun onActionSelected(action: ShareAction) {
         Log.i(TAG, "onActionSelected: $action")
-        scope.launch {
-            if (chooserResultSupported(callerUid)) {
-                @ResultType val chosenAction = shareActionToChooserResult(action)
-                val intent: Intent = createSelectedActionIntent(chosenAction)
-                intentDispatcher.dispatchIntent(resultSender, intent)
-            } else {
-                Log.i(TAG, "Not sending SelectedAction")
+        resultSender?.let {
+            scope.launch {
+                if (chooserResultSupported(callerUid)) {
+                    @ResultType val chosenAction = shareActionToChooserResult(action)
+                    val intent: Intent = createSelectedActionIntent(chosenAction)
+                    intentDispatcher.dispatchIntent(resultSender, intent)
+                } else {
+                    Log.i(TAG, "Not sending SelectedAction")
+                }
             }
         }
     }
@@ -120,7 +123,7 @@ class ShareResultSenderImpl(
                 return Intent()
                     .putExtra(
                         Intent.EXTRA_CHOOSER_RESULT,
-                        ChooserResult(CHOOSER_RESULT_UNKNOWN, null, direct)
+                        ChooserResult(CHOOSER_RESULT_UNKNOWN, null, direct),
                     )
             } else {
                 // Add extra with component name for backwards compatibility.
@@ -129,7 +132,7 @@ class ShareResultSenderImpl(
                 // Add ChooserResult value for Android V+
                 intent.putExtra(
                     Intent.EXTRA_CHOOSER_RESULT,
-                    ChooserResult(CHOOSER_RESULT_SELECTED_COMPONENT, component, direct)
+                    ChooserResult(CHOOSER_RESULT_SELECTED_COMPONENT, component, direct),
                 )
                 return intent
             }
@@ -173,7 +176,7 @@ private fun IntentSender.dispatchIntent(context: Context, intent: Intent) {
             /* code = */ Activity.RESULT_OK,
             /* intent = */ intent,
             /* onFinished = */ null,
-            /* handler = */ null
+            /* handler = */ null,
         )
     } catch (e: IntentSender.SendIntentException) {
         Log.e(TAG, "Failed to send intent to IntentSender", e)
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt b/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
index cb4bdcc1..8d6f8c05 100644
--- a/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
+++ b/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
@@ -39,20 +39,26 @@ import android.content.Intent.FLAG_ACTIVITY_NEW_DOCUMENT
 import android.content.IntentSender
 import android.net.Uri
 import android.os.Bundle
+import android.os.IBinder
 import android.service.chooser.ChooserAction
-import android.service.chooser.ChooserSession
 import android.service.chooser.ChooserTarget
+import android.service.chooser.Flags.interactiveChooser
+import android.service.chooser.IChooserControllerCallback
 import com.android.intentresolver.ChooserActivity
 import com.android.intentresolver.ContentTypeHint
-import com.android.intentresolver.Flags.interactiveSession
 import com.android.intentresolver.R
 import com.android.intentresolver.data.model.ChooserRequest
+import com.android.intentresolver.data.model.ColorScheme
 import com.android.intentresolver.ext.hasSendAction
 import com.android.intentresolver.ext.ifMatch
 import com.android.intentresolver.shared.model.ActivityModel
 import com.android.intentresolver.util.hasValidIcon
+import com.android.intentresolver.validation.IgnoredValue
+import com.android.intentresolver.validation.Importance
+import com.android.intentresolver.validation.Valid
 import com.android.intentresolver.validation.Validation
 import com.android.intentresolver.validation.ValidationResult
+import com.android.intentresolver.validation.Validator
 import com.android.intentresolver.validation.types.IntentOrUri
 import com.android.intentresolver.validation.types.array
 import com.android.intentresolver.validation.types.value
@@ -63,6 +69,12 @@ private const val MAX_INITIAL_INTENTS = 2
 private const val EXTRA_CHOOSER_INTERACTIVE_CALLBACK =
     "com.android.extra.EXTRA_CHOOSER_INTERACTIVE_CALLBACK"
 
+const val EXTRA_CHOOSER_COLOR_SCHEME = "com.android.extra.CHOOSER_COLOR_SCHEME"
+
+const val COLOR_SCHEME_SYSTEM_DEFAULT = 0
+const val COLOR_SCHEME_LIGHT = 1
+const val COLOR_SCHEME_DARK = 2
+
 internal fun Intent.maybeAddSendActionFlags() =
     ifMatch(Intent::hasSendAction) {
         addFlags(FLAG_ACTIVITY_NEW_DOCUMENT)
@@ -152,13 +164,43 @@ fun readChooserRequest(
         val metadataText = optional(value<CharSequence>(EXTRA_METADATA_TEXT))
 
         val interactiveSessionCallback =
-            if (interactiveSession()) {
-                optional(value<ChooserSession>(EXTRA_CHOOSER_INTERACTIVE_CALLBACK))
-                    ?.sessionCallbackBinder
+            if (interactiveChooser()) {
+                optional(value<IBinder>(EXTRA_CHOOSER_INTERACTIVE_CALLBACK))?.let {
+                    IChooserControllerCallback.Stub.asInterface(it)
+                }
             } else {
                 null
             }
 
+        val colorScheme =
+            if (interactiveChooser()) {
+                optional(
+                    object : Validator<ColorScheme> {
+                        override val key = EXTRA_CHOOSER_COLOR_SCHEME
+
+                        override fun validate(
+                            source: (String) -> Any?,
+                            importance: Importance,
+                        ): ValidationResult<ColorScheme> {
+                            val value = source(key) ?: return Valid(ColorScheme.SystemDefault)
+                            return when (value) {
+                                COLOR_SCHEME_LIGHT -> Valid(ColorScheme.Light)
+                                COLOR_SCHEME_DARK -> Valid(ColorScheme.Dark)
+                                COLOR_SCHEME_SYSTEM_DEFAULT -> Valid(ColorScheme.SystemDefault)
+                                else -> {
+                                    Valid(
+                                        ColorScheme.SystemDefault,
+                                        IgnoredValue(key, "Unexpected value $value"),
+                                    )
+                                }
+                            }
+                        }
+                    }
+                ) ?: ColorScheme.SystemDefault
+            } else {
+                ColorScheme.SystemDefault
+            }
+
         ChooserRequest(
             targetIntent = targetIntent,
             targetAction = targetIntent.action,
@@ -189,6 +231,7 @@ fun readChooserRequest(
             contentTypeHint = contentTypeHint,
             metadataText = metadataText,
             interactiveSessionCallback = interactiveSessionCallback,
+            colorScheme,
         )
     }
 }
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt b/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
index 7bc811c0..bc26f1ef 100644
--- a/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
+++ b/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
@@ -17,12 +17,11 @@ package com.android.intentresolver.ui.viewmodel
 
 import android.content.ContentInterface
 import android.os.Bundle
+import android.service.chooser.Flags.interactiveChooser
 import android.util.Log
 import androidx.lifecycle.SavedStateHandle
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
-import com.android.intentresolver.Flags.interactiveSession
-import com.android.intentresolver.Flags.saveShareouselState
 import com.android.intentresolver.contentpreview.ImageLoader
 import com.android.intentresolver.contentpreview.PreviewDataProvider
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.FetchPreviewsInteractor
@@ -110,19 +109,17 @@ constructor(
                 Log.w(TAG, "initialRequest is Invalid, initialization failed")
             }
             is Valid<ChooserRequest> -> {
-                if (saveShareouselState()) {
-                    val isRestored =
-                        savedStateHandle.get<Bundle>(CHOOSER_REQUEST_KEY)?.takeIf { !it.isEmpty } !=
-                            null
-                    savedStateHandle.setSavedStateProvider(CHOOSER_REQUEST_KEY) {
-                        Bundle().also { result ->
-                            request.value
-                                .takeIf { isRestored || it != initialRequest.value }
-                                ?.saveUpdates(result)
-                        }
+                val isRestored =
+                    savedStateHandle.get<Bundle>(CHOOSER_REQUEST_KEY)?.takeIf { !it.isEmpty } !=
+                        null
+                savedStateHandle.setSavedStateProvider(CHOOSER_REQUEST_KEY) {
+                    Bundle().also { result ->
+                        request.value
+                            .takeIf { isRestored || it != initialRequest.value }
+                            ?.saveUpdates(result)
                     }
                 }
-                if (interactiveSession()) {
+                if (interactiveChooser()) {
                     viewModelScope.launch(bgDispatcher) { interactiveSessionInteractor.activate() }
                 }
             }
diff --git a/java/src/com/android/intentresolver/util/IntentUtils.kt b/java/src/com/android/intentresolver/util/IntentUtils.kt
new file mode 100644
index 00000000..c20479c8
--- /dev/null
+++ b/java/src/com/android/intentresolver/util/IntentUtils.kt
@@ -0,0 +1,37 @@
+/*
+ * Copyright 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+@file:JvmName("IntentUtils")
+
+package com.android.intentresolver.util
+
+import android.content.Intent
+
+fun sanitizePayloadIntents(intents: List<Intent>): List<Intent> =
+    intents.map { intent ->
+        Intent(intent).also { sanitized ->
+            sanitized.setPackage(null)
+            sanitized.setComponent(null)
+            sanitized.selector?.let {
+                sanitized.setSelector(
+                    Intent(it).apply {
+                        setPackage(null)
+                        setComponent(null)
+                    }
+                )
+            }
+        }
+    }
diff --git a/java/src/com/android/intentresolver/widget/ChooserNestedScrollView.kt b/java/src/com/android/intentresolver/widget/ChooserNestedScrollView.kt
index a9577cf5..55a46ff1 100644
--- a/java/src/com/android/intentresolver/widget/ChooserNestedScrollView.kt
+++ b/java/src/com/android/intentresolver/widget/ChooserNestedScrollView.kt
@@ -25,7 +25,6 @@ import androidx.core.view.marginBottom
 import androidx.core.view.marginLeft
 import androidx.core.view.marginRight
 import androidx.core.view.marginTop
-import com.android.intentresolver.Flags.keyboardNavigationFix
 
 /**
  * A narrowly tailored [NestedScrollView] to be used inside [ResolverDrawerLayout] and help to
@@ -109,11 +108,7 @@ class ChooserNestedScrollView : NestedScrollView {
     }
 
     override fun onRequestChildFocus(child: View?, focused: View?) {
-        if (keyboardNavigationFix()) {
-            if (requestChildFocusPredicate(child, focused)) {
-                super.onRequestChildFocus(child, focused)
-            }
-        } else {
+        if (requestChildFocusPredicate(child, focused)) {
             super.onRequestChildFocus(child, focused)
         }
     }
diff --git a/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java b/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java
index 4895a2cd..50456e7c 100644
--- a/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java
+++ b/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java
@@ -137,13 +137,17 @@ public class ResolverDrawerLayout extends ViewGroup {
     @Nullable
     private final ScrollablePreviewFlingLogicDelegate mFlingLogicDelegate;
 
+    private static final CollapsibleHeightReservedDelegate
+            sDefaultCollapsibleHeightReservedDelegate =
+                    (drawer, l, t, r, b, offset) -> offset;
+
+    private CollapsibleHeightReservedDelegate mCollapsibleHeightReservedDelegate =
+            sDefaultCollapsibleHeightReservedDelegate;
+
     private final ViewTreeObserver.OnTouchModeChangeListener mTouchModeChangeListener =
-            new ViewTreeObserver.OnTouchModeChangeListener() {
-                @Override
-                public void onTouchModeChanged(boolean isInTouchMode) {
-                    if (!isInTouchMode && hasFocus() && isDescendantClipped(getFocusedChild())) {
-                        smoothScrollTo(0, 0);
-                    }
+            isInTouchMode -> {
+                if (!isInTouchMode && hasFocus() && isDescendantClipped(getFocusedChild())) {
+                    smoothScrollTo(0, 0);
                 }
             };
 
@@ -244,11 +248,25 @@ public class ResolverDrawerLayout extends ViewGroup {
         }
     }
 
+    /**
+     * Set collapsible height calculation delegate. The delegate will be invoked on layout pass
+     * and the returned value will be used as the collapsible height reserved value
+     * ({@link #setCollapsibleHeightReserved(int)}).
+     */
+    public void setCollapsibleHeightReservedDelegate(
+            @Nullable CollapsibleHeightReservedDelegate delegate) {
+        mCollapsibleHeightReservedDelegate = delegate == null
+                ? sDefaultCollapsibleHeightReservedDelegate
+                : delegate;
+    }
+
     public void setCollapsibleHeightReserved(int heightPixels) {
         final int oldReserved = mCollapsibleHeightReserved;
         mCollapsibleHeightReserved = heightPixels;
         if (oldReserved != mCollapsibleHeightReserved) {
-            requestLayout();
+            if (!isInLayout()) {
+                requestLayout();
+            }
         }
 
         final int dReserved = mCollapsibleHeightReserved - oldReserved;
@@ -261,7 +279,9 @@ public class ResolverDrawerLayout extends ViewGroup {
             return;
         }
 
-        invalidate();
+        if (!isInLayout()) {
+            invalidate();
+        }
     }
 
     /**
@@ -312,7 +332,11 @@ public class ResolverDrawerLayout extends ViewGroup {
             }
             final boolean isCollapsedNew = mCollapseOffset != 0;
             if (isCollapsedOld != isCollapsedNew) {
-                onCollapsedChanged(isCollapsedNew);
+                if (isInLayout()) {
+                    post(() -> onCollapsedChanged(isCollapsedNew));
+                } else {
+                    onCollapsedChanged(isCollapsedNew);
+                }
             }
         } else {
             // Start out collapsed at first unless we restored state for otherwise
@@ -324,7 +348,9 @@ public class ResolverDrawerLayout extends ViewGroup {
     private void setCollapseOffset(float collapseOffset) {
         if (mCollapseOffset != collapseOffset) {
             mCollapseOffset = collapseOffset;
-            requestLayout();
+            if (!isInLayout()) {
+                requestLayout();
+            }
         }
     }
 
@@ -1080,14 +1106,6 @@ public class ResolverDrawerLayout extends ViewGroup {
         }
 
         mHeightUsed = heightUsed;
-        int oldCollapsibleHeight = updateCollapsibleHeight();
-        updateCollapseOffset(oldCollapsibleHeight, !isDragging());
-
-        if (getShowAtTop()) {
-            mTopOffset = 0;
-        } else {
-            mTopOffset = Math.max(0, heightSize - mHeightUsed) + (int) mCollapseOffset;
-        }
 
         setMeasuredDimension(sourceWidth, heightSize);
     }
@@ -1107,6 +1125,25 @@ public class ResolverDrawerLayout extends ViewGroup {
 
     @Override
     protected void onLayout(boolean changed, int l, int t, int r, int b) {
+        onLayoutInternal();
+        int collapsibleHeightReserved = mCollapsibleHeightReservedDelegate.onLayout(
+                this, l, t, r, b, mCollapsibleHeightReserved);
+        if (collapsibleHeightReserved != mCollapsibleHeightReserved) {
+            setCollapsibleHeightReserved(collapsibleHeightReserved);
+            onLayoutInternal();
+        }
+    }
+
+    private void onLayoutInternal() {
+        int oldCollapsibleHeight = updateCollapsibleHeight();
+        updateCollapseOffset(oldCollapsibleHeight, !isDragging());
+
+        if (getShowAtTop()) {
+            mTopOffset = 0;
+        } else {
+            mTopOffset = Math.max(0, getMeasuredHeight() - mHeightUsed) + (int) mCollapseOffset;
+        }
+
         final int width = getWidth();
 
         View indicatorHost = null;
@@ -1325,6 +1362,17 @@ public class ResolverDrawerLayout extends ViewGroup {
         void onCollapsedChanged(boolean isCollapsed);
     }
 
+    /**
+     * A delegate for a synchronous offset calculation.
+     */
+    public interface CollapsibleHeightReservedDelegate {
+        /**
+         * A delegate for a synchronous offset calculation. This method will be called from the
+         * view's onLayout method and is expected to provide the drawer offset value.
+         */
+        int onLayout(ResolverDrawerLayout drawer, int l, int t, int r, int b, int offset);
+    }
+
     private class RunOnDismissedListener implements Runnable {
         @Override
         public void run() {
@@ -1339,10 +1387,6 @@ public class ResolverDrawerLayout extends ViewGroup {
         return mMetricsLogger;
     }
 
-    /**
-     * Controlled by
-     * {@link com.android.intentresolver.Flags#FLAG_SCROLLABLE_PREVIEW}
-     */
     private interface ScrollablePreviewFlingLogicDelegate {
         default boolean onNestedPreFling(
                 ResolverDrawerLayout drawer, View target, float velocityX, float velocityY) {
diff --git a/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt b/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt
index 935a8724..beece5c1 100644
--- a/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt
+++ b/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt
@@ -42,6 +42,7 @@ import androidx.recyclerview.widget.RecyclerView
 import com.android.intentresolver.R
 import com.android.intentresolver.util.throttle
 import com.android.intentresolver.widget.ImagePreviewView.TransitionElementStatusCallback
+import com.android.systemui.shared.Flags.usePreferredImageEditor
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.Job
@@ -225,6 +226,10 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
         maybeLoadAspectRatios()
     }
 
+    fun setImageEditorCallback(imageEditorCallback: Runnable) {
+        previewAdapter.setImageEditorCallback(imageEditorCallback)
+    }
+
     private fun maybeLoadAspectRatios() {
         if (isMeasured && isAttachedToWindow()) {
             batchLoader?.let { it.loadAspectRatios(getMaxWidth(), this::updatePreviewSize) }
@@ -305,6 +310,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
         private val editButtonRoleDescription: CharSequence?,
     ) : RecyclerView.Adapter<ViewHolder>() {
         private val previews = ArrayList<Preview>()
+        private var imageEditCallaback: Runnable? = null
         private val imagePreviewDescription =
             context.resources.getString(R.string.image_preview_a11y_description)
         private val videoPreviewDescription =
@@ -378,6 +384,11 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
             }
         }
 
+        fun setImageEditorCallback(callback: Runnable) {
+            imageEditCallaback = callback
+            notifyItemChanged(0)
+        }
+
         override fun onCreateViewHolder(parent: ViewGroup, itemType: Int): ViewHolder {
             val view = LayoutInflater.from(context).inflate(itemType, parent, false)
             return when (itemType) {
@@ -422,6 +433,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                             } else {
                                 null
                             },
+                        imageEditCallaback,
                     )
             }
         }
@@ -468,6 +480,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
             isSharedTransitionElement: Boolean,
             editButtonRoleDescription: CharSequence?,
             previewReadyCallback: ((String) -> Unit)?,
+            imageEditorCallback: Runnable?,
         ) {
             image.setImageDrawable(null)
             image.alpha = 1f
@@ -497,15 +510,34 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                     badgeFrame.visibility = View.VISIBLE
                 }
             }
-            preview.editAction?.also { onClick ->
+
+            if (usePreferredImageEditor()) {
                 editActionContainer?.apply {
-                    setOnClickListener { onClick.run() }
-                    visibility = View.VISIBLE
-                    if (editButtonRoleDescription != null) {
-                        ViewCompat.setAccessibilityDelegate(
-                            this,
-                            ViewRoleDescriptionAccessibilityDelegate(editButtonRoleDescription),
-                        )
+                    if (imageEditorCallback != null) {
+                        visibility = View.VISIBLE
+                        setOnClickListener { imageEditorCallback.run() }
+
+                        if (editButtonRoleDescription != null) {
+                            ViewCompat.setAccessibilityDelegate(
+                                this,
+                                ViewRoleDescriptionAccessibilityDelegate(editButtonRoleDescription),
+                            )
+                        }
+                    } else {
+                        visibility = View.GONE
+                    }
+                }
+            } else {
+                preview.editAction?.also { onClick ->
+                    editActionContainer?.apply {
+                        setOnClickListener { onClick.run() }
+                        visibility = View.VISIBLE
+                        if (editButtonRoleDescription != null) {
+                            ViewCompat.setAccessibilityDelegate(
+                                this,
+                                ViewRoleDescriptionAccessibilityDelegate(editButtonRoleDescription),
+                            )
+                        }
                     }
                 }
             }
diff --git a/tests/activity/src/com/android/intentresolver/ChooserActivityShareouselTest.kt b/tests/activity/src/com/android/intentresolver/ChooserActivityShareouselTest.kt
index cf1d8c60..7f84051b 100644
--- a/tests/activity/src/com/android/intentresolver/ChooserActivityShareouselTest.kt
+++ b/tests/activity/src/com/android/intentresolver/ChooserActivityShareouselTest.kt
@@ -63,8 +63,9 @@ import com.android.intentresolver.inject.PackageManagerModule
 import com.android.intentresolver.inject.ProfileParent
 import com.android.intentresolver.platform.AppPredictionAvailable
 import com.android.intentresolver.platform.AppPredictionModule
-import com.android.intentresolver.platform.ImageEditor
+import com.android.intentresolver.platform.FallbackImageEditor
 import com.android.intentresolver.platform.ImageEditorModule
+import com.android.intentresolver.platform.PreferredImageEditor
 import com.android.intentresolver.shared.model.User
 import com.android.intentresolver.tests.R
 import com.android.internal.config.sysui.SystemUiDeviceConfigFlags
@@ -132,7 +133,7 @@ class ChooserActivityShareouselTest() {
 
     @BindValue val imageLoader: ImageLoader = fakeImageLoader
     @BindValue
-    @ImageEditor
+    @FallbackImageEditor
     val imageEditor: Optional<ComponentName> =
         Optional.ofNullable(
             ComponentName.unflattenFromString(
@@ -140,6 +141,10 @@ class ChooserActivityShareouselTest() {
             )
         )
 
+    @BindValue
+    @PreferredImageEditor
+    val preferredImageEditor: Optional<ComponentName> = Optional.ofNullable(null)
+
     @BindValue @ApplicationUser val applicationUser = PERSONAL_USER_HANDLE
 
     @BindValue @ProfileParent val profileParent = PERSONAL_USER_HANDLE
diff --git a/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java b/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java
index 6f80c8f6..700f0efa 100644
--- a/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java
+++ b/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java
@@ -135,9 +135,10 @@ import com.android.intentresolver.logging.EventLog;
 import com.android.intentresolver.logging.FakeEventLog;
 import com.android.intentresolver.platform.AppPredictionAvailable;
 import com.android.intentresolver.platform.AppPredictionModule;
+import com.android.intentresolver.platform.FallbackImageEditor;
 import com.android.intentresolver.platform.GlobalSettings;
-import com.android.intentresolver.platform.ImageEditor;
 import com.android.intentresolver.platform.ImageEditorModule;
+import com.android.intentresolver.platform.PreferredImageEditor;
 import com.android.intentresolver.shared.model.User;
 import com.android.intentresolver.shortcuts.ShortcutLoader;
 import com.android.internal.config.sysui.SystemUiDeviceConfigFlags;
@@ -246,11 +247,15 @@ public class ChooserActivityTest {
 
     /** An arbitrary pre-installed activity that handles this type of intent. */
     @BindValue
-    @ImageEditor
+    @FallbackImageEditor
     final Optional<ComponentName> mImageEditor = Optional.ofNullable(
             ComponentName.unflattenFromString("com.google.android.apps.messaging/"
                     + ".ui.conversationlist.ShareIntentActivity"));
 
+    @BindValue
+    @PreferredImageEditor
+    final Optional<ComponentName> mPreferredImageEditor = Optional.ofNullable(null);
+
     /** Whether an AppPredictionService is available for use. */
     @BindValue
     @AppPredictionAvailable
diff --git a/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java b/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java
index 169c44b0..0f070a22 100644
--- a/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java
+++ b/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java
@@ -174,9 +174,9 @@ public class ResolverWrapperActivity extends ResolverActivity {
         @Nullable
         public Drawable getOrLoadAppTargetIcon(
                 @NonNull DisplayResolveInfo info,
-                @NonNull UserHandle userHandle,
+                @NonNull UserHandle defaultUserHandle,
                 @NonNull Consumer<Drawable> callback) {
-            return mTargetDataLoader.getOrLoadAppTargetIcon(info, userHandle, callback);
+            return mTargetDataLoader.getOrLoadAppTargetIcon(info, defaultUserHandle, callback);
         }
 
         @Override
diff --git a/tests/unit/src/com/android/intentresolver/actions/ImageEditorActionFactoryTest.kt b/tests/unit/src/com/android/intentresolver/actions/ImageEditorActionFactoryTest.kt
new file mode 100644
index 00000000..66aa6d34
--- /dev/null
+++ b/tests/unit/src/com/android/intentresolver/actions/ImageEditorActionFactoryTest.kt
@@ -0,0 +1,142 @@
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
+ * limitations under the License.
+ */
+
+package com.android.intentresolver.actions
+
+import android.content.ComponentName
+import android.content.ContentResolver
+import android.content.Intent
+import android.content.pm.ActivityInfo
+import android.content.pm.ApplicationInfo
+import android.content.pm.PackageManager
+import android.content.pm.ResolveInfo
+import androidx.test.platform.app.InstrumentationRegistry
+import com.google.common.truth.Truth.assertThat
+import java.util.Optional
+import kotlinx.coroutines.test.TestCoroutineScheduler
+import kotlinx.coroutines.test.UnconfinedTestDispatcher
+import kotlinx.coroutines.test.runTest
+import org.junit.Test
+import org.mockito.ArgumentMatchers.anyInt
+import org.mockito.kotlin.argForWhich
+import org.mockito.kotlin.doReturn
+import org.mockito.kotlin.mock
+
+class ImageEditorActionFactoryTest {
+    val scheduler = TestCoroutineScheduler()
+    val testDispatcher = UnconfinedTestDispatcher(scheduler)
+    val preferredEditorComponent = ComponentName("preferred.package", "preferred.class")
+    val fallbackEditorComponent = ComponentName("fallback.pkg", "fallback.cls")
+
+    val contentResolver: ContentResolver = mock()
+
+    fun createPackageManager(
+        hasPreferredEditor: Boolean,
+        hasFallbackEditor: Boolean,
+    ): PackageManager = mock {
+        if (hasPreferredEditor) {
+            on {
+                    resolveActivity(
+                        argForWhich { preferredEditorComponent.equals(component) },
+                        anyInt(),
+                    )
+                }
+                .doReturn(resolveInfoForComponent(preferredEditorComponent))
+        }
+        if (hasFallbackEditor) {
+            on {
+                    resolveActivity(
+                        argForWhich { fallbackEditorComponent.equals(component) },
+                        anyInt(),
+                    )
+                }
+                .doReturn(resolveInfoForComponent(fallbackEditorComponent))
+        }
+    }
+
+    fun resolveInfoForComponent(component: ComponentName): ResolveInfo =
+        ResolveInfo().apply {
+            activityInfo =
+                ActivityInfo().apply {
+                    name = component.className
+                    applicationInfo =
+                        ApplicationInfo().apply { packageName = component.packageName }
+                }
+        }
+
+    fun createFactory(
+        hasPreferredEditor: Boolean = true,
+        hasFallbackEditor: Boolean = true,
+        preferredEditor: ComponentName? = preferredEditorComponent,
+        fallbackEditor: ComponentName? = fallbackEditorComponent,
+    ) =
+        ImageEditorActionFactory(
+            InstrumentationRegistry.getInstrumentation().getContext(),
+            testDispatcher,
+            Optional.ofNullable(preferredEditor),
+            Optional.ofNullable(fallbackEditor),
+            createPackageManager(hasPreferredEditor, hasFallbackEditor),
+            contentResolver,
+        )
+
+    @Test
+    fun test_getImageEditorTargetInfo() = runTest {
+        val target = createFactory().getImageEditorTargetInfo(Intent(Intent.ACTION_SEND))
+        assertThat(target).isNotNull()
+        assertThat(target?.resolvedIntent?.component).isEqualTo(preferredEditorComponent)
+        assertThat(target?.resolvedIntent?.action).isEqualTo(Intent.ACTION_EDIT)
+    }
+
+    @Test
+    fun test_getImageEditorTargetInfo_preferredNotProvided() = runTest {
+        val target =
+            createFactory(preferredEditor = null)
+                .getImageEditorTargetInfo(Intent(Intent.ACTION_SEND))
+        assertThat(target).isNotNull()
+        assertThat(target?.resolvedIntent?.component).isEqualTo(fallbackEditorComponent)
+        assertThat(target?.resolvedIntent?.action).isEqualTo(Intent.ACTION_EDIT)
+    }
+
+    @Test
+    fun test_getImageEditorTargetInfo_noComponentProvided() = runTest {
+        val target =
+            createFactory(preferredEditor = null, fallbackEditor = null)
+                .getImageEditorTargetInfo(Intent(Intent.ACTION_SEND))
+        assertThat(target).isNull()
+    }
+
+    @Test
+    fun test_getImageEditorTargetInfo_nonSendAction() = runTest {
+        val target = createFactory().getImageEditorTargetInfo(Intent(Intent.ACTION_VIEW))
+        assertThat(target).isNull()
+    }
+
+    @Test
+    fun test_getImageEditorTargetInfo_preferredNotAvailable() = runTest {
+        val target =
+            createFactory(hasPreferredEditor = false)
+                .getImageEditorTargetInfo(Intent(Intent.ACTION_SEND))
+        assertThat(target?.resolvedIntent?.component).isEqualTo(fallbackEditorComponent)
+    }
+
+    @Test
+    fun test_getImageEditorTargetInfo_bothNotAvailable() = runTest {
+        val target =
+            createFactory(hasPreferredEditor = false, hasFallbackEditor = false)
+                .getImageEditorTargetInfo(Intent(Intent.ACTION_SEND))
+        assertThat(target).isNull()
+    }
+}
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt
index 9884a675..f5c8fb3d 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt
@@ -21,13 +21,9 @@ import android.content.Intent
 import android.database.MatrixCursor
 import android.media.MediaMetadata
 import android.net.Uri
-import android.platform.test.annotations.EnableFlags
-import android.platform.test.flag.junit.FlagsParameterization
-import android.platform.test.flag.junit.SetFlagsRule
 import android.provider.DocumentsContract
 import android.provider.Downloads
 import android.provider.OpenableColumns
-import com.android.intentresolver.Flags.FLAG_INDIVIDUAL_METADATA_TITLE_READ
 import com.google.common.truth.Truth.assertThat
 import kotlin.coroutines.EmptyCoroutineContext
 import kotlinx.coroutines.CoroutineScope
@@ -36,10 +32,7 @@ import kotlinx.coroutines.flow.toList
 import kotlinx.coroutines.test.TestScope
 import kotlinx.coroutines.test.UnconfinedTestDispatcher
 import kotlinx.coroutines.test.runTest
-import org.junit.Rule
 import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.Parameterized
 import org.mockito.kotlin.any
 import org.mockito.kotlin.anyOrNull
 import org.mockito.kotlin.eq
@@ -49,13 +42,11 @@ import org.mockito.kotlin.times
 import org.mockito.kotlin.verify
 import org.mockito.kotlin.whenever
 
-@RunWith(Parameterized::class)
 @OptIn(ExperimentalCoroutinesApi::class)
-class PreviewDataProviderTest(flags: FlagsParameterization) {
+class PreviewDataProviderTest() {
     private val contentResolver = mock<ContentInterface>()
     private val mimeTypeClassifier = DefaultMimeTypeClassifier
     private val testScope = TestScope(EmptyCoroutineContext + UnconfinedTestDispatcher())
-    @get:Rule val setFlagsRule = SetFlagsRule(flags)
 
     private fun createDataProvider(
         targetIntent: Intent,
@@ -207,7 +198,6 @@ class PreviewDataProviderTest(flags: FlagsParameterization) {
         }
 
     @Test
-    @EnableFlags(FLAG_INDIVIDUAL_METADATA_TITLE_READ)
     fun test_sendSingleImageWithFailingGetTypeDisjointTitleRead_resolvesToFilePreviewUi() =
         testScope.runTest {
             val uri = Uri.parse("content://org.pkg.app/image.png")
@@ -255,7 +245,6 @@ class PreviewDataProviderTest(flags: FlagsParameterization) {
         }
 
     @Test
-    @EnableFlags(FLAG_INDIVIDUAL_METADATA_TITLE_READ)
     fun test_sendSingleFileWithFailingImageMetadataIndividualTitleRead_resolvesToFilePreviewUi() =
         testScope.runTest {
             val uri = Uri.parse("content://org.pkg.app/image.png")
@@ -539,13 +528,6 @@ class PreviewDataProviderTest(flags: FlagsParameterization) {
         assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_TEXT)
         verify(contentResolver, never()).getType(any())
     }
-
-    companion object {
-        @JvmStatic
-        @Parameterized.Parameters(name = "{0}")
-        fun parameters(): List<FlagsParameterization> =
-            FlagsParameterization.allCombinationsOf(FLAG_INDIVIDUAL_METADATA_TITLE_READ)
-    }
 }
 
 private fun ContentInterface.setDisplayName(uri: Uri, displayName: String) =
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt
index c24138b8..5e33f5ef 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt
@@ -18,10 +18,7 @@ package com.android.intentresolver.contentpreview.payloadtoggle.domain.interacto
 
 import android.content.Intent
 import android.net.Uri
-import android.platform.test.annotations.DisableFlags
-import android.platform.test.annotations.EnableFlags
 import android.platform.test.flag.junit.SetFlagsRule
-import com.android.intentresolver.Flags
 import com.android.intentresolver.contentpreview.mimetypeClassifier
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.previewSelectionsRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewKey
@@ -36,35 +33,6 @@ class SelectionInteractorTest {
     @get:Rule val flagsRule = SetFlagsRule()
 
     @Test
-    @DisableFlags(Flags.FLAG_UNSELECT_FINAL_ITEM)
-    fun singleSelection_removalPrevented() = runKosmosTest {
-        val initialPreview =
-            PreviewModel(
-                key = PreviewKey.final(1),
-                uri = Uri.fromParts("scheme", "ssp", "fragment"),
-                mimeType = null,
-                order = 0,
-            )
-        previewSelectionsRepository.selections.value = mapOf(initialPreview.uri to initialPreview)
-
-        val underTest =
-            SelectionInteractor(
-                previewSelectionsRepository,
-                { Intent() },
-                updateTargetIntentInteractor,
-                mimetypeClassifier,
-            )
-
-        assertThat(underTest.selections.first()).containsExactly(initialPreview.uri)
-
-        // Shouldn't do anything!
-        underTest.unselect(initialPreview)
-
-        assertThat(underTest.selections.first()).containsExactly(initialPreview.uri)
-    }
-
-    @Test
-    @EnableFlags(Flags.FLAG_UNSELECT_FINAL_ITEM)
     fun singleSelection_itemRemovedNoPendingIntentUpdates() = runKosmosTest {
         val initialPreview =
             PreviewModel(
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractorTest.kt
index 32d040fe..e734aec7 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractorTest.kt
@@ -20,9 +20,7 @@ package com.android.intentresolver.contentpreview.payloadtoggle.domain.interacto
 
 import android.content.ComponentName
 import android.content.Intent
-import android.platform.test.annotations.EnableFlags
 import android.platform.test.flag.junit.SetFlagsRule
-import com.android.intentresolver.Flags.FLAG_SHAREOUSEL_UPDATE_EXCLUDE_COMPONENTS_EXTRA
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.pendingSelectionCallbackRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ShareouselUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
@@ -54,7 +52,6 @@ class UpdateChooserRequestInteractorTest {
     }
 
     @Test
-    @EnableFlags(FLAG_SHAREOUSEL_UPDATE_EXCLUDE_COMPONENTS_EXTRA)
     fun testSelectionResultWithExcludedComponents_chooserRequestIsUpdated() = runKosmosTest {
         val excludedComponent = ComponentName("org.pkg.app", "Class")
         val selectionCallbackResult =
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackImplTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackImplTest.kt
index c1a1833a..8f92c2ae 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackImplTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/SelectionChangeCallbackImplTest.kt
@@ -36,14 +36,12 @@ import android.content.Intent.EXTRA_STREAM
 import android.graphics.drawable.Icon
 import android.net.Uri
 import android.os.Bundle
-import android.platform.test.annotations.EnableFlags
 import android.platform.test.flag.junit.SetFlagsRule
 import android.service.chooser.AdditionalContentContract.MethodNames.ON_SELECTION_CHANGED
 import android.service.chooser.ChooserAction
 import android.service.chooser.ChooserTarget
 import androidx.test.ext.junit.runners.AndroidJUnit4
 import androidx.test.platform.app.InstrumentationRegistry
-import com.android.intentresolver.Flags.FLAG_SHAREOUSEL_UPDATE_EXCLUDE_COMPONENTS_EXTRA
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate.Absent
 import com.google.common.truth.Correspondence
@@ -98,7 +96,7 @@ class SelectionChangeCallbackImplTest {
                 authorityCaptor.capture(),
                 methodCaptor.capture(),
                 argCaptor.capture(),
-                extraCaptor.capture()
+                extraCaptor.capture(),
             )
         assertWithMessage("Wrong additional content provider authority")
             .that(authorityCaptor.firstValue)
@@ -147,8 +145,8 @@ class SelectionChangeCallbackImplTest {
                         context,
                         1,
                         Intent("test"),
-                        PendingIntent.FLAG_IMMUTABLE
-                    )
+                        PendingIntent.FLAG_IMMUTABLE,
+                    ),
                 )
                 .build()
         val a2 =
@@ -159,8 +157,8 @@ class SelectionChangeCallbackImplTest {
                         context,
                         1,
                         Intent("test"),
-                        PendingIntent.FLAG_IMMUTABLE
-                    )
+                        PendingIntent.FLAG_IMMUTABLE,
+                    ),
                 )
                 .build()
         whenever(contentResolver.call(any<String>(), any(), any(), any()))
@@ -198,8 +196,8 @@ class SelectionChangeCallbackImplTest {
                         context,
                         1,
                         Intent("test"),
-                        PendingIntent.FLAG_IMMUTABLE
-                    )
+                        PendingIntent.FLAG_IMMUTABLE,
+                    ),
                 )
                 .build()
         whenever(contentResolver.call(any<String>(), any(), any(), any()))
@@ -279,7 +277,7 @@ class SelectionChangeCallbackImplTest {
                 Icon.createWithContentUri(createUri(1)),
                 0.99f,
                 ComponentName("org.pkg.app", ".ClassA"),
-                null
+                null,
             )
         val t2 =
             ChooserTarget(
@@ -287,7 +285,7 @@ class SelectionChangeCallbackImplTest {
                 Icon.createWithContentUri(createUri(1)),
                 1f,
                 ComponentName("org.pkg.app", ".ClassB"),
-                null
+                null,
             )
         whenever(contentResolver.call(any<String>(), any(), any(), any()))
             .thenReturn(
@@ -310,7 +308,7 @@ class SelectionChangeCallbackImplTest {
                             expected.icon == actual?.icon &&
                             expected.score == actual?.score
                     },
-                    ""
+                    "",
                 )
             )
             .containsExactly(t1, t2)
@@ -404,7 +402,6 @@ class SelectionChangeCallbackImplTest {
     }
 
     @Test
-    @EnableFlags(FLAG_SHAREOUSEL_UPDATE_EXCLUDE_COMPONENTS_EXTRA)
     fun testPayloadChangeCallbackUpdatesExcludedComponents_valueUpdated() = runTest {
         val excludedComponent = ComponentName("org.pkg.app", "org.pkg.app.TheClass")
         whenever(contentResolver.call(any<String>(), any(), any(), any()))
diff --git a/tests/unit/src/com/android/intentresolver/icons/CachingTargetDataLoaderTest.kt b/tests/unit/src/com/android/intentresolver/icons/CachingTargetDataLoaderTest.kt
index 2f0ed423..3a5d54a6 100644
--- a/tests/unit/src/com/android/intentresolver/icons/CachingTargetDataLoaderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/icons/CachingTargetDataLoaderTest.kt
@@ -27,11 +27,17 @@ import android.graphics.drawable.ColorDrawable
 import android.graphics.drawable.Drawable
 import android.graphics.drawable.Icon
 import android.os.UserHandle
+import android.platform.test.annotations.DisableFlags
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
+import com.android.intentresolver.Flags.FLAG_USE_RESOLVE_INFO_USER_HANDLE
 import com.android.intentresolver.ResolverDataProvider.createResolveInfo
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.chooser.SelectableTargetInfo
 import com.android.intentresolver.chooser.TargetInfo
+import com.android.launcher3.icons.FastBitmapDrawable
 import java.util.function.Consumer
+import org.junit.Rule
 import org.junit.Test
 import org.mockito.kotlin.any
 import org.mockito.kotlin.doAnswer
@@ -42,6 +48,7 @@ import org.mockito.kotlin.verify
 import org.mockito.kotlin.whenever
 
 class CachingTargetDataLoaderTest {
+    @get:Rule val flagRule = SetFlagsRule()
     private val context = mock<Context>()
     private val userHandle = UserHandle.of(1)
 
@@ -153,7 +160,7 @@ class CachingTargetDataLoaderTest {
                     if (target === bitmapTargetInfo) {
                         BitmapDrawable(createBitmap())
                     } else if (target === hoverBitmapTargetInfo) {
-                        HoverBitmapDrawable(createBitmap())
+                        FastBitmapDrawable(createBitmap())
                     } else {
                         ColorDrawable(Color.RED)
                     }
@@ -182,6 +189,80 @@ class CachingTargetDataLoaderTest {
             1 * { getOrLoadAppTargetIcon(eq(hoverBitmapTargetInfo), eq(userHandle), any()) }
         }
     }
+
+    @Test
+    @EnableFlags(FLAG_USE_RESOLVE_INFO_USER_HANDLE)
+    fun testResolveInfoUserHandleIsUsed() {
+        val context =
+            mock<Context> {
+                on { userId } doReturn 1
+                on { packageName } doReturn "package"
+            }
+        val resolveInfoUserHandle = UserHandle.of(0)
+        val otherUserHandle = UserHandle.of(10)
+        val targetInfo =
+            DisplayResolveInfo.newDisplayResolveInfo(
+                Intent(),
+                createResolveInfo(2, userHandle.identifier).apply {
+                    userHandle = resolveInfoUserHandle
+                },
+                Intent(),
+            ) as DisplayResolveInfo
+
+        val targetDataLoader = mock<TargetDataLoader>()
+        doAnswer {
+                val callback = it.arguments[2] as Consumer<Drawable>
+                callback.accept(BitmapDrawable(createBitmap()))
+                null
+            }
+            .whenever(targetDataLoader)
+            .getOrLoadAppTargetIcon(any(), any(), any())
+        val testSubject = CachingTargetDataLoader(context, targetDataLoader)
+        val callback = Consumer<Drawable> {}
+
+        testSubject.getOrLoadAppTargetIcon(targetInfo, otherUserHandle, callback)
+
+        verify(targetDataLoader) {
+            1 * { getOrLoadAppTargetIcon(eq(targetInfo), eq(resolveInfoUserHandle), any()) }
+        }
+    }
+
+    @Test
+    @DisableFlags(FLAG_USE_RESOLVE_INFO_USER_HANDLE)
+    fun testResolveInfoUserHandleIsIgnored() {
+        val context =
+            mock<Context> {
+                on { userId } doReturn 1
+                on { packageName } doReturn "package"
+            }
+        val resolveInfoUserHandle = UserHandle.of(0)
+        val otherUserHandle = UserHandle.of(10)
+        val targetInfo =
+            DisplayResolveInfo.newDisplayResolveInfo(
+                Intent(),
+                createResolveInfo(2, userHandle.identifier).apply {
+                    userHandle = resolveInfoUserHandle
+                },
+                Intent(),
+            ) as DisplayResolveInfo
+
+        val targetDataLoader = mock<TargetDataLoader>()
+        doAnswer {
+                val callback = it.arguments[2] as Consumer<Drawable>
+                callback.accept(BitmapDrawable(createBitmap()))
+                null
+            }
+            .whenever(targetDataLoader)
+            .getOrLoadAppTargetIcon(any(), any(), any())
+        val testSubject = CachingTargetDataLoader(context, targetDataLoader)
+        val callback = Consumer<Drawable> {}
+
+        testSubject.getOrLoadAppTargetIcon(targetInfo, otherUserHandle, callback)
+
+        verify(targetDataLoader) {
+            1 * { getOrLoadAppTargetIcon(eq(targetInfo), eq(otherUserHandle), any()) }
+        }
+    }
 }
 
 private fun createBitmap() = Bitmap.createBitmap(100, 100, Bitmap.Config.ARGB_8888)
diff --git a/tests/unit/src/com/android/intentresolver/icons/DefaultTargetDataLoaderTest.kt b/tests/unit/src/com/android/intentresolver/icons/DefaultTargetDataLoaderTest.kt
new file mode 100644
index 00000000..ec3bb5f5
--- /dev/null
+++ b/tests/unit/src/com/android/intentresolver/icons/DefaultTargetDataLoaderTest.kt
@@ -0,0 +1,143 @@
+/*
+ * Copyright 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.intentresolver.icons
+
+import android.content.ComponentName
+import android.content.Context
+import android.content.pm.ActivityInfo
+import android.content.pm.PackageManager
+import android.graphics.Bitmap
+import android.graphics.drawable.BitmapDrawable
+import android.graphics.drawable.Drawable
+import android.os.UserHandle
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.testing.TestLifecycleOwner
+import androidx.test.filters.SmallTest
+import com.android.intentresolver.Flags
+import com.android.intentresolver.ResolverDataProvider
+import com.android.intentresolver.SimpleIconFactory
+import com.android.intentresolver.TargetPresentationGetter
+import com.android.intentresolver.chooser.SelectableTargetInfo
+import com.android.intentresolver.createChooserTarget
+import com.android.intentresolver.createShortcutInfo
+import com.google.common.truth.Truth
+import java.util.concurrent.atomic.AtomicReference
+import javax.inject.Provider
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.test.UnconfinedTestDispatcher
+import kotlinx.coroutines.test.resetMain
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.test.setMain
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.mockito.ArgumentMatchers.anyInt
+import org.mockito.kotlin.any
+import org.mockito.kotlin.anyOrNull
+import org.mockito.kotlin.doReturn
+import org.mockito.kotlin.eq
+import org.mockito.kotlin.mock
+import org.mockito.kotlin.verify
+
+@OptIn(ExperimentalCoroutinesApi::class)
+@SmallTest
+class DefaultTargetDataLoaderTest {
+    @get:Rule val flagRule = SetFlagsRule()
+    val testDispatcher = UnconfinedTestDispatcher()
+    private val appIcon = Bitmap.createBitmap(100, 100, Bitmap.Config.ARGB_8888)
+    private val badgedBitmap = Bitmap.createBitmap(100, 100, Bitmap.Config.ARGB_8888)
+    private val placeholderDrawable =
+        BitmapDrawable(Bitmap.createBitmap(100, 100, Bitmap.Config.ARGB_8888))
+    private val activityInfo = ActivityInfo()
+    private val pm =
+        mock<PackageManager> {
+            on { getActivityInfo(any<ComponentName>(), anyInt()) } doReturn activityInfo
+        }
+    private val userContext =
+        mock<Context> {
+            on { getSystemService(any<String>()) } doReturn null
+            on { packageManager } doReturn pm
+        }
+    private val context =
+        mock<Context> { on { createContextAsUser(any(), any()) } doReturn userContext }
+    private val presentationGetter =
+        mock<TargetPresentationGetter> { on { getIconBitmap(anyOrNull()) } doReturn appIcon }
+    private val presentationFactory =
+        mock<TargetPresentationGetter.Factory> {
+            on { makePresentationGetter(any<ActivityInfo>()) } doReturn presentationGetter
+        }
+    private val iconFactory =
+        mock<SimpleIconFactory> {
+            on { createAppBadgedIconBitmap(any<Drawable>(), eq(appIcon)) } doReturn badgedBitmap
+        }
+    private val lifecycleOwner = TestLifecycleOwner()
+
+    @Before
+    fun setup() {
+        Dispatchers.setMain(testDispatcher)
+    }
+
+    @After
+    fun cleanup() {
+        Dispatchers.resetMain()
+    }
+
+    @EnableFlags(Flags.FLAG_BADGE_SHORTCUT_ICON_PLACEHOLDERS)
+    @Test
+    fun test_ShortcutIconFailedToLoad_placeholderIsBadged() = runTest {
+        lifecycleOwner.currentState = Lifecycle.State.RESUMED
+        val testSubject =
+            DefaultTargetDataLoader(
+                context,
+                lifecycleOwner.lifecycle,
+                Provider { iconFactory },
+                presentationFactory,
+                testDispatcher,
+                { placeholderDrawable },
+                false,
+            )
+        val chooserTarget =
+            createChooserTarget(
+                "title",
+                0.3f,
+                ResolverDataProvider.createComponentName(1),
+                "test_shortcut_id",
+            )
+        val shortcutInfo = createShortcutInfo("id", ResolverDataProvider.createComponentName(2), 3)
+        val targetInfo =
+            SelectableTargetInfo.newSelectableTargetInfo(
+                null,
+                null,
+                mock(),
+                chooserTarget,
+                0.1f,
+                shortcutInfo,
+                null,
+                mock(),
+            ) as SelectableTargetInfo
+
+        val resultRef = AtomicReference<Drawable?>()
+        testSubject.getOrLoadDirectShareIcon(targetInfo, UserHandle.of(10)) { resultRef.set(it) }
+
+        Truth.assertThat(resultRef.get()).isNotNull()
+        verify(iconFactory) { 1 * { createAppBadgedIconBitmap(any<Drawable>(), eq(appIcon)) } }
+    }
+}
diff --git a/tests/unit/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractorTest.kt b/tests/unit/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractorTest.kt
index 75d4ec0d..8712ed1b 100644
--- a/tests/unit/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractorTest.kt
@@ -30,6 +30,7 @@ import android.content.Intent.EXTRA_EXCLUDE_COMPONENTS
 import android.content.Intent.EXTRA_INITIAL_INTENTS
 import android.content.Intent.EXTRA_REPLACEMENT_EXTRAS
 import android.content.IntentSender
+import android.graphics.Rect
 import android.os.Binder
 import android.os.IBinder
 import android.os.IBinder.DeathRecipient
@@ -38,10 +39,10 @@ import android.os.Parcel
 import android.os.ResultReceiver
 import android.os.ShellCallback
 import android.service.chooser.ChooserTarget
+import android.service.chooser.IChooserController
+import android.service.chooser.IChooserControllerCallback
 import androidx.core.os.bundleOf
 import androidx.lifecycle.SavedStateHandle
-import com.android.intentresolver.IChooserController
-import com.android.intentresolver.IChooserInteractiveSessionCallback
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.PendingSelectionCallbackRepository
 import com.android.intentresolver.data.model.ChooserRequest
 import com.android.intentresolver.data.repository.ActivityModelRepository
@@ -51,6 +52,7 @@ import com.android.intentresolver.shared.model.ActivityModel
 import com.google.common.truth.Correspondence
 import com.google.common.truth.Truth.assertThat
 import java.io.FileDescriptor
+import java.util.concurrent.atomic.AtomicInteger
 import kotlinx.coroutines.launch
 import kotlinx.coroutines.test.runTest
 import org.junit.Test
@@ -68,7 +70,7 @@ class InteractiveSessionInteractorTest {
                 )
             }
         }
-    private val interactiveSessionCallback = FakeChooserInteractiveSessionCallback()
+    private val interactiveSessionCallback = FakeChooserControllerCallback()
     private val pendingSelectionCallbackRepo = PendingSelectionCallbackRepository()
     private val savedStateHandle = SavedStateHandle()
     private val interactiveCallbackRepo = InteractiveSessionCallbackRepository(savedStateHandle)
@@ -107,7 +109,7 @@ class InteractiveSessionInteractorTest {
 
         testSubject.activate()
 
-        assertThat(interactiveSessionCallback.registeredIntentUpdaters).containsExactly(null)
+        assertThat(interactiveSessionCallback.registeredChooserController).containsExactly(null)
     }
 
     @Test
@@ -223,12 +225,12 @@ class InteractiveSessionInteractorTest {
         backgroundScope.launch { testSubject.activate() }
         testScheduler.runCurrent()
 
-        assertThat(interactiveSessionCallback.registeredIntentUpdaters).hasSize(1)
+        assertThat(interactiveSessionCallback.registeredChooserController).hasSize(1)
 
         testSubject.endSession()
 
-        assertThat(interactiveSessionCallback.registeredIntentUpdaters).hasSize(2)
-        assertThat(interactiveSessionCallback.registeredIntentUpdaters[1]).isNull()
+        assertThat(interactiveSessionCallback.registeredChooserController).hasSize(1)
+        assertThat(interactiveSessionCallback.onClosedInvocationCounter.get()).isEqualTo(1)
     }
 
     @Test
@@ -254,8 +256,8 @@ class InteractiveSessionInteractorTest {
         backgroundScope.launch { testSubject.activate() }
         testScheduler.runCurrent()
 
-        assertThat(interactiveSessionCallback.registeredIntentUpdaters).hasSize(1)
-        interactiveSessionCallback.registeredIntentUpdaters[0]!!.updateIntent(null)
+        assertThat(interactiveSessionCallback.registeredChooserController).hasSize(1)
+        interactiveSessionCallback.registeredChooserController[0]!!.updateIntent(null)
         testScheduler.runCurrent()
 
         assertThat(testSubject.isSessionActive.value).isFalse()
@@ -284,8 +286,8 @@ class InteractiveSessionInteractorTest {
         backgroundScope.launch { testSubject.activate() }
         testScheduler.runCurrent()
 
-        assertThat(interactiveSessionCallback.registeredIntentUpdaters).hasSize(1)
-        interactiveSessionCallback.registeredIntentUpdaters[0]!!.updateIntent(Intent())
+        assertThat(interactiveSessionCallback.registeredChooserController).hasSize(1)
+        interactiveSessionCallback.registeredChooserController[0]!!.updateIntent(Intent())
         testScheduler.runCurrent()
 
         assertThat(testSubject.isSessionActive.value).isTrue()
@@ -316,7 +318,7 @@ class InteractiveSessionInteractorTest {
         backgroundScope.launch { testSubject.activate() }
         testScheduler.runCurrent()
 
-        assertThat(interactiveSessionCallback.registeredIntentUpdaters).hasSize(1)
+        assertThat(interactiveSessionCallback.registeredChooserController).hasSize(1)
         val newTargetIntent = Intent(ACTION_VIEW).apply { type = "image/png" }
         val newFilteredComponents = arrayOf(ComponentName.unflattenFromString("com.app/.MainA"))
         val newCallerTargets =
@@ -334,7 +336,7 @@ class InteractiveSessionInteractorTest {
         val newInitialIntents = arrayOf(Intent(ACTION_QUICK_VIEW))
         val newResultSender = IntentSender(Binder())
         val newRefinementSender = IntentSender(Binder())
-        interactiveSessionCallback.registeredIntentUpdaters[0]!!.updateIntent(
+        interactiveSessionCallback.registeredChooserController[0]!!.updateIntent(
             Intent.createChooser(newTargetIntent, "").apply {
                 putExtra(EXTRA_EXCLUDE_COMPONENTS, newFilteredComponents)
                 putExtra(EXTRA_CHOOSER_TARGETS, newCallerTargets)
@@ -368,20 +370,61 @@ class InteractiveSessionInteractorTest {
         assertThat(updatedRequest.chosenComponentSender).isEqualTo(newResultSender)
         assertThat(updatedRequest.refinementIntentSender).isEqualTo(newRefinementSender)
     }
+
+    @Test
+    fun targetEnableStateReceived_isTargetEnabledUpdated() = runTest {
+        val chooserRequestRepository =
+            ChooserRequestRepository(
+                initialRequest =
+                    ChooserRequest(
+                        targetIntent = Intent(ACTION_SEND),
+                        interactiveSessionCallback = interactiveSessionCallback,
+                        launchedFromPackage = activityModelRepo.value.launchedFromPackage,
+                    ),
+                initialActions = emptyList(),
+            )
+        val testSubject =
+            InteractiveSessionInteractor(
+                activityModelRepo = activityModelRepo,
+                chooserRequestRepository = chooserRequestRepository,
+                pendingSelectionCallbackRepo,
+                interactiveCallbackRepo,
+            )
+
+        backgroundScope.launch { testSubject.activate() }
+        testScheduler.runCurrent()
+
+        assertThat(testSubject.isTargetEnabled.value).isTrue()
+        assertThat(interactiveSessionCallback.registeredChooserController).hasSize(1)
+
+        interactiveSessionCallback.registeredChooserController[0]!!.setTargetsEnabled(false)
+        testScheduler.runCurrent()
+
+        assertThat(testSubject.isTargetEnabled.value).isFalse()
+
+        interactiveSessionCallback.registeredChooserController[0]!!.setTargetsEnabled(true)
+        testScheduler.runCurrent()
+
+        assertThat(testSubject.isTargetEnabled.value).isTrue()
+    }
 }
 
-private class FakeChooserInteractiveSessionCallback :
-    IChooserInteractiveSessionCallback, IBinder, IInterface {
+private class FakeChooserControllerCallback : IChooserControllerCallback, IBinder, IInterface {
     var isAlive = true
-    val registeredIntentUpdaters = ArrayList<IChooserController?>()
+    val registeredChooserController = ArrayList<IChooserController?>()
     val linkedDeathRecipients = ArrayList<DeathRecipient>()
     val unlinkedDeathRecipients = ArrayList<DeathRecipient>()
+    val onClosedInvocationCounter = AtomicInteger(0)
 
     override fun registerChooserController(intentUpdater: IChooserController?) {
-        registeredIntentUpdaters.add(intentUpdater)
+        registeredChooserController.add(intentUpdater)
     }
 
-    override fun onDrawerVerticalOffsetChanged(offset: Int) {}
+    override fun onBoundsChanged(size: Rect) {}
+
+    override fun onClosed() {
+        onClosedInvocationCounter.incrementAndGet()
+    }
 
     override fun asBinder() = this
 
@@ -392,7 +435,7 @@ private class FakeChooserInteractiveSessionCallback :
     override fun isBinderAlive() = isAlive
 
     override fun queryLocalInterface(descriptor: String): IInterface =
-        this@FakeChooserInteractiveSessionCallback
+        this@FakeChooserControllerCallback
 
     override fun dump(fd: FileDescriptor, args: Array<out String>?) = Unit
 
diff --git a/tests/unit/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserControllerCallbackTest.kt b/tests/unit/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserControllerCallbackTest.kt
new file mode 100644
index 00000000..6061be50
--- /dev/null
+++ b/tests/unit/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserControllerCallbackTest.kt
@@ -0,0 +1,57 @@
+/*
+ * Copyright 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.intentresolver.interactive.domain.interactor
+
+import android.graphics.Rect
+import android.os.IBinder
+import android.service.chooser.IChooserControllerCallback
+import org.junit.Test
+import org.mockito.kotlin.any
+import org.mockito.kotlin.doReturn
+import org.mockito.kotlin.mock
+import org.mockito.kotlin.verify
+
+class SafeChooserControllerCallbackTest {
+    @Test
+    fun doNotCallMethodsOnInactiveBinder() {
+        val binder = mock<IBinder> { on { isBinderAlive } doReturn false }
+        val callback = mock<IChooserControllerCallback> { on { asBinder() } doReturn binder }
+        val testSubject = SafeChooserControllerCallback(callback)
+
+        testSubject.registerChooserController(mock())
+        testSubject.onBoundsChanged(Rect(0, 0, 0, 0))
+        testSubject.onClosed()
+
+        verify(callback) {
+            0 * { registerChooserController(any()) }
+            0 * { onBoundsChanged(any()) }
+            0 * { onClosed() }
+        }
+    }
+
+    @Test
+    fun onClosedGetsSendOnlyOnce() {
+        val binder = mock<IBinder> { on { isBinderAlive } doReturn true }
+        val callback = mock<IChooserControllerCallback> { on { asBinder() } doReturn binder }
+        val testSubject = SafeChooserControllerCallback(callback)
+
+        testSubject.onClosed()
+        testSubject.onClosed()
+
+        verify(callback) { 1 * { onClosed() } }
+    }
+}
diff --git a/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt b/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt
index eb5297b4..8b87e63b 100644
--- a/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt
@@ -26,11 +26,8 @@ import android.content.pm.PackageManager.ApplicationInfoFlags
 import android.content.pm.ShortcutManager
 import android.os.UserHandle
 import android.os.UserManager
-import android.platform.test.annotations.DisableFlags
-import android.platform.test.annotations.EnableFlags
 import android.platform.test.flag.junit.SetFlagsRule
 import androidx.test.filters.SmallTest
-import com.android.intentresolver.Flags.FLAG_FIX_SHORTCUTS_FLASHING_FIXED
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.createAppTarget
 import com.android.intentresolver.createShareShortcutInfo
@@ -324,43 +321,6 @@ class ShortcutLoaderTest {
         }
 
     @Test
-    @DisableFlags(FLAG_FIX_SHORTCUTS_FLASHING_FIXED)
-    fun test_appPredictorNotResponding_noCallbackFromShortcutLoader() {
-        scope.runTest {
-            val shortcutManagerResult =
-                listOf(
-                    ShortcutManager.ShareShortcutInfo(matchingShortcutInfo, componentName),
-                    // mismatching shortcut
-                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1),
-                )
-            val shortcutManager =
-                mock<ShortcutManager> {
-                    on { getShareTargets(intentFilter) } doReturn shortcutManagerResult
-                }
-            whenever(context.getSystemService(Context.SHORTCUT_SERVICE)).thenReturn(shortcutManager)
-            val testSubject =
-                ShortcutLoader(
-                    context,
-                    backgroundScope,
-                    appPredictor,
-                    UserHandle.of(0),
-                    true,
-                    intentFilter,
-                    dispatcher,
-                    callback,
-                )
-
-            testSubject.updateAppTargets(appTargets)
-
-            verify(appPredictor, times(1)).requestPredictionUpdate()
-
-            scheduler.advanceTimeBy(ShortcutLoader.APP_PREDICTOR_RESPONSE_TIMEOUT_MS * 2)
-            verify(callback, never()).accept(any())
-        }
-    }
-
-    @Test
-    @EnableFlags(FLAG_FIX_SHORTCUTS_FLASHING_FIXED)
     fun test_appPredictorNotResponding_timeoutAndFallbackToShortcutManager() {
         scope.runTest {
             val testSubject =
@@ -398,7 +358,6 @@ class ShortcutLoaderTest {
     }
 
     @Test
-    @EnableFlags(FLAG_FIX_SHORTCUTS_FLASHING_FIXED)
     fun test_appPredictorResponding_appPredictorTimeoutJobIsCancelled() {
         scope.runTest {
             val shortcutManagerResult =
diff --git a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
index 7bc1e785..f5dd6329 100644
--- a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
@@ -31,10 +31,12 @@ import android.net.Uri
 import android.platform.test.annotations.DisableFlags
 import android.platform.test.annotations.EnableFlags
 import android.platform.test.flag.junit.SetFlagsRule
+import android.service.chooser.Flags.FLAG_INTERACTIVE_CHOOSER
 import androidx.core.net.toUri
 import androidx.core.os.bundleOf
 import com.android.intentresolver.ContentTypeHint
 import com.android.intentresolver.data.model.ChooserRequest
+import com.android.intentresolver.data.model.ColorScheme
 import com.android.intentresolver.shared.model.ActivityModel
 import com.android.intentresolver.validation.Importance
 import com.android.intentresolver.validation.Invalid
@@ -50,11 +52,13 @@ private fun createActivityModel(
     referrer: Uri? = null,
     additionalIntents: List<Intent>? = null,
     launchedFromPackage: String = "com.android.example",
+    colorScheme: Int? = null,
 ) =
     ActivityModel(
         Intent(ACTION_CHOOSER).apply {
             targetIntent?.also { putExtra(EXTRA_INTENT, it) }
             additionalIntents?.also { putExtra(EXTRA_ALTERNATE_INTENTS, it.toTypedArray()) }
+            colorScheme?.let { putExtra(EXTRA_CHOOSER_COLOR_SCHEME, it) }
         },
         launchedFromUid = 10000,
         launchedFromPackage = launchedFromPackage,
@@ -314,4 +318,43 @@ class ChooserRequestTest {
 
         assertThat(result.value.callerAllowsTextToggle).isFalse()
     }
+
+    @Test
+    @EnableFlags(FLAG_INTERACTIVE_CHOOSER)
+    fun testMissingColorScheme() {
+        val intent = Intent().putExtras(bundleOf(EXTRA_INTENT to Intent(ACTION_SEND)))
+        val model = createActivityModel(targetIntent = intent)
+        val result = readChooserRequest(model)
+
+        assertThat(result).isInstanceOf(Valid::class.java)
+        assertThat((result as Valid<ChooserRequest>).value.colorScheme)
+            .isEqualTo(ColorScheme.SystemDefault)
+    }
+
+    @Test
+    @EnableFlags(FLAG_INTERACTIVE_CHOOSER)
+    fun testLightColorScheme() {
+        testColorScheme(provided = COLOR_SCHEME_LIGHT, expected = ColorScheme.Light)
+    }
+
+    @Test
+    @EnableFlags(FLAG_INTERACTIVE_CHOOSER)
+    fun testDarkColorScheme() {
+        testColorScheme(provided = COLOR_SCHEME_DARK, expected = ColorScheme.Dark)
+    }
+
+    @Test
+    @EnableFlags(FLAG_INTERACTIVE_CHOOSER)
+    fun testUnknownColorScheme() {
+        testColorScheme(provided = 100, expected = ColorScheme.SystemDefault)
+    }
+
+    private fun testColorScheme(provided: Int, expected: ColorScheme) {
+        val intent = Intent().putExtras(bundleOf(EXTRA_INTENT to Intent(ACTION_SEND)))
+        val model = createActivityModel(targetIntent = intent, colorScheme = provided)
+        val result = readChooserRequest(model)
+
+        assertThat(result).isInstanceOf(Valid::class.java)
+        assertThat((result as Valid<ChooserRequest>).value.colorScheme).isEqualTo(expected)
+    }
 }
diff --git a/tests/unit/src/com/android/intentresolver/util/IntentUtilsTest.kt b/tests/unit/src/com/android/intentresolver/util/IntentUtilsTest.kt
new file mode 100644
index 00000000..8042b82e
--- /dev/null
+++ b/tests/unit/src/com/android/intentresolver/util/IntentUtilsTest.kt
@@ -0,0 +1,62 @@
+/*
+ * Copyright 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.intentresolver.util
+
+import android.content.ComponentName
+import android.content.Intent
+import android.content.Intent.ACTION_SEND
+import com.google.common.truth.Truth.assertThat
+import org.junit.Test
+
+class IntentUtilsTest {
+    @Test
+    fun test_sanitizePayloadIntents() {
+        val intents =
+            listOf(
+                Intent(ACTION_SEND).apply { setPackage("org.test.example") },
+                Intent(ACTION_SEND).apply {
+                    setComponent(
+                        ComponentName.unflattenFromString("org.test.example/.TestActivity")
+                    )
+                },
+                Intent(ACTION_SEND).apply {
+                    setSelector(Intent(ACTION_SEND).apply { setPackage("org.test.example") })
+                },
+                Intent(ACTION_SEND).apply {
+                    setSelector(
+                        Intent(ACTION_SEND).apply {
+                            setComponent(
+                                ComponentName.unflattenFromString("org.test.example/.TestActivity")
+                            )
+                        }
+                    )
+                },
+            )
+
+        val sanitized = sanitizePayloadIntents(intents)
+
+        assertThat(sanitized).hasSize(intents.size)
+        for (i in sanitized) {
+            assertThat(i.getPackage()).isNull()
+            assertThat(i.getComponent()).isNull()
+            i.getSelector()?.let {
+                assertThat(it.getPackage()).isNull()
+                assertThat(it.getComponent()).isNull()
+            }
+        }
+    }
+}
```

