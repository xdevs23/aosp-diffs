```diff
diff --git a/Android.bp b/Android.bp
index c0e09105..bea5e270 100644
--- a/Android.bp
+++ b/Android.bp
@@ -24,6 +24,7 @@ java_defaults {
     srcs: [
         "java/src/**/*.java",
         "java/src/**/*.kt",
+        "java/aidl/**/I*.aidl",
     ],
     resource_dirs: [
         "java/res",
@@ -52,6 +53,7 @@ android_library {
         "androidx.lifecycle_lifecycle-runtime-ktx",
         "androidx.lifecycle_lifecycle-viewmodel-ktx",
         "dagger2",
+        "//frameworks/libs/systemui:com_android_systemui_shared_flags_lib",
         "hilt_android",
         "IntentResolverFlagsLib",
         "iconloader",
@@ -76,6 +78,9 @@ android_library {
         "-Adagger.explicitBindingConflictsWithInject=ERROR",
         "-Adagger.strictMultibindingValidation=enabled",
     ],
+    aidl: {
+        local_include_dirs: ["java/aidl"],
+    },
 }
 
 java_defaults {
@@ -104,9 +109,4 @@ android_app {
         proguard_flags_files: ["proguard.flags"],
     },
     visibility: ["//visibility:public"],
-    apex_available: [
-        "//apex_available:platform",
-        "com.android.intentresolver",
-        "test_com.android.intentresolver",
-    ],
 }
diff --git a/AndroidManifest-app.xml b/AndroidManifest-app.xml
index 7338dd08..f5d2ff8e 100644
--- a/AndroidManifest-app.xml
+++ b/AndroidManifest-app.xml
@@ -23,6 +23,8 @@
         android:versionName="2021-11"
         coreApp="true">
 
+    <uses-permission android:name="android.permission.INTERNAL_SYSTEM_WINDOW" />
+
     <application
         android:name=".MainApplication"
         android:hardwareAccelerated="true"
diff --git a/aconfig/FeatureFlags.aconfig b/aconfig/FeatureFlags.aconfig
index e2b2f57b..a5509b22 100644
--- a/aconfig/FeatureFlags.aconfig
+++ b/aconfig/FeatureFlags.aconfig
@@ -6,104 +6,70 @@ container: "system"
 # bug: "Feature_Bug_#" or "<none>"
 
 flag {
-  name: "modular_framework"
+  name: "announce_shareousel_item_list_position"
   namespace: "intentresolver"
-  description: "Enables the new modular framework"
-  bug: "302113519"
-}
-
-flag {
-  name: "enable_private_profile"
-  namespace: "intentresolver"
-  description: "Enable private profile support"
-  bug: "328029692"
-}
-
-flag {
-  name: "individual_metadata_title_read"
-  namespace: "intentresolver"
-  description: "Enables separate title URI metadata calls"
-  bug: "304686417"
+  description: "Add item list position to item content description."
+  bug: "379032721"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
 }
 
 flag {
-  name: "refine_system_actions"
+  name: "announce_shortcuts_and_suggested_apps"
   namespace: "intentresolver"
-  description: "This flag enables sending system actions to the caller refinement flow"
-  bug: "331206205"
+  description: "Enable talkback announcement for the app shortcuts and the suggested apps target groups."
+  bug: "379208685"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
 }
 
 flag {
-  name: "fix_drawer_offset_on_config_change"
+  name: "delay_drawer_offset_calculation"
   namespace: "intentresolver"
-  description: "Fix drawer offset calculation after rotating when in a non-initial tab"
-  bug: "344057117"
+  description: "Do not update the drawer offset until app targets are ready."
+  bug: "338229069"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
 }
 
 flag {
-  name: "fix_empty_state_padding"
-  namespace: "intentresolver"
-  description: "Always apply systemBar window insets regardless of profiles present"
-  bug: "338447666"
-}
-
-flag {
-  name: "fix_empty_state_padding_bug"
-  namespace: "intentresolver"
-  description: "Always apply systemBar window insets regardless of profiles present"
-  bug: "338447666"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
-flag {
-  name: "fix_missing_drawer_offset_calculation"
+  name: "individual_metadata_title_read"
   namespace: "intentresolver"
-  description: "Recalculate drawer offset upon the preview size change when the targets list remains unchanged"
-  bug: "347316548"
+  description: "Enables separate title URI metadata calls"
+  bug: "304686417"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
 }
 
 flag {
-  name: "fix_private_space_locked_on_restart"
+  name: "refine_system_actions"
   namespace: "intentresolver"
-  description: "Dismiss Share sheet on restart if private space became locked while stopped"
-  bug: "338125945"
+  description: "This flag enables sending system actions to the caller refinement flow"
+  bug: "331206205"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
 }
 
 flag {
-  name: "fix_shortcut_loader_job_leak"
+  name: "fix_shortcuts_flashing_fixed"
   namespace: "intentresolver"
-  description: "User a nested coroutine scope for shortcut loader instances"
-  bug: "358135601"
+  description: "Do not flash shortcuts on payload selection change"
+  bug: "343300158"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
 }
 
 flag {
-  name: "fix_shortcuts_flashing"
+  name: "interactive_session"
   namespace: "intentresolver"
-  description: "Do not flash shortcuts on payload selection change"
-  bug: "343300158"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
+  description: "Enables interactive chooser session (a.k.a 'Splitti') feature."
+  bug: "358166090"
 }
 
 flag {
@@ -133,13 +99,6 @@ flag {
   bug: "295175912"
 }
 
-flag {
-  name: "preview_image_loader"
-  namespace: "intentresolver"
-  description: "Use the unified preview image loader for all preview variations; support variable preview sizes."
-  bug: "348665058"
-}
-
 flag {
   name: "save_shareousel_state"
   namespace: "intentresolver"
@@ -170,3 +129,20 @@ flag {
   description: "Whether to scroll items onscreen when they are partially offscreen and selected/unselected."
   bug: "351883537"
 }
+
+flag {
+  name: "shareousel_selection_shrink"
+  namespace: "intentresolver"
+  description: "Whether to shrink Shareousel items when they are selected."
+  bug: "361792274"
+}
+
+flag {
+  name: "shareousel_tap_to_scroll_support"
+  namespace: "intentresolver"
+  description: "Whether to enable tap to scroll."
+  bug: "384656926"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
diff --git a/java/aidl/com/android/intentresolver/IChooserController.aidl b/java/aidl/com/android/intentresolver/IChooserController.aidl
new file mode 100644
index 00000000..a4ce718d
--- /dev/null
+++ b/java/aidl/com/android/intentresolver/IChooserController.aidl
@@ -0,0 +1,8 @@
+
+package com.android.intentresolver;
+
+import android.content.Intent;
+
+interface IChooserController {
+    oneway void updateIntent(in Intent intent);
+}
diff --git a/java/aidl/com/android/intentresolver/IChooserInteractiveSessionCallback.aidl b/java/aidl/com/android/intentresolver/IChooserInteractiveSessionCallback.aidl
new file mode 100644
index 00000000..4a6179d9
--- /dev/null
+++ b/java/aidl/com/android/intentresolver/IChooserInteractiveSessionCallback.aidl
@@ -0,0 +1,9 @@
+
+package com.android.intentresolver;
+
+import com.android.intentresolver.IChooserController;
+
+interface IChooserInteractiveSessionCallback {
+    oneway void registerChooserController(in IChooserController updater);
+    oneway void onDrawerVerticalOffsetChanged(in int offset);
+}
diff --git a/java/res/color/resolver_profile_tab_text.xml b/java/res/color/resolver_profile_tab_text.xml
index ffeba854..f6a4eadf 100644
--- a/java/res/color/resolver_profile_tab_text.xml
+++ b/java/res/color/resolver_profile_tab_text.xml
@@ -16,5 +16,5 @@
 <selector xmlns:android="http://schemas.android.com/apk/res/android"
           xmlns:androidprv="http://schemas.android.com/apk/prv/res/android">
     <item android:color="@androidprv:color/materialColorOnPrimary" android:state_selected="true"/>
-    <item android:color="@androidprv:color/materialColorOnSurfaceVariant"/>
+    <item android:color="@androidprv:color/materialColorOnSurface"/>
 </selector>
diff --git a/java/res/drawable/ic_drag_handle.xml b/java/res/drawable/ic_drag_handle.xml
index d6965209..96297a2e 100644
--- a/java/res/drawable/ic_drag_handle.xml
+++ b/java/res/drawable/ic_drag_handle.xml
@@ -17,6 +17,6 @@
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
     android:shape="rectangle" >
-    <solid android:color="@androidprv:color/materialColorOutlineVariant" />
+    <solid android:color="@androidprv:color/materialColorOutline" />
     <corners android:radius="2dp" />
 </shape>
diff --git a/java/res/drawable/resolver_profile_tab_bg.xml b/java/res/drawable/resolver_profile_tab_bg.xml
index 20f0be92..392f7e30 100644
--- a/java/res/drawable/resolver_profile_tab_bg.xml
+++ b/java/res/drawable/resolver_profile_tab_bg.xml
@@ -29,7 +29,7 @@
             <item android:state_selected="false">
                 <shape android:shape="rectangle">
                     <corners android:radius="12dp" />
-                    <solid android:color="@androidprv:color/materialColorSurfaceContainerHighest" />
+                    <solid android:color="@androidprv:color/materialColorSurfaceBright" />
                 </shape>
             </item>
 
diff --git a/java/res/layout/chooser_grid_item.xml b/java/res/layout/chooser_grid_item.xml
index 76d2e60f..dd07c4f8 100644
--- a/java/res/layout/chooser_grid_item.xml
+++ b/java/res/layout/chooser_grid_item.xml
@@ -18,14 +18,14 @@
 -->
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
               xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
-              android:id="@androidprv:id/item"
+              android:id="@+id/item"
               android:orientation="vertical"
               android:layout_width="match_parent"
               android:layout_height="wrap_content"
               android:minHeight="100dp"
               android:gravity="top|center_horizontal"
-              android:paddingVertical="@dimen/grid_padding"
-              android:paddingHorizontal="4dp"
+              android:paddingVertical="@dimen/grid_padding_vertical"
+              android:paddingHorizontal="@dimen/grid_padding_horizontal"
               android:focusable="true"
               android:background="?android:attr/selectableItemBackgroundBorderless">
 
@@ -37,7 +37,7 @@
 
     <!-- Size manually tuned to match specs -->
     <Space android:layout_width="1dp"
-           android:layout_height="7dp"/>
+           android:layout_height="@dimen/chooser_grid_item_space_height"/>
 
     <!-- NOTE: for id/text1 and id/text2 below set the width to match parent as a workaround for
          b/269395540 i.e. prevent views bounds change during a transition animation. It does not
@@ -50,7 +50,7 @@
               android:layout_width="match_parent"
               android:layout_height="wrap_content"
               android:textAppearance="?android:attr/textAppearanceSmall"
-              android:textColor="@androidprv:color/materialColorOnSurface"
+              android:textColor="@color/chooser_grid_item_text1_color"
               android:textSize="@dimen/chooser_grid_target_name_text_size"
               android:maxLines="1"
               android:ellipsize="end" />
@@ -59,7 +59,7 @@
     <TextView android:id="@android:id/text2"
               android:textAppearance="?android:attr/textAppearanceSmall"
               android:textSize="@dimen/chooser_grid_activity_name_text_size"
-              android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
+              android:textColor="@color/chooser_grid_item_text2_color"
               android:layout_width="match_parent"
               android:layout_height="wrap_content"
               android:lines="1"
diff --git a/java/res/layout/chooser_grid_item_hover.xml b/java/res/layout/chooser_grid_item_hover.xml
index 5e49c9fd..2bb94990 100644
--- a/java/res/layout/chooser_grid_item_hover.xml
+++ b/java/res/layout/chooser_grid_item_hover.xml
@@ -20,7 +20,7 @@
               xmlns:android="http://schemas.android.com/apk/res/android"
               xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
               xmlns:app="http://schemas.android.com/apk/res-auto"
-              android:id="@androidprv:id/item"
+              android:id="@+id/item"
               android:orientation="vertical"
               android:layout_width="match_parent"
               android:layout_height="wrap_content"
@@ -53,7 +53,7 @@
               android:layout_width="match_parent"
               android:layout_height="wrap_content"
               android:textAppearance="?android:attr/textAppearanceSmall"
-              android:textColor="@androidprv:color/materialColorOnSurface"
+              android:textColor="@color/chooser_grid_item_text1_color"
               android:textSize="@dimen/chooser_grid_target_name_text_size"
               android:maxLines="1"
               android:ellipsize="end" />
@@ -62,7 +62,7 @@
     <TextView android:id="@android:id/text2"
               android:textAppearance="?android:attr/textAppearanceSmall"
               android:textSize="@dimen/chooser_grid_activity_name_text_size"
-              android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
+              android:textColor="@color/chooser_grid_item_text2_color"
               android:layout_width="match_parent"
               android:layout_height="wrap_content"
               android:lines="1"
diff --git a/java/res/layout/chooser_grid_preview_file.xml b/java/res/layout/chooser_grid_preview_file.xml
index 9584ec9a..5be37481 100644
--- a/java/res/layout/chooser_grid_preview_file.xml
+++ b/java/res/layout/chooser_grid_preview_file.xml
@@ -24,7 +24,7 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
-    android:background="@androidprv:color/materialColorSurfaceContainer">
+    android:background="@color/chooser_grid_preview_background" >
 
     <RelativeLayout
         android:layout_width="match_parent"
@@ -32,6 +32,7 @@
         android:layout_gravity="center"
         android:layout_marginHorizontal="@dimen/chooser_edge_margin_normal"
         android:layout_marginBottom="8dp"
+        android:minHeight="@dimen/chooser_content_view_min_height"
         android:padding="@dimen/chooser_edge_margin_normal"
         android:background="@drawable/chooser_content_preview_rounded"
         android:id="@androidprv:id/content_preview_file_layout">
@@ -63,9 +64,9 @@
                 android:gravity="start|top"
                 android:singleLine="true"
                 android:textStyle="bold"
-                android:textColor="@androidprv:color/materialColorOnSurface"
-                android:textSize="12sp"
-                android:lineHeight="16sp"
+                android:textColor="@color/content_preview_filename_text_color"
+                android:textSize="@dimen/content_preview_text_size"
+                android:lineHeight="@dimen/content_preview_filename_line_size"
                 android:textAppearance="@style/TextAppearance.ChooserDefault"/>
 
             <TextView
@@ -74,9 +75,9 @@
                 android:layout_height="wrap_content"
                 android:gravity="start|top"
                 android:singleLine="true"
-                android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
-                android:textSize="12sp"
-                android:lineHeight="16sp"
+                android:textColor="@color/content_preview_more_files_text_color"
+                android:textSize="@dimen/content_preview_more_files_text_size"
+                android:lineHeight="@dimen/content_preview_more_files_line_size"
                 android:textAppearance="@style/TextAppearance.ChooserDefault"/>
 
         </LinearLayout>
diff --git a/java/res/layout/chooser_grid_preview_files_text.xml b/java/res/layout/chooser_grid_preview_files_text.xml
index 9e2bde67..b57d1394 100644
--- a/java/res/layout/chooser_grid_preview_files_text.xml
+++ b/java/res/layout/chooser_grid_preview_files_text.xml
@@ -23,13 +23,14 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
-    android:background="@androidprv:color/materialColorSurfaceContainer">
+    android:background="@color/chooser_grid_preview_background">
 
     <LinearLayout
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
         android:orientation="horizontal"
         android:gravity="center_horizontal"
+        android:minHeight="@dimen/chooser_content_view_min_height"
         android:layout_marginBottom="8dp"
         android:layout_marginHorizontal="@dimen/chooser_edge_margin_normal"
         android:padding="@dimen/chooser_edge_margin_normal_half"
@@ -53,7 +54,7 @@
             android:maxLines="@integer/text_preview_lines"
             android:ellipsize="end"
             android:linksClickable="false"
-            android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
+            android:textColor="@color/content_preview_text_color"
             android:textAppearance="@style/TextAppearance.ChooserDefault"/>
     </LinearLayout>
 
diff --git a/java/res/layout/chooser_grid_preview_image.xml b/java/res/layout/chooser_grid_preview_image.xml
index 199963b1..b14f6463 100644
--- a/java/res/layout/chooser_grid_preview_image.xml
+++ b/java/res/layout/chooser_grid_preview_image.xml
@@ -24,7 +24,7 @@
     android:layout_height="wrap_content"
     android:orientation="vertical"
     android:importantForAccessibility="no"
-    android:background="@androidprv:color/materialColorSurfaceContainer">
+    android:background="@color/chooser_grid_preview_background">
 
     <ViewStub
         android:id="@+id/chooser_headline_row_stub"
@@ -39,6 +39,7 @@
         android:layout_width="wrap_content"
         android:layout_height="@dimen/chooser_preview_image_height_tall"
         android:layout_gravity="center_horizontal"
+        android:minHeight="@dimen/chooser_content_view_min_height"
         android:layout_marginBottom="8dp"
         app:itemInnerSpacing="3dp"
         app:itemOuterSpacing="@dimen/chooser_edge_margin_normal"
diff --git a/java/res/layout/chooser_grid_preview_text.xml b/java/res/layout/chooser_grid_preview_text.xml
index 951abfc7..242b9409 100644
--- a/java/res/layout/chooser_grid_preview_text.xml
+++ b/java/res/layout/chooser_grid_preview_text.xml
@@ -25,14 +25,15 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
-    android:background="@androidprv:color/materialColorSurfaceContainer">
+    android:background="@color/chooser_grid_preview_background">
 
   <androidx.constraintlayout.widget.ConstraintLayout
       android:layout_width="match_parent"
       android:layout_height="wrap_content"
       android:layout_gravity="center"
+      android:minHeight="@dimen/chooser_content_view_min_height"
       android:layout_marginHorizontal="@dimen/chooser_edge_margin_normal"
-      android:layout_marginBottom="8dp"
+      android:layout_marginBottom="@dimen/chooser_edge_margin_normal_half"
       android:paddingVertical="@dimen/chooser_edge_margin_normal_half"
       android:paddingStart="@dimen/chooser_edge_margin_normal_half"
       android:paddingEnd="0dp"
@@ -67,7 +68,7 @@
         android:textAlignment="gravity"
         android:textDirection="locale"
         android:textStyle="bold"
-        android:textColor="@androidprv:color/materialColorOnSurface"
+        android:textColor="@color/content_preview_filename_text_color"
         android:fontFamily="@androidprv:string/config_headlineFontFamily"/>
 
     <TextView
@@ -82,7 +83,7 @@
         app:layout_goneMarginStart="0dp"
         android:ellipsize="end"
         android:fontFamily="@androidprv:string/config_headlineFontFamily"
-        android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
+        android:textColor="@color/content_preview_text_color"
         android:textAlignment="gravity"
         android:textDirection="locale"
         android:maxLines="@integer/text_preview_lines"
@@ -90,8 +91,8 @@
 
     <FrameLayout
         android:id="@+id/copy"
-        android:layout_width="48dp"
-        android:layout_height="48dp"
+        android:layout_width="@dimen/content_preview_copy_icon_size"
+        android:layout_height="@dimen/content_preview_copy_icon_size"
         style="?android:attr/borderlessButtonStyle"
         app:layout_constraintStart_toEndOf="@androidprv:id/content_preview_text"
         app:layout_constraintEnd_toEndOf="parent"
@@ -105,7 +106,7 @@
           android:layout_width="wrap_content"
           android:layout_height="wrap_content"
           android:layout_gravity="center"
-          android:tint="@androidprv:color/materialColorOnSurfaceVariant"
+          android:tint="@color/content_preview_copy_icon_tint"
           android:src="@androidprv:drawable/ic_menu_copy_material"
           />
     </FrameLayout>
diff --git a/java/res/layout/chooser_list_per_profile_wrap.xml b/java/res/layout/chooser_list_per_profile_wrap.xml
index e556bc94..db65533f 100644
--- a/java/res/layout/chooser_list_per_profile_wrap.xml
+++ b/java/res/layout/chooser_list_per_profile_wrap.xml
@@ -18,7 +18,8 @@
     xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
     android:layout_width="match_parent"
-    android:layout_height="wrap_content">
+    android:layout_height="wrap_content"
+    android:paddingHorizontal="@dimen/chooser_list_padding">
 
     <androidx.recyclerview.widget.RecyclerView
         android:layout_width="match_parent"
@@ -26,7 +27,7 @@
         app:layoutManager="com.android.intentresolver.ChooserGridLayoutManager"
         android:id="@androidprv:id/resolver_list"
         android:clipToPadding="false"
-        android:background="@androidprv:color/materialColorSurfaceContainer"
+        android:background="@color/chooser_grid_layout_background"
         android:scrollbars="none"
         android:nestedScrollingEnabled="true" />
 
diff --git a/java/res/layout/chooser_row.xml b/java/res/layout/chooser_row.xml
index bbe65a85..cb8a53f4 100644
--- a/java/res/layout/chooser_row.xml
+++ b/java/res/layout/chooser_row.xml
@@ -18,9 +18,10 @@
 -->
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
               xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
+              android:id="@+id/suggested_apps_container"
               android:orientation="horizontal"
               android:layout_width="match_parent"
-              android:layout_height="100dp"
+              android:layout_height="@dimen/chooser_row_height"
               android:gravity="start|top">
   <TextView
       android:id="@androidprv:id/chooser_row_text_option"
@@ -28,7 +29,7 @@
       android:layout_height="wrap_content"
       android:gravity="center"
       android:layout_gravity="center"
-      android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
+      android:textColor="@color/chooser_row_text_color"
       android:visibility="gone" />
 </LinearLayout>
 
diff --git a/java/res/layout/chooser_row_direct_share.xml b/java/res/layout/chooser_row_direct_share.xml
index d7e36eed..59794191 100644
--- a/java/res/layout/chooser_row_direct_share.xml
+++ b/java/res/layout/chooser_row_direct_share.xml
@@ -17,9 +17,10 @@
 */
 -->
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                android:id="@+id/shortcuts_container"
                 android:orientation="vertical"
                 android:layout_width="match_parent"
-                android:layout_height="200dp">
+                android:layout_height="@dimen/chooser_row_direct_share_height">
 
 </LinearLayout>
 
diff --git a/java/res/layout/resolver_profile_tab_button.xml b/java/res/layout/resolver_profile_tab_button.xml
index 52a1aacf..7404dc33 100644
--- a/java/res/layout/resolver_profile_tab_button.xml
+++ b/java/res/layout/resolver_profile_tab_button.xml
@@ -17,7 +17,6 @@
 
     <Button
         xmlns:android="http://schemas.android.com/apk/res/android"
-        xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
         android:layout_width="0dp"
         android:layout_height="48dp"
         android:layout_weight="1"
diff --git a/java/res/values-af/strings.xml b/java/res/values-af/strings.xml
index a0b78850..12a44b0e 100644
--- a/java/res/values-af/strings.xml
+++ b/java/res/values-af/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Sluit skakel uit"</string>
     <string name="include_link" msgid="827855767220339802">"Sluit skakel in"</string>
     <string name="pinned" msgid="7623664001331394139">"Vasgespeld"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Kiesbare prent"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Kiesbare video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Kiesbare item"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Knoppie"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Direktedelingteikens"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Appvoorstelle"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Applys"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopieer teks"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopieer skakel"</string>
 </resources>
diff --git a/java/res/values-am/strings.xml b/java/res/values-am/strings.xml
index d46f88d1..64cea88a 100644
--- a/java/res/values-am/strings.xml
+++ b/java/res/values-am/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"አገናኝን አታካትት"</string>
     <string name="include_link" msgid="827855767220339802">"አገናኝ አካትት"</string>
     <string name="pinned" msgid="7623664001331394139">"ፒን ተደርጓል"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"ንጥል <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"ሊመረጥ የሚችል ምስል"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ሊመረጥ የሚችል ቪድዮ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ሊመረጥ የሚችል ንጥል"</string>
     <string name="role_description_button" msgid="4537198530568333649">"አዝራር"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"የቀጥታ ማጋራት ዒላማዎች"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"የመተግበሪያ አስተያየቶች"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"የመተግበሪያ ዝርዝር"</string>
+    <string name="copy_text" msgid="1341801611046464360">"ጽሑፍ ቅዳ"</string>
+    <string name="copy_link" msgid="3822142723771306592">"አገናኝ ቅዳ"</string>
 </resources>
diff --git a/java/res/values-ar/strings.xml b/java/res/values-ar/strings.xml
index 278e03f2..b170e7f9 100644
--- a/java/res/values-ar/strings.xml
+++ b/java/res/values-ar/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"استثناء الرابط"</string>
     <string name="include_link" msgid="827855767220339802">"تضمين الرابط"</string>
     <string name="pinned" msgid="7623664001331394139">"مثبَّت"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"العنصر رقم <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"صورة يمكن اختيارها"</string>
     <string name="selectable_video" msgid="1271768647699300826">"فيديو يمكن اختياره"</string>
     <string name="selectable_item" msgid="7557320816744205280">"عنصر يمكن اختياره"</string>
     <string name="role_description_button" msgid="4537198530568333649">"زرّ"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"أهداف المشاركة المباشرة"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"التطبيقات المقترَحة"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"قائمة التطبيقات"</string>
+    <string name="copy_text" msgid="1341801611046464360">"نسخ النص"</string>
+    <string name="copy_link" msgid="3822142723771306592">"نسخ الرابط"</string>
 </resources>
diff --git a/java/res/values-as/strings.xml b/java/res/values-as/strings.xml
index 2177c527..fd0a407e 100644
--- a/java/res/values-as/strings.xml
+++ b/java/res/values-as/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"লিংক বহিৰ্ভূত কৰক"</string>
     <string name="include_link" msgid="827855767220339802">"লিংক অন্তৰ্ভুক্ত কৰক"</string>
     <string name="pinned" msgid="7623664001331394139">"পিন কৰা আছে"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"বস্তু <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"বাছনি কৰিব পৰা প্ৰতিচ্ছবি"</string>
     <string name="selectable_video" msgid="1271768647699300826">"বাছনি কৰিব পৰা ভিডিঅ’"</string>
     <string name="selectable_item" msgid="7557320816744205280">"বাছনি কৰিব পৰা বস্তু"</string>
     <string name="role_description_button" msgid="4537198530568333649">"বুটাম"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"পোনপটীয়াকৈ কৰা শ্বেয়াৰৰ লক্ষ্য"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"এপৰ পৰামৰ্শ"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"এপৰ সূচী"</string>
+    <string name="copy_text" msgid="1341801611046464360">"পাঠ প্ৰতিলিপি কৰক"</string>
+    <string name="copy_link" msgid="3822142723771306592">"লিংক প্ৰতিলিপি কৰক"</string>
 </resources>
diff --git a/java/res/values-az/strings.xml b/java/res/values-az/strings.xml
index 93086938..46baccee 100644
--- a/java/res/values-az/strings.xml
+++ b/java/res/values-az/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Keçidi istisna edin"</string>
     <string name="include_link" msgid="827855767220339802">"Keçid daxil edin"</string>
     <string name="pinned" msgid="7623664001331394139">"Bərkidilib"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Element <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Seçilə bilən şəkil"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Seçilə bilən video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Seçilə bilən element"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Düymə"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Birbaşa paylaşım hədəfləri"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Tətbiq təklifləri"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Tətbiq siyahısı"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Mətni kopyalayın"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Keçidi kopyalayın"</string>
 </resources>
diff --git a/java/res/values-b+sr+Latn/strings.xml b/java/res/values-b+sr+Latn/strings.xml
index 86fc1854..64ae817b 100644
--- a/java/res/values-b+sr+Latn/strings.xml
+++ b/java/res/values-b+sr+Latn/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{i još # fajl}one{i još # fajl}few{i još # fajla}other{i još # fajlova}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ još # fajl}one{+ još # fajl}few{+ još # fajla}other{+ još # fajlova}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Deli se tekst"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Deli se link"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Deljenje linka"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Deljenje slike}one{Deljenje # slike}few{Deljenje # slike}other{Deljenje # slika}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Deli se video}one{Deli se # video}few{Dele se # video snimka}other{Deli se # videa}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Deli se # fajl}one{Deli se # fajl}few{Dele se # fajla}other{Deli se # fajlova}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Izuzmi link"</string>
     <string name="include_link" msgid="827855767220339802">"Uvrsti link"</string>
     <string name="pinned" msgid="7623664001331394139">"Zakačeno"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Stavka <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Slika koja može da se izabere"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video koji može da se izabere"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Stavka koja može da se izabere"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Dugme"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Ciljevi direktnog deljenja"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Predlozi aplikacija"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista aplikacija"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopiraj tekst"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopiraj link"</string>
 </resources>
diff --git a/java/res/values-be/strings.xml b/java/res/values-be/strings.xml
index 97ca27d3..b51e0922 100644
--- a/java/res/values-be/strings.xml
+++ b/java/res/values-be/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Выдаліць спасылку"</string>
     <string name="include_link" msgid="827855767220339802">"Дадаць спасылку"</string>
     <string name="pinned" msgid="7623664001331394139">"Замацавана"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Элемент <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Відарыс, які можна выбраць"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Відэа, якое можна выбраць"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Элемент, які можна выбраць"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Кнопка"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Адрасаты для прамога абагульвання"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Прапановы праграм"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Спіс праграм"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Скапіраваць тэкст"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Скапіраваць спасылку"</string>
 </resources>
diff --git a/java/res/values-bg/strings.xml b/java/res/values-bg/strings.xml
index 3cec0cdf..0fcb751e 100644
--- a/java/res/values-bg/strings.xml
+++ b/java/res/values-bg/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Изключване на връзката"</string>
     <string name="include_link" msgid="827855767220339802">"Включване на връзката"</string>
     <string name="pinned" msgid="7623664001331394139">"Фиксирано"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Елемент <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Избираемо изображение"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Избираем видеоклип"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Избираем елемент"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Бутон"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Цели за директно споделяне"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Предложения за приложения"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Списък с приложения"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Копиране на текста"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Копиране на връзката"</string>
 </resources>
diff --git a/java/res/values-bn/strings.xml b/java/res/values-bn/strings.xml
index ea524006..69cbed55 100644
--- a/java/res/values-bn/strings.xml
+++ b/java/res/values-bn/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{আরও #টি ফাইল}one{আরও #টি ফাইল}other{আরও #টি ফাইল}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{আরও #টি ফাইল}one{আরও #টি ফাইল}other{আরও #টি ফাইল}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"টেক্সট শেয়ার করা হচ্ছে"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"শেয়ার করার জন্য লিঙ্ক"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"লিঙ্ক শেয়ার করা হচ্ছে"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ছবি শেয়ার করা হচ্ছে}one{#টি ছবি শেয়ার করা হচ্ছে}other{#টি ছবি শেয়ার করা হচ্ছে}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ভিডিও শেয়ার করা হচ্ছে}one{#টি ভিডিও শেয়ার করা হচ্ছে}other{#টি ভিডিও শেয়ার করা হচ্ছে}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{#টি ফাইল শেয়ার করা হচ্ছে}one{#টি ফাইল শেয়ার করা হচ্ছে}other{#টি ফাইল শেয়ার করা হচ্ছে}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"লিঙ্ক বাদ দিন"</string>
     <string name="include_link" msgid="827855767220339802">"লিঙ্ক যোগ করুন"</string>
     <string name="pinned" msgid="7623664001331394139">"পিন করা হয়েছে"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"আইটেম <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"বেছে নেওয়া যাবে এমন ছবি"</string>
     <string name="selectable_video" msgid="1271768647699300826">"বেছে নেওয়া যাবে এমন ভিডিও"</string>
     <string name="selectable_item" msgid="7557320816744205280">"বেছে নেওয়া যাবে এমন আইটেম"</string>
     <string name="role_description_button" msgid="4537198530568333649">"বোতাম"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"সরাসরি টার্গেট শেয়ার করুন"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"অ্যাপ সাজেশন"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"অ্যাপ তালিকা"</string>
+    <string name="copy_text" msgid="1341801611046464360">"টেক্সট কপি করুন"</string>
+    <string name="copy_link" msgid="3822142723771306592">"লিঙ্ক কপি করুন"</string>
 </resources>
diff --git a/java/res/values-bs/strings.xml b/java/res/values-bs/strings.xml
index ddf3119b..52b9f191 100644
--- a/java/res/values-bs/strings.xml
+++ b/java/res/values-bs/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{i još # fajl}one{i još # fajl}few{i još # fajla}other{i još # fajlova}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{i još # fajl}one{i još # fajl}few{i još # fajla}other{i još # fajlova}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Dijeljenje teksta"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Dijeljenje linka"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Podijelite link"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Podijelite sliku}one{Podijelite # sliku}few{Podijelite # slike}other{Podijelite # slika}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Dijeljenje videozapisa}one{Dijeljenje # videozapisa}few{Dijeljenje # videozapisa}other{Dijeljenje # videozapisa}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Dijeljenje # fajla}one{Dijeljenje # fajla}few{Dijeljenje # fajla}other{Dijeljenje # fajlova}}"</string>
@@ -85,7 +85,7 @@
     <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"Blokirao je vaš IT administrator"</string>
     <string name="resolver_cant_share_with_work_apps_explanation" msgid="2984105853145456723">"Ovaj sadržaj nije moguće dijeliti pomoću poslovnih aplikacija"</string>
     <string name="resolver_cant_access_work_apps_explanation" msgid="1463093773348988122">"Ovaj sadržaj nije moguće otvoriti pomoću poslovnih aplikacija"</string>
-    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"Ovaj sadržaj nije moguće dijeliti pomoću ličnih aplikacija"</string>
+    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"Ovaj sadržaj nije moguće dijeliti s ličnim aplikacijama"</string>
     <string name="resolver_cant_access_personal_apps_explanation" msgid="6209543716289792706">"Ovaj sadržaj nije moguće otvoriti pomoću ličnih aplikacija"</string>
     <string name="resolver_cant_share_with_private_apps_explanation" msgid="1781980997411434697">"Sadržaj se ne može dijeliti pomoću privatnih aplikacija"</string>
     <string name="resolver_cant_access_private_apps_explanation" msgid="5978609934961648342">"Sadržaj se ne može otvoriti pomoću privatnih aplikacija"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Izuzmi link"</string>
     <string name="include_link" msgid="827855767220339802">"Uključi link"</string>
     <string name="pinned" msgid="7623664001331394139">"Zakačeno"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g>. stavka"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Slika koju je moguće odabrati"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Videozapis koji je moguće odabrati"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Stavka koju je moguće odabrati"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Dugme"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Ciljevi direktnog dijeljenja"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Prijedlozi aplikacija"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista aplikacija"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopiranje teksta"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopiranje linka"</string>
 </resources>
diff --git a/java/res/values-ca/strings.xml b/java/res/values-ca/strings.xml
index 48d7138f..dd003124 100644
--- a/java/res/values-ca/strings.xml
+++ b/java/res/values-ca/strings.xml
@@ -57,7 +57,7 @@
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{# fitxer més}many{# de fitxers més}other{# fitxers més}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"S\'està compartint text"</string>
     <string name="sharing_link" msgid="2307694372813942916">"S\'està compartint un enllaç"</string>
-    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Comparteix una imatge}many{Comparteix # d\'imatges}other{Comparteix # imatges}}"</string>
+    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{S\'està compartint una imatge}many{S\'estan compartint # d\'imatges}other{S\'estan compartint # imatges}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{S\'està compartint un vídeo}many{S\'estan compartint # de vídeos}other{S\'estan compartint # vídeos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{S\'està compartint # fitxer}many{S\'estan compartint # de fitxers}other{S\'estan compartint # fitxers}}"</string>
     <string name="select_items_to_share" msgid="1026071777275022579">"Selecciona els elements que vols compartir"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Exclou l\'enllaç"</string>
     <string name="include_link" msgid="827855767220339802">"Inclou l\'enllaç"</string>
     <string name="pinned" msgid="7623664001331394139">"Fixat"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Element <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Imatge seleccionable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo seleccionable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Element seleccionable"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Botó"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Destinataris de la compartició directa"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Suggeriments d\'aplicacions"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Llista d\'aplicacions"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copia el text"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copia l\'enllaç"</string>
 </resources>
diff --git a/java/res/values-cs/strings.xml b/java/res/values-cs/strings.xml
index 151e2147..41fec051 100644
--- a/java/res/values-cs/strings.xml
+++ b/java/res/values-cs/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Vyloučit odkaz"</string>
     <string name="include_link" msgid="827855767220339802">"Zahrnout odkaz"</string>
     <string name="pinned" msgid="7623664001331394139">"Připnuto"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Položka <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Vybratelný obrázek"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vybratelné video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Vybratelná položka"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Tlačítko"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Přímé sdílení cílů"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Návrhy aplikací"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Seznam aplikací"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopírovat text"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopírovat odkaz"</string>
 </resources>
diff --git a/java/res/values-da/strings.xml b/java/res/values-da/strings.xml
index e9d952fe..1fe8da30 100644
--- a/java/res/values-da/strings.xml
+++ b/java/res/values-da/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Ekskluder link"</string>
     <string name="include_link" msgid="827855767220339802">"Inkluder link"</string>
     <string name="pinned" msgid="7623664001331394139">"Fastgjort"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Element <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Billede, der kan vælges"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video, der kan vælges"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Element, der kan vælges"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Knap"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Personer/grupper, der skal deles direkte med"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Appforslag"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Appliste"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopiér tekst"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopiér link"</string>
 </resources>
diff --git a/java/res/values-de/strings.xml b/java/res/values-de/strings.xml
index 911dd273..497f1e71 100644
--- a/java/res/values-de/strings.xml
+++ b/java/res/values-de/strings.xml
@@ -83,9 +83,9 @@
     <string name="resolver_work_tab_accessibility" msgid="7581878836587799920">"Geschäftliche Ansicht"</string>
     <string name="resolver_private_tab_accessibility" msgid="2513122834337197252">"Private Ansicht"</string>
     <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"Vom IT‑Administrator blockiert"</string>
-    <string name="resolver_cant_share_with_work_apps_explanation" msgid="2984105853145456723">"Diese Art von Inhalt kann nicht über geschäftliche Apps geteilt werden"</string>
+    <string name="resolver_cant_share_with_work_apps_explanation" msgid="2984105853145456723">"Dieser Inhalt kann nicht über geschäftliche Apps geteilt werden"</string>
     <string name="resolver_cant_access_work_apps_explanation" msgid="1463093773348988122">"Diese Art von Inhalt kann nicht mit geschäftlichen Apps geöffnet werden"</string>
-    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"Diese Art von Inhalt kann nicht über private Apps geteilt werden"</string>
+    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"Dieser Inhalt kann nicht über private Apps geteilt werden"</string>
     <string name="resolver_cant_access_personal_apps_explanation" msgid="6209543716289792706">"Diese Art von Inhalt kann nicht mit privaten Apps geöffnet werden"</string>
     <string name="resolver_cant_share_with_private_apps_explanation" msgid="1781980997411434697">"Diese Art von Inhalt kann nicht über interne Apps geteilt werden"</string>
     <string name="resolver_cant_access_private_apps_explanation" msgid="5978609934961648342">"Diese Art von Inhalt kann nicht mit internen Apps geöffnet werden"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Link ausschließen"</string>
     <string name="include_link" msgid="827855767220339802">"Link einschließen"</string>
     <string name="pinned" msgid="7623664001331394139">"Angepinnt"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Element <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Auswählbares Bild"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Auswählbares Video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Auswählbares Element"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Schaltfläche"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"„Direct Share“-Ziele"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"App-Vorschläge"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App-Liste"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Text kopieren"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Link kopieren"</string>
 </resources>
diff --git a/java/res/values-el/strings.xml b/java/res/values-el/strings.xml
index 319a3e2c..d84f7621 100644
--- a/java/res/values-el/strings.xml
+++ b/java/res/values-el/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Εξαίρεση συνδέσμου"</string>
     <string name="include_link" msgid="827855767220339802">"Συμπερίληψη συνδέσμου"</string>
     <string name="pinned" msgid="7623664001331394139">"Καρφιτσωμένο"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Στοιχείο <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Εικόνα με δυνατότητα επιλογής"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Βίντεο με δυνατότητα επιλογής"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Στοιχείο με δυνατότητα επιλογής"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Κουμπί"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Στοχευόμενοι χρήστες για Άμεση κοινή χρήση"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Προτεινόμενες εφαρμογές"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Λίστα εφαρμογών"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Αντιγραφή κειμένου"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Αντιγραφή συνδέσμου"</string>
 </resources>
diff --git a/java/res/values-en-rAU/strings.xml b/java/res/values-en-rAU/strings.xml
index 4d16a6f4..d4fb97e0 100644
--- a/java/res/values-en-rAU/strings.xml
+++ b/java/res/values-en-rAU/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Exclude link"</string>
     <string name="include_link" msgid="827855767220339802">"Include link"</string>
     <string name="pinned" msgid="7623664001331394139">"Pinned"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Selectable image"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Selectable video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Selectable item"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Button"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Direct share targets"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"App suggestions"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App list"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copy text"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copy link"</string>
 </resources>
diff --git a/java/res/values-en-rCA/strings.xml b/java/res/values-en-rCA/strings.xml
index 9f6d20c3..eca4abcc 100644
--- a/java/res/values-en-rCA/strings.xml
+++ b/java/res/values-en-rCA/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Exclude link"</string>
     <string name="include_link" msgid="827855767220339802">"Include link"</string>
     <string name="pinned" msgid="7623664001331394139">"Pinned"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Selectable image"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Selectable video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Selectable item"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Button"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Direct share targets"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"App suggestions"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App list"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copy text"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copy link"</string>
 </resources>
diff --git a/java/res/values-en-rGB/strings.xml b/java/res/values-en-rGB/strings.xml
index 4d16a6f4..d4fb97e0 100644
--- a/java/res/values-en-rGB/strings.xml
+++ b/java/res/values-en-rGB/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Exclude link"</string>
     <string name="include_link" msgid="827855767220339802">"Include link"</string>
     <string name="pinned" msgid="7623664001331394139">"Pinned"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Selectable image"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Selectable video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Selectable item"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Button"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Direct share targets"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"App suggestions"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App list"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copy text"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copy link"</string>
 </resources>
diff --git a/java/res/values-en-rIN/strings.xml b/java/res/values-en-rIN/strings.xml
index 4d16a6f4..d4fb97e0 100644
--- a/java/res/values-en-rIN/strings.xml
+++ b/java/res/values-en-rIN/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Exclude link"</string>
     <string name="include_link" msgid="827855767220339802">"Include link"</string>
     <string name="pinned" msgid="7623664001331394139">"Pinned"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Selectable image"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Selectable video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Selectable item"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Button"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Direct share targets"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"App suggestions"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App list"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copy text"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copy link"</string>
 </resources>
diff --git a/java/res/values-es-rUS/strings.xml b/java/res/values-es-rUS/strings.xml
index 923e9d36..fa61afab 100644
--- a/java/res/values-es-rUS/strings.xml
+++ b/java/res/values-es-rUS/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Excluir vínculo"</string>
     <string name="include_link" msgid="827855767220339802">"Incluir vínculo"</string>
     <string name="pinned" msgid="7623664001331394139">"Fijado"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Elemento <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Imagen seleccionable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video seleccionable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Elemento seleccionable"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Botón"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Objetivos de uso compartido directo"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Sugerencias de aplicaciones"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de apps"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copiar texto"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copiar vínculo"</string>
 </resources>
diff --git a/java/res/values-es/strings.xml b/java/res/values-es/strings.xml
index 7cb07c61..a7fa6a14 100644
--- a/java/res/values-es/strings.xml
+++ b/java/res/values-es/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # archivo}many{+ # archivos}other{+ # archivos}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{y # archivo más}many{y # archivos más}other{y # archivos más}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Compartir texto"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Compartiendo enlace"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Compartir enlace"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Compartiendo imagen}many{Compartiendo # imágenes}other{Compartiendo # imágenes}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Compartiendo vídeo}many{Compartiendo # vídeos}other{Compartiendo # vídeos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Compartiendo # archivo}many{Compartiendo # archivos}other{Compartiendo # archivos}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Excluir enlace"</string>
     <string name="include_link" msgid="827855767220339802">"Incluir enlace"</string>
     <string name="pinned" msgid="7623664001331394139">"Fijado"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Elemento <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Imagen seleccionable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo seleccionable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Elemento seleccionable"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Botón"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Objetivos de compartición directa"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Sugerencias de aplicaciones"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de aplicaciones"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copiar texto"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copiar enlace"</string>
 </resources>
diff --git a/java/res/values-et/strings.xml b/java/res/values-et/strings.xml
index 6a17f5b3..67584bec 100644
--- a/java/res/values-et/strings.xml
+++ b/java/res/values-et/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Välista link"</string>
     <string name="include_link" msgid="827855767220339802">"Kaasa link"</string>
     <string name="pinned" msgid="7623664001331394139">"Kinnitatud"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Üksus <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Valitav pilt"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Valitav video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Valitav üksus"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Nupp"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Otsejagamise sihtmärgid"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Rakenduste soovitused"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Rakenduste loend"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopeeri tekst"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopeeri link"</string>
 </resources>
diff --git a/java/res/values-eu/strings.xml b/java/res/values-eu/strings.xml
index e80edad4..fab9c44b 100644
--- a/java/res/values-eu/strings.xml
+++ b/java/res/values-eu/strings.xml
@@ -57,7 +57,7 @@
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{eta beste # fitxategi}other{eta beste # fitxategi}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Partekatuko den testua"</string>
     <string name="sharing_link" msgid="2307694372813942916">"Esteka partekatzen"</string>
-    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Irudia partekatuko da}other{# irudi partekatuko dira}}"</string>
+    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Irudia partekatzen}other{# irudi partekatzen}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Bideoa partekatzen}other{# bideo partekatzen}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# fitxategi partekatuko da}other{# fitxategi partekatuko dira}}"</string>
     <string name="select_items_to_share" msgid="1026071777275022579">"Hautatu partekatu beharreko elementuak"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Utzi kanpoan esteka"</string>
     <string name="include_link" msgid="827855767220339802">"Sartu esteka"</string>
     <string name="pinned" msgid="7623664001331394139">"Ainguratuta"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g>garren elementua"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Hauta daitekeen irudia"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Hauta daitekeen bideoa"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Hauta daitekeen elementua"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Botoia"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Partekatze zuzenen helburuak"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Aplikazioen iradokizunak"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Aplikazioen zerrenda"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopiatu testua"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopiatu esteka"</string>
 </resources>
diff --git a/java/res/values-fa/strings.xml b/java/res/values-fa/strings.xml
index 71386d35..597546b3 100644
--- a/java/res/values-fa/strings.xml
+++ b/java/res/values-fa/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"مستثنی کردن پیوند"</string>
     <string name="include_link" msgid="827855767220339802">"گنجاندن پیوند"</string>
     <string name="pinned" msgid="7623664001331394139">"سنجاق‌شده"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"مورد <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"تصویر قابل‌انتخاب"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ویدیو قابل‌انتخاب"</string>
     <string name="selectable_item" msgid="7557320816744205280">"مورد قابل‌انتخاب"</string>
     <string name="role_description_button" msgid="4537198530568333649">"دکمه"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"هدف‌های هم‌رسانی مستقیم"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"پیشنهادهای برنامه"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"فهرست برنامه"</string>
+    <string name="copy_text" msgid="1341801611046464360">"کپی کردن نوشتار"</string>
+    <string name="copy_link" msgid="3822142723771306592">"کپی کردن پیوند"</string>
 </resources>
diff --git a/java/res/values-fi/strings.xml b/java/res/values-fi/strings.xml
index 6938d4fa..12003636 100644
--- a/java/res/values-fi/strings.xml
+++ b/java/res/values-fi/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Jätä linkki pois"</string>
     <string name="include_link" msgid="827855767220339802">"Liitä linkki mukaan"</string>
     <string name="pinned" msgid="7623664001331394139">"Kiinnitetty"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Kohde <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Valittava kuva"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Valittava video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Valittava kohde"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Painike"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Suorajaon vastaanottajat"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Sovellusehdotukset"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Sovelluslista"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopioi teksti"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopioi linkki"</string>
 </resources>
diff --git a/java/res/values-fr-rCA/strings.xml b/java/res/values-fr-rCA/strings.xml
index 7fdda598..aa710ce8 100644
--- a/java/res/values-fr-rCA/strings.xml
+++ b/java/res/values-fr-rCA/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Exclure le lien"</string>
     <string name="include_link" msgid="827855767220339802">"Inclure le lien"</string>
     <string name="pinned" msgid="7623664001331394139">"Épinglée"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Élément <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Image sélectionnable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vidéo sélectionnable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Élément sélectionnable"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Bouton"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Cibles du partage direct"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Applis suggérées"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Liste d\'applis"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copier le texte"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copier le lien"</string>
 </resources>
diff --git a/java/res/values-fr/strings.xml b/java/res/values-fr/strings.xml
index 39d436a7..81c54ec2 100644
--- a/java/res/values-fr/strings.xml
+++ b/java/res/values-fr/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # fichier}one{+ # fichier}many{+ # fichiers}other{+ # fichiers}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ # autre fichier}one{+ # autre fichier}many{+ # autres fichiers}other{+ # autres fichiers}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Texte à partager"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Partager le lien"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Partage du lien..."</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Partager l\'image}one{Partager # image}many{Partager # d\'images}other{Partager # images}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Partage de la vidéo…}one{Partage de # vidéo…}many{Partage de # de vidéos…}other{Partage de # vidéos…}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Partage de # fichier}one{Partage de # fichier}many{Partage de # fichiers}other{Partage de # fichiers}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Exclure le lien"</string>
     <string name="include_link" msgid="827855767220339802">"Inclure le lien"</string>
     <string name="pinned" msgid="7623664001331394139">"Épinglée"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Élément <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Image sélectionnable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vidéo sélectionnable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Élément sélectionnable"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Bouton"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Cibles de partage direct"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Suggestions d\'applications"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Liste des applications"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copier le texte"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copier le lien"</string>
 </resources>
diff --git a/java/res/values-gl/strings.xml b/java/res/values-gl/strings.xml
index d45e982e..b173db33 100644
--- a/java/res/values-gl/strings.xml
+++ b/java/res/values-gl/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Excluír ligazón"</string>
     <string name="include_link" msgid="827855767220339802">"Incluír ligazón"</string>
     <string name="pinned" msgid="7623664001331394139">"Elemento fixado"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Elemento <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Imaxe seleccionable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo seleccionable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Elemento seleccionable"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Botón"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Destinatarios da función de compartir directamente"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Suxestións de aplicacións"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de aplicacións"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copiar o texto"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copiar a ligazón"</string>
 </resources>
diff --git a/java/res/values-gu/strings.xml b/java/res/values-gu/strings.xml
index d0e65a18..945486eb 100644
--- a/java/res/values-gu/strings.xml
+++ b/java/res/values-gu/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"લિંકને બાકાત કરો"</string>
     <string name="include_link" msgid="827855767220339802">"લિંક શામેલ કરો"</string>
     <string name="pinned" msgid="7623664001331394139">"પિન કરેલી"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"આઇટમ <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"પસંદ કરી શકાય તેવી છબી"</string>
     <string name="selectable_video" msgid="1271768647699300826">"પસંદ કરી શકાય તેવો વીડિયો"</string>
     <string name="selectable_item" msgid="7557320816744205280">"પસંદ કરી શકાય તેવી આઇટમ"</string>
     <string name="role_description_button" msgid="4537198530568333649">"બટન"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"સીધા શેર કરવાના લક્ષ્યો"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"ઍપના સૂચનો"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ઍપની સૂચિ"</string>
+    <string name="copy_text" msgid="1341801611046464360">"ટેક્સ્ટ કૉપિ કરો"</string>
+    <string name="copy_link" msgid="3822142723771306592">"લિંક કૉપિ કરો"</string>
 </resources>
diff --git a/java/res/values-hi/strings.xml b/java/res/values-hi/strings.xml
index 70da0c22..06e2030d 100644
--- a/java/res/values-hi/strings.xml
+++ b/java/res/values-hi/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"लिंक हटाएं"</string>
     <string name="include_link" msgid="827855767220339802">"लिंक जोड़ें"</string>
     <string name="pinned" msgid="7623664001331394139">"पिन किया गया"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"आइटम <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"ऐसी इमेज जिसे चुना जा सकता है"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ऐसा वीडियो जिसे चुना जा सकता है"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ऐसा आइटम जिसे चुना जा सकता है"</string>
     <string name="role_description_button" msgid="4537198530568333649">"बटन"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"सीधे तौर पर कॉन्टेंट शेयर करने के लिए चुने गए लोग या ग्रुप"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"सुझाए गए ऐप्लिकेशन"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ऐप्लिकेशन की सूची"</string>
+    <string name="copy_text" msgid="1341801611046464360">"टेक्स्ट कॉपी करें"</string>
+    <string name="copy_link" msgid="3822142723771306592">"लिंक कॉपी करें"</string>
 </resources>
diff --git a/java/res/values-hr/strings.xml b/java/res/values-hr/strings.xml
index c8f8c90d..1dbbef0a 100644
--- a/java/res/values-hr/strings.xml
+++ b/java/res/values-hr/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Isključi vezu"</string>
     <string name="include_link" msgid="827855767220339802">"Uključi vezu"</string>
     <string name="pinned" msgid="7623664001331394139">"Prikvačeno"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Stavka <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Slika koja se može odabrati"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Videozapis koji se može odabrati"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Stavka koja se može odabrati"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Gumb"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Osoba/skupina za izravno dijeljenje"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Prijedlozi aplikacija"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Popis aplikacija"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopiraj tekst"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopiraj vezu"</string>
 </resources>
diff --git a/java/res/values-hu/strings.xml b/java/res/values-hu/strings.xml
index a9e5e820..e719ef29 100644
--- a/java/res/values-hu/strings.xml
+++ b/java/res/values-hu/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Link eltávolítása"</string>
     <string name="include_link" msgid="827855767220339802">"Linkkel együtt"</string>
     <string name="pinned" msgid="7623664001331394139">"Kitűzve"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g>. elem"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Kijelölhető kép"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Kijelölhető videó"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Kijelölhető elem"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Gomb"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Közvetlen megosztási lehetőségek"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Alkalmazásjavaslatok"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Alkalmazáslista"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Szöveg másolása"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Link másolása"</string>
 </resources>
diff --git a/java/res/values-hy/strings.xml b/java/res/values-hy/strings.xml
index b0b0b235..751542b9 100644
--- a/java/res/values-hy/strings.xml
+++ b/java/res/values-hy/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Բացառել հղումը"</string>
     <string name="include_link" msgid="827855767220339802">"Ներառել հղումը"</string>
     <string name="pinned" msgid="7623664001331394139">"Ամրացված է"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Տարր <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Ընտրելու հնարավորությամբ պատկեր"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Ընտրելու հնարավորությամբ տեսանյութ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Ընտրելու հնարավորությամբ տարր"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Կոճակ"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Direct Share-ի ստացողներ"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Առաջարկվող հավելվածներ"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Հավելվածների ցուցակ"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Պատճենել տեքստ"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Պատճենել հղումը"</string>
 </resources>
diff --git a/java/res/values-in/strings.xml b/java/res/values-in/strings.xml
index 86828b7c..059b583e 100644
--- a/java/res/values-in/strings.xml
+++ b/java/res/values-in/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Kecualikan link"</string>
     <string name="include_link" msgid="827855767220339802">"Sertakan link"</string>
     <string name="pinned" msgid="7623664001331394139">"Disematkan"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Gambar yang dapat dipilih"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video yang dapat dipilih"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Item yang dapat dipilih"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Tombol"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Target berbagi langsung"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Saran aplikasi"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Daftar aplikasi"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Salin teks"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Salin link"</string>
 </resources>
diff --git a/java/res/values-is/strings.xml b/java/res/values-is/strings.xml
index 9125bae9..a53635d1 100644
--- a/java/res/values-is/strings.xml
+++ b/java/res/values-is/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # skrá}one{+ # skrá}other{+ # skrár}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ # skrá í viðbót}one{+ # skrá í viðbót}other{+ # skrár í viðbót}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Deilir texta"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Deilir tengli"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Deila tengli"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Deilir mynd}one{Deilir # mynd}other{Deilir # myndum}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Deilir myndskeiði}one{Deilir # myndskeiði}other{Deilir # myndskeiðum}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Deilir # skrá}one{Deilir # skrá}other{Deilir # skrám}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Útiloka tengil"</string>
     <string name="include_link" msgid="827855767220339802">"Hafa tengil með"</string>
     <string name="pinned" msgid="7623664001331394139">"Fest"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Atriði <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Mynd sem hægt er að velja"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeó sem hægt er að velja"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Atriði sem hægt er að velja"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Hnappur"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Deila beint með"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Tillögð forrit"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Forritalisti"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Afrita texta"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Afrita tengil"</string>
 </resources>
diff --git a/java/res/values-it/strings.xml b/java/res/values-it/strings.xml
index 7d0a7fa7..b97e10f7 100644
--- a/java/res/values-it/strings.xml
+++ b/java/res/values-it/strings.xml
@@ -59,7 +59,7 @@
     <string name="sharing_link" msgid="2307694372813942916">"Condivisione del link"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Condivisione dell\'immagine}many{Condivisione di # immagini}other{Condivisione di # immagini}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Condivisione del video…}many{Condivisione di # video…}other{Condivisione di # video…}}"</string>
-    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Condivisione di # file in corso…}many{Condivisione di # file in corso…}other{Condivisione di # file in corso…}}"</string>
+    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Condivisione di # file}many{Condivisione di # di file}other{Condivisione di # file}}"</string>
     <string name="select_items_to_share" msgid="1026071777275022579">"Seleziona gli elementi da condividere"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Condivisione immagine con testo in corso…}many{Condivisione # immagini con testo in corso…}other{Condivisione # immagini con testo in corso…}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Condivisione immagine con link}many{Condivisione # immagini con link}other{Condivisione # immagini con link}}"</string>
@@ -76,7 +76,7 @@
     <string name="file_preview_a11y_description" msgid="7397224827802410602">"Miniatura di anteprima del file"</string>
     <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"Nessuna persona consigliata per la condivisione"</string>
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"A questa app non è stata concessa l\'autorizzazione di registrazione, ma l\'app potrebbe acquisire l\'audio tramite questo dispositivo USB."</string>
-    <string name="resolver_personal_tab" msgid="1381052735324320565">"Personale"</string>
+    <string name="resolver_personal_tab" msgid="1381052735324320565">"Personali"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"Lavoro"</string>
     <string name="resolver_private_tab" msgid="3707548826254095157">"Privato"</string>
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"Visualizzazione personale"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Escludi link"</string>
     <string name="include_link" msgid="827855767220339802">"Includi link"</string>
     <string name="pinned" msgid="7623664001331394139">"Elemento fissato"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Elemento <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Immagine selezionabile"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video selezionabile"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Elemento selezionabile"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Pulsante"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Target di condivisione diretta"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"App suggerite"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Elenco di app"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copia testo"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copia link"</string>
 </resources>
diff --git a/java/res/values-iw/strings.xml b/java/res/values-iw/strings.xml
index 43921c78..e1971138 100644
--- a/java/res/values-iw/strings.xml
+++ b/java/res/values-iw/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ קובץ אחד}one{+ # קבצים}two{+ # קבצים}other{+ # קבצים}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{קובץ אחד נוסף}one{# קבצים נוספים}two{# קבצים נוספים}other{# קבצים נוספים}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"שיתוף טקסט"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"שיתוף קישור"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"קישור לשיתוף"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{שיתוף של תמונה}one{שיתוף של # תמונות}two{שיתוף של # תמונות}other{שיתוף של # תמונות}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{מתבצע שיתוף של סרטון}one{מתבצע שיתוף של # סרטונים}two{מתבצע שיתוף של # סרטונים}other{מתבצע שיתוף של # סרטונים}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{מתבצע שיתוף של קובץ אחד}one{מתבצע שיתוף של # קבצים}two{מתבצע שיתוף של # קבצים}other{מתבצע שיתוף של # קבצים}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"החרגת הקישור"</string>
     <string name="include_link" msgid="827855767220339802">"הכללת הקישור"</string>
     <string name="pinned" msgid="7623664001331394139">"מוצמד"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"פריט <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"תמונה שניתן לבחור"</string>
     <string name="selectable_video" msgid="1271768647699300826">"סרטון שניתן לבחור"</string>
     <string name="selectable_item" msgid="7557320816744205280">"פריט שניתן לבחור"</string>
     <string name="role_description_button" msgid="4537198530568333649">"כפתור"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"יעדים לשיתוף ישיר"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"הצעות לאפליקציות"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"רשימת האפליקציות"</string>
+    <string name="copy_text" msgid="1341801611046464360">"העתקת הטקסט"</string>
+    <string name="copy_link" msgid="3822142723771306592">"העתקת הקישור"</string>
 </resources>
diff --git a/java/res/values-ja/strings.xml b/java/res/values-ja/strings.xml
index 094106c3..666d8297 100644
--- a/java/res/values-ja/strings.xml
+++ b/java/res/values-ja/strings.xml
@@ -56,17 +56,17 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{他 # 件のファイル}other{他 # 件のファイル}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{その他 # ファイル}other{その他 # ファイル}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"テキストの共有"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"リンクを共有中"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"リンクを共有"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{1 枚の画像を共有します}other{# 枚の画像を共有します}}"</string>
-    <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{動画を共有中}other{# 個の動画を共有中}}"</string>
-    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# 個のファイルを共有中}other{# 個のファイルを共有中}}"</string>
+    <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{動画を共有します}other{# 本の動画を共有します}}"</string>
+    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# 件のファイルを共有します}other{# 件のファイルを共有します}}"</string>
     <string name="select_items_to_share" msgid="1026071777275022579">"共有するアイテムの選択"</string>
-    <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{テキスト付き画像を共有しています}other{テキスト付き画像を # 件共有しています}}"</string>
-    <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{リンク付き画像を共有しています}other{リンク付き画像を # 件共有しています}}"</string>
-    <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{テキスト付き動画を共有中}other{テキスト付き動画を # 件共有中}}"</string>
-    <string name="sharing_videos_with_link" msgid="6383290441403042321">"{count,plural, =1{リンク付き動画を共有中}other{リンク付き動画を # 件共有中}}"</string>
-    <string name="sharing_files_with_text" msgid="7331187260405018080">"{count,plural, =1{テキスト付きファイルを共有中}other{テキスト付きファイルを # 件共有中}}"</string>
-    <string name="sharing_files_with_link" msgid="6052797122358827239">"{count,plural, =1{リンク付きファイルを共有中}other{リンク付きファイルを # 件共有中}}"</string>
+    <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{テキスト付き画像を共有します}other{# 枚のテキスト付き画像を共有します}}"</string>
+    <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{リンク付き画像を共有します}other{# 枚のリンク付き画像を共有します}}"</string>
+    <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{テキスト付き動画を共有します}other{# 本のテキスト付き動画を共有します}}"</string>
+    <string name="sharing_videos_with_link" msgid="6383290441403042321">"{count,plural, =1{リンク付き動画を共有します}other{# 本のリンク付き動画を共有します}}"</string>
+    <string name="sharing_files_with_text" msgid="7331187260405018080">"{count,plural, =1{テキスト付きファイルを共有します}other{# 件のテキスト付きファイルを共有します}}"</string>
+    <string name="sharing_files_with_link" msgid="6052797122358827239">"{count,plural, =1{リンク付きファイルを共有します}other{# 件のリンク付きファイルを共有します}}"</string>
     <string name="sharing_album" msgid="191743129899503345">"アルバムの共有"</string>
     <string name="sharing_images_only" msgid="7762589767189955438">"{count,plural, =1{画像のみ}other{画像のみ}}"</string>
     <string name="sharing_videos_only" msgid="5549729252364968606">"{count,plural, =1{動画のみ}other{動画のみ}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"リンクを除外"</string>
     <string name="include_link" msgid="827855767220339802">"リンクを含める"</string>
     <string name="pinned" msgid="7623664001331394139">"固定されています"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"アイテム <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"選択可能な画像"</string>
     <string name="selectable_video" msgid="1271768647699300826">"選択可能な動画"</string>
     <string name="selectable_item" msgid="7557320816744205280">"選択可能なアイテム"</string>
     <string name="role_description_button" msgid="4537198530568333649">"ボタン"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"ダイレクト シェア ターゲット"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"アプリの候補"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"アプリリスト"</string>
+    <string name="copy_text" msgid="1341801611046464360">"テキストをコピー"</string>
+    <string name="copy_link" msgid="3822142723771306592">"リンクをコピー"</string>
 </resources>
diff --git a/java/res/values-ka/strings.xml b/java/res/values-ka/strings.xml
index e0951e39..ef11a5d4 100644
--- a/java/res/values-ka/strings.xml
+++ b/java/res/values-ka/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"ბმულის ამოღება"</string>
     <string name="include_link" msgid="827855767220339802">"ბმულის დართვა"</string>
     <string name="pinned" msgid="7623664001331394139">"ჩამაგრებული"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"ერთეული <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"არჩევადი სურათი"</string>
     <string name="selectable_video" msgid="1271768647699300826">"არჩევადი ვიდეო"</string>
     <string name="selectable_item" msgid="7557320816744205280">"არჩევადი ერთეული"</string>
     <string name="role_description_button" msgid="4537198530568333649">"ღილაკი"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"პირდაპირი გაზიარების მიზნები"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"აპის შეთავაზებები"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"აპების სია"</string>
+    <string name="copy_text" msgid="1341801611046464360">"ტექსტის კოპირება"</string>
+    <string name="copy_link" msgid="3822142723771306592">"ბმულის კოპირება"</string>
 </resources>
diff --git a/java/res/values-kk/strings.xml b/java/res/values-kk/strings.xml
index 99357ef6..b7f47e72 100644
--- a/java/res/values-kk/strings.xml
+++ b/java/res/values-kk/strings.xml
@@ -59,7 +59,7 @@
     <string name="sharing_link" msgid="2307694372813942916">"Сілтемені бөлісіп жатыр"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Сурет бөлісіп жатырсыз}other{# сурет бөлісіп жатырсыз}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Бейне бөлісіліп жатыр}other{# бейне бөлісіліп жатыр}}"</string>
-    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# файлды бөлісіп жатыр}other{# файлды бөлісіп жатыр}}"</string>
+    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# файлды бөлісіп жатырсыз}other{# файлды бөлісіп жатырсыз}}"</string>
     <string name="select_items_to_share" msgid="1026071777275022579">"Бөлісетін элементтерді таңдау"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Мәтіні бар сурет жіберу}other{Мәтіні бар # сурет жіберу}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Сілтемесі бар сурет жіберу}other{Сілтемесі бар # сурет жіберу}}"</string>
@@ -82,7 +82,7 @@
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"Жеке көру"</string>
     <string name="resolver_work_tab_accessibility" msgid="7581878836587799920">"Жұмыс деректерін көру"</string>
     <string name="resolver_private_tab_accessibility" msgid="2513122834337197252">"Құпия көрініс"</string>
-    <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"Әкімшіңіз бөгеген"</string>
+    <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"Әкімшіңіз блоктаған"</string>
     <string name="resolver_cant_share_with_work_apps_explanation" msgid="2984105853145456723">"Бұл контентті жұмыс қолданбаларымен бөлісу мүмкін емес."</string>
     <string name="resolver_cant_access_work_apps_explanation" msgid="1463093773348988122">"Бұл контентті жұмыс қолданбаларымен ашу мүмкін емес."</string>
     <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"Бұл контентті жеке қолданбалармен бөлісу мүмкін емес."</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Сілтемені шығару"</string>
     <string name="include_link" msgid="827855767220339802">"Сілтеме қосу"</string>
     <string name="pinned" msgid="7623664001331394139">"Бекітілген"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g>-элемент"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Таңдауға болатын сурет"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Таңдауға болатын бейне"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Таңдауға болатын элемент"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Түйме"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Тікелей бөлісу опциялары"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Қолданба ұсыныстары"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Қолданбалар тізімі"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Мәтінді көшіру"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Сілтемені көшіру"</string>
 </resources>
diff --git a/java/res/values-km/strings.xml b/java/res/values-km/strings.xml
index 29d80e96..81f2c1d2 100644
--- a/java/res/values-km/strings.xml
+++ b/java/res/values-km/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"មិនរួមបញ្ចូលតំណ"</string>
     <string name="include_link" msgid="827855767220339802">"រួមបញ្ចូល​តំណ"</string>
     <string name="pinned" msgid="7623664001331394139">"បាន​ខ្ទាស់"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"ធាតុទី <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"រូបភាពដែល​អាចជ្រើសរើសបាន"</string>
     <string name="selectable_video" msgid="1271768647699300826">"វីដេអូដែល​អាចជ្រើសរើសបាន"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ធាតុដែល​អាចជ្រើសរើសបាន"</string>
     <string name="role_description_button" msgid="4537198530568333649">"ប៊ូតុង"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"គោលដៅចែករំលែកដោយផ្ទាល់"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"ការណែនាំកម្មវិធី"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"បញ្ជីកម្មវិធី"</string>
+    <string name="copy_text" msgid="1341801611046464360">"ចម្លងអក្សរ"</string>
+    <string name="copy_link" msgid="3822142723771306592">"ចម្លង​តំណ"</string>
 </resources>
diff --git a/java/res/values-kn/strings.xml b/java/res/values-kn/strings.xml
index d777b6fa..4e6d1007 100644
--- a/java/res/values-kn/strings.xml
+++ b/java/res/values-kn/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"ಲಿಂಕ್ ಹೊರತುಪಡಿಸಿ"</string>
     <string name="include_link" msgid="827855767220339802">"ಲಿಂಕ್ ಸೇರಿಸಿ"</string>
     <string name="pinned" msgid="7623664001331394139">"ಪಿನ್‌ ಮಾಡಲಾಗಿದೆ"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g> ಐಟಂ"</string>
     <string name="selectable_image" msgid="3157858923437182271">"ಆಯ್ಕೆಮಾಡಬಹುದಾದ ಚಿತ್ರ"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ಆಯ್ಕೆ ಮಾಡಬಹುದಾದ ವೀಡಿಯೊ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ಆಯ್ಕೆ ಮಾಡಬಹುದಾದ ಐಟಂ"</string>
     <string name="role_description_button" msgid="4537198530568333649">"ಬಟನ್"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"ನೇರ ಹಂಚಿಕೊಳ್ಳುವಿಕೆ ಟಾರ್ಗೆಟ್‌ಗಳು"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"ಆ್ಯಪ್ ಸಲಹೆಗಳು"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ಆ್ಯಪ್ ಪಟ್ಟಿ"</string>
+    <string name="copy_text" msgid="1341801611046464360">"ಪಠ್ಯವನ್ನು ಕಾಪಿ ಮಾಡಿ"</string>
+    <string name="copy_link" msgid="3822142723771306592">"ಲಿಂಕ್ ಅನ್ನು ಕಾಪಿ ಮಾಡಿ"</string>
 </resources>
diff --git a/java/res/values-ko/strings.xml b/java/res/values-ko/strings.xml
index 0ab0cefb..590baa66 100644
--- a/java/res/values-ko/strings.xml
+++ b/java/res/values-ko/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"링크 제외"</string>
     <string name="include_link" msgid="827855767220339802">"링크 포함"</string>
     <string name="pinned" msgid="7623664001331394139">"고정됨"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"항목 <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"선택 가능한 이미지"</string>
     <string name="selectable_video" msgid="1271768647699300826">"선택 가능한 동영상"</string>
     <string name="selectable_item" msgid="7557320816744205280">"선택 가능한 항목"</string>
     <string name="role_description_button" msgid="4537198530568333649">"버튼"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"직접 공유 타겟"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"앱 제안"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"앱 목록"</string>
+    <string name="copy_text" msgid="1341801611046464360">"텍스트 복사"</string>
+    <string name="copy_link" msgid="3822142723771306592">"링크 복사"</string>
 </resources>
diff --git a/java/res/values-ky/strings.xml b/java/res/values-ky/strings.xml
index 7de1593d..0f69ebe9 100644
--- a/java/res/values-ky/strings.xml
+++ b/java/res/values-ky/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Шилтемени чыгарып салуу"</string>
     <string name="include_link" msgid="827855767220339802">"Шилтеме кошуу"</string>
     <string name="pinned" msgid="7623664001331394139">"Кадалган"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g>-нерсе"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Тандала турган сүрөт"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Тандала турган видео"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Тандала турган нерсе"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Баскыч"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Түздөн-түз бөлүшүлгөндөрдү алуучулар"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Сунушталган колдонмолор"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Колдонмолордун тизмеси"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Текстти көчүрүү"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Шилтемени көчүрүү"</string>
 </resources>
diff --git a/java/res/values-lo/strings.xml b/java/res/values-lo/strings.xml
index 9481a9ae..f8fcbfcc 100644
--- a/java/res/values-lo/strings.xml
+++ b/java/res/values-lo/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"ບໍ່ຮວມລິ້ງ"</string>
     <string name="include_link" msgid="827855767220339802">"ຮວມລິ້ງ"</string>
     <string name="pinned" msgid="7623664001331394139">"ປັກໝຸດແລ້ວ"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"ລາຍການ <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"ຮູບທີ່ເລືອກໄດ້"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ວິດີໂອທີ່ເລືອກໄດ້"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ລາຍການທີ່ເລືອກໄດ້"</string>
     <string name="role_description_button" msgid="4537198530568333649">"ປຸ່ມ"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"ເປົ້າໝາຍແບ່ງປັນໂດຍກົງ"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"ການແນະນຳແອັບ"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ລາຍການແອັບ"</string>
+    <string name="copy_text" msgid="1341801611046464360">"ສຳເນົາຂໍ້ຄວາມ"</string>
+    <string name="copy_link" msgid="3822142723771306592">"ສຳເນົາລິ້ງ"</string>
 </resources>
diff --git a/java/res/values-lt/strings.xml b/java/res/values-lt/strings.xml
index f1a0494d..f46f88e5 100644
--- a/java/res/values-lt/strings.xml
+++ b/java/res/values-lt/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Išskirti nuorodą"</string>
     <string name="include_link" msgid="827855767220339802">"Įtraukti nuorodą"</string>
     <string name="pinned" msgid="7623664001331394139">"Prisegta"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g> elementas"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Pasirenkamas vaizdas"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Pasirenkamas vaizdo įrašas"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Pasirenkamas elementas"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Mygtukas"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Tiesioginio bendrinimo paskirties vietos"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Siūlomos programos"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Programų sąrašas"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopijuoti tekstą"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopijuoti nuorodą"</string>
 </resources>
diff --git a/java/res/values-lv/strings.xml b/java/res/values-lv/strings.xml
index 5fed4d43..649533ab 100644
--- a/java/res/values-lv/strings.xml
+++ b/java/res/values-lv/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Izslēgt saiti"</string>
     <string name="include_link" msgid="827855767220339802">"Iekļaut saiti"</string>
     <string name="pinned" msgid="7623664001331394139">"Piespraustās"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g>. vienums"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Atlasāms attēls"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Atlasāms video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Atlasāms vienums"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Poga"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Tiešās kopīgošanas adresāti"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Ieteicamās lietotnes"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lietotņu saraksts"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopēt tekstu"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopēt saiti"</string>
 </resources>
diff --git a/java/res/values-mk/strings.xml b/java/res/values-mk/strings.xml
index 2ab3c072..3204ff91 100644
--- a/java/res/values-mk/strings.xml
+++ b/java/res/values-mk/strings.xml
@@ -85,7 +85,7 @@
     <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"Блокирано од IT-администраторот"</string>
     <string name="resolver_cant_share_with_work_apps_explanation" msgid="2984105853145456723">"Овие содржини не може да се споделуваат со работни апликации"</string>
     <string name="resolver_cant_access_work_apps_explanation" msgid="1463093773348988122">"Овие содржини не може да се отвораат со работни апликации"</string>
-    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"Овие содржини не може да се споделуваат со лични апликации"</string>
+    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"Содржиниве не може да се споделуваат со лични апликации"</string>
     <string name="resolver_cant_access_personal_apps_explanation" msgid="6209543716289792706">"Овие содржини не може да се отвораат со лични апликации"</string>
     <string name="resolver_cant_share_with_private_apps_explanation" msgid="1781980997411434697">"Овие содржини не може да се споделуваат со приватни апликации"</string>
     <string name="resolver_cant_access_private_apps_explanation" msgid="5978609934961648342">"Овие содржини не може да се отвораат со лични апликации"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Исклучи линк"</string>
     <string name="include_link" msgid="827855767220339802">"Вклучи линк"</string>
     <string name="pinned" msgid="7623664001331394139">"Закачено"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Ставка <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Слика што може да се избере"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Видео што може да се избере"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Ставка што може да се избере"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Копче"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Директни цели на споделување"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Предлози за апликации"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Список со апликации"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Копирај го текстот"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Копирај го линкот"</string>
 </resources>
diff --git a/java/res/values-ml/strings.xml b/java/res/values-ml/strings.xml
index 6318a101..63ddb262 100644
--- a/java/res/values-ml/strings.xml
+++ b/java/res/values-ml/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"ലിങ്ക് ഒഴിവാക്കുക"</string>
     <string name="include_link" msgid="827855767220339802">"ലിങ്ക് ഉൾപ്പെടുത്തുക"</string>
     <string name="pinned" msgid="7623664001331394139">"പിൻ ചെയ്‌തത്"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"ഇനം <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"തിരഞ്ഞെടുക്കാവുന്ന ചിത്രം"</string>
     <string name="selectable_video" msgid="1271768647699300826">"തിരഞ്ഞെടുക്കാവുന്ന വീഡിയോ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"തിരഞ്ഞെടുക്കാവുന്ന ഇനം"</string>
     <string name="role_description_button" msgid="4537198530568333649">"ബട്ടൺ"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"നേരിട്ടുള്ള പങ്കിടൽ ടാർഗെറ്റുകൾ"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"ആപ്പ് നിർദ്ദേശങ്ങൾ"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ആപ്പ് ലിസ്റ്റ്"</string>
+    <string name="copy_text" msgid="1341801611046464360">"ടെക്‌സ്റ്റ് പകർത്തുക"</string>
+    <string name="copy_link" msgid="3822142723771306592">"ലിങ്ക് പകർത്തുക"</string>
 </resources>
diff --git a/java/res/values-mn/strings.xml b/java/res/values-mn/strings.xml
index 8dc3cd58..4ce3b15e 100644
--- a/java/res/values-mn/strings.xml
+++ b/java/res/values-mn/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Холбоосыг хасах"</string>
     <string name="include_link" msgid="827855767220339802">"Холбоосыг оруулах"</string>
     <string name="pinned" msgid="7623664001331394139">"Бэхэлсэн"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g> зүйл"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Сонгох боломжтой зураг"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Сонгох боломжтой видео"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Сонгох боломжтой зүйл"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Товч"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Шууд хуваалцах сонголтууд"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Санал болгож буй аппууд"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Аппын жагсаалт"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Текстийг хуулах"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Холбоосыг хуулах"</string>
 </resources>
diff --git a/java/res/values-mr/strings.xml b/java/res/values-mr/strings.xml
index 5e54a61a..dce1241b 100644
--- a/java/res/values-mr/strings.xml
+++ b/java/res/values-mr/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"लिंक वगळा"</string>
     <string name="include_link" msgid="827855767220339802">"लिंक समाविष्ट करा"</string>
     <string name="pinned" msgid="7623664001331394139">"पिन केलेली"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"आयटम <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"निवडण्यायोग्य इमेज"</string>
     <string name="selectable_video" msgid="1271768647699300826">"निवडण्यायोग्य व्हिडिओ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"निवडण्यायोग्य आयटम"</string>
     <string name="role_description_button" msgid="4537198530568333649">"बटण"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"थेट शेअर करा लक्ष्ये"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"अ‍ॅप सूचना"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"अ‍ॅप सूची"</string>
+    <string name="copy_text" msgid="1341801611046464360">"मजकूर कॉपी करा"</string>
+    <string name="copy_link" msgid="3822142723771306592">"लिंक कॉपी करा"</string>
 </resources>
diff --git a/java/res/values-ms/strings.xml b/java/res/values-ms/strings.xml
index b6dca50f..300a763f 100644
--- a/java/res/values-ms/strings.xml
+++ b/java/res/values-ms/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Kecualikan pautan"</string>
     <string name="include_link" msgid="827855767220339802">"Sertakan pautan"</string>
     <string name="pinned" msgid="7623664001331394139">"Disemat"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Imej yang boleh dipilih"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video yang boleh dipilih"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Item yang boleh dipilih"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Butang"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Sasaran perkongsian langsung"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Cadangan apl"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Senarai apl"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Salin teks"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Salin pautan"</string>
 </resources>
diff --git a/java/res/values-my/strings.xml b/java/res/values-my/strings.xml
index af596656..6a5f559b 100644
--- a/java/res/values-my/strings.xml
+++ b/java/res/values-my/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"လင့်ခ် ဖယ်ထုတ်ရန်"</string>
     <string name="include_link" msgid="827855767220339802">"လင့်ခ်ထည့်သွင်းရန်"</string>
     <string name="pinned" msgid="7623664001331394139">"ပင်ထိုးထားသည်"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"အကြောင်းအရာ <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"ရွေးချယ်နိုင်သောပုံ"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ရွေးချယ်နိုင်သော ဗီဒီယို"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ရွေးချယ်နိုင်သောအရာ"</string>
     <string name="role_description_button" msgid="4537198530568333649">"ခလုတ်"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"တိုက်ရိုက်မျှဝေသည့် ပစ်မှတ်များ"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"အက်ပ်အကြံပြုချက်များ"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"အက်ပ်စာရင်း"</string>
+    <string name="copy_text" msgid="1341801611046464360">"စာသားကူးရန်"</string>
+    <string name="copy_link" msgid="3822142723771306592">"လင့်ခ်ကူးရန်"</string>
 </resources>
diff --git a/java/res/values-nb/strings.xml b/java/res/values-nb/strings.xml
index bd31a926..7381eaa8 100644
--- a/java/res/values-nb/strings.xml
+++ b/java/res/values-nb/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Ekskluder linken"</string>
     <string name="include_link" msgid="827855767220339802">"Inkluder linken"</string>
     <string name="pinned" msgid="7623664001331394139">"Festet"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Element <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Bilde som kan velges"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video som kan velges"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Element som kan velges"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Knapp"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Direkte delingsmål"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Appforslag"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Appliste"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopier teksten"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopier linken"</string>
 </resources>
diff --git a/java/res/values-ne/strings.xml b/java/res/values-ne/strings.xml
index 620e402c..18744d21 100644
--- a/java/res/values-ne/strings.xml
+++ b/java/res/values-ne/strings.xml
@@ -59,7 +59,7 @@
     <string name="sharing_link" msgid="2307694372813942916">"लिंक सेयर गरिँदै छ"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{फोटो सेयर गरिँदै छ}other{# वटा फोटो सेयर गरिँदै छ}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{भिडियो सेयर गरिँदै छ}other{# वटा भिडियो सेयर गरिँदै छ}}"</string>
-    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# वटा फाइल सेयर गरिँदै छ}other{# वटा फाइल सेयर गरिँदै छ}}"</string>
+    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# फाइल सेयर गरिँदै छ}other{# वटा फाइल सेयर गरिँदै छन्}}"</string>
     <string name="select_items_to_share" msgid="1026071777275022579">"आफूले सेयर गर्न चाहेका सामग्री चयन गर्नुहोस्"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{टेक्स्ट भएको फोटो सेयर गरिँदै छ}other{टेक्स्ट भएका # वटा फोटो सेयर गरिँदै छन्}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{लिंक भएको फोटो सेयर गरिँदै छ}other{लिंक भएका # वटा फोटो सेयर गरिँदै छन्}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"लिंक हटाउनुहोस्"</string>
     <string name="include_link" msgid="827855767220339802">"लिंक समावेश गर्नुहोस्"</string>
     <string name="pinned" msgid="7623664001331394139">"पिन गरिएको"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"वस्तु <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"चयन गर्न मिल्ने फोटो"</string>
     <string name="selectable_video" msgid="1271768647699300826">"चयन गर्न मिल्ने भिडियो"</string>
     <string name="selectable_item" msgid="7557320816744205280">"चयन गर्न मिल्ने वस्तु"</string>
     <string name="role_description_button" msgid="4537198530568333649">"बटन"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"सामग्री सीधै सेयर गर्नका निम्ति चयन गरिएका व्यक्ति वा समूहहरू"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"सिफारिस गरिएका एपहरू"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"एपहरूको सूची"</string>
+    <string name="copy_text" msgid="1341801611046464360">"टेक्स्ट कपी गर्नुहोस्"</string>
+    <string name="copy_link" msgid="3822142723771306592">"लिंक कपी गर्नुहोस्"</string>
 </resources>
diff --git a/java/res/values-nl/strings.xml b/java/res/values-nl/strings.xml
index 54123bef..de8050b9 100644
--- a/java/res/values-nl/strings.xml
+++ b/java/res/values-nl/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Link uitsluiten"</string>
     <string name="include_link" msgid="827855767220339802">"Link opnemen"</string>
     <string name="pinned" msgid="7623664001331394139">"Vastgezet"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Selecteerbare afbeelding"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Selecteerbare video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Selecteerbaar item"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Knop"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Doelen voor direct delen"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"App-suggesties"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"App-lijst"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Tekst kopiëren"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Link kopiëren"</string>
 </resources>
diff --git a/java/res/values-or/strings.xml b/java/res/values-or/strings.xml
index 785acbe1..c724f896 100644
--- a/java/res/values-or/strings.xml
+++ b/java/res/values-or/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"ଲିଙ୍କକୁ ବାଦ ଦିଅନ୍ତୁ"</string>
     <string name="include_link" msgid="827855767220339802">"ଲିଙ୍କକୁ ଅନ୍ତର୍ଭୁକ୍ତ କରନ୍ତୁ"</string>
     <string name="pinned" msgid="7623664001331394139">"ପିନ କରାଯାଇଛି"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"ଆଇଟମ <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"ଚୟନ କରାଯାଇପାରୁଥିବା ଇମେଜ"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ଚୟନ କରାଯାଇପାରୁଥିବା ଭିଡିଓ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ଚୟନ କରାଯାଇପାରୁଥିବା ଆଇଟମ"</string>
     <string name="role_description_button" msgid="4537198530568333649">"ବଟନ"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"ଡାଇରେକ୍ଟ ସେୟାର ଟାର୍ଗେଟ"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"ଆପ ପରାମର୍ଶ"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ଆପ ତାଲିକା"</string>
+    <string name="copy_text" msgid="1341801611046464360">"ଟେକ୍ସଟ କପି କରନ୍ତୁ"</string>
+    <string name="copy_link" msgid="3822142723771306592">"ଲିଙ୍କ କପି କରନ୍ତୁ"</string>
 </resources>
diff --git a/java/res/values-pa/strings.xml b/java/res/values-pa/strings.xml
index 8b9f528c..32dc39de 100644
--- a/java/res/values-pa/strings.xml
+++ b/java/res/values-pa/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"ਲਿੰਕ ਨੂੰ ਸ਼ਾਮਲ ਨਾ ਕਰੋ"</string>
     <string name="include_link" msgid="827855767220339802">"ਲਿੰਕ ਸ਼ਾਮਲ ਕਰੋ"</string>
     <string name="pinned" msgid="7623664001331394139">"ਪਿੰਨ ਕੀਤਾ ਗਿਆ"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"ਆਈਟਮ <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"ਚੁਣਨਯੋਗ ਚਿੱਤਰ"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ਚੁਣਨਯੋਗ ਵੀਡੀਓ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ਚੁਣਨਯੋਗ ਆਈਟਮ"</string>
     <string name="role_description_button" msgid="4537198530568333649">"ਬਟਨ"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"ਸਿੱਧੇ ਤੌਰ \'ਤੇ ਸਾਂਝਾ ਕਰਨ ਲਈ ਟਾਰਗੇਟ ਗਰੁੱਪ"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"ਐਪ ਸੁਝਾਅ"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ਐਪ ਸੂਚੀ"</string>
+    <string name="copy_text" msgid="1341801611046464360">"ਲਿਖਤ ਕਾਪੀ ਕਰੋ"</string>
+    <string name="copy_link" msgid="3822142723771306592">"ਲਿੰਕ ਕਾਪੀ ਕਰੋ"</string>
 </resources>
diff --git a/java/res/values-pl/strings.xml b/java/res/values-pl/strings.xml
index 3de2b1f4..e11ffb35 100644
--- a/java/res/values-pl/strings.xml
+++ b/java/res/values-pl/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Wyklucz link"</string>
     <string name="include_link" msgid="827855767220339802">"Dołącz link"</string>
     <string name="pinned" msgid="7623664001331394139">"Przypięte"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Element <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Obraz do wyboru"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Film do wyboru"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Element do wyboru"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Przycisk"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Odbiorcy udostępniania bezpośredniego"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Sugestie aplikacji"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista aplikacji"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Skopiuj tekst"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Skopiuj link"</string>
 </resources>
diff --git a/java/res/values-pt-rBR/strings.xml b/java/res/values-pt-rBR/strings.xml
index 5ed57493..fd1f1863 100644
--- a/java/res/values-pt-rBR/strings.xml
+++ b/java/res/values-pt-rBR/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Excluir link"</string>
     <string name="include_link" msgid="827855767220339802">"Incluir link"</string>
     <string name="pinned" msgid="7623664001331394139">"Fixada"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Imagem selecionável"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo selecionável"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Item selecionável"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Botão"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Destinos de compartilhamento direto"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Sugestões de apps"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de apps"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copiar texto"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copiar link"</string>
 </resources>
diff --git a/java/res/values-pt-rPT/strings.xml b/java/res/values-pt-rPT/strings.xml
index 73d12957..c4be78e4 100644
--- a/java/res/values-pt-rPT/strings.xml
+++ b/java/res/values-pt-rPT/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Excluir link"</string>
     <string name="include_link" msgid="827855767220339802">"Incluir link"</string>
     <string name="pinned" msgid="7623664001331394139">"Afixada"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Imagem selecionável"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo selecionável"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Item selecionável"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Botão"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Segmentações de partilha direta"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Sugestões de apps"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de apps"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copiar texto"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copiar link"</string>
 </resources>
diff --git a/java/res/values-pt/strings.xml b/java/res/values-pt/strings.xml
index 5ed57493..fd1f1863 100644
--- a/java/res/values-pt/strings.xml
+++ b/java/res/values-pt/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Excluir link"</string>
     <string name="include_link" msgid="827855767220339802">"Incluir link"</string>
     <string name="pinned" msgid="7623664001331394139">"Fixada"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Imagem selecionável"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo selecionável"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Item selecionável"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Botão"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Destinos de compartilhamento direto"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Sugestões de apps"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista de apps"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copiar texto"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copiar link"</string>
 </resources>
diff --git a/java/res/values-ro/strings.xml b/java/res/values-ro/strings.xml
index 7c8816b6..faa360f4 100644
--- a/java/res/values-ro/strings.xml
+++ b/java/res/values-ro/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Exclude linkul"</string>
     <string name="include_link" msgid="827855767220339802">"Include linkul"</string>
     <string name="pinned" msgid="7623664001331394139">"Fixat"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Elementul <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Imagine care poate fi selectată"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Videoclip care poate fi selectat"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Articol care poate fi selectat"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Buton"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Destinații de distribuire directă"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Sugestii de aplicații"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista cu aplicații"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Copiază textul"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Copiază linkul"</string>
 </resources>
diff --git a/java/res/values-ru/strings.xml b/java/res/values-ru/strings.xml
index 7a05c9d0..637a6bf8 100644
--- a/java/res/values-ru/strings.xml
+++ b/java/res/values-ru/strings.xml
@@ -59,7 +59,7 @@
     <string name="sharing_link" msgid="2307694372813942916">"Отправка ссылки"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Отправка изображения}one{Отправка # изображения}few{Отправка # изображений}many{Отправка # изображений}other{Отправка # изображения}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Отправка видео}one{Отправка # видео}few{Отправка # видео}many{Отправка # видео}other{Отправка # видео}}"</string>
-    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Предоставляется доступ к # файлу}one{Предоставляется доступ к # файлу}few{Предоставляется доступ к # файлам}many{Предоставляется доступ к # файлам}other{Предоставляется доступ к # файла}}"</string>
+    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Поделиться # файлом}one{Поделиться # файлом}few{Поделиться # файлами}many{Поделиться # файлом}other{Поделиться # файла}}"</string>
     <string name="select_items_to_share" msgid="1026071777275022579">"Выберите объекты для отправки"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Отправка изображения с текстом}one{Отправка # изображения с текстом}few{Отправка # изображений с текстом}many{Отправка # изображений с текстом}other{Отправка # изображения с текстом}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Отправка изображения со ссылкой}one{Отправка # изображения со ссылкой}few{Отправка # изображений со ссылкой}many{Отправка # изображений со ссылкой}other{Отправка # изображения со ссылкой}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Исключить ссылку"</string>
     <string name="include_link" msgid="827855767220339802">"Вернуть ссылку"</string>
     <string name="pinned" msgid="7623664001331394139">"Закреплено"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Элемент <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Изображение, которое можно выбрать"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Видео, которое можно выбрать"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Объект, который можно выбрать"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Кнопка"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Получатели Direct Share"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Рекомендуемые приложения"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Список приложений"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Копировать текст"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Копировать ссылку"</string>
 </resources>
diff --git a/java/res/values-si/strings.xml b/java/res/values-si/strings.xml
index 19af7794..482f0510 100644
--- a/java/res/values-si/strings.xml
+++ b/java/res/values-si/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"සබැඳිය බැහැර කරන්න"</string>
     <string name="include_link" msgid="827855767220339802">"සබැඳිය ඇතුළත් කරන්න"</string>
     <string name="pinned" msgid="7623664001331394139">"අමුණා ඇත"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"අයිතම <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"තෝරා ගත හැකි රූපය"</string>
     <string name="selectable_video" msgid="1271768647699300826">"තෝරා ගත හැකි වීඩියෝව"</string>
     <string name="selectable_item" msgid="7557320816744205280">"තෝරා ගත හැකි අයිතමය"</string>
     <string name="role_description_button" msgid="4537198530568333649">"බොත්තම"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"සෘජු බෙදා ගැනීමේ ඉලක්ක"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"යෙදුම් යෝජනා"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"යෙදුම් ලැයිස්තුව"</string>
+    <string name="copy_text" msgid="1341801611046464360">"පෙළ පිටපත් කරන්න"</string>
+    <string name="copy_link" msgid="3822142723771306592">"සබැඳිය පිටපත් කරන්න"</string>
 </resources>
diff --git a/java/res/values-sk/strings.xml b/java/res/values-sk/strings.xml
index 36898690..c3a08830 100644
--- a/java/res/values-sk/strings.xml
+++ b/java/res/values-sk/strings.xml
@@ -56,13 +56,13 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # súbor}few{+ # súbory}many{+ # files}other{+ # súborov}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{a # ďalší súbor}few{a # ďalšie súbory}many{+ # more files}other{a # ďalších súborov}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Zdieľanie textu"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Zdieľa sa odkaz"</string>
-    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Zdieľanie obrázku}few{Zdieľanie # obrázkov}many{Sharing # images}other{Zdieľanie # obrázkov}}"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Zdieľanie odkazu"</string>
+    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Zdieľanie obrázka}few{Zdieľanie # obrázkov}many{Sharing # images}other{Zdieľanie # obrázkov}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Zdieľa sa video}few{Zdieľajú sa # videá}many{Sharing # videos}other{Zdieľa sa # videí}}"</string>
-    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Zdieľa sa # súbor}few{Zdieľajú sa # súbory}many{Sharing # files}other{Zdieľa sa # súborov}}"</string>
+    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Zdieľanie # súboru}few{Zdieľanie # súborov}many{Sharing # files}other{Zdieľanie # súborov}}"</string>
     <string name="select_items_to_share" msgid="1026071777275022579">"Vyberte položky na zdieľanie"</string>
-    <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Zdieľa sa obrázok s textom}few{Zdieľajú sa # obrázky s textom}many{Sharing # images with text}other{Zdieľa sa # obrázkov s textom}}"</string>
-    <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Zdieľa sa obrázok s odkazom}few{Zdieľajú sa # obrázky s odkazom}many{Sharing # images with link}other{Zdieľa sa # obrázkov s odkazom}}"</string>
+    <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Zdieľanie obrázka s textom}few{Zdieľanie # obrázkov s textom}many{Sharing # images with text}other{Zdieľanie # obrázkov s textom}}"</string>
+    <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Zdieľanie obrázka s odkazom}few{Zdieľanie # obrázkov s odkazom}many{Sharing # images with link}other{Zdieľanie # obrázkov s odkazom}}"</string>
     <string name="sharing_videos_with_text" msgid="4169898442482118146">"{count,plural, =1{Zdieľa sa video s textom}few{Zdieľajú sa # videá s textom}many{Sharing # videos with text}other{Zdieľa sa # videí s textom}}"</string>
     <string name="sharing_videos_with_link" msgid="6383290441403042321">"{count,plural, =1{Zdieľa sa video s odkazom}few{Zdieľajú sa # videá s odkazom}many{Sharing # videos with link}other{Zdieľa sa # videí s odkazom}}"</string>
     <string name="sharing_files_with_text" msgid="7331187260405018080">"{count,plural, =1{Zdieľa sa súbor s textom}few{Zdieľajú sa # súbory s textom}many{Sharing # files with text}other{Zdieľa sa # súborov s textom}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Vylúčiť odkaz"</string>
     <string name="include_link" msgid="827855767220339802">"Zahrnúť odkaz"</string>
     <string name="pinned" msgid="7623664001331394139">"Pripnuté"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g>. položka"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Vybrateľný obrázok"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vybrateľné video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Vybrateľná položka"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Tlačidlo"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Ciele priameho zdieľania"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Návrhy aplikácií"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Zoznam aplikácií"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopírovať text"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopírovať odkaz"</string>
 </resources>
diff --git a/java/res/values-sl/strings.xml b/java/res/values-sl/strings.xml
index 714ba171..f5f77a1f 100644
--- a/java/res/values-sl/strings.xml
+++ b/java/res/values-sl/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Izloči povezavo"</string>
     <string name="include_link" msgid="827855767220339802">"Vključi povezavo"</string>
     <string name="pinned" msgid="7623664001331394139">"Pripeto"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Element <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Slika, ki jo je mogoče izbrati."</string>
     <string name="selectable_video" msgid="1271768647699300826">"Videoposnetek, ki ga je mogoče izbrati."</string>
     <string name="selectable_item" msgid="7557320816744205280">"Element, ki ga je mogoče izbrati."</string>
     <string name="role_description_button" msgid="4537198530568333649">"Gumb"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Naslovniki neposrednega deljenja"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Predlagane aplikacije"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Seznam aplikacij"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopiraj besedilo"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopiraj povezavo"</string>
 </resources>
diff --git a/java/res/values-sq/strings.xml b/java/res/values-sq/strings.xml
index db24392a..b5383962 100644
--- a/java/res/values-sq/strings.xml
+++ b/java/res/values-sq/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Përjashto lidhjen"</string>
     <string name="include_link" msgid="827855767220339802">"Përfshi lidhjen"</string>
     <string name="pinned" msgid="7623664001331394139">"U gozhdua"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Artikulli <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Imazh që mund të zgjidhet"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video që mund të zgjidhet"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Artikull që mund të zgjidhet"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Buton"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Objektivat e ndarjes së drejtpërdrejtë"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Aplikacionet e sugjeruara"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Lista e aplikacioneve"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopjo tekstin"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopjo lidhjen"</string>
 </resources>
diff --git a/java/res/values-sr/strings.xml b/java/res/values-sr/strings.xml
index 8591ef7d..7a45c4eb 100644
--- a/java/res/values-sr/strings.xml
+++ b/java/res/values-sr/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{и још # фајл}one{и још # фајл}few{и још # фајла}other{и још # фајлова}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ још # фајл}one{+ још # фајл}few{+ још # фајла}other{+ још # фајлова}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Дели се текст"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Дели се линк"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Дељење линка"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Дељење слике}one{Дељење # слике}few{Дељење # слике}other{Дељење # слика}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Дели се видео}one{Дели се # видео}few{Деле се # видео снимка}other{Дели се # видеа}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Дели се # фајл}one{Дели се # фајл}few{Деле се # фајла}other{Дели се # фајлова}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Изузми линк"</string>
     <string name="include_link" msgid="827855767220339802">"Уврсти линк"</string>
     <string name="pinned" msgid="7623664001331394139">"Закачено"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Ставка <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Слика која може да се изабере"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Видео који може да се изабере"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Ставка која може да се изабере"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Дугме"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Циљеви директног дељења"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Предлози апликација"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Листа апликација"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Копирај текст"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Копирај линк"</string>
 </resources>
diff --git a/java/res/values-sv/strings.xml b/java/res/values-sv/strings.xml
index 6810faa7..ec838aee 100644
--- a/java/res/values-sv/strings.xml
+++ b/java/res/values-sv/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Uteslut länk"</string>
     <string name="include_link" msgid="827855767220339802">"Inkludera länk"</string>
     <string name="pinned" msgid="7623664001331394139">"Fäst"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Objekt <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Bild som kan markeras"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video som kan markeras"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Objekt som kan markeras"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Knapp"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Personer/grupper att dela direkt med"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Appförslag"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Applista"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopiera text"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopiera länk"</string>
 </resources>
diff --git a/java/res/values-sw/strings.xml b/java/res/values-sw/strings.xml
index 77b83e99..f6f2c63a 100644
--- a/java/res/values-sw/strings.xml
+++ b/java/res/values-sw/strings.xml
@@ -57,9 +57,9 @@
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{Faili nyingine #}other{Faili zingine #}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Kutuma maandishi"</string>
     <string name="sharing_link" msgid="2307694372813942916">"Inatuma kiungo"</string>
-    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Kutuma picha}other{Kutuma picha #}}"</string>
+    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Inatuma picha}other{Inatuma picha #}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Inatuma video}other{Inatuma video #}}"</string>
-    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Inashiriki faili #}other{Inashiriki faili #}}"</string>
+    <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Inatuma faili #}other{Inatuma faili #}}"</string>
     <string name="select_items_to_share" msgid="1026071777275022579">"Chagua vipengee vya kutuma"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Inashiriki picha na maandishi}other{Inashiriki picha # na maandishi}}"</string>
     <string name="sharing_images_with_link" msgid="8907893266387877733">"{count,plural, =1{Inashiriki picha na kiungo}other{Inashiriki picha # na kiungo}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Usijumuishe kiungo"</string>
     <string name="include_link" msgid="827855767220339802">"Jumuisha kiungo"</string>
     <string name="pinned" msgid="7623664001331394139">"Imebandikwa"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Kipengee cha <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Picha inayoweza kuchaguliwa"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video inayoweza kuchaguliwa"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Kipengee kinachoweza kuchaguliwa"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Kitufe"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Chaguo za kutuma maudhui moja kwa moja"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Mapendekezo ya programu"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Orodha ya programu"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Nakili maandishi"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Nakili kiungo"</string>
 </resources>
diff --git a/java/res/values-ta/strings.xml b/java/res/values-ta/strings.xml
index f53e5b29..fa40446f 100644
--- a/java/res/values-ta/strings.xml
+++ b/java/res/values-ta/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"இணைப்பைத் தவிர்"</string>
     <string name="include_link" msgid="827855767220339802">"இணைப்பைச் சேர்"</string>
     <string name="pinned" msgid="7623664001331394139">"பின் செய்யப்பட்டுள்ளது"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"ஆவணம் <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"தேர்ந்தெடுக்கக்கூடிய படம்"</string>
     <string name="selectable_video" msgid="1271768647699300826">"தேர்ந்தெடுக்கக்கூடிய வீடியோ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"தேர்ந்தெடுக்கக்கூடியது"</string>
     <string name="role_description_button" msgid="4537198530568333649">"பட்டன்"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"நேரடிப் பகிர்வு இலக்குகள்"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"ஆப்ஸ் பரிந்துரைகள்"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ஆப்ஸ் பட்டியல்"</string>
+    <string name="copy_text" msgid="1341801611046464360">"வார்த்தைகளை நகலெடுக்கும்"</string>
+    <string name="copy_link" msgid="3822142723771306592">"இணைப்பை நகலெடுக்கும்"</string>
 </resources>
diff --git a/java/res/values-te/strings.xml b/java/res/values-te/strings.xml
index 5003d8eb..267978b8 100644
--- a/java/res/values-te/strings.xml
+++ b/java/res/values-te/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # ఫైల్}other{+ # ఫైల్స్}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ మరో # ఫైల్}other{+ మరో # ఫైల్స్}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"టెక్స్ట్‌ను షేర్ చేయడం"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"లింక్‌ను షేర్ చేయడం"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"షేరింగ్ లింక్"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ఈ ఇమేజ్‌ను షేర్ చేస్తున్నారు}other{ఈ # ఇమేజ్‌లను షేర్ చేస్తున్నారు}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{వీడియోను షేర్ చేయడం}other{# వీడియోలను షేర్ చేయడం}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ఫైల్‌ను షేర్ చేస్తోంది}other{# ఫైళ్లను షేర్ చేస్తోంది}}"</string>
@@ -85,7 +85,7 @@
     <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"మీ IT అడ్మిన్ ద్వారా బ్లాక్ చేయబడింది"</string>
     <string name="resolver_cant_share_with_work_apps_explanation" msgid="2984105853145456723">"ఈ కంటెంట్ వర్క్ యాప్‌తో షేర్ చేయడం సాధ్యం కాదు"</string>
     <string name="resolver_cant_access_work_apps_explanation" msgid="1463093773348988122">"ఈ కంటెంట్ వర్క్ యాప్‌తో తెరవడం సాధ్యం కాదు"</string>
-    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"ఈ కంటెంట్‌ను వ్యక్తిగత యాప్స్ లోకి షేర్ చేయడం సాధ్యం కాదు"</string>
+    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"ఈ కంటెంట్‌ను వ్యక్తిగత (పర్సనల్) యాప్స్‌కు షేర్ చేయడం సాధ్యపడదు"</string>
     <string name="resolver_cant_access_personal_apps_explanation" msgid="6209543716289792706">"ఈ కంటెంట్ వ్యక్తిగత యాప్‌తో తెరవడం సాధ్యం కాదు"</string>
     <string name="resolver_cant_share_with_private_apps_explanation" msgid="1781980997411434697">"ఈ కంటెంట్‌ను ప్రైవేట్ యాప్‌లతో షేర్ చేయడం సాధ్యం కాదు"</string>
     <string name="resolver_cant_access_private_apps_explanation" msgid="5978609934961648342">"ఈ కంటెంట్‌ను ప్రైవేట్ యాప్‌లతో తెరవడం సాధ్యం కాదు"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"లింక్‌ను మినహాయించండి"</string>
     <string name="include_link" msgid="827855767220339802">"లింక్‌ను చేర్చండి"</string>
     <string name="pinned" msgid="7623664001331394139">"పిన్ చేయబడింది"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"ఐటెమ్ <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"ఎంచుకోదగిన ఇమేజ్"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ఎంచుకోదగిన వీడియో"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ఎంచుకోదగిన ఐటెమ్"</string>
     <string name="role_description_button" msgid="4537198530568333649">"బటన్"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"టార్గెట్‌లను నేరుగా షేర్ చేయడం"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"యాప్ సూచనలు"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"యాప్ లిస్ట్"</string>
+    <string name="copy_text" msgid="1341801611046464360">"టెక్స్ట్‌ను కాపీ చేయండి"</string>
+    <string name="copy_link" msgid="3822142723771306592">"లింక్‌ను కాపీ చేయండి"</string>
 </resources>
diff --git a/java/res/values-th/strings.xml b/java/res/values-th/strings.xml
index 8bb9408f..d20d8189 100644
--- a/java/res/values-th/strings.xml
+++ b/java/res/values-th/strings.xml
@@ -85,7 +85,7 @@
     <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"ผู้ดูแลระบบไอทีบล็อกไว้"</string>
     <string name="resolver_cant_share_with_work_apps_explanation" msgid="2984105853145456723">"แชร์เนื้อหานี้โดยใช้แอปงานไม่ได้"</string>
     <string name="resolver_cant_access_work_apps_explanation" msgid="1463093773348988122">"เปิดเนื้อหานี้โดยใช้แอปงานไม่ได้"</string>
-    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"แชร์เนื้อหานี้โดยใช้แอปส่วนตัวไม่ได้"</string>
+    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"แชร์เนื้อหานี้กับแอปส่วนตัวไม่ได้"</string>
     <string name="resolver_cant_access_personal_apps_explanation" msgid="6209543716289792706">"เปิดเนื้อหานี้โดยใช้แอปส่วนตัวไม่ได้"</string>
     <string name="resolver_cant_share_with_private_apps_explanation" msgid="1781980997411434697">"แชร์เนื้อหานี้โดยใช้แอปส่วนตัวไม่ได้"</string>
     <string name="resolver_cant_access_private_apps_explanation" msgid="5978609934961648342">"เปิดเนื้อหานี้โดยใช้แอปส่วนตัวไม่ได้"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"ไม่รวมลิงก์"</string>
     <string name="include_link" msgid="827855767220339802">"รวมลิงก์"</string>
     <string name="pinned" msgid="7623664001331394139">"ปักหมุดไว้"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"รายการ <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"รูปภาพที่เลือกได้"</string>
     <string name="selectable_video" msgid="1271768647699300826">"วิดีโอที่เลือกได้"</string>
     <string name="selectable_item" msgid="7557320816744205280">"รายการที่เลือกได้"</string>
     <string name="role_description_button" msgid="4537198530568333649">"ปุ่ม"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"เป้าหมายการแชร์โดยตรง"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"คำแนะนำเกี่ยวกับแอป"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"รายการแอป"</string>
+    <string name="copy_text" msgid="1341801611046464360">"คัดลอกข้อความ"</string>
+    <string name="copy_link" msgid="3822142723771306592">"คัดลอกลิงก์"</string>
 </resources>
diff --git a/java/res/values-tl/strings.xml b/java/res/values-tl/strings.xml
index e98c06bf..13bf4863 100644
--- a/java/res/values-tl/strings.xml
+++ b/java/res/values-tl/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Huwag isama ang link"</string>
     <string name="include_link" msgid="827855767220339802">"Isama ang link"</string>
     <string name="pinned" msgid="7623664001331394139">"Naka-pin"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Item <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Napipiling larawan"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Napipiling video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Napipiling item"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Button"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Mga target ng direktang pagbabahagi"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Mga iminumungkahing app"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Listahan ng app"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopyahin ang text"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopyahin ang link"</string>
 </resources>
diff --git a/java/res/values-tr/strings.xml b/java/res/values-tr/strings.xml
index 25b7e860..4bfe38b1 100644
--- a/java/res/values-tr/strings.xml
+++ b/java/res/values-tr/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # dosya}other{+ # dosya}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ # dosya daha}other{+ # dosya daha}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Metin paylaşılıyor"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Paylaşım bağlantısı"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Bağlantı paylaşılıyor"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Resim paylaşılıyor}other{# resim paylaşılıyor}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Video paylaşılıyor}other{# video paylaşılıyor}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# dosya paylaşılıyor}other{# dosya paylaşılıyor}}"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Bağlantıyı hariç tut"</string>
     <string name="include_link" msgid="827855767220339802">"Bağlantıyı dahil et"</string>
     <string name="pinned" msgid="7623664001331394139">"Sabitlendi"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g>. öğe"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Seçilebilir resim"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Seçilebilir video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Seçilebilir öğe"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Düğme"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Doğrudan paylaşım hedefleri"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Önerilen uygulamalar"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Uygulama listesi"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Metni kopyala"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Bağlantıyı kopyala"</string>
 </resources>
diff --git a/java/res/values-uk/strings.xml b/java/res/values-uk/strings.xml
index 33f9e350..db252f2e 100644
--- a/java/res/values-uk/strings.xml
+++ b/java/res/values-uk/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Вилучити посилання"</string>
     <string name="include_link" msgid="827855767220339802">"Додати посилання"</string>
     <string name="pinned" msgid="7623664001331394139">"Закріплено"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Об’єкт <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Зображення, яке можна вибрати"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Відео, яке можна вибрати"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Об’єкт, який можна вибрати"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Кнопка"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Цілі прямого надання доступу"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Рекомендовані додатки"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Список додатків"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Копіювати текст"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Копіювати посилання"</string>
 </resources>
diff --git a/java/res/values-ur/strings.xml b/java/res/values-ur/strings.xml
index 950041e7..6d52881c 100644
--- a/java/res/values-ur/strings.xml
+++ b/java/res/values-ur/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"لنک خارج کریں"</string>
     <string name="include_link" msgid="827855767220339802">"لنک شامل کریں"</string>
     <string name="pinned" msgid="7623664001331394139">"پن کردہ"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"آئٹم <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"قابل انتخاب تصویر"</string>
     <string name="selectable_video" msgid="1271768647699300826">"قابل انتخاب ویڈیو"</string>
     <string name="selectable_item" msgid="7557320816744205280">"قابل انتخاب آئٹم"</string>
     <string name="role_description_button" msgid="4537198530568333649">"بٹن"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"براہ راست اشتراک کے اہداف"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"ایپ کی تجاویز"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"ایپ کی فہرست"</string>
+    <string name="copy_text" msgid="1341801611046464360">"ٹیکسٹ کاپی کریں"</string>
+    <string name="copy_link" msgid="3822142723771306592">"لنک کاپی کریں"</string>
 </resources>
diff --git a/java/res/values-uz/strings.xml b/java/res/values-uz/strings.xml
index 1792e0d2..90c1008b 100644
--- a/java/res/values-uz/strings.xml
+++ b/java/res/values-uz/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Havolani chiqarib tashlash"</string>
     <string name="include_link" msgid="827855767220339802">"Havolani kiritish"</string>
     <string name="pinned" msgid="7623664001331394139">"Mahkamlangan"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"<xliff:g id="ITEM_POSITION">%1$d</xliff:g>-element"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Tanlanadigan rasm"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Tanlanadigan video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Tanlanadigan fayl"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Tugma"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Direct Share nishonlari"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Ilova takliflari"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Ilovalar roʻyxati"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Matnni nusxalash"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Havoladan nusxa olish"</string>
 </resources>
diff --git a/java/res/values-vi/strings.xml b/java/res/values-vi/strings.xml
index a32bacc1..a3ad15fa 100644
--- a/java/res/values-vi/strings.xml
+++ b/java/res/values-vi/strings.xml
@@ -82,10 +82,10 @@
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"Chế độ xem cá nhân"</string>
     <string name="resolver_work_tab_accessibility" msgid="7581878836587799920">"Chế độ xem công việc"</string>
     <string name="resolver_private_tab_accessibility" msgid="2513122834337197252">"Chế độ xem riêng tư"</string>
-    <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"Bị quản trị viên CNTT chặn"</string>
+    <string name="resolver_cross_profile_blocked" msgid="3515194063758605377">"Quản trị viên CNTT của bạn đã chặn thao tác này"</string>
     <string name="resolver_cant_share_with_work_apps_explanation" msgid="2984105853145456723">"Bạn không thể chia sẻ nội dung này bằng ứng dụng công việc"</string>
     <string name="resolver_cant_access_work_apps_explanation" msgid="1463093773348988122">"Bạn không thể mở nội dung này bằng ứng dụng công việc"</string>
-    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"Bạn không thể chia sẻ nội dung này bằng ứng dụng cá nhân"</string>
+    <string name="resolver_cant_share_with_personal_apps_explanation" msgid="6406971348929464569">"Bạn không thể chia sẻ nội dung này với các ứng dụng cá nhân"</string>
     <string name="resolver_cant_access_personal_apps_explanation" msgid="6209543716289792706">"Bạn không thể mở nội dung này bằng ứng dụng cá nhân"</string>
     <string name="resolver_cant_share_with_private_apps_explanation" msgid="1781980997411434697">"Không chia sẻ được nội dung này bằng ứng dụng riêng tư"</string>
     <string name="resolver_cant_access_private_apps_explanation" msgid="5978609934961648342">"Không mở được nội dung này bằng ứng dụng riêng tư"</string>
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Không kèm đường liên kết"</string>
     <string name="include_link" msgid="827855767220339802">"Thêm đường liên kết"</string>
     <string name="pinned" msgid="7623664001331394139">"Đã ghim"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Mục <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Hình ảnh có thể chọn"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video có thể chọn"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Mục có thể chọn"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Nút"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Mục tiêu chia sẻ trực tiếp"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Ứng dụng đề xuất"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Danh sách ứng dụng"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Sao chép văn bản"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Sao chép đường liên kết"</string>
 </resources>
diff --git a/java/res/values-zh-rCN/strings.xml b/java/res/values-zh-rCN/strings.xml
index 603a4e5e..761fa8e3 100644
--- a/java/res/values-zh-rCN/strings.xml
+++ b/java/res/values-zh-rCN/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"排除链接"</string>
     <string name="include_link" msgid="827855767220339802">"包括链接"</string>
     <string name="pinned" msgid="7623664001331394139">"已固定"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"第 <xliff:g id="ITEM_POSITION">%1$d</xliff:g> 项"</string>
     <string name="selectable_image" msgid="3157858923437182271">"可选择的图片"</string>
     <string name="selectable_video" msgid="1271768647699300826">"可选择的视频"</string>
     <string name="selectable_item" msgid="7557320816744205280">"可选择的内容"</string>
     <string name="role_description_button" msgid="4537198530568333649">"按钮"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"直接分享目标"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"应用建议"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"应用列表"</string>
+    <string name="copy_text" msgid="1341801611046464360">"复制文字"</string>
+    <string name="copy_link" msgid="3822142723771306592">"复制链接"</string>
 </resources>
diff --git a/java/res/values-zh-rHK/strings.xml b/java/res/values-zh-rHK/strings.xml
index b3aed885..6a4a37bf 100644
--- a/java/res/values-zh-rHK/strings.xml
+++ b/java/res/values-zh-rHK/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"不包括連結"</string>
     <string name="include_link" msgid="827855767220339802">"加入連結"</string>
     <string name="pinned" msgid="7623664001331394139">"固定咗"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"項目 <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"可以揀嘅圖片"</string>
     <string name="selectable_video" msgid="1271768647699300826">"可以揀嘅影片"</string>
     <string name="selectable_item" msgid="7557320816744205280">"可以揀嘅項目"</string>
     <string name="role_description_button" msgid="4537198530568333649">"按鈕"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"直接分享對象"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"應用程式建議"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"應用程式清單"</string>
+    <string name="copy_text" msgid="1341801611046464360">"複製文字"</string>
+    <string name="copy_link" msgid="3822142723771306592">"複製連結"</string>
 </resources>
diff --git a/java/res/values-zh-rTW/strings.xml b/java/res/values-zh-rTW/strings.xml
index 97770baf..9e8342d8 100644
--- a/java/res/values-zh-rTW/strings.xml
+++ b/java/res/values-zh-rTW/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"排除連結"</string>
     <string name="include_link" msgid="827855767220339802">"加回連結"</string>
     <string name="pinned" msgid="7623664001331394139">"已固定"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"項目 <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"可選取的圖片"</string>
     <string name="selectable_video" msgid="1271768647699300826">"可選取的影片"</string>
     <string name="selectable_item" msgid="7557320816744205280">"可選取的項目"</string>
     <string name="role_description_button" msgid="4537198530568333649">"按鈕"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"直接分享目標"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"應用程式建議"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"應用程式清單"</string>
+    <string name="copy_text" msgid="1341801611046464360">"複製文字"</string>
+    <string name="copy_link" msgid="3822142723771306592">"複製連結"</string>
 </resources>
diff --git a/java/res/values-zu/strings.xml b/java/res/values-zu/strings.xml
index bdf42d69..f1644127 100644
--- a/java/res/values-zu/strings.xml
+++ b/java/res/values-zu/strings.xml
@@ -103,8 +103,14 @@
     <string name="exclude_link" msgid="1332778255031992228">"Ungafaki ilinki"</string>
     <string name="include_link" msgid="827855767220339802">"Faka ilinki"</string>
     <string name="pinned" msgid="7623664001331394139">"Kuphiniwe"</string>
+    <string name="item_position_label" msgid="5112465518086817859">"Into <xliff:g id="ITEM_POSITION">%1$d</xliff:g>"</string>
     <string name="selectable_image" msgid="3157858923437182271">"Umfanekiso okhethekayo"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Ividiyo ekhethekayo"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Into ekhethekayo"</string>
     <string name="role_description_button" msgid="4537198530568333649">"Inkinobho"</string>
+    <string name="shortcut_group_a11y_title" msgid="3097624986281770746">"Qondisa ofuna ukwabelana nabo"</string>
+    <string name="suggested_apps_group_a11y_title" msgid="2394561651436551139">"Iziphakamiso ze-app"</string>
+    <string name="all_apps_group_a11y_title" msgid="2646382370571120047">"Uhlu lwama-app"</string>
+    <string name="copy_text" msgid="1341801611046464360">"Kopisha umbhalo"</string>
+    <string name="copy_link" msgid="3822142723771306592">"Kopisha ilinki"</string>
 </resources>
diff --git a/java/res/values/colors.xml b/java/res/values/colors.xml
index 758e403b..966c2d28 100644
--- a/java/res/values/colors.xml
+++ b/java/res/values/colors.xml
@@ -17,7 +17,17 @@
 ** limitations under the License.
 */
 -->
-<resources>
+<resources xmlns:androidprv="http://schemas.android.com/apk/prv/res/android">
     <color name="chooser_row_divider">@*android:color/list_divider_color_light</color>
     <color name="chooser_gradient_background">@*android:color/loading_gradient_background_color_light</color>
+
+    <color name="chooser_grid_layout_background">@androidprv:color/materialColorSurfaceContainer</color>
+    <color name="chooser_grid_preview_background">@androidprv:color/materialColorSurfaceContainer</color>
+    <color name="chooser_grid_item_text1_color">@androidprv:color/materialColorOnSurface</color>
+    <color name="chooser_grid_item_text2_color">@androidprv:color/materialColorOnSurfaceVariant</color>
+    <color name="content_preview_filename_text_color">@androidprv:color/materialColorOnSurface</color>
+    <color name="content_preview_more_files_text_color">@androidprv:color/materialColorOnSurfaceVariant</color>
+    <color name="content_preview_text_color">@androidprv:color/materialColorOnSurfaceVariant</color>
+    <color name="content_preview_copy_icon_tint">@androidprv:color/materialColorOnSurfaceVariant</color>
+    <color name="chooser_row_text_color">@androidprv:color/materialColorOnSurfaceVariant</color>
 </resources>
diff --git a/java/res/values/dimens.xml b/java/res/values/dimens.xml
index 515343b6..805f00f5 100644
--- a/java/res/values/dimens.xml
+++ b/java/res/values/dimens.xml
@@ -43,6 +43,12 @@
     <dimen name="chooser_grid_activity_name_text_size">12sp</dimen>
     <dimen name="chooser_item_focus_outline_corner_radius">11dp</dimen>
     <dimen name="chooser_item_focus_outline_width">2dp</dimen>
+    <dimen name="chooser_row_height">100dp</dimen>
+    <dimen name="content_preview_text_size">12sp</dimen>
+    <dimen name="content_preview_filename_line_size">16sp</dimen>
+    <dimen name="content_preview_more_files_text_size">12sp</dimen>
+    <dimen name="content_preview_more_files_line_size">16sp</dimen>
+    <dimen name="content_preview_copy_icon_size">48dp</dimen>
     <dimen name="resolver_icon_size">32dp</dimen>
     <dimen name="resolver_button_bar_spacing">0dp</dimen>
     <dimen name="resolver_badge_size">18dp</dimen>
@@ -65,11 +71,29 @@
     <dimen name="modify_share_text_toggle_max_width">150dp</dimen>
     <dimen name="chooser_view_spacing">16dp</dimen>
 
+    <dimen name="preview_text_padding">124dp</dimen>
+    <dimen name="chooser_list_padding">0dp</dimen>
+    <dimen name="chooser_row_direct_share_height">200dp</dimen>
+    <dimen name="preview_text_min_height">46dp</dimen>
+    <dimen name="view_holder_height">200dp</dimen>
+    <dimen name="chooser_grid_item_space_height">7dp</dimen>
+
+    <dimen name="chooser_margin_vertical">80dp</dimen>
+    <dimen name="chooser_padding_bottom">80dp</dimen>
+    <dimen name="chooser_padding_start">0dp</dimen>
+    <dimen name="chooser_padding_end">0dp</dimen>
+    <dimen name="chooser_close_icon_size">60dp</dimen>
+    <dimen name="chooser_close_icon_size_margin">16dp</dimen>
+    <dimen name="chooser_content_view_margin_horizontal">200dp</dimen>
+    <dimen name="chooser_content_view_margin_vertical">16dp</dimen>
+    <dimen name="chooser_content_view_min_height">0dp</dimen>
+
     <!-- Note that the values in this section are for landscape phones. For screen configs taller
          than 480dp, the values are set in values-h480dp/dimens.xml -->
     <dimen name="chooser_preview_width">412dp</dimen>
     <dimen name="chooser_preview_image_height_tall">124dp</dimen>
-    <dimen name="grid_padding">8dp</dimen>
+    <dimen name="grid_padding_vertical">8dp</dimen>
+    <dimen name="grid_padding_horizontal">4dp</dimen>
     <dimen name="width_text_image_preview_size">46dp</dimen>
     <!-- END SECTION -->
 </resources>
diff --git a/java/res/values/strings.xml b/java/res/values/strings.xml
index 2261a4a8..c9ee9d80 100644
--- a/java/res/values/strings.xml
+++ b/java/res/values/strings.xml
@@ -329,6 +329,9 @@
          front of the list by the user. [CHAR LIMIT=NONE] -->
     <string name="pinned">Pinned</string>
 
+    <!-- Accessibility content description, item position label e.g. "Item 1" or "Item 345".
+         [CHAR LIMIT=NONE] -->
+    <string name="item_position_label">Item <xliff:g id="item_position" example="123">%1$d</xliff:g></string>
     <!-- Accessibility content description for an image that the user may select for sharing.
          [CHAR LIMIT=NONE] -->
     <string name="selectable_image">Selectable image</string>
@@ -340,4 +343,21 @@
     <string name="selectable_item">Selectable item</string>
     <!-- Accessibility role description for a11y on button. [CHAR LIMIT=NONE] -->
     <string name="role_description_button">Button</string>
+
+    <!-- Accessibility announcement for the shortcut group (https://developer.android.com/training/sharing/direct-share-targets)
+         in the list of targets. [CHAR LIMIT=NONE]-->
+    <string name="shortcut_group_a11y_title">Direct share targets</string>
+    <!-- Accessibility announcement for the suggested application group in the list of targets.
+    [CHAR LIMIT=NONE] -->
+    <string name="suggested_apps_group_a11y_title">App suggestions</string>
+    <!-- Accessibility announcement for the all-applications group in the list of targets.
+    [CHAR LIMIT=NONE] -->
+    <string name="all_apps_group_a11y_title">App list</string>
+
+    <!-- Content description for an action chip button in the content preview UI when a text is
+         shared. The button is used to copy the text into the clipboard. [CHAR_LIMIT=NONE] -->
+    <string name="copy_text">Copy text</string>
+    <!-- Content description for an action chip button in the content preview UI when a link is
+         shared. The button is used to copy the text into the clipboard. [CHAR_LIMIT=NONE] -->
+    <string name="copy_link">Copy link</string>
 </resources>
diff --git a/java/src/android/service/chooser/ChooserSession.kt b/java/src/android/service/chooser/ChooserSession.kt
new file mode 100644
index 00000000..3bbe23a4
--- /dev/null
+++ b/java/src/android/service/chooser/ChooserSession.kt
@@ -0,0 +1,39 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package android.service.chooser
+
+import android.os.Parcel
+import android.os.Parcelable
+import com.android.intentresolver.IChooserInteractiveSessionCallback
+
+/** A stub for the potential future API class. */
+class ChooserSession(val sessionCallbackBinder: IChooserInteractiveSessionCallback) : Parcelable {
+    override fun describeContents() = 0
+
+    override fun writeToParcel(dest: Parcel, flags: Int) {
+        TODO("Not yet implemented")
+    }
+
+    companion object CREATOR : Parcelable.Creator<ChooserSession> {
+        override fun createFromParcel(source: Parcel): ChooserSession? =
+            ChooserSession(
+                IChooserInteractiveSessionCallback.Stub.asInterface(source.readStrongBinder())
+            )
+
+        override fun newArray(size: Int): Array<out ChooserSession?> = arrayOfNulls(size)
+    }
+}
diff --git a/java/src/com/android/intentresolver/ChooserActivity.java b/java/src/com/android/intentresolver/ChooserActivity.java
index 54f575d7..aff34580 100644
--- a/java/src/com/android/intentresolver/ChooserActivity.java
+++ b/java/src/com/android/intentresolver/ChooserActivity.java
@@ -23,9 +23,12 @@ import static android.view.WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTE
 import static androidx.lifecycle.LifecycleKt.getCoroutineScope;
 
 import static com.android.intentresolver.ChooserActionFactory.EDIT_SOURCE;
-import static com.android.intentresolver.Flags.fixShortcutsFlashing;
+import static com.android.intentresolver.Flags.delayDrawerOffsetCalculation;
+import static com.android.intentresolver.Flags.fixShortcutsFlashingFixed;
+import static com.android.intentresolver.Flags.interactiveSession;
 import static com.android.intentresolver.Flags.keyboardNavigationFix;
 import static com.android.intentresolver.Flags.rebuildAdaptersOnTargetPinning;
+import static com.android.intentresolver.Flags.refineSystemActions;
 import static com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra;
 import static com.android.intentresolver.Flags.unselectFinalItem;
 import static com.android.intentresolver.ext.CreationExtrasExtKt.replaceDefaultArgs;
@@ -59,6 +62,7 @@ import android.content.pm.ShortcutInfo;
 import android.content.res.Configuration;
 import android.database.Cursor;
 import android.graphics.Insets;
+import android.graphics.Rect;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.StrictMode;
@@ -142,6 +146,7 @@ import com.android.intentresolver.widget.ActionRow;
 import com.android.intentresolver.widget.ChooserNestedScrollView;
 import com.android.intentresolver.widget.ImagePreviewView;
 import com.android.intentresolver.widget.ResolverDrawerLayout;
+import com.android.intentresolver.widget.ResolverDrawerLayoutExt;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.content.PackageMonitor;
 import com.android.internal.logging.MetricsLogger;
@@ -256,7 +261,6 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     @Inject public UserInteractor mUserInteractor;
     @Inject @Background public CoroutineDispatcher mBackgroundDispatcher;
     @Inject public ChooserHelper mChooserHelper;
-    @Inject public FeatureFlags mFeatureFlags;
     @Inject public EventLog mEventLog;
     @Inject @AppPredictionAvailable public boolean mAppPredictionAvailable;
     @Inject @ImageEditor public Optional<ComponentName> mImageEditor;
@@ -422,13 +426,11 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     @Override
     protected final void onRestart() {
         super.onRestart();
-        if (mFeatureFlags.fixPrivateSpaceLockedOnRestart()) {
-            if (mChooserMultiProfilePagerAdapter.hasPageForProfile(Profile.Type.PRIVATE.ordinal())
-                    && !mProfileAvailability.isAvailable(mProfiles.getPrivateProfile())) {
-                Log.d(TAG, "Exiting due to unavailable profile");
-                finish();
-                return;
-            }
+        if (mChooserMultiProfilePagerAdapter.hasPageForProfile(Profile.Type.PRIVATE.ordinal())
+                && !mProfileAvailability.isAvailable(mProfiles.getPrivateProfile())) {
+            Log.d(TAG, "Exiting due to unavailable profile");
+            finish();
+            return;
         }
 
         if (!mRegistered) {
@@ -465,6 +467,9 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
 
         if (isFinishing()) {
             mLatencyTracker.onActionCancel(ACTION_LOAD_SHARE_SHEET);
+            if (interactiveSession() && mViewModel != null) {
+                mViewModel.getInteractiveSessionInteractor().endSession();
+            }
         }
 
         mBackgroundThreadPoolExecutor.shutdownNow();
@@ -481,9 +486,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
 
         mProfiles =  new ProfileHelper(
                 mUserInteractor,
-                getCoroutineScope(getLifecycle()),
-                mBackgroundDispatcher,
-                mFeatureFlags);
+                mBackgroundDispatcher);
 
         mProfileAvailability = new ProfileAvailability(
                 mUserInteractor,
@@ -686,6 +689,11 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         mEnterTransitionAnimationDelegate.postponeTransition();
         mInitialProfile = findSelectedProfile();
         Tracer.INSTANCE.markLaunched();
+
+        if (isInteractiveSession()) {
+            configureInteractiveSessionWindow();
+            updateInteractiveArea();
+        }
     }
 
     private void maybeDisableRecentsScreenshot(
@@ -725,6 +733,45 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         mChooserMultiProfilePagerAdapter.setTargetsEnabled(hasSelections);
     }
 
+    private void configureInteractiveSessionWindow() {
+        if (!isInteractiveSession()) {
+            Log.wtf(TAG, "Unexpected user of the method; should be an interactive session");
+            return;
+        }
+        final Window window = getWindow();
+        if (window == null) {
+            return;
+        }
+        window.clearFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
+        window.addPrivateFlags(WindowManager.LayoutParams.PRIVATE_FLAG_TRUSTED_OVERLAY);
+    }
+
+    private void updateInteractiveArea() {
+        if (!isInteractiveSession()) {
+            Log.wtf(TAG, "Unexpected user of the method; should be an interactive session");
+            return;
+        }
+        final View contentView = findViewById(android.R.id.content);
+        final ResolverDrawerLayout rdl = mResolverDrawerLayout;
+        if (contentView == null || rdl == null) {
+            return;
+        }
+        final Rect rect = new Rect();
+        contentView.getViewTreeObserver().addOnComputeInternalInsetsListener((info) -> {
+            int oldTop = rect.top;
+            rdl.getBoundsInWindow(rect, true);
+            int left = rect.left;
+            int top = rect.top;
+            ResolverDrawerLayoutExt.getVisibleDrawerRect(rdl, rect);
+            rect.offset(left, top);
+            if (oldTop != rect.top) {
+                mViewModel.getInteractiveSessionInteractor().sendTopDrawerTopOffsetChange(rect.top);
+            }
+            info.setTouchableInsets(ViewTreeObserver.InternalInsetsInfo.TOUCHABLE_INSETS_REGION);
+            info.touchableRegion.set(new Rect(rect));
+        });
+    }
+
     private void onAppTargetsLoaded(ResolverListAdapter listAdapter) {
         Log.d(TAG, "onAppTargetsLoaded("
                 + "listAdapter.userHandle=" + listAdapter.getUserHandle() + ")");
@@ -825,7 +872,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         postRebuildList(
                 mChooserMultiProfilePagerAdapter.rebuildTabs(
                     mProfiles.getWorkProfilePresent() || mProfiles.getPrivateProfilePresent()));
-        if (fixShortcutsFlashing() && oldPagerAdapter != null) {
+        if (fixShortcutsFlashingFixed() && oldPagerAdapter != null) {
             for (int i = 0, count = mChooserMultiProfilePagerAdapter.getCount(); i < count; i++) {
                 ChooserListAdapter listAdapter =
                         mChooserMultiProfilePagerAdapter.getPageAdapterForIndex(i)
@@ -968,6 +1015,9 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
      * @return {@code true} if a resolved target is autolaunched, otherwise {@code false}
      */
     private boolean maybeAutolaunchActivity() {
+        if (isInteractiveSession()) {
+            return false;
+        }
         int numberOfProfiles = mChooserMultiProfilePagerAdapter.getItemCount();
         // TODO(b/280988288): If the ChooserActivity is shown we should consider showing the
         //  correct intent-picker UIs (e.g., mini-resolver) if it was launched without
@@ -1566,8 +1616,12 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         mChooserMultiProfilePagerAdapter.getActiveListAdapter().handlePackagesChanged();
 
         if (mSystemWindowInsets != null) {
-            mResolverDrawerLayout.setPadding(mSystemWindowInsets.left, mSystemWindowInsets.top,
-                    mSystemWindowInsets.right, 0);
+            int topSpacing = isInteractiveSession() ? getInteractiveSessionTopSpacing() : 0;
+            mResolverDrawerLayout.setPadding(
+                    mSystemWindowInsets.left,
+                    mSystemWindowInsets.top + topSpacing,
+                    mSystemWindowInsets.right,
+                    0);
         }
         if (mViewPager.isLayoutRtl()) {
             mChooserMultiProfilePagerAdapter.setupViewPager(mViewPager);
@@ -2073,8 +2127,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 },
                 chooserListAdapter,
                 shouldShowContentPreview(),
-                mMaxTargetsPerRow,
-                mFeatureFlags);
+                mMaxTargetsPerRow);
     }
 
     @VisibleForTesting
@@ -2168,7 +2221,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
 
     private ChooserContentPreviewUi.ActionFactory decorateActionFactoryWithRefinement(
             ChooserContentPreviewUi.ActionFactory originalFactory) {
-        if (!mFeatureFlags.refineSystemActions()) {
+        if (!refineSystemActions()) {
             return originalFactory;
         }
 
@@ -2301,6 +2354,9 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 || recyclerView.computeVerticalScrollOffset() != 0) {
             return;
         }
+        if (delayDrawerOffsetCalculation() && !gridAdapter.getListAdapter().areAppTargetsReady()) {
+            return;
+        }
 
         final int availableWidth = right - left - v.getPaddingLeft() - v.getPaddingRight();
         final int maxChooserWidth = getResources().getDimensionPixelSize(R.dimen.chooser_width);
@@ -2312,47 +2368,31 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 || recyclerView.getAdapter() == null
                 || availableWidth != mCurrAvailableWidth;
 
-        boolean insetsChanged = !Objects.equals(mLastAppliedInsets, mSystemWindowInsets);
-
-        if (isLayoutUpdated
-                || insetsChanged
-                || mLastNumberOfChildren != recyclerView.getChildCount()
-                || mFeatureFlags.fixMissingDrawerOffsetCalculation()) {
-            mCurrAvailableWidth = availableWidth;
-            if (isLayoutUpdated) {
-                // It is very important we call setAdapter from here. Otherwise in some cases
-                // the resolver list doesn't get populated, such as b/150922090, b/150918223
-                // and b/150936654
-                recyclerView.setAdapter(gridAdapter);
-                ((GridLayoutManager) recyclerView.getLayoutManager()).setSpanCount(
-                        mMaxTargetsPerRow);
-
-                updateTabPadding();
-            }
+        mCurrAvailableWidth = availableWidth;
+        if (isLayoutUpdated) {
+            // It is very important we call setAdapter from here. Otherwise in some cases
+            // the resolver list doesn't get populated, such as b/150922090, b/150918223
+            // and b/150936654
+            recyclerView.setAdapter(gridAdapter);
+            ((GridLayoutManager) recyclerView.getLayoutManager()).setSpanCount(
+                    mMaxTargetsPerRow);
 
-            int currentProfile = mChooserMultiProfilePagerAdapter.getActiveProfile();
-            int initialProfile = Flags.fixDrawerOffsetOnConfigChange()
-                    ? mInitialProfile
-                    : findSelectedProfile();
-            if (currentProfile != initialProfile) {
-                return;
-            }
+            updateTabPadding();
+        }
 
-            if (mLastNumberOfChildren == recyclerView.getChildCount() && !insetsChanged
-                    && !mFeatureFlags.fixMissingDrawerOffsetCalculation()) {
+        if (mChooserMultiProfilePagerAdapter.getActiveProfile() != mInitialProfile) {
+            return;
+        }
+
+        getMainThreadHandler().post(() -> {
+            if (mResolverDrawerLayout == null) {
                 return;
             }
-
-            getMainThreadHandler().post(() -> {
-                if (mResolverDrawerLayout == null || gridAdapter == null) {
-                    return;
-                }
-                int offset = calculateDrawerOffset(top, bottom, recyclerView, gridAdapter);
-                mResolverDrawerLayout.setCollapsibleHeightReserved(offset);
-                mEnterTransitionAnimationDelegate.markOffsetCalculated();
-                mLastAppliedInsets = mSystemWindowInsets;
-            });
-        }
+            int offset = calculateDrawerOffset(top, bottom, recyclerView, gridAdapter);
+            mResolverDrawerLayout.setCollapsibleHeightReserved(offset);
+            mEnterTransitionAnimationDelegate.markOffsetCalculated();
+            mLastAppliedInsets = mSystemWindowInsets;
+        });
     }
 
     private int calculateDrawerOffset(
@@ -2446,22 +2486,16 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
 
         //TODO: move this block inside ChooserListAdapter (should be called when
         // ResolverListAdapter#mPostListReadyRunnable is executed.
-        if (chooserListAdapter.getDisplayResolveInfoCount() == 0) {
-            Log.d(TAG, "getDisplayResolveInfoCount() == 0");
-            if (rebuildComplete) {
-                onAppTargetsLoaded(listAdapter);
-            }
-            chooserListAdapter.notifyDataSetChanged();
-        } else {
-            chooserListAdapter.updateAlphabeticalList(() -> onAppTargetsLoaded(listAdapter));
-        }
+        chooserListAdapter.updateAlphabeticalList(
+                rebuildComplete,
+                () -> onAppTargetsLoaded(listAdapter));
 
         if (rebuildComplete) {
             long duration = Tracer.INSTANCE.endAppTargetLoadingSection(listProfileUserHandle);
             if (duration >= 0) {
                 Log.d(TAG, "app target loading time " + duration + " ms");
             }
-            if (!fixShortcutsFlashing()) {
+            if (!fixShortcutsFlashingFixed()) {
                 addCallerChooserTargets(chooserListAdapter);
             }
             getEventLog().logSharesheetAppLoadComplete();
@@ -2493,8 +2527,9 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         ChooserListAdapter adapter =
                 mChooserMultiProfilePagerAdapter.getListAdapterForUserHandle(userHandle);
         if (adapter != null) {
-            if (fixShortcutsFlashing()) {
+            if (fixShortcutsFlashingFixed()) {
                 adapter.setDirectTargetsEnabled(true);
+                adapter.resetDirectTargets();
                 addCallerChooserTargets(adapter);
             }
             for (ShortcutLoader.ShortcutResultInfo resultInfo : result.getShortcutsByApp()) {
@@ -2595,7 +2630,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     }
 
     private boolean shouldShowStickyContentPreviewNoOrientationCheck() {
-        if (!shouldShowContentPreview()) {
+        if (isInteractiveSession() || !shouldShowContentPreview()) {
             return false;
         }
         ResolverListAdapter adapter = mChooserMultiProfilePagerAdapter.getListAdapterForUserHandle(
@@ -2688,15 +2723,26 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         }
     }
 
+    private int getInteractiveSessionTopSpacing() {
+        return getResources().getDimensionPixelSize(R.dimen.chooser_preview_image_height_tall);
+    }
+
+    private boolean isInteractiveSession() {
+        return interactiveSession() && mRequest.getInteractiveSessionCallback() != null
+                && !isTaskRoot();
+    }
+
     protected WindowInsets onApplyWindowInsets(View v, WindowInsets insets) {
         mSystemWindowInsets = insets.getInsets(WindowInsets.Type.systemBars());
-        if (mFeatureFlags.fixEmptyStatePaddingBug() || mProfiles.getWorkProfilePresent()) {
-            mChooserMultiProfilePagerAdapter
-                    .setEmptyStateBottomOffset(mSystemWindowInsets.bottom);
-        }
-
-        mResolverDrawerLayout.setPadding(mSystemWindowInsets.left, mSystemWindowInsets.top,
-                mSystemWindowInsets.right, 0);
+        mChooserMultiProfilePagerAdapter
+                .setEmptyStateBottomOffset(mSystemWindowInsets.bottom);
+
+        final int topSpacing = isInteractiveSession() ? getInteractiveSessionTopSpacing() : 0;
+        mResolverDrawerLayout.setPadding(
+                mSystemWindowInsets.left,
+                mSystemWindowInsets.top + topSpacing,
+                mSystemWindowInsets.right,
+                0);
 
         // Need extra padding so the list can fully scroll up
         // To accommodate for window insets
diff --git a/java/src/com/android/intentresolver/ChooserGridLayoutManager.java b/java/src/com/android/intentresolver/ChooserGridLayoutManager.java
index aaa7554c..5bbb6c24 100644
--- a/java/src/com/android/intentresolver/ChooserGridLayoutManager.java
+++ b/java/src/com/android/intentresolver/ChooserGridLayoutManager.java
@@ -16,18 +16,35 @@
 
 package com.android.intentresolver;
 
+import static com.android.intentresolver.Flags.announceShortcutsAndSuggestedApps;
+
 import android.content.Context;
 import android.util.AttributeSet;
+import android.view.View;
+import android.view.ViewGroup;
+import android.widget.GridView;
+import android.widget.TextView;
 
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
+import androidx.core.view.accessibility.AccessibilityNodeInfoCompat.CollectionInfoCompat;
 import androidx.recyclerview.widget.GridLayoutManager;
 import androidx.recyclerview.widget.RecyclerView;
 
+import com.android.intentresolver.grid.ChooserGridAdapter;
+
 /**
  * For a11y and per {@link RecyclerView#onInitializeAccessibilityNodeInfo}, override
  * methods to ensure proper row counts.
  */
 public class ChooserGridLayoutManager extends GridLayoutManager {
 
+    private CharSequence mShortcutGroupTitle = "";
+    private CharSequence mSuggestedAppsGroupTitle = "";
+    private CharSequence mAllAppListGroupTitle = "";
+    @Nullable
+    private RecyclerView mRecyclerView;
     private boolean mVerticalScrollEnabled = true;
 
     /**
@@ -39,6 +56,9 @@ public class ChooserGridLayoutManager extends GridLayoutManager {
     public ChooserGridLayoutManager(Context context, AttributeSet attrs, int defStyleAttr,
             int defStyleRes) {
         super(context, attrs, defStyleAttr, defStyleRes);
+        if (announceShortcutsAndSuggestedApps()) {
+            readGroupTitles(context);
+        }
     }
 
     /**
@@ -49,6 +69,9 @@ public class ChooserGridLayoutManager extends GridLayoutManager {
      */
     public ChooserGridLayoutManager(Context context, int spanCount) {
         super(context, spanCount);
+        if (announceShortcutsAndSuggestedApps()) {
+            readGroupTitles(context);
+        }
     }
 
     /**
@@ -61,6 +84,27 @@ public class ChooserGridLayoutManager extends GridLayoutManager {
     public ChooserGridLayoutManager(Context context, int spanCount, int orientation,
             boolean reverseLayout) {
         super(context, spanCount, orientation, reverseLayout);
+        if (announceShortcutsAndSuggestedApps()) {
+            readGroupTitles(context);
+        }
+    }
+
+    private void readGroupTitles(Context context) {
+        mShortcutGroupTitle = context.getString(R.string.shortcut_group_a11y_title);
+        mSuggestedAppsGroupTitle = context.getString(R.string.suggested_apps_group_a11y_title);
+        mAllAppListGroupTitle = context.getString(R.string.all_apps_group_a11y_title);
+    }
+
+    @Override
+    public void onAttachedToWindow(RecyclerView view) {
+        super.onAttachedToWindow(view);
+        mRecyclerView = view;
+    }
+
+    @Override
+    public void onDetachedFromWindow(RecyclerView view, RecyclerView.Recycler recycler) {
+        super.onDetachedFromWindow(view, recycler);
+        mRecyclerView = null;
     }
 
     @Override
@@ -78,4 +122,91 @@ public class ChooserGridLayoutManager extends GridLayoutManager {
     public boolean canScrollVertically() {
         return mVerticalScrollEnabled && super.canScrollVertically();
     }
+
+    @Override
+    public void onInitializeAccessibilityNodeInfoForItem(
+            RecyclerView.Recycler recycler,
+            RecyclerView.State state,
+            View host,
+            AccessibilityNodeInfoCompat info) {
+        super.onInitializeAccessibilityNodeInfoForItem(recycler, state, host, info);
+        if (announceShortcutsAndSuggestedApps() && host instanceof ViewGroup) {
+            if (host.getId() == R.id.shortcuts_container) {
+                info.setClassName(GridView.class.getName());
+                info.setContainerTitle(mShortcutGroupTitle);
+                info.setCollectionInfo(createShortcutsA11yCollectionInfo((ViewGroup) host));
+            } else if (host.getId() == R.id.suggested_apps_container) {
+                RecyclerView.Adapter adapter =
+                        mRecyclerView == null ? null : mRecyclerView.getAdapter();
+                ChooserListAdapter gridAdapter = adapter instanceof ChooserGridAdapter
+                        ? ((ChooserGridAdapter) adapter).getListAdapter()
+                        : null;
+                info.setClassName(GridView.class.getName());
+                info.setCollectionInfo(createSuggestedAppsA11yCollectionInfo((ViewGroup) host));
+                if (gridAdapter == null || gridAdapter.getAlphaTargetCount() > 0) {
+                    info.setContainerTitle(mSuggestedAppsGroupTitle);
+                } else {
+                    // if all applications fit into one row, they will be put into the suggested
+                    // applications group.
+                    info.setContainerTitle(mAllAppListGroupTitle);
+                }
+            }
+        }
+    }
+
+    @Override
+    public void onInitializeAccessibilityNodeInfo(@NonNull RecyclerView.Recycler recycler,
+            @NonNull RecyclerView.State state, @NonNull AccessibilityNodeInfoCompat info) {
+        super.onInitializeAccessibilityNodeInfo(recycler, state, info);
+        if (announceShortcutsAndSuggestedApps()) {
+            info.setContainerTitle(mAllAppListGroupTitle);
+        }
+    }
+
+    @Override
+    public boolean isLayoutHierarchical(
+            @NonNull RecyclerView.Recycler recycler, @NonNull RecyclerView.State state) {
+        return announceShortcutsAndSuggestedApps() || super.isLayoutHierarchical(recycler, state);
+    }
+
+    private CollectionInfoCompat createShortcutsA11yCollectionInfo(ViewGroup container) {
+        // TODO: create a custom view for the shortcuts row and move this logic there.
+        int rowCount = 0;
+        int columnCount = 0;
+        for (int i = 0; i < container.getChildCount(); i++) {
+            View row = container.getChildAt(i);
+            int rowColumnCount = 0;
+            if (row instanceof ViewGroup rowGroup && row.getVisibility() == View.VISIBLE) {
+                for (int j = 0; j < rowGroup.getChildCount(); j++) {
+                    View v = rowGroup.getChildAt(j);
+                    if (v != null && v.getVisibility() == View.VISIBLE) {
+                        rowColumnCount++;
+                        if (v instanceof TextView) {
+                            // A special case of the no-targets message that also contains an
+                            // off-screen item (which looks like a bug).
+                            rowColumnCount = 1;
+                            break;
+                        }
+                    }
+                }
+            }
+            if (rowColumnCount > 0) {
+                rowCount++;
+                columnCount = Math.max(columnCount, rowColumnCount);
+            }
+        }
+        return CollectionInfoCompat.obtain(rowCount, columnCount, false);
+    }
+
+    private CollectionInfoCompat createSuggestedAppsA11yCollectionInfo(ViewGroup container) {
+        // TODO: create a custom view for the suggested apps row and move this logic there.
+        int columnCount = 0;
+        for (int i = 0; i < container.getChildCount(); i++) {
+            View v = container.getChildAt(i);
+            if (v.getVisibility() == View.VISIBLE) {
+                columnCount++;
+            }
+        }
+        return CollectionInfoCompat.obtain(1, columnCount, false);
+    }
 }
diff --git a/java/src/com/android/intentresolver/ChooserHelper.kt b/java/src/com/android/intentresolver/ChooserHelper.kt
index c26dd77c..2d015128 100644
--- a/java/src/com/android/intentresolver/ChooserHelper.kt
+++ b/java/src/com/android/intentresolver/ChooserHelper.kt
@@ -27,6 +27,7 @@ import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
+import com.android.intentresolver.Flags.interactiveSession
 import com.android.intentresolver.Flags.unselectFinalItem
 import com.android.intentresolver.annotation.JavaInterop
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_PAYLOAD_SELECTION
@@ -188,6 +189,14 @@ constructor(
                     .collect { onChooserRequestChanged.accept(it) }
             }
         }
+
+        if (interactiveSession()) {
+            activity.lifecycleScope.launch {
+                viewModel.interactiveSessionInteractor.isSessionActive
+                    .filter { !it }
+                    .collect { activity.finish() }
+            }
+        }
     }
 
     override fun onStart(owner: LifecycleOwner) {
diff --git a/java/src/com/android/intentresolver/ChooserListAdapter.java b/java/src/com/android/intentresolver/ChooserListAdapter.java
index 563d7d1a..7e5de74b 100644
--- a/java/src/com/android/intentresolver/ChooserListAdapter.java
+++ b/java/src/com/android/intentresolver/ChooserListAdapter.java
@@ -124,6 +124,21 @@ public class ChooserListAdapter extends ResolverListAdapter {
 
     private final ItemRevealAnimationTracker mAnimationTracker = new ItemRevealAnimationTracker();
 
+    /**
+     * Indicates whether the app targets are ready. The flag is reset in
+     * {@link #rebuildList(boolean)} and set to true in {@link #updateAlphabeticalList(Runnable)}'s
+     * onPostExecute.
+     * There's one nuance though, {@link #updateAlphabeticalList(Runnable)} is called by the
+     * {@link ChooserActivity} only when {@link #rebuildList(boolean)} was called with {@code true}
+     * It is called with {@code false} only for inactive tabs in the
+     * MultiProfilePagerAdapter.rebuildTabs which, in turn, is called from either
+     * {@link ChooserActivity#recreatePagerAdapter} or {@link ChooserActivity#configureContentView}
+     * and, in both cases, there are no inactive pages in the MultiProfilePagerAdapter and
+     * {@link #rebuildList(boolean)} will be called with true upon navigation to the missing page.
+     * Yeah.
+     */
+    private boolean mAppTargetsReady = false;
+
     // For pinned direct share labels, if the text spans multiple lines, the TextView will consume
     // the full width, even if the characters actually take up less than that. Measure the actual
     // line widths and constrain the View's width based upon that so that the pin doesn't end up
@@ -311,6 +326,13 @@ public class ChooserListAdapter extends ResolverListAdapter {
         }
     }
 
+    /**
+     * @return {@code true} if the app targets are ready.
+     */
+    public final boolean areAppTargetsReady() {
+        return mAppTargetsReady;
+    }
+
     /**
      * Set the enabled state for all targets.
      */
@@ -354,6 +376,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
     public boolean rebuildList(boolean doPostProcessing) {
         mAnimationTracker.reset();
         mSortedList.clear();
+        mAppTargetsReady = false;
         boolean result = super.rebuildList(doPostProcessing);
         notifyDataSetChanged();
         return result;
@@ -518,7 +541,16 @@ public class ChooserListAdapter extends ResolverListAdapter {
     /**
      * Group application targets
      */
-    public void updateAlphabeticalList(Runnable onCompleted) {
+    public void updateAlphabeticalList(boolean rebuildComplete, Runnable onCompleted) {
+        if (getDisplayResolveInfoCount() == 0) {
+            Log.d(TAG, "getDisplayResolveInfoCount() == 0");
+            if (rebuildComplete) {
+                mAppTargetsReady = true;
+                onCompleted.run();
+            }
+            notifyDataSetChanged();
+            return;
+        }
         final DisplayResolveInfoAzInfoComparator
                 comparator = new DisplayResolveInfoAzInfoComparator(mContext);
         ImmutableList<DisplayResolveInfo> displayList = getTargetsInCurrentDisplayList();
@@ -582,6 +614,7 @@ public class ChooserListAdapter extends ResolverListAdapter {
             protected void onPostExecute(List<DisplayResolveInfo> newList) {
                 mSortedList.clear();
                 mSortedList.addAll(newList);
+                mAppTargetsReady = true;
                 notifyDataSetChanged();
                 onCompleted.run();
             }
@@ -811,6 +844,13 @@ public class ChooserListAdapter extends ResolverListAdapter {
         mServiceTargets.addAll(adapter.mServiceTargets);
     }
 
+    /**
+     * Reset direct targets
+     */
+    public void resetDirectTargets() {
+        createPlaceHolders();
+    }
+
     private boolean isDirectTargetRowEmptyState() {
         return (mServiceTargets.size() == 1) && mServiceTargets.get(0).isEmptyTargetInfo();
     }
diff --git a/java/src/com/android/intentresolver/ChooserSelector.kt b/java/src/com/android/intentresolver/ChooserSelector.kt
deleted file mode 100644
index c1174e95..00000000
--- a/java/src/com/android/intentresolver/ChooserSelector.kt
+++ /dev/null
@@ -1,52 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.intentresolver.v2
-
-import android.content.BroadcastReceiver
-import android.content.ComponentName
-import android.content.Context
-import android.content.Intent
-import android.content.pm.PackageManager
-import com.android.intentresolver.FeatureFlags
-import dagger.hilt.android.AndroidEntryPoint
-import javax.inject.Inject
-
-@AndroidEntryPoint(BroadcastReceiver::class)
-class ChooserSelector : Hilt_ChooserSelector() {
-
-    @Inject lateinit var featureFlags: FeatureFlags
-
-    override fun onReceive(context: Context, intent: Intent) {
-        super.onReceive(context, intent)
-        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
-            context.packageManager.setComponentEnabledSetting(
-                ComponentName(CHOOSER_PACKAGE, CHOOSER_PACKAGE + CHOOSER_CLASS),
-                if (featureFlags.modularFramework()) {
-                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED
-                } else {
-                    PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
-                },
-                /* flags = */ 0,
-            )
-        }
-    }
-
-    companion object {
-        private const val CHOOSER_PACKAGE = "com.android.intentresolver"
-        private const val CHOOSER_CLASS = ".v2.ChooserActivity"
-    }
-}
diff --git a/java/src/com/android/intentresolver/ProfileHelper.kt b/java/src/com/android/intentresolver/ProfileHelper.kt
index 53a873a3..b87f7e3f 100644
--- a/java/src/com/android/intentresolver/ProfileHelper.kt
+++ b/java/src/com/android/intentresolver/ProfileHelper.kt
@@ -20,12 +20,10 @@ import android.os.UserHandle
 import androidx.annotation.MainThread
 import com.android.intentresolver.annotation.JavaInterop
 import com.android.intentresolver.domain.interactor.UserInteractor
-import com.android.intentresolver.inject.IntentResolverFlags
 import com.android.intentresolver.shared.model.Profile
 import com.android.intentresolver.shared.model.User
 import javax.inject.Inject
 import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.runBlocking
 
@@ -33,12 +31,7 @@ import kotlinx.coroutines.runBlocking
 @MainThread
 class ProfileHelper
 @Inject
-constructor(
-    interactor: UserInteractor,
-    private val scope: CoroutineScope,
-    private val background: CoroutineDispatcher,
-    private val flags: IntentResolverFlags,
-) {
+constructor(interactor: UserInteractor, private val background: CoroutineDispatcher) {
     private val launchedByHandle: UserHandle = interactor.launchedAs
 
     val launchedAsProfile by lazy {
diff --git a/java/src/com/android/intentresolver/ResolverActivity.java b/java/src/com/android/intentresolver/ResolverActivity.java
index 38259281..a63b3a98 100644
--- a/java/src/com/android/intentresolver/ResolverActivity.java
+++ b/java/src/com/android/intentresolver/ResolverActivity.java
@@ -148,7 +148,6 @@ public class ResolverActivity extends Hilt_ResolverActivity implements
     @Inject public DevicePolicyResources mDevicePolicyResources;
     @Inject public ProfilePagerResources mProfilePagerResources;
     @Inject public IntentForwarding mIntentForwarding;
-    @Inject public FeatureFlags mFeatureFlags;
     @Inject public ActivityModelRepository mActivityModelRepository;
     @Inject public DefaultTargetDataLoader.Factory mTargetDataLoaderFactory;
 
@@ -323,9 +322,7 @@ public class ResolverActivity extends Hilt_ResolverActivity implements
 
         mProfiles =  new ProfileHelper(
                 mUserInteractor,
-                getCoroutineScope(getLifecycle()),
-                mBackgroundDispatcher,
-                mFeatureFlags);
+                mBackgroundDispatcher);
 
         mProfileAvailability = new ProfileAvailability(
                 mUserInteractor,
diff --git a/java/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoader.kt b/java/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoader.kt
deleted file mode 100644
index 847fcc82..00000000
--- a/java/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoader.kt
+++ /dev/null
@@ -1,110 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-import android.graphics.Bitmap
-import android.net.Uri
-import android.util.Log
-import android.util.Size
-import androidx.core.util.lruCache
-import com.android.intentresolver.inject.Background
-import com.android.intentresolver.inject.ViewModelOwned
-import javax.inject.Inject
-import javax.inject.Qualifier
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.Deferred
-import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.async
-import kotlinx.coroutines.ensureActive
-import kotlinx.coroutines.sync.Semaphore
-import kotlinx.coroutines.sync.withPermit
-import kotlinx.coroutines.withContext
-
-@Qualifier
-@MustBeDocumented
-@Retention(AnnotationRetention.BINARY)
-annotation class PreviewMaxConcurrency
-
-/**
- * Implementation of [ImageLoader].
- *
- * Allows for cached or uncached loading of images and limits the number of concurrent requests.
- * Requests are automatically cancelled when they are evicted from the cache. If image loading fails
- * or the request is cancelled (e.g. by eviction), the returned [Bitmap] will be null.
- */
-class CachingImagePreviewImageLoader
-@Inject
-constructor(
-    @ViewModelOwned private val scope: CoroutineScope,
-    @Background private val bgDispatcher: CoroutineDispatcher,
-    private val thumbnailLoader: ThumbnailLoader,
-    @PreviewCacheSize cacheSize: Int,
-    @PreviewMaxConcurrency maxConcurrency: Int,
-) : ImageLoader {
-
-    private val semaphore = Semaphore(maxConcurrency)
-
-    private val cache =
-        lruCache(
-            maxSize = cacheSize,
-            create = { uri: Uri -> scope.async { loadUncachedImage(uri) } },
-            onEntryRemoved = { evicted: Boolean, _, oldValue: Deferred<Bitmap?>, _ ->
-                // If removed due to eviction, cancel the coroutine, otherwise it is the
-                // responsibility
-                // of the caller of [cache.remove] to cancel the removed entry when done with it.
-                if (evicted) {
-                    oldValue.cancel()
-                }
-            }
-        )
-
-    override fun prePopulate(uriSizePairs: List<Pair<Uri, Size>>) {
-        uriSizePairs.take(cache.maxSize()).map { cache[it.first] }
-    }
-
-    override suspend fun invoke(uri: Uri, size: Size, caching: Boolean): Bitmap? {
-        return if (caching) {
-            loadCachedImage(uri)
-        } else {
-            loadUncachedImage(uri)
-        }
-    }
-
-    private suspend fun loadUncachedImage(uri: Uri): Bitmap? =
-        withContext(bgDispatcher) {
-            runCatching { semaphore.withPermit { thumbnailLoader.loadThumbnail(uri) } }
-                .onFailure {
-                    ensureActive()
-                    Log.d(TAG, "Failed to load preview for $uri", it)
-                }
-                .getOrNull()
-        }
-
-    private suspend fun loadCachedImage(uri: Uri): Bitmap? =
-        // [Deferred#await] is called in a [runCatching] block to catch
-        // [CancellationExceptions]s so that they don't cancel the calling coroutine/scope.
-        runCatching { cache[uri].await() }.getOrNull()
-
-    @OptIn(ExperimentalCoroutinesApi::class)
-    override fun getCachedBitmap(uri: Uri): Bitmap? =
-        kotlin.runCatching { cache[uri].getCompleted() }.getOrNull()
-
-    companion object {
-        private const val TAG = "CachingImgPrevLoader"
-    }
-}
diff --git a/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
index 4166e5ae..2af5881f 100644
--- a/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
@@ -184,7 +184,8 @@ public final class ChooserContentPreviewUi {
                             imageLoader,
                             typeClassifier,
                             headlineGenerator,
-                            metadata
+                            metadata,
+                            chooserRequest.getCallerAllowsTextToggle()
                     );
             if (previewData.getUriCount() > 0) {
                 JavaFlowHelper.collectToList(
diff --git a/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java
index 30161cfb..da701ec4 100644
--- a/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUi.java
@@ -62,6 +62,7 @@ class FilesPlusTextContentPreviewUi extends ContentPreviewUi {
     private final CharSequence mMetadata;
     private final boolean mIsSingleImage;
     private final int mFileCount;
+    private final boolean mAllowTextToggle;
     private ViewGroup mContentPreviewView;
     private View mHeadliveView;
     private boolean mIsMetadataUpdated = false;
@@ -70,8 +71,6 @@ class FilesPlusTextContentPreviewUi extends ContentPreviewUi {
     private boolean mAllImages;
     private boolean mAllVideos;
     private int mPreviewSize;
-    // TODO(b/285309527): make this a flag
-    private static final boolean SHOW_TOGGLE_CHECKMARK = false;
 
     FilesPlusTextContentPreviewUi(
             CoroutineScope scope,
@@ -83,7 +82,8 @@ class FilesPlusTextContentPreviewUi extends ContentPreviewUi {
             ImageLoader imageLoader,
             MimeTypeClassifier typeClassifier,
             HeadlineGenerator headlineGenerator,
-            @Nullable CharSequence metadata) {
+            @Nullable CharSequence metadata,
+            boolean allowTextToggle) {
         if (isSingleImage && fileCount != 1) {
             throw new IllegalArgumentException(
                     "fileCount = " + fileCount + " and isSingleImage = true");
@@ -98,6 +98,7 @@ class FilesPlusTextContentPreviewUi extends ContentPreviewUi {
         mTypeClassifier = typeClassifier;
         mHeadlineGenerator = headlineGenerator;
         mMetadata = metadata;
+        mAllowTextToggle = allowTextToggle;
     }
 
     @Override
@@ -234,7 +235,7 @@ class FilesPlusTextContentPreviewUi extends ContentPreviewUi {
             shareTextAction.accept(!isChecked);
             updateHeadline(headlineView, mFileCount, mAllImages, mAllVideos);
         });
-        if (SHOW_TOGGLE_CHECKMARK) {
+        if (mAllowTextToggle) {
             includeText.setVisibility(View.VISIBLE);
         }
     }
diff --git a/java/src/com/android/intentresolver/contentpreview/HeadlineGenerator.kt b/java/src/com/android/intentresolver/contentpreview/HeadlineGenerator.kt
index 059ee083..9c4122bb 100644
--- a/java/src/com/android/intentresolver/contentpreview/HeadlineGenerator.kt
+++ b/java/src/com/android/intentresolver/contentpreview/HeadlineGenerator.kt
@@ -38,4 +38,6 @@ interface HeadlineGenerator {
     fun getFilesHeadline(count: Int): String
 
     fun getNotItemsSelectedHeadline(): String
+
+    fun getCopyButtonContentDescription(sharedText: CharSequence): String
 }
diff --git a/java/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImpl.kt b/java/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImpl.kt
index 822d3097..ca01875b 100644
--- a/java/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImpl.kt
+++ b/java/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImpl.kt
@@ -33,11 +33,8 @@ private const val PLURALS_COUNT = "count"
  * HeadlineGenerator generates the text to show at the top of the sharesheet as a brief description
  * of the content being shared.
  */
-class HeadlineGeneratorImpl
-@Inject
-constructor(
-    @ApplicationContext private val context: Context,
-) : HeadlineGenerator {
+class HeadlineGeneratorImpl @Inject constructor(@ApplicationContext private val context: Context) :
+    HeadlineGenerator {
     override fun getTextHeadline(text: CharSequence): String {
         return context.getString(
             getTemplateResource(text, R.string.sharing_link, R.string.sharing_text)
@@ -53,9 +50,9 @@ constructor(
             getTemplateResource(
                 text,
                 R.string.sharing_images_with_link,
-                R.string.sharing_images_with_text
+                R.string.sharing_images_with_text,
             ),
-            count
+            count,
         )
     }
 
@@ -64,9 +61,9 @@ constructor(
             getTemplateResource(
                 text,
                 R.string.sharing_videos_with_link,
-                R.string.sharing_videos_with_text
+                R.string.sharing_videos_with_text,
             ),
-            count
+            count,
         )
     }
 
@@ -75,9 +72,9 @@ constructor(
             getTemplateResource(
                 text,
                 R.string.sharing_files_with_link,
-                R.string.sharing_files_with_text
+                R.string.sharing_files_with_text,
             ),
-            count
+            count,
         )
     }
 
@@ -96,11 +93,17 @@ constructor(
     override fun getNotItemsSelectedHeadline(): String =
         context.getString(R.string.select_items_to_share)
 
+    override fun getCopyButtonContentDescription(sharedText: CharSequence): String {
+        return context.getString(
+            getTemplateResource(sharedText, R.string.copy_link, R.string.copy_text)
+        )
+    }
+
     private fun getPluralString(@StringRes templateResource: Int, count: Int): String {
         return PluralsMessageFormatter.format(
             context.resources,
             mapOf(PLURALS_COUNT to count),
-            templateResource
+            templateResource,
         )
     }
 
@@ -108,7 +111,7 @@ constructor(
     private fun getTemplateResource(
         text: CharSequence,
         @StringRes linkResource: Int,
-        @StringRes nonLinkResource: Int
+        @StringRes nonLinkResource: Int,
     ): Int {
         return if (text.toString().isHttpUri()) linkResource else nonLinkResource
     }
diff --git a/java/src/com/android/intentresolver/contentpreview/ImageLoaderModule.kt b/java/src/com/android/intentresolver/contentpreview/ImageLoaderModule.kt
index 27e817db..7cc4458f 100644
--- a/java/src/com/android/intentresolver/contentpreview/ImageLoaderModule.kt
+++ b/java/src/com/android/intentresolver/contentpreview/ImageLoaderModule.kt
@@ -17,7 +17,6 @@
 package com.android.intentresolver.contentpreview
 
 import android.content.res.Resources
-import com.android.intentresolver.Flags
 import com.android.intentresolver.R
 import com.android.intentresolver.inject.ApplicationOwned
 import dagger.Binds
@@ -25,25 +24,15 @@ import dagger.Module
 import dagger.Provides
 import dagger.hilt.InstallIn
 import dagger.hilt.android.components.ViewModelComponent
-import javax.inject.Provider
 
 @Module
 @InstallIn(ViewModelComponent::class)
 interface ImageLoaderModule {
     @Binds fun thumbnailLoader(thumbnailLoader: ThumbnailLoaderImpl): ThumbnailLoader
 
-    companion object {
-        @Provides
-        fun imageLoader(
-            imagePreviewImageLoader: Provider<ImagePreviewImageLoader>,
-            previewImageLoader: Provider<PreviewImageLoader>
-        ): ImageLoader =
-            if (Flags.previewImageLoader()) {
-                previewImageLoader.get()
-            } else {
-                imagePreviewImageLoader.get()
-            }
+    @Binds fun imageLoader(previewImageLoader: PreviewImageLoader): ImageLoader
 
+    companion object {
         @Provides
         @ThumbnailSize
         fun thumbnailSize(@ApplicationOwned resources: Resources): Int =
diff --git a/java/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoader.kt b/java/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoader.kt
deleted file mode 100644
index 379bdb37..00000000
--- a/java/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoader.kt
+++ /dev/null
@@ -1,178 +0,0 @@
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
-import android.content.ContentResolver
-import android.graphics.Bitmap
-import android.net.Uri
-import android.util.Log
-import android.util.Size
-import androidx.annotation.GuardedBy
-import androidx.annotation.VisibleForTesting
-import androidx.collection.LruCache
-import com.android.intentresolver.inject.Background
-import javax.inject.Inject
-import javax.inject.Qualifier
-import kotlinx.coroutines.CancellationException
-import kotlinx.coroutines.CompletableDeferred
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.CoroutineExceptionHandler
-import kotlinx.coroutines.CoroutineName
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.Deferred
-import kotlinx.coroutines.SupervisorJob
-import kotlinx.coroutines.launch
-import kotlinx.coroutines.sync.Semaphore
-
-private const val TAG = "ImagePreviewImageLoader"
-
-@Qualifier @MustBeDocumented @Retention(AnnotationRetention.BINARY) annotation class ThumbnailSize
-
-@Qualifier
-@MustBeDocumented
-@Retention(AnnotationRetention.BINARY)
-annotation class PreviewCacheSize
-
-/**
- * Implements preview image loading for the content preview UI. Provides requests deduplication,
- * image caching, and a limit on the number of parallel loadings.
- */
-@VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
-class ImagePreviewImageLoader
-@VisibleForTesting
-constructor(
-    private val scope: CoroutineScope,
-    thumbnailSize: Int,
-    private val contentResolver: ContentResolver,
-    cacheSize: Int,
-    // TODO: consider providing a scope with the dispatcher configured with
-    //  [CoroutineDispatcher#limitedParallelism] instead
-    private val contentResolverSemaphore: Semaphore,
-) : ImageLoader {
-
-    @Inject
-    constructor(
-        @Background dispatcher: CoroutineDispatcher,
-        @ThumbnailSize thumbnailSize: Int,
-        contentResolver: ContentResolver,
-        @PreviewCacheSize cacheSize: Int,
-    ) : this(
-        CoroutineScope(
-            SupervisorJob() +
-                dispatcher +
-                CoroutineExceptionHandler { _, exception ->
-                    Log.w(TAG, "Uncaught exception in ImageLoader", exception)
-                } +
-                CoroutineName("ImageLoader")
-        ),
-        thumbnailSize,
-        contentResolver,
-        cacheSize,
-    )
-
-    constructor(
-        scope: CoroutineScope,
-        thumbnailSize: Int,
-        contentResolver: ContentResolver,
-        cacheSize: Int,
-        maxSimultaneousRequests: Int = 4
-    ) : this(scope, thumbnailSize, contentResolver, cacheSize, Semaphore(maxSimultaneousRequests))
-
-    private val thumbnailSize: Size = Size(thumbnailSize, thumbnailSize)
-
-    private val lock = Any()
-    @GuardedBy("lock") private val cache = LruCache<Uri, RequestRecord>(cacheSize)
-    @GuardedBy("lock") private val runningRequests = HashMap<Uri, RequestRecord>()
-
-    override suspend fun invoke(uri: Uri, size: Size, caching: Boolean): Bitmap? =
-        loadImageAsync(uri, caching)
-
-    override fun prePopulate(uriSizePairs: List<Pair<Uri, Size>>) {
-        uriSizePairs.asSequence().take(cache.maxSize()).forEach { (uri, _) ->
-            scope.launch { loadImageAsync(uri, caching = true) }
-        }
-    }
-
-    private suspend fun loadImageAsync(uri: Uri, caching: Boolean): Bitmap? {
-        return getRequestDeferred(uri, caching).await()
-    }
-
-    private fun getRequestDeferred(uri: Uri, caching: Boolean): Deferred<Bitmap?> {
-        var shouldLaunchImageLoading = false
-        val request =
-            synchronized(lock) {
-                cache[uri]
-                    ?: runningRequests
-                        .getOrPut(uri) {
-                            shouldLaunchImageLoading = true
-                            RequestRecord(uri, CompletableDeferred(), caching)
-                        }
-                        .apply { this.caching = this.caching || caching }
-            }
-        if (shouldLaunchImageLoading) {
-            request.loadBitmapAsync()
-        }
-        return request.deferred
-    }
-
-    private fun RequestRecord.loadBitmapAsync() {
-        scope
-            .launch { loadBitmap() }
-            .invokeOnCompletion { cause ->
-                if (cause is CancellationException) {
-                    cancel()
-                }
-            }
-    }
-
-    private suspend fun RequestRecord.loadBitmap() {
-        contentResolverSemaphore.acquire()
-        val bitmap =
-            try {
-                contentResolver.loadThumbnail(uri, thumbnailSize, null)
-            } catch (t: Throwable) {
-                Log.d(TAG, "failed to load $uri preview", t)
-                null
-            } finally {
-                contentResolverSemaphore.release()
-            }
-        complete(bitmap)
-    }
-
-    private fun RequestRecord.cancel() {
-        synchronized(lock) {
-            runningRequests.remove(uri)
-            deferred.cancel()
-        }
-    }
-
-    private fun RequestRecord.complete(bitmap: Bitmap?) {
-        deferred.complete(bitmap)
-        synchronized(lock) {
-            runningRequests.remove(uri)
-            if (bitmap != null && caching) {
-                cache.put(uri, this)
-            }
-        }
-    }
-
-    private class RequestRecord(
-        val uri: Uri,
-        val deferred: CompletableDeferred<Bitmap?>,
-        @GuardedBy("lock") var caching: Boolean
-    )
-}
diff --git a/java/src/com/android/intentresolver/contentpreview/PreviewImageLoader.kt b/java/src/com/android/intentresolver/contentpreview/PreviewImageLoader.kt
index b10f7ef9..44d88c41 100644
--- a/java/src/com/android/intentresolver/contentpreview/PreviewImageLoader.kt
+++ b/java/src/com/android/intentresolver/contentpreview/PreviewImageLoader.kt
@@ -25,6 +25,7 @@ import com.android.intentresolver.inject.Background
 import com.android.intentresolver.inject.ViewModelOwned
 import javax.annotation.concurrent.GuardedBy
 import javax.inject.Inject
+import javax.inject.Qualifier
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.ExperimentalCoroutinesApi
@@ -39,7 +40,19 @@ import kotlinx.coroutines.launch
 import kotlinx.coroutines.sync.Semaphore
 import kotlinx.coroutines.sync.withPermit
 
-private const val TAG = "PayloadSelImageLoader"
+private const val TAG = "ImageLoader"
+
+@Qualifier @MustBeDocumented @Retention(AnnotationRetention.BINARY) annotation class ThumbnailSize
+
+@Qualifier
+@MustBeDocumented
+@Retention(AnnotationRetention.BINARY)
+annotation class PreviewCacheSize
+
+@Qualifier
+@MustBeDocumented
+@Retention(AnnotationRetention.BINARY)
+annotation class PreviewMaxConcurrency
 
 /**
  * Implements preview image loading for the payload selection UI. Cancels preview loading for items
@@ -69,7 +82,7 @@ constructor(
                 if (oldRec !== newRec) {
                     onRecordEvictedFromCache(oldRec)
                 }
-            }
+            },
         )
 
     override suspend fun invoke(uri: Uri, size: Size, caching: Boolean): Bitmap? =
@@ -104,7 +117,7 @@ constructor(
     private suspend fun withRequestRecord(
         uri: Uri,
         caching: Boolean,
-        block: suspend (RequestRecord) -> Bitmap?
+        block: suspend (RequestRecord) -> Bitmap?,
     ): Bitmap? {
         val record = trackRecordRunning(uri, caching)
         return try {
diff --git a/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
index 45a0130d..8592e6ae 100644
--- a/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
@@ -142,6 +142,8 @@ class TextContentPreviewUi extends ContentPreviewUi {
         View copyButton = contentPreviewLayout.findViewById(R.id.copy);
         if (copyButton != null) {
             if (onCopy != null) {
+                copyButton.setContentDescription(
+                        mHeadlineGenerator.getCopyButtonContentDescription(mSharingText));
                 copyButton.setOnClickListener((v) -> onCopy.run());
                 ViewCompat.setAccessibilityDelegate(
                         copyButton,
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ModifierExt.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ModifierExt.kt
new file mode 100644
index 00000000..a9d8b9dc
--- /dev/null
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ModifierExt.kt
@@ -0,0 +1,118 @@
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
+package com.android.intentresolver.contentpreview.payloadtoggle.ui.composable
+
+import androidx.compose.foundation.gestures.ScrollableState
+import androidx.compose.foundation.gestures.animateScrollBy
+import androidx.compose.foundation.gestures.awaitEachGesture
+import androidx.compose.foundation.gestures.awaitFirstDown
+import androidx.compose.foundation.gestures.waitForUpOrCancellation
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.derivedStateOf
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.remember
+import androidx.compose.runtime.rememberCoroutineScope
+import androidx.compose.runtime.setValue
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.input.pointer.PointerEventPass
+import androidx.compose.ui.input.pointer.pointerInput
+import androidx.compose.ui.layout.onGloballyPositioned
+import androidx.compose.ui.platform.LocalLayoutDirection
+import androidx.compose.ui.unit.Dp
+import androidx.compose.ui.unit.LayoutDirection
+import androidx.compose.ui.unit.dp
+import kotlinx.coroutines.launch
+
+/** Calls [whenTrue] on this [Modifier] if [condition] is true. */
+@Composable
+inline fun Modifier.conditional(
+    condition: Boolean,
+    crossinline whenTrue: @Composable Modifier.() -> Modifier,
+): Modifier = if (condition) this.whenTrue() else this
+
+/**
+ * Overlays tap regions at the beginning and end of the scrollable region.
+ *
+ * When tap regions are tapped, [scrollableState] will be scrolled by the size of the modified
+ * scrollable multiplied by the [scrollRatio].
+ *
+ * Note: [scrollableState] must be shared with the scrollable being modified and [vertical] must be
+ * true only if the modified scrollable scrolls vertically.
+ */
+@Composable
+fun Modifier.tapToScroll(
+    scrollableState: ScrollableState,
+    vertical: Boolean = false,
+    tapRegionSize: Dp = 48.dp,
+    scrollRatio: Float = 0.5f,
+): Modifier {
+    val scope = rememberCoroutineScope()
+    var viewSize by remember { mutableStateOf(0) }
+    val isLtrLayoutDirection = LocalLayoutDirection.current == LayoutDirection.Ltr
+    val normalizedScrollVector = remember {
+        derivedStateOf {
+            if (vertical || isLtrLayoutDirection) {
+                viewSize * scrollRatio
+            } else {
+                -viewSize * scrollRatio
+            }
+        }
+    }
+    return onGloballyPositioned { viewSize = if (vertical) it.size.height else it.size.width }
+        .pointerInput(Unit) {
+            val tapRegionSizePx = tapRegionSize.roundToPx()
+
+            awaitEachGesture {
+                // Tap to scroll is disabled if the modified composable is not large enough to fit
+                // both tap regions.
+                if (viewSize < tapRegionSizePx * 2) return@awaitEachGesture
+
+                val down = awaitFirstDown(pass = PointerEventPass.Initial)
+                if (down.isConsumed) return@awaitEachGesture
+
+                val downPosition = if (vertical) down.position.y else down.position.x
+                val scrollVector =
+                    when {
+                        // Start taps scroll toward start
+                        downPosition <= tapRegionSizePx -> -normalizedScrollVector.value
+
+                        // End taps scroll toward end
+                        downPosition >= viewSize - tapRegionSizePx -> normalizedScrollVector.value
+
+                        // Middle taps are ignored
+                        else -> return@awaitEachGesture
+                    }
+
+                val up =
+                    waitForUpOrCancellation(pass = PointerEventPass.Initial)
+                        ?: return@awaitEachGesture
+
+                // Long presses are ignored
+                if (up.uptimeMillis - down.uptimeMillis >= viewConfiguration.longPressTimeoutMillis)
+                    return@awaitEachGesture
+
+                // Swipes are ignored
+                if ((up.position - down.position).getDistance() >= viewConfiguration.touchSlop)
+                    return@awaitEachGesture
+
+                down.consume()
+                up.consume()
+                scope.launch { scrollableState.animateScrollBy(scrollVector) }
+            }
+        }
+}
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
index c51021a8..015a0490 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
@@ -15,11 +15,14 @@
  */
 package com.android.intentresolver.contentpreview.payloadtoggle.ui.composable
 
+import android.graphics.Bitmap
 import androidx.compose.animation.Crossfade
+import androidx.compose.animation.core.animateFloatAsState
 import androidx.compose.foundation.ExperimentalFoundationApi
 import androidx.compose.foundation.Image
 import androidx.compose.foundation.background
 import androidx.compose.foundation.border
+import androidx.compose.foundation.clickable
 import androidx.compose.foundation.layout.Arrangement
 import androidx.compose.foundation.layout.Box
 import androidx.compose.foundation.layout.Column
@@ -36,7 +39,6 @@ import androidx.compose.foundation.layout.width
 import androidx.compose.foundation.lazy.LazyListState
 import androidx.compose.foundation.lazy.LazyRow
 import androidx.compose.foundation.lazy.itemsIndexed
-import androidx.compose.foundation.selection.toggleable
 import androidx.compose.foundation.shape.RoundedCornerShape
 import androidx.compose.foundation.systemGestureExclusion
 import androidx.compose.material3.AssistChip
@@ -52,14 +54,17 @@ import androidx.compose.runtime.mutableStateOf
 import androidx.compose.runtime.remember
 import androidx.compose.runtime.rememberCoroutineScope
 import androidx.compose.runtime.setValue
+import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
 import androidx.compose.ui.draw.clip
+import androidx.compose.ui.draw.scale
 import androidx.compose.ui.graphics.ColorFilter
 import androidx.compose.ui.graphics.asImageBitmap
 import androidx.compose.ui.layout.ContentScale
 import androidx.compose.ui.layout.MeasureScope
 import androidx.compose.ui.layout.Placeable
 import androidx.compose.ui.layout.layout
+import androidx.compose.ui.platform.testTag
 import androidx.compose.ui.res.dimensionResource
 import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.semantics.contentDescription
@@ -67,7 +72,10 @@ import androidx.compose.ui.semantics.semantics
 import androidx.compose.ui.unit.Dp
 import androidx.compose.ui.unit.dp
 import androidx.lifecycle.compose.collectAsStateWithLifecycle
+import com.android.intentresolver.Flags.announceShareouselItemListPosition
 import com.android.intentresolver.Flags.shareouselScrollOffscreenSelections
+import com.android.intentresolver.Flags.shareouselSelectionShrink
+import com.android.intentresolver.Flags.shareouselTapToScrollSupport
 import com.android.intentresolver.Flags.unselectFinalItem
 import com.android.intentresolver.R
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
@@ -80,6 +88,7 @@ import com.android.intentresolver.contentpreview.payloadtoggle.ui.viewmodel.Shar
 import kotlin.math.abs
 import kotlin.math.min
 import kotlin.math.roundToInt
+import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.launch
 
@@ -126,6 +135,7 @@ private fun PreviewCarousel(previews: PreviewsModel, viewModel: ShareouselViewMo
                         }
                     layout(placeable.width, placeable.height) { placeable.place(0, 0) }
                 }
+                .systemGestureExclusion()
     ) {
         // Do not compose the list until we have measured values
         if (measurements == PreviewCarouselMeasurements.UNMEASURED) return@Box
@@ -142,150 +152,235 @@ private fun PreviewCarousel(previews: PreviewsModel, viewModel: ShareouselViewMo
             )
         }
 
-        LazyRow(
+        PreviewCarouselItems(
             state = carouselState,
-            horizontalArrangement = Arrangement.spacedBy(4.dp),
-            contentPadding =
-                PaddingValues(
-                    start = measurements.horizontalPaddingDp,
-                    end = measurements.horizontalPaddingDp,
-                ),
-            modifier = Modifier.fillMaxSize().systemGestureExclusion(),
-        ) {
-            itemsIndexed(
-                items = previews.previewModels,
-                key = { _, model -> model.key.key to model.key.isFinal },
-            ) { index, model ->
-                val visibleItem by remember {
-                    derivedStateOf {
-                        carouselState.layoutInfo.visibleItemsInfo.firstOrNull { it.index == index }
-                    }
+            measurements = measurements,
+            previews = previews,
+            viewModel = viewModel,
+        )
+    }
+}
+
+@Composable
+private fun PreviewCarouselItems(
+    state: LazyListState,
+    measurements: PreviewCarouselMeasurements,
+    previews: PreviewsModel,
+    viewModel: ShareouselViewModel,
+) {
+    LazyRow(
+        state = state,
+        horizontalArrangement = Arrangement.spacedBy(4.dp),
+        contentPadding =
+            PaddingValues(
+                start = measurements.horizontalPaddingDp,
+                end = measurements.horizontalPaddingDp,
+            ),
+        modifier =
+            Modifier.fillMaxSize().conditional(shareouselTapToScrollSupport()) {
+                tapToScroll(scrollableState = state)
+            },
+    ) {
+        itemsIndexed(
+            items = previews.previewModels,
+            key = { _, model -> model.key.key to model.key.isFinal },
+        ) { index, model ->
+            val visibleItem by remember {
+                derivedStateOf {
+                    state.layoutInfo.visibleItemsInfo.firstOrNull { it.index == index }
                 }
+            }
 
-                // Index if this is the element in the center of the viewing area, otherwise null
-                val previewIndex by remember {
-                    derivedStateOf {
-                        visibleItem?.let {
-                            val halfPreviewWidth = it.size / 2
-                            val previewCenter = it.offset + halfPreviewWidth
-                            val previewDistanceToViewportCenter =
-                                abs(previewCenter - measurements.viewportCenterPx)
-                            if (previewDistanceToViewportCenter <= halfPreviewWidth) {
-                                index
-                            } else {
-                                null
-                            }
+            // Index if this is the element in the center of the viewing area, otherwise null
+            val previewIndex by remember {
+                derivedStateOf {
+                    visibleItem?.let {
+                        val halfPreviewWidth = it.size / 2
+                        val previewCenter = it.offset + halfPreviewWidth
+                        val previewDistanceToViewportCenter =
+                            abs(previewCenter - measurements.viewportCenterPx)
+                        if (previewDistanceToViewportCenter <= halfPreviewWidth) {
+                            index
+                        } else {
+                            null
                         }
                     }
                 }
+            }
 
-                val previewModel =
-                    viewModel.preview(
-                        /* key = */ model,
-                        /* previewHeight = */ measurements.viewportHeightPx,
-                        /* index = */ previewIndex,
-                        /* scope = */ rememberCoroutineScope(),
-                    )
+            val previewModel =
+                viewModel.preview(
+                    /* key = */ model,
+                    /* previewHeight = */ measurements.viewportHeightPx,
+                    /* index = */ previewIndex,
+                    /* scope = */ rememberCoroutineScope(),
+                )
 
-                if (shareouselScrollOffscreenSelections()) {
-                    LaunchedEffect(index, model.uri) {
-                        var current: Boolean? = null
-                        previewModel.isSelected.collect { selected ->
-                            when {
-                                // First update will always be the current state, so we just want to
-                                // record the state and do nothing else.
-                                current == null -> current = selected
+            if (shareouselScrollOffscreenSelections()) {
+                ScrollOffscreenSelectionsEffect(
+                    index = index,
+                    previewModel = model,
+                    isSelected = previewModel.isSelected,
+                    state = state,
+                    measurements = measurements,
+                )
+            }
+
+            ShareouselCard(
+                viewModel = previewModel,
+                aspectRatio = measurements.coerceAspectRatio(previewModel.aspectRatio),
+                annotateWithPosition = previews.previewModels.size > 1,
+            )
+        }
+    }
+}
+
+@Composable
+private fun ScrollOffscreenSelectionsEffect(
+    index: Int,
+    previewModel: PreviewModel,
+    isSelected: Flow<Boolean>,
+    state: LazyListState,
+    measurements: PreviewCarouselMeasurements,
+) {
+    LaunchedEffect(index, previewModel.uri) {
+        var current: Boolean? = null
+        isSelected.collect { selected ->
+            when {
+                // First update will always be the current state, so we just want to
+                // record the state and do nothing else.
+                current == null -> current = selected
 
-                                // We only want to act when the state changes
-                                current != selected -> {
-                                    current = selected
-                                    with(carouselState.layoutInfo) {
-                                        visibleItemsInfo
-                                            .firstOrNull { it.index == index }
-                                            ?.let { item ->
-                                                when {
-                                                    // Item is partially past start of viewport
-                                                    item.offset < viewportStartOffset ->
-                                                        measurements.scrollOffsetToStartEdge()
-                                                    // Item is partially past end of viewport
-                                                    (item.offset + item.size) > viewportEndOffset ->
-                                                        measurements.scrollOffsetToEndEdge(model)
-                                                    // Item is fully within viewport
-                                                    else -> null
-                                                }?.let { scrollOffset ->
-                                                    carouselState.animateScrollToItem(
-                                                        index = index,
-                                                        scrollOffset = scrollOffset,
-                                                    )
-                                                }
-                                            }
-                                    }
+                // We only want to act when the state changes
+                current != selected -> {
+                    current = selected
+                    with(state.layoutInfo) {
+                        visibleItemsInfo
+                            .firstOrNull { it.index == index }
+                            ?.let { item ->
+                                when {
+                                    // Item is partially past start of viewport
+                                    item.offset < viewportStartOffset ->
+                                        measurements.scrollOffsetToStartEdge()
+                                    // Item is partially past end of viewport
+                                    (item.offset + item.size) > viewportEndOffset ->
+                                        measurements.scrollOffsetToEndEdge(previewModel)
+                                    // Item is fully within viewport
+                                    else -> null
+                                }?.let { scrollOffset ->
+                                    state.animateScrollToItem(
+                                        index = index,
+                                        scrollOffset = scrollOffset,
+                                    )
                                 }
                             }
-                        }
                     }
                 }
-
-                ShareouselCard(
-                    viewModel = previewModel,
-                    aspectRatio = measurements.coerceAspectRatio(previewModel.aspectRatio),
-                )
             }
         }
     }
 }
 
 @Composable
-private fun ShareouselCard(viewModel: ShareouselPreviewViewModel, aspectRatio: Float) {
+private fun ShareouselCard(
+    viewModel: ShareouselPreviewViewModel,
+    aspectRatio: Float,
+    annotateWithPosition: Boolean,
+) {
     val bitmapLoadState by viewModel.bitmapLoadState.collectAsStateWithLifecycle()
     val selected by viewModel.isSelected.collectAsStateWithLifecycle(initialValue = false)
-    val borderColor = MaterialTheme.colorScheme.primary
-    val scope = rememberCoroutineScope()
     val contentDescription =
+        buildContentDescription(annotateWithPosition = annotateWithPosition, viewModel = viewModel)
+
+    Box(
+        modifier = Modifier.fillMaxHeight().aspectRatio(aspectRatio),
+        contentAlignment = Alignment.Center,
+    ) {
+        val scope = rememberCoroutineScope()
+        Crossfade(
+            targetState = bitmapLoadState,
+            modifier =
+                Modifier.semantics { this.contentDescription = contentDescription }
+                    .testTag(viewModel.testTag)
+                    .clickable { scope.launch { viewModel.setSelected(!selected) } }
+                    .conditional(shareouselSelectionShrink()) {
+                        val selectionScale by animateFloatAsState(if (selected) 0.95f else 1f)
+                        scale(selectionScale)
+                    }
+                    .clip(RoundedCornerShape(size = 12.dp)),
+        ) { state ->
+            if (state is ValueUpdate.Value) {
+                ShareouselBitmapCard(
+                    bitmap = state.getOrDefault(null),
+                    aspectRatio = aspectRatio,
+                    contentType = viewModel.contentType,
+                    selected = selected,
+                )
+            } else {
+                PlaceholderBox(aspectRatio)
+            }
+        }
+    }
+}
+
+@Composable
+private fun buildContentDescription(
+    annotateWithPosition: Boolean,
+    viewModel: ShareouselPreviewViewModel,
+): String = buildString {
+    if (
+        announceShareouselItemListPosition() &&
+            annotateWithPosition &&
+            viewModel.cursorPosition >= 0
+    ) {
+        // If item cursor position is not known, do not announce item position.
+        // We can have items with an unknown cursor position only when:
+        // * when we haven't got the cursor and showing the initially shared items;
+        // * when we've got an inconsistent data from the app (some initially shared items
+        //   are missing in the cursor);
+        append(stringResource(R.string.item_position_label, viewModel.cursorPosition + 1))
+        append(", ")
+    }
+    append(
         when (viewModel.contentType) {
             ContentType.Image -> stringResource(R.string.selectable_image)
             ContentType.Video -> stringResource(R.string.selectable_video)
             else -> stringResource(R.string.selectable_item)
         }
-    Crossfade(
-        targetState = bitmapLoadState,
-        modifier =
-            Modifier.semantics { this.contentDescription = contentDescription }
-                .clip(RoundedCornerShape(size = 12.dp))
-                .toggleable(
-                    value = selected,
-                    onValueChange = { scope.launch { viewModel.setSelected(it) } },
-                ),
-    ) { state ->
-        if (state is ValueUpdate.Value) {
-            state.getOrDefault(null).let { bitmap ->
-                ShareouselCard(
-                    image = {
-                        bitmap?.let {
-                            Image(
-                                bitmap = bitmap.asImageBitmap(),
-                                contentDescription = null,
-                                contentScale = ContentScale.Crop,
-                                modifier = Modifier.aspectRatio(aspectRatio),
-                            )
-                        } ?: PlaceholderBox(aspectRatio)
-                    },
-                    contentType = viewModel.contentType,
-                    selected = selected,
-                    modifier =
-                        Modifier.thenIf(selected) {
-                            Modifier.border(
-                                width = 4.dp,
-                                color = borderColor,
-                                shape = RoundedCornerShape(size = 12.dp),
-                            )
-                        },
+    )
+}
+
+@Composable
+private fun ShareouselBitmapCard(
+    bitmap: Bitmap?,
+    aspectRatio: Float,
+    contentType: ContentType,
+    selected: Boolean,
+) {
+    ShareouselCard(
+        image = {
+            if (bitmap == null) {
+                PlaceholderBox(aspectRatio)
+            } else {
+                Image(
+                    bitmap = bitmap.asImageBitmap(),
+                    contentDescription = null,
+                    contentScale = ContentScale.Crop,
+                    modifier = Modifier.aspectRatio(aspectRatio),
                 )
             }
-        } else {
-            PlaceholderBox(aspectRatio)
-        }
-    }
+        },
+        contentType = contentType,
+        selected = selected,
+        modifier =
+            Modifier.conditional(selected) {
+                border(
+                    width = 4.dp,
+                    color = MaterialTheme.colorScheme.primary,
+                    shape = RoundedCornerShape(size = 12.dp),
+                )
+            },
+    )
 }
 
 @Composable
@@ -370,9 +465,6 @@ private fun ShareouselAction(
     )
 }
 
-inline fun Modifier.thenIf(condition: Boolean, crossinline factory: () -> Modifier): Modifier =
-    if (condition) this.then(factory()) else this
-
 private data class PreviewCarouselMeasurements(
     val viewportHeightPx: Int,
     val viewportWidthPx: Int,
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselPreviewViewModel.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselPreviewViewModel.kt
index de435290..85f278a6 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselPreviewViewModel.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselPreviewViewModel.kt
@@ -33,4 +33,6 @@ data class ShareouselPreviewViewModel(
     /** Sets whether this preview has been selected by the user. */
     val setSelected: suspend (Boolean) -> Unit,
     val aspectRatio: Float,
+    val cursorPosition: Int,
+    val testTag: String,
 )
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt
index ebcd58d1..45e01e9d 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModel.kt
@@ -16,14 +16,10 @@
 package com.android.intentresolver.contentpreview.payloadtoggle.ui.viewmodel
 
 import android.util.Size
-import com.android.intentresolver.Flags
 import com.android.intentresolver.Flags.unselectFinalItem
-import com.android.intentresolver.contentpreview.CachingImagePreviewImageLoader
 import com.android.intentresolver.contentpreview.HeadlineGenerator
 import com.android.intentresolver.contentpreview.ImageLoader
 import com.android.intentresolver.contentpreview.MimeTypeClassifier
-import com.android.intentresolver.contentpreview.PreviewImageLoader
-import com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor.PayloadToggle
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.ChooserRequestInteractor
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.CustomActionsInteractor
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.SelectablePreviewsInteractor
@@ -37,7 +33,6 @@ import dagger.Module
 import dagger.Provides
 import dagger.hilt.InstallIn
 import dagger.hilt.android.components.ViewModelComponent
-import javax.inject.Provider
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.SharingStarted
@@ -65,7 +60,7 @@ data class ShareouselViewModel(
     /** Creates a [ShareouselPreviewViewModel] for a [PreviewModel] present in [previews]. */
     val preview:
         (
-            key: PreviewModel, previewHeight: Int, index: Int?, scope: CoroutineScope
+            key: PreviewModel, previewHeight: Int, index: Int?, scope: CoroutineScope,
         ) -> ShareouselPreviewViewModel,
 )
 
@@ -73,22 +68,10 @@ data class ShareouselViewModel(
 @InstallIn(ViewModelComponent::class)
 object ShareouselViewModelModule {
 
-    @Provides
-    @PayloadToggle
-    fun imageLoader(
-        cachingImageLoader: Provider<CachingImagePreviewImageLoader>,
-        previewImageLoader: Provider<PreviewImageLoader>
-    ): ImageLoader =
-        if (Flags.previewImageLoader()) {
-            previewImageLoader.get()
-        } else {
-            cachingImageLoader.get()
-        }
-
     @Provides
     fun create(
         interactor: SelectablePreviewsInteractor,
-        @PayloadToggle imageLoader: ImageLoader,
+        imageLoader: ImageLoader,
         actionsInteractor: CustomActionsInteractor,
         headlineGenerator: HeadlineGenerator,
         selectionInteractor: SelectionInteractor,
@@ -97,12 +80,7 @@ object ShareouselViewModelModule {
         // TODO: remove if possible
         @ViewModelOwned scope: CoroutineScope,
     ): ShareouselViewModel {
-        val keySet =
-            interactor.previews.stateIn(
-                scope,
-                SharingStarted.Eagerly,
-                initialValue = null,
-            )
+        val keySet = interactor.previews.stateIn(scope, SharingStarted.Eagerly, initialValue = null)
         return ShareouselViewModel(
             headline =
                 selectionInteractor.aggregateContentType.zip(selectionInteractor.amountSelected) {
@@ -174,6 +152,9 @@ object ShareouselViewModelModule {
                     isSelected = previewInteractor.isSelected,
                     setSelected = previewInteractor::setSelected,
                     aspectRatio = key.aspectRatio,
+                    // only items with a final key has a known cursor position
+                    cursorPosition = if (key.key.isFinal) key.order else -1,
+                    testTag = key.uri.toString(),
                 )
             },
         )
diff --git a/java/src/com/android/intentresolver/data/model/ChooserRequest.kt b/java/src/com/android/intentresolver/data/model/ChooserRequest.kt
index c4aa2b98..ad338103 100644
--- a/java/src/com/android/intentresolver/data/model/ChooserRequest.kt
+++ b/java/src/com/android/intentresolver/data/model/ChooserRequest.kt
@@ -28,7 +28,9 @@ import android.service.chooser.ChooserAction
 import android.service.chooser.ChooserTarget
 import androidx.annotation.StringRes
 import com.android.intentresolver.ContentTypeHint
+import com.android.intentresolver.IChooserInteractiveSessionCallback
 import com.android.intentresolver.ext.hasAction
+import com.android.systemui.shared.Flags.screenshotContextUrl
 
 const val ANDROID_APP_SCHEME = "android-app"
 
@@ -182,6 +184,7 @@ data class ChooserRequest(
      * Specified by the [Intent.EXTRA_METADATA_TEXT]
      */
     val metadataText: CharSequence? = null,
+    val interactiveSessionCallback: IChooserInteractiveSessionCallback? = null,
 ) {
     val referrerPackage = referrer?.takeIf { it.scheme == ANDROID_APP_SCHEME }?.authority
 
@@ -194,4 +197,7 @@ data class ChooserRequest(
     }
 
     val payloadIntents = listOf(targetIntent) + additionalTargets
+
+    val callerAllowsTextToggle =
+        screenshotContextUrl() && "com.android.systemui".equals(referrerPackage)
 }
diff --git a/java/src/com/android/intentresolver/data/repository/ChooserRequestRepository.kt b/java/src/com/android/intentresolver/data/repository/ChooserRequestRepository.kt
index 14177b1b..8b7885c9 100644
--- a/java/src/com/android/intentresolver/data/repository/ChooserRequestRepository.kt
+++ b/java/src/com/android/intentresolver/data/repository/ChooserRequestRepository.kt
@@ -25,10 +25,7 @@ import kotlinx.coroutines.flow.MutableStateFlow
 @ViewModelScoped
 class ChooserRequestRepository
 @Inject
-constructor(
-    initialRequest: ChooserRequest,
-    initialActions: List<CustomActionModel>,
-) {
+constructor(val initialRequest: ChooserRequest, initialActions: List<CustomActionModel>) {
     /** All information from the sharing application pertaining to the chooser. */
     val chooserRequest: MutableStateFlow<ChooserRequest> = MutableStateFlow(initialRequest)
 
diff --git a/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java b/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java
index 9a50d7e4..f78fffd6 100644
--- a/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java
+++ b/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java
@@ -37,7 +37,6 @@ import androidx.annotation.Nullable;
 import androidx.recyclerview.widget.RecyclerView;
 
 import com.android.intentresolver.ChooserListAdapter;
-import com.android.intentresolver.FeatureFlags;
 import com.android.intentresolver.R;
 import com.android.intentresolver.ResolverListAdapter.ViewHolder;
 
@@ -89,7 +88,6 @@ public final class ChooserGridAdapter extends RecyclerView.Adapter<RecyclerView.
     private final int mMaxTargetsPerRow;
     private final boolean mShouldShowContentPreview;
     private final int mChooserRowTextOptionTranslatePixelSize;
-    private final FeatureFlags mFeatureFlags;
     @Nullable
     private RecyclerView mRecyclerView;
 
@@ -104,8 +102,7 @@ public final class ChooserGridAdapter extends RecyclerView.Adapter<RecyclerView.
             ChooserActivityDelegate chooserActivityDelegate,
             ChooserListAdapter wrappedAdapter,
             boolean shouldShowContentPreview,
-            int maxTargetsPerRow,
-            FeatureFlags featureFlags) {
+            int maxTargetsPerRow) {
         super();
 
         mChooserActivityDelegate = chooserActivityDelegate;
@@ -118,7 +115,6 @@ public final class ChooserGridAdapter extends RecyclerView.Adapter<RecyclerView.
 
         mChooserRowTextOptionTranslatePixelSize = context.getResources().getDimensionPixelSize(
                 R.dimen.chooser_row_text_option_translate);
-        mFeatureFlags = featureFlags;
 
         wrappedAdapter.registerDataSetObserver(new DataSetObserver() {
             @Override
diff --git a/java/src/com/android/intentresolver/inject/FeatureFlagsModule.kt b/java/src/com/android/intentresolver/inject/FeatureFlagsModule.kt
deleted file mode 100644
index d7be67db..00000000
--- a/java/src/com/android/intentresolver/inject/FeatureFlagsModule.kt
+++ /dev/null
@@ -1,41 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.intentresolver.inject
-
-import android.service.chooser.FeatureFlagsImpl as ChooserServiceFlagsImpl
-import com.android.intentresolver.FeatureFlagsImpl as IntentResolverFlagsImpl
-import dagger.Module
-import dagger.Provides
-import dagger.hilt.InstallIn
-import dagger.hilt.components.SingletonComponent
-
-typealias IntentResolverFlags = com.android.intentresolver.FeatureFlags
-
-typealias FakeIntentResolverFlags = com.android.intentresolver.FakeFeatureFlagsImpl
-
-typealias ChooserServiceFlags = android.service.chooser.FeatureFlags
-
-typealias FakeChooserServiceFlags = android.service.chooser.FakeFeatureFlagsImpl
-
-@Module
-@InstallIn(SingletonComponent::class)
-object FeatureFlagsModule {
-
-    @Provides fun intentResolverFlags(): IntentResolverFlags = IntentResolverFlagsImpl()
-
-    @Provides fun chooserServiceFlags(): ChooserServiceFlags = ChooserServiceFlagsImpl()
-}
diff --git a/java/src/com/android/intentresolver/interactive/data/repository/InteractiveSessionCallbackRepository.kt b/java/src/com/android/intentresolver/interactive/data/repository/InteractiveSessionCallbackRepository.kt
new file mode 100644
index 00000000..f8894de5
--- /dev/null
+++ b/java/src/com/android/intentresolver/interactive/data/repository/InteractiveSessionCallbackRepository.kt
@@ -0,0 +1,54 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.intentresolver.interactive.data.repository
+
+import android.os.Bundle
+import androidx.lifecycle.SavedStateHandle
+import com.android.intentresolver.IChooserController
+import com.android.intentresolver.interactive.domain.model.ChooserIntentUpdater
+import dagger.hilt.android.scopes.ViewModelScoped
+import java.util.concurrent.atomic.AtomicReference
+import javax.inject.Inject
+
+private const val INTERACTIVE_SESSION_CALLBACK_KEY = "interactive-session-callback"
+
+@ViewModelScoped
+class InteractiveSessionCallbackRepository @Inject constructor(savedStateHandle: SavedStateHandle) {
+    private val intentUpdaterRef =
+        AtomicReference<ChooserIntentUpdater?>(
+            savedStateHandle
+                .get<Bundle>(INTERACTIVE_SESSION_CALLBACK_KEY)
+                ?.let { it.getBinder(INTERACTIVE_SESSION_CALLBACK_KEY) }
+                ?.let { binder ->
+                    binder.queryLocalInterface(IChooserController.DESCRIPTOR)
+                        as? ChooserIntentUpdater
+                }
+        )
+
+    val intentUpdater: ChooserIntentUpdater?
+        get() = intentUpdaterRef.get()
+
+    init {
+        savedStateHandle.setSavedStateProvider(INTERACTIVE_SESSION_CALLBACK_KEY) {
+            Bundle().apply { putBinder(INTERACTIVE_SESSION_CALLBACK_KEY, intentUpdater) }
+        }
+    }
+
+    fun setChooserIntentUpdater(intentUpdater: ChooserIntentUpdater) {
+        intentUpdaterRef.compareAndSet(null, intentUpdater)
+    }
+}
diff --git a/java/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractor.kt b/java/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractor.kt
new file mode 100644
index 00000000..09b79985
--- /dev/null
+++ b/java/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractor.kt
@@ -0,0 +1,139 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+import android.content.Intent
+import android.os.Bundle
+import android.os.IBinder
+import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.PendingSelectionCallbackRepository
+import com.android.intentresolver.data.model.ChooserRequest
+import com.android.intentresolver.data.repository.ActivityModelRepository
+import com.android.intentresolver.data.repository.ChooserRequestRepository
+import com.android.intentresolver.interactive.data.repository.InteractiveSessionCallbackRepository
+import com.android.intentresolver.interactive.domain.model.ChooserIntentUpdater
+import com.android.intentresolver.ui.viewmodel.readChooserRequest
+import com.android.intentresolver.validation.Invalid
+import com.android.intentresolver.validation.Valid
+import com.android.intentresolver.validation.log
+import dagger.hilt.android.scopes.ViewModelScoped
+import javax.inject.Inject
+import kotlinx.coroutines.awaitCancellation
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.update
+import kotlinx.coroutines.launch
+
+private const val TAG = "ChooserSession"
+
+@ViewModelScoped
+class InteractiveSessionInteractor
+@Inject
+constructor(
+    activityModelRepo: ActivityModelRepository,
+    private val chooserRequestRepository: ChooserRequestRepository,
+    private val pendingSelectionCallbackRepo: PendingSelectionCallbackRepository,
+    private val interactiveCallbackRepo: InteractiveSessionCallbackRepository,
+) {
+    private val activityModel = activityModelRepo.value
+    private val sessionCallback =
+        chooserRequestRepository.initialRequest.interactiveSessionCallback?.let {
+            SafeChooserInteractiveSessionCallback(it)
+        }
+    val isSessionActive = MutableStateFlow(true)
+
+    suspend fun activate() = coroutineScope {
+        if (sessionCallback == null || activityModel.isTaskRoot) {
+            sessionCallback?.registerChooserController(null)
+            return@coroutineScope
+        }
+        launch {
+            val callbackBinder: IBinder = sessionCallback.asBinder()
+            if (callbackBinder.isBinderAlive) {
+                val deathRecipient = IBinder.DeathRecipient { isSessionActive.value = false }
+                callbackBinder.linkToDeath(deathRecipient, 0)
+                try {
+                    awaitCancellation()
+                } finally {
+                    runCatching { sessionCallback.asBinder().unlinkToDeath(deathRecipient, 0) }
+                }
+            } else {
+                isSessionActive.value = false
+            }
+        }
+        val chooserIntentUpdater =
+            interactiveCallbackRepo.intentUpdater
+                ?: ChooserIntentUpdater().also {
+                    interactiveCallbackRepo.setChooserIntentUpdater(it)
+                    sessionCallback.registerChooserController(it)
+                }
+        chooserIntentUpdater.chooserIntent.collect { onIntentUpdated(it) }
+    }
+
+    fun sendTopDrawerTopOffsetChange(offset: Int) {
+        sessionCallback?.onDrawerVerticalOffsetChanged(offset)
+    }
+
+    fun endSession() {
+        sessionCallback?.registerChooserController(null)
+    }
+
+    private fun onIntentUpdated(chooserIntent: Intent?) {
+        if (chooserIntent == null) {
+            isSessionActive.value = false
+            return
+        }
+
+        val result =
+            readChooserRequest(
+                chooserIntent.extras ?: Bundle(),
+                activityModel.launchedFromPackage,
+                activityModel.referrer,
+            )
+        when (result) {
+            is Valid<ChooserRequest> -> {
+                val newRequest = result.value
+                pendingSelectionCallbackRepo.pendingTargetIntent.compareAndSet(
+                    null,
+                    result.value.targetIntent,
+                )
+                chooserRequestRepository.chooserRequest.update {
+                    it.copy(
+                        targetIntent = newRequest.targetIntent,
+                        targetAction = newRequest.targetAction,
+                        isSendActionTarget = newRequest.isSendActionTarget,
+                        targetType = newRequest.targetType,
+                        filteredComponentNames = newRequest.filteredComponentNames,
+                        callerChooserTargets = newRequest.callerChooserTargets,
+                        additionalTargets = newRequest.additionalTargets,
+                        replacementExtras = newRequest.replacementExtras,
+                        initialIntents = newRequest.initialIntents,
+                        shareTargetFilter = newRequest.shareTargetFilter,
+                        chosenComponentSender = newRequest.chosenComponentSender,
+                        refinementIntentSender = newRequest.refinementIntentSender,
+                    )
+                }
+                pendingSelectionCallbackRepo.pendingTargetIntent.compareAndSet(
+                    result.value.targetIntent,
+                    null,
+                )
+            }
+            is Invalid -> {
+                result.errors.forEach { it.log(TAG) }
+            }
+        }
+    }
+}
diff --git a/java/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserInteractiveSessionCallback.kt b/java/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserInteractiveSessionCallback.kt
new file mode 100644
index 00000000..d746a3b5
--- /dev/null
+++ b/java/src/com/android/intentresolver/interactive/domain/interactor/SafeChooserInteractiveSessionCallback.kt
@@ -0,0 +1,43 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+import android.util.Log
+import com.android.intentresolver.IChooserController
+import com.android.intentresolver.IChooserInteractiveSessionCallback
+
+private const val TAG = "SessionCallback"
+
+class SafeChooserInteractiveSessionCallback(
+    private val delegate: IChooserInteractiveSessionCallback
+) : IChooserInteractiveSessionCallback by delegate {
+
+    override fun registerChooserController(updater: IChooserController?) {
+        if (!isAlive) return
+        runCatching { delegate.registerChooserController(updater) }
+            .onFailure { Log.e(TAG, "Failed to invoke registerChooserController", it) }
+    }
+
+    override fun onDrawerVerticalOffsetChanged(offset: Int) {
+        if (!isAlive) return
+        runCatching { delegate.onDrawerVerticalOffsetChanged(offset) }
+            .onFailure { Log.e(TAG, "Failed to invoke onDrawerVerticalOffsetChanged", it) }
+    }
+
+    private val isAlive: Boolean
+        get() = delegate.asBinder().isBinderAlive
+}
diff --git a/java/src/com/android/intentresolver/interactive/domain/model/ChooserIntentUpdater.kt b/java/src/com/android/intentresolver/interactive/domain/model/ChooserIntentUpdater.kt
new file mode 100644
index 00000000..5466a95d
--- /dev/null
+++ b/java/src/com/android/intentresolver/interactive/domain/model/ChooserIntentUpdater.kt
@@ -0,0 +1,36 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.intentresolver.interactive.domain.model
+
+import android.content.Intent
+import com.android.intentresolver.IChooserController
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.filter
+
+private val NotSet = Intent()
+
+class ChooserIntentUpdater : IChooserController.Stub() {
+    private val updates = MutableStateFlow<Intent?>(NotSet)
+
+    val chooserIntent: Flow<Intent?>
+        get() = updates.filter { it !== NotSet }
+
+    override fun updateIntent(chooserIntent: Intent?) {
+        updates.value = chooserIntent
+    }
+}
diff --git a/java/src/com/android/intentresolver/shared/model/ActivityModel.kt b/java/src/com/android/intentresolver/shared/model/ActivityModel.kt
index c5efdeba..1a57759d 100644
--- a/java/src/com/android/intentresolver/shared/model/ActivityModel.kt
+++ b/java/src/com/android/intentresolver/shared/model/ActivityModel.kt
@@ -35,6 +35,8 @@ data class ActivityModel(
     val launchedFromPackage: String,
     /** The referrer as supplied to the activity. */
     val referrer: Uri?,
+    /** True if the activity is the first activity in the task */
+    val isTaskRoot: Boolean,
 ) : Parcelable {
     constructor(
         source: Parcel
@@ -43,6 +45,7 @@ data class ActivityModel(
         launchedFromUid = source.readInt(),
         launchedFromPackage = requireNotNull(source.readString()),
         referrer = source.readParcelable(),
+        isTaskRoot = source.readBoolean(),
     )
 
     /** A package name from referrer, if it is an android-app URI */
@@ -55,6 +58,7 @@ data class ActivityModel(
         dest.writeInt(launchedFromUid)
         dest.writeString(launchedFromPackage)
         dest.writeParcelable(referrer, flags)
+        dest.writeBoolean(isTaskRoot)
     }
 
     companion object {
@@ -74,6 +78,7 @@ data class ActivityModel(
                 activity.launchedFromUid,
                 Objects.requireNonNull<String>(activity.launchedFromPackage),
                 activity.referrer,
+                activity.isTaskRoot,
             )
         }
     }
diff --git a/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt b/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt
index 828d8561..aa1f385f 100644
--- a/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt
+++ b/java/src/com/android/intentresolver/shortcuts/ShortcutLoader.kt
@@ -35,8 +35,7 @@ import androidx.annotation.MainThread
 import androidx.annotation.OpenForTesting
 import androidx.annotation.VisibleForTesting
 import androidx.annotation.WorkerThread
-import com.android.intentresolver.Flags.fixShortcutLoaderJobLeak
-import com.android.intentresolver.Flags.fixShortcutsFlashing
+import com.android.intentresolver.Flags.fixShortcutsFlashingFixed
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.measurements.Tracer
 import com.android.intentresolver.measurements.runTracing
@@ -80,8 +79,7 @@ constructor(
     private val dispatcher: CoroutineDispatcher,
     private val callback: Consumer<Result>,
 ) {
-    private val scope =
-        if (fixShortcutLoaderJobLeak()) parentScope.createChildScope() else parentScope
+    private val scope = parentScope.createChildScope()
     private val shortcutToChooserTargetConverter = ShortcutToChooserTargetConverter()
     private val userManager = context.getSystemService(Context.USER_SERVICE) as UserManager
     private val appPredictorWatchdog = AtomicReference<Job?>(null)
@@ -170,9 +168,7 @@ constructor(
 
     @OpenForTesting
     open fun destroy() {
-        if (fixShortcutLoaderJobLeak()) {
-            scope.cancel()
-        }
+        scope.cancel()
     }
 
     @WorkerThread
@@ -193,7 +189,7 @@ constructor(
                 Log.d(TAG, "[$id] query AppPredictor for user $userHandle")
 
                 val watchdogJob =
-                    if (fixShortcutsFlashing()) {
+                    if (fixShortcutsFlashingFixed()) {
                         scope
                             .launch(start = CoroutineStart.LAZY) {
                                 delay(APP_PREDICTOR_RESPONSE_TIMEOUT_MS)
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt b/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
index 13de84b2..cb4bdcc1 100644
--- a/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
+++ b/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
@@ -40,9 +40,11 @@ import android.content.IntentSender
 import android.net.Uri
 import android.os.Bundle
 import android.service.chooser.ChooserAction
+import android.service.chooser.ChooserSession
 import android.service.chooser.ChooserTarget
 import com.android.intentresolver.ChooserActivity
 import com.android.intentresolver.ContentTypeHint
+import com.android.intentresolver.Flags.interactiveSession
 import com.android.intentresolver.R
 import com.android.intentresolver.data.model.ChooserRequest
 import com.android.intentresolver.ext.hasSendAction
@@ -58,6 +60,8 @@ import com.android.intentresolver.validation.validateFrom
 
 private const val MAX_CHOOSER_ACTIONS = 5
 private const val MAX_INITIAL_INTENTS = 2
+private const val EXTRA_CHOOSER_INTERACTIVE_CALLBACK =
+    "com.android.extra.EXTRA_CHOOSER_INTERACTIVE_CALLBACK"
 
 internal fun Intent.maybeAddSendActionFlags() =
     ifMatch(Intent::hasSendAction) {
@@ -68,6 +72,14 @@ internal fun Intent.maybeAddSendActionFlags() =
 fun readChooserRequest(
     model: ActivityModel,
     savedState: Bundle = model.intent.extras ?: Bundle(),
+): ValidationResult<ChooserRequest> {
+    return readChooserRequest(savedState, model.launchedFromPackage, model.referrer)
+}
+
+fun readChooserRequest(
+    savedState: Bundle,
+    launchedFromPackage: String,
+    referrer: Uri?,
 ): ValidationResult<ChooserRequest> {
     @Suppress("DEPRECATION")
     return validateFrom(savedState::get) {
@@ -139,18 +151,26 @@ fun readChooserRequest(
 
         val metadataText = optional(value<CharSequence>(EXTRA_METADATA_TEXT))
 
+        val interactiveSessionCallback =
+            if (interactiveSession()) {
+                optional(value<ChooserSession>(EXTRA_CHOOSER_INTERACTIVE_CALLBACK))
+                    ?.sessionCallbackBinder
+            } else {
+                null
+            }
+
         ChooserRequest(
             targetIntent = targetIntent,
             targetAction = targetIntent.action,
             isSendActionTarget = isSendAction,
             targetType = targetIntent.type,
             launchedFromPackage =
-                requireNotNull(model.launchedFromPackage) {
+                requireNotNull(launchedFromPackage) {
                     "launch.fromPackage was null, See Activity.getLaunchedFromPackage()"
                 },
             title = customTitle,
             defaultTitleResource = defaultTitleResource,
-            referrer = model.referrer,
+            referrer = referrer,
             filteredComponentNames = filteredComponents,
             callerChooserTargets = callerChooserTargets,
             chooserActions = chooserActions,
@@ -168,6 +188,7 @@ fun readChooserRequest(
             focusedItemPosition = focusedItemPos,
             contentTypeHint = contentTypeHint,
             metadataText = metadataText,
+            interactiveSessionCallback = interactiveSessionCallback,
         )
     }
 }
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt b/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
index 8597d802..7bc811c0 100644
--- a/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
+++ b/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
@@ -21,6 +21,7 @@ import android.util.Log
 import androidx.lifecycle.SavedStateHandle
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
+import com.android.intentresolver.Flags.interactiveSession
 import com.android.intentresolver.Flags.saveShareouselState
 import com.android.intentresolver.contentpreview.ImageLoader
 import com.android.intentresolver.contentpreview.PreviewDataProvider
@@ -32,6 +33,7 @@ import com.android.intentresolver.data.repository.ActivityModelRepository
 import com.android.intentresolver.data.repository.ChooserRequestRepository
 import com.android.intentresolver.domain.saveUpdates
 import com.android.intentresolver.inject.Background
+import com.android.intentresolver.interactive.domain.interactor.InteractiveSessionInteractor
 import com.android.intentresolver.shared.model.ActivityModel
 import com.android.intentresolver.validation.Invalid
 import com.android.intentresolver.validation.Valid
@@ -67,6 +69,7 @@ constructor(
     private val chooserRequestRepository: Lazy<ChooserRequestRepository>,
     private val contentResolver: ContentInterface,
     val imageLoader: ImageLoader,
+    private val interactiveSessionInteractorLazy: Lazy<InteractiveSessionInteractor>,
 ) : ViewModel() {
 
     /** Parcelable-only references provided from the creating Activity */
@@ -98,6 +101,9 @@ constructor(
         )
     }
 
+    val interactiveSessionInteractor: InteractiveSessionInteractor
+        get() = interactiveSessionInteractorLazy.get()
+
     init {
         when (initialRequest) {
             is Invalid -> {
@@ -116,6 +122,9 @@ constructor(
                         }
                     }
                 }
+                if (interactiveSession()) {
+                    viewModelScope.launch(bgDispatcher) { interactiveSessionInteractor.activate() }
+                }
             }
         }
     }
diff --git a/java/src/com/android/intentresolver/widget/ChooserTargetItemView.kt b/java/src/com/android/intentresolver/widget/ChooserTargetItemView.kt
index b5a4d617..816a2b1d 100644
--- a/java/src/com/android/intentresolver/widget/ChooserTargetItemView.kt
+++ b/java/src/com/android/intentresolver/widget/ChooserTargetItemView.kt
@@ -22,7 +22,10 @@ import android.graphics.Color
 import android.graphics.Paint
 import android.util.AttributeSet
 import android.util.TypedValue
+import android.view.InputDevice.SOURCE_MOUSE
 import android.view.MotionEvent
+import android.view.MotionEvent.ACTION_HOVER_ENTER
+import android.view.MotionEvent.ACTION_HOVER_MOVE
 import android.view.View
 import android.widget.ImageView
 import android.widget.LinearLayout
@@ -93,7 +96,7 @@ class ChooserTargetItemView(
         val iconView = iconView ?: return false
         if (!isEnabled) return true
         when (event.action) {
-            MotionEvent.ACTION_HOVER_ENTER -> {
+            ACTION_HOVER_ENTER -> {
                 iconView.isHovered = true
             }
             MotionEvent.ACTION_HOVER_EXIT -> {
@@ -103,7 +106,17 @@ class ChooserTargetItemView(
         return true
     }
 
-    override fun onInterceptHoverEvent(event: MotionEvent?) = true
+    override fun onInterceptHoverEvent(event: MotionEvent) =
+        if (event.isFromSource(SOURCE_MOUSE)) {
+            // This is the same logic as in super.onInterceptHoverEvent (ViewGroup) minus the check
+            // that the pointer fall on the scroll bar as we need to control the hover state of the
+            // icon.
+            // We also want to intercept only MOUSE hover events as the TalkBack's Explore by Touch
+            // (including single taps) reported as a hover event.
+            event.action == ACTION_HOVER_MOVE || event.action == ACTION_HOVER_ENTER
+        } else {
+            super.onInterceptHoverEvent(event)
+        }
 
     override fun dispatchDraw(canvas: Canvas) {
         super.dispatchDraw(canvas)
diff --git a/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java b/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java
index 07693b25..4895a2cd 100644
--- a/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java
+++ b/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java
@@ -278,6 +278,10 @@ public class ResolverDrawerLayout extends ViewGroup {
         mDismissLocked = locked;
     }
 
+    int getTopOffset() {
+        return mTopOffset;
+    }
+
     private boolean isMoving() {
         return mIsDragging || !mScroller.isFinished();
     }
diff --git a/java/src/com/android/intentresolver/widget/ResolverDrawerLayoutExt.kt b/java/src/com/android/intentresolver/widget/ResolverDrawerLayoutExt.kt
new file mode 100644
index 00000000..0c537a12
--- /dev/null
+++ b/java/src/com/android/intentresolver/widget/ResolverDrawerLayoutExt.kt
@@ -0,0 +1,51 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+@file:JvmName("ResolverDrawerLayoutExt")
+
+package com.android.intentresolver.widget
+
+import android.graphics.Rect
+import android.view.View
+import android.view.ViewGroup.MarginLayoutParams
+
+fun ResolverDrawerLayout.getVisibleDrawerRect(outRect: Rect) {
+    if (!isLaidOut) {
+        outRect.set(0, 0, 0, 0)
+        return
+    }
+    val firstChild = firstNonGoneChild()
+    val lp = firstChild?.layoutParams as? MarginLayoutParams
+    val margin = lp?.topMargin ?: 0
+    val top = maxOf(paddingTop, topOffset + margin)
+    val leftEdge = paddingLeft
+    val rightEdge = width - paddingRight
+    val widthAvailable = rightEdge - leftEdge
+    val childWidth = firstChild?.width ?: 0
+    val left = leftEdge + (widthAvailable - childWidth) / 2
+    val right = left + childWidth
+    outRect.set(left, top, right, height - paddingBottom)
+}
+
+fun ResolverDrawerLayout.firstNonGoneChild(): View? {
+    for (i in 0 until childCount) {
+        val view = getChildAt(i)
+        if (view.visibility != View.GONE) {
+            return view
+        }
+    }
+    return null
+}
diff --git a/proguard.flags b/proguard.flags
index 5541c3ff..c0b7f21e 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -1,2 +1,5 @@
 # Class referenced from xml drawable
--keep class com.android.intentresolver.SimpleIconFactory$FixedScaleDrawable
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.intentresolver.SimpleIconFactory$FixedScaleDrawable {
+    void <init>();
+}
diff --git a/tests/activity/Android.bp b/tests/activity/Android.bp
index 2e66a84d..ef54d825 100644
--- a/tests/activity/Android.bp
+++ b/tests/activity/Android.bp
@@ -43,6 +43,8 @@ android_test {
         "androidx.test.ext.truth",
         "androidx.test.espresso.contrib",
         "androidx.test.espresso.core",
+        "androidx.compose.ui_ui-test-junit4",
+        "androidx.compose.ui_ui-test-manifest",
         "androidx.test.rules",
         "androidx.test.runner",
         "androidx.lifecycle_lifecycle-common-java8",
diff --git a/tests/activity/AndroidManifest.xml b/tests/activity/AndroidManifest.xml
index 00dbd78d..90cb3d92 100644
--- a/tests/activity/AndroidManifest.xml
+++ b/tests/activity/AndroidManifest.xml
@@ -22,12 +22,12 @@
     <uses-permission android:name="android.permission.WRITE_DEVICE_CONFIG"/>
     <uses-permission android:name="android.permission.READ_DEVICE_CONFIG" />
 
-    <application android:name="dagger.hilt.android.testing.HiltTestApplication">
+    <application android:name="dagger.hilt.android.testing.HiltTestApplication"
+            android:label="IntentResolver Tests">
         <uses-library android:name="android.test.runner" />
         <activity android:name="com.android.intentresolver.ChooserWrapperActivity" />
         <activity android:name="com.android.intentresolver.ResolverWrapperActivity" />
-        <activity android:name="com.android.intentresolver.ChooserWrapperActivity" />
-        <activity android:name="com.android.intentresolver.ResolverWrapperActivity" />
+
         <provider
             android:authorities="com.android.intentresolver.tests"
             android:name="com.android.intentresolver.TestContentProvider"
diff --git a/tests/activity/src/com/android/intentresolver/ChooserActivityOverrideData.java b/tests/activity/src/com/android/intentresolver/ChooserActivityOverrideData.java
index 311201cf..c583b056 100644
--- a/tests/activity/src/com/android/intentresolver/ChooserActivityOverrideData.java
+++ b/tests/activity/src/com/android/intentresolver/ChooserActivityOverrideData.java
@@ -49,7 +49,6 @@ public class ChooserActivityOverrideData {
         return sInstance;
     }
     public Function<TargetInfo, Boolean> onSafelyStartInternalCallback;
-    public Function<TargetInfo, Boolean> onSafelyStartCallback;
     public Function2<UserHandle, Consumer<ShortcutLoader.Result>, ShortcutLoader>
             shortcutLoaderFactory = (userHandle, callback) -> null;
     public ChooserListController resolverListController;
@@ -60,7 +59,7 @@ public class ChooserActivityOverrideData {
     public Resources resources;
     public boolean hasCrossProfileIntents;
     public boolean isQuietModeEnabled;
-    public Integer myUserId;
+    public UserHandle personalUserHandle;
     public CrossProfileIntentsChecker mCrossProfileIntentsChecker;
 
     public void reset() {
@@ -73,7 +72,7 @@ public class ChooserActivityOverrideData {
         resources = null;
         hasCrossProfileIntents = true;
         isQuietModeEnabled = false;
-        myUserId = null;
+        personalUserHandle = null;
         shortcutLoaderFactory = ((userHandle, resultConsumer) -> null);
         mCrossProfileIntentsChecker = mock(CrossProfileIntentsChecker.class);
         when(mCrossProfileIntentsChecker.hasCrossProfileIntents(any(), anyInt(), anyInt()))
diff --git a/tests/activity/src/com/android/intentresolver/ChooserActivityShareouselTest.kt b/tests/activity/src/com/android/intentresolver/ChooserActivityShareouselTest.kt
new file mode 100644
index 00000000..cf1d8c60
--- /dev/null
+++ b/tests/activity/src/com/android/intentresolver/ChooserActivityShareouselTest.kt
@@ -0,0 +1,412 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+package com.android.intentresolver
+
+import android.content.ClipData
+import android.content.ClipDescription
+import android.content.ComponentName
+import android.content.Context
+import android.content.Intent
+import android.content.pm.PackageManager
+import android.content.pm.ResolveInfo
+import android.graphics.Color
+import android.net.Uri
+import android.os.UserHandle
+import android.platform.test.flag.junit.CheckFlagsRule
+import android.platform.test.flag.junit.DeviceFlagsValueProvider
+import android.provider.DeviceConfig
+import androidx.compose.ui.test.AndroidComposeUiTest
+import androidx.compose.ui.test.AndroidComposeUiTestEnvironment
+import androidx.compose.ui.test.ExperimentalTestApi
+import androidx.compose.ui.test.hasScrollToIndexAction
+import androidx.compose.ui.test.onNodeWithTag
+import androidx.compose.ui.test.performClick
+import androidx.compose.ui.test.performScrollToIndex
+import androidx.test.core.app.ActivityScenario
+import androidx.test.espresso.Espresso.onView
+import androidx.test.espresso.action.ViewActions.click
+import androidx.test.espresso.matcher.ViewMatchers
+import androidx.test.espresso.matcher.ViewMatchers.withId
+import androidx.test.espresso.matcher.ViewMatchers.withText
+import androidx.test.platform.app.InstrumentationRegistry
+import com.android.intentresolver.TestContentProvider.Companion.makeItemUri
+import com.android.intentresolver.chooser.TargetInfo
+import com.android.intentresolver.contentpreview.ImageLoader
+import com.android.intentresolver.contentpreview.ImageLoaderModule
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor.CursorResolver
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor.FakePayloadToggleCursorResolver
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor.FakePayloadToggleCursorResolver.Companion.DEFAULT_MIME_TYPE
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor.PayloadToggle
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor.PayloadToggleCursorResolver
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.CursorRow
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.update.FakeSelectionChangeCallback
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.update.SelectionChangeCallback
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.update.SelectionChangeCallbackModule
+import com.android.intentresolver.data.repository.FakeUserRepository
+import com.android.intentresolver.data.repository.UserRepository
+import com.android.intentresolver.data.repository.UserRepositoryModule
+import com.android.intentresolver.inject.ApplicationUser
+import com.android.intentresolver.inject.PackageManagerModule
+import com.android.intentresolver.inject.ProfileParent
+import com.android.intentresolver.platform.AppPredictionAvailable
+import com.android.intentresolver.platform.AppPredictionModule
+import com.android.intentresolver.platform.ImageEditor
+import com.android.intentresolver.platform.ImageEditorModule
+import com.android.intentresolver.shared.model.User
+import com.android.intentresolver.tests.R
+import com.android.internal.config.sysui.SystemUiDeviceConfigFlags
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.BindValue
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import dagger.hilt.android.testing.UninstallModules
+import java.util.Optional
+import java.util.concurrent.atomic.AtomicReference
+import java.util.function.Function
+import javax.inject.Inject
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import org.hamcrest.Matchers.allOf
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.mockito.ArgumentMatchers.anyBoolean
+import org.mockito.kotlin.any
+import org.mockito.kotlin.doAnswer
+import org.mockito.kotlin.stub
+
+private const val TEST_TARGET_CATEGORY = "com.android.intentresolver.tests.TEST_RECEIVER_CATEGORY"
+private const val PACKAGE = "com.android.intentresolver.tests"
+private const val IMAGE_ACTIVITY = "com.android.intentresolver.tests.ImageReceiverActivity"
+private const val VIDEO_ACTIVITY = "com.android.intentresolver.tests.VideoReceiverActivity"
+private const val ALL_MEDIA_ACTIVITY = "com.android.intentresolver.tests.AllMediaReceiverActivity"
+private const val IMAGE_ACTIVITY_LABEL = "ImageActivity"
+private const val VIDEO_ACTIVITY_LABEL = "VideoActivity"
+private const val ALL_MEDIA_ACTIVITY_LABEL = "AllMediaActivity"
+
+/**
+ * Instrumentation tests for ChooserActivity.
+ *
+ * Legacy test suite migrated from framework CoreTests.
+ */
+@OptIn(ExperimentalCoroutinesApi::class, ExperimentalTestApi::class)
+@HiltAndroidTest
+@UninstallModules(
+    AppPredictionModule::class,
+    ImageEditorModule::class,
+    PackageManagerModule::class,
+    ImageLoaderModule::class,
+    UserRepositoryModule::class,
+    PayloadToggleCursorResolver.Binding::class,
+    SelectionChangeCallbackModule::class,
+)
+class ChooserActivityShareouselTest() {
+    @get:Rule(order = 0)
+    val checkFlagsRule: CheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule()
+
+    @get:Rule(order = 1) val hiltAndroidRule: HiltAndroidRule = HiltAndroidRule(this)
+
+    @Inject @ApplicationContext lateinit var context: Context
+
+    @BindValue lateinit var packageManager: PackageManager
+
+    private val fakeUserRepo = FakeUserRepository(listOf(PERSONAL_USER))
+
+    @BindValue val userRepository: UserRepository = fakeUserRepo
+    @AppPredictionAvailable @BindValue val appPredictionAvailable = false
+
+    private val fakeImageLoader = FakeImageLoader()
+
+    @BindValue val imageLoader: ImageLoader = fakeImageLoader
+    @BindValue
+    @ImageEditor
+    val imageEditor: Optional<ComponentName> =
+        Optional.ofNullable(
+            ComponentName.unflattenFromString(
+                "com.google.android.apps.messaging/.ui.conversationlist.ShareIntentActivity"
+            )
+        )
+
+    @BindValue @ApplicationUser val applicationUser = PERSONAL_USER_HANDLE
+
+    @BindValue @ProfileParent val profileParent = PERSONAL_USER_HANDLE
+
+    private val fakeCursorResolver = FakePayloadToggleCursorResolver()
+    @BindValue
+    @PayloadToggle
+    val additionalContentCursorResolver: CursorResolver<CursorRow?> = fakeCursorResolver
+
+    @BindValue val selectionChangeCallback: SelectionChangeCallback = FakeSelectionChangeCallback()
+
+    @Before
+    fun setUp() {
+        // TODO: use the other form of `adoptShellPermissionIdentity()` where we explicitly list the
+        // permissions we require (which we'll read from the manifest at runtime).
+        InstrumentationRegistry.getInstrumentation().uiAutomation.adoptShellPermissionIdentity()
+
+        cleanOverrideData()
+
+        // Assign @Inject fields
+        hiltAndroidRule.inject()
+
+        // Populate @BindValue dependencies using injected values. These fields contribute
+        // values to the dependency graph at activity launch time. This allows replacing
+        // arbitrary bindings per-test case if needed.
+        packageManager = context.packageManager
+        with(ChooserActivityOverrideData.getInstance()) {
+            personalUserHandle = PERSONAL_USER_HANDLE
+            mockListController(resolverListController)
+        }
+    }
+
+    private fun setDeviceConfigProperty(propertyName: String, value: String) {
+        // TODO: consider running with {@link #runWithShellPermissionIdentity()} to more narrowly
+        // request WRITE_DEVICE_CONFIG permissions if we get rid of the broad grant we currently
+        // configure in {@link #setup()}.
+        // TODO: is it really appropriate that this is always set with makeDefault=true?
+        val valueWasSet =
+            DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_SYSTEMUI,
+                propertyName,
+                value,
+                true, /* makeDefault */
+            )
+        check(valueWasSet) { "Could not set $propertyName to $value" }
+    }
+
+    private fun cleanOverrideData() {
+        ChooserActivityOverrideData.getInstance().reset()
+
+        setDeviceConfigProperty(
+            SystemUiDeviceConfigFlags.APPLY_SHARING_APP_LIMITS_IN_SYSUI,
+            true.toString(),
+        )
+    }
+
+    @Test
+    fun test_shareInitiallySelectedItem_initiallySelectedItemShared() {
+        val launchedTargetInfo = AtomicReference<TargetInfo?>()
+        with(ChooserActivityOverrideData.getInstance()) {
+            onSafelyStartInternalCallback =
+                Function<TargetInfo, Boolean> { targetInfo ->
+                    launchedTargetInfo.set(targetInfo)
+                    true
+                }
+        }
+        val mimeTypes = emptyMap<Int, String>()
+        setBitmaps(mimeTypes)
+        fakeCursorResolver.setUris(count = 3, startPosition = 1, mimeTypes)
+        launchActivityWithComposeTestEnv(makeItemUri("1", DEFAULT_MIME_TYPE), DEFAULT_MIME_TYPE) {
+            selectTarget(IMAGE_ACTIVITY_LABEL)
+        }
+
+        val launchedTarget = launchedTargetInfo.get()
+        assertThat(launchedTarget).isNotNull()
+        val launchedIntent = launchedTarget!!.resolvedIntent
+        assertThat(launchedIntent.action).isEqualTo(Intent.ACTION_SEND)
+        assertThat(launchedIntent.type).isEqualTo(DEFAULT_MIME_TYPE)
+        assertThat(launchedIntent.component).isEqualTo(ComponentName(PACKAGE, IMAGE_ACTIVITY))
+    }
+
+    @Test
+    fun test_changeSelectedItem_newlySelectedItemShared() {
+        val launchedTargetInfo = AtomicReference<TargetInfo?>()
+        with(ChooserActivityOverrideData.getInstance()) {
+            onSafelyStartInternalCallback =
+                Function<TargetInfo, Boolean> { targetInfo ->
+                    launchedTargetInfo.set(targetInfo)
+                    true
+                }
+        }
+        val videoMimeType = "video/mp4"
+        val mimeTypes = mapOf(1 to videoMimeType)
+        setBitmaps(mimeTypes)
+        fakeCursorResolver.setUris(count = 3, startPosition = 0, mimeTypes)
+        launchActivityWithComposeTestEnv(makeItemUri("0", DEFAULT_MIME_TYPE), DEFAULT_MIME_TYPE) {
+            scrollToPosition(0)
+            tapOnItem(makeItemUri("0", DEFAULT_MIME_TYPE))
+            scrollToPosition(1)
+            tapOnItem(makeItemUri("1", videoMimeType))
+            selectTarget(VIDEO_ACTIVITY_LABEL)
+        }
+
+        val launchedTarget = launchedTargetInfo.get()
+        assertThat(launchedTarget).isNotNull()
+        val launchedIntent = launchedTarget!!.resolvedIntent
+        assertThat(launchedIntent.action).isEqualTo(Intent.ACTION_SEND)
+        assertThat(launchedIntent.type).isEqualTo(videoMimeType)
+        assertThat(launchedIntent.component).isEqualTo(ComponentName(PACKAGE, VIDEO_ACTIVITY))
+    }
+
+    @Test
+    fun test_selectAllItems_allItemsShared() {
+        val launchedTargetInfo = AtomicReference<TargetInfo?>()
+        with(ChooserActivityOverrideData.getInstance()) {
+            onSafelyStartInternalCallback =
+                Function<TargetInfo, Boolean> { targetInfo ->
+                    launchedTargetInfo.set(targetInfo)
+                    true
+                }
+        }
+        val videoMimeType = "video/mp4"
+        val mimeTypes = mapOf(1 to videoMimeType)
+        setBitmaps(mimeTypes)
+        fakeCursorResolver.setUris(3, 0, mimeTypes)
+        launchActivityWithComposeTestEnv(makeItemUri("0", DEFAULT_MIME_TYPE), DEFAULT_MIME_TYPE) {
+            scrollToPosition(1)
+            tapOnItem(makeItemUri("1", videoMimeType))
+            scrollToPosition(2)
+            tapOnItem(makeItemUri("2", DEFAULT_MIME_TYPE))
+            selectTarget(ALL_MEDIA_ACTIVITY_LABEL)
+        }
+
+        val launchedTarget = launchedTargetInfo.get()
+        assertThat(launchedTarget).isNotNull()
+        val launchedIntent = launchedTarget!!.resolvedIntent
+        assertThat(launchedIntent.action).isEqualTo(Intent.ACTION_SEND_MULTIPLE)
+        assertThat(launchedIntent.type).isEqualTo("*/*")
+        assertThat(launchedIntent.component).isEqualTo(ComponentName(PACKAGE, ALL_MEDIA_ACTIVITY))
+    }
+
+    private fun setBitmaps(mimeTypes: Map<Int, String>) {
+        arrayOf(Color.RED, Color.GREEN, Color.BLUE).forEachIndexed { i, color ->
+            fakeImageLoader.setBitmap(
+                makeItemUri(i.toString(), mimeTypes.getOrDefault(i, DEFAULT_MIME_TYPE)),
+                createBitmap(100, 100, color),
+            )
+        }
+    }
+
+    private fun launchActivityWithComposeTestEnv(
+        initialItem: Uri,
+        mimeType: String,
+        block: AndroidComposeUiTest<ChooserWrapperActivity>.() -> Unit,
+    ) {
+        val sendIntent =
+            Intent().apply {
+                action = Intent.ACTION_SEND
+                putExtra(Intent.EXTRA_STREAM, initialItem)
+                addCategory(TEST_TARGET_CATEGORY)
+                type = mimeType
+                clipData = ClipData("test", arrayOf(mimeType), ClipData.Item(initialItem))
+                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
+            }
+
+        val chooserIntent =
+            Intent.createChooser(sendIntent, null).apply {
+                component =
+                    ComponentName(
+                        "com.android.intentresolver.tests",
+                        "com.android.intentresolver.ChooserWrapperActivity",
+                    )
+                putExtra(
+                    Intent.EXTRA_CHOOSER_ADDITIONAL_CONTENT_URI,
+                    Uri.parse("content://com.android.intentresolver.test.additional"),
+                )
+                putExtra(Intent.EXTRA_AUTO_LAUNCH_SINGLE_CHOICE, false)
+                putExtra(Intent.EXTRA_CHOOSER_FOCUSED_ITEM_POSITION, 0)
+                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
+            }
+        val activityRef = AtomicReference<ChooserWrapperActivity?>()
+        val composeTestEnv = AndroidComposeUiTestEnvironment {
+            requireNotNull(activityRef.get()) { "Activity was not launched" }
+        }
+        var scenario: ActivityScenario<ChooserWrapperActivity?>? = null
+        try {
+            composeTestEnv.runTest {
+                this@runTest.mainClock.autoAdvance = true
+                scenario = ActivityScenario.launch<ChooserWrapperActivity>(chooserIntent)
+                scenario.onActivity { activityRef.set(it) }
+                waitForIdle()
+                block()
+            }
+        } finally {
+            scenario?.close()
+        }
+    }
+
+    private fun AndroidComposeUiTest<ChooserWrapperActivity>.tapOnItem(uri: Uri) {
+        onNodeWithTag(uri.toString()).performClick()
+        waitForIdle()
+    }
+
+    private fun AndroidComposeUiTest<ChooserWrapperActivity>.scrollToPosition(position: Int) {
+        onNode(hasScrollToIndexAction()).performScrollToIndex(position)
+        waitForIdle()
+    }
+
+    private fun AndroidComposeUiTest<ChooserWrapperActivity>.selectTarget(name: String) {
+        onView(
+                allOf(
+                    withId(R.id.item),
+                    ViewMatchers.hasDescendant(withText(name)),
+                    ViewMatchers.isEnabled(),
+                )
+            )
+            .perform(click())
+        waitForIdle()
+    }
+
+    private fun mockListController(resolverListController: ResolverListController) {
+        resolverListController.stub {
+            on {
+                getResolversForIntentAsUser(anyBoolean(), anyBoolean(), anyBoolean(), any(), any())
+            } doAnswer
+                { invocation ->
+                    fakeTargetResolutionLogic(invocation.getArgument<List<Intent>>(3))
+                }
+        }
+    }
+
+    private fun fakeTargetResolutionLogic(intentList: List<Intent>): List<ResolvedComponentInfo> {
+        require(intentList.size == 1) { "Expected a single intent" }
+        val intent = intentList[0]
+        require(
+            intent.action == Intent.ACTION_SEND || intent.action == Intent.ACTION_SEND_MULTIPLE
+        ) {
+            "Expected send intent"
+        }
+        val mimeType = requireNotNull(intent.type) { "Expected intent with type" }
+        val (activity, label) =
+            when {
+                ClipDescription.compareMimeTypes(mimeType, "image/*") ->
+                    IMAGE_ACTIVITY to IMAGE_ACTIVITY_LABEL
+                ClipDescription.compareMimeTypes(mimeType, "video/*") ->
+                    VIDEO_ACTIVITY to VIDEO_ACTIVITY_LABEL
+                else -> ALL_MEDIA_ACTIVITY to ALL_MEDIA_ACTIVITY_LABEL
+            }
+        val componentName = ComponentName(PACKAGE, activity)
+        return listOf(
+            ResolvedComponentInfo(
+                componentName,
+                intent,
+                ResolveInfo().apply {
+                    activityInfo = ResolverDataProvider.createActivityInfo(componentName)
+                    targetUserId = UserHandle.USER_CURRENT
+                    userHandle = PERSONAL_USER_HANDLE
+                    nonLocalizedLabel = label
+                },
+            )
+        )
+    }
+
+    companion object {
+        private val PERSONAL_USER_HANDLE: UserHandle =
+            InstrumentationRegistry.getInstrumentation().targetContext.getUser()
+
+        private val PERSONAL_USER = User(PERSONAL_USER_HANDLE.identifier, User.Role.PERSONAL)
+    }
+}
diff --git a/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java b/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java
index e103e57b..6f80c8f6 100644
--- a/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java
+++ b/tests/activity/src/com/android/intentresolver/ChooserActivityTest.java
@@ -38,6 +38,7 @@ import static com.android.intentresolver.ChooserActivity.TARGET_TYPE_SHORTCUTS_F
 import static com.android.intentresolver.ChooserListAdapter.CALLER_TARGET_SCORE_BOOST;
 import static com.android.intentresolver.ChooserListAdapter.SHORTCUT_TARGET_SCORE_BOOST;
 import static com.android.intentresolver.MatcherUtils.first;
+import static com.android.intentresolver.TestUtils.createSendImageIntent;
 
 import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
@@ -79,9 +80,7 @@ import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.database.Cursor;
 import android.graphics.Bitmap;
-import android.graphics.Canvas;
 import android.graphics.Color;
-import android.graphics.Paint;
 import android.graphics.Rect;
 import android.graphics.Typeface;
 import android.graphics.drawable.Icon;
@@ -202,12 +201,14 @@ public class ChooserActivityTest {
     private static final User PERSONAL_USER =
             new User(PERSONAL_USER_HANDLE.getIdentifier(), User.Role.PERSONAL);
 
-    private static final UserHandle WORK_PROFILE_USER_HANDLE = UserHandle.of(10);
+    private static final UserHandle WORK_PROFILE_USER_HANDLE =
+            UserHandle.of(PERSONAL_USER_HANDLE.getIdentifier() + 1);
 
     private static final User WORK_USER =
             new User(WORK_PROFILE_USER_HANDLE.getIdentifier(), User.Role.WORK);
 
-    private static final UserHandle CLONE_PROFILE_USER_HANDLE = UserHandle.of(11);
+    private static final UserHandle CLONE_PROFILE_USER_HANDLE =
+            UserHandle.of(PERSONAL_USER_HANDLE.getIdentifier() + 2);
 
     private static final User CLONE_USER =
             new User(CLONE_PROFILE_USER_HANDLE.getIdentifier(), User.Role.CLONE);
@@ -302,6 +303,7 @@ public class ChooserActivityTest {
                 .adoptShellPermissionIdentity();
 
         cleanOverrideData();
+        ChooserActivityOverrideData.getInstance().personalUserHandle = PERSONAL_USER_HANDLE;
 
         // Assign @Inject fields
         mHiltAndroidRule.inject();
@@ -1537,7 +1539,8 @@ public class ChooserActivityTest {
         // verify that ShortcutLoader was queried
         ArgumentCaptor<DisplayResolveInfo[]> appTargets =
                 ArgumentCaptor.forClass(DisplayResolveInfo[].class);
-        verify(shortcutLoaders.get(0).first, times(1)).updateAppTargets(appTargets.capture());
+        verify(shortcutLoaders.get(PERSONAL_USER_HANDLE.getIdentifier()).first,
+                times(1)).updateAppTargets(appTargets.capture());
 
         // send shortcuts
         assertThat(
@@ -1557,7 +1560,8 @@ public class ChooserActivityTest {
                 new HashMap<>(),
                 new HashMap<>()
         );
-        activity.getMainExecutor().execute(() -> shortcutLoaders.get(0).second.accept(result));
+        activity.getMainExecutor().execute(() -> shortcutLoaders.get(
+                PERSONAL_USER_HANDLE.getIdentifier()).second.accept(result));
         waitForIdle();
 
         final ChooserListAdapter activeAdapter = activity.getAdapter();
@@ -1611,7 +1615,8 @@ public class ChooserActivityTest {
         // verify that ShortcutLoader was queried
         ArgumentCaptor<DisplayResolveInfo[]> appTargets =
                 ArgumentCaptor.forClass(DisplayResolveInfo[].class);
-        verify(shortcutLoaders.get(0).first, times(1)).updateAppTargets(appTargets.capture());
+        verify(shortcutLoaders.get(PERSONAL_USER_HANDLE.getIdentifier()).first,
+                times(1)).updateAppTargets(appTargets.capture());
 
         // send shortcuts
         assertThat(
@@ -1633,7 +1638,8 @@ public class ChooserActivityTest {
                 new HashMap<>(),
                 new HashMap<>()
         );
-        activity.getMainExecutor().execute(() -> shortcutLoaders.get(0).second.accept(result));
+        activity.getMainExecutor().execute(() -> shortcutLoaders.get(
+                PERSONAL_USER_HANDLE.getIdentifier()).second.accept(result));
         waitForIdle();
 
         final ChooserListAdapter activeAdapter = activity.getAdapter();
@@ -1688,7 +1694,8 @@ public class ChooserActivityTest {
         // verify that ShortcutLoader was queried
         ArgumentCaptor<DisplayResolveInfo[]> appTargets =
                 ArgumentCaptor.forClass(DisplayResolveInfo[].class);
-        verify(shortcutLoaders.get(0).first, times(1)).updateAppTargets(appTargets.capture());
+        verify(shortcutLoaders.get(PERSONAL_USER_HANDLE.getIdentifier()).first,
+                times(1)).updateAppTargets(appTargets.capture());
 
         // send shortcuts
         assertThat(
@@ -1710,7 +1717,8 @@ public class ChooserActivityTest {
                 new HashMap<>(),
                 new HashMap<>()
         );
-        activity.getMainExecutor().execute(() -> shortcutLoaders.get(0).second.accept(result));
+        activity.getMainExecutor().execute(() -> shortcutLoaders.get(
+                PERSONAL_USER_HANDLE.getIdentifier()).second.accept(result));
         waitForIdle();
 
         final ChooserListAdapter activeAdapter = activity.getAdapter();
@@ -1759,7 +1767,8 @@ public class ChooserActivityTest {
         // verify that ShortcutLoader was queried
         ArgumentCaptor<DisplayResolveInfo[]> appTargets =
                 ArgumentCaptor.forClass(DisplayResolveInfo[].class);
-        verify(shortcutLoaders.get(0).first, times(1)).updateAppTargets(appTargets.capture());
+        verify(shortcutLoaders.get(PERSONAL_USER_HANDLE.getIdentifier()).first,
+                times(1)).updateAppTargets(appTargets.capture());
 
         // send shortcuts
         assertThat(
@@ -1781,7 +1790,8 @@ public class ChooserActivityTest {
                 new HashMap<>(),
                 new HashMap<>()
         );
-        activity.getMainExecutor().execute(() -> shortcutLoaders.get(0).second.accept(result));
+        activity.getMainExecutor().execute(() -> shortcutLoaders.get(
+                PERSONAL_USER_HANDLE.getIdentifier()).second.accept(result));
         waitForIdle();
 
         final ChooserListAdapter activeAdapter = activity.getAdapter();
@@ -1848,7 +1858,8 @@ public class ChooserActivityTest {
         // verify that ShortcutLoader was queried
         ArgumentCaptor<DisplayResolveInfo[]> appTargets =
                 ArgumentCaptor.forClass(DisplayResolveInfo[].class);
-        verify(shortcutLoaders.get(0).first, times(1)).updateAppTargets(appTargets.capture());
+        verify(shortcutLoaders.get(PERSONAL_USER_HANDLE.getIdentifier()).first,
+                times(1)).updateAppTargets(appTargets.capture());
 
         // send shortcuts
         assertThat(
@@ -1861,7 +1872,8 @@ public class ChooserActivityTest {
                 new ShortcutLoader.ShortcutResultInfo[0],
                 new HashMap<>(),
                 new HashMap<>());
-        activity.getMainExecutor().execute(() -> shortcutLoaders.get(0).second.accept(result));
+        activity.getMainExecutor().execute(() -> shortcutLoaders.get(
+                PERSONAL_USER_HANDLE.getIdentifier()).second.accept(result));
         waitForIdle();
 
         final ChooserListAdapter activeAdapter = activity.getAdapter();
@@ -2120,9 +2132,10 @@ public class ChooserActivityTest {
                 mActivityRule.launchActivity(Intent.createChooser(sendIntent, "work tab test"));
         waitForIdle();
 
-        assertThat(activity.getCurrentUserHandle().getIdentifier(), is(0));
+        assertThat(activity.getCurrentUserHandle().getIdentifier(),
+                is(PERSONAL_USER_HANDLE.getIdentifier()));
         onView(withText(R.string.resolver_work_tab)).perform(click());
-        assertThat(activity.getCurrentUserHandle().getIdentifier(), is(10));
+        assertThat(activity.getCurrentUserHandle(), is(WORK_PROFILE_USER_HANDLE));
         assertThat(activity.getPersonalListAdapter().getCount(), is(personalProfileTargets));
         assertThat(activity.getWorkListAdapter().getCount(), is(workProfileTargets));
     }
@@ -2389,7 +2402,7 @@ public class ChooserActivityTest {
         // verify that ShortcutLoader was queried
         ArgumentCaptor<DisplayResolveInfo[]> appTargets =
                 ArgumentCaptor.forClass(DisplayResolveInfo[].class);
-        verify(shortcutLoaders.get(0).first, times(1))
+        verify(shortcutLoaders.get(PERSONAL_USER_HANDLE.getIdentifier()).first, times(1))
                 .updateAppTargets(appTargets.capture());
 
         // send shortcuts
@@ -2412,7 +2425,8 @@ public class ChooserActivityTest {
                 new HashMap<>(),
                 new HashMap<>()
         );
-        activity.getMainExecutor().execute(() -> shortcutLoaders.get(0).second.accept(result));
+        activity.getMainExecutor().execute(() -> shortcutLoaders.get(
+                PERSONAL_USER_HANDLE.getIdentifier()).second.accept(result));
         waitForIdle();
 
         assertThat("Chooser should have 3 targets (2 apps, 1 direct)",
@@ -2462,7 +2476,7 @@ public class ChooserActivityTest {
         // verify that ShortcutLoader was queried
         ArgumentCaptor<DisplayResolveInfo[]> appTargets =
                 ArgumentCaptor.forClass(DisplayResolveInfo[].class);
-        verify(shortcutLoaders.get(0).first, times(1))
+        verify(shortcutLoaders.get(PERSONAL_USER_HANDLE.getIdentifier()).first, times(1))
                 .updateAppTargets(appTargets.capture());
 
         // send shortcuts
@@ -2482,7 +2496,8 @@ public class ChooserActivityTest {
                 new HashMap<>(),
                 new HashMap<>()
         );
-        activity.getMainExecutor().execute(() -> shortcutLoaders.get(0).second.accept(result));
+        activity.getMainExecutor().execute(() -> shortcutLoaders.get(
+                PERSONAL_USER_HANDLE.getIdentifier()).second.accept(result));
         waitForIdle();
 
         // Long-click on the direct target
@@ -2709,15 +2724,17 @@ public class ChooserActivityTest {
     public void test_query_shortcut_loader_for_the_selected_tab() {
         markOtherProfileAvailability(/* workAvailable= */ true, /* cloneAvailable= */ false);
         List<ResolvedComponentInfo> personalResolvedComponentInfos =
-                createResolvedComponentsForTestWithOtherProfile(3, /* userId */ 10);
+                createResolvedComponentsForTestWithOtherProfile(
+                        3,
+                        WORK_PROFILE_USER_HANDLE.getIdentifier());
         List<ResolvedComponentInfo> workResolvedComponentInfos =
                 createResolvedComponentsForTest(3);
         setupResolverControllers(personalResolvedComponentInfos, workResolvedComponentInfos);
         ShortcutLoader personalProfileShortcutLoader = mock(ShortcutLoader.class);
         ShortcutLoader workProfileShortcutLoader = mock(ShortcutLoader.class);
         final SparseArray<ShortcutLoader> shortcutLoaders = new SparseArray<>();
-        shortcutLoaders.put(0, personalProfileShortcutLoader);
-        shortcutLoaders.put(10, workProfileShortcutLoader);
+        shortcutLoaders.put(PERSONAL_USER_HANDLE.getIdentifier(), personalProfileShortcutLoader);
+        shortcutLoaders.put(WORK_PROFILE_USER_HANDLE.getIdentifier(), workProfileShortcutLoader);
         ChooserActivityOverrideData.getInstance().shortcutLoaderFactory =
                 (userHandle, callback) -> shortcutLoaders.get(userHandle.getIdentifier(), null);
         Intent sendIntent = createSendTextIntent();
@@ -2832,19 +2849,6 @@ public class ChooserActivityTest {
         return sendIntent;
     }
 
-    private Intent createSendImageIntent(Uri imageThumbnail) {
-        Intent sendIntent = new Intent();
-        sendIntent.setAction(Intent.ACTION_SEND);
-        sendIntent.putExtra(Intent.EXTRA_STREAM, imageThumbnail);
-        sendIntent.setType("image/png");
-        if (imageThumbnail != null) {
-            ClipData.Item clipItem = new ClipData.Item(imageThumbnail);
-            sendIntent.setClipData(new ClipData("Clip Label", new String[]{"image/png"}, clipItem));
-        }
-
-        return sendIntent;
-    }
-
     private Uri createTestContentProviderUri(
             @Nullable String mimeType, @Nullable String streamType) {
         return createTestContentProviderUri(mimeType, streamType, 0);
@@ -2852,22 +2856,11 @@ public class ChooserActivityTest {
 
     private Uri createTestContentProviderUri(
             @Nullable String mimeType, @Nullable String streamType, long streamTypeTimeout) {
-        String packageName =
-                InstrumentationRegistry.getInstrumentation().getContext().getPackageName();
-        Uri.Builder builder = Uri.parse("content://" + packageName + "/image.png")
-                .buildUpon();
-        if (mimeType != null) {
-            builder.appendQueryParameter(TestContentProvider.PARAM_MIME_TYPE, mimeType);
-        }
-        if (streamType != null) {
-            builder.appendQueryParameter(TestContentProvider.PARAM_STREAM_TYPE, streamType);
-        }
-        if (streamTypeTimeout > 0) {
-            builder.appendQueryParameter(
-                    TestContentProvider.PARAM_STREAM_TYPE_TIMEOUT,
-                    Long.toString(streamTypeTimeout));
-        }
-        return builder.build();
+        return TestContentProvider.makeItemUri(
+                "image.png",
+                mimeType,
+                streamType == null ? new String[0] : new String[] { streamType },
+                streamTypeTimeout);
     }
 
     private Intent createSendTextIntentWithPreview(String title, Uri imageThumbnail) {
@@ -3012,29 +3005,11 @@ public class ChooserActivityTest {
             Rect bounds = windowManager.getMaximumWindowMetrics().getBounds();
             width = bounds.width() + 200;
         }
-        return createBitmap(width, 100, bgColor);
+        return TestUtils.createBitmap(width, 100, bgColor);
     }
 
     private Bitmap createBitmap(int width, int height) {
-        return createBitmap(width, height, Color.RED);
-    }
-
-    private Bitmap createBitmap(int width, int height, int bgColor) {
-        Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
-        Canvas canvas = new Canvas(bitmap);
-
-        Paint paint = new Paint();
-        paint.setColor(bgColor);
-        paint.setStyle(Paint.Style.FILL);
-        canvas.drawPaint(paint);
-
-        paint.setColor(Color.WHITE);
-        paint.setAntiAlias(true);
-        paint.setTextSize(14.f);
-        paint.setTextAlign(Paint.Align.CENTER);
-        canvas.drawText("Hi!", (width / 2.f), (height / 2.f), paint);
-
-        return bitmap;
+        return TestUtils.createBitmap(width, height, Color.RED);
     }
 
     private List<ShareShortcutInfo> createShortcuts(Context context) {
diff --git a/tests/activity/src/com/android/intentresolver/ChooserActivityWorkProfileTest.java b/tests/activity/src/com/android/intentresolver/ChooserActivityWorkProfileTest.java
index 022ae2e1..5400ac6d 100644
--- a/tests/activity/src/com/android/intentresolver/ChooserActivityWorkProfileTest.java
+++ b/tests/activity/src/com/android/intentresolver/ChooserActivityWorkProfileTest.java
@@ -83,7 +83,8 @@ public class ChooserActivityWorkProfileTest {
 
     private static final UserHandle PERSONAL_USER_HANDLE = InstrumentationRegistry
             .getInstrumentation().getTargetContext().getUser();
-    private static final UserHandle WORK_USER_HANDLE = UserHandle.of(10);
+    private static final UserHandle WORK_USER_HANDLE =
+            UserHandle.of(PERSONAL_USER_HANDLE.getIdentifier() + 1);
 
     @Rule(order = 0)
     public HiltAndroidRule mHiltAndroidRule = new HiltAndroidRule(this);
diff --git a/tests/activity/src/com/android/intentresolver/ChooserWrapperActivity.java b/tests/activity/src/com/android/intentresolver/ChooserWrapperActivity.java
index 6ff7af3f..c279dae8 100644
--- a/tests/activity/src/com/android/intentresolver/ChooserWrapperActivity.java
+++ b/tests/activity/src/com/android/intentresolver/ChooserWrapperActivity.java
@@ -134,7 +134,7 @@ public class ChooserWrapperActivity extends ChooserActivity implements IChooserW
 
     @Override
     public final ChooserListController createListController(UserHandle userHandle) {
-        if (userHandle == UserHandle.SYSTEM) {
+        if (userHandle == sOverrides.personalUserHandle) {
             return sOverrides.resolverListController;
         }
         return sOverrides.workResolverListController;
diff --git a/tests/activity/src/com/android/intentresolver/ResolverActivityTest.java b/tests/activity/src/com/android/intentresolver/ResolverActivityTest.java
index b44f4f91..003e64fe 100644
--- a/tests/activity/src/com/android/intentresolver/ResolverActivityTest.java
+++ b/tests/activity/src/com/android/intentresolver/ResolverActivityTest.java
@@ -91,8 +91,11 @@ public class ResolverActivityTest {
 
     private static final UserHandle PERSONAL_USER_HANDLE =
             getInstrumentation().getTargetContext().getUser();
-    private static final UserHandle WORK_PROFILE_USER_HANDLE = UserHandle.of(10);
-    private static final UserHandle CLONE_PROFILE_USER_HANDLE = UserHandle.of(11);
+    private static final int WORK_PROFILE_USER_ID = PERSONAL_USER_HANDLE.getIdentifier() + 1;
+    private static final UserHandle WORK_PROFILE_USER_HANDLE =
+            UserHandle.of(WORK_PROFILE_USER_ID);
+    private static final UserHandle CLONE_PROFILE_USER_HANDLE =
+            UserHandle.of(PERSONAL_USER_HANDLE.getIdentifier() + 2);
     private static final User WORK_PROFILE_USER =
             new User(WORK_PROFILE_USER_HANDLE.getIdentifier(), User.Role.WORK);
 
@@ -267,7 +270,7 @@ public class ResolverActivityTest {
     @Test
     public void hasOtherProfileOneOption() throws Exception {
         List<ResolvedComponentInfo> personalResolvedComponentInfos =
-                createResolvedComponentsForTestWithOtherProfile(2, /* userId */ 10,
+                createResolvedComponentsForTestWithOtherProfile(2, WORK_PROFILE_USER_ID,
                         PERSONAL_USER_HANDLE);
         markOtherProfileAvailability(/* workAvailable= */ true, /* cloneAvailable= */ false);
         List<ResolvedComponentInfo> workResolvedComponentInfos = createResolvedComponentsForTest(4,
@@ -290,7 +293,7 @@ public class ResolverActivityTest {
         };
         // Make a stable copy of the components as the original list may be modified
         List<ResolvedComponentInfo> stableCopy =
-                createResolvedComponentsForTestWithOtherProfile(2, /* userId= */ 10,
+                createResolvedComponentsForTestWithOtherProfile(2, WORK_PROFILE_USER_ID,
                         PERSONAL_USER_HANDLE);
         // We pick the first one as there is another one in the work profile side
         onView(first(withText(stableCopy.get(1).getResolveInfoAt(0).activityInfo.name)))
@@ -402,7 +405,7 @@ public class ResolverActivityTest {
     @Test
     public void testWorkTab_workTabListPopulatedBeforeGoingToTab() throws InterruptedException {
         List<ResolvedComponentInfo> personalResolvedComponentInfos =
-                createResolvedComponentsForTestWithOtherProfile(3, /* userId = */ 10,
+                createResolvedComponentsForTestWithOtherProfile(3, WORK_PROFILE_USER_ID,
                         PERSONAL_USER_HANDLE);
         markOtherProfileAvailability(/* workAvailable= */ true, /* cloneAvailable= */ false);
         List<ResolvedComponentInfo> workResolvedComponentInfos = createResolvedComponentsForTest(4,
@@ -414,7 +417,7 @@ public class ResolverActivityTest {
         final ResolverWrapperActivity activity = mActivityRule.launchActivity(sendIntent);
         waitForIdle();
 
-        assertThat(activity.getCurrentUserHandle().getIdentifier(), is(0));
+        assertThat(activity.getCurrentUserHandle(), is(PERSONAL_USER_HANDLE));
         // The work list adapter must be populated in advance before tapping the other tab
         assertThat(activity.getWorkListAdapter().getCount(), is(4));
     }
@@ -423,7 +426,7 @@ public class ResolverActivityTest {
     public void testWorkTab_workTabUsesExpectedAdapter() {
         markOtherProfileAvailability(/* workAvailable= */ true, /* cloneAvailable= */ false);
         List<ResolvedComponentInfo> personalResolvedComponentInfos =
-                createResolvedComponentsForTestWithOtherProfile(3, /* userId */ 10,
+                createResolvedComponentsForTestWithOtherProfile(3, WORK_PROFILE_USER_ID,
                         PERSONAL_USER_HANDLE);
         List<ResolvedComponentInfo> workResolvedComponentInfos = createResolvedComponentsForTest(4,
                 WORK_PROFILE_USER_HANDLE);
@@ -434,7 +437,7 @@ public class ResolverActivityTest {
         waitForIdle();
         onView(withText(R.string.resolver_work_tab)).perform(click());
 
-        assertThat(activity.getCurrentUserHandle().getIdentifier(), is(10));
+        assertThat(activity.getCurrentUserHandle().getIdentifier(), is(WORK_PROFILE_USER_ID));
         assertThat(activity.getWorkListAdapter().getCount(), is(4));
     }
 
@@ -452,7 +455,7 @@ public class ResolverActivityTest {
         waitForIdle();
         onView(withText(R.string.resolver_work_tab)).perform(click());
 
-        assertThat(activity.getCurrentUserHandle().getIdentifier(), is(10));
+        assertThat(activity.getCurrentUserHandle().getIdentifier(), is(WORK_PROFILE_USER_ID));
         assertThat(activity.getPersonalListAdapter().getCount(), is(2));
     }
 
@@ -460,7 +463,7 @@ public class ResolverActivityTest {
     public void testWorkTab_workProfileHasExpectedNumberOfTargets() throws InterruptedException {
         markOtherProfileAvailability(/* workAvailable= */ true, /* cloneAvailable= */ false);
         List<ResolvedComponentInfo> personalResolvedComponentInfos =
-                createResolvedComponentsForTestWithOtherProfile(3, /* userId */ 10,
+                createResolvedComponentsForTestWithOtherProfile(3, WORK_PROFILE_USER_ID,
                         PERSONAL_USER_HANDLE);
         List<ResolvedComponentInfo> workResolvedComponentInfos = createResolvedComponentsForTest(4,
                 WORK_PROFILE_USER_HANDLE);
@@ -576,7 +579,7 @@ public class ResolverActivityTest {
             throws InterruptedException {
         markOtherProfileAvailability(/* workAvailable= */ true, /* cloneAvailable= */ false);
         List<ResolvedComponentInfo> personalResolvedComponentInfos =
-                createResolvedComponentsForTestWithOtherProfile(3, /* userId= */ 10,
+                createResolvedComponentsForTestWithOtherProfile(3, WORK_PROFILE_USER_ID,
                         PERSONAL_USER_HANDLE);
         List<ResolvedComponentInfo> workResolvedComponentInfos = createResolvedComponentsForTest(4,
                 WORK_PROFILE_USER_HANDLE);
@@ -610,7 +613,7 @@ public class ResolverActivityTest {
         markOtherProfileAvailability(/* workAvailable= */ true, /* cloneAvailable= */ false);
         int workProfileTargets = 4;
         List<ResolvedComponentInfo> personalResolvedComponentInfos =
-                createResolvedComponentsForTestWithOtherProfile(3, /* userId */ 10,
+                createResolvedComponentsForTestWithOtherProfile(3, WORK_PROFILE_USER_ID,
                         PERSONAL_USER_HANDLE);
         List<ResolvedComponentInfo> workResolvedComponentInfos =
                 createResolvedComponentsForTest(workProfileTargets, WORK_PROFILE_USER_HANDLE);
@@ -635,7 +638,7 @@ public class ResolverActivityTest {
         markOtherProfileAvailability(/* workAvailable= */ true, /* cloneAvailable= */ false);
         int workProfileTargets = 4;
         List<ResolvedComponentInfo> personalResolvedComponentInfos =
-                createResolvedComponentsForTestWithOtherProfile(3, /* userId */ 10,
+                createResolvedComponentsForTestWithOtherProfile(3, WORK_PROFILE_USER_ID,
                         PERSONAL_USER_HANDLE);
         List<ResolvedComponentInfo> workResolvedComponentInfos =
                 createResolvedComponentsForTest(workProfileTargets, WORK_PROFILE_USER_HANDLE);
@@ -775,7 +778,7 @@ public class ResolverActivityTest {
         markOtherProfileAvailability(/* workAvailable= */ true, /* cloneAvailable= */ false);
         int workProfileTargets = 4;
         List<ResolvedComponentInfo> personalResolvedComponentInfos =
-                createResolvedComponentsForTestWithOtherProfile(2, /* userId */ 10,
+                createResolvedComponentsForTestWithOtherProfile(2, WORK_PROFILE_USER_ID,
                         PERSONAL_USER_HANDLE);
         List<ResolvedComponentInfo> workResolvedComponentInfos =
                 createResolvedComponentsForTest(workProfileTargets, WORK_PROFILE_USER_HANDLE);
diff --git a/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java b/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java
index 0d317dc3..169c44b0 100644
--- a/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java
+++ b/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java
@@ -119,7 +119,7 @@ public class ResolverWrapperActivity extends ResolverActivity {
 
     @Override
     protected ResolverListController createListController(UserHandle userHandle) {
-        if (userHandle == UserHandle.SYSTEM) {
+        if (userHandle == getUser()) {
             return sOverrides.resolverListController;
         }
         return sOverrides.workResolverListController;
diff --git a/tests/activity/src/com/android/intentresolver/TestContentProvider.kt b/tests/activity/src/com/android/intentresolver/TestContentProvider.kt
index 426f9af2..dcd5888c 100644
--- a/tests/activity/src/com/android/intentresolver/TestContentProvider.kt
+++ b/tests/activity/src/com/android/intentresolver/TestContentProvider.kt
@@ -27,7 +27,7 @@ class TestContentProvider : ContentProvider() {
         projection: Array<out String>?,
         selection: String?,
         selectionArgs: Array<out String>?,
-        sortOrder: String?
+        sortOrder: String?,
     ): Cursor? = null
 
     override fun getType(uri: Uri): String? =
@@ -44,7 +44,7 @@ class TestContentProvider : ContentProvider() {
                 Thread.currentThread().interrupt()
             }
         }
-        return runCatching { uri.getQueryParameter(PARAM_STREAM_TYPE)?.let { arrayOf(it) } }
+        return runCatching { uri.getQueryParameter(PARAM_STREAM_TYPE)?.split(",")?.toTypedArray() }
             .getOrNull()
     }
 
@@ -56,7 +56,7 @@ class TestContentProvider : ContentProvider() {
         uri: Uri,
         values: ContentValues?,
         selection: String?,
-        selectionArgs: Array<out String>?
+        selectionArgs: Array<out String>?,
     ): Int = 0
 
     override fun onCreate(): Boolean = true
@@ -65,5 +65,27 @@ class TestContentProvider : ContentProvider() {
         const val PARAM_MIME_TYPE = "mimeType"
         const val PARAM_STREAM_TYPE = "streamType"
         const val PARAM_STREAM_TYPE_TIMEOUT = "streamTypeTo"
+
+        @JvmStatic
+        @JvmOverloads
+        fun makeItemUri(
+            name: String,
+            mimeType: String?,
+            streamTypes: Array<String> = emptyArray(),
+            timeout: Long = 0L,
+        ): Uri =
+            Uri.parse("content://com.android.intentresolver.tests/$name")
+                .buildUpon()
+                .appendQueryParameter(PARAM_MIME_TYPE, mimeType)
+                .apply {
+                    mimeType?.let { appendQueryParameter(PARAM_MIME_TYPE, it) }
+                    if (streamTypes.isNotEmpty()) {
+                        appendQueryParameter(PARAM_STREAM_TYPE, streamTypes.joinToString(","))
+                    }
+                    if (timeout > 0) {
+                        appendQueryParameter(PARAM_STREAM_TYPE_TIMEOUT, timeout.toString())
+                    }
+                }
+                .build()
     }
 }
diff --git a/tests/activity/src/com/android/intentresolver/TestUtils.kt b/tests/activity/src/com/android/intentresolver/TestUtils.kt
new file mode 100644
index 00000000..18dee644
--- /dev/null
+++ b/tests/activity/src/com/android/intentresolver/TestUtils.kt
@@ -0,0 +1,61 @@
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
+@file:JvmName("TestUtils")
+
+package com.android.intentresolver
+
+import android.content.ClipData
+import android.content.Intent
+import android.graphics.Bitmap
+import android.graphics.Canvas
+import android.graphics.Color
+import android.graphics.Paint
+import android.net.Uri
+
+@JvmOverloads
+fun createSendImageIntent(imageThumbnail: Uri?, mimeType: String = "image/png") =
+    Intent().apply {
+        setAction(Intent.ACTION_SEND)
+        putExtra(Intent.EXTRA_STREAM, imageThumbnail)
+        setType(mimeType)
+        if (imageThumbnail != null) {
+            val clipItem = ClipData.Item(imageThumbnail)
+            clipData = ClipData("Clip Label", arrayOf<String>(mimeType), clipItem)
+        }
+    }
+
+fun createBitmap(width: Int, height: Int, bgColor: Int): Bitmap {
+    val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
+    val canvas = Canvas(bitmap)
+
+    val paint =
+        Paint().apply {
+            setColor(bgColor)
+            style = Paint.Style.FILL
+        }
+    canvas.drawPaint(paint)
+
+    with(paint) {
+        setColor(Color.WHITE)
+        isAntiAlias = true
+        textSize = 14f
+        textAlign = Paint.Align.CENTER
+    }
+    canvas.drawText("Hi!", (width / 2f), (height / 2f), paint)
+
+    return bitmap
+}
diff --git a/tests/activity/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/FakePayloadToggleCursorResolver.kt b/tests/activity/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/FakePayloadToggleCursorResolver.kt
new file mode 100644
index 00000000..ded9dce0
--- /dev/null
+++ b/tests/activity/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/cursor/FakePayloadToggleCursorResolver.kt
@@ -0,0 +1,67 @@
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
+package com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor
+
+import android.database.MatrixCursor
+import android.net.Uri
+import android.os.Bundle
+import android.service.chooser.AdditionalContentContract
+import com.android.intentresolver.TestContentProvider
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.CursorRow
+import com.android.intentresolver.util.cursor.CursorView
+import com.android.intentresolver.util.cursor.viewBy
+
+class FakePayloadToggleCursorResolver : CursorResolver<CursorRow?> {
+    private val uris = mutableListOf<Uri>()
+    private var startPosition = -1
+
+    fun setUris(count: Int, startPosition: Int, mimeTypes: Map<Int, String> = emptyMap()) {
+        uris.clear()
+        this.startPosition = startPosition
+        for (i in 0 until count) {
+            uris.add(
+                TestContentProvider.makeItemUri(
+                    i.toString(),
+                    mimeTypes.getOrDefault(i, DEFAULT_MIME_TYPE),
+                )
+            )
+        }
+    }
+
+    override suspend fun getCursor(): CursorView<CursorRow?>? {
+        val cursor = MatrixCursor(arrayOf(AdditionalContentContract.Columns.URI))
+        for (uri in uris) {
+            cursor.addRow(arrayOf(uri.toString()))
+        }
+        if (startPosition >= 0) {
+            var cursorExtras = cursor.extras
+            cursorExtras =
+                if (cursorExtras == null) {
+                    Bundle()
+                } else {
+                    Bundle(cursorExtras)
+                }
+            cursorExtras.putInt(AdditionalContentContract.CursorExtraKeys.POSITION, startPosition)
+            cursor.extras = cursorExtras
+        }
+        return cursor.viewBy { CursorRow(Uri.parse(getString(0)), null, position) }
+    }
+
+    companion object {
+        const val DEFAULT_MIME_TYPE = "image/png"
+    }
+}
diff --git a/tests/shared/src/com/android/intentresolver/inject/ChooserServiceFlagsKosmos.kt b/tests/activity/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/FakeSelectionChangeCallback.kt
similarity index 50%
rename from tests/shared/src/com/android/intentresolver/inject/ChooserServiceFlagsKosmos.kt
rename to tests/activity/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/FakeSelectionChangeCallback.kt
index 51dad82a..ad095677 100644
--- a/tests/shared/src/com/android/intentresolver/inject/ChooserServiceFlagsKosmos.kt
+++ b/tests/activity/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/update/FakeSelectionChangeCallback.kt
@@ -1,11 +1,11 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
- *      http://www.apache.org/licenses/LICENSE-2.0
+ *      https://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
@@ -14,11 +14,12 @@
  * limitations under the License.
  */
 
-package com.android.intentresolver.inject
+package com.android.intentresolver.contentpreview.payloadtoggle.domain.update
 
-import android.service.chooser.FeatureFlagsImpl
-import com.android.systemui.kosmos.Kosmos
+import android.content.Intent
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ShareouselUpdate
 
-var Kosmos.chooserServiceFlags: ChooserServiceFlags by Kosmos.Fixture { chooserServiceFlagsImpl }
-val chooserServiceFlagsImpl: FeatureFlagsImpl
-    get() = FeatureFlagsImpl()
+/** Fake no-op [SelectionChangeCallback]. */
+class FakeSelectionChangeCallback : SelectionChangeCallback {
+    override suspend fun onSelectionChanged(targetIntent: Intent): ShareouselUpdate? = null
+}
diff --git a/tests/shared/src/com/android/intentresolver/ResolverDataProvider.java b/tests/shared/src/com/android/intentresolver/ResolverDataProvider.java
index db109941..3953d89c 100644
--- a/tests/shared/src/com/android/intentresolver/ResolverDataProvider.java
+++ b/tests/shared/src/com/android/intentresolver/ResolverDataProvider.java
@@ -36,7 +36,7 @@ import androidx.annotation.NonNull;
  */
 public class ResolverDataProvider {
 
-    static private int USER_SOMEONE_ELSE = 10;
+    private static int sUserSomeoneElse = 99;
 
     static ResolvedComponentInfo createResolvedComponentInfo(int i) {
         return new ResolvedComponentInfo(
@@ -73,7 +73,7 @@ public class ResolverDataProvider {
         return new ResolvedComponentInfo(
                 createComponentName(i),
                 createResolverIntent(i),
-                createResolveInfo(i, USER_SOMEONE_ELSE));
+                createResolveInfo(i, sUserSomeoneElse));
     }
 
     public static ResolvedComponentInfo createResolvedComponentInfoWithOtherId(int i,
@@ -81,7 +81,7 @@ public class ResolverDataProvider {
         return new ResolvedComponentInfo(
                 createComponentName(i),
                 createResolverIntent(i),
-                createResolveInfo(i, USER_SOMEONE_ELSE, resolvedForUser));
+                createResolveInfo(i, sUserSomeoneElse, resolvedForUser));
     }
 
     static ResolvedComponentInfo createResolvedComponentInfoWithOtherId(int i, int userId) {
diff --git a/tests/unit/src/com/android/intentresolver/ProfileHelperTest.kt b/tests/unit/src/com/android/intentresolver/ProfileHelperTest.kt
index 05d642f7..956c39e9 100644
--- a/tests/unit/src/com/android/intentresolver/ProfileHelperTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ProfileHelperTest.kt
@@ -16,11 +16,9 @@
 
 package com.android.intentresolver
 
-import com.android.intentresolver.Flags.FLAG_ENABLE_PRIVATE_PROFILE
 import com.android.intentresolver.annotation.JavaInterop
 import com.android.intentresolver.data.repository.FakeUserRepository
 import com.android.intentresolver.domain.interactor.UserInteractor
-import com.android.intentresolver.inject.FakeIntentResolverFlags
 import com.android.intentresolver.shared.model.Profile
 import com.android.intentresolver.shared.model.User
 import com.google.common.truth.Truth.assertThat
@@ -43,14 +41,11 @@ class ProfileHelperTest {
     private val privateUser = User(12, User.Role.PRIVATE)
     private val privateProfile = Profile(Profile.Type.PRIVATE, privateUser)
 
-    private val flags =
-        FakeIntentResolverFlags().apply { setFlag(FLAG_ENABLE_PRIVATE_PROFILE, true) }
-
     private fun assertProfiles(
         helper: ProfileHelper,
         personalProfile: Profile,
         workProfile: Profile? = null,
-        privateProfile: Profile? = null
+        privateProfile: Profile? = null,
     ) {
         assertThat(helper.personalProfile).isEqualTo(personalProfile)
         assertThat(helper.personalHandle).isEqualTo(personalProfile.primary.handle)
@@ -92,13 +87,7 @@ class ProfileHelperTest {
         val repository = FakeUserRepository(listOf(personalUser))
         val interactor = UserInteractor(repository, launchedAs = personalUser.handle)
 
-        val helper =
-            ProfileHelper(
-                interactor = interactor,
-                scope = this,
-                background = Dispatchers.Unconfined,
-                flags = flags
-            )
+        val helper = ProfileHelper(interactor = interactor, background = Dispatchers.Unconfined)
 
         assertProfiles(helper, personalProfile)
 
@@ -114,13 +103,7 @@ class ProfileHelperTest {
         val repository = FakeUserRepository(listOf(personalUser, cloneUser))
         val interactor = UserInteractor(repository, launchedAs = personalUser.handle)
 
-        val helper =
-            ProfileHelper(
-                interactor = interactor,
-                scope = this,
-                background = Dispatchers.Unconfined,
-                flags = flags
-            )
+        val helper = ProfileHelper(interactor = interactor, background = Dispatchers.Unconfined)
 
         assertProfiles(helper, personalWithCloneProfile)
 
@@ -135,13 +118,7 @@ class ProfileHelperTest {
         val repository = FakeUserRepository(listOf(personalUser, cloneUser))
         val interactor = UserInteractor(repository, launchedAs = cloneUser.handle)
 
-        val helper =
-            ProfileHelper(
-                interactor = interactor,
-                scope = this,
-                background = Dispatchers.Unconfined,
-                flags = flags
-            )
+        val helper = ProfileHelper(interactor = interactor, background = Dispatchers.Unconfined)
 
         assertProfiles(helper, personalWithCloneProfile)
 
@@ -158,13 +135,7 @@ class ProfileHelperTest {
         val repository = FakeUserRepository(listOf(personalUser, workUser))
         val interactor = UserInteractor(repository, launchedAs = personalUser.handle)
 
-        val helper =
-            ProfileHelper(
-                interactor = interactor,
-                scope = this,
-                background = Dispatchers.Unconfined,
-                flags = flags
-            )
+        val helper = ProfileHelper(interactor = interactor, background = Dispatchers.Unconfined)
 
         assertProfiles(helper, personalProfile = personalProfile, workProfile = workProfile)
 
@@ -182,13 +153,7 @@ class ProfileHelperTest {
         val repository = FakeUserRepository(listOf(personalUser, workUser))
         val interactor = UserInteractor(repository, launchedAs = workUser.handle)
 
-        val helper =
-            ProfileHelper(
-                interactor = interactor,
-                scope = this,
-                background = Dispatchers.Unconfined,
-                flags = flags
-            )
+        val helper = ProfileHelper(interactor = interactor, background = Dispatchers.Unconfined)
 
         assertProfiles(helper, personalProfile = personalProfile, workProfile = workProfile)
 
@@ -206,13 +171,7 @@ class ProfileHelperTest {
         val repository = FakeUserRepository(listOf(personalUser, privateUser))
         val interactor = UserInteractor(repository, launchedAs = personalUser.handle)
 
-        val helper =
-            ProfileHelper(
-                interactor = interactor,
-                scope = this,
-                background = Dispatchers.Unconfined,
-                flags = flags
-            )
+        val helper = ProfileHelper(interactor = interactor, background = Dispatchers.Unconfined)
 
         assertProfiles(helper, personalProfile = personalProfile, privateProfile = privateProfile)
 
@@ -230,13 +189,7 @@ class ProfileHelperTest {
         val repository = FakeUserRepository(listOf(personalUser, privateUser))
         val interactor = UserInteractor(repository, launchedAs = privateUser.handle)
 
-        val helper =
-            ProfileHelper(
-                interactor = interactor,
-                scope = this,
-                background = Dispatchers.Unconfined,
-                flags = flags
-            )
+        val helper = ProfileHelper(interactor = interactor, background = Dispatchers.Unconfined)
 
         assertProfiles(helper, personalProfile = personalProfile, privateProfile = privateProfile)
 
@@ -248,28 +201,4 @@ class ProfileHelperTest {
             .isEqualTo(privateProfile.primary.handle)
         assertThat(helper.tabOwnerUserHandleForLaunch).isEqualTo(privateProfile.primary.handle)
     }
-
-    @Test
-    fun launchedByPersonal_withPrivate_privateDisabled() = runTest {
-        flags.setFlag(FLAG_ENABLE_PRIVATE_PROFILE, false)
-
-        val repository = FakeUserRepository(listOf(personalUser, privateUser))
-        val interactor = UserInteractor(repository, launchedAs = personalUser.handle)
-
-        val helper =
-            ProfileHelper(
-                interactor = interactor,
-                scope = this,
-                background = Dispatchers.Unconfined,
-                flags = flags
-            )
-
-        assertProfiles(helper, personalProfile = personalProfile, privateProfile = null)
-
-        assertThat(helper.isLaunchedAsCloneProfile).isFalse()
-        assertThat(helper.launchedAsProfileType).isEqualTo(Profile.Type.PERSONAL)
-        assertThat(helper.getQueryIntentsHandle(personalProfile.primary.handle))
-            .isEqualTo(personalProfile.primary.handle)
-        assertThat(helper.tabOwnerUserHandleForLaunch).isEqualTo(personalProfile.primary.handle)
-    }
 }
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoaderTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoaderTest.kt
deleted file mode 100644
index d5a569aa..00000000
--- a/tests/unit/src/com/android/intentresolver/contentpreview/CachingImagePreviewImageLoaderTest.kt
+++ /dev/null
@@ -1,280 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-import android.graphics.Bitmap
-import android.net.Uri
-import android.util.Size
-import com.google.common.truth.Truth.assertThat
-import kotlin.math.ceil
-import kotlin.math.roundToInt
-import kotlin.time.Duration.Companion.milliseconds
-import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.delay
-import kotlinx.coroutines.test.StandardTestDispatcher
-import kotlinx.coroutines.test.TestScope
-import kotlinx.coroutines.test.advanceTimeBy
-import kotlinx.coroutines.test.runCurrent
-import kotlinx.coroutines.test.runTest
-import org.junit.Test
-
-@OptIn(ExperimentalCoroutinesApi::class)
-class CachingImagePreviewImageLoaderTest {
-
-    private val testDispatcher = StandardTestDispatcher()
-    private val testScope = TestScope(testDispatcher)
-    private val testJobTime = 100.milliseconds
-    private val testCacheSize = 4
-    private val testMaxConcurrency = 2
-    private val testTimeToFillCache =
-        testJobTime * ceil((testCacheSize).toFloat() / testMaxConcurrency.toFloat()).roundToInt()
-    private val testUris =
-        List(5) { Uri.fromParts("TestScheme$it", "TestSsp$it", "TestFragment$it") }
-    private val previewSize = Size(500, 500)
-    private val testTimeToLoadAllUris =
-        testJobTime * ceil((testUris.size).toFloat() / testMaxConcurrency.toFloat()).roundToInt()
-    private val testBitmap = Bitmap.createBitmap(10, 10, Bitmap.Config.ALPHA_8)
-    private val fakeThumbnailLoader =
-        FakeThumbnailLoader().apply {
-            testUris.forEach {
-                fakeInvoke[it] = {
-                    delay(testJobTime)
-                    testBitmap
-                }
-            }
-        }
-
-    private val imageLoader =
-        CachingImagePreviewImageLoader(
-            scope = testScope.backgroundScope,
-            bgDispatcher = testDispatcher,
-            thumbnailLoader = fakeThumbnailLoader,
-            cacheSize = testCacheSize,
-            maxConcurrency = testMaxConcurrency,
-        )
-
-    @Test
-    fun loadImage_notCached_callsThumbnailLoader() =
-        testScope.runTest {
-            // Arrange
-            var result: Bitmap? = null
-
-            // Act
-            imageLoader.loadImage(testScope, testUris[0], previewSize) { result = it }
-            advanceTimeBy(testJobTime)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).containsExactly(testUris[0])
-            assertThat(result).isSameInstanceAs(testBitmap)
-        }
-
-    @Test
-    fun loadImage_cached_usesCachedValue() =
-        testScope.runTest {
-            // Arrange
-            imageLoader.loadImage(testScope, testUris[0], previewSize) {}
-            advanceTimeBy(testJobTime)
-            runCurrent()
-            fakeThumbnailLoader.invokeCalls.clear()
-            var result: Bitmap? = null
-
-            // Act
-            imageLoader.loadImage(testScope, testUris[0], previewSize) { result = it }
-            advanceTimeBy(testJobTime)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).isEmpty()
-            assertThat(result).isSameInstanceAs(testBitmap)
-        }
-
-    @Test
-    fun loadImage_error_returnsNull() =
-        testScope.runTest {
-            // Arrange
-            fakeThumbnailLoader.fakeInvoke[testUris[0]] = {
-                delay(testJobTime)
-                throw RuntimeException("Test exception")
-            }
-            var result: Bitmap? = testBitmap
-
-            // Act
-            imageLoader.loadImage(testScope, testUris[0], previewSize) { result = it }
-            advanceTimeBy(testJobTime)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).containsExactly(testUris[0])
-            assertThat(result).isNull()
-        }
-
-    @Test
-    fun loadImage_uncached_limitsConcurrency() =
-        testScope.runTest {
-            // Arrange
-            val results = mutableListOf<Bitmap?>()
-            assertThat(testUris.size).isGreaterThan(testMaxConcurrency)
-
-            // Act
-            testUris.take(testMaxConcurrency + 1).forEach { uri ->
-                imageLoader.loadImage(testScope, uri, previewSize) { results.add(it) }
-            }
-
-            // Assert
-            assertThat(results).isEmpty()
-            advanceTimeBy(testJobTime)
-            runCurrent()
-            assertThat(results).hasSize(testMaxConcurrency)
-            advanceTimeBy(testJobTime)
-            runCurrent()
-            assertThat(results).hasSize(testMaxConcurrency + 1)
-            assertThat(results)
-                .containsExactlyElementsIn(List(testMaxConcurrency + 1) { testBitmap })
-        }
-
-    @Test
-    fun loadImage_cacheEvicted_cancelsLoadAndReturnsNull() =
-        testScope.runTest {
-            // Arrange
-            val results = MutableList<Bitmap?>(testUris.size) { null }
-            assertThat(testUris.size).isGreaterThan(testCacheSize)
-
-            // Act
-            imageLoader.loadImage(testScope, testUris[0], previewSize) { results[0] = it }
-            runCurrent()
-            testUris.indices.drop(1).take(testCacheSize).forEach { i ->
-                imageLoader.loadImage(testScope, testUris[i], previewSize) { results[i] = it }
-            }
-            advanceTimeBy(testTimeToFillCache)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).containsExactlyElementsIn(testUris)
-            assertThat(results)
-                .containsExactlyElementsIn(
-                    List(testUris.size) { index -> if (index == 0) null else testBitmap }
-                )
-                .inOrder()
-            assertThat(fakeThumbnailLoader.unfinishedInvokeCount).isEqualTo(1)
-        }
-
-    @Test
-    fun prePopulate_fillsCache() =
-        testScope.runTest {
-            // Arrange
-            val fullCacheUris = testUris.take(testCacheSize)
-            assertThat(fullCacheUris).hasSize(testCacheSize)
-
-            // Act
-            imageLoader.prePopulate(fullCacheUris.map { it to previewSize })
-            advanceTimeBy(testTimeToFillCache)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).containsExactlyElementsIn(fullCacheUris)
-
-            // Act
-            fakeThumbnailLoader.invokeCalls.clear()
-            imageLoader.prePopulate(fullCacheUris.map { it to previewSize })
-            advanceTimeBy(testTimeToFillCache)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).isEmpty()
-        }
-
-    @Test
-    fun prePopulate_greaterThanCacheSize_fillsCacheThenDropsRemaining() =
-        testScope.runTest {
-            // Arrange
-            assertThat(testUris.size).isGreaterThan(testCacheSize)
-
-            // Act
-            imageLoader.prePopulate(testUris.map { it to previewSize })
-            advanceTimeBy(testTimeToLoadAllUris)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls)
-                .containsExactlyElementsIn(testUris.take(testCacheSize))
-
-            // Act
-            fakeThumbnailLoader.invokeCalls.clear()
-            imageLoader.prePopulate(testUris.map { it to previewSize })
-            advanceTimeBy(testTimeToLoadAllUris)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).isEmpty()
-        }
-
-    @Test
-    fun prePopulate_fewerThatCacheSize_loadsTheGiven() =
-        testScope.runTest {
-            // Arrange
-            val unfilledCacheUris = testUris.take(testMaxConcurrency)
-            assertThat(unfilledCacheUris.size).isLessThan(testCacheSize)
-
-            // Act
-            imageLoader.prePopulate(unfilledCacheUris.map { it to previewSize })
-            advanceTimeBy(testJobTime)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).containsExactlyElementsIn(unfilledCacheUris)
-
-            // Act
-            fakeThumbnailLoader.invokeCalls.clear()
-            imageLoader.prePopulate(unfilledCacheUris.map { it to previewSize })
-            advanceTimeBy(testJobTime)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).isEmpty()
-        }
-
-    @Test
-    fun invoke_uncached_alwaysCallsTheThumbnailLoader() =
-        testScope.runTest {
-            // Arrange
-
-            // Act
-            imageLoader.invoke(testUris[0], previewSize, caching = false)
-            imageLoader.invoke(testUris[0], previewSize, caching = false)
-            advanceTimeBy(testJobTime)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).containsExactly(testUris[0], testUris[0])
-        }
-
-    @Test
-    fun invoke_cached_usesTheCacheWhenPossible() =
-        testScope.runTest {
-            // Arrange
-
-            // Act
-            imageLoader.invoke(testUris[0], previewSize, caching = true)
-            imageLoader.invoke(testUris[0], previewSize, caching = true)
-            advanceTimeBy(testJobTime)
-            runCurrent()
-
-            // Assert
-            assertThat(fakeThumbnailLoader.invokeCalls).containsExactly(testUris[0])
-        }
-}
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUiTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUiTest.kt
index 1d85c61b..a944beee 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUiTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/FilesPlusTextContentPreviewUiTest.kt
@@ -20,6 +20,7 @@ import android.net.Uri
 import android.view.LayoutInflater
 import android.view.View
 import android.view.ViewGroup
+import android.widget.CheckBox
 import android.widget.TextView
 import androidx.annotation.IdRes
 import androidx.test.ext.junit.runners.AndroidJUnit4
@@ -192,6 +193,7 @@ class FilesPlusTextContentPreviewUiTest {
                 DefaultMimeTypeClassifier,
                 headlineGenerator,
                 testMetadataText,
+                /* allowTextToggle=*/ false,
             )
         val layoutInflater = LayoutInflater.from(context)
         val gridLayout =
@@ -203,7 +205,7 @@ class FilesPlusTextContentPreviewUiTest {
             context.resources,
             LayoutInflater.from(context),
             gridLayout,
-            headlineRow
+            headlineRow,
         )
 
         verify(headlineGenerator, times(1)).getFilesHeadline(sharedFileCount)
@@ -234,6 +236,7 @@ class FilesPlusTextContentPreviewUiTest {
                 DefaultMimeTypeClassifier,
                 headlineGenerator,
                 testMetadataText,
+                /* allowTextToggle=*/ false,
             )
         val layoutInflater = LayoutInflater.from(context)
         val gridLayout =
@@ -253,7 +256,7 @@ class FilesPlusTextContentPreviewUiTest {
                 context.resources,
                 LayoutInflater.from(context),
                 gridLayout,
-                headlineRow
+                headlineRow,
             )
 
         verify(headlineGenerator, times(1)).getFilesHeadline(sharedFileCount)
@@ -270,6 +273,73 @@ class FilesPlusTextContentPreviewUiTest {
         verifyPreviewMetadata(headlineRow, testMetadataText)
     }
 
+    @Test
+    fun test_allowToggle() {
+        val testSubject =
+            FilesPlusTextContentPreviewUi(
+                testScope,
+                /*isSingleImage=*/ false,
+                /* fileCount=*/ 1,
+                SHARED_TEXT,
+                /*intentMimeType=*/ "*/*",
+                actionFactory,
+                imageLoader,
+                DefaultMimeTypeClassifier,
+                headlineGenerator,
+                testMetadataText,
+                /* allowTextToggle=*/ true,
+            )
+        val layoutInflater = LayoutInflater.from(context)
+        val gridLayout =
+            layoutInflater.inflate(R.layout.chooser_grid_scrollable_preview, null, false)
+                as ViewGroup
+        val headlineRow = gridLayout.requireViewById<View>(R.id.chooser_headline_row_container)
+
+        testSubject.display(
+            context.resources,
+            LayoutInflater.from(context),
+            gridLayout,
+            headlineRow,
+        )
+
+        val checkbox = headlineRow.requireViewById<CheckBox>(R.id.include_text_action)
+        assertThat(checkbox.visibility).isEqualTo(View.VISIBLE)
+        assertThat(checkbox.isChecked).isTrue()
+    }
+
+    @Test
+    fun test_hideTextToggle() {
+        val testSubject =
+            FilesPlusTextContentPreviewUi(
+                testScope,
+                /*isSingleImage=*/ false,
+                /* fileCount=*/ 1,
+                SHARED_TEXT,
+                /*intentMimeType=*/ "*/*",
+                actionFactory,
+                imageLoader,
+                DefaultMimeTypeClassifier,
+                headlineGenerator,
+                testMetadataText,
+                /* allowTextToggle=*/ false,
+            )
+        val layoutInflater = LayoutInflater.from(context)
+        val gridLayout =
+            layoutInflater.inflate(R.layout.chooser_grid_scrollable_preview, null, false)
+                as ViewGroup
+        val headlineRow = gridLayout.requireViewById<View>(R.id.chooser_headline_row_container)
+
+        testSubject.display(
+            context.resources,
+            LayoutInflater.from(context),
+            gridLayout,
+            headlineRow,
+        )
+
+        val checkbox = headlineRow.requireViewById<CheckBox>(R.id.include_text_action)
+        assertThat(checkbox.visibility).isNotEqualTo(View.VISIBLE)
+    }
+
     private fun testLoadingHeadline(
         intentMimeType: String,
         sharedFileCount: Int,
@@ -287,6 +357,7 @@ class FilesPlusTextContentPreviewUiTest {
                 DefaultMimeTypeClassifier,
                 headlineGenerator,
                 testMetadataText,
+                /* allowTextToggle=*/ false,
             )
         val layoutInflater = LayoutInflater.from(context)
         val gridLayout =
@@ -307,7 +378,7 @@ class FilesPlusTextContentPreviewUiTest {
             context.resources,
             LayoutInflater.from(context),
             gridLayout,
-            headlineRow
+            headlineRow,
         ) to headlineRow
     }
 
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImplTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImplTest.kt
index dbc37b44..6d07d195 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImplTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/HeadlineGeneratorImplTest.kt
@@ -35,6 +35,12 @@ class HeadlineGeneratorImplTest {
         assertThat(generator.getTextHeadline(url)).isEqualTo("Sharing link")
     }
 
+    @Test
+    fun testCopyButtonContentDescription() {
+        assertThat(generator.getCopyButtonContentDescription(str)).isEqualTo("Copy text")
+        assertThat(generator.getCopyButtonContentDescription(url)).isEqualTo("Copy link")
+    }
+
     @Test
     fun testImagesWIthTextHeadline() {
         assertThat(generator.getImagesWithTextHeadline(str, 1)).isEqualTo("Sharing image with text")
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoaderTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoaderTest.kt
deleted file mode 100644
index d78e6665..00000000
--- a/tests/unit/src/com/android/intentresolver/contentpreview/ImagePreviewImageLoaderTest.kt
+++ /dev/null
@@ -1,375 +0,0 @@
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
-import android.content.ContentResolver
-import android.graphics.Bitmap
-import android.net.Uri
-import android.util.Size
-import com.google.common.truth.Truth.assertThat
-import java.util.ArrayDeque
-import java.util.concurrent.CountDownLatch
-import java.util.concurrent.TimeUnit.MILLISECONDS
-import java.util.concurrent.TimeUnit.SECONDS
-import java.util.concurrent.atomic.AtomicInteger
-import kotlin.coroutines.CoroutineContext
-import kotlinx.coroutines.CancellationException
-import kotlinx.coroutines.CompletableDeferred
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.CoroutineName
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.CoroutineStart.UNDISPATCHED
-import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.Runnable
-import kotlinx.coroutines.async
-import kotlinx.coroutines.cancel
-import kotlinx.coroutines.coroutineScope
-import kotlinx.coroutines.launch
-import kotlinx.coroutines.sync.Semaphore
-import kotlinx.coroutines.test.StandardTestDispatcher
-import kotlinx.coroutines.test.TestCoroutineScheduler
-import kotlinx.coroutines.test.TestScope
-import kotlinx.coroutines.test.UnconfinedTestDispatcher
-import kotlinx.coroutines.test.runTest
-import kotlinx.coroutines.yield
-import org.junit.Assert.assertTrue
-import org.junit.Test
-import org.mockito.kotlin.any
-import org.mockito.kotlin.anyOrNull
-import org.mockito.kotlin.doAnswer
-import org.mockito.kotlin.doReturn
-import org.mockito.kotlin.doThrow
-import org.mockito.kotlin.mock
-import org.mockito.kotlin.never
-import org.mockito.kotlin.times
-import org.mockito.kotlin.verify
-import org.mockito.kotlin.whenever
-
-@OptIn(ExperimentalCoroutinesApi::class)
-class ImagePreviewImageLoaderTest {
-    private val imageSize = Size(300, 300)
-    private val uriOne = Uri.parse("content://org.package.app/image-1.png")
-    private val uriTwo = Uri.parse("content://org.package.app/image-2.png")
-    private val bitmap = Bitmap.createBitmap(1, 1, Bitmap.Config.ARGB_8888)
-    private val contentResolver =
-        mock<ContentResolver> { on { loadThumbnail(any(), any(), anyOrNull()) } doReturn bitmap }
-    private val scheduler = TestCoroutineScheduler()
-    private val dispatcher = UnconfinedTestDispatcher(scheduler)
-    private val scope = TestScope(dispatcher)
-    private val testSubject =
-        ImagePreviewImageLoader(
-            dispatcher,
-            imageSize.width,
-            contentResolver,
-            cacheSize = 1,
-        )
-    private val previewSize = Size(500, 500)
-
-    @Test
-    fun prePopulate_cachesImagesUpToTheCacheSize() =
-        scope.runTest {
-            testSubject.prePopulate(listOf(uriOne to previewSize, uriTwo to previewSize))
-
-            verify(contentResolver, times(1)).loadThumbnail(uriOne, imageSize, null)
-            verify(contentResolver, never()).loadThumbnail(uriTwo, imageSize, null)
-
-            testSubject(uriOne, previewSize)
-            verify(contentResolver, times(1)).loadThumbnail(uriOne, imageSize, null)
-        }
-
-    @Test
-    fun invoke_returnCachedImageWhenCalledTwice() =
-        scope.runTest {
-            testSubject(uriOne, previewSize)
-            testSubject(uriOne, previewSize)
-
-            verify(contentResolver, times(1)).loadThumbnail(any(), any(), anyOrNull())
-        }
-
-    @Test
-    fun invoke_whenInstructed_doesNotCache() =
-        scope.runTest {
-            testSubject(uriOne, previewSize, false)
-            testSubject(uriOne, previewSize, false)
-
-            verify(contentResolver, times(2)).loadThumbnail(any(), any(), anyOrNull())
-        }
-
-    @Test
-    fun invoke_overlappedRequests_Deduplicate() =
-        scope.runTest {
-            val dispatcher = StandardTestDispatcher(scheduler)
-            val testSubject =
-                ImagePreviewImageLoader(
-                    dispatcher,
-                    imageSize.width,
-                    contentResolver,
-                    cacheSize = 1,
-                )
-            coroutineScope {
-                launch(start = UNDISPATCHED) { testSubject(uriOne, previewSize, false) }
-                launch(start = UNDISPATCHED) { testSubject(uriOne, previewSize, false) }
-                scheduler.advanceUntilIdle()
-            }
-
-            verify(contentResolver, times(1)).loadThumbnail(any(), any(), anyOrNull())
-        }
-
-    @Test
-    fun invoke_oldRecordsEvictedFromTheCache() =
-        scope.runTest {
-            testSubject(uriOne, previewSize)
-            testSubject(uriTwo, previewSize)
-            testSubject(uriTwo, previewSize)
-            testSubject(uriOne, previewSize)
-
-            verify(contentResolver, times(2)).loadThumbnail(uriOne, imageSize, null)
-            verify(contentResolver, times(1)).loadThumbnail(uriTwo, imageSize, null)
-        }
-
-    @Test
-    fun invoke_doNotCacheNulls() =
-        scope.runTest {
-            whenever(contentResolver.loadThumbnail(any(), any(), anyOrNull())).thenReturn(null)
-            testSubject(uriOne, previewSize)
-            testSubject(uriOne, previewSize)
-
-            verify(contentResolver, times(2)).loadThumbnail(uriOne, imageSize, null)
-        }
-
-    @Test(expected = CancellationException::class)
-    fun invoke_onClosedImageLoaderScope_throwsCancellationException() =
-        scope.runTest {
-            val imageLoaderScope = CoroutineScope(coroutineContext)
-            val testSubject =
-                ImagePreviewImageLoader(
-                    imageLoaderScope,
-                    imageSize.width,
-                    contentResolver,
-                    cacheSize = 1,
-                )
-            imageLoaderScope.cancel()
-            testSubject(uriOne, previewSize)
-        }
-
-    @Test(expected = CancellationException::class)
-    fun invoke_imageLoaderScopeClosedMidflight_throwsCancellationException() =
-        scope.runTest {
-            val dispatcher = StandardTestDispatcher(scheduler)
-            val imageLoaderScope = CoroutineScope(coroutineContext + dispatcher)
-            val testSubject =
-                ImagePreviewImageLoader(
-                    imageLoaderScope,
-                    imageSize.width,
-                    contentResolver,
-                    cacheSize = 1,
-                )
-            coroutineScope {
-                val deferred =
-                    async(start = UNDISPATCHED) { testSubject(uriOne, previewSize, false) }
-                imageLoaderScope.cancel()
-                scheduler.advanceUntilIdle()
-                deferred.await()
-            }
-        }
-
-    @Test
-    fun invoke_multipleCallsWithDifferentCacheInstructions_cachingPrevails() =
-        scope.runTest {
-            val dispatcher = StandardTestDispatcher(scheduler)
-            val imageLoaderScope = CoroutineScope(coroutineContext + dispatcher)
-            val testSubject =
-                ImagePreviewImageLoader(
-                    imageLoaderScope,
-                    imageSize.width,
-                    contentResolver,
-                    cacheSize = 1,
-                )
-            coroutineScope {
-                launch(start = UNDISPATCHED) { testSubject(uriOne, previewSize, false) }
-                launch(start = UNDISPATCHED) { testSubject(uriOne, previewSize, true) }
-                scheduler.advanceUntilIdle()
-            }
-            testSubject(uriOne, previewSize, true)
-
-            verify(contentResolver, times(1)).loadThumbnail(uriOne, imageSize, null)
-        }
-
-    @Test
-    fun invoke_semaphoreGuardsContentResolverCalls() =
-        scope.runTest {
-            val contentResolver =
-                mock<ContentResolver> {
-                    on { loadThumbnail(any(), any(), anyOrNull()) } doThrow
-                        SecurityException("test")
-                }
-            val acquireCount = AtomicInteger()
-            val releaseCount = AtomicInteger()
-            val testSemaphore =
-                object : Semaphore {
-                    override val availablePermits: Int
-                        get() = error("Unexpected invocation")
-
-                    override suspend fun acquire() {
-                        acquireCount.getAndIncrement()
-                    }
-
-                    override fun tryAcquire(): Boolean {
-                        error("Unexpected invocation")
-                    }
-
-                    override fun release() {
-                        releaseCount.getAndIncrement()
-                    }
-                }
-
-            val testSubject =
-                ImagePreviewImageLoader(
-                    CoroutineScope(coroutineContext + dispatcher),
-                    imageSize.width,
-                    contentResolver,
-                    cacheSize = 1,
-                    testSemaphore,
-                )
-            testSubject(uriOne, previewSize, false)
-
-            verify(contentResolver, times(1)).loadThumbnail(uriOne, imageSize, null)
-            assertThat(acquireCount.get()).isEqualTo(1)
-            assertThat(releaseCount.get()).isEqualTo(1)
-        }
-
-    @Test
-    fun invoke_semaphoreIsReleasedAfterContentResolverFailure() =
-        scope.runTest {
-            val semaphoreDeferred = CompletableDeferred<Unit>()
-            val releaseCount = AtomicInteger()
-            val testSemaphore =
-                object : Semaphore {
-                    override val availablePermits: Int
-                        get() = error("Unexpected invocation")
-
-                    override suspend fun acquire() {
-                        semaphoreDeferred.await()
-                    }
-
-                    override fun tryAcquire(): Boolean {
-                        error("Unexpected invocation")
-                    }
-
-                    override fun release() {
-                        releaseCount.getAndIncrement()
-                    }
-                }
-
-            val testSubject =
-                ImagePreviewImageLoader(
-                    CoroutineScope(coroutineContext + dispatcher),
-                    imageSize.width,
-                    contentResolver,
-                    cacheSize = 1,
-                    testSemaphore,
-                )
-            launch(start = UNDISPATCHED) { testSubject(uriOne, previewSize, false) }
-
-            verify(contentResolver, never()).loadThumbnail(any(), any(), anyOrNull())
-
-            semaphoreDeferred.complete(Unit)
-
-            verify(contentResolver, times(1)).loadThumbnail(uriOne, imageSize, null)
-            assertThat(releaseCount.get()).isEqualTo(1)
-        }
-
-    @Test
-    fun invoke_multipleSimultaneousCalls_limitOnNumberOfSimultaneousOutgoingCallsIsRespected() =
-        scope.runTest {
-            val requestCount = 4
-            val thumbnailCallsCdl = CountDownLatch(requestCount)
-            val pendingThumbnailCalls = ArrayDeque<CountDownLatch>()
-            val contentResolver =
-                mock<ContentResolver> {
-                    on { loadThumbnail(any(), any(), anyOrNull()) } doAnswer
-                        {
-                            val latch = CountDownLatch(1)
-                            synchronized(pendingThumbnailCalls) {
-                                pendingThumbnailCalls.offer(latch)
-                            }
-                            thumbnailCallsCdl.countDown()
-                            assertTrue("Timeout waiting thumbnail calls", latch.await(1, SECONDS))
-                            bitmap
-                        }
-                }
-            val name = "LoadImage"
-            val maxSimultaneousRequests = 2
-            val threadsStartedCdl = CountDownLatch(requestCount)
-            val dispatcher = NewThreadDispatcher(name) { threadsStartedCdl.countDown() }
-            val testSubject =
-                ImagePreviewImageLoader(
-                    CoroutineScope(coroutineContext + dispatcher + CoroutineName(name)),
-                    imageSize.width,
-                    contentResolver,
-                    cacheSize = 1,
-                    maxSimultaneousRequests,
-                )
-            coroutineScope {
-                repeat(requestCount) {
-                    launch {
-                        testSubject(Uri.parse("content://org.pkg.app/image-$it.png"), previewSize)
-                    }
-                }
-                yield()
-                // wait for all requests to be dispatched
-                assertThat(threadsStartedCdl.await(5, SECONDS)).isTrue()
-
-                assertThat(thumbnailCallsCdl.await(100, MILLISECONDS)).isFalse()
-                synchronized(pendingThumbnailCalls) {
-                    assertThat(pendingThumbnailCalls.size).isEqualTo(maxSimultaneousRequests)
-                }
-
-                pendingThumbnailCalls.poll()?.countDown()
-                assertThat(thumbnailCallsCdl.await(100, MILLISECONDS)).isFalse()
-                synchronized(pendingThumbnailCalls) {
-                    assertThat(pendingThumbnailCalls.size).isEqualTo(maxSimultaneousRequests)
-                }
-
-                pendingThumbnailCalls.poll()?.countDown()
-                assertThat(thumbnailCallsCdl.await(100, MILLISECONDS)).isTrue()
-                synchronized(pendingThumbnailCalls) {
-                    assertThat(pendingThumbnailCalls.size).isEqualTo(maxSimultaneousRequests)
-                }
-                for (cdl in pendingThumbnailCalls) {
-                    cdl.countDown()
-                }
-            }
-        }
-}
-
-private class NewThreadDispatcher(
-    private val coroutineName: String,
-    private val launchedCallback: () -> Unit
-) : CoroutineDispatcher() {
-    override fun isDispatchNeeded(context: CoroutineContext): Boolean = true
-
-    override fun dispatch(context: CoroutineContext, block: Runnable) {
-        Thread {
-                if (coroutineName == context[CoroutineName.Key]?.name) {
-                    launchedCallback()
-                }
-                block.run()
-            }
-            .start()
-    }
-}
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt
index 6dd96040..c1be5162 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt
@@ -363,6 +363,9 @@ class ShareouselViewModelTest {
                 override fun getFilesHeadline(count: Int): String = "FILES: $count"
 
                 override fun getNotItemsSelectedHeadline() = "Select items to share"
+
+                override fun getCopyButtonContentDescription(sharedText: CharSequence): String =
+                    "Copy"
             }
         // instantiate the view model, and then runCurrent() so that it is fully hydrated before
         // starting the test
diff --git a/tests/unit/src/com/android/intentresolver/emptystate/NoCrossProfileEmptyStateProviderTest.kt b/tests/unit/src/com/android/intentresolver/emptystate/NoCrossProfileEmptyStateProviderTest.kt
index 135ac064..bee13a21 100644
--- a/tests/unit/src/com/android/intentresolver/emptystate/NoCrossProfileEmptyStateProviderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/emptystate/NoCrossProfileEmptyStateProviderTest.kt
@@ -23,11 +23,9 @@ import com.android.intentresolver.annotation.JavaInterop
 import com.android.intentresolver.data.repository.DevicePolicyResources
 import com.android.intentresolver.data.repository.FakeUserRepository
 import com.android.intentresolver.domain.interactor.UserInteractor
-import com.android.intentresolver.inject.FakeIntentResolverFlags
 import com.android.intentresolver.shared.model.User
 import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.Truth.assertWithMessage
-import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Dispatchers
 import org.junit.Test
 import org.mockito.Mockito.never
@@ -46,7 +44,6 @@ class NoCrossProfileEmptyStateProviderTest {
     private val personalUser = User(0, User.Role.PERSONAL)
     private val workUser = User(10, User.Role.WORK)
     private val privateUser = User(11, User.Role.PRIVATE)
-    private val flags = FakeIntentResolverFlags()
 
     private val userRepository = FakeUserRepository(listOf(personalUser, workUser, privateUser))
 
@@ -84,7 +81,7 @@ class NoCrossProfileEmptyStateProviderTest {
                 hasCrossProfileIntents(
                     /* intents = */ any(),
                     /* source = */ any(),
-                    /* target = */ any()
+                    /* target = */ any(),
                 )
             } doReturn false /* Never allow */
         }
@@ -105,7 +102,7 @@ class NoCrossProfileEmptyStateProviderTest {
                 profileHelper,
                 devicePolicyResources,
                 crossProfileIntentsChecker,
-                /* isShare = */ true
+                /* isShare = */ true,
             )
 
         // Work to work, not blocked
@@ -123,7 +120,7 @@ class NoCrossProfileEmptyStateProviderTest {
                 profileHelper,
                 devicePolicyResources,
                 crossProfileIntentsChecker,
-                /* isShare = */ true
+                /* isShare = */ true,
             )
 
         val result = provider.getEmptyState(workListAdapter)
@@ -143,7 +140,7 @@ class NoCrossProfileEmptyStateProviderTest {
                 profileHelper,
                 devicePolicyResources,
                 crossProfileIntentsChecker,
-                /* isShare = */ true
+                /* isShare = */ true,
             )
 
         val result = provider.getEmptyState(personalListAdapter)
@@ -163,7 +160,7 @@ class NoCrossProfileEmptyStateProviderTest {
                 profileHelper,
                 devicePolicyResources,
                 crossProfileIntentsChecker,
-                /* isShare = */ true
+                /* isShare = */ true,
             )
 
         val result = provider.getEmptyState(privateListAdapter)
@@ -184,7 +181,7 @@ class NoCrossProfileEmptyStateProviderTest {
                 profileHelper,
                 devicePolicyResources,
                 crossProfileIntentsChecker,
-                /* isShare = */ true
+                /* isShare = */ true,
             )
 
         // Private -> Personal is always allowed:
@@ -197,12 +194,7 @@ class NoCrossProfileEmptyStateProviderTest {
     private fun createProfileHelper(launchedAs: User): ProfileHelper {
         val userInteractor = UserInteractor(userRepository, launchedAs = launchedAs.handle)
 
-        return ProfileHelper(
-            userInteractor,
-            CoroutineScope(Dispatchers.Unconfined),
-            Dispatchers.Unconfined,
-            flags
-        )
+        return ProfileHelper(userInteractor, Dispatchers.Unconfined)
     }
 
     private fun CrossProfileIntentsChecker.verifyCalled(
diff --git a/tests/unit/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractorTest.kt b/tests/unit/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractorTest.kt
new file mode 100644
index 00000000..75d4ec0d
--- /dev/null
+++ b/tests/unit/src/com/android/intentresolver/interactive/domain/interactor/InteractiveSessionInteractorTest.kt
@@ -0,0 +1,420 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+import android.content.ComponentName
+import android.content.Intent
+import android.content.Intent.ACTION_QUICK_VIEW
+import android.content.Intent.ACTION_RUN
+import android.content.Intent.ACTION_SEND
+import android.content.Intent.ACTION_VIEW
+import android.content.Intent.EXTRA_ALTERNATE_INTENTS
+import android.content.Intent.EXTRA_CHOOSER_REFINEMENT_INTENT_SENDER
+import android.content.Intent.EXTRA_CHOOSER_RESULT_INTENT_SENDER
+import android.content.Intent.EXTRA_CHOOSER_TARGETS
+import android.content.Intent.EXTRA_EXCLUDE_COMPONENTS
+import android.content.Intent.EXTRA_INITIAL_INTENTS
+import android.content.Intent.EXTRA_REPLACEMENT_EXTRAS
+import android.content.IntentSender
+import android.os.Binder
+import android.os.IBinder
+import android.os.IBinder.DeathRecipient
+import android.os.IInterface
+import android.os.Parcel
+import android.os.ResultReceiver
+import android.os.ShellCallback
+import android.service.chooser.ChooserTarget
+import androidx.core.os.bundleOf
+import androidx.lifecycle.SavedStateHandle
+import com.android.intentresolver.IChooserController
+import com.android.intentresolver.IChooserInteractiveSessionCallback
+import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.PendingSelectionCallbackRepository
+import com.android.intentresolver.data.model.ChooserRequest
+import com.android.intentresolver.data.repository.ActivityModelRepository
+import com.android.intentresolver.data.repository.ChooserRequestRepository
+import com.android.intentresolver.interactive.data.repository.InteractiveSessionCallbackRepository
+import com.android.intentresolver.shared.model.ActivityModel
+import com.google.common.truth.Correspondence
+import com.google.common.truth.Truth.assertThat
+import java.io.FileDescriptor
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.test.runTest
+import org.junit.Test
+
+class InteractiveSessionInteractorTest {
+    private val activityModelRepo =
+        ActivityModelRepository().apply {
+            initialize {
+                ActivityModel(
+                    intent = Intent(),
+                    launchedFromUid = 12345,
+                    launchedFromPackage = "org.client.package",
+                    referrer = null,
+                    isTaskRoot = false,
+                )
+            }
+        }
+    private val interactiveSessionCallback = FakeChooserInteractiveSessionCallback()
+    private val pendingSelectionCallbackRepo = PendingSelectionCallbackRepository()
+    private val savedStateHandle = SavedStateHandle()
+    private val interactiveCallbackRepo = InteractiveSessionCallbackRepository(savedStateHandle)
+
+    @Test
+    fun testChooserLaunchedInNewTask_sessionClosed() = runTest {
+        val activityModelRepo =
+            ActivityModelRepository().apply {
+                initialize {
+                    ActivityModel(
+                        intent = Intent(),
+                        launchedFromUid = 12345,
+                        launchedFromPackage = "org.client.package",
+                        referrer = null,
+                        isTaskRoot = true,
+                    )
+                }
+            }
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
+        testSubject.activate()
+
+        assertThat(interactiveSessionCallback.registeredIntentUpdaters).containsExactly(null)
+    }
+
+    @Test
+    fun testDeadBinder_sessionEnd() = runTest {
+        interactiveSessionCallback.isAlive = false
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
+        this.testScheduler.runCurrent()
+
+        assertThat(testSubject.isSessionActive.value).isFalse()
+    }
+
+    @Test
+    fun testBinderDies_sessionEnd() = runTest {
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
+        this.testScheduler.runCurrent()
+
+        assertThat(testSubject.isSessionActive.value).isTrue()
+        assertThat(interactiveSessionCallback.linkedDeathRecipients).hasSize(1)
+
+        interactiveSessionCallback.linkedDeathRecipients[0].binderDied()
+
+        assertThat(testSubject.isSessionActive.value).isFalse()
+    }
+
+    @Test
+    fun testScopeCancelled_unsubscribeFromBinder() = runTest {
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
+        val job = backgroundScope.launch { testSubject.activate() }
+        testScheduler.runCurrent()
+
+        assertThat(interactiveSessionCallback.linkedDeathRecipients).hasSize(1)
+        assertThat(interactiveSessionCallback.unlinkedDeathRecipients).hasSize(0)
+
+        job.cancel()
+        testScheduler.runCurrent()
+
+        assertThat(interactiveSessionCallback.unlinkedDeathRecipients).hasSize(1)
+    }
+
+    @Test
+    fun endSession_intentUpdaterCallbackReset() = runTest {
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
+        assertThat(interactiveSessionCallback.registeredIntentUpdaters).hasSize(1)
+
+        testSubject.endSession()
+
+        assertThat(interactiveSessionCallback.registeredIntentUpdaters).hasSize(2)
+        assertThat(interactiveSessionCallback.registeredIntentUpdaters[1]).isNull()
+    }
+
+    @Test
+    fun nullChooserIntentReceived_sessionEnds() = runTest {
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
+        assertThat(interactiveSessionCallback.registeredIntentUpdaters).hasSize(1)
+        interactiveSessionCallback.registeredIntentUpdaters[0]!!.updateIntent(null)
+        testScheduler.runCurrent()
+
+        assertThat(testSubject.isSessionActive.value).isFalse()
+    }
+
+    @Test
+    fun invalidChooserIntentReceived_intentIgnored() = runTest {
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
+        assertThat(interactiveSessionCallback.registeredIntentUpdaters).hasSize(1)
+        interactiveSessionCallback.registeredIntentUpdaters[0]!!.updateIntent(Intent())
+        testScheduler.runCurrent()
+
+        assertThat(testSubject.isSessionActive.value).isTrue()
+        assertThat(chooserRequestRepository.chooserRequest.value)
+            .isEqualTo(chooserRequestRepository.initialRequest)
+    }
+
+    @Test
+    fun validChooserIntentReceived_chooserRequestUpdated() = runTest {
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
+        assertThat(interactiveSessionCallback.registeredIntentUpdaters).hasSize(1)
+        val newTargetIntent = Intent(ACTION_VIEW).apply { type = "image/png" }
+        val newFilteredComponents = arrayOf(ComponentName.unflattenFromString("com.app/.MainA"))
+        val newCallerTargets =
+            arrayOf(
+                ChooserTarget(
+                    "A",
+                    null,
+                    0.5f,
+                    ComponentName.unflattenFromString("org.pkg/.Activity"),
+                    null,
+                )
+            )
+        val newAdditionalIntents = arrayOf(Intent(ACTION_RUN))
+        val newReplacementExtras = bundleOf("ONE" to 1, "TWO" to 2)
+        val newInitialIntents = arrayOf(Intent(ACTION_QUICK_VIEW))
+        val newResultSender = IntentSender(Binder())
+        val newRefinementSender = IntentSender(Binder())
+        interactiveSessionCallback.registeredIntentUpdaters[0]!!.updateIntent(
+            Intent.createChooser(newTargetIntent, "").apply {
+                putExtra(EXTRA_EXCLUDE_COMPONENTS, newFilteredComponents)
+                putExtra(EXTRA_CHOOSER_TARGETS, newCallerTargets)
+                putExtra(EXTRA_ALTERNATE_INTENTS, newAdditionalIntents)
+                putExtra(EXTRA_REPLACEMENT_EXTRAS, newReplacementExtras)
+                putExtra(EXTRA_INITIAL_INTENTS, newInitialIntents)
+                putExtra(EXTRA_CHOOSER_RESULT_INTENT_SENDER, newResultSender)
+                putExtra(EXTRA_CHOOSER_REFINEMENT_INTENT_SENDER, newRefinementSender)
+            }
+        )
+        testScheduler.runCurrent()
+
+        assertThat(testSubject.isSessionActive.value).isTrue()
+        val updatedRequest = chooserRequestRepository.chooserRequest.value
+        assertThat(updatedRequest.targetAction).isEqualTo(newTargetIntent.action)
+        assertThat(updatedRequest.targetType).isEqualTo(newTargetIntent.type)
+        assertThat(updatedRequest.filteredComponentNames).containsExactly(newFilteredComponents[0])
+        assertThat(updatedRequest.callerChooserTargets).containsExactly(newCallerTargets[0])
+        assertThat(updatedRequest.additionalTargets)
+            .comparingElementsUsing<Intent, String>(
+                Correspondence.transforming({ it.action }, "action")
+            )
+            .containsExactly(newAdditionalIntents[0].action)
+        assertThat(updatedRequest.replacementExtras!!.keySet())
+            .containsExactlyElementsIn(newReplacementExtras.keySet())
+        assertThat(updatedRequest.initialIntents)
+            .comparingElementsUsing<Intent, String>(
+                Correspondence.transforming({ it.action }, "action")
+            )
+            .containsExactly(newInitialIntents[0].action)
+        assertThat(updatedRequest.chosenComponentSender).isEqualTo(newResultSender)
+        assertThat(updatedRequest.refinementIntentSender).isEqualTo(newRefinementSender)
+    }
+}
+
+private class FakeChooserInteractiveSessionCallback :
+    IChooserInteractiveSessionCallback, IBinder, IInterface {
+    var isAlive = true
+    val registeredIntentUpdaters = ArrayList<IChooserController?>()
+    val linkedDeathRecipients = ArrayList<DeathRecipient>()
+    val unlinkedDeathRecipients = ArrayList<DeathRecipient>()
+
+    override fun registerChooserController(intentUpdater: IChooserController?) {
+        registeredIntentUpdaters.add(intentUpdater)
+    }
+
+    override fun onDrawerVerticalOffsetChanged(offset: Int) {}
+
+    override fun asBinder() = this
+
+    override fun getInterfaceDescriptor() = ""
+
+    override fun pingBinder() = true
+
+    override fun isBinderAlive() = isAlive
+
+    override fun queryLocalInterface(descriptor: String): IInterface =
+        this@FakeChooserInteractiveSessionCallback
+
+    override fun dump(fd: FileDescriptor, args: Array<out String>?) = Unit
+
+    override fun dumpAsync(fd: FileDescriptor, args: Array<out String>?) = Unit
+
+    override fun shellCommand(
+        `in`: FileDescriptor?,
+        out: FileDescriptor?,
+        err: FileDescriptor?,
+        args: Array<out String>,
+        shellCallback: ShellCallback?,
+        resultReceiver: ResultReceiver,
+    ) = Unit
+
+    override fun transact(code: Int, data: Parcel, reply: Parcel?, flags: Int) = true
+
+    override fun linkToDeath(recipient: DeathRecipient, flags: Int) {
+        linkedDeathRecipients.add(recipient)
+    }
+
+    override fun unlinkToDeath(recipient: DeathRecipient, flags: Int): Boolean {
+        unlinkedDeathRecipients.add(recipient)
+        return true
+    }
+}
diff --git a/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt b/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt
index d11cb460..eb5297b4 100644
--- a/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/shortcuts/ShortcutLoaderTest.kt
@@ -30,8 +30,7 @@ import android.platform.test.annotations.DisableFlags
 import android.platform.test.annotations.EnableFlags
 import android.platform.test.flag.junit.SetFlagsRule
 import androidx.test.filters.SmallTest
-import com.android.intentresolver.Flags.FLAG_FIX_SHORTCUTS_FLASHING
-import com.android.intentresolver.Flags.FLAG_FIX_SHORTCUT_LOADER_JOB_LEAK
+import com.android.intentresolver.Flags.FLAG_FIX_SHORTCUTS_FLASHING_FIXED
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.createAppTarget
 import com.android.intentresolver.createShareShortcutInfo
@@ -109,7 +108,7 @@ class ShortcutLoaderTest {
                     true,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(appTargets)
@@ -122,7 +121,7 @@ class ShortcutLoaderTest {
                     // ignored
                     createAppTarget(
                         createShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
-                    )
+                    ),
                 )
             val appPredictorCallbackCaptor = argumentCaptor<AppPredictor.Callback>()
             verify(appPredictor, atLeastOnce())
@@ -137,7 +136,7 @@ class ShortcutLoaderTest {
             assertArrayEquals(
                 "Wrong input app targets in the result",
                 appTargets,
-                result.appTargets
+                result.appTargets,
             )
             assertEquals("Wrong shortcut count", 1, result.shortcutsByApp.size)
             assertEquals("Wrong app target", appTarget, result.shortcutsByApp[0].appTarget)
@@ -145,12 +144,12 @@ class ShortcutLoaderTest {
                 assertEquals(
                     "Wrong AppTarget in the cache",
                     matchingAppTarget,
-                    result.directShareAppTargetCache[shortcut]
+                    result.directShareAppTargetCache[shortcut],
                 )
                 assertEquals(
                     "Wrong ShortcutInfo in the cache",
                     matchingShortcutInfo,
-                    result.directShareShortcutInfoCache[shortcut]
+                    result.directShareShortcutInfoCache[shortcut],
                 )
             }
         }
@@ -162,7 +161,7 @@ class ShortcutLoaderTest {
                 listOf(
                     ShortcutManager.ShareShortcutInfo(matchingShortcutInfo, componentName),
                     // mismatching shortcut
-                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
+                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1),
                 )
             val shortcutManager =
                 mock<ShortcutManager> {
@@ -178,7 +177,7 @@ class ShortcutLoaderTest {
                     true,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(appTargets)
@@ -191,19 +190,19 @@ class ShortcutLoaderTest {
             assertArrayEquals(
                 "Wrong input app targets in the result",
                 appTargets,
-                result.appTargets
+                result.appTargets,
             )
             assertEquals("Wrong shortcut count", 1, result.shortcutsByApp.size)
             assertEquals("Wrong app target", appTarget, result.shortcutsByApp[0].appTarget)
             for (shortcut in result.shortcutsByApp[0].shortcuts) {
                 assertTrue(
                     "AppTargets are not expected the cache of a ShortcutManager result",
-                    result.directShareAppTargetCache.isEmpty()
+                    result.directShareAppTargetCache.isEmpty(),
                 )
                 assertEquals(
                     "Wrong ShortcutInfo in the cache",
                     matchingShortcutInfo,
-                    result.directShareShortcutInfoCache[shortcut]
+                    result.directShareShortcutInfoCache[shortcut],
                 )
             }
         }
@@ -215,7 +214,7 @@ class ShortcutLoaderTest {
                 listOf(
                     ShortcutManager.ShareShortcutInfo(matchingShortcutInfo, componentName),
                     // mismatching shortcut
-                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
+                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1),
                 )
             val shortcutManager =
                 mock<ShortcutManager> {
@@ -231,7 +230,7 @@ class ShortcutLoaderTest {
                     true,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(appTargets)
@@ -250,19 +249,19 @@ class ShortcutLoaderTest {
             assertArrayEquals(
                 "Wrong input app targets in the result",
                 appTargets,
-                result.appTargets
+                result.appTargets,
             )
             assertEquals("Wrong shortcut count", 1, result.shortcutsByApp.size)
             assertEquals("Wrong app target", appTarget, result.shortcutsByApp[0].appTarget)
             for (shortcut in result.shortcutsByApp[0].shortcuts) {
                 assertTrue(
                     "AppTargets are not expected the cache of a ShortcutManager result",
-                    result.directShareAppTargetCache.isEmpty()
+                    result.directShareAppTargetCache.isEmpty(),
                 )
                 assertEquals(
                     "Wrong ShortcutInfo in the cache",
                     matchingShortcutInfo,
-                    result.directShareShortcutInfoCache[shortcut]
+                    result.directShareShortcutInfoCache[shortcut],
                 )
             }
         }
@@ -274,7 +273,7 @@ class ShortcutLoaderTest {
                 listOf(
                     ShortcutManager.ShareShortcutInfo(matchingShortcutInfo, componentName),
                     // mismatching shortcut
-                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
+                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1),
                 )
             val shortcutManager =
                 mock<ShortcutManager> {
@@ -292,7 +291,7 @@ class ShortcutLoaderTest {
                     true,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(appTargets)
@@ -307,32 +306,32 @@ class ShortcutLoaderTest {
             assertArrayEquals(
                 "Wrong input app targets in the result",
                 appTargets,
-                result.appTargets
+                result.appTargets,
             )
             assertEquals("Wrong shortcut count", 1, result.shortcutsByApp.size)
             assertEquals("Wrong app target", appTarget, result.shortcutsByApp[0].appTarget)
             for (shortcut in result.shortcutsByApp[0].shortcuts) {
                 assertTrue(
                     "AppTargets are not expected the cache of a ShortcutManager result",
-                    result.directShareAppTargetCache.isEmpty()
+                    result.directShareAppTargetCache.isEmpty(),
                 )
                 assertEquals(
                     "Wrong ShortcutInfo in the cache",
                     matchingShortcutInfo,
-                    result.directShareShortcutInfoCache[shortcut]
+                    result.directShareShortcutInfoCache[shortcut],
                 )
             }
         }
 
     @Test
-    @DisableFlags(FLAG_FIX_SHORTCUTS_FLASHING)
+    @DisableFlags(FLAG_FIX_SHORTCUTS_FLASHING_FIXED)
     fun test_appPredictorNotResponding_noCallbackFromShortcutLoader() {
         scope.runTest {
             val shortcutManagerResult =
                 listOf(
                     ShortcutManager.ShareShortcutInfo(matchingShortcutInfo, componentName),
                     // mismatching shortcut
-                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
+                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1),
                 )
             val shortcutManager =
                 mock<ShortcutManager> {
@@ -348,7 +347,7 @@ class ShortcutLoaderTest {
                     true,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(appTargets)
@@ -361,7 +360,7 @@ class ShortcutLoaderTest {
     }
 
     @Test
-    @EnableFlags(FLAG_FIX_SHORTCUTS_FLASHING)
+    @EnableFlags(FLAG_FIX_SHORTCUTS_FLASHING_FIXED)
     fun test_appPredictorNotResponding_timeoutAndFallbackToShortcutManager() {
         scope.runTest {
             val testSubject =
@@ -373,7 +372,7 @@ class ShortcutLoaderTest {
                     true,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(appTargets)
@@ -386,7 +385,7 @@ class ShortcutLoaderTest {
                     // ignored
                     createAppTarget(
                         createShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
-                    )
+                    ),
                 )
             val appPredictorCallbackCaptor = argumentCaptor<AppPredictor.Callback>()
             verify(appPredictor, atLeastOnce())
@@ -399,14 +398,14 @@ class ShortcutLoaderTest {
     }
 
     @Test
-    @EnableFlags(FLAG_FIX_SHORTCUTS_FLASHING)
+    @EnableFlags(FLAG_FIX_SHORTCUTS_FLASHING_FIXED)
     fun test_appPredictorResponding_appPredictorTimeoutJobIsCancelled() {
         scope.runTest {
             val shortcutManagerResult =
                 listOf(
                     ShortcutManager.ShareShortcutInfo(matchingShortcutInfo, componentName),
                     // mismatching shortcut
-                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
+                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1),
                 )
             val shortcutManager =
                 mock<ShortcutManager> {
@@ -422,7 +421,7 @@ class ShortcutLoaderTest {
                     true,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(appTargets)
@@ -472,7 +471,7 @@ class ShortcutLoaderTest {
                 true,
                 intentFilter,
                 dispatcher,
-                callback
+                callback,
             )
 
             verify(appPredictor, times(1)).requestPredictionUpdate()
@@ -486,7 +485,7 @@ class ShortcutLoaderTest {
                 listOf(
                     ShortcutManager.ShareShortcutInfo(matchingShortcutInfo, componentName),
                     // mismatching shortcut
-                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1)
+                    createShareShortcutInfo("id-1", ComponentName("mismatching.pkg", "Class"), 1),
                 )
             val shortcutManager =
                 mock<ShortcutManager> {
@@ -502,7 +501,7 @@ class ShortcutLoaderTest {
                     true,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             verify(shortcutManager, times(1)).getShareTargets(any())
@@ -530,7 +529,7 @@ class ShortcutLoaderTest {
                 true,
                 intentFilter,
                 dispatcher,
-                callback
+                callback,
             )
 
             verify(appPredictor, never()).unregisterPredictionUpdates(any())
@@ -553,7 +552,7 @@ class ShortcutLoaderTest {
                     isPersonalProfile = true,
                     targetIntentFilter = null,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(appTargets)
@@ -575,7 +574,7 @@ class ShortcutLoaderTest {
             assertArrayEquals(
                 "Wrong input app targets in the result",
                 appTargets,
-                result.appTargets
+                result.appTargets,
             )
             assertWithMessage("An empty result is expected").that(result.shortcutsByApp).isEmpty()
         }
@@ -611,7 +610,6 @@ class ShortcutLoaderTest {
     }
 
     @Test
-    @EnableFlags(FLAG_FIX_SHORTCUT_LOADER_JOB_LEAK)
     fun test_ShortcutLoaderDestroyed_appPredictorCallbackUnregisteredAndWatchdogCancelled() {
         scope.runTest {
             val testSubject =
@@ -623,7 +621,7 @@ class ShortcutLoaderTest {
                     true,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(appTargets)
@@ -637,7 +635,7 @@ class ShortcutLoaderTest {
     private fun testDisabledWorkProfileDoNotCallSystem(
         isUserRunning: Boolean = true,
         isUserUnlocked: Boolean = true,
-        isQuietModeEnabled: Boolean = false
+        isQuietModeEnabled: Boolean = false,
     ) =
         scope.runTest {
             val userHandle = UserHandle.of(10)
@@ -658,7 +656,7 @@ class ShortcutLoaderTest {
                     false,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(arrayOf<DisplayResolveInfo>(mock()))
@@ -669,7 +667,7 @@ class ShortcutLoaderTest {
     private fun testAlwaysCallSystemForMainProfile(
         isUserRunning: Boolean = true,
         isUserUnlocked: Boolean = true,
-        isQuietModeEnabled: Boolean = false
+        isQuietModeEnabled: Boolean = false,
     ) =
         scope.runTest {
             val userHandle = UserHandle.of(10)
@@ -690,7 +688,7 @@ class ShortcutLoaderTest {
                     true,
                     intentFilter,
                     dispatcher,
-                    callback
+                    callback,
                 )
 
             testSubject.updateAppTargets(arrayOf<DisplayResolveInfo>(mock()))
diff --git a/tests/unit/src/com/android/intentresolver/ui/model/ActivityModelTest.kt b/tests/unit/src/com/android/intentresolver/ui/model/ActivityModelTest.kt
index 5f86159c..b48a6422 100644
--- a/tests/unit/src/com/android/intentresolver/ui/model/ActivityModelTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ui/model/ActivityModelTest.kt
@@ -30,7 +30,7 @@ class ActivityModelTest {
 
     @Test
     fun testDefaultValues() {
-        val input = ActivityModel(Intent(ACTION_CHOOSER), 0, "example.com", null)
+        val input = ActivityModel(Intent(ACTION_CHOOSER), 0, "example.com", null, false)
 
         val output = input.toParcelAndBack()
 
@@ -41,7 +41,13 @@ class ActivityModelTest {
     fun testCommonValues() {
         val intent = Intent(ACTION_CHOOSER).apply { putExtra(EXTRA_TEXT, "Test") }
         val input =
-            ActivityModel(intent, 1234, "com.example", Uri.parse("android-app://example.com"))
+            ActivityModel(
+                intent,
+                1234,
+                "com.example",
+                Uri.parse("android-app://example.com"),
+                false,
+            )
 
         val output = input.toParcelAndBack()
 
@@ -56,6 +62,7 @@ class ActivityModelTest {
                 launchedFromUid = 1000,
                 launchedFromPackage = "other.example.com",
                 referrer = Uri.parse("android-app://app.example.com"),
+                false,
             )
 
         assertThat(launch1.referrerPackage).isEqualTo("app.example.com")
@@ -69,6 +76,7 @@ class ActivityModelTest {
                 launchedFromUid = 1000,
                 launchedFromPackage = "example.com",
                 referrer = Uri.parse("http://some.other.value"),
+                false,
             )
 
         assertThat(launch.referrerPackage).isNull()
@@ -82,6 +90,7 @@ class ActivityModelTest {
                 launchedFromUid = 1000,
                 launchedFromPackage = "example.com",
                 referrer = null,
+                false,
             )
 
         assertThat(launch.referrerPackage).isNull()
diff --git a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
index 71f28950..7bc1e785 100644
--- a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
@@ -28,6 +28,9 @@ import android.content.Intent.EXTRA_REFERRER
 import android.content.Intent.EXTRA_TEXT
 import android.content.Intent.EXTRA_TITLE
 import android.net.Uri
+import android.platform.test.annotations.DisableFlags
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
 import androidx.core.net.toUri
 import androidx.core.os.bundleOf
 import com.android.intentresolver.ContentTypeHint
@@ -37,13 +40,16 @@ import com.android.intentresolver.validation.Importance
 import com.android.intentresolver.validation.Invalid
 import com.android.intentresolver.validation.NoValue
 import com.android.intentresolver.validation.Valid
+import com.android.systemui.shared.Flags
 import com.google.common.truth.Truth.assertThat
+import org.junit.Rule
 import org.junit.Test
 
 private fun createActivityModel(
     targetIntent: Intent?,
     referrer: Uri? = null,
     additionalIntents: List<Intent>? = null,
+    launchedFromPackage: String = "com.android.example",
 ) =
     ActivityModel(
         Intent(ACTION_CHOOSER).apply {
@@ -51,11 +57,13 @@ private fun createActivityModel(
             additionalIntents?.also { putExtra(EXTRA_ALTERNATE_INTENTS, it.toTypedArray()) }
         },
         launchedFromUid = 10000,
-        launchedFromPackage = "com.android.example",
-        referrer = referrer ?: "android-app://com.android.example".toUri(),
+        launchedFromPackage = launchedFromPackage,
+        referrer = referrer ?: "android-app://$launchedFromPackage".toUri(),
+        false,
     )
 
 class ChooserRequestTest {
+    @get:Rule val flagsRule = SetFlagsRule()
 
     @Test
     fun missingIntent() {
@@ -264,4 +272,46 @@ class ChooserRequestTest {
             assertThat(request.sharedTextTitle).isEqualTo(title)
         }
     }
+
+    @Test
+    @DisableFlags(Flags.FLAG_SCREENSHOT_CONTEXT_URL)
+    fun testCallerAllowsTextToggle_flagOff() {
+        val intent = Intent().putExtras(bundleOf(EXTRA_INTENT to Intent(ACTION_SEND)))
+        val model =
+            createActivityModel(targetIntent = intent, launchedFromPackage = "com.android.systemui")
+        val result = readChooserRequest(model)
+
+        assertThat(result).isInstanceOf(Valid::class.java)
+        result as Valid<ChooserRequest>
+
+        assertThat(result.value.callerAllowsTextToggle).isFalse()
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_SCREENSHOT_CONTEXT_URL)
+    fun testCallerAllowsTextToggle_sysuiPackage() {
+        val intent = Intent().putExtras(bundleOf(EXTRA_INTENT to Intent(ACTION_SEND)))
+        val model =
+            createActivityModel(targetIntent = intent, launchedFromPackage = "com.android.systemui")
+        val result = readChooserRequest(model)
+
+        assertThat(result).isInstanceOf(Valid::class.java)
+        result as Valid<ChooserRequest>
+
+        assertThat(result.value.callerAllowsTextToggle).isTrue()
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_SCREENSHOT_CONTEXT_URL)
+    fun testCallerAllowsTextToggle_otherPackage() {
+        val intent = Intent().putExtras(bundleOf(EXTRA_INTENT to Intent(ACTION_SEND)))
+        val model =
+            createActivityModel(targetIntent = intent, launchedFromPackage = "com.hello.world")
+        val result = readChooserRequest(model)
+
+        assertThat(result).isInstanceOf(Valid::class.java)
+        result as Valid<ChooserRequest>
+
+        assertThat(result.value.callerAllowsTextToggle).isFalse()
+    }
 }
diff --git a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ResolverRequestTest.kt b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ResolverRequestTest.kt
index 70512021..be6560c2 100644
--- a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ResolverRequestTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ResolverRequestTest.kt
@@ -40,6 +40,7 @@ private fun createActivityModel(targetIntent: Intent, referrer: Uri? = null) =
         launchedFromUid = 10000,
         launchedFromPackage = "com.android.example",
         referrer = referrer ?: "android-app://com.android.example".toUri(),
+        false,
     )
 
 class ResolverRequestTest {
```

