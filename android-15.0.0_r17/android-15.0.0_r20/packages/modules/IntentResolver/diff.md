```diff
diff --git a/Android.bp b/Android.bp
index 75e29a8c..c0e09105 100644
--- a/Android.bp
+++ b/Android.bp
@@ -54,6 +54,7 @@ android_library {
         "dagger2",
         "hilt_android",
         "IntentResolverFlagsLib",
+        "iconloader",
         "jsr330",
         "kotlin-stdlib",
         "kotlinx_coroutines",
diff --git a/aconfig/FeatureFlags.aconfig b/aconfig/FeatureFlags.aconfig
index 8396bc24..e2b2f57b 100644
--- a/aconfig/FeatureFlags.aconfig
+++ b/aconfig/FeatureFlags.aconfig
@@ -19,6 +19,16 @@ flag {
   bug: "328029692"
 }
 
+flag {
+  name: "individual_metadata_title_read"
+  namespace: "intentresolver"
+  description: "Enables separate title URI metadata calls"
+  bug: "304686417"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
 flag {
   name: "refine_system_actions"
   namespace: "intentresolver"
@@ -96,6 +106,33 @@ flag {
   }
 }
 
+flag {
+  name: "keyboard_navigation_fix"
+  namespace: "intentresolver"
+  description: "Enable Chooser keyboard navigation bugfix"
+  bug: "325259478"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+flag {
+  name: "rebuild_adapters_on_target_pinning"
+  namespace: "intentresolver"
+  description: "Rebuild and swap adapters when a target gets (un)pinned to avoid flickering."
+  bug: "230703572"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+flag {
+  name: "target_hover_and_keyboard_focus_states"
+  namespace: "intentresolver"
+  description: "Adopt Launcher pointer hover and keyboard novigation focus effects for targets."
+  bug: "295175912"
+}
+
 flag {
   name: "preview_image_loader"
   namespace: "intentresolver"
@@ -103,6 +140,16 @@ flag {
   bug: "348665058"
 }
 
+flag {
+  name: "save_shareousel_state"
+  namespace: "intentresolver"
+  description: "Preserve Shareousel state over a system-initiated process death."
+  bug: "362347212"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
 flag {
   name: "shareousel_update_exclude_components_extra"
   namespace: "intentresolver"
diff --git a/java/res/color/resolver_profile_tab_text.xml b/java/res/color/resolver_profile_tab_text.xml
index 7c2723ce..ffeba854 100644
--- a/java/res/color/resolver_profile_tab_text.xml
+++ b/java/res/color/resolver_profile_tab_text.xml
@@ -15,6 +15,6 @@
 -->
 <selector xmlns:android="http://schemas.android.com/apk/res/android"
           xmlns:androidprv="http://schemas.android.com/apk/prv/res/android">
-    <item android:color="?androidprv:attr/materialColorOnPrimary" android:state_selected="true"/>
-    <item android:color="?androidprv:attr/materialColorOnSurfaceVariant"/>
+    <item android:color="@androidprv:color/materialColorOnPrimary" android:state_selected="true"/>
+    <item android:color="@androidprv:color/materialColorOnSurfaceVariant"/>
 </selector>
diff --git a/java/res/drawable/bottomsheet_background.xml b/java/res/drawable/bottomsheet_background.xml
index f4386b7d..ec676cea 100644
--- a/java/res/drawable/bottomsheet_background.xml
+++ b/java/res/drawable/bottomsheet_background.xml
@@ -20,5 +20,5 @@
     <corners
         android:topLeftRadius="@*android:dimen/config_bottomDialogCornerRadius"
         android:topRightRadius="@*android:dimen/config_bottomDialogCornerRadius"/>
-    <solid android:color="?androidprv:attr/materialColorSurfaceContainer" />
+    <solid android:color="@androidprv:color/materialColorSurfaceContainer" />
 </shape>
diff --git a/java/res/drawable/chevron_right.xml b/java/res/drawable/chevron_right.xml
index 747e06dd..09fd97a7 100644
--- a/java/res/drawable/chevron_right.xml
+++ b/java/res/drawable/chevron_right.xml
@@ -26,7 +26,7 @@
         android:viewportWidth="16"
         android:viewportHeight="24"
         android:autoMirrored="true"
-        android:tint="?androidprv:attr/materialColorOnSurface">
+        android:tint="@androidprv:color/materialColorOnSurface">
     <path
         android:fillColor="@android:color/white"
         android:pathData="M10,4.5L8.59,5.91 13.17,10.5l-4.58,4.59L10,16.5l6,-6 -6,-6z"/>
diff --git a/java/res/drawable/chooser_action_button_bg.xml b/java/res/drawable/chooser_action_button_bg.xml
index 300be831..88eac4ce 100644
--- a/java/res/drawable/chooser_action_button_bg.xml
+++ b/java/res/drawable/chooser_action_button_bg.xml
@@ -25,7 +25,7 @@
             android:insetBottom="8dp">
             <shape android:shape="rectangle">
                 <corners android:radius="@dimen/chooser_action_corner_radius" />
-                <solid android:color="?androidprv:attr/materialColorSurfaceContainerHigh"/>
+                <solid android:color="@androidprv:color/materialColorSurfaceContainerHigh"/>
             </shape>
         </inset>
     </item>
diff --git a/java/res/drawable/chooser_content_preview_rounded.xml b/java/res/drawable/chooser_content_preview_rounded.xml
index a1b204bd..00aa2912 100644
--- a/java/res/drawable/chooser_content_preview_rounded.xml
+++ b/java/res/drawable/chooser_content_preview_rounded.xml
@@ -21,7 +21,7 @@
     android:shape="rectangle">
 
     <solid
-        android:color="?androidprv:attr/materialColorSurfaceContainerHigh" />
+        android:color="@androidprv:color/materialColorSurfaceContainerHigh" />
 
     <corners android:radius="16dp" />
 </shape>
diff --git a/java/res/drawable/chooser_row_layer_list.xml b/java/res/drawable/chooser_row_layer_list.xml
index 868ac8aa..2f1e2046 100644
--- a/java/res/drawable/chooser_row_layer_list.xml
+++ b/java/res/drawable/chooser_row_layer_list.xml
@@ -20,7 +20,7 @@
             xmlns:androidprv="http://schemas.android.com/apk/prv/res/android">
     <item>
         <shape android:shape="rectangle">
-            <solid android:color="?androidprv:attr/materialColorSecondary"/>
+            <solid android:color="@androidprv:color/materialColorSecondary"/>
             <size android:width="128dp" android:height="2dp"/>
             <corners android:radius="2dp" />
         </shape>
diff --git a/java/res/drawable/edit_action_background.xml b/java/res/drawable/edit_action_background.xml
index 91726f49..ebc6d814 100644
--- a/java/res/drawable/edit_action_background.xml
+++ b/java/res/drawable/edit_action_background.xml
@@ -22,7 +22,7 @@
         <inset android:inset="8dp">
             <shape android:shape="rectangle">
                 <corners android:radius="12dp" />
-                <solid android:color="?androidprv:attr/materialColorSecondaryFixed"/>
+                <solid android:color="@androidprv:color/materialColorSecondaryFixed"/>
             </shape>
         </inset>
     </item>
diff --git a/java/res/drawable/ic_drag_handle.xml b/java/res/drawable/ic_drag_handle.xml
index f22e8c30..d6965209 100644
--- a/java/res/drawable/ic_drag_handle.xml
+++ b/java/res/drawable/ic_drag_handle.xml
@@ -17,6 +17,6 @@
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
     android:shape="rectangle" >
-    <solid android:color="?androidprv:attr/materialColorOutlineVariant" />
+    <solid android:color="@androidprv:color/materialColorOutlineVariant" />
     <corners android:radius="2dp" />
 </shape>
diff --git a/java/res/drawable/resolver_outlined_button_bg.xml b/java/res/drawable/resolver_outlined_button_bg.xml
index 3469a06e..b018624c 100644
--- a/java/res/drawable/resolver_outlined_button_bg.xml
+++ b/java/res/drawable/resolver_outlined_button_bg.xml
@@ -26,7 +26,7 @@
             <shape android:shape="rectangle">
                 <corners android:radius="8dp" />
                 <stroke android:width="1dp"
-                        android:color="?androidprv:attr/materialColorPrimaryContainer"/>
+                        android:color="@androidprv:color/materialColorPrimaryContainer"/>
             </shape>
         </inset>
     </item>
diff --git a/java/res/drawable/resolver_profile_tab_bg.xml b/java/res/drawable/resolver_profile_tab_bg.xml
index 97f3b7e2..20f0be92 100644
--- a/java/res/drawable/resolver_profile_tab_bg.xml
+++ b/java/res/drawable/resolver_profile_tab_bg.xml
@@ -29,14 +29,14 @@
             <item android:state_selected="false">
                 <shape android:shape="rectangle">
                     <corners android:radius="12dp" />
-                    <solid android:color="?androidprv:attr/materialColorSurfaceContainerHighest" />
+                    <solid android:color="@androidprv:color/materialColorSurfaceContainerHighest" />
                 </shape>
             </item>
 
             <item android:state_selected="true">
                 <shape android:shape="rectangle">
                     <corners android:radius="12dp" />
-                    <solid android:color="?androidprv:attr/materialColorPrimary" />
+                    <solid android:color="@androidprv:color/materialColorPrimary" />
                 </shape>
             </item>
         </selector>
diff --git a/java/res/layout-h480dp/image_preview_image_item.xml b/java/res/layout-h480dp/image_preview_image_item.xml
index ac63b2d5..47dc7012 100644
--- a/java/res/layout-h480dp/image_preview_image_item.xml
+++ b/java/res/layout-h480dp/image_preview_image_item.xml
@@ -61,7 +61,7 @@
         app:layout_constraintEnd_toEndOf="parent"
         app:layout_constraintBottom_toBottomOf="parent"
         android:background="@drawable/edit_action_background"
-        android:drawableTint="?androidprv:attr/materialColorSecondaryFixed"
+        android:drawableTint="@androidprv:color/materialColorSecondaryFixed"
         android:contentDescription="@string/screenshot_edit"
         android:visibility="gone"
         >
@@ -70,7 +70,7 @@
             android:layout_height="wrap_content"
             android:layout_gravity="center"
             android:padding="4dp"
-            android:tint="?androidprv:attr/materialColorOnSecondaryFixed"
+            android:tint="@androidprv:color/materialColorOnSecondaryFixed"
             android:src="@androidprv:drawable/ic_screenshot_edit"
             />
     </FrameLayout>
diff --git a/java/res/layout-h480dp/image_preview_loading_item.xml b/java/res/layout-h480dp/image_preview_loading_item.xml
index 85020e9a..0bc2656f 100644
--- a/java/res/layout-h480dp/image_preview_loading_item.xml
+++ b/java/res/layout-h480dp/image_preview_loading_item.xml
@@ -26,7 +26,7 @@
         android:layout_height="wrap_content"
         android:layout_gravity="center"
         android:indeterminate="true"
-        android:indeterminateTint="?androidprv:attr/materialColorPrimary"
+        android:indeterminateTint="@androidprv:color/materialColorPrimary"
         android:indeterminateTintMode="src_in" />
 
 </FrameLayout>
diff --git a/java/res/layout/chooser_action_row.xml b/java/res/layout/chooser_action_row.xml
index 7bce113e..9b39ba67 100644
--- a/java/res/layout/chooser_action_row.xml
+++ b/java/res/layout/chooser_action_row.xml
@@ -30,7 +30,7 @@
         android:layout_marginTop="8dp"
         android:layout_marginHorizontal="@dimen/chooser_edge_margin_normal"
         android:layout_marginBottom="10dp"
-        android:background="?androidprv:attr/materialColorSurfaceContainerHighest"
+        android:background="@androidprv:color/materialColorSurfaceContainerHighest"
     />
 </merge>
 
diff --git a/java/res/layout/chooser_action_view.xml b/java/res/layout/chooser_action_view.xml
index 6177821a..57cc59b7 100644
--- a/java/res/layout/chooser_action_view.xml
+++ b/java/res/layout/chooser_action_view.xml
@@ -14,7 +14,7 @@
   ~ limitations under the License
   -->
 
-<TextView xmlns:android="http://schemas.android.com/apk/res/android"
+<Button xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
     style="?android:attr/borderlessButtonStyle"
     android:background="@drawable/chooser_action_button_bg"
@@ -22,10 +22,10 @@
     android:paddingHorizontal="@dimen/chooser_edge_margin_normal_half"
     android:clickable="true"
     android:drawablePadding="6dp"
-    android:drawableTint="?androidprv:attr/materialColorOnSurface"
+    android:drawableTint="@androidprv:color/materialColorOnSurface"
     android:drawableTintMode="src_in"
     android:ellipsize="end"
     android:gravity="center"
     android:maxLines="1"
-    android:textColor="?androidprv:attr/materialColorOnSurface"
+    android:textColor="@androidprv:color/materialColorOnSurface"
     android:textSize="@dimen/chooser_action_view_text_size" />
diff --git a/java/res/layout/chooser_grid_item.xml b/java/res/layout/chooser_grid_item.xml
index 547a9944..76d2e60f 100644
--- a/java/res/layout/chooser_grid_item.xml
+++ b/java/res/layout/chooser_grid_item.xml
@@ -50,7 +50,7 @@
               android:layout_width="match_parent"
               android:layout_height="wrap_content"
               android:textAppearance="?android:attr/textAppearanceSmall"
-              android:textColor="?androidprv:attr/materialColorOnSurface"
+              android:textColor="@androidprv:color/materialColorOnSurface"
               android:textSize="@dimen/chooser_grid_target_name_text_size"
               android:maxLines="1"
               android:ellipsize="end" />
@@ -59,7 +59,7 @@
     <TextView android:id="@android:id/text2"
               android:textAppearance="?android:attr/textAppearanceSmall"
               android:textSize="@dimen/chooser_grid_activity_name_text_size"
-              android:textColor="?androidprv:attr/materialColorOnSurfaceVariant"
+              android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
               android:layout_width="match_parent"
               android:layout_height="wrap_content"
               android:lines="1"
diff --git a/java/res/layout/chooser_grid_item_hover.xml b/java/res/layout/chooser_grid_item_hover.xml
new file mode 100644
index 00000000..5e49c9fd
--- /dev/null
+++ b/java/res/layout/chooser_grid_item_hover.xml
@@ -0,0 +1,72 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+/*
+** Copyright 2006, The Android Open Source Project
+**
+** Licensed under the Apache License, Version 2.0 (the "License");
+** you may not use this file except in compliance with the License.
+** You may obtain a copy of the License at
+**
+**     http://www.apache.org/licenses/LICENSE-2.0
+**
+** Unless required by applicable law or agreed to in writing, software
+** distributed under the License is distributed on an "AS IS" BASIS,
+** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+** See the License for the specific language governing permissions and
+** limitations under the License.
+*/
+-->
+<com.android.intentresolver.widget.ChooserTargetItemView
+              xmlns:android="http://schemas.android.com/apk/res/android"
+              xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
+              xmlns:app="http://schemas.android.com/apk/res-auto"
+              android:id="@androidprv:id/item"
+              android:orientation="vertical"
+              android:layout_width="match_parent"
+              android:layout_height="wrap_content"
+              android:minHeight="100dp"
+              android:gravity="top|center_horizontal"
+              android:paddingVertical="1dp"
+              android:paddingHorizontal="4dp"
+              android:focusable="true"
+              android:defaultFocusHighlightEnabled="false"
+              app:focusOutlineWidth="@dimen/chooser_item_focus_outline_width"
+              app:focusOutlineCornerRadius="@dimen/chooser_item_focus_outline_corner_radius"
+              app:focusOutlineColor="@androidprv:color/materialColorSecondaryFixed"
+              app:focusInnerOutlineColor="@androidprv:color/materialColorOnSecondaryFixedVariant">
+
+    <ImageView android:id="@android:id/icon"
+               android:layout_width="@dimen/chooser_icon_width_with_padding"
+               android:layout_height="@dimen/chooser_icon_height_with_padding"
+               android:paddingHorizontal="@dimen/chooser_icon_horizontal_padding"
+               android:paddingBottom="@dimen/chooser_icon_vertical_padding"
+               android:scaleType="fitCenter" />
+
+    <!-- NOTE: for id/text1 and id/text2 below set the width to match parent as a workaround for
+         b/269395540 i.e. prevent views bounds change during a transition animation. It does not
+         affect pinned views as we change their layout parameters programmatically (but that's even
+         more narrow possibility and it's not clear if the root cause or the bug would affect it).
+    -->
+    <!-- App name or Direct Share target name, DS set to 2 lines -->
+    <com.android.intentresolver.widget.BadgeTextView
+              android:id="@android:id/text1"
+              android:layout_width="match_parent"
+              android:layout_height="wrap_content"
+              android:textAppearance="?android:attr/textAppearanceSmall"
+              android:textColor="@androidprv:color/materialColorOnSurface"
+              android:textSize="@dimen/chooser_grid_target_name_text_size"
+              android:maxLines="1"
+              android:ellipsize="end" />
+
+    <!-- Activity name if set, gone for Direct Share targets -->
+    <TextView android:id="@android:id/text2"
+              android:textAppearance="?android:attr/textAppearanceSmall"
+              android:textSize="@dimen/chooser_grid_activity_name_text_size"
+              android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
+              android:layout_width="match_parent"
+              android:layout_height="wrap_content"
+              android:lines="1"
+              android:gravity="top|center_horizontal"
+              android:ellipsize="end"/>
+
+</com.android.intentresolver.widget.ChooserTargetItemView>
diff --git a/java/res/layout/chooser_grid_preview_file.xml b/java/res/layout/chooser_grid_preview_file.xml
index 4e8cf7ba..9584ec9a 100644
--- a/java/res/layout/chooser_grid_preview_file.xml
+++ b/java/res/layout/chooser_grid_preview_file.xml
@@ -24,7 +24,7 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
-    android:background="?androidprv:attr/materialColorSurfaceContainer">
+    android:background="@androidprv:color/materialColorSurfaceContainer">
 
     <RelativeLayout
         android:layout_width="match_parent"
@@ -63,7 +63,7 @@
                 android:gravity="start|top"
                 android:singleLine="true"
                 android:textStyle="bold"
-                android:textColor="?androidprv:attr/materialColorOnSurface"
+                android:textColor="@androidprv:color/materialColorOnSurface"
                 android:textSize="12sp"
                 android:lineHeight="16sp"
                 android:textAppearance="@style/TextAppearance.ChooserDefault"/>
@@ -74,7 +74,7 @@
                 android:layout_height="wrap_content"
                 android:gravity="start|top"
                 android:singleLine="true"
-                android:textColor="?androidprv:attr/materialColorOnSurfaceVariant"
+                android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
                 android:textSize="12sp"
                 android:lineHeight="16sp"
                 android:textAppearance="@style/TextAppearance.ChooserDefault"/>
diff --git a/java/res/layout/chooser_grid_preview_files_text.xml b/java/res/layout/chooser_grid_preview_files_text.xml
index 65c62f82..9e2bde67 100644
--- a/java/res/layout/chooser_grid_preview_files_text.xml
+++ b/java/res/layout/chooser_grid_preview_files_text.xml
@@ -23,7 +23,7 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
-    android:background="?androidprv:attr/materialColorSurfaceContainer">
+    android:background="@androidprv:color/materialColorSurfaceContainer">
 
     <LinearLayout
         android:layout_width="match_parent"
@@ -53,7 +53,7 @@
             android:maxLines="@integer/text_preview_lines"
             android:ellipsize="end"
             android:linksClickable="false"
-            android:textColor="?androidprv:attr/materialColorOnSurfaceVariant"
+            android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
             android:textAppearance="@style/TextAppearance.ChooserDefault"/>
     </LinearLayout>
 
diff --git a/java/res/layout/chooser_grid_preview_image.xml b/java/res/layout/chooser_grid_preview_image.xml
index 4745e04c..199963b1 100644
--- a/java/res/layout/chooser_grid_preview_image.xml
+++ b/java/res/layout/chooser_grid_preview_image.xml
@@ -24,7 +24,7 @@
     android:layout_height="wrap_content"
     android:orientation="vertical"
     android:importantForAccessibility="no"
-    android:background="?androidprv:attr/materialColorSurfaceContainer">
+    android:background="@androidprv:color/materialColorSurfaceContainer">
 
     <ViewStub
         android:id="@+id/chooser_headline_row_stub"
@@ -41,7 +41,8 @@
         android:layout_gravity="center_horizontal"
         android:layout_marginBottom="8dp"
         app:itemInnerSpacing="3dp"
-        app:itemOuterSpacing="@dimen/chooser_edge_margin_normal"/>
+        app:itemOuterSpacing="@dimen/chooser_edge_margin_normal"
+        app:editButtonRoleDescription="@string/role_description_button"/>
 
     <include layout="@layout/chooser_action_row"/>
 </LinearLayout>
diff --git a/java/res/layout/chooser_grid_preview_text.xml b/java/res/layout/chooser_grid_preview_text.xml
index ee54c0ae..951abfc7 100644
--- a/java/res/layout/chooser_grid_preview_text.xml
+++ b/java/res/layout/chooser_grid_preview_text.xml
@@ -25,7 +25,7 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
-    android:background="?androidprv:attr/materialColorSurfaceContainer">
+    android:background="@androidprv:color/materialColorSurfaceContainer">
 
   <androidx.constraintlayout.widget.ConstraintLayout
       android:layout_width="match_parent"
@@ -67,7 +67,7 @@
         android:textAlignment="gravity"
         android:textDirection="locale"
         android:textStyle="bold"
-        android:textColor="?androidprv:attr/materialColorOnSurface"
+        android:textColor="@androidprv:color/materialColorOnSurface"
         android:fontFamily="@androidprv:string/config_headlineFontFamily"/>
 
     <TextView
@@ -82,7 +82,7 @@
         app:layout_goneMarginStart="0dp"
         android:ellipsize="end"
         android:fontFamily="@androidprv:string/config_headlineFontFamily"
-        android:textColor="?androidprv:attr/materialColorOnSurfaceVariant"
+        android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
         android:textAlignment="gravity"
         android:textDirection="locale"
         android:maxLines="@integer/text_preview_lines"
@@ -105,7 +105,7 @@
           android:layout_width="wrap_content"
           android:layout_height="wrap_content"
           android:layout_gravity="center"
-          android:tint="?androidprv:attr/materialColorOnSurfaceVariant"
+          android:tint="@androidprv:color/materialColorOnSurfaceVariant"
           android:src="@androidprv:drawable/ic_menu_copy_material"
           />
     </FrameLayout>
diff --git a/java/res/layout/chooser_grid_scrollable_preview.xml b/java/res/layout/chooser_grid_scrollable_preview.xml
index c1bcf912..f8c7a541 100644
--- a/java/res/layout/chooser_grid_scrollable_preview.xml
+++ b/java/res/layout/chooser_grid_scrollable_preview.xml
@@ -65,7 +65,7 @@
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
         app:layout_alwaysShow="true"
-        android:background="?androidprv:attr/materialColorSurfaceContainer">
+        android:background="@androidprv:color/materialColorSurfaceContainer">
 
         <ViewStub
             android:id="@+id/chooser_headline_row_stub"
@@ -78,6 +78,7 @@
     </FrameLayout>
 
     <com.android.intentresolver.widget.ChooserNestedScrollView
+        android:id="@+id/chooser_scrollable_container"
         android:layout_width="match_parent"
         android:layout_height="wrap_content">
 
@@ -98,7 +99,7 @@
                 android:layout_height="wrap_content"
                 android:layout_alignParentTop="true"
                 android:layout_centerHorizontal="true"
-                android:background="?androidprv:attr/materialColorSurfaceContainer">
+                android:background="@androidprv:color/materialColorSurfaceContainer">
                 <LinearLayout
                     android:orientation="vertical"
                     android:layout_width="match_parent"
diff --git a/java/res/layout/chooser_headline_row.xml b/java/res/layout/chooser_headline_row.xml
index 01be653f..1c8a0ac9 100644
--- a/java/res/layout/chooser_headline_row.xml
+++ b/java/res/layout/chooser_headline_row.xml
@@ -60,7 +60,7 @@
         app:barrierDirection="start"
         app:constraint_referenced_ids="reselection_action,include_text_action" />
 
-    <TextView
+    <Button
         android:id="@+id/reselection_action"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
@@ -74,7 +74,7 @@
         android:paddingHorizontal="@dimen/chooser_edge_margin_normal_half"
         style="?android:attr/borderlessButtonStyle"
         android:drawableEnd="@drawable/chevron_right"
-        android:textColor="?androidprv:attr/materialColorOnSurface"
+        android:textColor="@androidprv:color/materialColorOnSurface"
         android:textSize="12sp"
         />
 
@@ -90,7 +90,7 @@
         app:layout_constraintEnd_toEndOf="parent"
         app:layout_constraintTop_toBottomOf="@id/reselection_action"
         android:layout_alignWithParentIfMissing="true"
-        android:textColor="?androidprv:attr/materialColorOnSurface"
+        android:textColor="@androidprv:color/materialColorOnSurface"
         android:visibility="gone" />
 
 </androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/java/res/layout/chooser_list_per_profile_wrap.xml b/java/res/layout/chooser_list_per_profile_wrap.xml
index fc0431d7..e556bc94 100644
--- a/java/res/layout/chooser_list_per_profile_wrap.xml
+++ b/java/res/layout/chooser_list_per_profile_wrap.xml
@@ -18,14 +18,7 @@
     xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
     android:layout_width="match_parent"
-    android:layout_height="wrap_content"
-    android:descendantFocusability="blocksDescendants">
-    <!--    ^^^ Block descendants from receiving focus to prevent NestedScrollView
-    (ChooserNestedScrollView) scrolling to the focused view when switching tabs. Without it, TabHost
-    view will request focus on the newly activated tab. The RecyclerView from this layout gets
-    focused and  notifies its parents (including NestedScrollView) about it through
-    #requestChildFocus method call. NestedScrollView's view implementation of the method  will
-    scroll to the focused view. -->
+    android:layout_height="wrap_content">
 
     <androidx.recyclerview.widget.RecyclerView
         android:layout_width="match_parent"
@@ -33,7 +26,7 @@
         app:layoutManager="com.android.intentresolver.ChooserGridLayoutManager"
         android:id="@androidprv:id/resolver_list"
         android:clipToPadding="false"
-        android:background="?androidprv:attr/materialColorSurfaceContainer"
+        android:background="@androidprv:color/materialColorSurfaceContainer"
         android:scrollbars="none"
         android:nestedScrollingEnabled="true" />
 
diff --git a/java/res/layout/chooser_row.xml b/java/res/layout/chooser_row.xml
index 4a5e28c3..bbe65a85 100644
--- a/java/res/layout/chooser_row.xml
+++ b/java/res/layout/chooser_row.xml
@@ -28,7 +28,7 @@
       android:layout_height="wrap_content"
       android:gravity="center"
       android:layout_gravity="center"
-      android:textColor="?androidprv:attr/materialColorOnSurfaceVariant"
+      android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
       android:visibility="gone" />
 </LinearLayout>
 
diff --git a/java/res/layout/image_preview_loading_item.xml b/java/res/layout/image_preview_loading_item.xml
index a8a8f264..edcfb3d1 100644
--- a/java/res/layout/image_preview_loading_item.xml
+++ b/java/res/layout/image_preview_loading_item.xml
@@ -27,7 +27,7 @@
         android:layout_height="wrap_content"
         android:layout_gravity="center"
         android:indeterminate="true"
-        android:indeterminateTint="?androidprv:attr/materialColorPrimary"
+        android:indeterminateTint="@androidprv:color/materialColorPrimary"
         android:indeterminateTintMode="src_in" />
 
 </FrameLayout>
diff --git a/java/res/layout/resolve_grid_item.xml b/java/res/layout/resolve_grid_item.xml
index e5a00429..f9d433de 100644
--- a/java/res/layout/resolve_grid_item.xml
+++ b/java/res/layout/resolve_grid_item.xml
@@ -49,7 +49,7 @@
               android:layout_width="match_parent"
               android:layout_height="wrap_content"
               android:textAppearance="?android:attr/textAppearanceSmall"
-              android:textColor="?androidprv:attr/materialColorOnSurface"
+              android:textColor="@androidprv:color/materialColorOnSurface"
               android:textSize="@dimen/chooser_grid_target_name_text_size"
               android:gravity="top|center_horizontal"
               android:maxLines="1"
@@ -59,7 +59,7 @@
     <TextView android:id="@android:id/text2"
               android:textAppearance="?android:attr/textAppearanceSmall"
               android:textSize="@dimen/chooser_grid_activity_name_text_size"
-              android:textColor="?androidprv:attr/materialColorOnSurfaceVariant"
+              android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
               android:layout_width="match_parent"
               android:layout_height="wrap_content"
               android:lines="1"
diff --git a/java/res/layout/resolver_empty_states.xml b/java/res/layout/resolver_empty_states.xml
index 0cf6e955..4dac23ab 100644
--- a/java/res/layout/resolver_empty_states.xml
+++ b/java/res/layout/resolver_empty_states.xml
@@ -84,7 +84,7 @@
             android:layout_width="match_parent"
             android:layout_height="wrap_content"
             android:text="@string/noApplications"
-            android:textColor="?androidprv:attr/materialColorOnSurfaceVariant"
+            android:textColor="@androidprv:color/materialColorOnSurfaceVariant"
             android:padding="@dimen/chooser_edge_margin_normal"
             android:gravity="center"/>
     </RelativeLayout>
diff --git a/java/res/values-af/strings.xml b/java/res/values-af/strings.xml
index 55d84dfa..a0b78850 100644
--- a/java/res/values-af/strings.xml
+++ b/java/res/values-af/strings.xml
@@ -36,17 +36,17 @@
     <string name="whichSendToApplication" msgid="2724450540348806267">"Stuur met"</string>
     <string name="whichSendToApplicationNamed" msgid="1996548940365954543">"Stuur met <xliff:g id="APP">%1$s</xliff:g>"</string>
     <string name="whichSendToApplicationLabel" msgid="6909037198280591110">"Stuur"</string>
-    <string name="whichHomeApplication" msgid="8797832422254564739">"Kies \'n Tuis-program"</string>
+    <string name="whichHomeApplication" msgid="8797832422254564739">"Kies \'n Tuis-app"</string>
     <string name="whichHomeApplicationNamed" msgid="3943122502791761387">"Gebruik <xliff:g id="APP">%1$s</xliff:g> as Tuis"</string>
     <string name="whichHomeApplicationLabel" msgid="2066319585322981524">"Vang prent vas"</string>
     <string name="whichImageCaptureApplication" msgid="7830965894804399333">"Vang prent vas met"</string>
     <string name="whichImageCaptureApplicationNamed" msgid="5927801386307049780">"Vang prent vas met <xliff:g id="APP">%1$s</xliff:g>"</string>
     <string name="whichImageCaptureApplicationLabel" msgid="987153638235357094">"Vang prent vas"</string>
-    <string name="use_a_different_app" msgid="2062380818535918975">"Gebruik \'n ander program"</string>
+    <string name="use_a_different_app" msgid="2062380818535918975">"Gebruik ’n ander app"</string>
     <string name="chooseActivity" msgid="6659724877523973446">"Kies \'n handeling"</string>
     <string name="noApplications" msgid="1139487441772284671">"Geen programme kan hierdie handeling uitvoer nie."</string>
-    <string name="forward_intent_to_owner" msgid="6454987608971162379">"Jy gebruik hierdie program buite jou werkprofiel"</string>
-    <string name="forward_intent_to_work" msgid="2906094223089139419">"Jy gebruik tans hierdie program in jou werkprofiel"</string>
+    <string name="forward_intent_to_owner" msgid="6454987608971162379">"Jy gebruik hierdie app buite jou werkprofiel"</string>
+    <string name="forward_intent_to_work" msgid="2906094223089139419">"Jy gebruik tans hierdie app in jou werkprofiel"</string>
     <string name="activity_resolver_use_always" msgid="8674194687637555245">"Altyd"</string>
     <string name="activity_resolver_use_once" msgid="594173435998892989">"Net een keer"</string>
     <string name="activity_resolver_work_profiles_support" msgid="8228711455685203580">"<xliff:g id="APP">%1$s</xliff:g> steun nie werkprofiel nie"</string>
@@ -75,7 +75,7 @@
     <string name="video_preview_a11y_description" msgid="683440858811095990">"Videovoorskouminiprent"</string>
     <string name="file_preview_a11y_description" msgid="7397224827802410602">"Lêervoorskouminiprent"</string>
     <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"Geen mense om mee te deel is aanbeveel nie"</string>
-    <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"Opneemtoestemming is nie aan hierdie program verleen nie, maar dit kan oudio deur hierdie USB-toestel opneem."</string>
+    <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"Opneemtoestemming is nie aan hierdie app verleen nie, maar dit kan oudio deur hierdie USB-toestel opneem."</string>
     <string name="resolver_personal_tab" msgid="1381052735324320565">"Persoonlik"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"Werk"</string>
     <string name="resolver_private_tab" msgid="3707548826254095157">"Privaat"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Kiesbare prent"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Kiesbare video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Kiesbare item"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Knoppie"</string>
 </resources>
diff --git a/java/res/values-am/strings.xml b/java/res/values-am/strings.xml
index a7b5922b..d46f88d1 100644
--- a/java/res/values-am/strings.xml
+++ b/java/res/values-am/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"ሊመረጥ የሚችል ምስል"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ሊመረጥ የሚችል ቪድዮ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ሊመረጥ የሚችል ንጥል"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"አዝራር"</string>
 </resources>
diff --git a/java/res/values-ar/strings.xml b/java/res/values-ar/strings.xml
index 49769c57..278e03f2 100644
--- a/java/res/values-ar/strings.xml
+++ b/java/res/values-ar/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"صورة يمكن اختيارها"</string>
     <string name="selectable_video" msgid="1271768647699300826">"فيديو يمكن اختياره"</string>
     <string name="selectable_item" msgid="7557320816744205280">"عنصر يمكن اختياره"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"زرّ"</string>
 </resources>
diff --git a/java/res/values-as/strings.xml b/java/res/values-as/strings.xml
index 1983e4fe..2177c527 100644
--- a/java/res/values-as/strings.xml
+++ b/java/res/values-as/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"বাছনি কৰিব পৰা প্ৰতিচ্ছবি"</string>
     <string name="selectable_video" msgid="1271768647699300826">"বাছনি কৰিব পৰা ভিডিঅ’"</string>
     <string name="selectable_item" msgid="7557320816744205280">"বাছনি কৰিব পৰা বস্তু"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"বুটাম"</string>
 </resources>
diff --git a/java/res/values-az/strings.xml b/java/res/values-az/strings.xml
index c5674b86..93086938 100644
--- a/java/res/values-az/strings.xml
+++ b/java/res/values-az/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Seçilə bilən şəkil"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Seçilə bilən video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Seçilə bilən element"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Düymə"</string>
 </resources>
diff --git a/java/res/values-b+sr+Latn/strings.xml b/java/res/values-b+sr+Latn/strings.xml
index 6d9dbd87..86fc1854 100644
--- a/java/res/values-b+sr+Latn/strings.xml
+++ b/java/res/values-b+sr+Latn/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Slika koja može da se izabere"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video koji može da se izabere"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Stavka koja može da se izabere"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Dugme"</string>
 </resources>
diff --git a/java/res/values-be/strings.xml b/java/res/values-be/strings.xml
index 2724855b..97ca27d3 100644
--- a/java/res/values-be/strings.xml
+++ b/java/res/values-be/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Відарыс, які можна выбраць"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Відэа, якое можна выбраць"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Элемент, які можна выбраць"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Кнопка"</string>
 </resources>
diff --git a/java/res/values-bg/strings.xml b/java/res/values-bg/strings.xml
index 450712b1..3cec0cdf 100644
--- a/java/res/values-bg/strings.xml
+++ b/java/res/values-bg/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # файл}other{+ # файла}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ още # файл}other{+ още # файла}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Текстът се споделя"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Връзката се споделя"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Споделяне на връзката"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Изображението се споделя}other{# изображения се споделят}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Видеоклипът се споделя}other{# видеоклипа се споделят}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# файл се споделя}other{# файла се споделят}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Избираемо изображение"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Избираем видеоклип"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Избираем елемент"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Бутон"</string>
 </resources>
diff --git a/java/res/values-bn/strings.xml b/java/res/values-bn/strings.xml
index 2d33eb29..ea524006 100644
--- a/java/res/values-bn/strings.xml
+++ b/java/res/values-bn/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{আরও #টি ফাইল}one{আরও #টি ফাইল}other{আরও #টি ফাইল}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{আরও #টি ফাইল}one{আরও #টি ফাইল}other{আরও #টি ফাইল}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"টেক্সট শেয়ার করা হচ্ছে"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"শেয়ার করা লিঙ্ক"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"শেয়ার করার জন্য লিঙ্ক"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ছবি শেয়ার করা হচ্ছে}one{#টি ছবি শেয়ার করা হচ্ছে}other{#টি ছবি শেয়ার করা হচ্ছে}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ভিডিও শেয়ার করা হচ্ছে}one{#টি ভিডিও শেয়ার করা হচ্ছে}other{#টি ভিডিও শেয়ার করা হচ্ছে}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{#টি ফাইল শেয়ার করা হচ্ছে}one{#টি ফাইল শেয়ার করা হচ্ছে}other{#টি ফাইল শেয়ার করা হচ্ছে}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"বেছে নেওয়া যাবে এমন ছবি"</string>
     <string name="selectable_video" msgid="1271768647699300826">"বেছে নেওয়া যাবে এমন ভিডিও"</string>
     <string name="selectable_item" msgid="7557320816744205280">"বেছে নেওয়া যাবে এমন আইটেম"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"বোতাম"</string>
 </resources>
diff --git a/java/res/values-bs/strings.xml b/java/res/values-bs/strings.xml
index 10335fab..ddf3119b 100644
--- a/java/res/values-bs/strings.xml
+++ b/java/res/values-bs/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Slika koju je moguće odabrati"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Videozapis koji je moguće odabrati"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Stavka koju je moguće odabrati"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Dugme"</string>
 </resources>
diff --git a/java/res/values-ca/strings.xml b/java/res/values-ca/strings.xml
index 11029365..48d7138f 100644
--- a/java/res/values-ca/strings.xml
+++ b/java/res/values-ca/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Imatge seleccionable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo seleccionable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Element seleccionable"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Botó"</string>
 </resources>
diff --git a/java/res/values-cs/strings.xml b/java/res/values-cs/strings.xml
index 0ce7e140..151e2147 100644
--- a/java/res/values-cs/strings.xml
+++ b/java/res/values-cs/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Vybratelný obrázek"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vybratelné video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Vybratelná položka"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Tlačítko"</string>
 </resources>
diff --git a/java/res/values-da/strings.xml b/java/res/values-da/strings.xml
index 3a3e2062..e9d952fe 100644
--- a/java/res/values-da/strings.xml
+++ b/java/res/values-da/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Billede, der kan vælges"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video, der kan vælges"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Element, der kan vælges"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Knap"</string>
 </resources>
diff --git a/java/res/values-de/strings.xml b/java/res/values-de/strings.xml
index 3a561101..911dd273 100644
--- a/java/res/values-de/strings.xml
+++ b/java/res/values-de/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Auswählbares Bild"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Auswählbares Video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Auswählbares Element"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Schaltfläche"</string>
 </resources>
diff --git a/java/res/values-el/strings.xml b/java/res/values-el/strings.xml
index 8903eec1..319a3e2c 100644
--- a/java/res/values-el/strings.xml
+++ b/java/res/values-el/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Εικόνα με δυνατότητα επιλογής"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Βίντεο με δυνατότητα επιλογής"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Στοιχείο με δυνατότητα επιλογής"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Κουμπί"</string>
 </resources>
diff --git a/java/res/values-en-rAU/strings.xml b/java/res/values-en-rAU/strings.xml
index 53e64659..4d16a6f4 100644
--- a/java/res/values-en-rAU/strings.xml
+++ b/java/res/values-en-rAU/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Selectable image"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Selectable video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Selectable item"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Button"</string>
 </resources>
diff --git a/java/res/values-en-rCA/strings.xml b/java/res/values-en-rCA/strings.xml
index 1c44b945..9f6d20c3 100644
--- a/java/res/values-en-rCA/strings.xml
+++ b/java/res/values-en-rCA/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Selectable image"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Selectable video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Selectable item"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Button"</string>
 </resources>
diff --git a/java/res/values-en-rGB/strings.xml b/java/res/values-en-rGB/strings.xml
index 53e64659..4d16a6f4 100644
--- a/java/res/values-en-rGB/strings.xml
+++ b/java/res/values-en-rGB/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Selectable image"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Selectable video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Selectable item"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Button"</string>
 </resources>
diff --git a/java/res/values-en-rIN/strings.xml b/java/res/values-en-rIN/strings.xml
index 53e64659..4d16a6f4 100644
--- a/java/res/values-en-rIN/strings.xml
+++ b/java/res/values-en-rIN/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Selectable image"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Selectable video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Selectable item"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Button"</string>
 </resources>
diff --git a/java/res/values-es-rUS/strings.xml b/java/res/values-es-rUS/strings.xml
index f3b7fe85..923e9d36 100644
--- a/java/res/values-es-rUS/strings.xml
+++ b/java/res/values-es-rUS/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Imagen seleccionable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video seleccionable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Elemento seleccionable"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Botón"</string>
 </resources>
diff --git a/java/res/values-es/strings.xml b/java/res/values-es/strings.xml
index 460de896..7cb07c61 100644
--- a/java/res/values-es/strings.xml
+++ b/java/res/values-es/strings.xml
@@ -55,7 +55,7 @@
     <string name="screenshot_edit" msgid="3857183660047569146">"Editar"</string>
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # archivo}many{+ # archivos}other{+ # archivos}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{y # archivo más}many{y # archivos más}other{y # archivos más}}"</string>
-    <string name="sharing_text" msgid="8137537443603304062">"Compartiendo texto"</string>
+    <string name="sharing_text" msgid="8137537443603304062">"Compartir texto"</string>
     <string name="sharing_link" msgid="2307694372813942916">"Compartiendo enlace"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Compartiendo imagen}many{Compartiendo # imágenes}other{Compartiendo # imágenes}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Compartiendo vídeo}many{Compartiendo # vídeos}other{Compartiendo # vídeos}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Imagen seleccionable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo seleccionable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Elemento seleccionable"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Botón"</string>
 </resources>
diff --git a/java/res/values-et/strings.xml b/java/res/values-et/strings.xml
index 85fca08f..6a17f5b3 100644
--- a/java/res/values-et/strings.xml
+++ b/java/res/values-et/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Valitav pilt"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Valitav video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Valitav üksus"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Nupp"</string>
 </resources>
diff --git a/java/res/values-eu/strings.xml b/java/res/values-eu/strings.xml
index 5020f62d..e80edad4 100644
--- a/java/res/values-eu/strings.xml
+++ b/java/res/values-eu/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Hauta daitekeen irudia"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Hauta daitekeen bideoa"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Hauta daitekeen elementua"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Botoia"</string>
 </resources>
diff --git a/java/res/values-fa/strings.xml b/java/res/values-fa/strings.xml
index 7b3dc6ea..71386d35 100644
--- a/java/res/values-fa/strings.xml
+++ b/java/res/values-fa/strings.xml
@@ -74,7 +74,7 @@
     <string name="image_preview_a11y_description" msgid="297102643932491797">"ریزعکس پیش‌نمای تصویر"</string>
     <string name="video_preview_a11y_description" msgid="683440858811095990">"ریزعکس پیش‌نمای ویدیو"</string>
     <string name="file_preview_a11y_description" msgid="7397224827802410602">"ریزعکس پیش‌نمای فایل"</string>
-    <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"هیچ فردی که با او هم‌رسانی کنید توصیه نشده است"</string>
+    <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"هیچ فرد توصیه‌شده‌ای برای هم‌رسانی وجود ندارد"</string>
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"‏مجوز ضبط به این برنامه داده نشده است اما می‌تواند صدا را ازطریق این دستگاه USB ضبط کند."</string>
     <string name="resolver_personal_tab" msgid="1381052735324320565">"شخصی"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"کاری"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"تصویر قابل‌انتخاب"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ویدیو قابل‌انتخاب"</string>
     <string name="selectable_item" msgid="7557320816744205280">"مورد قابل‌انتخاب"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"دکمه"</string>
 </resources>
diff --git a/java/res/values-fi/strings.xml b/java/res/values-fi/strings.xml
index 65244293..6938d4fa 100644
--- a/java/res/values-fi/strings.xml
+++ b/java/res/values-fi/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Valittava kuva"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Valittava video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Valittava kohde"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Painike"</string>
 </resources>
diff --git a/java/res/values-fr-rCA/strings.xml b/java/res/values-fr-rCA/strings.xml
index b2ae5f5c..7fdda598 100644
--- a/java/res/values-fr-rCA/strings.xml
+++ b/java/res/values-fr-rCA/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Image sélectionnable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vidéo sélectionnable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Élément sélectionnable"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Bouton"</string>
 </resources>
diff --git a/java/res/values-fr/strings.xml b/java/res/values-fr/strings.xml
index 2b96c92f..39d436a7 100644
--- a/java/res/values-fr/strings.xml
+++ b/java/res/values-fr/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Image sélectionnable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vidéo sélectionnable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Élément sélectionnable"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Bouton"</string>
 </resources>
diff --git a/java/res/values-gl/strings.xml b/java/res/values-gl/strings.xml
index a8caf6f3..d45e982e 100644
--- a/java/res/values-gl/strings.xml
+++ b/java/res/values-gl/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Imaxe seleccionable"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo seleccionable"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Elemento seleccionable"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Botón"</string>
 </resources>
diff --git a/java/res/values-gu/strings.xml b/java/res/values-gu/strings.xml
index a70a1b0f..d0e65a18 100644
--- a/java/res/values-gu/strings.xml
+++ b/java/res/values-gu/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"પસંદ કરી શકાય તેવી છબી"</string>
     <string name="selectable_video" msgid="1271768647699300826">"પસંદ કરી શકાય તેવો વીડિયો"</string>
     <string name="selectable_item" msgid="7557320816744205280">"પસંદ કરી શકાય તેવી આઇટમ"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"બટન"</string>
 </resources>
diff --git a/java/res/values-hi/strings.xml b/java/res/values-hi/strings.xml
index 3f6db1be..70da0c22 100644
--- a/java/res/values-hi/strings.xml
+++ b/java/res/values-hi/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"ऐसी इमेज जिसे चुना जा सकता है"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ऐसा वीडियो जिसे चुना जा सकता है"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ऐसा आइटम जिसे चुना जा सकता है"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"बटन"</string>
 </resources>
diff --git a/java/res/values-hr/strings.xml b/java/res/values-hr/strings.xml
index 85858303..c8f8c90d 100644
--- a/java/res/values-hr/strings.xml
+++ b/java/res/values-hr/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # datoteka}one{+ # datoteka}few{+ # datoteke}other{+ # datoteka}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{i još # datoteka}one{i još # datoteka}few{i još # datoteke}other{i još # datoteka}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Dijeli se tekst"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Dijeli se veza"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Veza za dijeljenje"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Podijelite sliku}one{Podijelite # sliku}few{Podijelite # slike}other{Podijelite # slika}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Dijeli se videozapis}one{Dijeli se # videozapis}few{Dijele se # videozapisa}other{Dijeli se # videozapisa}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Dijeli se # datoteka}one{Dijeli se # datoteka}few{Dijele se # datoteke}other{Dijeli se # datoteka}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Slika koja se može odabrati"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Videozapis koji se može odabrati"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Stavka koja se može odabrati"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Gumb"</string>
 </resources>
diff --git a/java/res/values-hu/strings.xml b/java/res/values-hu/strings.xml
index 792b07e2..a9e5e820 100644
--- a/java/res/values-hu/strings.xml
+++ b/java/res/values-hu/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Kijelölhető kép"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Kijelölhető videó"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Kijelölhető elem"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Gomb"</string>
 </resources>
diff --git a/java/res/values-hy/strings.xml b/java/res/values-hy/strings.xml
index f9232a5a..b0b0b235 100644
--- a/java/res/values-hy/strings.xml
+++ b/java/res/values-hy/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Ընտրելու հնարավորությամբ պատկեր"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Ընտրելու հնարավորությամբ տեսանյութ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Ընտրելու հնարավորությամբ տարր"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Կոճակ"</string>
 </resources>
diff --git a/java/res/values-in/strings.xml b/java/res/values-in/strings.xml
index df05fdd0..86828b7c 100644
--- a/java/res/values-in/strings.xml
+++ b/java/res/values-in/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Gambar yang dapat dipilih"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video yang dapat dipilih"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Item yang dapat dipilih"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Tombol"</string>
 </resources>
diff --git a/java/res/values-is/strings.xml b/java/res/values-is/strings.xml
index 680ed17a..9125bae9 100644
--- a/java/res/values-is/strings.xml
+++ b/java/res/values-is/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Mynd sem hægt er að velja"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeó sem hægt er að velja"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Atriði sem hægt er að velja"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Hnappur"</string>
 </resources>
diff --git a/java/res/values-it/strings.xml b/java/res/values-it/strings.xml
index 3762f58b..7d0a7fa7 100644
--- a/java/res/values-it/strings.xml
+++ b/java/res/values-it/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Immagine selezionabile"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video selezionabile"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Elemento selezionabile"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Pulsante"</string>
 </resources>
diff --git a/java/res/values-iw/strings.xml b/java/res/values-iw/strings.xml
index bed01ff0..43921c78 100644
--- a/java/res/values-iw/strings.xml
+++ b/java/res/values-iw/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"תמונה שניתן לבחור"</string>
     <string name="selectable_video" msgid="1271768647699300826">"סרטון שניתן לבחור"</string>
     <string name="selectable_item" msgid="7557320816744205280">"פריט שניתן לבחור"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"כפתור"</string>
 </resources>
diff --git a/java/res/values-ja/strings.xml b/java/res/values-ja/strings.xml
index 1d2a2f06..094106c3 100644
--- a/java/res/values-ja/strings.xml
+++ b/java/res/values-ja/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"選択可能な画像"</string>
     <string name="selectable_video" msgid="1271768647699300826">"選択可能な動画"</string>
     <string name="selectable_item" msgid="7557320816744205280">"選択可能なアイテム"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"ボタン"</string>
 </resources>
diff --git a/java/res/values-ka/strings.xml b/java/res/values-ka/strings.xml
index 4675734b..e0951e39 100644
--- a/java/res/values-ka/strings.xml
+++ b/java/res/values-ka/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"არჩევადი სურათი"</string>
     <string name="selectable_video" msgid="1271768647699300826">"არჩევადი ვიდეო"</string>
     <string name="selectable_item" msgid="7557320816744205280">"არჩევადი ერთეული"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"ღილაკი"</string>
 </resources>
diff --git a/java/res/values-kk/strings.xml b/java/res/values-kk/strings.xml
index 362db640..99357ef6 100644
--- a/java/res/values-kk/strings.xml
+++ b/java/res/values-kk/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Таңдауға болатын сурет"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Таңдауға болатын бейне"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Таңдауға болатын элемент"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Түйме"</string>
 </resources>
diff --git a/java/res/values-km/strings.xml b/java/res/values-km/strings.xml
index cee11e26..29d80e96 100644
--- a/java/res/values-km/strings.xml
+++ b/java/res/values-km/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"រូបភាពដែល​អាចជ្រើសរើសបាន"</string>
     <string name="selectable_video" msgid="1271768647699300826">"វីដេអូដែល​អាចជ្រើសរើសបាន"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ធាតុដែល​អាចជ្រើសរើសបាន"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"ប៊ូតុង"</string>
 </resources>
diff --git a/java/res/values-kn/strings.xml b/java/res/values-kn/strings.xml
index 35bf148c..d777b6fa 100644
--- a/java/res/values-kn/strings.xml
+++ b/java/res/values-kn/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # ಫೈಲ್‌}one{+ # ಫೈಲ್‌ಗಳು}other{+ # ಫೈಲ್‌ಗಳು}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ # ಇನ್ನಷ್ಟು ಫೈಲ್}one{+ # ಇನ್ನಷ್ಟು ಫೈಲ್‌ಗಳು}other{+ # ಇನ್ನಷ್ಟು ಫೈಲ್‌ಗಳು}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"ಪಠ್ಯ ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"ಲಿಂಕ್ ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"ಹಂಚಿಕೊಳ್ಳಬಹುದಾದ ಲಿಂಕ್"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{ಚಿತ್ರವನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}one{# ಚಿತ್ರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}other{# ಚಿತ್ರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{ವೀಡಿಯೊವನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}one{# ವೀಡಿಯೊಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}other{# ವೀಡಿಯೊಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# ಫೈಲ್ ಅನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}one{# ಫೈಲ್‌ಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}other{# ಫೈಲ್‌ಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಲಾಗುತ್ತಿದೆ}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"ಆಯ್ಕೆಮಾಡಬಹುದಾದ ಚಿತ್ರ"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ಆಯ್ಕೆ ಮಾಡಬಹುದಾದ ವೀಡಿಯೊ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ಆಯ್ಕೆ ಮಾಡಬಹುದಾದ ಐಟಂ"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"ಬಟನ್"</string>
 </resources>
diff --git a/java/res/values-ko/strings.xml b/java/res/values-ko/strings.xml
index 094f09b0..0ab0cefb 100644
--- a/java/res/values-ko/strings.xml
+++ b/java/res/values-ko/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"선택 가능한 이미지"</string>
     <string name="selectable_video" msgid="1271768647699300826">"선택 가능한 동영상"</string>
     <string name="selectable_item" msgid="7557320816744205280">"선택 가능한 항목"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"버튼"</string>
 </resources>
diff --git a/java/res/values-ky/strings.xml b/java/res/values-ky/strings.xml
index 610adaf2..7de1593d 100644
--- a/java/res/values-ky/strings.xml
+++ b/java/res/values-ky/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Тандала турган сүрөт"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Тандала турган видео"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Тандала турган нерсе"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Баскыч"</string>
 </resources>
diff --git a/java/res/values-lo/strings.xml b/java/res/values-lo/strings.xml
index 2cdea91f..9481a9ae 100644
--- a/java/res/values-lo/strings.xml
+++ b/java/res/values-lo/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"ຮູບທີ່ເລືອກໄດ້"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ວິດີໂອທີ່ເລືອກໄດ້"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ລາຍການທີ່ເລືອກໄດ້"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"ປຸ່ມ"</string>
 </resources>
diff --git a/java/res/values-lt/strings.xml b/java/res/values-lt/strings.xml
index 7b0c6695..f1a0494d 100644
--- a/java/res/values-lt/strings.xml
+++ b/java/res/values-lt/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Pasirenkamas vaizdas"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Pasirenkamas vaizdo įrašas"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Pasirenkamas elementas"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Mygtukas"</string>
 </resources>
diff --git a/java/res/values-lv/strings.xml b/java/res/values-lv/strings.xml
index 1c14c2b8..5fed4d43 100644
--- a/java/res/values-lv/strings.xml
+++ b/java/res/values-lv/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{un vēl # fails}zero{un vēl # faili}one{un vēl # fails}other{un vēl # faili}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{Un vēl # fails}zero{Un vēl # failu}one{Un vēl # fails}other{Un vēl # faili}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Tiek kopīgots teksts"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Tiek kopīgota saite"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Kopīgošanas saite"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Tiek kopīgots attēls}zero{Tiek kopīgoti # attēli}one{Tiek kopīgots # attēls}other{Tiek kopīgoti # attēli}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Tiek kopīgots video}zero{Tiek kopīgoti # video}one{Tiek kopīgots # video}other{Tiek kopīgoti # video}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Notiek # faila kopīgošana}zero{Notiek # failu kopīgošana}one{Notiek # faila kopīgošana}other{Notiek # failu kopīgošana}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Atlasāms attēls"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Atlasāms video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Atlasāms vienums"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Poga"</string>
 </resources>
diff --git a/java/res/values-mk/strings.xml b/java/res/values-mk/strings.xml
index 19ff3c67..2ab3c072 100644
--- a/java/res/values-mk/strings.xml
+++ b/java/res/values-mk/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Слика што може да се избере"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Видео што може да се избере"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Ставка што може да се избере"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Копче"</string>
 </resources>
diff --git a/java/res/values-ml/strings.xml b/java/res/values-ml/strings.xml
index bcd07dd7..6318a101 100644
--- a/java/res/values-ml/strings.xml
+++ b/java/res/values-ml/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"തിരഞ്ഞെടുക്കാവുന്ന ചിത്രം"</string>
     <string name="selectable_video" msgid="1271768647699300826">"തിരഞ്ഞെടുക്കാവുന്ന വീഡിയോ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"തിരഞ്ഞെടുക്കാവുന്ന ഇനം"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"ബട്ടൺ"</string>
 </resources>
diff --git a/java/res/values-mn/strings.xml b/java/res/values-mn/strings.xml
index 81d97d99..8dc3cd58 100644
--- a/java/res/values-mn/strings.xml
+++ b/java/res/values-mn/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Сонгох боломжтой зураг"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Сонгох боломжтой видео"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Сонгох боломжтой зүйл"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Товч"</string>
 </resources>
diff --git a/java/res/values-mr/strings.xml b/java/res/values-mr/strings.xml
index 4a061601..5e54a61a 100644
--- a/java/res/values-mr/strings.xml
+++ b/java/res/values-mr/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"निवडण्यायोग्य इमेज"</string>
     <string name="selectable_video" msgid="1271768647699300826">"निवडण्यायोग्य व्हिडिओ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"निवडण्यायोग्य आयटम"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"बटण"</string>
 </resources>
diff --git a/java/res/values-ms/strings.xml b/java/res/values-ms/strings.xml
index a01376c6..b6dca50f 100644
--- a/java/res/values-ms/strings.xml
+++ b/java/res/values-ms/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Imej yang boleh dipilih"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video yang boleh dipilih"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Item yang boleh dipilih"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Butang"</string>
 </resources>
diff --git a/java/res/values-my/strings.xml b/java/res/values-my/strings.xml
index 9eeda078..af596656 100644
--- a/java/res/values-my/strings.xml
+++ b/java/res/values-my/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"ရွေးချယ်နိုင်သောပုံ"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ရွေးချယ်နိုင်သော ဗီဒီယို"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ရွေးချယ်နိုင်သောအရာ"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"ခလုတ်"</string>
 </resources>
diff --git a/java/res/values-nb/strings.xml b/java/res/values-nb/strings.xml
index 7a67bc34..bd31a926 100644
--- a/java/res/values-nb/strings.xml
+++ b/java/res/values-nb/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Bilde som kan velges"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video som kan velges"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Element som kan velges"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Knapp"</string>
 </resources>
diff --git a/java/res/values-ne/strings.xml b/java/res/values-ne/strings.xml
index 76365455..620e402c 100644
--- a/java/res/values-ne/strings.xml
+++ b/java/res/values-ne/strings.xml
@@ -78,7 +78,7 @@
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"यो एपलाई रेकर्ड गर्ने अनुमति प्रदान गरिएको छैन तर यसले यो USB यन्त्रमार्फत अडियो क्याप्चर गर्न सक्छ।"</string>
     <string name="resolver_personal_tab" msgid="1381052735324320565">"व्यक्तिगत"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"काम"</string>
-    <string name="resolver_private_tab" msgid="3707548826254095157">"निजी"</string>
+    <string name="resolver_private_tab" msgid="3707548826254095157">"निजी स्पेस"</string>
     <string name="resolver_personal_tab_accessibility" msgid="4467784352232582574">"व्यक्तिगत दृश्य"</string>
     <string name="resolver_work_tab_accessibility" msgid="7581878836587799920">"कार्य दृश्य"</string>
     <string name="resolver_private_tab_accessibility" msgid="2513122834337197252">"निजी भ्यू"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"चयन गर्न मिल्ने फोटो"</string>
     <string name="selectable_video" msgid="1271768647699300826">"चयन गर्न मिल्ने भिडियो"</string>
     <string name="selectable_item" msgid="7557320816744205280">"चयन गर्न मिल्ने वस्तु"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"बटन"</string>
 </resources>
diff --git a/java/res/values-nl/strings.xml b/java/res/values-nl/strings.xml
index e452e98e..54123bef 100644
--- a/java/res/values-nl/strings.xml
+++ b/java/res/values-nl/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Selecteerbare afbeelding"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Selecteerbare video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Selecteerbaar item"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Knop"</string>
 </resources>
diff --git a/java/res/values-or/strings.xml b/java/res/values-or/strings.xml
index 0e2ece56..785acbe1 100644
--- a/java/res/values-or/strings.xml
+++ b/java/res/values-or/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"ଚୟନ କରାଯାଇପାରୁଥିବା ଇମେଜ"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ଚୟନ କରାଯାଇପାରୁଥିବା ଭିଡିଓ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ଚୟନ କରାଯାଇପାରୁଥିବା ଆଇଟମ"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"ବଟନ"</string>
 </resources>
diff --git a/java/res/values-pa/strings.xml b/java/res/values-pa/strings.xml
index 607f7d26..8b9f528c 100644
--- a/java/res/values-pa/strings.xml
+++ b/java/res/values-pa/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"ਚੁਣਨਯੋਗ ਚਿੱਤਰ"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ਚੁਣਨਯੋਗ ਵੀਡੀਓ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ਚੁਣਨਯੋਗ ਆਈਟਮ"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"ਬਟਨ"</string>
 </resources>
diff --git a/java/res/values-pl/strings.xml b/java/res/values-pl/strings.xml
index 10dda621..3de2b1f4 100644
--- a/java/res/values-pl/strings.xml
+++ b/java/res/values-pl/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Obraz do wyboru"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Film do wyboru"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Element do wyboru"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Przycisk"</string>
 </resources>
diff --git a/java/res/values-pt-rBR/strings.xml b/java/res/values-pt-rBR/strings.xml
index c8ce55a8..5ed57493 100644
--- a/java/res/values-pt-rBR/strings.xml
+++ b/java/res/values-pt-rBR/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{Mais # arquivo}one{Mais # arquivo}many{Mais # de arquivos}other{Mais # arquivos}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{Mais # arquivo}one{Mais # arquivo}many{Mais # de arquivos}other{Mais # arquivos}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Compartilhando texto"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Compartilhando link"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Compartilhar link"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Compartilhar imagem}one{Compartilhar # imagem}many{Compartilhar # de imagens}other{Compartilhar # imagens}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Compartilhando vídeo}one{Compartilhando # vídeo}many{Compartilhando # de vídeos}other{Compartilhando # vídeos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Compartilhando # arquivo}one{Compartilhando # arquivo}many{Compartilhando # de arquivos}other{Compartilhando # arquivos}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Imagem selecionável"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo selecionável"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Item selecionável"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Botão"</string>
 </resources>
diff --git a/java/res/values-pt-rPT/strings.xml b/java/res/values-pt-rPT/strings.xml
index ffcf9a1e..73d12957 100644
--- a/java/res/values-pt-rPT/strings.xml
+++ b/java/res/values-pt-rPT/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Imagem selecionável"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo selecionável"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Item selecionável"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Botão"</string>
 </resources>
diff --git a/java/res/values-pt/strings.xml b/java/res/values-pt/strings.xml
index c8ce55a8..5ed57493 100644
--- a/java/res/values-pt/strings.xml
+++ b/java/res/values-pt/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{Mais # arquivo}one{Mais # arquivo}many{Mais # de arquivos}other{Mais # arquivos}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{Mais # arquivo}one{Mais # arquivo}many{Mais # de arquivos}other{Mais # arquivos}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Compartilhando texto"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Compartilhando link"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Compartilhar link"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Compartilhar imagem}one{Compartilhar # imagem}many{Compartilhar # de imagens}other{Compartilhar # imagens}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Compartilhando vídeo}one{Compartilhando # vídeo}many{Compartilhando # de vídeos}other{Compartilhando # vídeos}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Compartilhando # arquivo}one{Compartilhando # arquivo}many{Compartilhando # de arquivos}other{Compartilhando # arquivos}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Imagem selecionável"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vídeo selecionável"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Item selecionável"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Botão"</string>
 </resources>
diff --git a/java/res/values-ro/strings.xml b/java/res/values-ro/strings.xml
index c2843bab..7c8816b6 100644
--- a/java/res/values-ro/strings.xml
+++ b/java/res/values-ro/strings.xml
@@ -74,7 +74,7 @@
     <string name="image_preview_a11y_description" msgid="297102643932491797">"Miniatură pentru previzualizarea imaginii"</string>
     <string name="video_preview_a11y_description" msgid="683440858811095990">"Miniatură pentru previzualizarea videoclipului"</string>
     <string name="file_preview_a11y_description" msgid="7397224827802410602">"Miniatură pentru previzualizarea fișierului"</string>
-    <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"Nu există persoane recomandate pentru permiterea accesului"</string>
+    <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"Nu există persoane recomandate pentru trimitere"</string>
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"Permisiunea de înregistrare nu a fost acordată aplicației, dar aceasta poate să înregistreze conținut audio prin intermediul acestui dispozitiv USB."</string>
     <string name="resolver_personal_tab" msgid="1381052735324320565">"Personal"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"Serviciu"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Imagine care poate fi selectată"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Videoclip care poate fi selectat"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Articol care poate fi selectat"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Buton"</string>
 </resources>
diff --git a/java/res/values-ru/strings.xml b/java/res/values-ru/strings.xml
index 9b4c2d20..7a05c9d0 100644
--- a/java/res/values-ru/strings.xml
+++ b/java/res/values-ru/strings.xml
@@ -55,7 +55,7 @@
     <string name="screenshot_edit" msgid="3857183660047569146">"Изменить"</string>
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{и ещё # файл}one{и ещё # файл}few{и ещё # файла}many{и ещё # файлов}other{и ещё # файла}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ ещё # файл}one{+ ещё # файл}few{+ ещё # файла}many{+ ещё # файлов}other{+ ещё # файла}}"</string>
-    <string name="sharing_text" msgid="8137537443603304062">"Отправка сообщения"</string>
+    <string name="sharing_text" msgid="8137537443603304062">"Поделиться текстом"</string>
     <string name="sharing_link" msgid="2307694372813942916">"Отправка ссылки"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Отправка изображения}one{Отправка # изображения}few{Отправка # изображений}many{Отправка # изображений}other{Отправка # изображения}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Отправка видео}one{Отправка # видео}few{Отправка # видео}many{Отправка # видео}other{Отправка # видео}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Изображение, которое можно выбрать"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Видео, которое можно выбрать"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Объект, который можно выбрать"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Кнопка"</string>
 </resources>
diff --git a/java/res/values-si/strings.xml b/java/res/values-si/strings.xml
index 1fc87e4d..19af7794 100644
--- a/java/res/values-si/strings.xml
+++ b/java/res/values-si/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"තෝරා ගත හැකි රූපය"</string>
     <string name="selectable_video" msgid="1271768647699300826">"තෝරා ගත හැකි වීඩියෝව"</string>
     <string name="selectable_item" msgid="7557320816744205280">"තෝරා ගත හැකි අයිතමය"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"බොත්තම"</string>
 </resources>
diff --git a/java/res/values-sk/strings.xml b/java/res/values-sk/strings.xml
index 9119aaa0..36898690 100644
--- a/java/res/values-sk/strings.xml
+++ b/java/res/values-sk/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Vybrateľný obrázok"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Vybrateľné video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Vybrateľná položka"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Tlačidlo"</string>
 </resources>
diff --git a/java/res/values-sl/strings.xml b/java/res/values-sl/strings.xml
index 78e07ad1..714ba171 100644
--- a/java/res/values-sl/strings.xml
+++ b/java/res/values-sl/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Slika, ki jo je mogoče izbrati."</string>
     <string name="selectable_video" msgid="1271768647699300826">"Videoposnetek, ki ga je mogoče izbrati."</string>
     <string name="selectable_item" msgid="7557320816744205280">"Element, ki ga je mogoče izbrati."</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Gumb"</string>
 </resources>
diff --git a/java/res/values-sq/strings.xml b/java/res/values-sq/strings.xml
index 374b2e0a..db24392a 100644
--- a/java/res/values-sq/strings.xml
+++ b/java/res/values-sq/strings.xml
@@ -74,7 +74,7 @@
     <string name="image_preview_a11y_description" msgid="297102643932491797">"Miniatura e pamjes paraprake të imazhit"</string>
     <string name="video_preview_a11y_description" msgid="683440858811095990">"Miniatura e pamjes paraprake të videos"</string>
     <string name="file_preview_a11y_description" msgid="7397224827802410602">"Miniatura e pamjes paraprake të skedarit"</string>
-    <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"Nuk ka persona të rekomanduar për ta ndarë"</string>
+    <string name="chooser_no_direct_share_targets" msgid="4233416657754261844">"Nuk ka persona të rekomanduar për të ndarë"</string>
     <string name="usb_device_resolve_prompt_warn" msgid="4254493957548169620">"Këtij aplikacioni nuk i është dhënë leje për regjistrim, por mund të regjistrojë audio përmes kësaj pajisjeje USB."</string>
     <string name="resolver_personal_tab" msgid="1381052735324320565">"Personal"</string>
     <string name="resolver_work_tab" msgid="3588325717455216412">"Puna"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Imazh që mund të zgjidhet"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video që mund të zgjidhet"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Artikull që mund të zgjidhet"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Buton"</string>
 </resources>
diff --git a/java/res/values-sr/strings.xml b/java/res/values-sr/strings.xml
index 8e7c57d1..8591ef7d 100644
--- a/java/res/values-sr/strings.xml
+++ b/java/res/values-sr/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Слика која може да се изабере"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Видео који може да се изабере"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Ставка која може да се изабере"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Дугме"</string>
 </resources>
diff --git a/java/res/values-sv/strings.xml b/java/res/values-sv/strings.xml
index d48cc781..6810faa7 100644
--- a/java/res/values-sv/strings.xml
+++ b/java/res/values-sv/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Bild som kan markeras"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video som kan markeras"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Objekt som kan markeras"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Knapp"</string>
 </resources>
diff --git a/java/res/values-sw/strings.xml b/java/res/values-sw/strings.xml
index 2f63e887..77b83e99 100644
--- a/java/res/values-sw/strings.xml
+++ b/java/res/values-sw/strings.xml
@@ -56,9 +56,9 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ faili #}other{+ faili #}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{Faili nyingine #}other{Faili zingine #}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Kutuma maandishi"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Inashiriki kiungo"</string>
-    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Inashiriki picha}other{Inashiriki picha #}}"</string>
-    <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Inashiriki video}other{Inashiriki video #}}"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Inatuma kiungo"</string>
+    <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Kutuma picha}other{Kutuma picha #}}"</string>
+    <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Inatuma video}other{Inatuma video #}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{Inashiriki faili #}other{Inashiriki faili #}}"</string>
     <string name="select_items_to_share" msgid="1026071777275022579">"Chagua vipengee vya kutuma"</string>
     <string name="sharing_images_with_text" msgid="9005717434461730242">"{count,plural, =1{Inashiriki picha na maandishi}other{Inashiriki picha # na maandishi}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Picha inayoweza kuchaguliwa"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video inayoweza kuchaguliwa"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Kipengee kinachoweza kuchaguliwa"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Kitufe"</string>
 </resources>
diff --git a/java/res/values-sw600dp/dimens.xml b/java/res/values-sw600dp/dimens.xml
index 240ee067..e152ba06 100644
--- a/java/res/values-sw600dp/dimens.xml
+++ b/java/res/values-sw600dp/dimens.xml
@@ -20,4 +20,5 @@
 <resources>
     <dimen name="chooser_width">624dp</dimen>
     <dimen name="modify_share_text_toggle_max_width">250dp</dimen>
+    <dimen name="chooser_item_focus_outline_corner_radius">16dp</dimen>
 </resources>
diff --git a/java/res/values-ta/strings.xml b/java/res/values-ta/strings.xml
index f1df5cba..f53e5b29 100644
--- a/java/res/values-ta/strings.xml
+++ b/java/res/values-ta/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"தேர்ந்தெடுக்கக்கூடிய படம்"</string>
     <string name="selectable_video" msgid="1271768647699300826">"தேர்ந்தெடுக்கக்கூடிய வீடியோ"</string>
     <string name="selectable_item" msgid="7557320816744205280">"தேர்ந்தெடுக்கக்கூடியது"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"பட்டன்"</string>
 </resources>
diff --git a/java/res/values-te/strings.xml b/java/res/values-te/strings.xml
index b88d7d4e..5003d8eb 100644
--- a/java/res/values-te/strings.xml
+++ b/java/res/values-te/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"ఎంచుకోదగిన ఇమేజ్"</string>
     <string name="selectable_video" msgid="1271768647699300826">"ఎంచుకోదగిన వీడియో"</string>
     <string name="selectable_item" msgid="7557320816744205280">"ఎంచుకోదగిన ఐటెమ్"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"బటన్"</string>
 </resources>
diff --git a/java/res/values-th/strings.xml b/java/res/values-th/strings.xml
index 5effd16c..8bb9408f 100644
--- a/java/res/values-th/strings.xml
+++ b/java/res/values-th/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"รูปภาพที่เลือกได้"</string>
     <string name="selectable_video" msgid="1271768647699300826">"วิดีโอที่เลือกได้"</string>
     <string name="selectable_item" msgid="7557320816744205280">"รายการที่เลือกได้"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"ปุ่ม"</string>
 </resources>
diff --git a/java/res/values-tl/strings.xml b/java/res/values-tl/strings.xml
index 67782253..e98c06bf 100644
--- a/java/res/values-tl/strings.xml
+++ b/java/res/values-tl/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Napipiling larawan"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Napipiling video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Napipiling item"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Button"</string>
 </resources>
diff --git a/java/res/values-tr/strings.xml b/java/res/values-tr/strings.xml
index 5dee9296..25b7e860 100644
--- a/java/res/values-tr/strings.xml
+++ b/java/res/values-tr/strings.xml
@@ -56,7 +56,7 @@
     <string name="other_files" msgid="4501185823517473875">"{count,plural, =1{+ # dosya}other{+ # dosya}}"</string>
     <string name="more_files" msgid="1043875756612339842">"{count,plural, =1{+ # dosya daha}other{+ # dosya daha}}"</string>
     <string name="sharing_text" msgid="8137537443603304062">"Metin paylaşılıyor"</string>
-    <string name="sharing_link" msgid="2307694372813942916">"Bağlantı paylaşılıyor"</string>
+    <string name="sharing_link" msgid="2307694372813942916">"Paylaşım bağlantısı"</string>
     <string name="sharing_images" msgid="5251443722186962006">"{count,plural, =1{Resim paylaşılıyor}other{# resim paylaşılıyor}}"</string>
     <string name="sharing_videos" msgid="3583423190182877434">"{count,plural, =1{Video paylaşılıyor}other{# video paylaşılıyor}}"</string>
     <string name="sharing_files" msgid="1275646542246028823">"{count,plural, =1{# dosya paylaşılıyor}other{# dosya paylaşılıyor}}"</string>
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Seçilebilir resim"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Seçilebilir video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Seçilebilir öğe"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Düğme"</string>
 </resources>
diff --git a/java/res/values-uk/strings.xml b/java/res/values-uk/strings.xml
index 293696fd..33f9e350 100644
--- a/java/res/values-uk/strings.xml
+++ b/java/res/values-uk/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Зображення, яке можна вибрати"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Відео, яке можна вибрати"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Об’єкт, який можна вибрати"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Кнопка"</string>
 </resources>
diff --git a/java/res/values-ur/strings.xml b/java/res/values-ur/strings.xml
index 9ecc8443..950041e7 100644
--- a/java/res/values-ur/strings.xml
+++ b/java/res/values-ur/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"قابل انتخاب تصویر"</string>
     <string name="selectable_video" msgid="1271768647699300826">"قابل انتخاب ویڈیو"</string>
     <string name="selectable_item" msgid="7557320816744205280">"قابل انتخاب آئٹم"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"بٹن"</string>
 </resources>
diff --git a/java/res/values-uz/strings.xml b/java/res/values-uz/strings.xml
index f9434b18..1792e0d2 100644
--- a/java/res/values-uz/strings.xml
+++ b/java/res/values-uz/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Tanlanadigan rasm"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Tanlanadigan video"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Tanlanadigan fayl"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Tugma"</string>
 </resources>
diff --git a/java/res/values-vi/strings.xml b/java/res/values-vi/strings.xml
index 4c84256e..a32bacc1 100644
--- a/java/res/values-vi/strings.xml
+++ b/java/res/values-vi/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Hình ảnh có thể chọn"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Video có thể chọn"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Mục có thể chọn"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Nút"</string>
 </resources>
diff --git a/java/res/values-zh-rCN/strings.xml b/java/res/values-zh-rCN/strings.xml
index c2fa444f..603a4e5e 100644
--- a/java/res/values-zh-rCN/strings.xml
+++ b/java/res/values-zh-rCN/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"可选择的图片"</string>
     <string name="selectable_video" msgid="1271768647699300826">"可选择的视频"</string>
     <string name="selectable_item" msgid="7557320816744205280">"可选择的内容"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"按钮"</string>
 </resources>
diff --git a/java/res/values-zh-rHK/strings.xml b/java/res/values-zh-rHK/strings.xml
index 54a61c7e..b3aed885 100644
--- a/java/res/values-zh-rHK/strings.xml
+++ b/java/res/values-zh-rHK/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"可以揀嘅圖片"</string>
     <string name="selectable_video" msgid="1271768647699300826">"可以揀嘅影片"</string>
     <string name="selectable_item" msgid="7557320816744205280">"可以揀嘅項目"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"按鈕"</string>
 </resources>
diff --git a/java/res/values-zh-rTW/strings.xml b/java/res/values-zh-rTW/strings.xml
index 0d369318..97770baf 100644
--- a/java/res/values-zh-rTW/strings.xml
+++ b/java/res/values-zh-rTW/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"可選取的圖片"</string>
     <string name="selectable_video" msgid="1271768647699300826">"可選取的影片"</string>
     <string name="selectable_item" msgid="7557320816744205280">"可選取的項目"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"按鈕"</string>
 </resources>
diff --git a/java/res/values-zu/strings.xml b/java/res/values-zu/strings.xml
index 9d6d13dc..bdf42d69 100644
--- a/java/res/values-zu/strings.xml
+++ b/java/res/values-zu/strings.xml
@@ -106,4 +106,5 @@
     <string name="selectable_image" msgid="3157858923437182271">"Umfanekiso okhethekayo"</string>
     <string name="selectable_video" msgid="1271768647699300826">"Ividiyo ekhethekayo"</string>
     <string name="selectable_item" msgid="7557320816744205280">"Into ekhethekayo"</string>
+    <string name="role_description_button" msgid="4537198530568333649">"Inkinobho"</string>
 </resources>
diff --git a/java/res/values/attrs.xml b/java/res/values/attrs.xml
index c9f2c300..19d85573 100644
--- a/java/res/values/attrs.xml
+++ b/java/res/values/attrs.xml
@@ -55,5 +55,13 @@
         <attr name="itemInnerSpacing" format="dimension" />
         <attr name="itemOuterSpacing" format="dimension" />
         <attr name="maxWidthHint" format="dimension" />
+        <attr name="editButtonRoleDescription" format="string" />
+    </declare-styleable>
+
+    <declare-styleable name="ChooserTargetItemView">
+        <attr name="focusOutlineColor" format="color" />
+        <attr name="focusInnerOutlineColor" format="color" />
+        <attr name="focusOutlineWidth" format="dimension" />
+        <attr name="focusOutlineCornerRadius" format="dimension" />
     </declare-styleable>
 </resources>
diff --git a/java/res/values/dimens.xml b/java/res/values/dimens.xml
index a1f03276..515343b6 100644
--- a/java/res/values/dimens.xml
+++ b/java/res/values/dimens.xml
@@ -34,9 +34,15 @@
     <dimen name="chooser_max_collapsed_height">288dp</dimen>
     <dimen name="chooser_icon_size">56dp</dimen>
     <dimen name="chooser_badge_size">22dp</dimen>
+    <dimen name="chooser_icon_horizontal_padding">8dp</dimen>
+    <dimen name="chooser_icon_vertical_padding">7dp</dimen>
+    <dimen name="chooser_icon_width_with_padding">72dp</dimen> <!-- = chooser_icon_size + chooser_icon_horizontal_padding * 2 -->
+    <dimen name="chooser_icon_height_with_padding">70dp</dimen> <!-- = chooser_icon_size + chooser_icon_vertical_padding * 2 -->
     <dimen name="chooser_headline_text_size">18sp</dimen>
     <dimen name="chooser_grid_target_name_text_size">12sp</dimen>
     <dimen name="chooser_grid_activity_name_text_size">12sp</dimen>
+    <dimen name="chooser_item_focus_outline_corner_radius">11dp</dimen>
+    <dimen name="chooser_item_focus_outline_width">2dp</dimen>
     <dimen name="resolver_icon_size">32dp</dimen>
     <dimen name="resolver_button_bar_spacing">0dp</dimen>
     <dimen name="resolver_badge_size">18dp</dimen>
diff --git a/java/res/values/strings.xml b/java/res/values/strings.xml
index 4f77d248..2261a4a8 100644
--- a/java/res/values/strings.xml
+++ b/java/res/values/strings.xml
@@ -338,4 +338,6 @@
     <!-- Accessibility content description for an item that the user may select for sharing.
          [CHAR LIMIT=NONE] -->
     <string name="selectable_item">Selectable item</string>
+    <!-- Accessibility role description for a11y on button. [CHAR LIMIT=NONE] -->
+    <string name="role_description_button">Button</string>
 </resources>
diff --git a/java/src/com/android/intentresolver/ChooserActivity.java b/java/src/com/android/intentresolver/ChooserActivity.java
index 4fc8fd9d..54f575d7 100644
--- a/java/src/com/android/intentresolver/ChooserActivity.java
+++ b/java/src/com/android/intentresolver/ChooserActivity.java
@@ -23,13 +23,14 @@ import static android.view.WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTE
 import static androidx.lifecycle.LifecycleKt.getCoroutineScope;
 
 import static com.android.intentresolver.ChooserActionFactory.EDIT_SOURCE;
-import static com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra;
 import static com.android.intentresolver.Flags.fixShortcutsFlashing;
+import static com.android.intentresolver.Flags.keyboardNavigationFix;
+import static com.android.intentresolver.Flags.rebuildAdaptersOnTargetPinning;
+import static com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra;
 import static com.android.intentresolver.Flags.unselectFinalItem;
-import static com.android.intentresolver.ext.CreationExtrasExtKt.addDefaultArgs;
+import static com.android.intentresolver.ext.CreationExtrasExtKt.replaceDefaultArgs;
 import static com.android.intentresolver.profiles.MultiProfilePagerAdapter.PROFILE_PERSONAL;
 import static com.android.intentresolver.profiles.MultiProfilePagerAdapter.PROFILE_WORK;
-import static com.android.intentresolver.ui.model.ActivityModel.ACTIVITY_MODEL_KEY;
 import static com.android.internal.util.LatencyTracker.ACTION_LOAD_SHARE_SHEET;
 
 import static java.util.Objects.requireNonNull;
@@ -102,6 +103,7 @@ import com.android.intentresolver.chooser.TargetInfo;
 import com.android.intentresolver.contentpreview.ChooserContentPreviewUi;
 import com.android.intentresolver.contentpreview.HeadlineGeneratorImpl;
 import com.android.intentresolver.data.model.ChooserRequest;
+import com.android.intentresolver.data.repository.ActivityModelRepository;
 import com.android.intentresolver.data.repository.DevicePolicyResources;
 import com.android.intentresolver.domain.interactor.UserInteractor;
 import com.android.intentresolver.emptystate.CompositeEmptyStateProvider;
@@ -127,6 +129,7 @@ import com.android.intentresolver.profiles.MultiProfilePagerAdapter.ProfileType;
 import com.android.intentresolver.profiles.OnProfileSelectedListener;
 import com.android.intentresolver.profiles.OnSwitchOnWorkSelectedListener;
 import com.android.intentresolver.profiles.TabConfig;
+import com.android.intentresolver.shared.model.ActivityModel;
 import com.android.intentresolver.shared.model.Profile;
 import com.android.intentresolver.shortcuts.AppPredictorFactory;
 import com.android.intentresolver.shortcuts.ShortcutLoader;
@@ -134,9 +137,9 @@ import com.android.intentresolver.ui.ActionTitle;
 import com.android.intentresolver.ui.ProfilePagerResources;
 import com.android.intentresolver.ui.ShareResultSender;
 import com.android.intentresolver.ui.ShareResultSenderFactory;
-import com.android.intentresolver.ui.model.ActivityModel;
 import com.android.intentresolver.ui.viewmodel.ChooserViewModel;
 import com.android.intentresolver.widget.ActionRow;
+import com.android.intentresolver.widget.ChooserNestedScrollView;
 import com.android.intentresolver.widget.ImagePreviewView;
 import com.android.intentresolver.widget.ResolverDrawerLayout;
 import com.android.internal.annotations.VisibleForTesting;
@@ -149,8 +152,6 @@ import com.google.common.collect.ImmutableList;
 
 import dagger.hilt.android.AndroidEntryPoint;
 
-import kotlin.Pair;
-
 import kotlinx.coroutines.CoroutineDispatcher;
 
 import java.util.ArrayList;
@@ -171,7 +172,6 @@ import java.util.function.Consumer;
 import java.util.function.Supplier;
 
 import javax.inject.Inject;
-import javax.inject.Provider;
 
 /**
  * The Chooser Activity handles intent resolution specifically for sharing intents -
@@ -257,22 +257,20 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     @Inject @Background public CoroutineDispatcher mBackgroundDispatcher;
     @Inject public ChooserHelper mChooserHelper;
     @Inject public FeatureFlags mFeatureFlags;
-    @Inject public android.service.chooser.FeatureFlags mChooserServiceFeatureFlags;
     @Inject public EventLog mEventLog;
     @Inject @AppPredictionAvailable public boolean mAppPredictionAvailable;
     @Inject @ImageEditor public Optional<ComponentName> mImageEditor;
     @Inject @NearbyShare public Optional<ComponentName> mNearbyShare;
-    protected TargetDataLoader mTargetDataLoader;
-    @Inject public Provider<TargetDataLoader> mTargetDataLoaderProvider;
     @Inject
     @Caching
-    public Provider<TargetDataLoader> mCachingTargetDataLoaderProvider;
+    public TargetDataLoader mTargetDataLoader;
     @Inject public DevicePolicyResources mDevicePolicyResources;
     @Inject public ProfilePagerResources mProfilePagerResources;
     @Inject public PackageManager mPackageManager;
     @Inject public ClipboardManager mClipboardManager;
     @Inject public IntentForwarding mIntentForwarding;
     @Inject public ShareResultSenderFactory mShareResultSenderFactory;
+    @Inject public ActivityModelRepository mActivityModelRepository;
 
     private ActivityModel mActivityModel;
     private ChooserRequest mRequest;
@@ -331,30 +329,27 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     @NonNull
     @Override
     public CreationExtras getDefaultViewModelCreationExtras() {
-        return addDefaultArgs(
-                super.getDefaultViewModelCreationExtras(),
-                new Pair<>(ACTIVITY_MODEL_KEY, createActivityModel()));
+        // DEFAULT_ARGS_KEY extra is saved for each ViewModel we create. ComponentActivity puts the
+        // initial intent's extra into DEFAULT_ARGS_KEY thus we store these values 2 times (3 if we
+        // count the initial intent). We don't need those values to be saved as they don't capture
+        // the state.
+        return replaceDefaultArgs(super.getDefaultViewModelCreationExtras());
     }
 
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
         Log.i(TAG, "onCreate");
-
-        mTargetDataLoader = mChooserServiceFeatureFlags.chooserPayloadToggling()
-                ? mCachingTargetDataLoaderProvider.get()
-                : mTargetDataLoaderProvider.get();
+        mActivityModelRepository.initialize(this::createActivityModel);
 
         setTheme(R.style.Theme_DeviceDefault_Chooser);
 
         // Initializer is invoked when this function returns, via Lifecycle.
         mChooserHelper.setInitializer(this::initialize);
-        if (mChooserServiceFeatureFlags.chooserPayloadToggling()) {
-            mChooserHelper.setOnChooserRequestChanged(this::onChooserRequestChanged);
-            mChooserHelper.setOnPendingSelection(this::onPendingSelection);
-            if (unselectFinalItem()) {
-                mChooserHelper.setOnHasSelections(this::onHasSelections);
-            }
+        mChooserHelper.setOnChooserRequestChanged(this::onChooserRequestChanged);
+        mChooserHelper.setOnPendingSelection(this::onPendingSelection);
+        if (unselectFinalItem()) {
+            mChooserHelper.setOnHasSelections(this::onHasSelections);
         }
     }
     private int mInitialProfile = -1;
@@ -655,8 +650,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
                 mEnterTransitionAnimationDelegate,
                 new HeadlineGeneratorImpl(this),
                 mRequest.getContentTypeHint(),
-                mRequest.getMetadataText(),
-                mChooserServiceFeatureFlags.chooserPayloadToggling());
+                mRequest.getMetadataText());
         updateStickyContentPreview();
         if (shouldShowStickyContentPreview()) {
             getEventLog().logActionShareWithPreview(
@@ -773,9 +767,6 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     }
 
     private void recreatePagerAdapter() {
-        if (!mChooserServiceFeatureFlags.chooserPayloadToggling()) {
-            return;
-        }
         destroyProfileRecords();
         createProfileRecords(
                 new AppPredictorFactory(
@@ -848,6 +839,9 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
             }
         }
         setTabsViewEnabled(false);
+        if (mSystemWindowInsets != null) {
+            applyFooterView(mSystemWindowInsets.bottom);
+        }
     }
 
     private void setTabsViewEnabled(boolean isEnabled) {
@@ -1282,6 +1276,18 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         mTabHost = findViewById(com.android.internal.R.id.profile_tabhost);
         mViewPager = requireViewById(com.android.internal.R.id.profile_pager);
         mChooserMultiProfilePagerAdapter.setupViewPager(mViewPager);
+        ChooserNestedScrollView scrollableContainer =
+                requireViewById(R.id.chooser_scrollable_container);
+        if (keyboardNavigationFix()) {
+            scrollableContainer.setRequestChildFocusPredicate((child, focused) ->
+                    // TabHost view will request focus on the newly activated tab. The RecyclerView
+                    // from the tab gets focused and  notifies its parents (including
+                    // NestedScrollView) about it through #requestChildFocus method call.
+                    // NestedScrollView's view implementation of the method  will  scroll to the
+                    // focused view. As we don't want to change drawer's position upon tab change,
+                    // ignore focus requests from tab RecyclerViews.
+                    focused == null || focused.getId() != com.android.internal.R.id.resolver_list);
+        }
         boolean result = postRebuildList(rebuildCompleted);
         Trace.endSection();
         return result;
@@ -1543,10 +1549,14 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
     private void handlePackagesChanged(@Nullable ResolverListAdapter listAdapter) {
         // Refresh pinned items
         mPinnedSharedPrefs = getPinnedSharedPrefs(this);
-        if (listAdapter == null) {
-            mChooserMultiProfilePagerAdapter.refreshPackagesInAllTabs();
+        if (rebuildAdaptersOnTargetPinning()) {
+            recreatePagerAdapter();
         } else {
-            listAdapter.handlePackagesChanged();
+            if (listAdapter == null) {
+                mChooserMultiProfilePagerAdapter.refreshPackagesInAllTabs();
+            } else {
+                listAdapter.handlePackagesChanged();
+            }
         }
     }
 
@@ -1566,6 +1576,7 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         mShouldDisplayLandscape = shouldDisplayLandscape(newConfig.orientation);
         mMaxTargetsPerRow = getResources().getInteger(R.integer.config_chooser_max_targets_per_row);
         mChooserMultiProfilePagerAdapter.setMaxTargetsPerRow(mMaxTargetsPerRow);
+        adjustMaxPreviewWidth();
         adjustPreviewWidth(newConfig.orientation, null);
         updateStickyContentPreview();
         updateTabPadding();
@@ -1578,6 +1589,14 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         return orientation == Configuration.ORIENTATION_LANDSCAPE && !isInMultiWindowMode();
     }
 
+    private void adjustMaxPreviewWidth() {
+        if (mResolverDrawerLayout == null) {
+            return;
+        }
+        mResolverDrawerLayout.setMaxWidth(
+                getResources().getDimensionPixelSize(R.dimen.chooser_width));
+    }
+
     private void adjustPreviewWidth(int orientation, View parent) {
         int width = -1;
         if (mShouldDisplayLandscape) {
@@ -2284,8 +2303,12 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         }
 
         final int availableWidth = right - left - v.getPaddingLeft() - v.getPaddingRight();
+        final int maxChooserWidth = getResources().getDimensionPixelSize(R.dimen.chooser_width);
         boolean isLayoutUpdated =
-                gridAdapter.calculateChooserTargetWidth(availableWidth)
+                gridAdapter.calculateChooserTargetWidth(
+                        maxChooserWidth >= 0
+                                ? Math.min(maxChooserWidth, availableWidth)
+                                : availableWidth)
                 || recyclerView.getAdapter() == null
                 || availableWidth != mCurrAvailableWidth;
 
@@ -2425,17 +2448,12 @@ public class ChooserActivity extends Hilt_ChooserActivity implements
         // ResolverListAdapter#mPostListReadyRunnable is executed.
         if (chooserListAdapter.getDisplayResolveInfoCount() == 0) {
             Log.d(TAG, "getDisplayResolveInfoCount() == 0");
-            if (rebuildComplete && mChooserServiceFeatureFlags.chooserPayloadToggling()) {
+            if (rebuildComplete) {
                 onAppTargetsLoaded(listAdapter);
             }
             chooserListAdapter.notifyDataSetChanged();
         } else {
-            if (mChooserServiceFeatureFlags.chooserPayloadToggling()) {
-                chooserListAdapter.updateAlphabeticalList(
-                        () -> onAppTargetsLoaded(listAdapter));
-            } else {
-                chooserListAdapter.updateAlphabeticalList();
-            }
+            chooserListAdapter.updateAlphabeticalList(() -> onAppTargetsLoaded(listAdapter));
         }
 
         if (rebuildComplete) {
diff --git a/java/src/com/android/intentresolver/ChooserListAdapter.java b/java/src/com/android/intentresolver/ChooserListAdapter.java
index 016eb714..563d7d1a 100644
--- a/java/src/com/android/intentresolver/ChooserListAdapter.java
+++ b/java/src/com/android/intentresolver/ChooserListAdapter.java
@@ -18,6 +18,7 @@ package com.android.intentresolver;
 
 import static com.android.intentresolver.ChooserActivity.TARGET_TYPE_SHORTCUTS_FROM_PREDICTION_SERVICE;
 import static com.android.intentresolver.ChooserActivity.TARGET_TYPE_SHORTCUTS_FROM_SHORTCUT_MANAGER;
+import static com.android.intentresolver.Flags.targetHoverAndKeyboardFocusStates;
 
 import android.app.ActivityManager;
 import android.app.prediction.AppTarget;
@@ -59,6 +60,8 @@ import com.android.intentresolver.widget.BadgeTextView;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.config.sysui.SystemUiDeviceConfigFlags;
 
+import com.google.common.collect.ImmutableList;
+
 import java.util.ArrayList;
 import java.util.HashSet;
 import java.util.List;
@@ -365,7 +368,10 @@ public class ChooserListAdapter extends ResolverListAdapter {
 
     @Override
     View onCreateView(ViewGroup parent) {
-        return mInflater.inflate(R.layout.chooser_grid_item, parent, false);
+        int layout = targetHoverAndKeyboardFocusStates()
+                ? R.layout.chooser_grid_item_hover
+                : R.layout.chooser_grid_item;
+        return mInflater.inflate(layout, parent, false);
     }
 
     @Override
@@ -509,21 +515,16 @@ public class ChooserListAdapter extends ResolverListAdapter {
         }
     }
 
-    /**
-     * Group application targets
-     */
-    public void updateAlphabeticalList() {
-        updateAlphabeticalList(() -> {});
-    }
-
     /**
      * Group application targets
      */
     public void updateAlphabeticalList(Runnable onCompleted) {
         final DisplayResolveInfoAzInfoComparator
                 comparator = new DisplayResolveInfoAzInfoComparator(mContext);
-        final List<DisplayResolveInfo> allTargets = new ArrayList<>();
-        allTargets.addAll(getTargetsInCurrentDisplayList());
+        ImmutableList<DisplayResolveInfo> displayList = getTargetsInCurrentDisplayList();
+        final List<DisplayResolveInfo> allTargets =
+                new ArrayList<>(displayList.size() + mCallerTargets.size());
+        allTargets.addAll(displayList);
         allTargets.addAll(mCallerTargets);
 
         new AsyncTask<Void, Void, List<DisplayResolveInfo>>() {
@@ -543,6 +544,24 @@ public class ChooserListAdapter extends ResolverListAdapter {
                 // Consolidate multiple targets from same app.
                 return allTargets
                         .stream()
+                        .map(appTarget -> {
+                            if (targetHoverAndKeyboardFocusStates()) {
+                                // Icon drawables are effectively cached per target info.
+                                // Without cloning target infos, the same target info could be used
+                                // for two different positions in the grid: once in the ranked
+                                // targets row (from ResolverListAdapter#mDisplayList or
+                                // #mCallerTargets, see #getItem()) and again in the all-app-target
+                                // grid (copied from #mDisplayList and #mCallerTargets to
+                                // #mSortedList).
+                                // Using the same drawable for two list items would result in visual
+                                // effects being applied to both simultaneously.
+                                DisplayResolveInfo copy = appTarget.copy();
+                                copy.getDisplayIconHolder().setDisplayIcon(null);
+                                return copy;
+                            } else {
+                                return appTarget;
+                            }
+                        })
                         .collect(Collectors.groupingBy(target ->
                                 target.getResolvedComponentName().getPackageName()
                                         + "#" + target.getDisplayLabel()
diff --git a/java/src/com/android/intentresolver/ChooserTargetActionsDialogFragment.java b/java/src/com/android/intentresolver/ChooserTargetActionsDialogFragment.java
index ae80fad4..8070fc84 100644
--- a/java/src/com/android/intentresolver/ChooserTargetActionsDialogFragment.java
+++ b/java/src/com/android/intentresolver/ChooserTargetActionsDialogFragment.java
@@ -33,6 +33,7 @@ import android.content.pm.PackageManager;
 import android.content.pm.ShortcutInfo;
 import android.content.pm.ShortcutManager;
 import android.graphics.Color;
+import android.graphics.drawable.BitmapDrawable;
 import android.graphics.drawable.ColorDrawable;
 import android.graphics.drawable.Drawable;
 import android.os.Bundle;
@@ -136,7 +137,7 @@ public class ChooserTargetActionsDialogFragment extends DialogFragment
 
         final TargetPresentationGetter pg = getProvidingAppPresentationGetter();
         title.setText(isShortcutTarget() ? mShortcutTitle : pg.getLabel());
-        icon.setImageDrawable(pg.getIcon(mUserHandle));
+        icon.setImageDrawable(new BitmapDrawable(getResources(), pg.getIconBitmap(mUserHandle)));
         rv.setAdapter(new VHAdapter(items));
 
         return v;
@@ -280,7 +281,11 @@ public class ChooserTargetActionsDialogFragment extends DialogFragment
         final int iconDpi = am.getLauncherLargeIconDensity();
 
         // Use the matching application icon and label for the title, any TargetInfo will do
-        return new TargetPresentationGetter.Factory(getContext(), iconDpi)
+        final Context context = getContext();
+        return new TargetPresentationGetter.Factory(
+                () -> SimpleIconFactory.obtain(context),
+                context.getPackageManager(),
+                iconDpi)
                 .makePresentationGetter(mTargetInfos.get(0).getResolveInfo());
     }
 
diff --git a/java/src/com/android/intentresolver/ResolverActivity.java b/java/src/com/android/intentresolver/ResolverActivity.java
index a402fc72..38259281 100644
--- a/java/src/com/android/intentresolver/ResolverActivity.java
+++ b/java/src/com/android/intentresolver/ResolverActivity.java
@@ -21,7 +21,7 @@ import static android.view.WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTE
 
 import static androidx.lifecycle.LifecycleKt.getCoroutineScope;
 
-import static com.android.intentresolver.ext.CreationExtrasExtKt.addDefaultArgs;
+import static com.android.intentresolver.ext.CreationExtrasExtKt.replaceDefaultArgs;
 import static com.android.internal.annotations.VisibleForTesting.Visibility.PROTECTED;
 
 import static java.util.Objects.requireNonNull;
@@ -85,6 +85,7 @@ import androidx.viewpager.widget.ViewPager;
 
 import com.android.intentresolver.chooser.DisplayResolveInfo;
 import com.android.intentresolver.chooser.TargetInfo;
+import com.android.intentresolver.data.repository.ActivityModelRepository;
 import com.android.intentresolver.data.repository.DevicePolicyResources;
 import com.android.intentresolver.domain.interactor.UserInteractor;
 import com.android.intentresolver.emptystate.CompositeEmptyStateProvider;
@@ -103,10 +104,10 @@ import com.android.intentresolver.profiles.OnProfileSelectedListener;
 import com.android.intentresolver.profiles.OnSwitchOnWorkSelectedListener;
 import com.android.intentresolver.profiles.ResolverMultiProfilePagerAdapter;
 import com.android.intentresolver.profiles.TabConfig;
+import com.android.intentresolver.shared.model.ActivityModel;
 import com.android.intentresolver.shared.model.Profile;
 import com.android.intentresolver.ui.ActionTitle;
 import com.android.intentresolver.ui.ProfilePagerResources;
-import com.android.intentresolver.ui.model.ActivityModel;
 import com.android.intentresolver.ui.model.ResolverRequest;
 import com.android.intentresolver.ui.viewmodel.ResolverViewModel;
 import com.android.intentresolver.widget.ResolverDrawerLayout;
@@ -119,8 +120,6 @@ import com.google.common.collect.ImmutableList;
 
 import dagger.hilt.android.AndroidEntryPoint;
 
-import kotlin.Pair;
-
 import kotlinx.coroutines.CoroutineDispatcher;
 
 import java.util.ArrayList;
@@ -150,6 +149,8 @@ public class ResolverActivity extends Hilt_ResolverActivity implements
     @Inject public ProfilePagerResources mProfilePagerResources;
     @Inject public IntentForwarding mIntentForwarding;
     @Inject public FeatureFlags mFeatureFlags;
+    @Inject public ActivityModelRepository mActivityModelRepository;
+    @Inject public DefaultTargetDataLoader.Factory mTargetDataLoaderFactory;
 
     private ResolverViewModel mViewModel;
     private ResolverRequest mRequest;
@@ -220,15 +221,14 @@ public class ResolverActivity extends Hilt_ResolverActivity implements
     @NonNull
     @Override
     public CreationExtras getDefaultViewModelCreationExtras() {
-        return addDefaultArgs(
-                super.getDefaultViewModelCreationExtras(),
-                new Pair<>(ActivityModel.ACTIVITY_MODEL_KEY, createActivityModel()));
+        return replaceDefaultArgs(super.getDefaultViewModelCreationExtras());
     }
 
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
         Log.i(TAG, "onCreate");
+        mActivityModelRepository.initialize(this::createActivityModel);
         setTheme(R.style.Theme_DeviceDefault_Resolver);
         mResolverHelper.setInitializer(this::initialize);
     }
@@ -335,10 +335,7 @@ public class ResolverActivity extends Hilt_ResolverActivity implements
         mProfileAvailability.setOnProfileStatusChange(this::onWorkProfileStatusUpdated);
 
         mResolvingHome = mRequest.isResolvingHome();
-        mTargetDataLoader = new DefaultTargetDataLoader(
-                this,
-                getLifecycle(),
-                mRequest.isAudioCaptureDevice());
+        mTargetDataLoader = mTargetDataLoaderFactory.create(mRequest.isAudioCaptureDevice());
 
         // The last argument of createResolverListAdapter is whether to do special handling
         // of the last used choice to highlight it in the list.  We need to always
diff --git a/java/src/com/android/intentresolver/ResolverListAdapter.java b/java/src/com/android/intentresolver/ResolverListAdapter.java
index fc5514b6..f29553eb 100644
--- a/java/src/com/android/intentresolver/ResolverListAdapter.java
+++ b/java/src/com/android/intentresolver/ResolverListAdapter.java
@@ -404,14 +404,18 @@ public class ResolverListAdapter extends BaseAdapter {
             );
         } else {
             mOtherProfile = null;
-            try {
-                mLastChosen = mResolverListController.getLastChosen();
-                // TODO: does this also somehow need to update mLastChosenPosition? If so, maybe
-                // the current method should also take responsibility for re-initializing
-                // mLastChosenPosition, where it's currently done at the start of rebuildList()?
-                // (Why is this related to the presence of mOtherProfile in fhe first place?)
-            } catch (RemoteException re) {
-                Log.d(TAG, "Error calling getLastChosenActivity\n" + re);
+            // If `mFilterLastUsed` is (`final`) false, we'll never read `mLastChosen`, so don't
+            // bother making the system query.
+            if (mFilterLastUsed) {
+                try {
+                    mLastChosen = mResolverListController.getLastChosen();
+                    // TODO: does this also somehow need to update mLastChosenPosition? If so, maybe
+                    // the current method should also take responsibility for re-initializing
+                    // mLastChosenPosition, where it's currently done at the start of rebuildList()?
+                    // (Why is this related to the presence of mOtherProfile in fhe first place?)
+                } catch (RemoteException re) {
+                    Log.d(TAG, "Error calling getLastChosenActivity\n" + re);
+                }
             }
         }
     }
diff --git a/java/src/com/android/intentresolver/ShortcutSelectionLogic.java b/java/src/com/android/intentresolver/ShortcutSelectionLogic.java
index 2d5ec451..3a1a51e3 100644
--- a/java/src/com/android/intentresolver/ShortcutSelectionLogic.java
+++ b/java/src/com/android/intentresolver/ShortcutSelectionLogic.java
@@ -16,6 +16,8 @@
 
 package com.android.intentresolver;
 
+import static com.android.intentresolver.Flags.rebuildAdaptersOnTargetPinning;
+
 import android.app.prediction.AppTarget;
 import android.content.Context;
 import android.content.Intent;
@@ -171,16 +173,21 @@ public class ShortcutSelectionLogic {
             List<TargetInfo> serviceTargets) {
 
         // Check for duplicates and abort if found
-        for (TargetInfo otherTargetInfo : serviceTargets) {
+        for (int i = 0; i < serviceTargets.size(); i++) {
+            TargetInfo otherTargetInfo = serviceTargets.get(i);
             if (chooserTargetInfo.isSimilar(otherTargetInfo)) {
+                if (rebuildAdaptersOnTargetPinning()
+                        && chooserTargetInfo.isPinned() != otherTargetInfo.isPinned()) {
+                    serviceTargets.set(i, chooserTargetInfo);
+                    return true;
+                }
                 return false;
             }
         }
 
         int currentSize = serviceTargets.size();
         final float newScore = chooserTargetInfo.getModifiedScore();
-        for (int i = 0; i < Math.min(currentSize, maxRankedTargets);
-                i++) {
+        for (int i = 0; i < Math.min(currentSize, maxRankedTargets); i++) {
             final TargetInfo serviceTarget = serviceTargets.get(i);
             if (serviceTarget == null) {
                 serviceTargets.set(i, chooserTargetInfo);
diff --git a/java/src/com/android/intentresolver/SimpleIconFactory.java b/java/src/com/android/intentresolver/SimpleIconFactory.java
index f4871e36..afb7d19e 100644
--- a/java/src/com/android/intentresolver/SimpleIconFactory.java
+++ b/java/src/com/android/intentresolver/SimpleIconFactory.java
@@ -64,7 +64,7 @@ import java.util.Optional;
  * possibly badged. It is intended to be used only by Sharesheet for the Q release with custom code.
  */
 @Deprecated
-public class SimpleIconFactory {
+public class SimpleIconFactory implements AutoCloseable {
 
 
     private static final SynchronizedPool<SimpleIconFactory> sPool =
@@ -139,6 +139,11 @@ public class SimpleIconFactory {
                 "Expected theme to define iconfactoryBadgeSize.");
     }
 
+    @Override
+    public void close() {
+        recycle();
+    }
+
     /**
      * Recycles the SimpleIconFactory so others may use it.
      *
@@ -146,9 +151,11 @@ public class SimpleIconFactory {
      */
     @Deprecated
     public void recycle() {
-        // Return to default background color
-        setWrapperBackgroundColor(Color.WHITE);
-        sPool.release(this);
+        if (sPoolEnabled) {
+            // Return to default background color
+            setWrapperBackgroundColor(Color.WHITE);
+            sPool.release(this);
+        }
     }
 
     /**
diff --git a/java/src/com/android/intentresolver/TargetPresentationGetter.java b/java/src/com/android/intentresolver/TargetPresentationGetter.java
index 910c65c9..3a7f807d 100644
--- a/java/src/com/android/intentresolver/TargetPresentationGetter.java
+++ b/java/src/com/android/intentresolver/TargetPresentationGetter.java
@@ -16,14 +16,12 @@
 
 package com.android.intentresolver;
 
-import android.content.Context;
 import android.content.pm.ActivityInfo;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
 import android.content.res.Resources;
 import android.graphics.Bitmap;
-import android.graphics.drawable.BitmapDrawable;
 import android.graphics.drawable.Drawable;
 import android.os.UserHandle;
 import android.text.TextUtils;
@@ -31,6 +29,8 @@ import android.util.Log;
 
 import androidx.annotation.Nullable;
 
+import javax.inject.Provider;
+
 /**
  * Loads the icon and label for the provided ApplicationInfo. Defaults to using the application icon
  * and label over any IntentFilter or Activity icon to increase user understanding, with an
@@ -49,22 +49,29 @@ public abstract class TargetPresentationGetter {
 
     /** Helper to build appropriate type-specific {@link TargetPresentationGetter} instances. */
     public static class Factory {
-        private final Context mContext;
+        private final Provider<SimpleIconFactory> mIconFactoryProvider;
+        private final PackageManager mPackageManager;
         private final int mIconDpi;
 
-        public Factory(Context context, int iconDpi) {
-            mContext = context;
+        public Factory(
+                Provider<SimpleIconFactory> iconfactoryProvider,
+                PackageManager packageManager,
+                int iconDpi) {
+            mIconFactoryProvider = iconfactoryProvider;
+            mPackageManager = packageManager;
             mIconDpi = iconDpi;
         }
 
         /** Make a {@link TargetPresentationGetter} for an {@link ActivityInfo}. */
         public TargetPresentationGetter makePresentationGetter(ActivityInfo activityInfo) {
-            return new ActivityInfoPresentationGetter(mContext, mIconDpi, activityInfo);
+            return new ActivityInfoPresentationGetter(
+                    mIconFactoryProvider, mPackageManager, mIconDpi, activityInfo);
         }
 
         /** Make a {@link TargetPresentationGetter} for a {@link ResolveInfo}. */
         public TargetPresentationGetter makePresentationGetter(ResolveInfo resolveInfo) {
-            return new ResolveInfoPresentationGetter(mContext, mIconDpi, resolveInfo);
+            return new ResolveInfoPresentationGetter(
+                    mIconFactoryProvider, mPackageManager, mIconDpi, resolveInfo);
         }
     }
 
@@ -77,21 +84,13 @@ public abstract class TargetPresentationGetter {
     @Nullable
     protected abstract String getAppLabelForSubstitutePermission();
 
-    private Context mContext;
+    private final Provider<SimpleIconFactory> mIconFactoryProvider;
     private final int mIconDpi;
     private final boolean mHasSubstitutePermission;
     private final ApplicationInfo mAppInfo;
 
     protected PackageManager mPm;
 
-    /**
-     * Retrieve the image that should be displayed as the icon when this target is presented to the
-     * specified {@code userHandle}.
-     */
-    public Drawable getIcon(UserHandle userHandle) {
-        return new BitmapDrawable(mContext.getResources(), getIconBitmap(userHandle));
-    }
-
     /**
      * Retrieve the image that should be displayed as the icon when this target is presented to the
      * specified {@code userHandle}.
@@ -116,9 +115,10 @@ public abstract class TargetPresentationGetter {
             drawable = mAppInfo.loadIcon(mPm);
         }
 
-        SimpleIconFactory iconFactory = SimpleIconFactory.obtain(mContext);
-        Bitmap icon = iconFactory.createUserBadgedIconBitmap(drawable, userHandle);
-        iconFactory.recycle();
+        Bitmap icon;
+        try (SimpleIconFactory iconFactory = mIconFactoryProvider.get()) {
+            icon = iconFactory.createUserBadgedIconBitmap(drawable, userHandle);
+        }
 
         return icon;
     }
@@ -168,9 +168,13 @@ public abstract class TargetPresentationGetter {
         return res.getDrawableForDensity(resId, mIconDpi);
     }
 
-    private TargetPresentationGetter(Context context, int iconDpi, ApplicationInfo appInfo) {
-        mContext = context;
-        mPm = context.getPackageManager();
+    private TargetPresentationGetter(
+            Provider<SimpleIconFactory> iconfactoryProvider,
+            PackageManager packageManager,
+            int iconDpi,
+            ApplicationInfo appInfo) {
+        mIconFactoryProvider = iconfactoryProvider;
+        mPm = packageManager;
         mAppInfo = appInfo;
         mIconDpi = iconDpi;
         mHasSubstitutePermission = (PackageManager.PERMISSION_GRANTED == mPm.checkPermission(
@@ -183,8 +187,11 @@ public abstract class TargetPresentationGetter {
         private final ResolveInfo mResolveInfo;
 
         ResolveInfoPresentationGetter(
-                Context context, int iconDpi, ResolveInfo resolveInfo) {
-            super(context, iconDpi, resolveInfo.activityInfo);
+                Provider<SimpleIconFactory> iconfactoryProvider,
+                PackageManager packageManager,
+                int iconDpi,
+                ResolveInfo resolveInfo) {
+            super(iconfactoryProvider, packageManager, iconDpi, resolveInfo.activityInfo);
             mResolveInfo = resolveInfo;
         }
 
@@ -230,8 +237,11 @@ public abstract class TargetPresentationGetter {
         private final ActivityInfo mActivityInfo;
 
         ActivityInfoPresentationGetter(
-                Context context, int iconDpi, ActivityInfo activityInfo) {
-            super(context, iconDpi, activityInfo.applicationInfo);
+                Provider<SimpleIconFactory> iconfactoryProvider,
+                PackageManager packageManager,
+                int iconDpi,
+                ActivityInfo activityInfo) {
+            super(iconfactoryProvider, packageManager, iconDpi, activityInfo.applicationInfo);
             mActivityInfo = activityInfo;
         }
 
diff --git a/java/src/com/android/intentresolver/chooser/DisplayResolveInfo.java b/java/src/com/android/intentresolver/chooser/DisplayResolveInfo.java
index 5e44c53e..e641944e 100644
--- a/java/src/com/android/intentresolver/chooser/DisplayResolveInfo.java
+++ b/java/src/com/android/intentresolver/chooser/DisplayResolveInfo.java
@@ -205,6 +205,7 @@ public class DisplayResolveInfo implements TargetInfo {
     @Override
     public boolean startAsCaller(Activity activity, Bundle options, int userId) {
         TargetInfo.prepareIntentForCrossProfileLaunch(mResolvedIntent, userId);
+        TargetInfo.refreshIntentCreatorToken(mResolvedIntent);
         activity.startActivityAsCaller(mResolvedIntent, options, false, userId);
         return true;
     }
@@ -212,6 +213,7 @@ public class DisplayResolveInfo implements TargetInfo {
     @Override
     public boolean startAsUser(Activity activity, Bundle options, UserHandle user) {
         TargetInfo.prepareIntentForCrossProfileLaunch(mResolvedIntent, user.getIdentifier());
+        TargetInfo.refreshIntentCreatorToken(mResolvedIntent);
         // TODO: is this equivalent to `startActivityAsCaller` with `ignoreTargetSecurity=true`? If
         // so, we can consolidate on the one API method to show that this flag is the only
         // distinction between `startAsCaller` and `startAsUser`. We can even bake that flag into
@@ -239,4 +241,11 @@ public class DisplayResolveInfo implements TargetInfo {
     public void setPinned(boolean pinned) {
         mPinned = pinned;
     }
+
+    /**
+     * Creates a copy of the object.
+     */
+    public DisplayResolveInfo copy() {
+        return new DisplayResolveInfo(this);
+    }
 }
diff --git a/java/src/com/android/intentresolver/chooser/SelectableTargetInfo.java b/java/src/com/android/intentresolver/chooser/SelectableTargetInfo.java
index c4aa9021..2658f3e5 100644
--- a/java/src/com/android/intentresolver/chooser/SelectableTargetInfo.java
+++ b/java/src/com/android/intentresolver/chooser/SelectableTargetInfo.java
@@ -229,6 +229,7 @@ public final class SelectableTargetInfo extends ChooserTargetInfo {
                 intent.setComponent(getChooserTargetComponentName());
                 intent.putExtras(mChooserTargetIntentExtras);
                 TargetInfo.prepareIntentForCrossProfileLaunch(intent, userId);
+                TargetInfo.refreshIntentCreatorToken(intent);
 
                 // Important: we will ignore the target security checks in ActivityManager if and
                 // only if the ChooserTarget's target package is the same package where we got the
diff --git a/java/src/com/android/intentresolver/chooser/TargetInfo.java b/java/src/com/android/intentresolver/chooser/TargetInfo.java
index ba6c3c05..0935c6e8 100644
--- a/java/src/com/android/intentresolver/chooser/TargetInfo.java
+++ b/java/src/com/android/intentresolver/chooser/TargetInfo.java
@@ -17,7 +17,10 @@
 package com.android.intentresolver.chooser;
 
 
+import static android.security.Flags.preventIntentRedirect;
+
 import android.app.Activity;
+import android.app.ActivityManager;
 import android.app.prediction.AppTarget;
 import android.content.ComponentName;
 import android.content.Context;
@@ -28,6 +31,7 @@ import android.content.pm.ShortcutInfo;
 import android.content.pm.ShortcutManager;
 import android.graphics.drawable.Drawable;
 import android.os.Bundle;
+import android.os.RemoteException;
 import android.os.UserHandle;
 import android.service.chooser.ChooserTarget;
 import android.text.TextUtils;
@@ -65,7 +69,7 @@ public interface TargetInfo {
          * @param icon the icon to return on subsequent calls to {@link #getDisplayIcon()}.
          * Implementations may discard this request as a no-op if they don't support setting.
          */
-        void setDisplayIcon(Drawable icon);
+        void setDisplayIcon(@Nullable Drawable icon);
     }
 
     /** A simple mutable-container implementation of {@link IconHolder}. */
@@ -78,7 +82,7 @@ public interface TargetInfo {
             return mDisplayIcon;
         }
 
-        public void setDisplayIcon(Drawable icon) {
+        public void setDisplayIcon(@Nullable Drawable icon) {
             mDisplayIcon = icon;
         }
     }
@@ -462,6 +466,22 @@ public interface TargetInfo {
         }
     }
 
+    /**
+     * refreshes intent's creatorToken with its current intent key fields. This allows
+     * ChooserActivity to still keep original creatorToken's creator uid after making changes to
+     * the intent and still keep it valid.
+     * @param intent the intent's creatorToken needs to up refreshed.
+     */
+    static void refreshIntentCreatorToken(Intent intent) {
+        if (!preventIntentRedirect()) return;
+        try {
+            intent.setCreatorToken(ActivityManager.getService().refreshIntentCreatorToken(
+                    intent.cloneForCreatorToken()));
+        } catch (RemoteException e) {
+            throw new RuntimeException("Failure from system", e);
+        }
+    }
+
     /**
      * Derive a "complete" intent from a proposed `refinement` intent by merging it into a matching
      * `base` intent, without modifying the filter-equality properties of the `base` intent, while
diff --git a/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
index 1128ec5d..4166e5ae 100644
--- a/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUi.java
@@ -51,7 +51,6 @@ import java.util.function.Supplier;
 public final class ChooserContentPreviewUi {
 
     private final CoroutineScope mScope;
-    private final boolean mIsPayloadTogglingEnabled;
 
     /**
      * Delegate to build the default system action buttons to display in the preview layout, if/when
@@ -109,11 +108,8 @@ public final class ChooserContentPreviewUi {
             TransitionElementStatusCallback transitionElementStatusCallback,
             HeadlineGenerator headlineGenerator,
             ContentTypeHint contentTypeHint,
-            @Nullable CharSequence metadata,
-            // TODO: replace with the FeatureFlag ref when v1 is gone
-            boolean isPayloadTogglingEnabled) {
+            @Nullable CharSequence metadata) {
         mScope = scope;
-        mIsPayloadTogglingEnabled = isPayloadTogglingEnabled;
         mModifyShareActionFactory = modifyShareActionFactory;
         mContentPreviewUi = createContentPreview(
                 previewData,
@@ -169,7 +165,7 @@ public final class ChooserContentPreviewUi {
             return fileContentPreviewUi;
         }
 
-        if (previewType == CONTENT_PREVIEW_PAYLOAD_SELECTION && mIsPayloadTogglingEnabled) {
+        if (previewType == CONTENT_PREVIEW_PAYLOAD_SELECTION) {
             transitionElementStatusCallback.onAllTransitionElementsReady(); // TODO
             return new ShareouselContentPreviewUi();
         }
diff --git a/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt b/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt
index 9b2dbebf..d7b9077d 100644
--- a/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt
+++ b/java/src/com/android/intentresolver/contentpreview/PreviewDataProvider.kt
@@ -28,11 +28,11 @@ import android.text.TextUtils
 import android.util.Log
 import androidx.annotation.OpenForTesting
 import androidx.annotation.VisibleForTesting
+import com.android.intentresolver.Flags.individualMetadataTitleRead
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_FILE
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_IMAGE
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_PAYLOAD_SELECTION
 import com.android.intentresolver.contentpreview.ContentPreviewType.CONTENT_PREVIEW_TEXT
-import com.android.intentresolver.inject.ChooserServiceFlags
 import com.android.intentresolver.measurements.runTracing
 import com.android.intentresolver.util.ownedByCurrentUser
 import java.util.concurrent.atomic.AtomicInteger
@@ -55,14 +55,19 @@ import kotlinx.coroutines.withTimeoutOrNull
  * A set of metadata columns we read for a content URI (see
  * [PreviewDataProvider.UriRecord.readQueryResult] method).
  */
-@VisibleForTesting
-val METADATA_COLUMNS =
+private val METADATA_COLUMNS =
     arrayOf(
         DocumentsContract.Document.COLUMN_FLAGS,
         MediaMetadata.METADATA_KEY_DISPLAY_ICON_URI,
         OpenableColumns.DISPLAY_NAME,
-        Downloads.Impl.COLUMN_TITLE
+        Downloads.Impl.COLUMN_TITLE,
     )
+
+/** Preview-related metadata columns. */
+@VisibleForTesting
+val ICON_METADATA_COLUMNS =
+    arrayOf(DocumentsContract.Document.COLUMN_FLAGS, MediaMetadata.METADATA_KEY_DISPLAY_ICON_URI)
+
 private const val TIMEOUT_MS = 1_000L
 
 /**
@@ -77,7 +82,6 @@ constructor(
     private val targetIntent: Intent,
     private val additionalContentUri: Uri?,
     private val contentResolver: ContentInterface,
-    private val featureFlags: ChooserServiceFlags,
     private val typeClassifier: MimeTypeClassifier = DefaultMimeTypeClassifier,
 ) {
 
@@ -128,7 +132,7 @@ constructor(
              * IMAGE, FILE, TEXT. */
             if (!targetIntent.isSend || records.isEmpty()) {
                 CONTENT_PREVIEW_TEXT
-            } else if (featureFlags.chooserPayloadToggling() && shouldShowPayloadSelection()) {
+            } else if (shouldShowPayloadSelection()) {
                 // TODO: replace with the proper flags injection
                 CONTENT_PREVIEW_PAYLOAD_SELECTION
             } else {
@@ -141,7 +145,7 @@ constructor(
                     Log.w(
                         ContentPreviewUi.TAG,
                         "An attempt to read preview type from a cancelled scope",
-                        e
+                        e,
                     )
                     CONTENT_PREVIEW_FILE
                 }
@@ -159,7 +163,7 @@ constructor(
                 Log.w(
                     ContentPreviewUi.TAG,
                     "Failed to check URI authorities; no payload toggling",
-                    it
+                    it,
                 )
             }
             .getOrDefault(false)
@@ -183,7 +187,7 @@ constructor(
                     Log.w(
                         ContentPreviewUi.TAG,
                         "An attempt to read first file info from a cancelled scope",
-                        e
+                        e,
                     )
                 }
                 builder.build()
@@ -212,14 +216,20 @@ constructor(
         if (records.isEmpty()) {
             throw IndexOutOfBoundsException("There are no shared URIs")
         }
-        callerScope.launch {
-            val result = scope.async { getFirstFileName() }.await()
-            callback.accept(result)
-        }
+        callerScope.launch { callback.accept(getFirstFileName()) }
     }
 
+    /**
+     * Returns a title for the first shared URI which is read from URI metadata or, if the metadata
+     * is not provided, derived from the URI.
+     */
     @Throws(IndexOutOfBoundsException::class)
-    private fun getFirstFileName(): String {
+    suspend fun getFirstFileName(): String {
+        return scope.async { getFirstFileNameInternal() }.await()
+    }
+
+    @Throws(IndexOutOfBoundsException::class)
+    private fun getFirstFileNameInternal(): String {
         if (records.isEmpty()) throw IndexOutOfBoundsException("There are no shared URIs")
 
         val record = records[0]
@@ -282,16 +292,23 @@ constructor(
             get() = query.supportsThumbnail
 
         val title: String
-            get() = query.title
+            get() = if (individualMetadataTitleRead()) titleFromQuery else query.title
 
         val iconUri: Uri?
             get() = query.iconUri
 
-        private val query by lazy { readQueryResult() }
+        private val query by lazy {
+            readQueryResult(
+                if (individualMetadataTitleRead()) ICON_METADATA_COLUMNS else METADATA_COLUMNS
+            )
+        }
+
+        private val titleFromQuery by lazy {
+            readDisplayNameFromQuery().takeIf { !TextUtils.isEmpty(it) } ?: readTitleFromQuery()
+        }
 
-        private fun readQueryResult(): QueryResult =
-            // TODO: rewrite using methods from UiMetadataHelpers.kt
-            contentResolver.querySafe(uri, METADATA_COLUMNS)?.use { cursor ->
+        private fun readQueryResult(columns: Array<String>): QueryResult =
+            contentResolver.querySafe(uri, columns)?.use { cursor ->
                 if (!cursor.moveToFirst()) return@use null
 
                 var flagColIdx = -1
@@ -329,12 +346,23 @@ constructor(
 
                 QueryResult(supportsThumbnail, title, iconUri)
             } ?: QueryResult()
+
+        private fun readTitleFromQuery(): String = readStringColumn(Downloads.Impl.COLUMN_TITLE)
+
+        private fun readDisplayNameFromQuery(): String =
+            readStringColumn(OpenableColumns.DISPLAY_NAME)
+
+        private fun readStringColumn(column: String): String =
+            contentResolver.querySafe(uri, arrayOf(column))?.use { cursor ->
+                if (!cursor.moveToFirst()) return@use null
+                cursor.readString(column)
+            } ?: ""
     }
 
     private class QueryResult(
         val supportsThumbnail: Boolean = false,
         val title: String = "",
-        val iconUri: Uri? = null
+        val iconUri: Uri? = null,
     )
 }
 
diff --git a/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java b/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
index b12eb8cf..45a0130d 100644
--- a/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
+++ b/java/src/com/android/intentresolver/contentpreview/TextContentPreviewUi.java
@@ -30,10 +30,12 @@ import android.widget.ImageView;
 import android.widget.TextView;
 
 import androidx.annotation.Nullable;
+import androidx.core.view.ViewCompat;
 
 import com.android.intentresolver.ContentTypeHint;
 import com.android.intentresolver.R;
 import com.android.intentresolver.widget.ActionRow;
+import com.android.intentresolver.widget.ViewRoleDescriptionAccessibilityDelegate;
 
 import kotlinx.coroutines.CoroutineScope;
 
@@ -138,10 +140,17 @@ class TextContentPreviewUi extends ContentPreviewUi {
 
         Runnable onCopy = mActionFactory.getCopyButtonRunnable();
         View copyButton = contentPreviewLayout.findViewById(R.id.copy);
-        if (onCopy != null) {
-            copyButton.setOnClickListener((v) -> onCopy.run());
-        } else {
-            copyButton.setVisibility(View.GONE);
+        if (copyButton != null) {
+            if (onCopy != null) {
+                copyButton.setOnClickListener((v) -> onCopy.run());
+                ViewCompat.setAccessibilityDelegate(
+                        copyButton,
+                        new ViewRoleDescriptionAccessibilityDelegate(
+                                layoutInflater.getContext()
+                                        .getString(R.string.role_description_button)));
+            } else {
+                copyButton.setVisibility(View.GONE);
+            }
         }
 
         String headlineText = (mContentTypeHint == ContentTypeHint.ALBUM)
diff --git a/java/src/com/android/intentresolver/contentpreview/UriMetadataHelpers.kt b/java/src/com/android/intentresolver/contentpreview/UriMetadataHelpers.kt
index c532b9a5..80d0e058 100644
--- a/java/src/com/android/intentresolver/contentpreview/UriMetadataHelpers.kt
+++ b/java/src/com/android/intentresolver/contentpreview/UriMetadataHelpers.kt
@@ -22,11 +22,8 @@ import android.media.MediaMetadata
 import android.net.Uri
 import android.provider.DocumentsContract
 import android.provider.DocumentsContract.Document.FLAG_SUPPORTS_THUMBNAIL
-import android.provider.Downloads
 import android.provider.MediaStore.MediaColumns.HEIGHT
 import android.provider.MediaStore.MediaColumns.WIDTH
-import android.provider.OpenableColumns
-import android.text.TextUtils
 import android.util.Log
 import android.util.Size
 import com.android.intentresolver.measurements.runTracing
@@ -78,12 +75,7 @@ internal fun Cursor.readSupportsThumbnail(): Boolean =
         .getOrDefault(false)
 
 internal fun Cursor.readPreviewUri(): Uri? =
-    runCatching {
-            columnNames
-                .indexOf(MediaMetadata.METADATA_KEY_DISPLAY_ICON_URI)
-                .takeIf { it >= 0 }
-                ?.let { getString(it)?.let(Uri::parse) }
-        }
+    runCatching { readString(MediaMetadata.METADATA_KEY_DISPLAY_ICON_URI)?.let(Uri::parse) }
         .getOrNull()
 
 fun Cursor.readSize(): Size? {
@@ -105,34 +97,15 @@ fun Cursor.readSize(): Size? {
     }
 }
 
-internal fun Cursor.readTitle(): String =
-    runCatching {
-            var nameColIndex = -1
-            var titleColIndex = -1
-            // TODO: double-check why Cursor#getColumnInded didn't work
-            columnNames.forEachIndexed { i, columnName ->
-                when (columnName) {
-                    OpenableColumns.DISPLAY_NAME -> nameColIndex = i
-                    Downloads.Impl.COLUMN_TITLE -> titleColIndex = i
-                }
-            }
-
-            var title = ""
-            if (nameColIndex >= 0) {
-                title = getString(nameColIndex) ?: ""
-            }
-            if (TextUtils.isEmpty(title) && titleColIndex >= 0) {
-                title = getString(titleColIndex) ?: ""
-            }
-            title
-        }
-        .getOrDefault("")
+internal fun Cursor.readString(columnName: String): String? =
+    runCatching { columnNames.indexOf(columnName).takeIf { it >= 0 }?.let { getString(it) } }
+        .getOrNull()
 
 private fun logProviderPermissionWarning(uri: Uri, dataName: String) {
     // The ContentResolver already logs the exception. Log something more informative.
     Log.w(
         ContentPreviewUi.TAG,
         "Could not read $uri $dataName. If a preview is desired, call Intent#setClipData() to" +
-            " ensure that the sharesheet is given permission."
+            " ensure that the sharesheet is given permission.",
     )
 }
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractor.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractor.kt
index 7d658209..59e7e15e 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractor.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractor.kt
@@ -30,6 +30,7 @@ import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.expa
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.numLoadedPages
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.shiftWindowLeft
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.shiftWindowRight
+import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewKey
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.inject.FocusedItemIndex
 import com.android.intentresolver.util.cursor.CursorView
@@ -82,16 +83,19 @@ constructor(
                 .toMap(ConcurrentHashMap())
         val pagedCursor: PagedCursor<CursorRow?> = uriCursor.paged(pageSize)
         val startPosition = uriCursor.extras?.getInt(POSITION, 0) ?: 0
+
         val state =
             loadToMaxPages(
-                initialState = readInitialState(pagedCursor, startPosition, unclaimedRecords),
+                startPosition = startPosition,
+                initialState = readInitialState(startPosition, pagedCursor, unclaimedRecords),
                 pagedCursor = pagedCursor,
                 unclaimedRecords = unclaimedRecords,
             )
-        processLoadRequests(state, pagedCursor, unclaimedRecords)
+        processLoadRequests(startPosition, state, pagedCursor, unclaimedRecords)
     }
 
     private suspend fun loadToMaxPages(
+        startPosition: Int,
         initialState: CursorWindow,
         pagedCursor: PagedCursor<CursorRow?>,
         unclaimedRecords: MutableUnclaimedMap,
@@ -102,7 +106,7 @@ constructor(
             val (leftTriggerIndex, rightTriggerIndex) = state.triggerIndices()
             interactor.setPreviews(
                 previews = state.merged.values.toList(),
-                startIndex = startPageNum,
+                startIndex = state.startIndex,
                 hasMoreLeft = state.hasMoreLeft,
                 hasMoreRight = state.hasMoreRight,
                 leftTriggerIndex = leftTriggerIndex,
@@ -113,9 +117,10 @@ constructor(
             state =
                 when {
                     state.hasMoreLeft && loadedLeft < loadedRight ->
-                        state.loadMoreLeft(pagedCursor, unclaimedRecords)
-                    state.hasMoreRight -> state.loadMoreRight(pagedCursor, unclaimedRecords)
-                    else -> state.loadMoreLeft(pagedCursor, unclaimedRecords)
+                        state.loadMoreLeft(startPosition, pagedCursor, unclaimedRecords)
+                    state.hasMoreRight ->
+                        state.loadMoreRight(startPosition, pagedCursor, unclaimedRecords)
+                    else -> state.loadMoreLeft(startPosition, pagedCursor, unclaimedRecords)
                 }
         }
         return state
@@ -123,6 +128,7 @@ constructor(
 
     /** Loop forever, processing any loading requests from the UI and updating local cache. */
     private suspend fun processLoadRequests(
+        startPosition: Int,
         initialState: CursorWindow,
         pagedCursor: PagedCursor<CursorRow?>,
         unclaimedRecords: MutableUnclaimedMap,
@@ -138,13 +144,19 @@ constructor(
             val loadingState: Flow<LoadDirection?> =
                 interactor.setPreviews(
                     previews = state.merged.values.toList(),
-                    startIndex = 0, // TODO: actually track this as the window changes?
+                    startIndex = state.startIndex,
                     hasMoreLeft = state.hasMoreLeft,
                     hasMoreRight = state.hasMoreRight,
                     leftTriggerIndex = leftTriggerIndex,
                     rightTriggerIndex = rightTriggerIndex,
                 )
-            state = loadingState.handleOneLoadRequest(state, pagedCursor, unclaimedRecords)
+            state =
+                loadingState.handleOneLoadRequest(
+                    startPosition,
+                    state,
+                    pagedCursor,
+                    unclaimedRecords,
+                )
         }
     }
 
@@ -153,6 +165,7 @@ constructor(
      * with the loaded data incorporated.
      */
     private suspend fun Flow<LoadDirection?>.handleOneLoadRequest(
+        startPosition: Int,
         state: CursorWindow,
         pagedCursor: PagedCursor<CursorRow?>,
         unclaimedRecords: MutableUnclaimedMap,
@@ -160,8 +173,10 @@ constructor(
         mapLatest { loadDirection ->
                 loadDirection?.let {
                     when (loadDirection) {
-                        LoadDirection.Left -> state.loadMoreLeft(pagedCursor, unclaimedRecords)
-                        LoadDirection.Right -> state.loadMoreRight(pagedCursor, unclaimedRecords)
+                        LoadDirection.Left ->
+                            state.loadMoreLeft(startPosition, pagedCursor, unclaimedRecords)
+                        LoadDirection.Right ->
+                            state.loadMoreRight(startPosition, pagedCursor, unclaimedRecords)
                     }
                 }
             }
@@ -169,12 +184,12 @@ constructor(
             .first()
 
     /**
-     * Returns the initial [CursorWindow], with a single page loaded that contains the given
+     * Returns the initial [CursorWindow], with a single page loaded that contains the
      * [startPosition].
      */
     private suspend fun readInitialState(
-        cursor: PagedCursor<CursorRow?>,
         startPosition: Int,
+        cursor: PagedCursor<CursorRow?>,
         unclaimedRecords: MutableUnclaimedMap,
     ): CursorWindow {
         val startPageIdx = startPosition / pageSize
@@ -184,13 +199,15 @@ constructor(
             if (!hasMoreLeft) {
                 // First read the initial page; this might claim some unclaimed Uris
                 val page =
-                    cursor.getPageRows(startPageIdx)?.toPage(mutableMapOf(), unclaimedRecords)
+                    cursor
+                        .getPageRows(startPageIdx)
+                        ?.toPage(startPosition, mutableMapOf(), unclaimedRecords)
                 // Now that unclaimed Uris are up-to-date, add them first.
                 putAllUnclaimedLeft(unclaimedRecords)
                 // Then add the loaded page
                 page?.let(::putAll)
             } else {
-                cursor.getPageRows(startPageIdx)?.toPage(this, unclaimedRecords)
+                cursor.getPageRows(startPageIdx)?.toPage(startPosition, this, unclaimedRecords)
             }
             // Finally, add the remainder of the unclaimed Uris.
             if (!hasMoreRight) {
@@ -198,6 +215,7 @@ constructor(
             }
         }
         return CursorWindow(
+            startIndex = startPosition % pageSize,
             firstLoadedPageNum = startPageIdx,
             lastLoadedPageNum = startPageIdx,
             pages = listOf(page.keys),
@@ -208,13 +226,14 @@ constructor(
     }
 
     private suspend fun CursorWindow.loadMoreRight(
+        startPosition: Int,
         cursor: PagedCursor<CursorRow?>,
         unclaimedRecords: MutableUnclaimedMap,
     ): CursorWindow {
         val pageNum = lastLoadedPageNum + 1
         val hasMoreRight = pageNum < cursor.count - 1
         val newPage: PreviewMap = buildMap {
-            readAndPutPage(this@loadMoreRight, cursor, pageNum, unclaimedRecords)
+            readAndPutPage(startPosition, this@loadMoreRight, cursor, pageNum, unclaimedRecords)
             if (!hasMoreRight) {
                 putAllUnclaimedRight(unclaimedRecords)
             }
@@ -227,6 +246,7 @@ constructor(
     }
 
     private suspend fun CursorWindow.loadMoreLeft(
+        startPosition: Int,
         cursor: PagedCursor<CursorRow?>,
         unclaimedRecords: MutableUnclaimedMap,
     ): CursorWindow {
@@ -235,13 +255,14 @@ constructor(
         val newPage: PreviewMap = buildMap {
             if (!hasMoreLeft) {
                 // First read the page; this might claim some unclaimed Uris
-                val page = readPage(this@loadMoreLeft, cursor, pageNum, unclaimedRecords)
+                val page =
+                    readPage(startPosition, this@loadMoreLeft, cursor, pageNum, unclaimedRecords)
                 // Now that unclaimed URIs are up-to-date, add them first
                 putAllUnclaimedLeft(unclaimedRecords)
                 // Then add the loaded page
                 putAll(page)
             } else {
-                readAndPutPage(this@loadMoreLeft, cursor, pageNum, unclaimedRecords)
+                readAndPutPage(startPosition, this@loadMoreLeft, cursor, pageNum, unclaimedRecords)
             }
         }
         return if (numLoadedPages < maxLoadedPages) {
@@ -259,15 +280,17 @@ constructor(
     }
 
     private suspend fun readPage(
+        startPosition: Int,
         state: CursorWindow,
         pagedCursor: PagedCursor<CursorRow?>,
         pageNum: Int,
         unclaimedRecords: MutableUnclaimedMap,
     ): PreviewMap =
-        mutableMapOf<Uri, PreviewModel>()
-            .readAndPutPage(state, pagedCursor, pageNum, unclaimedRecords)
+        mutableMapOf<PreviewKey, PreviewModel>()
+            .readAndPutPage(startPosition, state, pagedCursor, pageNum, unclaimedRecords)
 
     private suspend fun <M : MutablePreviewMap> M.readAndPutPage(
+        startPosition: Int,
         state: CursorWindow,
         pagedCursor: PagedCursor<CursorRow?>,
         pageNum: Int,
@@ -275,19 +298,23 @@ constructor(
     ): M =
         pagedCursor
             .getPageRows(pageNum) // TODO: what do we do if the load fails?
-            ?.filter { it.uri !in state.merged }
-            ?.toPage(this, unclaimedRecords) ?: this
+            ?.filter { PreviewKey.final(it.position - startPosition) !in state.merged }
+            ?.toPage(startPosition, this, unclaimedRecords) ?: this
 
     private suspend fun <M : MutablePreviewMap> Sequence<CursorRow>.toPage(
+        startPosition: Int,
         destination: M,
         unclaimedRecords: MutableUnclaimedMap,
     ): M =
         // Restrict parallelism so as to not overload the metadata reader; anecdotally, too
         // many parallel queries causes failures.
-        mapParallel(parallelism = 4) { row -> createPreviewModel(row, unclaimedRecords) }
-            .associateByTo(destination) { it.uri }
+        mapParallel(parallelism = 4) { row ->
+                createPreviewModel(startPosition, row, unclaimedRecords)
+            }
+            .associateByTo(destination) { it.key }
 
     private fun createPreviewModel(
+        startPosition: Int,
         row: CursorRow,
         unclaimedRecords: MutableUnclaimedMap,
     ): PreviewModel =
@@ -298,6 +325,7 @@ constructor(
                     row.previewSize
                         ?: metadata.previewUri?.let { uriMetadataReader.readPreviewSize(it) }
                 PreviewModel(
+                    key = PreviewKey.final(row.position - startPosition),
                     uri = row.uri,
                     previewUri = metadata.previewUri,
                     mimeType = metadata.mimeType,
@@ -308,11 +336,9 @@ constructor(
             .also { updated ->
                 if (unclaimedRecords.remove(row.uri) != null) {
                     // unclaimedRecords contains initially shared (and thus selected) items with
-                    // unknown
-                    // cursor position. Update selection records when any of those items is
-                    // encountered
-                    // in the cursor to maintain proper selection order should other items also be
-                    // selected.
+                    // unknown cursor position. Update selection records when any of those items is
+                    // encountered in the cursor to maintain proper selection order should other
+                    // items also be selected.
                     selectionInteractor.updateSelection(updated)
                 }
             }
@@ -324,7 +350,7 @@ constructor(
         putAllUnclaimedWhere(unclaimed) { it < focusedItemIdx }
 }
 
-private typealias CursorWindow = LoadedWindow<Uri, PreviewModel>
+private typealias CursorWindow = LoadedWindow<PreviewKey, PreviewModel>
 
 /**
  * Values from the initial selection set that have not yet appeared within the Cursor. These values
@@ -336,9 +362,13 @@ private typealias UnclaimedMap = Map<Uri, Pair<Int, PreviewModel>>
 /** Mutable version of [UnclaimedMap]. */
 private typealias MutableUnclaimedMap = MutableMap<Uri, Pair<Int, PreviewModel>>
 
-private typealias MutablePreviewMap = MutableMap<Uri, PreviewModel>
+private typealias UnkeyedMap = Map<Uri, PreviewModel>
+
+private typealias MutableUnkeyedMap = MutableMap<Uri, PreviewModel>
+
+private typealias MutablePreviewMap = MutableMap<PreviewKey, PreviewModel>
 
-private typealias PreviewMap = Map<Uri, PreviewModel>
+private typealias PreviewMap = Map<PreviewKey, PreviewModel>
 
 private fun <M : MutablePreviewMap> M.putAllUnclaimedWhere(
     unclaimedRecords: UnclaimedMap,
@@ -347,7 +377,7 @@ private fun <M : MutablePreviewMap> M.putAllUnclaimedWhere(
     unclaimedRecords
         .asSequence()
         .filter { predicate(it.value.first) }
-        .map { it.key to it.value.second }
+        .map { (_, value) -> value.second.key to value.second }
         .toMap(this)
 
 private fun PagedCursor<CursorRow?>.getPageRows(pageNum: Int): Sequence<CursorRow>? =
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/FetchPreviewsInteractor.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/FetchPreviewsInteractor.kt
index 50086a23..1fd69351 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/FetchPreviewsInteractor.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/FetchPreviewsInteractor.kt
@@ -22,6 +22,7 @@ import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.P
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor.CursorResolver
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor.PayloadToggle
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.CursorRow
+import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewKey
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.inject.ContentUris
 import com.android.intentresolver.inject.FocusedItemIndex
@@ -64,6 +65,12 @@ constructor(
             .mapParallelIndexed(parallelism = 4) { index, uri ->
                 val metadata = uriMetadataReader.getMetadata(uri)
                 PreviewModel(
+                    key =
+                        if (index == focusedItemIdx) {
+                            PreviewKey.final(0)
+                        } else {
+                            PreviewKey.temp(index)
+                        },
                     uri = uri,
                     previewUri = metadata.previewUri,
                     mimeType = metadata.mimeType,
@@ -71,11 +78,12 @@ constructor(
                         metadata.previewUri?.let {
                             uriMetadataReader.readPreviewSize(it).aspectRatioOrDefault(1f)
                         } ?: 1f,
-                    order = when {
-                        index < focusedItemIdx -> Int.MIN_VALUE + index
-                        index == focusedItemIdx -> 0
-                        else -> Int.MAX_VALUE - selectedItems.size + index + 1
-                    }
+                    order =
+                        when {
+                            index < focusedItemIdx -> Int.MIN_VALUE + index
+                            index == focusedItemIdx -> 0
+                            else -> Int.MAX_VALUE - selectedItems.size + index + 1
+                        },
                 )
             }
 }
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractor.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractor.kt
index 4fe5e8d5..fc193eca 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractor.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/UpdateChooserRequestInteractor.kt
@@ -17,14 +17,13 @@
 package com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor
 
 import android.content.Intent
-import com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.CustomAction
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.PendingIntentSender
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.toCustomActionModel
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ShareouselUpdate
-import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.getOrDefault
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.onValue
 import com.android.intentresolver.data.repository.ChooserRequestRepository
+import com.android.intentresolver.domain.updateWith
 import javax.inject.Inject
 import kotlinx.coroutines.flow.update
 
@@ -36,28 +35,7 @@ constructor(
     @CustomAction private val pendingIntentSender: PendingIntentSender,
 ) {
     fun applyUpdate(targetIntent: Intent, update: ShareouselUpdate) {
-        repository.chooserRequest.update { current ->
-            current.copy(
-                targetIntent = targetIntent,
-                callerChooserTargets =
-                    update.callerTargets.getOrDefault(current.callerChooserTargets),
-                modifyShareAction =
-                    update.modifyShareAction.getOrDefault(current.modifyShareAction),
-                additionalTargets = update.alternateIntents.getOrDefault(current.additionalTargets),
-                chosenComponentSender =
-                    update.resultIntentSender.getOrDefault(current.chosenComponentSender),
-                refinementIntentSender =
-                    update.refinementIntentSender.getOrDefault(current.refinementIntentSender),
-                metadataText = update.metadataText.getOrDefault(current.metadataText),
-                chooserActions = update.customActions.getOrDefault(current.chooserActions),
-                filteredComponentNames =
-                    if (shareouselUpdateExcludeComponentsExtra()) {
-                        update.excludeComponents.getOrDefault(current.filteredComponentNames)
-                    } else {
-                        current.filteredComponentNames
-                    }
-            )
-        }
+        repository.chooserRequest.update { it.updateWith(targetIntent, update) }
         update.customActions.onValue { actions ->
             repository.customActions.value =
                 actions.map { it.toCustomActionModel(pendingIntentSender) }
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/model/LoadedWindow.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/model/LoadedWindow.kt
index e2e69852..5e34b178 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/model/LoadedWindow.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/model/LoadedWindow.kt
@@ -18,6 +18,8 @@ package com.android.intentresolver.contentpreview.payloadtoggle.domain.model
 
 /** A window of data loaded from a cursor. */
 data class LoadedWindow<K, V>(
+    /** The index position of the item that should be displayed initially. */
+    val startIndex: Int,
     /** First cursor page index loaded within this window. */
     val firstLoadedPageNum: Int,
     /** Last cursor page index loaded within this window. */
@@ -42,6 +44,7 @@ fun <K, V> LoadedWindow<K, V>.shiftWindowRight(
     hasMore: Boolean,
 ): LoadedWindow<K, V> =
     LoadedWindow(
+        startIndex = startIndex - newPage.size,
         firstLoadedPageNum = firstLoadedPageNum + 1,
         lastLoadedPageNum = lastLoadedPageNum + 1,
         pages = pages.drop(1) + listOf(newPage.keys),
@@ -61,6 +64,7 @@ fun <K, V> LoadedWindow<K, V>.expandWindowRight(
     hasMore: Boolean,
 ): LoadedWindow<K, V> =
     LoadedWindow(
+        startIndex = startIndex,
         firstLoadedPageNum = firstLoadedPageNum,
         lastLoadedPageNum = lastLoadedPageNum + 1,
         pages = pages + listOf(newPage.keys),
@@ -75,6 +79,7 @@ fun <K, V> LoadedWindow<K, V>.shiftWindowLeft(
     hasMore: Boolean,
 ): LoadedWindow<K, V> =
     LoadedWindow(
+        startIndex = startIndex + newPage.size,
         firstLoadedPageNum = firstLoadedPageNum - 1,
         lastLoadedPageNum = lastLoadedPageNum - 1,
         pages = listOf(newPage.keys) + pages.dropLast(1),
@@ -93,6 +98,7 @@ fun <K, V> LoadedWindow<K, V>.expandWindowLeft(
     hasMore: Boolean,
 ): LoadedWindow<K, V> =
     LoadedWindow(
+        startIndex = startIndex + newPage.size,
         firstLoadedPageNum = firstLoadedPageNum - 1,
         lastLoadedPageNum = lastLoadedPageNum,
         pages = listOf(newPage.keys) + pages,
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/shared/model/PreviewKey.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/shared/model/PreviewKey.kt
new file mode 100644
index 00000000..6b42133e
--- /dev/null
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/shared/model/PreviewKey.kt
@@ -0,0 +1,49 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.intentresolver.contentpreview.payloadtoggle.shared.model
+
+/** Unique identifier for preview items. */
+sealed interface PreviewKey {
+
+    private data class Temp(override val key: Int, override val isFinal: Boolean = false) :
+        PreviewKey
+
+    private data class Final(override val key: Int, override val isFinal: Boolean = true) :
+        PreviewKey
+
+    /** The identifier, must be unique among like keys types */
+    val key: Int
+    /** Whether this key is final or temporary. */
+    val isFinal: Boolean
+
+    companion object {
+        /**
+         * Creates a temporary key.
+         *
+         * This is used for the initial preview items until final keys can be generated, at which
+         * point it is replaced with a final key.
+         */
+        fun temp(key: Int): PreviewKey = Temp(key)
+
+        /**
+         * Creates a final key.
+         *
+         * This is used for all preview items other than the initial preview items.
+         */
+        fun final(key: Int): PreviewKey = Final(key)
+    }
+}
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/shared/model/PreviewModel.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/shared/model/PreviewModel.kt
index 8a479156..d4df8a3a 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/shared/model/PreviewModel.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/shared/model/PreviewModel.kt
@@ -20,6 +20,8 @@ import android.net.Uri
 
 /** An individual preview presented in Shareousel. */
 data class PreviewModel(
+    /** Unique identifier for this model. */
+    val key: PreviewKey,
     /** Uri for this item; if this preview is selected, this will be shared with the target app. */
     val uri: Uri,
     /** Uri for the preview image. */
@@ -28,7 +30,8 @@ data class PreviewModel(
     val mimeType: String?,
     val aspectRatio: Float = 1f,
     /**
-     * Relative item position in the list that is used to determine items order in the target intent
+     * Relative item position in the list that is used to determine items order in the target
+     * intent.
      */
     val order: Int,
 )
diff --git a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
index 4b87d227..c51021a8 100644
--- a/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
+++ b/java/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/composable/ShareouselComposable.kt
@@ -33,9 +33,9 @@ import androidx.compose.foundation.layout.height
 import androidx.compose.foundation.layout.padding
 import androidx.compose.foundation.layout.size
 import androidx.compose.foundation.layout.width
+import androidx.compose.foundation.lazy.LazyListState
 import androidx.compose.foundation.lazy.LazyRow
 import androidx.compose.foundation.lazy.itemsIndexed
-import androidx.compose.foundation.lazy.rememberLazyListState
 import androidx.compose.foundation.selection.toggleable
 import androidx.compose.foundation.shape.RoundedCornerShape
 import androidx.compose.foundation.systemGestureExclusion
@@ -57,11 +57,14 @@ import androidx.compose.ui.draw.clip
 import androidx.compose.ui.graphics.ColorFilter
 import androidx.compose.ui.graphics.asImageBitmap
 import androidx.compose.ui.layout.ContentScale
+import androidx.compose.ui.layout.MeasureScope
+import androidx.compose.ui.layout.Placeable
 import androidx.compose.ui.layout.layout
 import androidx.compose.ui.res.dimensionResource
 import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.semantics.contentDescription
 import androidx.compose.ui.semantics.semantics
+import androidx.compose.ui.unit.Dp
 import androidx.compose.ui.unit.dp
 import androidx.lifecycle.compose.collectAsStateWithLifecycle
 import com.android.intentresolver.Flags.shareouselScrollOffscreenSelections
@@ -70,11 +73,13 @@ import com.android.intentresolver.R
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.getOrDefault
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.ContentType
+import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewsModel
 import com.android.intentresolver.contentpreview.payloadtoggle.ui.viewmodel.ShareouselPreviewViewModel
 import com.android.intentresolver.contentpreview.payloadtoggle.ui.viewmodel.ShareouselViewModel
 import kotlin.math.abs
 import kotlin.math.min
+import kotlin.math.roundToInt
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.launch
 
@@ -96,7 +101,7 @@ private fun Shareousel(viewModel: ShareouselViewModel, keySet: PreviewsModel) {
     Column(
         modifier =
             Modifier.background(MaterialTheme.colorScheme.surfaceContainer)
-                .padding(vertical = 16.dp),
+                .padding(vertical = 16.dp)
     ) {
         PreviewCarousel(keySet, viewModel)
         ActionCarousel(viewModel)
@@ -105,59 +110,52 @@ private fun Shareousel(viewModel: ShareouselViewModel, keySet: PreviewsModel) {
 
 @OptIn(ExperimentalFoundationApi::class)
 @Composable
-private fun PreviewCarousel(
-    previews: PreviewsModel,
-    viewModel: ShareouselViewModel,
-) {
-    var maxAspectRatio by remember { mutableStateOf(0f) }
-    var viewportHeight by remember { mutableStateOf(0) }
-    var viewportCenter by remember { mutableStateOf(0) }
-    var horizontalPadding by remember { mutableStateOf(0.dp) }
+private fun PreviewCarousel(previews: PreviewsModel, viewModel: ShareouselViewModel) {
+    var measurements by remember { mutableStateOf(PreviewCarouselMeasurements.UNMEASURED) }
     Box(
         modifier =
             Modifier.fillMaxWidth()
                 .height(dimensionResource(R.dimen.chooser_preview_image_height_tall))
                 .layout { measurable, constraints ->
                     val placeable = measurable.measure(constraints)
-                    val (minItemWidth, maxAR) =
+                    measurements =
                         if (placeable.height <= 0) {
-                            0f to 0f
+                            PreviewCarouselMeasurements.UNMEASURED
                         } else {
-                            val minItemWidth = (MIN_ASPECT_RATIO * placeable.height)
-                            val maxItemWidth = maxOf(0, placeable.width - 32.dp.roundToPx())
-                            val maxAR =
-                                (maxItemWidth.toFloat() / placeable.height).coerceIn(
-                                    0f,
-                                    MAX_ASPECT_RATIO
-                                )
-                            minItemWidth to maxAR
+                            PreviewCarouselMeasurements(placeable, measureScope = this)
                         }
-                    viewportCenter = placeable.width / 2
-                    maxAspectRatio = maxAR
-                    viewportHeight = placeable.height
-                    horizontalPadding = ((placeable.width - minItemWidth) / 2).toDp()
                     layout(placeable.width, placeable.height) { placeable.place(0, 0) }
-                },
+                }
     ) {
-        if (maxAspectRatio <= 0 && previews.previewModels.isNotEmpty()) {
-            // Do not compose the list until we know the viewport size
-            return@Box
-        }
-
-        var firstSelectedIndex by remember { mutableStateOf(null as Int?) }
+        // Do not compose the list until we have measured values
+        if (measurements == PreviewCarouselMeasurements.UNMEASURED) return@Box
 
-        val carouselState =
-            rememberLazyListState(
-                prefetchStrategy = remember { ShareouselLazyListPrefetchStrategy() },
+        val prefetchStrategy = remember { ShareouselLazyListPrefetchStrategy() }
+        val carouselState = remember {
+            LazyListState(
+                prefetchStrategy = prefetchStrategy,
+                firstVisibleItemIndex = previews.startIdx,
+                firstVisibleItemScrollOffset =
+                    measurements.scrollOffsetToCenter(
+                        previewModel = previews.previewModels[previews.startIdx]
+                    ),
             )
+        }
 
         LazyRow(
             state = carouselState,
             horizontalArrangement = Arrangement.spacedBy(4.dp),
-            contentPadding = PaddingValues(start = horizontalPadding, end = horizontalPadding),
+            contentPadding =
+                PaddingValues(
+                    start = measurements.horizontalPaddingDp,
+                    end = measurements.horizontalPaddingDp,
+                ),
             modifier = Modifier.fillMaxSize().systemGestureExclusion(),
         ) {
-            itemsIndexed(previews.previewModels, key = { _, model -> model.uri }) { index, model ->
+            itemsIndexed(
+                items = previews.previewModels,
+                key = { _, model -> model.key.key to model.key.isFinal },
+            ) { index, model ->
                 val visibleItem by remember {
                     derivedStateOf {
                         carouselState.layoutInfo.visibleItemsInfo.firstOrNull { it.index == index }
@@ -171,7 +169,7 @@ private fun PreviewCarousel(
                             val halfPreviewWidth = it.size / 2
                             val previewCenter = it.offset + halfPreviewWidth
                             val previewDistanceToViewportCenter =
-                                abs(previewCenter - viewportCenter)
+                                abs(previewCenter - measurements.viewportCenterPx)
                             if (previewDistanceToViewportCenter <= halfPreviewWidth) {
                                 index
                             } else {
@@ -182,13 +180,12 @@ private fun PreviewCarousel(
                 }
 
                 val previewModel =
-                    viewModel.preview(model, viewportHeight, previewIndex, rememberCoroutineScope())
-                val selected by
-                    previewModel.isSelected.collectAsStateWithLifecycle(initialValue = false)
-
-                if (selected) {
-                    firstSelectedIndex = min(index, firstSelectedIndex ?: Int.MAX_VALUE)
-                }
+                    viewModel.preview(
+                        /* key = */ model,
+                        /* previewHeight = */ measurements.viewportHeightPx,
+                        /* index = */ previewIndex,
+                        /* scope = */ rememberCoroutineScope(),
+                    )
 
                 if (shareouselScrollOffscreenSelections()) {
                     LaunchedEffect(index, model.uri) {
@@ -209,10 +206,10 @@ private fun PreviewCarousel(
                                                 when {
                                                     // Item is partially past start of viewport
                                                     item.offset < viewportStartOffset ->
-                                                        -viewportStartOffset
+                                                        measurements.scrollOffsetToStartEdge()
                                                     // Item is partially past end of viewport
                                                     (item.offset + item.size) > viewportEndOffset ->
-                                                        item.size - viewportEndOffset
+                                                        measurements.scrollOffsetToEndEdge(model)
                                                     // Item is fully within viewport
                                                     else -> null
                                                 }?.let { scrollOffset ->
@@ -230,29 +227,8 @@ private fun PreviewCarousel(
                 }
 
                 ShareouselCard(
-                    viewModel.preview(
-                        model,
-                        viewportHeight,
-                        previewIndex,
-                        rememberCoroutineScope()
-                    ),
-                    maxAspectRatio,
-                )
-            }
-        }
-
-        firstSelectedIndex?.let { index ->
-            LaunchedEffect(Unit) {
-                val visibleItem =
-                    carouselState.layoutInfo.visibleItemsInfo.firstOrNull { it.index == index }
-                val center =
-                    with(carouselState.layoutInfo) {
-                        ((viewportEndOffset - viewportStartOffset) / 2) + viewportStartOffset
-                    }
-
-                carouselState.scrollToItem(
-                    index = index,
-                    scrollOffset = visibleItem?.size?.div(2)?.minus(center) ?: 0,
+                    viewModel = previewModel,
+                    aspectRatio = measurements.coerceAspectRatio(previewModel.aspectRatio),
                 )
             }
         }
@@ -260,7 +236,7 @@ private fun PreviewCarousel(
 }
 
 @Composable
-private fun ShareouselCard(viewModel: ShareouselPreviewViewModel, maxAspectRatio: Float) {
+private fun ShareouselCard(viewModel: ShareouselPreviewViewModel, aspectRatio: Float) {
     val bitmapLoadState by viewModel.bitmapLoadState.collectAsStateWithLifecycle()
     val selected by viewModel.isSelected.collectAsStateWithLifecycle(initialValue = false)
     val borderColor = MaterialTheme.colorScheme.primary
@@ -279,9 +255,8 @@ private fun ShareouselCard(viewModel: ShareouselPreviewViewModel, maxAspectRatio
                 .toggleable(
                     value = selected,
                     onValueChange = { scope.launch { viewModel.setSelected(it) } },
-                )
+                ),
     ) { state ->
-        val aspectRatio = minOf(maxAspectRatio, maxOf(MIN_ASPECT_RATIO, viewModel.aspectRatio))
         if (state is ValueUpdate.Value) {
             state.getOrDefault(null).let { bitmap ->
                 ShareouselCard(
@@ -304,7 +279,7 @@ private fun ShareouselCard(viewModel: ShareouselPreviewViewModel, maxAspectRatio
                                 color = borderColor,
                                 shape = RoundedCornerShape(size = 12.dp),
                             )
-                        }
+                        },
                 )
             }
         } else {
@@ -355,7 +330,7 @@ private fun ActionCarousel(viewModel: ShareouselViewModel) {
                             Image(
                                 icon = it,
                                 modifier = Modifier.size(16.dp),
-                                colorFilter = ColorFilter.tint(LocalContentColor.current)
+                                colorFilter = ColorFilter.tint(LocalContentColor.current),
                             )
                         }
                     }
@@ -389,7 +364,7 @@ private fun ShareouselAction(
             AssistChipDefaults.assistChipColors(
                 containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                 labelColor = MaterialTheme.colorScheme.onSurface,
-                leadingIconContentColor = MaterialTheme.colorScheme.onSurface
+                leadingIconContentColor = MaterialTheme.colorScheme.onSurface,
             ),
         modifier = modifier,
     )
@@ -398,5 +373,57 @@ private fun ShareouselAction(
 inline fun Modifier.thenIf(condition: Boolean, crossinline factory: () -> Modifier): Modifier =
     if (condition) this.then(factory()) else this
 
-private const val MIN_ASPECT_RATIO = 0.4f
-private const val MAX_ASPECT_RATIO = 2.5f
+private data class PreviewCarouselMeasurements(
+    val viewportHeightPx: Int,
+    val viewportWidthPx: Int,
+    val viewportCenterPx: Int = viewportWidthPx / 2,
+    val maxAspectRatio: Float,
+    val horizontalPaddingPx: Int,
+    val horizontalPaddingDp: Dp,
+) {
+    constructor(
+        placeable: Placeable,
+        measureScope: MeasureScope,
+        horizontalPadding: Float = (placeable.width - (MIN_ASPECT_RATIO * placeable.height)) / 2,
+    ) : this(
+        viewportHeightPx = placeable.height,
+        viewportWidthPx = placeable.width,
+        maxAspectRatio =
+            with(measureScope) {
+                min(
+                    (placeable.width - 32.dp.roundToPx()).toFloat() / placeable.height,
+                    MAX_ASPECT_RATIO,
+                )
+            },
+        horizontalPaddingPx = horizontalPadding.roundToInt(),
+        horizontalPaddingDp = with(measureScope) { horizontalPadding.toDp() },
+    )
+
+    fun coerceAspectRatio(ratio: Float): Float = ratio.coerceIn(MIN_ASPECT_RATIO, maxAspectRatio)
+
+    fun scrollOffsetToCenter(previewModel: PreviewModel): Int =
+        horizontalPaddingPx + (aspectRatioToWidthPx(previewModel.aspectRatio) / 2) -
+            viewportCenterPx
+
+    fun scrollOffsetToStartEdge(): Int = horizontalPaddingPx
+
+    fun scrollOffsetToEndEdge(previewModel: PreviewModel): Int =
+        horizontalPaddingPx + aspectRatioToWidthPx(previewModel.aspectRatio) - viewportWidthPx
+
+    private fun aspectRatioToWidthPx(ratio: Float): Int =
+        (coerceAspectRatio(ratio) * viewportHeightPx).roundToInt()
+
+    companion object {
+        private const val MIN_ASPECT_RATIO = 0.4f
+        private const val MAX_ASPECT_RATIO = 2.5f
+
+        val UNMEASURED =
+            PreviewCarouselMeasurements(
+                viewportHeightPx = 0,
+                viewportWidthPx = 0,
+                maxAspectRatio = 0f,
+                horizontalPaddingPx = 0,
+                horizontalPaddingDp = 0.dp,
+            )
+    }
+}
diff --git a/java/src/com/android/intentresolver/data/repository/ActivityModelRepository.kt b/java/src/com/android/intentresolver/data/repository/ActivityModelRepository.kt
new file mode 100644
index 00000000..7c3188d2
--- /dev/null
+++ b/java/src/com/android/intentresolver/data/repository/ActivityModelRepository.kt
@@ -0,0 +1,37 @@
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
+package com.android.intentresolver.data.repository
+
+import com.android.intentresolver.shared.model.ActivityModel
+import dagger.hilt.android.scopes.ActivityRetainedScoped
+import javax.inject.Inject
+import kotlinx.atomicfu.atomic
+
+/** An [ActivityModel] repository that captures the first value. */
+@ActivityRetainedScoped
+class ActivityModelRepository @Inject constructor() {
+    private val _value = atomic<ActivityModel?>(null)
+
+    val value: ActivityModel
+        get() = requireNotNull(_value.value) { "Repository has not been initialized" }
+
+    fun initialize(block: () -> ActivityModel) {
+        if (_value.value == null) {
+            _value.compareAndSet(null, block())
+        }
+    }
+}
diff --git a/java/src/com/android/intentresolver/domain/ChooserRequestExt.kt b/java/src/com/android/intentresolver/domain/ChooserRequestExt.kt
new file mode 100644
index 00000000..5ca3ad20
--- /dev/null
+++ b/java/src/com/android/intentresolver/domain/ChooserRequestExt.kt
@@ -0,0 +1,70 @@
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
+package com.android.intentresolver.domain
+
+import android.content.Intent
+import android.content.Intent.EXTRA_ALTERNATE_INTENTS
+import android.content.Intent.EXTRA_CHOOSER_CUSTOM_ACTIONS
+import android.content.Intent.EXTRA_CHOOSER_MODIFY_SHARE_ACTION
+import android.content.Intent.EXTRA_CHOOSER_REFINEMENT_INTENT_SENDER
+import android.content.Intent.EXTRA_CHOOSER_RESULT_INTENT_SENDER
+import android.content.Intent.EXTRA_CHOOSER_TARGETS
+import android.content.Intent.EXTRA_CHOSEN_COMPONENT_INTENT_SENDER
+import android.content.Intent.EXTRA_EXCLUDE_COMPONENTS
+import android.content.Intent.EXTRA_INTENT
+import android.content.Intent.EXTRA_METADATA_TEXT
+import android.os.Bundle
+import com.android.intentresolver.Flags.shareouselUpdateExcludeComponentsExtra
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ShareouselUpdate
+import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.getOrDefault
+import com.android.intentresolver.data.model.ChooserRequest
+
+/** Creates a new ChooserRequest with the target intent and updates from a Shareousel callback */
+fun ChooserRequest.updateWith(targetIntent: Intent, update: ShareouselUpdate): ChooserRequest =
+    copy(
+        targetIntent = targetIntent,
+        callerChooserTargets = update.callerTargets.getOrDefault(callerChooserTargets),
+        modifyShareAction = update.modifyShareAction.getOrDefault(modifyShareAction),
+        additionalTargets = update.alternateIntents.getOrDefault(additionalTargets),
+        chosenComponentSender = update.resultIntentSender.getOrDefault(chosenComponentSender),
+        refinementIntentSender = update.refinementIntentSender.getOrDefault(refinementIntentSender),
+        metadataText = update.metadataText.getOrDefault(metadataText),
+        chooserActions = update.customActions.getOrDefault(chooserActions),
+        filteredComponentNames =
+            if (shareouselUpdateExcludeComponentsExtra()) {
+                update.excludeComponents.getOrDefault(filteredComponentNames)
+            } else {
+                filteredComponentNames
+            },
+    )
+
+/** Save ChooserRequest values that can be updated by the Shareousel into a Bundle */
+fun ChooserRequest.saveUpdates(bundle: Bundle): Bundle {
+    bundle.putParcelable(EXTRA_INTENT, targetIntent)
+    bundle.putParcelableArray(EXTRA_CHOOSER_TARGETS, callerChooserTargets.toTypedArray())
+    bundle.putParcelable(EXTRA_CHOOSER_MODIFY_SHARE_ACTION, modifyShareAction)
+    bundle.putParcelableArray(EXTRA_ALTERNATE_INTENTS, additionalTargets.toTypedArray())
+    bundle.putParcelable(EXTRA_CHOOSER_RESULT_INTENT_SENDER, chosenComponentSender)
+    bundle.putParcelable(EXTRA_CHOSEN_COMPONENT_INTENT_SENDER, chosenComponentSender)
+    bundle.putParcelable(EXTRA_CHOOSER_REFINEMENT_INTENT_SENDER, refinementIntentSender)
+    bundle.putCharSequence(EXTRA_METADATA_TEXT, metadataText)
+    bundle.putParcelableArray(EXTRA_CHOOSER_CUSTOM_ACTIONS, chooserActions.toTypedArray())
+    if (shareouselUpdateExcludeComponentsExtra()) {
+        bundle.putParcelableArray(EXTRA_EXCLUDE_COMPONENTS, filteredComponentNames.toTypedArray())
+    }
+    return bundle
+}
diff --git a/java/src/com/android/intentresolver/ext/CreationExtrasExt.kt b/java/src/com/android/intentresolver/ext/CreationExtrasExt.kt
index 2ba08c90..5635ec28 100644
--- a/java/src/com/android/intentresolver/ext/CreationExtrasExt.kt
+++ b/java/src/com/android/intentresolver/ext/CreationExtrasExt.kt
@@ -32,3 +32,9 @@ fun CreationExtras.addDefaultArgs(vararg values: Pair<String, Parcelable>): Crea
     defaultArgs.putAll(bundleOf(*values))
     return MutableCreationExtras(this).apply { set(DEFAULT_ARGS_KEY, defaultArgs) }
 }
+
+fun CreationExtras.replaceDefaultArgs(vararg values: Pair<String, Parcelable>): CreationExtras {
+    val mutableExtras = if (this is MutableCreationExtras) this else MutableCreationExtras(this)
+    mutableExtras[DEFAULT_ARGS_KEY] = bundleOf(*values)
+    return mutableExtras
+}
diff --git a/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java b/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java
index 1dd83566..9a50d7e4 100644
--- a/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java
+++ b/java/src/com/android/intentresolver/grid/ChooserGridAdapter.java
@@ -88,7 +88,6 @@ public final class ChooserGridAdapter extends RecyclerView.Adapter<RecyclerView.
 
     private final int mMaxTargetsPerRow;
     private final boolean mShouldShowContentPreview;
-    private final int mChooserWidthPixels;
     private final int mChooserRowTextOptionTranslatePixelSize;
     private final FeatureFlags mFeatureFlags;
     @Nullable
@@ -117,7 +116,6 @@ public final class ChooserGridAdapter extends RecyclerView.Adapter<RecyclerView.
         mShouldShowContentPreview = shouldShowContentPreview;
         mMaxTargetsPerRow = maxTargetsPerRow;
 
-        mChooserWidthPixels = context.getResources().getDimensionPixelSize(R.dimen.chooser_width);
         mChooserRowTextOptionTranslatePixelSize = context.getResources().getDimensionPixelSize(
                 R.dimen.chooser_row_text_option_translate);
         mFeatureFlags = featureFlags;
@@ -167,11 +165,6 @@ public final class ChooserGridAdapter extends RecyclerView.Adapter<RecyclerView.
             return false;
         }
 
-        // Limit width to the maximum width of the chooser activity, if the maximum width is set
-        if (mChooserWidthPixels >= 0) {
-            width = Math.min(mChooserWidthPixels, width);
-        }
-
         int newWidth = width / mMaxTargetsPerRow;
         if (newWidth != mChooserTargetWidth) {
             mChooserTargetWidth = newWidth;
diff --git a/java/src/com/android/intentresolver/icons/BaseLoadIconTask.java b/java/src/com/android/intentresolver/icons/BaseLoadIconTask.java
index 2eceb89c..f09fcfc5 100644
--- a/java/src/com/android/intentresolver/icons/BaseLoadIconTask.java
+++ b/java/src/com/android/intentresolver/icons/BaseLoadIconTask.java
@@ -17,34 +17,31 @@
 package com.android.intentresolver.icons;
 
 import android.content.Context;
-import android.graphics.drawable.Drawable;
+import android.graphics.Bitmap;
 import android.os.AsyncTask;
 
-import com.android.intentresolver.R;
+import androidx.annotation.Nullable;
+
 import com.android.intentresolver.TargetPresentationGetter;
 
 import java.util.function.Consumer;
 
-abstract class BaseLoadIconTask extends AsyncTask<Void, Void, Drawable> {
+abstract class BaseLoadIconTask extends AsyncTask<Void, Void, Bitmap> {
     protected final Context mContext;
     protected final TargetPresentationGetter.Factory mPresentationFactory;
-    private final Consumer<Drawable> mCallback;
+    private final Consumer<Bitmap> mCallback;
 
     BaseLoadIconTask(
             Context context,
             TargetPresentationGetter.Factory presentationFactory,
-            Consumer<Drawable> callback) {
+            Consumer<Bitmap> callback) {
         mContext = context;
         mPresentationFactory = presentationFactory;
         mCallback = callback;
     }
 
-    protected final Drawable loadIconPlaceholder() {
-        return mContext.getDrawable(R.drawable.resolver_icon_placeholder);
-    }
-
     @Override
-    protected final void onPostExecute(Drawable d) {
+    protected final void onPostExecute(@Nullable Bitmap d) {
         mCallback.accept(d);
     }
 }
diff --git a/java/src/com/android/intentresolver/icons/CachingTargetDataLoader.kt b/java/src/com/android/intentresolver/icons/CachingTargetDataLoader.kt
index 8474b4c3..793b7621 100644
--- a/java/src/com/android/intentresolver/icons/CachingTargetDataLoader.kt
+++ b/java/src/com/android/intentresolver/icons/CachingTargetDataLoader.kt
@@ -17,9 +17,13 @@
 package com.android.intentresolver.icons
 
 import android.content.ComponentName
+import android.content.Context
+import android.graphics.Bitmap
+import android.graphics.drawable.BitmapDrawable
 import android.graphics.drawable.Drawable
 import android.os.UserHandle
 import androidx.collection.LruCache
+import com.android.intentresolver.Flags.targetHoverAndKeyboardFocusStates
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.chooser.SelectableTargetInfo
 import java.util.function.Consumer
@@ -28,23 +32,24 @@ import javax.inject.Qualifier
 
 @Qualifier @MustBeDocumented @Retention(AnnotationRetention.BINARY) annotation class Caching
 
-private typealias IconCache = LruCache<String, Drawable>
+private typealias IconCache = LruCache<String, Bitmap>
 
 class CachingTargetDataLoader(
+    private val context: Context,
     private val targetDataLoader: TargetDataLoader,
     private val cacheSize: Int = 100,
-) : TargetDataLoader() {
+) : TargetDataLoader {
     @GuardedBy("self") private val perProfileIconCache = HashMap<UserHandle, IconCache>()
 
     override fun getOrLoadAppTargetIcon(
         info: DisplayResolveInfo,
         userHandle: UserHandle,
-        callback: Consumer<Drawable>
+        callback: Consumer<Drawable>,
     ): Drawable? {
         val cacheKey = info.toCacheKey()
-        return getCachedAppIcon(cacheKey, userHandle)
+        return getCachedAppIcon(cacheKey, userHandle)?.toDrawable()
             ?: targetDataLoader.getOrLoadAppTargetIcon(info, userHandle) { drawable ->
-                getProfileIconCache(userHandle).put(cacheKey, drawable)
+                drawable.extractBitmap()?.let { getProfileIconCache(userHandle).put(cacheKey, it) }
                 callback.accept(drawable)
             }
     }
@@ -52,13 +57,15 @@ class CachingTargetDataLoader(
     override fun getOrLoadDirectShareIcon(
         info: SelectableTargetInfo,
         userHandle: UserHandle,
-        callback: Consumer<Drawable>
+        callback: Consumer<Drawable>,
     ): Drawable? {
         val cacheKey = info.toCacheKey()
-        return cacheKey?.let { getCachedAppIcon(it, userHandle) }
+        return cacheKey?.let { getCachedAppIcon(it, userHandle) }?.toDrawable()
             ?: targetDataLoader.getOrLoadDirectShareIcon(info, userHandle) { drawable ->
                 if (cacheKey != null) {
-                    getProfileIconCache(userHandle).put(cacheKey, drawable)
+                    drawable.extractBitmap()?.let {
+                        getProfileIconCache(userHandle).put(cacheKey, it)
+                    }
                 }
                 callback.accept(drawable)
             }
@@ -69,7 +76,7 @@ class CachingTargetDataLoader(
 
     override fun getOrLoadLabel(info: DisplayResolveInfo) = targetDataLoader.getOrLoadLabel(info)
 
-    private fun getCachedAppIcon(component: String, userHandle: UserHandle): Drawable? =
+    private fun getCachedAppIcon(component: String, userHandle: UserHandle): Bitmap? =
         getProfileIconCache(userHandle)[component]
 
     private fun getProfileIconCache(userHandle: UserHandle): IconCache =
@@ -78,10 +85,7 @@ class CachingTargetDataLoader(
         }
 
     private fun DisplayResolveInfo.toCacheKey() =
-        ComponentName(
-                resolveInfo.activityInfo.packageName,
-                resolveInfo.activityInfo.name,
-            )
+        ComponentName(resolveInfo.activityInfo.packageName, resolveInfo.activityInfo.name)
             .flattenToString()
 
     private fun SelectableTargetInfo.toCacheKey(): String? =
@@ -95,4 +99,20 @@ class CachingTargetDataLoader(
                 append(directShareShortcutInfo?.id ?: "")
             }
         }
+
+    private fun Bitmap.toDrawable(): Drawable {
+        return if (targetHoverAndKeyboardFocusStates()) {
+            HoverBitmapDrawable(this)
+        } else {
+            BitmapDrawable(context.resources, this)
+        }
+    }
+
+    private fun Drawable.extractBitmap(): Bitmap? {
+        return when (this) {
+            is BitmapDrawable -> bitmap
+            is HoverBitmapDrawable -> bitmap
+            else -> null
+        }
+    }
 }
diff --git a/java/src/com/android/intentresolver/icons/DefaultTargetDataLoader.kt b/java/src/com/android/intentresolver/icons/DefaultTargetDataLoader.kt
index e7392f58..1ff1ddfa 100644
--- a/java/src/com/android/intentresolver/icons/DefaultTargetDataLoader.kt
+++ b/java/src/com/android/intentresolver/icons/DefaultTargetDataLoader.kt
@@ -16,8 +16,9 @@
 
 package com.android.intentresolver.icons
 
-import android.app.ActivityManager
 import android.content.Context
+import android.graphics.Bitmap
+import android.graphics.drawable.BitmapDrawable
 import android.graphics.drawable.Drawable
 import android.os.AsyncTask
 import android.os.UserHandle
@@ -26,27 +27,34 @@ import androidx.annotation.GuardedBy
 import androidx.lifecycle.DefaultLifecycleObserver
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
+import com.android.intentresolver.Flags.targetHoverAndKeyboardFocusStates
+import com.android.intentresolver.R
+import com.android.intentresolver.SimpleIconFactory
 import com.android.intentresolver.TargetPresentationGetter
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.chooser.SelectableTargetInfo
+import com.android.intentresolver.inject.ActivityOwned
+import dagger.assisted.Assisted
+import dagger.assisted.AssistedFactory
+import dagger.assisted.AssistedInject
+import dagger.hilt.android.qualifiers.ActivityContext
 import java.util.concurrent.atomic.AtomicInteger
 import java.util.function.Consumer
+import javax.inject.Provider
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.asExecutor
 
 /** An actual [TargetDataLoader] implementation. */
 // TODO: replace async tasks with coroutines.
-class DefaultTargetDataLoader(
-    private val context: Context,
-    private val lifecycle: Lifecycle,
-    private val isAudioCaptureDevice: Boolean,
-) : TargetDataLoader() {
-    private val presentationFactory =
-        TargetPresentationGetter.Factory(
-            context,
-            context.getSystemService(ActivityManager::class.java)?.launcherLargeIconDensity
-                ?: error("Unable to access ActivityManager")
-        )
+class DefaultTargetDataLoader
+@AssistedInject
+constructor(
+    @ActivityContext private val context: Context,
+    @ActivityOwned private val lifecycle: Lifecycle,
+    private val iconFactoryProvider: Provider<SimpleIconFactory>,
+    private val presentationFactory: TargetPresentationGetter.Factory,
+    @Assisted private val isAudioCaptureDevice: Boolean,
+) : TargetDataLoader {
     private val nextTaskId = AtomicInteger(0)
     @GuardedBy("self") private val activeTasks = SparseArray<AsyncTask<*, *, *>>()
     private val executor = Dispatchers.IO.asExecutor()
@@ -68,9 +76,9 @@ class DefaultTargetDataLoader(
         callback: Consumer<Drawable>,
     ): Drawable? {
         val taskId = nextTaskId.getAndIncrement()
-        LoadIconTask(context, info, userHandle, presentationFactory) { result ->
+        LoadIconTask(context, info, presentationFactory) { bitmap ->
                 removeTask(taskId)
-                callback.accept(result)
+                callback.accept(bitmap?.toDrawable() ?: loadIconPlaceholder())
             }
             .also { addTask(taskId, it) }
             .executeOnExecutor(executor)
@@ -87,9 +95,10 @@ class DefaultTargetDataLoader(
                 context.createContextAsUser(userHandle, 0),
                 info,
                 presentationFactory,
-            ) { result ->
+                iconFactoryProvider,
+            ) { bitmap ->
                 removeTask(taskId)
-                callback.accept(result)
+                callback.accept(bitmap?.toDrawable() ?: loadIconPlaceholder())
             }
             .also { addTask(taskId, it) }
             .executeOnExecutor(executor)
@@ -123,6 +132,9 @@ class DefaultTargetDataLoader(
         synchronized(activeTasks) { activeTasks.remove(id) }
     }
 
+    private fun loadIconPlaceholder(): Drawable =
+        requireNotNull(context.getDrawable(R.drawable.resolver_icon_placeholder))
+
     private fun destroy() {
         synchronized(activeTasks) {
             for (i in 0 until activeTasks.size()) {
@@ -131,4 +143,17 @@ class DefaultTargetDataLoader(
             activeTasks.clear()
         }
     }
+
+    private fun Bitmap.toDrawable(): Drawable {
+        return if (targetHoverAndKeyboardFocusStates()) {
+            HoverBitmapDrawable(this)
+        } else {
+            BitmapDrawable(context.resources, this)
+        }
+    }
+
+    @AssistedFactory
+    interface Factory {
+        fun create(isAudioCaptureDevice: Boolean): DefaultTargetDataLoader
+    }
 }
diff --git a/java/src/com/android/intentresolver/icons/HoverBitmapDrawable.kt b/java/src/com/android/intentresolver/icons/HoverBitmapDrawable.kt
new file mode 100644
index 00000000..4a21df92
--- /dev/null
+++ b/java/src/com/android/intentresolver/icons/HoverBitmapDrawable.kt
@@ -0,0 +1,41 @@
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
+package com.android.intentresolver.icons
+
+import android.graphics.Bitmap
+import com.android.launcher3.icons.FastBitmapDrawable
+
+/** A [FastBitmapDrawable] extension that provides access to the bitmap. */
+class HoverBitmapDrawable(val bitmap: Bitmap) : FastBitmapDrawable(bitmap) {
+
+    override fun newConstantState(): FastBitmapConstantState {
+        return HoverBitmapDrawableState(bitmap, iconColor)
+    }
+
+    private class HoverBitmapDrawableState(private val bitmap: Bitmap, color: Int) :
+        FastBitmapConstantState(bitmap, color) {
+        override fun createDrawable(): FastBitmapDrawable {
+            return HoverBitmapDrawable(bitmap)
+        }
+    }
+
+    companion object {
+        init {
+            setFlagHoverEnabled(true)
+        }
+    }
+}
diff --git a/java/src/com/android/intentresolver/icons/LoadDirectShareIconTask.java b/java/src/com/android/intentresolver/icons/LoadDirectShareIconTask.java
index e2c0362d..01f9330e 100644
--- a/java/src/com/android/intentresolver/icons/LoadDirectShareIconTask.java
+++ b/java/src/com/android/intentresolver/icons/LoadDirectShareIconTask.java
@@ -23,7 +23,6 @@ import android.content.pm.LauncherApps;
 import android.content.pm.PackageManager;
 import android.content.pm.ShortcutInfo;
 import android.graphics.Bitmap;
-import android.graphics.drawable.BitmapDrawable;
 import android.graphics.drawable.Drawable;
 import android.graphics.drawable.Icon;
 import android.os.Trace;
@@ -39,30 +38,36 @@ import com.android.intentresolver.util.UriFilters;
 
 import java.util.function.Consumer;
 
+import javax.inject.Provider;
+
 /**
  * Loads direct share targets icons.
  */
 class LoadDirectShareIconTask extends BaseLoadIconTask {
     private static final String TAG = "DirectShareIconTask";
     private final SelectableTargetInfo mTargetInfo;
+    private final Provider<SimpleIconFactory> mIconFactoryProvider;
 
     LoadDirectShareIconTask(
             Context context,
             SelectableTargetInfo targetInfo,
             TargetPresentationGetter.Factory presentationFactory,
-            Consumer<Drawable> callback) {
+            Provider<SimpleIconFactory> iconFactoryProvider,
+            Consumer<Bitmap> callback) {
         super(context, presentationFactory, callback);
+        mIconFactoryProvider = iconFactoryProvider;
         mTargetInfo = targetInfo;
     }
 
     @Override
-    protected Drawable doInBackground(Void... voids) {
-        Drawable drawable = null;
+    @Nullable
+    protected Bitmap doInBackground(Void... voids) {
+        Bitmap iconBitmap = null;
         Trace.beginSection("shortcut-icon");
         try {
             final Icon icon = mTargetInfo.getChooserTargetIcon();
             if (icon == null || UriFilters.hasValidIcon(icon)) {
-                drawable = getChooserTargetIconDrawable(
+                iconBitmap = getChooserTargetIconBitmap(
                         mContext,
                         icon,
                         mTargetInfo.getChooserTargetComponentName(),
@@ -71,25 +76,21 @@ class LoadDirectShareIconTask extends BaseLoadIconTask {
                 Log.e(TAG, "Failed to load shortcut icon for "
                         + mTargetInfo.getChooserTargetComponentName() + "; no access");
             }
-            if (drawable == null) {
-                drawable = loadIconPlaceholder();
-            }
         } catch (Exception e) {
             Log.e(
                     TAG,
                     "Failed to load shortcut icon for "
                             + mTargetInfo.getChooserTargetComponentName(),
                     e);
-            drawable = loadIconPlaceholder();
         } finally {
             Trace.endSection();
         }
-        return drawable;
+        return iconBitmap;
     }
 
     @WorkerThread
     @Nullable
-    private Drawable getChooserTargetIconDrawable(
+    private Bitmap getChooserTargetIconBitmap(
             Context context,
             @Nullable Icon icon,
             ComponentName targetComponentName,
@@ -125,10 +126,11 @@ class LoadDirectShareIconTask extends BaseLoadIconTask {
         Bitmap appIcon = mPresentationFactory.makePresentationGetter(info).getIconBitmap(null);
 
         // Raster target drawable with appIcon as a badge
-        SimpleIconFactory sif = SimpleIconFactory.obtain(context);
-        Bitmap directShareBadgedIcon = sif.createAppBadgedIconBitmap(directShareIcon, appIcon);
-        sif.recycle();
+        Bitmap directShareBadgedIcon;
+        try (SimpleIconFactory sif = mIconFactoryProvider.get()) {
+            directShareBadgedIcon = sif.createAppBadgedIconBitmap(directShareIcon, appIcon);
+        }
 
-        return new BitmapDrawable(context.getResources(), directShareBadgedIcon);
+        return directShareBadgedIcon;
     }
 }
diff --git a/java/src/com/android/intentresolver/icons/LoadIconTask.java b/java/src/com/android/intentresolver/icons/LoadIconTask.java
index 75132208..4573fadf 100644
--- a/java/src/com/android/intentresolver/icons/LoadIconTask.java
+++ b/java/src/com/android/intentresolver/icons/LoadIconTask.java
@@ -19,11 +19,12 @@ package com.android.intentresolver.icons;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.pm.ResolveInfo;
-import android.graphics.drawable.Drawable;
+import android.graphics.Bitmap;
 import android.os.Trace;
-import android.os.UserHandle;
 import android.util.Log;
 
+import androidx.annotation.Nullable;
+
 import com.android.intentresolver.TargetPresentationGetter;
 import com.android.intentresolver.chooser.DisplayResolveInfo;
 
@@ -32,38 +33,36 @@ import java.util.function.Consumer;
 class LoadIconTask extends BaseLoadIconTask {
     private static final String TAG = "IconTask";
     protected final DisplayResolveInfo mDisplayResolveInfo;
-    private final UserHandle mUserHandle;
     private final ResolveInfo mResolveInfo;
 
     LoadIconTask(
             Context context, DisplayResolveInfo dri,
-            UserHandle userHandle,
             TargetPresentationGetter.Factory presentationFactory,
-            Consumer<Drawable> callback) {
+            Consumer<Bitmap> callback) {
         super(context, presentationFactory, callback);
-        mUserHandle = userHandle;
         mDisplayResolveInfo = dri;
         mResolveInfo = dri.getResolveInfo();
     }
 
     @Override
-    protected Drawable doInBackground(Void... params) {
+    @Nullable
+    protected Bitmap doInBackground(Void... params) {
         Trace.beginSection("app-icon");
         try {
             return loadIconForResolveInfo(mResolveInfo);
         } catch (Exception e) {
             ComponentName componentName = mDisplayResolveInfo.getResolvedComponentName();
             Log.e(TAG, "Failed to load app icon for " + componentName, e);
-            return loadIconPlaceholder();
+            return null;
         } finally {
             Trace.endSection();
         }
     }
 
-    protected final Drawable loadIconForResolveInfo(ResolveInfo ri) {
+    protected final Bitmap loadIconForResolveInfo(ResolveInfo ri) {
         // Load icons based on userHandle from ResolveInfo. If in work profile/clone profile, icons
         // should be badged.
-        return mPresentationFactory.makePresentationGetter(ri).getIcon(ri.userHandle);
+        return mPresentationFactory.makePresentationGetter(ri).getIconBitmap(ri.userHandle);
     }
 
 }
diff --git a/java/src/com/android/intentresolver/icons/TargetDataLoader.kt b/java/src/com/android/intentresolver/icons/TargetDataLoader.kt
index 935b527a..7cbd040e 100644
--- a/java/src/com/android/intentresolver/icons/TargetDataLoader.kt
+++ b/java/src/com/android/intentresolver/icons/TargetDataLoader.kt
@@ -23,24 +23,24 @@ import com.android.intentresolver.chooser.SelectableTargetInfo
 import java.util.function.Consumer
 
 /** A target data loader contract. Added to support testing. */
-abstract class TargetDataLoader {
+interface TargetDataLoader {
     /** Load an app target icon */
-    abstract fun getOrLoadAppTargetIcon(
+    fun getOrLoadAppTargetIcon(
         info: DisplayResolveInfo,
         userHandle: UserHandle,
         callback: Consumer<Drawable>,
     ): Drawable?
 
     /** Load a shortcut icon */
-    abstract fun getOrLoadDirectShareIcon(
+    fun getOrLoadDirectShareIcon(
         info: SelectableTargetInfo,
         userHandle: UserHandle,
         callback: Consumer<Drawable>,
     ): Drawable?
 
     /** Load target label */
-    abstract fun loadLabel(info: DisplayResolveInfo, callback: Consumer<LabelInfo>)
+    fun loadLabel(info: DisplayResolveInfo, callback: Consumer<LabelInfo>)
 
     /** Loads DisplayResolveInfo's display label synchronously, if needed */
-    abstract fun getOrLoadLabel(info: DisplayResolveInfo)
+    fun getOrLoadLabel(info: DisplayResolveInfo)
 }
diff --git a/java/src/com/android/intentresolver/icons/TargetDataLoaderModule.kt b/java/src/com/android/intentresolver/icons/TargetDataLoaderModule.kt
index 9c0acb11..d6d4aae1 100644
--- a/java/src/com/android/intentresolver/icons/TargetDataLoaderModule.kt
+++ b/java/src/com/android/intentresolver/icons/TargetDataLoaderModule.kt
@@ -16,29 +16,45 @@
 
 package com.android.intentresolver.icons
 
+import android.app.ActivityManager
 import android.content.Context
-import androidx.lifecycle.Lifecycle
-import com.android.intentresolver.inject.ActivityOwned
+import android.content.pm.PackageManager
+import com.android.intentresolver.SimpleIconFactory
+import com.android.intentresolver.TargetPresentationGetter
 import dagger.Module
 import dagger.Provides
 import dagger.hilt.InstallIn
 import dagger.hilt.android.components.ActivityComponent
 import dagger.hilt.android.qualifiers.ActivityContext
 import dagger.hilt.android.scopes.ActivityScoped
+import javax.inject.Provider
 
 @Module
 @InstallIn(ActivityComponent::class)
 object TargetDataLoaderModule {
     @Provides
-    @ActivityScoped
-    fun targetDataLoader(
-        @ActivityContext context: Context,
-        @ActivityOwned lifecycle: Lifecycle,
-    ): TargetDataLoader = DefaultTargetDataLoader(context, lifecycle, isAudioCaptureDevice = false)
+    fun simpleIconFactory(@ActivityContext context: Context): SimpleIconFactory =
+        SimpleIconFactory.obtain(context)
+
+    @Provides
+    fun presentationGetterFactory(
+        iconFactoryProvider: Provider<SimpleIconFactory>,
+        packageManager: PackageManager,
+        activityManager: ActivityManager,
+    ): TargetPresentationGetter.Factory =
+        TargetPresentationGetter.Factory(
+            iconFactoryProvider,
+            packageManager,
+            activityManager.launcherLargeIconDensity,
+        )
 
     @Provides
     @ActivityScoped
     @Caching
-    fun cachingTargetDataLoader(targetDataLoader: TargetDataLoader): TargetDataLoader =
-        CachingTargetDataLoader(targetDataLoader)
+    fun cachingTargetDataLoader(
+        @ActivityContext context: Context,
+        dataLoaderFactory: DefaultTargetDataLoader.Factory,
+    ): TargetDataLoader =
+        // Intended to be used in Chooser only thus the hardcoded isAudioCaptureDevice value.
+        CachingTargetDataLoader(context, dataLoaderFactory.create(isAudioCaptureDevice = false))
 }
diff --git a/java/src/com/android/intentresolver/inject/ActivityModelModule.kt b/java/src/com/android/intentresolver/inject/ActivityModelModule.kt
index bbd25eb7..60eff925 100644
--- a/java/src/com/android/intentresolver/inject/ActivityModelModule.kt
+++ b/java/src/com/android/intentresolver/inject/ActivityModelModule.kt
@@ -18,10 +18,13 @@ package com.android.intentresolver.inject
 
 import android.content.Intent
 import android.net.Uri
+import android.os.Bundle
 import android.service.chooser.ChooserAction
 import androidx.lifecycle.SavedStateHandle
+import com.android.intentresolver.Flags.saveShareouselState
 import com.android.intentresolver.data.model.ChooserRequest
-import com.android.intentresolver.ui.model.ActivityModel
+import com.android.intentresolver.data.repository.ActivityModelRepository
+import com.android.intentresolver.ui.viewmodel.CHOOSER_REQUEST_KEY
 import com.android.intentresolver.ui.viewmodel.readChooserRequest
 import com.android.intentresolver.util.ownedByCurrentUser
 import com.android.intentresolver.validation.Valid
@@ -36,27 +39,24 @@ import javax.inject.Qualifier
 @Module
 @InstallIn(ViewModelComponent::class)
 object ActivityModelModule {
-    @Provides
-    fun provideActivityModel(savedStateHandle: SavedStateHandle): ActivityModel =
-        requireNotNull(savedStateHandle[ActivityModel.ACTIVITY_MODEL_KEY]) {
-            "ActivityModel missing in SavedStateHandle! (${ActivityModel.ACTIVITY_MODEL_KEY})"
-        }
-
     @Provides
     @ChooserIntent
-    fun chooserIntent(activityModel: ActivityModel): Intent = activityModel.intent
+    fun chooserIntent(activityModelRepo: ActivityModelRepository): Intent =
+        activityModelRepo.value.intent
 
     @Provides
     @ViewModelScoped
     fun provideInitialRequest(
-        activityModel: ActivityModel,
-        flags: ChooserServiceFlags,
-    ): ValidationResult<ChooserRequest> = readChooserRequest(activityModel, flags)
+        activityModelRepo: ActivityModelRepository,
+        savedStateHandle: SavedStateHandle,
+    ): ValidationResult<ChooserRequest> {
+        val activityModel = activityModelRepo.value
+        val extras = restoreChooserRequestExtras(activityModel.intent.extras, savedStateHandle)
+        return readChooserRequest(activityModel, extras)
+    }
 
     @Provides
-    fun provideChooserRequest(
-        initialRequest: ValidationResult<ChooserRequest>,
-    ): ChooserRequest =
+    fun provideChooserRequest(initialRequest: ValidationResult<ChooserRequest>): ChooserRequest =
         requireNotNull((initialRequest as? Valid)?.value) {
             "initialRequest is Invalid, no chooser request available"
         }
@@ -125,3 +125,18 @@ private val Intent.contentUris: Sequence<Uri>
             }
         }
     }
+
+private fun restoreChooserRequestExtras(
+    initialExtras: Bundle?,
+    savedStateHandle: SavedStateHandle,
+): Bundle =
+    if (saveShareouselState()) {
+        savedStateHandle.get<Bundle>(CHOOSER_REQUEST_KEY)?.let { savedSateBundle ->
+            Bundle().apply {
+                initialExtras?.let { putAll(it) }
+                putAll(savedSateBundle)
+            }
+        } ?: initialExtras
+    } else {
+        initialExtras
+    } ?: Bundle()
diff --git a/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java b/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java
index 9176cd35..677b6366 100644
--- a/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java
+++ b/java/src/com/android/intentresolver/profiles/ChooserMultiProfilePagerAdapter.java
@@ -16,6 +16,8 @@
 
 package com.android.intentresolver.profiles;
 
+import static com.android.intentresolver.Flags.keyboardNavigationFix;
+
 import android.content.Context;
 import android.os.UserHandle;
 import android.view.LayoutInflater;
@@ -125,6 +127,9 @@ public class ChooserMultiProfilePagerAdapter extends MultiProfilePagerAdapter<
         LayoutInflater inflater = LayoutInflater.from(context);
         ViewGroup rootView =
                 (ViewGroup) inflater.inflate(R.layout.chooser_list_per_profile_wrap, null, false);
+        if (!keyboardNavigationFix()) {
+            rootView.setDescendantFocusability(ViewGroup.FOCUS_BLOCK_DESCENDANTS);
+        }
         RecyclerView recyclerView = rootView.findViewById(com.android.internal.R.id.resolver_list);
         recyclerView.setAccessibilityDelegateCompat(
                 new ChooserRecyclerViewAccessibilityDelegate(recyclerView));
diff --git a/java/src/com/android/intentresolver/ui/model/ActivityModel.kt b/java/src/com/android/intentresolver/shared/model/ActivityModel.kt
similarity index 90%
rename from java/src/com/android/intentresolver/ui/model/ActivityModel.kt
rename to java/src/com/android/intentresolver/shared/model/ActivityModel.kt
index 4bcdd69b..c5efdeba 100644
--- a/java/src/com/android/intentresolver/ui/model/ActivityModel.kt
+++ b/java/src/com/android/intentresolver/shared/model/ActivityModel.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.intentresolver.ui.model
+package com.android.intentresolver.shared.model
 
 import android.app.Activity
 import android.content.Intent
@@ -34,7 +34,7 @@ data class ActivityModel(
     /** The package of the sending app */
     val launchedFromPackage: String,
     /** The referrer as supplied to the activity. */
-    val referrer: Uri?
+    val referrer: Uri?,
 ) : Parcelable {
     constructor(
         source: Parcel
@@ -42,7 +42,7 @@ data class ActivityModel(
         intent = source.requireParcelable(),
         launchedFromUid = source.readInt(),
         launchedFromPackage = requireNotNull(source.readString()),
-        referrer = source.readParcelable()
+        referrer = source.readParcelable(),
     )
 
     /** A package name from referrer, if it is an android-app URI */
@@ -58,13 +58,12 @@ data class ActivityModel(
     }
 
     companion object {
-        const val ACTIVITY_MODEL_KEY = "com.android.intentresolver.ACTIVITY_MODEL"
-
         @JvmField
         @Suppress("unused")
         val CREATOR =
             object : Parcelable.Creator<ActivityModel> {
                 override fun newArray(size: Int) = arrayOfNulls<ActivityModel>(size)
+
                 override fun createFromParcel(source: Parcel) = ActivityModel(source)
             }
 
@@ -74,7 +73,7 @@ data class ActivityModel(
                 activity.intent,
                 activity.launchedFromUid,
                 Objects.requireNonNull<String>(activity.launchedFromPackage),
-                activity.referrer
+                activity.referrer,
             )
         }
     }
diff --git a/java/src/com/android/intentresolver/ui/ShareResultSender.kt b/java/src/com/android/intentresolver/ui/ShareResultSender.kt
index dce477ec..2684b817 100644
--- a/java/src/com/android/intentresolver/ui/ShareResultSender.kt
+++ b/java/src/com/android/intentresolver/ui/ShareResultSender.kt
@@ -30,7 +30,6 @@ import android.service.chooser.ChooserResult.CHOOSER_RESULT_UNKNOWN
 import android.service.chooser.ChooserResult.ResultType
 import android.util.Log
 import com.android.intentresolver.inject.Background
-import com.android.intentresolver.inject.ChooserServiceFlags
 import com.android.intentresolver.inject.Main
 import com.android.intentresolver.ui.model.ShareAction
 import dagger.assisted.Assisted
@@ -64,7 +63,6 @@ fun interface IntentSenderDispatcher {
 }
 
 class ShareResultSenderImpl(
-    private val flags: ChooserServiceFlags,
     @Main private val scope: CoroutineScope,
     @Background val backgroundDispatcher: CoroutineDispatcher,
     private val callerUid: Int,
@@ -74,13 +72,11 @@ class ShareResultSenderImpl(
     @AssistedInject
     constructor(
         @ActivityContext context: Context,
-        flags: ChooserServiceFlags,
         @Main scope: CoroutineScope,
         @Background backgroundDispatcher: CoroutineDispatcher,
         @Assisted callerUid: Int,
         @Assisted chosenComponentSender: IntentSender,
     ) : this(
-        flags,
         scope,
         backgroundDispatcher,
         callerUid,
@@ -103,7 +99,7 @@ class ShareResultSenderImpl(
     override fun onActionSelected(action: ShareAction) {
         Log.i(TAG, "onActionSelected: $action")
         scope.launch {
-            if (flags.enableChooserResult() && chooserResultSupported(callerUid)) {
+            if (chooserResultSupported(callerUid)) {
                 @ResultType val chosenAction = shareActionToChooserResult(action)
                 val intent: Intent = createSelectedActionIntent(chosenAction)
                 intentDispatcher.dispatchIntent(resultSender, intent)
@@ -118,7 +114,7 @@ class ShareResultSenderImpl(
         direct: Boolean,
         crossProfile: Boolean,
     ): Intent? {
-        if (flags.enableChooserResult() && chooserResultSupported(callerUid)) {
+        if (chooserResultSupported(callerUid)) {
             if (crossProfile) {
                 Log.i(TAG, "Redacting package from cross-profile ${Intent.EXTRA_CHOOSER_RESULT}")
                 return Intent()
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt b/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
index 4a194db9..13de84b2 100644
--- a/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
+++ b/java/src/com/android/intentresolver/ui/viewmodel/ChooserRequestReader.kt
@@ -36,7 +36,6 @@ import android.content.Intent.EXTRA_TEXT
 import android.content.Intent.EXTRA_TITLE
 import android.content.Intent.FLAG_ACTIVITY_MULTIPLE_TASK
 import android.content.Intent.FLAG_ACTIVITY_NEW_DOCUMENT
-import android.content.IntentFilter
 import android.content.IntentSender
 import android.net.Uri
 import android.os.Bundle
@@ -48,8 +47,7 @@ import com.android.intentresolver.R
 import com.android.intentresolver.data.model.ChooserRequest
 import com.android.intentresolver.ext.hasSendAction
 import com.android.intentresolver.ext.ifMatch
-import com.android.intentresolver.inject.ChooserServiceFlags
-import com.android.intentresolver.ui.model.ActivityModel
+import com.android.intentresolver.shared.model.ActivityModel
 import com.android.intentresolver.util.hasValidIcon
 import com.android.intentresolver.validation.Validation
 import com.android.intentresolver.validation.ValidationResult
@@ -69,11 +67,10 @@ internal fun Intent.maybeAddSendActionFlags() =
 
 fun readChooserRequest(
     model: ActivityModel,
-    flags: ChooserServiceFlags
+    savedState: Bundle = model.intent.extras ?: Bundle(),
 ): ValidationResult<ChooserRequest> {
-    val extras = model.intent.extras ?: Bundle()
     @Suppress("DEPRECATION")
-    return validateFrom(extras::get) {
+    return validateFrom(savedState::get) {
         val targetIntent = required(IntentOrUri(EXTRA_INTENT)).maybeAddSendActionFlags()
 
         val isSendAction = targetIntent.hasSendAction()
@@ -87,7 +84,7 @@ fun readChooserRequest(
                 ignored(
                     value<CharSequence>(EXTRA_TITLE),
                     "deprecated in P. You may wish to set a preview title by using EXTRA_TITLE " +
-                        "property of the wrapped EXTRA_INTENT."
+                        "property of the wrapped EXTRA_INTENT.",
                 )
                 null to R.string.chooseActivity
             } else {
@@ -126,7 +123,7 @@ fun readChooserRequest(
 
         val additionalContentUri: Uri?
         val focusedItemPos: Int
-        if (isSendAction && flags.chooserPayloadToggling()) {
+        if (isSendAction) {
             additionalContentUri = optional(value<Uri>(EXTRA_CHOOSER_ADDITIONAL_CONTENT_URI))
             focusedItemPos = optional(value<Int>(EXTRA_CHOOSER_FOCUSED_ITEM_POSITION)) ?: 0
         } else {
@@ -166,7 +163,7 @@ fun readChooserRequest(
             refinementIntentSender = refinementIntentSender,
             sharedText = sharedText,
             sharedTextTitle = sharedTextTitle,
-            shareTargetFilter = targetIntent.toShareTargetFilter(),
+            shareTargetFilter = targetIntent.createIntentFilter(),
             additionalContentUri = additionalContentUri,
             focusedItemPosition = focusedItemPos,
             contentTypeHint = contentTypeHint,
@@ -182,12 +179,3 @@ fun Validation.readChooserActions(): List<ChooserAction>? =
     optional(array<ChooserAction>(EXTRA_CHOOSER_CUSTOM_ACTIONS))
         ?.filter { hasValidIcon(it) }
         ?.take(MAX_CHOOSER_ACTIONS)
-
-private fun Intent.toShareTargetFilter(): IntentFilter? {
-    return type?.let {
-        IntentFilter().apply {
-            action?.also { addAction(it) }
-            addDataType(it)
-        }
-    }
-}
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt b/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
index 619e118a..8597d802 100644
--- a/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
+++ b/java/src/com/android/intentresolver/ui/viewmodel/ChooserViewModel.kt
@@ -16,21 +16,23 @@
 package com.android.intentresolver.ui.viewmodel
 
 import android.content.ContentInterface
+import android.os.Bundle
 import android.util.Log
 import androidx.lifecycle.SavedStateHandle
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
+import com.android.intentresolver.Flags.saveShareouselState
 import com.android.intentresolver.contentpreview.ImageLoader
 import com.android.intentresolver.contentpreview.PreviewDataProvider
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.FetchPreviewsInteractor
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.ProcessTargetIntentUpdatesInteractor
 import com.android.intentresolver.contentpreview.payloadtoggle.ui.viewmodel.ShareouselViewModel
 import com.android.intentresolver.data.model.ChooserRequest
+import com.android.intentresolver.data.repository.ActivityModelRepository
 import com.android.intentresolver.data.repository.ChooserRequestRepository
+import com.android.intentresolver.domain.saveUpdates
 import com.android.intentresolver.inject.Background
-import com.android.intentresolver.inject.ChooserServiceFlags
-import com.android.intentresolver.ui.model.ActivityModel
-import com.android.intentresolver.ui.model.ActivityModel.Companion.ACTIVITY_MODEL_KEY
+import com.android.intentresolver.shared.model.ActivityModel
 import com.android.intentresolver.validation.Invalid
 import com.android.intentresolver.validation.Valid
 import com.android.intentresolver.validation.ValidationResult
@@ -44,17 +46,18 @@ import kotlinx.coroutines.launch
 import kotlinx.coroutines.plus
 
 private const val TAG = "ChooserViewModel"
+const val CHOOSER_REQUEST_KEY = "chooser-request"
 
 @HiltViewModel
 class ChooserViewModel
 @Inject
 constructor(
-    args: SavedStateHandle,
+    savedStateHandle: SavedStateHandle,
+    activityModelRepository: ActivityModelRepository,
     private val shareouselViewModelProvider: Lazy<ShareouselViewModel>,
     private val processUpdatesInteractor: Lazy<ProcessTargetIntentUpdatesInteractor>,
     private val fetchPreviewsInteractor: Lazy<FetchPreviewsInteractor>,
     @Background private val bgDispatcher: CoroutineDispatcher,
-    private val flags: ChooserServiceFlags,
     /**
      * Provided only for the express purpose of early exit in the event of an invalid request.
      *
@@ -67,18 +70,11 @@ constructor(
 ) : ViewModel() {
 
     /** Parcelable-only references provided from the creating Activity */
-    val activityModel: ActivityModel =
-        requireNotNull(args[ACTIVITY_MODEL_KEY]) {
-            "ActivityModel missing in SavedStateHandle! ($ACTIVITY_MODEL_KEY)"
-        }
+    val activityModel: ActivityModel = activityModelRepository.value
 
     val shareouselViewModel: ShareouselViewModel by lazy {
         // TODO: consolidate this logic, this would require a consolidated preview view model but
         //  for now just postpone starting the payload selection preview machinery until it's needed
-        assert(flags.chooserPayloadToggling()) {
-            "An attempt to use payload selection preview with the disabled flag"
-        }
-
         viewModelScope.launch(bgDispatcher) { processUpdatesInteractor.get().activate() }
         viewModelScope.launch(bgDispatcher) { fetchPreviewsInteractor.get().activate() }
         shareouselViewModelProvider.get()
@@ -99,13 +95,28 @@ constructor(
             chooserRequest.targetIntent,
             chooserRequest.additionalContentUri,
             contentResolver,
-            flags,
         )
     }
 
     init {
-        if (initialRequest is Invalid) {
-            Log.w(TAG, "initialRequest is Invalid, initialization failed")
+        when (initialRequest) {
+            is Invalid -> {
+                Log.w(TAG, "initialRequest is Invalid, initialization failed")
+            }
+            is Valid<ChooserRequest> -> {
+                if (saveShareouselState()) {
+                    val isRestored =
+                        savedStateHandle.get<Bundle>(CHOOSER_REQUEST_KEY)?.takeIf { !it.isEmpty } !=
+                            null
+                    savedStateHandle.setSavedStateProvider(CHOOSER_REQUEST_KEY) {
+                        Bundle().also { result ->
+                            request.value
+                                .takeIf { isRestored || it != initialRequest.value }
+                                ?.saveUpdates(result)
+                        }
+                    }
+                }
+            }
         }
     }
 }
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/IntentExt.kt b/java/src/com/android/intentresolver/ui/viewmodel/IntentExt.kt
new file mode 100644
index 00000000..30f16d20
--- /dev/null
+++ b/java/src/com/android/intentresolver/ui/viewmodel/IntentExt.kt
@@ -0,0 +1,58 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.intentresolver.ui.viewmodel
+
+import android.content.Intent
+import android.content.IntentFilter
+import android.content.IntentFilter.MalformedMimeTypeException
+import android.net.Uri
+import android.os.PatternMatcher
+
+/** Collects Uris from standard locations within the Intent. */
+fun Intent.collectUris(): Set<Uri> = buildSet {
+    data?.also { add(it) }
+    @Suppress("DEPRECATION")
+    when (val stream = extras?.get(Intent.EXTRA_STREAM)) {
+        is Uri -> add(stream)
+        is ArrayList<*> -> addAll(stream.mapNotNull { it as? Uri })
+        else -> Unit
+    }
+    clipData?.apply { (0..<itemCount).mapNotNull { getItemAt(it).uri }.forEach(::add) }
+}
+
+fun IntentFilter.addUri(uri: Uri) {
+    uri.scheme?.also { addDataScheme(it) }
+    uri.host?.also { addDataAuthority(it, null) }
+    uri.path?.also { addDataPath(it, PatternMatcher.PATTERN_LITERAL) }
+}
+
+fun Intent.createIntentFilter(): IntentFilter? {
+    val uris = collectUris()
+    if (action == null && uris.isEmpty()) {
+        // at least one is required to be meaningful
+        return null
+    }
+    return IntentFilter().also { filter ->
+        type?.also {
+            try {
+                filter.addDataType(it)
+            } catch (_: MalformedMimeTypeException) { // ignore malformed type
+            }
+        }
+        action?.also { filter.addAction(it) }
+        uris.forEach(filter::addUri)
+    }
+}
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/ResolverRequestReader.kt b/java/src/com/android/intentresolver/ui/viewmodel/ResolverRequestReader.kt
index 856d9fdd..884be635 100644
--- a/java/src/com/android/intentresolver/ui/viewmodel/ResolverRequestReader.kt
+++ b/java/src/com/android/intentresolver/ui/viewmodel/ResolverRequestReader.kt
@@ -20,8 +20,8 @@ import android.os.Bundle
 import android.os.UserHandle
 import com.android.intentresolver.ResolverActivity.PROFILE_PERSONAL
 import com.android.intentresolver.ResolverActivity.PROFILE_WORK
+import com.android.intentresolver.shared.model.ActivityModel
 import com.android.intentresolver.shared.model.Profile
-import com.android.intentresolver.ui.model.ActivityModel
 import com.android.intentresolver.ui.model.ResolverRequest
 import com.android.intentresolver.validation.Validation
 import com.android.intentresolver.validation.ValidationResult
diff --git a/java/src/com/android/intentresolver/ui/viewmodel/ResolverViewModel.kt b/java/src/com/android/intentresolver/ui/viewmodel/ResolverViewModel.kt
index a3dc58a6..3511637b 100644
--- a/java/src/com/android/intentresolver/ui/viewmodel/ResolverViewModel.kt
+++ b/java/src/com/android/intentresolver/ui/viewmodel/ResolverViewModel.kt
@@ -17,10 +17,9 @@
 package com.android.intentresolver.ui.viewmodel
 
 import android.util.Log
-import androidx.lifecycle.SavedStateHandle
 import androidx.lifecycle.ViewModel
-import com.android.intentresolver.ui.model.ActivityModel
-import com.android.intentresolver.ui.model.ActivityModel.Companion.ACTIVITY_MODEL_KEY
+import com.android.intentresolver.data.repository.ActivityModelRepository
+import com.android.intentresolver.shared.model.ActivityModel
 import com.android.intentresolver.ui.model.ResolverRequest
 import com.android.intentresolver.validation.Invalid
 import com.android.intentresolver.validation.Valid
@@ -33,13 +32,11 @@ import kotlinx.coroutines.flow.asStateFlow
 private const val TAG = "ResolverViewModel"
 
 @HiltViewModel
-class ResolverViewModel @Inject constructor(args: SavedStateHandle) : ViewModel() {
+class ResolverViewModel @Inject constructor(activityModelrepo: ActivityModelRepository) :
+    ViewModel() {
 
     /** Parcelable-only references provided from the creating Activity */
-    val activityModel: ActivityModel =
-        requireNotNull(args[ACTIVITY_MODEL_KEY]) {
-            "ActivityModel missing in SavedStateHandle! ($ACTIVITY_MODEL_KEY)"
-        }
+    val activityModel: ActivityModel = activityModelrepo.value
 
     /**
      * Provided only for the express purpose of early exit in the event of an invalid request.
diff --git a/java/src/com/android/intentresolver/widget/ChooserNestedScrollView.kt b/java/src/com/android/intentresolver/widget/ChooserNestedScrollView.kt
index e86de888..a9577cf5 100644
--- a/java/src/com/android/intentresolver/widget/ChooserNestedScrollView.kt
+++ b/java/src/com/android/intentresolver/widget/ChooserNestedScrollView.kt
@@ -25,7 +25,7 @@ import androidx.core.view.marginBottom
 import androidx.core.view.marginLeft
 import androidx.core.view.marginRight
 import androidx.core.view.marginTop
-import androidx.core.widget.NestedScrollView
+import com.android.intentresolver.Flags.keyboardNavigationFix
 
 /**
  * A narrowly tailored [NestedScrollView] to be used inside [ResolverDrawerLayout] and help to
@@ -35,13 +35,17 @@ import androidx.core.widget.NestedScrollView
  */
 class ChooserNestedScrollView : NestedScrollView {
     constructor(context: Context) : super(context)
+
     constructor(context: Context, attrs: AttributeSet?) : super(context, attrs)
+
     constructor(
         context: Context,
         attrs: AttributeSet?,
-        defStyleAttr: Int
+        defStyleAttr: Int,
     ) : super(context, attrs, defStyleAttr)
 
+    var requestChildFocusPredicate: (View?, View?) -> Boolean = DefaultChildFocusPredicate
+
     override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
         val content =
             getChildAt(0) as? LinearLayout ?: error("Exactly one child, LinerLayout, is expected")
@@ -55,13 +59,13 @@ class ChooserNestedScrollView : NestedScrollView {
             getChildMeasureSpec(
                 widthMeasureSpec,
                 paddingLeft + content.marginLeft + content.marginRight + paddingRight,
-                lp.width
+                lp.width,
             )
         val contentHeightSpec =
             getChildMeasureSpec(
                 heightMeasureSpec,
                 paddingTop + content.marginTop + content.marginBottom + paddingBottom,
-                lp.height
+                lp.height,
             )
         content.measure(contentWidthSpec, contentHeightSpec)
 
@@ -76,7 +80,7 @@ class ChooserNestedScrollView : NestedScrollView {
 
             content.measure(
                 contentWidthSpec,
-                MeasureSpec.makeMeasureSpec(height, MeasureSpec.getMode(heightMeasureSpec))
+                MeasureSpec.makeMeasureSpec(height, MeasureSpec.getMode(heightMeasureSpec)),
             )
         }
         setMeasuredDimension(
@@ -87,8 +91,8 @@ class ChooserNestedScrollView : NestedScrollView {
                     content.marginTop +
                     content.measuredHeight +
                     content.marginBottom +
-                    paddingBottom
-            )
+                    paddingBottom,
+            ),
         )
     }
 
@@ -103,4 +107,18 @@ class ChooserNestedScrollView : NestedScrollView {
             consumed[1] += scrollY - preScrollY
         }
     }
+
+    override fun onRequestChildFocus(child: View?, focused: View?) {
+        if (keyboardNavigationFix()) {
+            if (requestChildFocusPredicate(child, focused)) {
+                super.onRequestChildFocus(child, focused)
+            }
+        } else {
+            super.onRequestChildFocus(child, focused)
+        }
+    }
+
+    companion object {
+        val DefaultChildFocusPredicate: (View?, View?) -> Boolean = { _, _ -> true }
+    }
 }
diff --git a/java/src/com/android/intentresolver/widget/ChooserTargetItemView.kt b/java/src/com/android/intentresolver/widget/ChooserTargetItemView.kt
new file mode 100644
index 00000000..b5a4d617
--- /dev/null
+++ b/java/src/com/android/intentresolver/widget/ChooserTargetItemView.kt
@@ -0,0 +1,141 @@
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
+package com.android.intentresolver.widget
+
+import android.content.Context
+import android.graphics.Canvas
+import android.graphics.Color
+import android.graphics.Paint
+import android.util.AttributeSet
+import android.util.TypedValue
+import android.view.MotionEvent
+import android.view.View
+import android.widget.ImageView
+import android.widget.LinearLayout
+import com.android.intentresolver.R
+
+class ChooserTargetItemView(
+    context: Context,
+    attrs: AttributeSet?,
+    defStyleAttr: Int,
+    defStyleRes: Int,
+) : LinearLayout(context, attrs, defStyleAttr, defStyleRes) {
+    private val outlineRadius: Float
+    private val outlineWidth: Float
+    private val outlinePaint: Paint =
+        Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
+    private val outlineInnerPaint: Paint =
+        Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
+    private var iconView: ImageView? = null
+
+    constructor(context: Context) : this(context, null)
+
+    constructor(context: Context, attrs: AttributeSet?) : this(context, attrs, 0)
+
+    constructor(
+        context: Context,
+        attrs: AttributeSet?,
+        defStyleAttr: Int,
+    ) : this(context, attrs, defStyleAttr, 0)
+
+    init {
+        val a = context.obtainStyledAttributes(attrs, R.styleable.ChooserTargetItemView)
+        val defaultWidth =
+            TypedValue.applyDimension(
+                TypedValue.COMPLEX_UNIT_DIP,
+                2f,
+                context.resources.displayMetrics,
+            )
+        outlineRadius =
+            a.getDimension(R.styleable.ChooserTargetItemView_focusOutlineCornerRadius, 0f)
+        outlineWidth =
+            a.getDimension(R.styleable.ChooserTargetItemView_focusOutlineWidth, defaultWidth)
+
+        outlinePaint.strokeWidth = outlineWidth
+        outlinePaint.color =
+            a.getColor(R.styleable.ChooserTargetItemView_focusOutlineColor, Color.TRANSPARENT)
+
+        outlineInnerPaint.strokeWidth = outlineWidth
+        outlineInnerPaint.color =
+            a.getColor(R.styleable.ChooserTargetItemView_focusInnerOutlineColor, Color.TRANSPARENT)
+        a.recycle()
+    }
+
+    override fun onViewAdded(child: View) {
+        super.onViewAdded(child)
+        if (child is ImageView) {
+            iconView = child
+        }
+    }
+
+    override fun onViewRemoved(child: View?) {
+        super.onViewRemoved(child)
+        if (child === iconView) {
+            iconView = null
+        }
+    }
+
+    override fun onHoverEvent(event: MotionEvent): Boolean {
+        val iconView = iconView ?: return false
+        if (!isEnabled) return true
+        when (event.action) {
+            MotionEvent.ACTION_HOVER_ENTER -> {
+                iconView.isHovered = true
+            }
+            MotionEvent.ACTION_HOVER_EXIT -> {
+                iconView.isHovered = false
+            }
+        }
+        return true
+    }
+
+    override fun onInterceptHoverEvent(event: MotionEvent?) = true
+
+    override fun dispatchDraw(canvas: Canvas) {
+        super.dispatchDraw(canvas)
+        if (isFocused) {
+            drawFocusInnerOutline(canvas)
+            drawFocusOutline(canvas)
+        }
+    }
+
+    private fun drawFocusInnerOutline(canvas: Canvas) {
+        val outlineOffset = outlineWidth + outlineWidth / 2
+        canvas.drawRoundRect(
+            outlineOffset,
+            outlineOffset,
+            maxOf(0f, width - outlineOffset),
+            maxOf(0f, height - outlineOffset),
+            outlineRadius - outlineWidth,
+            outlineRadius - outlineWidth,
+            outlineInnerPaint,
+        )
+    }
+
+    private fun drawFocusOutline(canvas: Canvas) {
+        val outlineOffset = outlineWidth / 2
+        canvas.drawRoundRect(
+            outlineOffset,
+            outlineOffset,
+            maxOf(0f, width - outlineOffset),
+            maxOf(0f, height - outlineOffset),
+            outlineRadius,
+            outlineRadius,
+            outlinePaint,
+        )
+    }
+}
diff --git a/java/src/com/android/intentresolver/widget/NestedScrollView.java b/java/src/com/android/intentresolver/widget/NestedScrollView.java
new file mode 100644
index 00000000..36fc7da6
--- /dev/null
+++ b/java/src/com/android/intentresolver/widget/NestedScrollView.java
@@ -0,0 +1,2611 @@
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
+
+package com.android.intentresolver.widget;
+
+import static androidx.annotation.RestrictTo.Scope.LIBRARY;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.graphics.Canvas;
+import android.graphics.Rect;
+import android.hardware.SensorManager;
+import android.os.Build;
+import android.os.Bundle;
+import android.os.Parcel;
+import android.os.Parcelable;
+import android.util.AttributeSet;
+import android.util.Log;
+import android.util.TypedValue;
+import android.view.FocusFinder;
+import android.view.InputDevice;
+import android.view.KeyEvent;
+import android.view.MotionEvent;
+import android.view.VelocityTracker;
+import android.view.View;
+import android.view.ViewConfiguration;
+import android.view.ViewGroup;
+import android.view.ViewParent;
+import android.view.accessibility.AccessibilityEvent;
+import android.view.animation.AnimationUtils;
+import android.widget.EdgeEffect;
+import android.widget.FrameLayout;
+import android.widget.OverScroller;
+import android.widget.ScrollView;
+
+import androidx.annotation.DoNotInline;
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.annotation.RequiresApi;
+import androidx.annotation.RestrictTo;
+import androidx.annotation.VisibleForTesting;
+import androidx.core.R;
+import androidx.core.view.AccessibilityDelegateCompat;
+import androidx.core.view.DifferentialMotionFlingController;
+import androidx.core.view.DifferentialMotionFlingTarget;
+import androidx.core.view.MotionEventCompat;
+import androidx.core.view.NestedScrollingChild3;
+import androidx.core.view.NestedScrollingChildHelper;
+import androidx.core.view.NestedScrollingParent3;
+import androidx.core.view.NestedScrollingParentHelper;
+import androidx.core.view.ScrollingView;
+import androidx.core.view.ViewCompat;
+import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
+import androidx.core.view.accessibility.AccessibilityRecordCompat;
+import androidx.core.widget.EdgeEffectCompat;
+
+import java.util.List;
+
+/**
+ * A copy of the {@link androidx.core.widget.NestedScrollView} (from
+ * prebuilts/sdk/current/androidx/m2repository/androidx/core/core/1.13.0-beta01/core-1.13.0-beta01-sources.jar)
+ * without any functional changes with a pure refactoring of {@link #requestChildFocus(View, View)}:
+ * the method's body is extracted into the new protected method,
+ * {@link #onRequestChildFocus(View, View)}.
+ * <p>
+ * For the exact change see NestedScrollView.java.patch file.
+ * </p>
+ */
+public class NestedScrollView extends FrameLayout implements NestedScrollingParent3,
+        NestedScrollingChild3, ScrollingView {
+    static final int ANIMATED_SCROLL_GAP = 250;
+
+    static final float MAX_SCROLL_FACTOR = 0.5f;
+
+    private static final String TAG = "NestedScrollView";
+    private static final int DEFAULT_SMOOTH_SCROLL_DURATION = 250;
+
+    /**
+     * The following are copied from OverScroller to determine how far a fling will go.
+     */
+    private static final float SCROLL_FRICTION = 0.015f;
+    private static final float INFLEXION = 0.35f; // Tension lines cross at (INFLEXION, 1)
+    private static final float DECELERATION_RATE = (float) (Math.log(0.78) / Math.log(0.9));
+    private final float mPhysicalCoeff;
+
+    /**
+     * When flinging the stretch towards scrolling content, it should destretch quicker than the
+     * fling would normally do. The visual effect of flinging the stretch looks strange as little
+     * appears to happen at first and then when the stretch disappears, the content starts
+     * scrolling quickly.
+     */
+    private static final float FLING_DESTRETCH_FACTOR = 4f;
+
+    /**
+     * Interface definition for a callback to be invoked when the scroll
+     * X or Y positions of a view change.
+     *
+     * <p>This version of the interface works on all versions of Android, back to API v4.</p>
+     *
+     * @see #setOnScrollChangeListener(OnScrollChangeListener)
+     */
+    public interface OnScrollChangeListener {
+        /**
+         * Called when the scroll position of a view changes.
+         * @param v The view whose scroll position has changed.
+         * @param scrollX Current horizontal scroll origin.
+         * @param scrollY Current vertical scroll origin.
+         * @param oldScrollX Previous horizontal scroll origin.
+         * @param oldScrollY Previous vertical scroll origin.
+         */
+        void onScrollChange(@NonNull NestedScrollView v, int scrollX, int scrollY,
+                int oldScrollX, int oldScrollY);
+    }
+
+    private long mLastScroll;
+
+    private final Rect mTempRect = new Rect();
+    private OverScroller mScroller;
+
+    @RestrictTo(LIBRARY)
+    @VisibleForTesting
+    @NonNull
+    public EdgeEffect mEdgeGlowTop;
+
+    @RestrictTo(LIBRARY)
+    @VisibleForTesting
+    @NonNull
+    public EdgeEffect mEdgeGlowBottom;
+
+    /**
+     * Position of the last motion event; only used with touch related events (usually to assist
+     * in movement changes in a drag gesture).
+     */
+    private int mLastMotionY;
+
+    /**
+     * True when the layout has changed but the traversal has not come through yet.
+     * Ideally the view hierarchy would keep track of this for us.
+     */
+    private boolean mIsLayoutDirty = true;
+    private boolean mIsLaidOut = false;
+
+    /**
+     * The child to give focus to in the event that a child has requested focus while the
+     * layout is dirty. This prevents the scroll from being wrong if the child has not been
+     * laid out before requesting focus.
+     */
+    private View mChildToScrollTo = null;
+
+    /**
+     * True if the user is currently dragging this ScrollView around. This is
+     * not the same as 'is being flinged', which can be checked by
+     * mScroller.isFinished() (flinging begins when the user lifts their finger).
+     */
+    private boolean mIsBeingDragged = false;
+
+    /**
+     * Determines speed during touch scrolling
+     */
+    private VelocityTracker mVelocityTracker;
+
+    /**
+     * When set to true, the scroll view measure its child to make it fill the currently
+     * visible area.
+     */
+    private boolean mFillViewport;
+
+    /**
+     * Whether arrow scrolling is animated.
+     */
+    private boolean mSmoothScrollingEnabled = true;
+
+    private int mTouchSlop;
+    private int mMinimumVelocity;
+    private int mMaximumVelocity;
+
+    /**
+     * ID of the active pointer. This is used to retain consistency during
+     * drags/flings if multiple pointers are used.
+     */
+    private int mActivePointerId = INVALID_POINTER;
+
+    /**
+     * Used during scrolling to retrieve the new offset within the window. Saves memory by saving
+     * x, y changes to this array (0 position = x, 1 position = y) vs. reallocating an x and y
+     * every time.
+     */
+    private final int[] mScrollOffset = new int[2];
+
+    /*
+     * Used during scrolling to retrieve the new consumed offset within the window.
+     * Uses same memory saving strategy as mScrollOffset.
+     */
+    private final int[] mScrollConsumed = new int[2];
+
+    // Used to track the position of the touch only events relative to the container.
+    private int mNestedYOffset;
+
+    private int mLastScrollerY;
+
+    /**
+     * Sentinel value for no current active pointer.
+     * Used by {@link #mActivePointerId}.
+     */
+    private static final int INVALID_POINTER = -1;
+
+    private SavedState mSavedState;
+
+    private static final AccessibilityDelegate ACCESSIBILITY_DELEGATE = new AccessibilityDelegate();
+
+    private static final int[] SCROLLVIEW_STYLEABLE = new int[] {
+            android.R.attr.fillViewport
+    };
+
+    private final NestedScrollingParentHelper mParentHelper;
+    private final NestedScrollingChildHelper mChildHelper;
+
+    private float mVerticalScrollFactor;
+
+    private OnScrollChangeListener mOnScrollChangeListener;
+
+    @VisibleForTesting
+    final DifferentialMotionFlingTargetImpl mDifferentialMotionFlingTarget =
+            new DifferentialMotionFlingTargetImpl();
+
+    @VisibleForTesting
+    DifferentialMotionFlingController mDifferentialMotionFlingController =
+            new DifferentialMotionFlingController(getContext(), mDifferentialMotionFlingTarget);
+
+    public NestedScrollView(@NonNull Context context) {
+        this(context, null);
+    }
+
+    public NestedScrollView(@NonNull Context context, @Nullable AttributeSet attrs) {
+        this(context, attrs, R.attr.nestedScrollViewStyle);
+    }
+
+    public NestedScrollView(@NonNull Context context, @Nullable AttributeSet attrs,
+            int defStyleAttr) {
+        super(context, attrs, defStyleAttr);
+        mEdgeGlowTop = EdgeEffectCompat.create(context, attrs);
+        mEdgeGlowBottom = EdgeEffectCompat.create(context, attrs);
+
+        final float ppi = context.getResources().getDisplayMetrics().density * 160.0f;
+        mPhysicalCoeff = SensorManager.GRAVITY_EARTH // g (m/s^2)
+                * 39.37f // inch/meter
+                * ppi
+                * 0.84f; // look and feel tuning
+
+        initScrollView();
+
+        final TypedArray a = context.obtainStyledAttributes(
+                attrs, SCROLLVIEW_STYLEABLE, defStyleAttr, 0);
+
+        setFillViewport(a.getBoolean(0, false));
+
+        a.recycle();
+
+        mParentHelper = new NestedScrollingParentHelper(this);
+        mChildHelper = new NestedScrollingChildHelper(this);
+
+        // ...because why else would you be using this widget?
+        setNestedScrollingEnabled(true);
+
+        ViewCompat.setAccessibilityDelegate(this, ACCESSIBILITY_DELEGATE);
+    }
+
+    // NestedScrollingChild3
+
+    @Override
+    public void dispatchNestedScroll(int dxConsumed, int dyConsumed, int dxUnconsumed,
+            int dyUnconsumed, @Nullable int[] offsetInWindow, int type, @NonNull int[] consumed) {
+        mChildHelper.dispatchNestedScroll(dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed,
+                offsetInWindow, type, consumed);
+    }
+
+    // NestedScrollingChild2
+
+    @Override
+    public boolean startNestedScroll(int axes, int type) {
+        return mChildHelper.startNestedScroll(axes, type);
+    }
+
+    @Override
+    public void stopNestedScroll(int type) {
+        mChildHelper.stopNestedScroll(type);
+    }
+
+    @Override
+    public boolean hasNestedScrollingParent(int type) {
+        return mChildHelper.hasNestedScrollingParent(type);
+    }
+
+    @Override
+    public boolean dispatchNestedScroll(int dxConsumed, int dyConsumed, int dxUnconsumed,
+            int dyUnconsumed, @Nullable int[] offsetInWindow, int type) {
+        return mChildHelper.dispatchNestedScroll(dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed,
+                offsetInWindow, type);
+    }
+
+    @Override
+    public boolean dispatchNestedPreScroll(
+            int dx,
+            int dy,
+            @Nullable int[] consumed,
+            @Nullable int[] offsetInWindow,
+            int type
+    ) {
+        return mChildHelper.dispatchNestedPreScroll(dx, dy, consumed, offsetInWindow, type);
+    }
+
+    // NestedScrollingChild
+
+    @Override
+    public void setNestedScrollingEnabled(boolean enabled) {
+        mChildHelper.setNestedScrollingEnabled(enabled);
+    }
+
+    @Override
+    public boolean isNestedScrollingEnabled() {
+        return mChildHelper.isNestedScrollingEnabled();
+    }
+
+    @Override
+    public boolean startNestedScroll(int axes) {
+        return startNestedScroll(axes, ViewCompat.TYPE_TOUCH);
+    }
+
+    @Override
+    public void stopNestedScroll() {
+        stopNestedScroll(ViewCompat.TYPE_TOUCH);
+    }
+
+    @Override
+    public boolean hasNestedScrollingParent() {
+        return hasNestedScrollingParent(ViewCompat.TYPE_TOUCH);
+    }
+
+    @Override
+    public boolean dispatchNestedScroll(int dxConsumed, int dyConsumed, int dxUnconsumed,
+            int dyUnconsumed, @Nullable int[] offsetInWindow) {
+        return mChildHelper.dispatchNestedScroll(dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed,
+                offsetInWindow);
+    }
+
+    @Override
+    public boolean dispatchNestedPreScroll(int dx, int dy, @Nullable int[] consumed,
+            @Nullable int[] offsetInWindow) {
+        return dispatchNestedPreScroll(dx, dy, consumed, offsetInWindow, ViewCompat.TYPE_TOUCH);
+    }
+
+    @Override
+    public boolean dispatchNestedFling(float velocityX, float velocityY, boolean consumed) {
+        return mChildHelper.dispatchNestedFling(velocityX, velocityY, consumed);
+    }
+
+    @Override
+    public boolean dispatchNestedPreFling(float velocityX, float velocityY) {
+        return mChildHelper.dispatchNestedPreFling(velocityX, velocityY);
+    }
+
+    // NestedScrollingParent3
+
+    @Override
+    public void onNestedScroll(@NonNull View target, int dxConsumed, int dyConsumed,
+            int dxUnconsumed, int dyUnconsumed, int type, @NonNull int[] consumed) {
+        onNestedScrollInternal(dyUnconsumed, type, consumed);
+    }
+
+    private void onNestedScrollInternal(int dyUnconsumed, int type, @Nullable int[] consumed) {
+        final int oldScrollY = getScrollY();
+        scrollBy(0, dyUnconsumed);
+        final int myConsumed = getScrollY() - oldScrollY;
+
+        if (consumed != null) {
+            consumed[1] += myConsumed;
+        }
+        final int myUnconsumed = dyUnconsumed - myConsumed;
+
+        mChildHelper.dispatchNestedScroll(0, myConsumed, 0, myUnconsumed, null, type, consumed);
+    }
+
+    // NestedScrollingParent2
+
+    @Override
+    public boolean onStartNestedScroll(@NonNull View child, @NonNull View target, int axes,
+            int type) {
+        return (axes & ViewCompat.SCROLL_AXIS_VERTICAL) != 0;
+    }
+
+    @Override
+    public void onNestedScrollAccepted(@NonNull View child, @NonNull View target, int axes,
+            int type) {
+        mParentHelper.onNestedScrollAccepted(child, target, axes, type);
+        startNestedScroll(ViewCompat.SCROLL_AXIS_VERTICAL, type);
+    }
+
+    @Override
+    public void onStopNestedScroll(@NonNull View target, int type) {
+        mParentHelper.onStopNestedScroll(target, type);
+        stopNestedScroll(type);
+    }
+
+    @Override
+    public void onNestedScroll(@NonNull View target, int dxConsumed, int dyConsumed,
+            int dxUnconsumed, int dyUnconsumed, int type) {
+        onNestedScrollInternal(dyUnconsumed, type, null);
+    }
+
+    @Override
+    public void onNestedPreScroll(@NonNull View target, int dx, int dy, @NonNull int[] consumed,
+            int type) {
+        dispatchNestedPreScroll(dx, dy, consumed, null, type);
+    }
+
+    // NestedScrollingParent
+
+    @Override
+    public boolean onStartNestedScroll(
+            @NonNull View child, @NonNull View target, int axes) {
+        return onStartNestedScroll(child, target, axes, ViewCompat.TYPE_TOUCH);
+    }
+
+    @Override
+    public void onNestedScrollAccepted(
+            @NonNull View child, @NonNull View target, int axes) {
+        onNestedScrollAccepted(child, target, axes, ViewCompat.TYPE_TOUCH);
+    }
+
+    @Override
+    public void onStopNestedScroll(@NonNull View target) {
+        onStopNestedScroll(target, ViewCompat.TYPE_TOUCH);
+    }
+
+    @Override
+    public void onNestedScroll(@NonNull View target, int dxConsumed, int dyConsumed,
+            int dxUnconsumed, int dyUnconsumed) {
+        onNestedScrollInternal(dyUnconsumed, ViewCompat.TYPE_TOUCH, null);
+    }
+
+    @Override
+    public void onNestedPreScroll(@NonNull View target, int dx, int dy, @NonNull int[] consumed) {
+        onNestedPreScroll(target, dx, dy, consumed, ViewCompat.TYPE_TOUCH);
+    }
+
+    @Override
+    public boolean onNestedFling(
+            @NonNull View target, float velocityX, float velocityY, boolean consumed) {
+        if (!consumed) {
+            dispatchNestedFling(0, velocityY, true);
+            fling((int) velocityY);
+            return true;
+        }
+        return false;
+    }
+
+    @Override
+    public boolean onNestedPreFling(@NonNull View target, float velocityX, float velocityY) {
+        return dispatchNestedPreFling(velocityX, velocityY);
+    }
+
+    @Override
+    public int getNestedScrollAxes() {
+        return mParentHelper.getNestedScrollAxes();
+    }
+
+    // ScrollView import
+
+    @Override
+    public boolean shouldDelayChildPressedState() {
+        return true;
+    }
+
+    @Override
+    protected float getTopFadingEdgeStrength() {
+        if (getChildCount() == 0) {
+            return 0.0f;
+        }
+
+        final int length = getVerticalFadingEdgeLength();
+        final int scrollY = getScrollY();
+        if (scrollY < length) {
+            return scrollY / (float) length;
+        }
+
+        return 1.0f;
+    }
+
+    @Override
+    protected float getBottomFadingEdgeStrength() {
+        if (getChildCount() == 0) {
+            return 0.0f;
+        }
+
+        View child = getChildAt(0);
+        final LayoutParams lp = (LayoutParams) child.getLayoutParams();
+        final int length = getVerticalFadingEdgeLength();
+        final int bottomEdge = getHeight() - getPaddingBottom();
+        final int span = child.getBottom() + lp.bottomMargin - getScrollY() - bottomEdge;
+        if (span < length) {
+            return span / (float) length;
+        }
+
+        return 1.0f;
+    }
+
+    /**
+     * @return The maximum amount this scroll view will scroll in response to
+     *   an arrow event.
+     */
+    public int getMaxScrollAmount() {
+        return (int) (MAX_SCROLL_FACTOR * getHeight());
+    }
+
+    private void initScrollView() {
+        mScroller = new OverScroller(getContext());
+        setFocusable(true);
+        setDescendantFocusability(FOCUS_AFTER_DESCENDANTS);
+        setWillNotDraw(false);
+        final ViewConfiguration configuration = ViewConfiguration.get(getContext());
+        mTouchSlop = configuration.getScaledTouchSlop();
+        mMinimumVelocity = configuration.getScaledMinimumFlingVelocity();
+        mMaximumVelocity = configuration.getScaledMaximumFlingVelocity();
+    }
+
+    @Override
+    public void addView(@NonNull View child) {
+        if (getChildCount() > 0) {
+            throw new IllegalStateException("ScrollView can host only one direct child");
+        }
+
+        super.addView(child);
+    }
+
+    @Override
+    public void addView(View child, int index) {
+        if (getChildCount() > 0) {
+            throw new IllegalStateException("ScrollView can host only one direct child");
+        }
+
+        super.addView(child, index);
+    }
+
+    @Override
+    public void addView(View child, ViewGroup.LayoutParams params) {
+        if (getChildCount() > 0) {
+            throw new IllegalStateException("ScrollView can host only one direct child");
+        }
+
+        super.addView(child, params);
+    }
+
+    @Override
+    public void addView(View child, int index, ViewGroup.LayoutParams params) {
+        if (getChildCount() > 0) {
+            throw new IllegalStateException("ScrollView can host only one direct child");
+        }
+
+        super.addView(child, index, params);
+    }
+
+    /**
+     * Register a callback to be invoked when the scroll X or Y positions of
+     * this view change.
+     * <p>This version of the method works on all versions of Android, back to API v4.</p>
+     *
+     * @param l The listener to notify when the scroll X or Y position changes.
+     * @see View#getScrollX()
+     * @see View#getScrollY()
+     */
+    public void setOnScrollChangeListener(@Nullable OnScrollChangeListener l) {
+        mOnScrollChangeListener = l;
+    }
+
+    /**
+     * @return Returns true this ScrollView can be scrolled
+     */
+    private boolean canScroll() {
+        if (getChildCount() > 0) {
+            View child = getChildAt(0);
+            final LayoutParams lp = (LayoutParams) child.getLayoutParams();
+            int childSize = child.getHeight() + lp.topMargin + lp.bottomMargin;
+            int parentSpace = getHeight() - getPaddingTop() - getPaddingBottom();
+            return childSize > parentSpace;
+        }
+        return false;
+    }
+
+    /**
+     * Indicates whether this ScrollView's content is stretched to fill the viewport.
+     *
+     * @return True if the content fills the viewport, false otherwise.
+     *
+     * @attr name android:fillViewport
+     */
+    public boolean isFillViewport() {
+        return mFillViewport;
+    }
+
+    /**
+     * Set whether this ScrollView should stretch its content height to fill the viewport or not.
+     *
+     * @param fillViewport True to stretch the content's height to the viewport's
+     *        boundaries, false otherwise.
+     *
+     * @attr name android:fillViewport
+     */
+    public void setFillViewport(boolean fillViewport) {
+        if (fillViewport != mFillViewport) {
+            mFillViewport = fillViewport;
+            requestLayout();
+        }
+    }
+
+    /**
+     * @return Whether arrow scrolling will animate its transition.
+     */
+    public boolean isSmoothScrollingEnabled() {
+        return mSmoothScrollingEnabled;
+    }
+
+    /**
+     * Set whether arrow scrolling will animate its transition.
+     * @param smoothScrollingEnabled whether arrow scrolling will animate its transition
+     */
+    public void setSmoothScrollingEnabled(boolean smoothScrollingEnabled) {
+        mSmoothScrollingEnabled = smoothScrollingEnabled;
+    }
+
+    @Override
+    protected void onScrollChanged(int l, int t, int oldl, int oldt) {
+        super.onScrollChanged(l, t, oldl, oldt);
+
+        if (mOnScrollChangeListener != null) {
+            mOnScrollChangeListener.onScrollChange(this, l, t, oldl, oldt);
+        }
+    }
+
+    @Override
+    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
+        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
+
+        if (!mFillViewport) {
+            return;
+        }
+
+        final int heightMode = MeasureSpec.getMode(heightMeasureSpec);
+        if (heightMode == MeasureSpec.UNSPECIFIED) {
+            return;
+        }
+
+        if (getChildCount() > 0) {
+            View child = getChildAt(0);
+            final LayoutParams lp = (LayoutParams) child.getLayoutParams();
+
+            int childSize = child.getMeasuredHeight();
+            int parentSpace = getMeasuredHeight()
+                    - getPaddingTop()
+                    - getPaddingBottom()
+                    - lp.topMargin
+                    - lp.bottomMargin;
+
+            if (childSize < parentSpace) {
+                int childWidthMeasureSpec = getChildMeasureSpec(widthMeasureSpec,
+                        getPaddingLeft() + getPaddingRight() + lp.leftMargin + lp.rightMargin,
+                        lp.width);
+                int childHeightMeasureSpec =
+                        MeasureSpec.makeMeasureSpec(parentSpace, MeasureSpec.EXACTLY);
+                child.measure(childWidthMeasureSpec, childHeightMeasureSpec);
+            }
+        }
+    }
+
+    @Override
+    public boolean dispatchKeyEvent(KeyEvent event) {
+        // Let the focused view and/or our descendants get the key first
+        return super.dispatchKeyEvent(event) || executeKeyEvent(event);
+    }
+
+    /**
+     * You can call this function yourself to have the scroll view perform
+     * scrolling from a key event, just as if the event had been dispatched to
+     * it by the view hierarchy.
+     *
+     * @param event The key event to execute.
+     * @return Return true if the event was handled, else false.
+     */
+    public boolean executeKeyEvent(@NonNull KeyEvent event) {
+        mTempRect.setEmpty();
+
+        if (!canScroll()) {
+            if (isFocused() && event.getKeyCode() != KeyEvent.KEYCODE_BACK) {
+                View currentFocused = findFocus();
+                if (currentFocused == this) currentFocused = null;
+                View nextFocused = FocusFinder.getInstance().findNextFocus(this,
+                        currentFocused, View.FOCUS_DOWN);
+                return nextFocused != null
+                        && nextFocused != this
+                        && nextFocused.requestFocus(View.FOCUS_DOWN);
+            }
+            return false;
+        }
+
+        boolean handled = false;
+        if (event.getAction() == KeyEvent.ACTION_DOWN) {
+            switch (event.getKeyCode()) {
+                case KeyEvent.KEYCODE_DPAD_UP:
+                    if (event.isAltPressed()) {
+                        handled = fullScroll(View.FOCUS_UP);
+                    } else {
+                        handled = arrowScroll(View.FOCUS_UP);
+                    }
+                    break;
+                case KeyEvent.KEYCODE_DPAD_DOWN:
+                    if (event.isAltPressed()) {
+                        handled = fullScroll(View.FOCUS_DOWN);
+                    } else {
+                        handled = arrowScroll(View.FOCUS_DOWN);
+                    }
+                    break;
+                case KeyEvent.KEYCODE_PAGE_UP:
+                    handled = fullScroll(View.FOCUS_UP);
+                    break;
+                case KeyEvent.KEYCODE_PAGE_DOWN:
+                    handled = fullScroll(View.FOCUS_DOWN);
+                    break;
+                case KeyEvent.KEYCODE_SPACE:
+                    pageScroll(event.isShiftPressed() ? View.FOCUS_UP : View.FOCUS_DOWN);
+                    break;
+                case KeyEvent.KEYCODE_MOVE_HOME:
+                    pageScroll(View.FOCUS_UP);
+                    break;
+                case KeyEvent.KEYCODE_MOVE_END:
+                    pageScroll(View.FOCUS_DOWN);
+                    break;
+            }
+        }
+
+        return handled;
+    }
+
+    private boolean inChild(int x, int y) {
+        if (getChildCount() > 0) {
+            final int scrollY = getScrollY();
+            final View child = getChildAt(0);
+            return !(y < child.getTop() - scrollY
+                    || y >= child.getBottom() - scrollY
+                    || x < child.getLeft()
+                    || x >= child.getRight());
+        }
+        return false;
+    }
+
+    private void initOrResetVelocityTracker() {
+        if (mVelocityTracker == null) {
+            mVelocityTracker = VelocityTracker.obtain();
+        } else {
+            mVelocityTracker.clear();
+        }
+    }
+
+    private void initVelocityTrackerIfNotExists() {
+        if (mVelocityTracker == null) {
+            mVelocityTracker = VelocityTracker.obtain();
+        }
+    }
+
+    private void recycleVelocityTracker() {
+        if (mVelocityTracker != null) {
+            mVelocityTracker.recycle();
+            mVelocityTracker = null;
+        }
+    }
+
+    @Override
+    public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
+        if (disallowIntercept) {
+            recycleVelocityTracker();
+        }
+        super.requestDisallowInterceptTouchEvent(disallowIntercept);
+    }
+
+    @Override
+    public boolean onInterceptTouchEvent(@NonNull MotionEvent ev) {
+        /*
+         * This method JUST determines whether we want to intercept the motion.
+         * If we return true, onMotionEvent will be called and we do the actual
+         * scrolling there.
+         */
+
+        /*
+        * Shortcut the most recurring case: the user is in the dragging
+        * state and they are moving their finger.  We want to intercept this
+        * motion.
+        */
+        final int action = ev.getAction();
+        if ((action == MotionEvent.ACTION_MOVE) && mIsBeingDragged) {
+            return true;
+        }
+
+        switch (action & MotionEvent.ACTION_MASK) {
+            case MotionEvent.ACTION_MOVE: {
+                /*
+                 * mIsBeingDragged == false, otherwise the shortcut would have caught it. Check
+                 * whether the user has moved far enough from their original down touch.
+                 */
+
+                /*
+                * Locally do absolute value. mLastMotionY is set to the y value
+                * of the down event.
+                */
+                final int activePointerId = mActivePointerId;
+                if (activePointerId == INVALID_POINTER) {
+                    // If we don't have a valid id, the touch down wasn't on content.
+                    break;
+                }
+
+                final int pointerIndex = ev.findPointerIndex(activePointerId);
+                if (pointerIndex == -1) {
+                    Log.e(TAG, "Invalid pointerId=" + activePointerId
+                            + " in onInterceptTouchEvent");
+                    break;
+                }
+
+                final int y = (int) ev.getY(pointerIndex);
+                final int yDiff = Math.abs(y - mLastMotionY);
+                if (yDiff > mTouchSlop
+                        && (getNestedScrollAxes() & ViewCompat.SCROLL_AXIS_VERTICAL) == 0) {
+                    mIsBeingDragged = true;
+                    mLastMotionY = y;
+                    initVelocityTrackerIfNotExists();
+                    mVelocityTracker.addMovement(ev);
+                    mNestedYOffset = 0;
+                    final ViewParent parent = getParent();
+                    if (parent != null) {
+                        parent.requestDisallowInterceptTouchEvent(true);
+                    }
+                }
+                break;
+            }
+
+            case MotionEvent.ACTION_DOWN: {
+                final int y = (int) ev.getY();
+                if (!inChild((int) ev.getX(), y)) {
+                    mIsBeingDragged = stopGlowAnimations(ev) || !mScroller.isFinished();
+                    recycleVelocityTracker();
+                    break;
+                }
+
+                /*
+                 * Remember location of down touch.
+                 * ACTION_DOWN always refers to pointer index 0.
+                 */
+                mLastMotionY = y;
+                mActivePointerId = ev.getPointerId(0);
+
+                initOrResetVelocityTracker();
+                mVelocityTracker.addMovement(ev);
+                /*
+                 * If being flinged and user touches the screen, initiate drag;
+                 * otherwise don't. mScroller.isFinished should be false when
+                 * being flinged. We also want to catch the edge glow and start dragging
+                 * if one is being animated. We need to call computeScrollOffset() first so that
+                 * isFinished() is correct.
+                */
+                mScroller.computeScrollOffset();
+                mIsBeingDragged = stopGlowAnimations(ev) || !mScroller.isFinished();
+                startNestedScroll(ViewCompat.SCROLL_AXIS_VERTICAL, ViewCompat.TYPE_TOUCH);
+                break;
+            }
+
+            case MotionEvent.ACTION_CANCEL:
+            case MotionEvent.ACTION_UP:
+                /* Release the drag */
+                mIsBeingDragged = false;
+                mActivePointerId = INVALID_POINTER;
+                recycleVelocityTracker();
+                if (mScroller.springBack(getScrollX(), getScrollY(), 0, 0, 0, getScrollRange())) {
+                    postInvalidateOnAnimation();
+                }
+                stopNestedScroll(ViewCompat.TYPE_TOUCH);
+                break;
+            case MotionEvent.ACTION_POINTER_UP:
+                onSecondaryPointerUp(ev);
+                break;
+        }
+
+        /*
+        * The only time we want to intercept motion events is if we are in the
+        * drag mode.
+        */
+        return mIsBeingDragged;
+    }
+
+    @Override
+    public boolean onTouchEvent(@NonNull MotionEvent motionEvent) {
+        initVelocityTrackerIfNotExists();
+
+        final int actionMasked = motionEvent.getActionMasked();
+
+        if (actionMasked == MotionEvent.ACTION_DOWN) {
+            mNestedYOffset = 0;
+        }
+
+        MotionEvent velocityTrackerMotionEvent = MotionEvent.obtain(motionEvent);
+        velocityTrackerMotionEvent.offsetLocation(0, mNestedYOffset);
+
+        switch (actionMasked) {
+            case MotionEvent.ACTION_DOWN: {
+                if (getChildCount() == 0) {
+                    return false;
+                }
+
+                // If additional fingers touch the screen while a drag is in progress, this block
+                // of code will make sure the drag isn't interrupted.
+                if (mIsBeingDragged) {
+                    final ViewParent parent = getParent();
+                    if (parent != null) {
+                        parent.requestDisallowInterceptTouchEvent(true);
+                    }
+                }
+
+                /*
+                 * If being flinged and user touches, stop the fling. isFinished
+                 * will be false if being flinged.
+                 */
+                if (!mScroller.isFinished()) {
+                    abortAnimatedScroll();
+                }
+
+                initializeTouchDrag(
+                        (int) motionEvent.getY(),
+                        motionEvent.getPointerId(0)
+                );
+
+                break;
+            }
+
+            case MotionEvent.ACTION_MOVE: {
+                final int activePointerIndex = motionEvent.findPointerIndex(mActivePointerId);
+                if (activePointerIndex == -1) {
+                    Log.e(TAG, "Invalid pointerId=" + mActivePointerId + " in onTouchEvent");
+                    break;
+                }
+
+                final int y = (int) motionEvent.getY(activePointerIndex);
+                int deltaY = mLastMotionY - y;
+                deltaY -= releaseVerticalGlow(deltaY, motionEvent.getX(activePointerIndex));
+
+                // Changes to dragged state if delta is greater than the slop (and not in
+                // the dragged state).
+                if (!mIsBeingDragged && Math.abs(deltaY) > mTouchSlop) {
+                    final ViewParent parent = getParent();
+                    if (parent != null) {
+                        parent.requestDisallowInterceptTouchEvent(true);
+                    }
+                    mIsBeingDragged = true;
+                    if (deltaY > 0) {
+                        deltaY -= mTouchSlop;
+                    } else {
+                        deltaY += mTouchSlop;
+                    }
+                }
+
+                if (mIsBeingDragged) {
+                    final int x = (int) motionEvent.getX(activePointerIndex);
+                    int scrollOffset = scrollBy(deltaY, x, ViewCompat.TYPE_TOUCH, false);
+                    // Updates the global positions (used by later move events to properly scroll).
+                    mLastMotionY = y - scrollOffset;
+                    mNestedYOffset += scrollOffset;
+                }
+                break;
+            }
+
+            case MotionEvent.ACTION_UP: {
+                final VelocityTracker velocityTracker = mVelocityTracker;
+                velocityTracker.computeCurrentVelocity(1000, mMaximumVelocity);
+                int initialVelocity = (int) velocityTracker.getYVelocity(mActivePointerId);
+                if ((Math.abs(initialVelocity) >= mMinimumVelocity)) {
+                    if (!edgeEffectFling(initialVelocity)
+                            && !dispatchNestedPreFling(0, -initialVelocity)) {
+                        dispatchNestedFling(0, -initialVelocity, true);
+                        fling(-initialVelocity);
+                    }
+                } else if (mScroller.springBack(getScrollX(), getScrollY(), 0, 0, 0,
+                        getScrollRange())) {
+                    postInvalidateOnAnimation();
+                }
+                endTouchDrag();
+                break;
+            }
+
+            case MotionEvent.ACTION_CANCEL: {
+                if (mIsBeingDragged && getChildCount() > 0) {
+                    if (mScroller.springBack(getScrollX(), getScrollY(), 0, 0, 0,
+                            getScrollRange())) {
+                        postInvalidateOnAnimation();
+                    }
+                }
+                endTouchDrag();
+                break;
+            }
+
+            case MotionEvent.ACTION_POINTER_DOWN: {
+                final int index = motionEvent.getActionIndex();
+                mLastMotionY = (int) motionEvent.getY(index);
+                mActivePointerId = motionEvent.getPointerId(index);
+                break;
+            }
+
+            case MotionEvent.ACTION_POINTER_UP: {
+                onSecondaryPointerUp(motionEvent);
+                mLastMotionY =
+                        (int) motionEvent.getY(motionEvent.findPointerIndex(mActivePointerId));
+                break;
+            }
+        }
+
+        if (mVelocityTracker != null) {
+            mVelocityTracker.addMovement(velocityTrackerMotionEvent);
+        }
+        // Returns object back to be re-used by others.
+        velocityTrackerMotionEvent.recycle();
+
+        return true;
+    }
+
+    private void initializeTouchDrag(int lastMotionY, int activePointerId) {
+        mLastMotionY = lastMotionY;
+        mActivePointerId = activePointerId;
+        startNestedScroll(ViewCompat.SCROLL_AXIS_VERTICAL, ViewCompat.TYPE_TOUCH);
+    }
+
+    // Ends drag in a nested scroll.
+    private void endTouchDrag() {
+        mActivePointerId = INVALID_POINTER;
+        mIsBeingDragged = false;
+
+        recycleVelocityTracker();
+        stopNestedScroll(ViewCompat.TYPE_TOUCH);
+
+        mEdgeGlowTop.onRelease();
+        mEdgeGlowBottom.onRelease();
+    }
+
+    /*
+     * Handles scroll events for both touch and non-touch events (mouse scroll wheel,
+     * rotary button, keyboard, etc.).
+     *
+     * Note: This function returns the total scroll offset for this scroll event which is required
+     * for calculating the total scroll between multiple move events (touch). This returned value
+     * is NOT needed for non-touch events since a scroll is a one time event (vs. touch where a
+     * drag may be triggered multiple times with the movement of the finger).
+     */
+    // TODO: You should rename this to nestedScrollBy() so it is different from View.scrollBy
+    private int scrollBy(
+            int verticalScrollDistance,
+            int x,
+            int touchType,
+            boolean isSourceMouseOrKeyboard
+    ) {
+        int totalScrollOffset = 0;
+
+        /*
+         * Starts nested scrolling for non-touch events (mouse scroll wheel, rotary button, etc.).
+         * This is in contrast to a touch event which would trigger the start of nested scrolling
+         * with a touch down event outside of this method, since for a single gesture scrollBy()
+         * might be called several times for a move event for a single drag gesture.
+         */
+        if (touchType == ViewCompat.TYPE_NON_TOUCH) {
+            startNestedScroll(ViewCompat.SCROLL_AXIS_VERTICAL, touchType);
+        }
+
+        // Dispatches scrolling delta amount available to parent (to consume what it needs).
+        // Note: The amounts the parent consumes are saved in arrays named mScrollConsumed and
+        // mScrollConsumed to save space.
+        if (dispatchNestedPreScroll(
+                0,
+                verticalScrollDistance,
+                mScrollConsumed,
+                mScrollOffset,
+                touchType)
+        ) {
+            // Deducts the scroll amount (y) consumed by the parent (x in position 0,
+            // y in position 1). Nested scroll only works with Y position (so we don't use x).
+            verticalScrollDistance -= mScrollConsumed[1];
+            totalScrollOffset += mScrollOffset[1];
+        }
+
+        // Retrieves the scroll y position (top position of this view) and scroll Y range (how far
+        // the scroll can go).
+        final int initialScrollY = getScrollY();
+        final int scrollRangeY = getScrollRange();
+
+        // Overscroll is for adding animations at the top/bottom of a view when the user scrolls
+        // beyond the beginning/end of the view. Overscroll is not used with a mouse.
+        boolean canOverscroll = canOverScroll() && !isSourceMouseOrKeyboard;
+
+        // Scrolls content in the current View, but clamps it if it goes too far.
+        boolean hitScrollBarrier =
+                overScrollByCompat(
+                        0,
+                        verticalScrollDistance,
+                        0,
+                        initialScrollY,
+                        0,
+                        scrollRangeY,
+                        0,
+                        0,
+                        true
+                ) && !hasNestedScrollingParent(touchType);
+
+        // The position may have been adjusted in the previous call, so we must revise our values.
+        final int scrollYDelta = getScrollY() - initialScrollY;
+        final int unconsumedY = verticalScrollDistance - scrollYDelta;
+
+        // Reset the Y consumed scroll to zero
+        mScrollConsumed[1] = 0;
+
+        //  Dispatch the unconsumed delta Y to the children to consume.
+        dispatchNestedScroll(
+                0,
+                scrollYDelta,
+                0,
+                unconsumedY,
+                mScrollOffset,
+                touchType,
+                mScrollConsumed
+        );
+
+        totalScrollOffset += mScrollOffset[1];
+
+        // Handle overscroll of the children.
+        verticalScrollDistance -= mScrollConsumed[1];
+        int newScrollY = initialScrollY + verticalScrollDistance;
+
+        if (newScrollY < 0) {
+            if (canOverscroll) {
+                EdgeEffectCompat.onPullDistance(
+                        mEdgeGlowTop,
+                        (float) -verticalScrollDistance / getHeight(),
+                        (float) x / getWidth()
+                );
+
+                if (!mEdgeGlowBottom.isFinished()) {
+                    mEdgeGlowBottom.onRelease();
+                }
+            }
+
+        } else if (newScrollY > scrollRangeY) {
+            if (canOverscroll) {
+                EdgeEffectCompat.onPullDistance(
+                        mEdgeGlowBottom,
+                        (float) verticalScrollDistance / getHeight(),
+                        1.f - ((float) x / getWidth())
+                );
+
+                if (!mEdgeGlowTop.isFinished()) {
+                    mEdgeGlowTop.onRelease();
+                }
+            }
+        }
+
+        if (!mEdgeGlowTop.isFinished() || !mEdgeGlowBottom.isFinished()) {
+            postInvalidateOnAnimation();
+            hitScrollBarrier = false;
+        }
+
+        if (hitScrollBarrier && (touchType == ViewCompat.TYPE_TOUCH)) {
+            // Break our velocity if we hit a scroll barrier.
+            if (mVelocityTracker != null) {
+                mVelocityTracker.clear();
+            }
+        }
+
+        /*
+         * Ends nested scrolling for non-touch events (mouse scroll wheel, rotary button, etc.).
+         * As noted above, this is in contrast to a touch event.
+         */
+        if (touchType == ViewCompat.TYPE_NON_TOUCH) {
+            stopNestedScroll(touchType);
+
+            // Required for scrolling with Rotary Device stretch top/bottom to work properly
+            mEdgeGlowTop.onRelease();
+            mEdgeGlowBottom.onRelease();
+        }
+
+        return totalScrollOffset;
+    }
+
+    /**
+     * Returns true if edgeEffect should call onAbsorb() with veclocity or false if it should
+     * animate with a fling. It will animate with a fling if the velocity will remove the
+     * EdgeEffect through its normal operation.
+     *
+     * @param edgeEffect The EdgeEffect that might absorb the velocity.
+     * @param velocity The velocity of the fling motion
+     * @return true if the velocity should be absorbed or false if it should be flung.
+     */
+    private boolean shouldAbsorb(@NonNull EdgeEffect edgeEffect, int velocity) {
+        if (velocity > 0) {
+            return true;
+        }
+        float distance = EdgeEffectCompat.getDistance(edgeEffect) * getHeight();
+
+        // This is flinging without the spring, so let's see if it will fling past the overscroll
+        float flingDistance = getSplineFlingDistance(-velocity);
+
+        return flingDistance < distance;
+    }
+
+    /**
+     * If mTopGlow or mBottomGlow is currently active and the motion will remove some of the
+     * stretch, this will consume any of unconsumedY that the glow can. If the motion would
+     * increase the stretch, or the EdgeEffect isn't a stretch, then nothing will be consumed.
+     *
+     * @param unconsumedY The vertical delta that might be consumed by the vertical EdgeEffects
+     * @return The remaining unconsumed delta after the edge effects have consumed.
+     */
+    int consumeFlingInVerticalStretch(int unconsumedY) {
+        int height = getHeight();
+        if (unconsumedY > 0 && EdgeEffectCompat.getDistance(mEdgeGlowTop) != 0f) {
+            float deltaDistance = -unconsumedY * FLING_DESTRETCH_FACTOR / height;
+            int consumed = Math.round(-height / FLING_DESTRETCH_FACTOR
+                    * EdgeEffectCompat.onPullDistance(mEdgeGlowTop, deltaDistance, 0.5f));
+            if (consumed != unconsumedY) {
+                mEdgeGlowTop.finish();
+            }
+            return unconsumedY - consumed;
+        }
+        if (unconsumedY < 0 && EdgeEffectCompat.getDistance(mEdgeGlowBottom) != 0f) {
+            float deltaDistance = unconsumedY * FLING_DESTRETCH_FACTOR / height;
+            int consumed = Math.round(height / FLING_DESTRETCH_FACTOR
+                    * EdgeEffectCompat.onPullDistance(mEdgeGlowBottom, deltaDistance, 0.5f));
+            if (consumed != unconsumedY) {
+                mEdgeGlowBottom.finish();
+            }
+            return unconsumedY - consumed;
+        }
+        return unconsumedY;
+    }
+
+    /**
+     * Copied from OverScroller, this returns the distance that a fling with the given velocity
+     * will go.
+     * @param velocity The velocity of the fling
+     * @return The distance that will be traveled by a fling of the given velocity.
+     */
+    private float getSplineFlingDistance(int velocity) {
+        final double l =
+                Math.log(INFLEXION * Math.abs(velocity) / (SCROLL_FRICTION * mPhysicalCoeff));
+        final double decelMinusOne = DECELERATION_RATE - 1.0;
+        return (float) (SCROLL_FRICTION * mPhysicalCoeff
+                * Math.exp(DECELERATION_RATE / decelMinusOne * l));
+    }
+
+    private boolean edgeEffectFling(int velocityY) {
+        boolean consumed = true;
+        if (EdgeEffectCompat.getDistance(mEdgeGlowTop) != 0) {
+            if (shouldAbsorb(mEdgeGlowTop, velocityY)) {
+                mEdgeGlowTop.onAbsorb(velocityY);
+            } else {
+                fling(-velocityY);
+            }
+        } else if (EdgeEffectCompat.getDistance(mEdgeGlowBottom) != 0) {
+            if (shouldAbsorb(mEdgeGlowBottom, -velocityY)) {
+                mEdgeGlowBottom.onAbsorb(-velocityY);
+            } else {
+                fling(-velocityY);
+            }
+        } else {
+            consumed = false;
+        }
+        return consumed;
+    }
+
+    /**
+     * This stops any edge glow animation that is currently running by applying a
+     * 0 length pull at the displacement given by the provided MotionEvent. On pre-S devices,
+     * this method does nothing, allowing any animating edge effect to continue animating and
+     * returning <code>false</code> always.
+     *
+     * @param e The motion event to use to indicate the finger position for the displacement of
+     *          the current pull.
+     * @return <code>true</code> if any edge effect had an existing effect to be drawn ond the
+     * animation was stopped or <code>false</code> if no edge effect had a value to display.
+     */
+    private boolean stopGlowAnimations(MotionEvent e) {
+        boolean stopped = false;
+        if (EdgeEffectCompat.getDistance(mEdgeGlowTop) != 0) {
+            EdgeEffectCompat.onPullDistance(mEdgeGlowTop, 0, e.getX() / getWidth());
+            stopped = true;
+        }
+        if (EdgeEffectCompat.getDistance(mEdgeGlowBottom) != 0) {
+            EdgeEffectCompat.onPullDistance(mEdgeGlowBottom, 0, 1 - e.getX() / getWidth());
+            stopped = true;
+        }
+        return stopped;
+    }
+
+    private void onSecondaryPointerUp(MotionEvent ev) {
+        final int pointerIndex = ev.getActionIndex();
+        final int pointerId = ev.getPointerId(pointerIndex);
+        if (pointerId == mActivePointerId) {
+            // This was our active pointer going up. Choose a new
+            // active pointer and adjust accordingly.
+            // TODO: Make this decision more intelligent.
+            final int newPointerIndex = pointerIndex == 0 ? 1 : 0;
+            mLastMotionY = (int) ev.getY(newPointerIndex);
+            mActivePointerId = ev.getPointerId(newPointerIndex);
+            if (mVelocityTracker != null) {
+                mVelocityTracker.clear();
+            }
+        }
+    }
+
+    @Override
+    public boolean onGenericMotionEvent(@NonNull MotionEvent motionEvent) {
+        if (motionEvent.getAction() == MotionEvent.ACTION_SCROLL && !mIsBeingDragged) {
+            final float verticalScroll;
+            final int x;
+            final int flingAxis;
+
+            if (MotionEventCompat.isFromSource(motionEvent, InputDevice.SOURCE_CLASS_POINTER)) {
+                verticalScroll = motionEvent.getAxisValue(MotionEvent.AXIS_VSCROLL);
+                x = (int) motionEvent.getX();
+                flingAxis = MotionEvent.AXIS_VSCROLL;
+            } else if (
+                    MotionEventCompat.isFromSource(motionEvent, InputDevice.SOURCE_ROTARY_ENCODER)
+            ) {
+                verticalScroll = motionEvent.getAxisValue(MotionEvent.AXIS_SCROLL);
+                // Since a Wear rotary event doesn't have a true X and we want to support proper
+                // overscroll animations, we put the x at the center of the screen.
+                x = getWidth() / 2;
+                flingAxis = MotionEvent.AXIS_SCROLL;
+            } else {
+                verticalScroll = 0;
+                x = 0;
+                flingAxis = 0;
+            }
+
+            if (verticalScroll != 0) {
+                // Rotary and Mouse scrolls are inverted from a touch scroll.
+                final int invertedDelta = (int) (verticalScroll * getVerticalScrollFactorCompat());
+
+                final boolean isSourceMouse =
+                        MotionEventCompat.isFromSource(motionEvent, InputDevice.SOURCE_MOUSE);
+
+                scrollBy(-invertedDelta, x, ViewCompat.TYPE_NON_TOUCH, isSourceMouse);
+                if (flingAxis != 0) {
+                    mDifferentialMotionFlingController.onMotionEvent(motionEvent, flingAxis);
+                }
+
+                return true;
+            }
+        }
+        return false;
+    }
+
+    /**
+     * Returns true if the NestedScrollView supports over scroll.
+     */
+    private boolean canOverScroll() {
+        final int mode = getOverScrollMode();
+        return mode == OVER_SCROLL_ALWAYS
+                || (mode == OVER_SCROLL_IF_CONTENT_SCROLLS && getScrollRange() > 0);
+    }
+
+    @VisibleForTesting
+    float getVerticalScrollFactorCompat() {
+        if (mVerticalScrollFactor == 0) {
+            TypedValue outValue = new TypedValue();
+            final Context context = getContext();
+            if (!context.getTheme().resolveAttribute(
+                    android.R.attr.listPreferredItemHeight, outValue, true)) {
+                throw new IllegalStateException(
+                        "Expected theme to define listPreferredItemHeight.");
+            }
+            mVerticalScrollFactor = outValue.getDimension(
+                    context.getResources().getDisplayMetrics());
+        }
+        return mVerticalScrollFactor;
+    }
+
+    @Override
+    protected void onOverScrolled(int scrollX, int scrollY,
+            boolean clampedX, boolean clampedY) {
+        super.scrollTo(scrollX, scrollY);
+    }
+
+    @SuppressWarnings({"SameParameterValue", "unused"})
+    boolean overScrollByCompat(int deltaX, int deltaY,
+            int scrollX, int scrollY,
+            int scrollRangeX, int scrollRangeY,
+            int maxOverScrollX, int maxOverScrollY,
+            boolean isTouchEvent) {
+
+        final int overScrollMode = getOverScrollMode();
+        final boolean canScrollHorizontal =
+                computeHorizontalScrollRange() > computeHorizontalScrollExtent();
+        final boolean canScrollVertical =
+                computeVerticalScrollRange() > computeVerticalScrollExtent();
+
+        final boolean overScrollHorizontal = overScrollMode == View.OVER_SCROLL_ALWAYS
+                || (overScrollMode == View.OVER_SCROLL_IF_CONTENT_SCROLLS && canScrollHorizontal);
+        final boolean overScrollVertical = overScrollMode == View.OVER_SCROLL_ALWAYS
+                || (overScrollMode == View.OVER_SCROLL_IF_CONTENT_SCROLLS && canScrollVertical);
+
+        int newScrollX = scrollX + deltaX;
+        if (!overScrollHorizontal) {
+            maxOverScrollX = 0;
+        }
+
+        int newScrollY = scrollY + deltaY;
+        if (!overScrollVertical) {
+            maxOverScrollY = 0;
+        }
+
+        // Clamp values if at the limits and record
+        final int left = -maxOverScrollX;
+        final int right = maxOverScrollX + scrollRangeX;
+        final int top = -maxOverScrollY;
+        final int bottom = maxOverScrollY + scrollRangeY;
+
+        boolean clampedX = false;
+        if (newScrollX > right) {
+            newScrollX = right;
+            clampedX = true;
+        } else if (newScrollX < left) {
+            newScrollX = left;
+            clampedX = true;
+        }
+
+        boolean clampedY = false;
+        if (newScrollY > bottom) {
+            newScrollY = bottom;
+            clampedY = true;
+        } else if (newScrollY < top) {
+            newScrollY = top;
+            clampedY = true;
+        }
+
+        if (clampedY && !hasNestedScrollingParent(ViewCompat.TYPE_NON_TOUCH)) {
+            mScroller.springBack(newScrollX, newScrollY, 0, 0, 0, getScrollRange());
+        }
+
+        onOverScrolled(newScrollX, newScrollY, clampedX, clampedY);
+
+        return clampedX || clampedY;
+    }
+
+    int getScrollRange() {
+        int scrollRange = 0;
+        if (getChildCount() > 0) {
+            View child = getChildAt(0);
+            LayoutParams lp = (LayoutParams) child.getLayoutParams();
+            int childSize = child.getHeight() + lp.topMargin + lp.bottomMargin;
+            int parentSpace = getHeight() - getPaddingTop() - getPaddingBottom();
+            scrollRange = Math.max(0, childSize - parentSpace);
+        }
+        return scrollRange;
+    }
+
+    /**
+     * <p>
+     * Finds the next focusable component that fits in the specified bounds.
+     * </p>
+     *
+     * @param topFocus look for a candidate is the one at the top of the bounds
+     *                 if topFocus is true, or at the bottom of the bounds if topFocus is
+     *                 false
+     * @param top      the top offset of the bounds in which a focusable must be
+     *                 found
+     * @param bottom   the bottom offset of the bounds in which a focusable must
+     *                 be found
+     * @return the next focusable component in the bounds or null if none can
+     *         be found
+     */
+    private View findFocusableViewInBounds(boolean topFocus, int top, int bottom) {
+
+        List<View> focusables = getFocusables(View.FOCUS_FORWARD);
+        View focusCandidate = null;
+
+        /*
+         * A fully contained focusable is one where its top is below the bound's
+         * top, and its bottom is above the bound's bottom. A partially
+         * contained focusable is one where some part of it is within the
+         * bounds, but it also has some part that is not within bounds.  A fully contained
+         * focusable is preferred to a partially contained focusable.
+         */
+        boolean foundFullyContainedFocusable = false;
+
+        int count = focusables.size();
+        for (int i = 0; i < count; i++) {
+            View view = focusables.get(i);
+            int viewTop = view.getTop();
+            int viewBottom = view.getBottom();
+
+            if (top < viewBottom && viewTop < bottom) {
+                /*
+                 * the focusable is in the target area, it is a candidate for
+                 * focusing
+                 */
+
+                final boolean viewIsFullyContained = (top < viewTop) && (viewBottom < bottom);
+
+                if (focusCandidate == null) {
+                    /* No candidate, take this one */
+                    focusCandidate = view;
+                    foundFullyContainedFocusable = viewIsFullyContained;
+                } else {
+                    final boolean viewIsCloserToBoundary =
+                            (topFocus && viewTop < focusCandidate.getTop())
+                                    || (!topFocus && viewBottom > focusCandidate.getBottom());
+
+                    if (foundFullyContainedFocusable) {
+                        if (viewIsFullyContained && viewIsCloserToBoundary) {
+                            /*
+                             * We're dealing with only fully contained views, so
+                             * it has to be closer to the boundary to beat our
+                             * candidate
+                             */
+                            focusCandidate = view;
+                        }
+                    } else {
+                        if (viewIsFullyContained) {
+                            /* Any fully contained view beats a partially contained view */
+                            focusCandidate = view;
+                            foundFullyContainedFocusable = true;
+                        } else if (viewIsCloserToBoundary) {
+                            /*
+                             * Partially contained view beats another partially
+                             * contained view if it's closer
+                             */
+                            focusCandidate = view;
+                        }
+                    }
+                }
+            }
+        }
+
+        return focusCandidate;
+    }
+
+    /**
+     * <p>Handles scrolling in response to a "page up/down" shortcut press. This
+     * method will scroll the view by one page up or down and give the focus
+     * to the topmost/bottommost component in the new visible area. If no
+     * component is a good candidate for focus, this scrollview reclaims the
+     * focus.</p>
+     *
+     * @param direction the scroll direction: {@link View#FOCUS_UP}
+     *                  to go one page up or
+     *                  {@link View#FOCUS_DOWN} to go one page down
+     * @return true if the key event is consumed by this method, false otherwise
+     */
+    public boolean pageScroll(int direction) {
+        boolean down = direction == View.FOCUS_DOWN;
+        int height = getHeight();
+
+        if (down) {
+            mTempRect.top = getScrollY() + height;
+            int count = getChildCount();
+            if (count > 0) {
+                View view = getChildAt(count - 1);
+                LayoutParams lp = (LayoutParams) view.getLayoutParams();
+                int bottom = view.getBottom() + lp.bottomMargin + getPaddingBottom();
+                if (mTempRect.top + height > bottom) {
+                    mTempRect.top = bottom - height;
+                }
+            }
+        } else {
+            mTempRect.top = getScrollY() - height;
+            if (mTempRect.top < 0) {
+                mTempRect.top = 0;
+            }
+        }
+        mTempRect.bottom = mTempRect.top + height;
+
+        return scrollAndFocus(direction, mTempRect.top, mTempRect.bottom);
+    }
+
+    /**
+     * <p>Handles scrolling in response to a "home/end" shortcut press. This
+     * method will scroll the view to the top or bottom and give the focus
+     * to the topmost/bottommost component in the new visible area. If no
+     * component is a good candidate for focus, this scrollview reclaims the
+     * focus.</p>
+     *
+     * @param direction the scroll direction: {@link View#FOCUS_UP}
+     *                  to go the top of the view or
+     *                  {@link View#FOCUS_DOWN} to go the bottom
+     * @return true if the key event is consumed by this method, false otherwise
+     */
+    public boolean fullScroll(int direction) {
+        boolean down = direction == View.FOCUS_DOWN;
+        int height = getHeight();
+
+        mTempRect.top = 0;
+        mTempRect.bottom = height;
+
+        if (down) {
+            int count = getChildCount();
+            if (count > 0) {
+                View view = getChildAt(count - 1);
+                LayoutParams lp = (LayoutParams) view.getLayoutParams();
+                mTempRect.bottom = view.getBottom() + lp.bottomMargin + getPaddingBottom();
+                mTempRect.top = mTempRect.bottom - height;
+            }
+        }
+        return scrollAndFocus(direction, mTempRect.top, mTempRect.bottom);
+    }
+
+    /**
+     * <p>Scrolls the view to make the area defined by <code>top</code> and
+     * <code>bottom</code> visible. This method attempts to give the focus
+     * to a component visible in this area. If no component can be focused in
+     * the new visible area, the focus is reclaimed by this ScrollView.</p>
+     *
+     * @param direction the scroll direction: {@link View#FOCUS_UP}
+     *                  to go upward, {@link View#FOCUS_DOWN} to downward
+     * @param top       the top offset of the new area to be made visible
+     * @param bottom    the bottom offset of the new area to be made visible
+     * @return true if the key event is consumed by this method, false otherwise
+     */
+    private boolean scrollAndFocus(int direction, int top, int bottom) {
+        boolean handled = true;
+
+        int height = getHeight();
+        int containerTop = getScrollY();
+        int containerBottom = containerTop + height;
+        boolean up = direction == View.FOCUS_UP;
+
+        View newFocused = findFocusableViewInBounds(up, top, bottom);
+        if (newFocused == null) {
+            newFocused = this;
+        }
+
+        if (top >= containerTop && bottom <= containerBottom) {
+            handled = false;
+        } else {
+            int delta = up ? (top - containerTop) : (bottom - containerBottom);
+            scrollBy(delta, 0, ViewCompat.TYPE_NON_TOUCH, true);
+        }
+
+        if (newFocused != findFocus()) newFocused.requestFocus(direction);
+
+        return handled;
+    }
+
+    /**
+     * Handle scrolling in response to an up or down arrow click.
+     *
+     * @param direction The direction corresponding to the arrow key that was
+     *                  pressed
+     * @return True if we consumed the event, false otherwise
+     */
+    public boolean arrowScroll(int direction) {
+        View currentFocused = findFocus();
+        if (currentFocused == this) currentFocused = null;
+
+        View nextFocused = FocusFinder.getInstance().findNextFocus(this, currentFocused, direction);
+
+        final int maxJump = getMaxScrollAmount();
+
+        if (nextFocused != null && isWithinDeltaOfScreen(nextFocused, maxJump, getHeight())) {
+            nextFocused.getDrawingRect(mTempRect);
+            offsetDescendantRectToMyCoords(nextFocused, mTempRect);
+            int scrollDelta = computeScrollDeltaToGetChildRectOnScreen(mTempRect);
+
+            scrollBy(scrollDelta, 0, ViewCompat.TYPE_NON_TOUCH, true);
+            nextFocused.requestFocus(direction);
+
+        } else {
+            // no new focus
+            int scrollDelta = maxJump;
+
+            if (direction == View.FOCUS_UP && getScrollY() < scrollDelta) {
+                scrollDelta = getScrollY();
+            } else if (direction == View.FOCUS_DOWN) {
+                if (getChildCount() > 0) {
+                    View child = getChildAt(0);
+                    LayoutParams lp = (LayoutParams) child.getLayoutParams();
+                    int daBottom = child.getBottom() + lp.bottomMargin;
+                    int screenBottom = getScrollY() + getHeight() - getPaddingBottom();
+                    scrollDelta = Math.min(daBottom - screenBottom, maxJump);
+                }
+            }
+            if (scrollDelta == 0) {
+                return false;
+            }
+
+            int finalScrollDelta = direction == View.FOCUS_DOWN ? scrollDelta : -scrollDelta;
+            scrollBy(finalScrollDelta, 0, ViewCompat.TYPE_NON_TOUCH, true);
+        }
+
+        if (currentFocused != null && currentFocused.isFocused()
+                && isOffScreen(currentFocused)) {
+            // previously focused item still has focus and is off screen, give
+            // it up (take it back to ourselves)
+            // (also, need to temporarily force FOCUS_BEFORE_DESCENDANTS so we are
+            // sure to
+            // get it)
+            final int descendantFocusability = getDescendantFocusability();  // save
+            setDescendantFocusability(ViewGroup.FOCUS_BEFORE_DESCENDANTS);
+            requestFocus();
+            setDescendantFocusability(descendantFocusability);  // restore
+        }
+        return true;
+    }
+
+    /**
+     * @return whether the descendant of this scroll view is scrolled off
+     *  screen.
+     */
+    private boolean isOffScreen(View descendant) {
+        return !isWithinDeltaOfScreen(descendant, 0, getHeight());
+    }
+
+    /**
+     * @return whether the descendant of this scroll view is within delta
+     *  pixels of being on the screen.
+     */
+    private boolean isWithinDeltaOfScreen(View descendant, int delta, int height) {
+        descendant.getDrawingRect(mTempRect);
+        offsetDescendantRectToMyCoords(descendant, mTempRect);
+
+        return (mTempRect.bottom + delta) >= getScrollY()
+                && (mTempRect.top - delta) <= (getScrollY() + height);
+    }
+
+    /**
+     * Smooth scroll by a Y delta
+     *
+     * @param delta the number of pixels to scroll by on the Y axis
+     */
+    private void doScrollY(int delta) {
+        if (delta != 0) {
+            if (mSmoothScrollingEnabled) {
+                smoothScrollBy(0, delta);
+            } else {
+                scrollBy(0, delta);
+            }
+        }
+    }
+
+    /**
+     * Like {@link View#scrollBy}, but scroll smoothly instead of immediately.
+     *
+     * @param dx the number of pixels to scroll by on the X axis
+     * @param dy the number of pixels to scroll by on the Y axis
+     */
+    public final void smoothScrollBy(int dx, int dy) {
+        smoothScrollBy(dx, dy, DEFAULT_SMOOTH_SCROLL_DURATION, false);
+    }
+
+   /**
+     * Like {@link View#scrollBy}, but scroll smoothly instead of immediately.
+     *
+     * @param dx the number of pixels to scroll by on the X axis
+     * @param dy the number of pixels to scroll by on the Y axis
+     * @param scrollDurationMs the duration of the smooth scroll operation in milliseconds
+     */
+    public final void smoothScrollBy(int dx, int dy, int scrollDurationMs) {
+        smoothScrollBy(dx, dy, scrollDurationMs, false);
+    }
+
+    /**
+     * Like {@link View#scrollBy}, but scroll smoothly instead of immediately.
+     *
+     * @param dx the number of pixels to scroll by on the X axis
+     * @param dy the number of pixels to scroll by on the Y axis
+     * @param scrollDurationMs the duration of the smooth scroll operation in milliseconds
+     * @param withNestedScrolling whether to include nested scrolling operations.
+     */
+    private void smoothScrollBy(int dx, int dy, int scrollDurationMs, boolean withNestedScrolling) {
+        if (getChildCount() == 0) {
+            // Nothing to do.
+            return;
+        }
+        long duration = AnimationUtils.currentAnimationTimeMillis() - mLastScroll;
+        if (duration > ANIMATED_SCROLL_GAP) {
+            View child = getChildAt(0);
+            LayoutParams lp = (LayoutParams) child.getLayoutParams();
+            int childSize = child.getHeight() + lp.topMargin + lp.bottomMargin;
+            int parentSpace = getHeight() - getPaddingTop() - getPaddingBottom();
+            final int scrollY = getScrollY();
+            final int maxY = Math.max(0, childSize - parentSpace);
+            dy = Math.max(0, Math.min(scrollY + dy, maxY)) - scrollY;
+            mScroller.startScroll(getScrollX(), scrollY, 0, dy, scrollDurationMs);
+            runAnimatedScroll(withNestedScrolling);
+        } else {
+            if (!mScroller.isFinished()) {
+                abortAnimatedScroll();
+            }
+            scrollBy(dx, dy);
+        }
+        mLastScroll = AnimationUtils.currentAnimationTimeMillis();
+    }
+
+    /**
+     * Like {@link #scrollTo}, but scroll smoothly instead of immediately.
+     *
+     * @param x the position where to scroll on the X axis
+     * @param y the position where to scroll on the Y axis
+     */
+    public final void smoothScrollTo(int x, int y) {
+        smoothScrollTo(x, y, DEFAULT_SMOOTH_SCROLL_DURATION, false);
+    }
+
+    /**
+     * Like {@link #scrollTo}, but scroll smoothly instead of immediately.
+     *
+     * @param x the position where to scroll on the X axis
+     * @param y the position where to scroll on the Y axis
+     * @param scrollDurationMs the duration of the smooth scroll operation in milliseconds
+     */
+    public final void smoothScrollTo(int x, int y, int scrollDurationMs) {
+        smoothScrollTo(x, y, scrollDurationMs, false);
+    }
+
+    /**
+     * Like {@link #scrollTo}, but scroll smoothly instead of immediately.
+     *
+     * @param x the position where to scroll on the X axis
+     * @param y the position where to scroll on the Y axis
+     * @param withNestedScrolling whether to include nested scrolling operations.
+     */
+    // This should be considered private, it is package private to avoid a synthetic ancestor.
+    @SuppressWarnings("SameParameterValue")
+    void smoothScrollTo(int x, int y, boolean withNestedScrolling) {
+        smoothScrollTo(x, y, DEFAULT_SMOOTH_SCROLL_DURATION, withNestedScrolling);
+    }
+
+    /**
+     * Like {@link #scrollTo}, but scroll smoothly instead of immediately.
+     *
+     * @param x the position where to scroll on the X axis
+     * @param y the position where to scroll on the Y axis
+     * @param scrollDurationMs the duration of the smooth scroll operation in milliseconds
+     * @param withNestedScrolling whether to include nested scrolling operations.
+     */
+    // This should be considered private, it is package private to avoid a synthetic ancestor.
+    void smoothScrollTo(int x, int y, int scrollDurationMs, boolean withNestedScrolling) {
+        smoothScrollBy(x - getScrollX(), y - getScrollY(), scrollDurationMs, withNestedScrolling);
+    }
+
+    /**
+     * <p>The scroll range of a scroll view is the overall height of all of its
+     * children.</p>
+     */
+    @Override
+    public int computeVerticalScrollRange() {
+        final int count = getChildCount();
+        final int parentSpace = getHeight() - getPaddingBottom() - getPaddingTop();
+        if (count == 0) {
+            return parentSpace;
+        }
+
+        View child = getChildAt(0);
+        LayoutParams lp = (LayoutParams) child.getLayoutParams();
+        int scrollRange = child.getBottom() + lp.bottomMargin;
+        final int scrollY = getScrollY();
+        final int overscrollBottom = Math.max(0, scrollRange - parentSpace);
+        if (scrollY < 0) {
+            scrollRange -= scrollY;
+        } else if (scrollY > overscrollBottom) {
+            scrollRange += scrollY - overscrollBottom;
+        }
+
+        return scrollRange;
+    }
+
+    @Override
+    public int computeVerticalScrollOffset() {
+        return Math.max(0, super.computeVerticalScrollOffset());
+    }
+
+    @Override
+    public int computeVerticalScrollExtent() {
+        return super.computeVerticalScrollExtent();
+    }
+
+    @Override
+    public int computeHorizontalScrollRange() {
+        return super.computeHorizontalScrollRange();
+    }
+
+    @Override
+    public int computeHorizontalScrollOffset() {
+        return super.computeHorizontalScrollOffset();
+    }
+
+    @Override
+    public int computeHorizontalScrollExtent() {
+        return super.computeHorizontalScrollExtent();
+    }
+
+    @Override
+    protected void measureChild(@NonNull View child, int parentWidthMeasureSpec,
+            int parentHeightMeasureSpec) {
+        ViewGroup.LayoutParams lp = child.getLayoutParams();
+
+        int childWidthMeasureSpec;
+        int childHeightMeasureSpec;
+
+        childWidthMeasureSpec = getChildMeasureSpec(parentWidthMeasureSpec, getPaddingLeft()
+                + getPaddingRight(), lp.width);
+
+        childHeightMeasureSpec = MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED);
+
+        child.measure(childWidthMeasureSpec, childHeightMeasureSpec);
+    }
+
+    @Override
+    protected void measureChildWithMargins(View child, int parentWidthMeasureSpec, int widthUsed,
+            int parentHeightMeasureSpec, int heightUsed) {
+        final MarginLayoutParams lp = (MarginLayoutParams) child.getLayoutParams();
+
+        final int childWidthMeasureSpec = getChildMeasureSpec(parentWidthMeasureSpec,
+                getPaddingLeft() + getPaddingRight() + lp.leftMargin + lp.rightMargin
+                        + widthUsed, lp.width);
+        final int childHeightMeasureSpec = MeasureSpec.makeMeasureSpec(
+                lp.topMargin + lp.bottomMargin, MeasureSpec.UNSPECIFIED);
+
+        child.measure(childWidthMeasureSpec, childHeightMeasureSpec);
+    }
+
+    @Override
+    public void computeScroll() {
+
+        if (mScroller.isFinished()) {
+            return;
+        }
+
+        mScroller.computeScrollOffset();
+        final int y = mScroller.getCurrY();
+        int unconsumed = consumeFlingInVerticalStretch(y - mLastScrollerY);
+        mLastScrollerY = y;
+
+        // Nested Scrolling Pre Pass
+        mScrollConsumed[1] = 0;
+        dispatchNestedPreScroll(0, unconsumed, mScrollConsumed, null,
+                ViewCompat.TYPE_NON_TOUCH);
+        unconsumed -= mScrollConsumed[1];
+
+        final int range = getScrollRange();
+
+        if (unconsumed != 0) {
+            // Internal Scroll
+            final int oldScrollY = getScrollY();
+            overScrollByCompat(0, unconsumed, getScrollX(), oldScrollY, 0, range, 0, 0, false);
+            final int scrolledByMe = getScrollY() - oldScrollY;
+            unconsumed -= scrolledByMe;
+
+            // Nested Scrolling Post Pass
+            mScrollConsumed[1] = 0;
+            dispatchNestedScroll(0, scrolledByMe, 0, unconsumed, mScrollOffset,
+                    ViewCompat.TYPE_NON_TOUCH, mScrollConsumed);
+            unconsumed -= mScrollConsumed[1];
+        }
+
+        if (unconsumed != 0) {
+            final int mode = getOverScrollMode();
+            final boolean canOverscroll = mode == OVER_SCROLL_ALWAYS
+                    || (mode == OVER_SCROLL_IF_CONTENT_SCROLLS && range > 0);
+            if (canOverscroll) {
+                if (unconsumed < 0) {
+                    if (mEdgeGlowTop.isFinished()) {
+                        mEdgeGlowTop.onAbsorb((int) mScroller.getCurrVelocity());
+                    }
+                } else {
+                    if (mEdgeGlowBottom.isFinished()) {
+                        mEdgeGlowBottom.onAbsorb((int) mScroller.getCurrVelocity());
+                    }
+                }
+            }
+            abortAnimatedScroll();
+        }
+
+        if (!mScroller.isFinished()) {
+            postInvalidateOnAnimation();
+        } else {
+            stopNestedScroll(ViewCompat.TYPE_NON_TOUCH);
+        }
+    }
+
+    /**
+     * If either of the vertical edge glows are currently active, this consumes part or all of
+     * deltaY on the edge glow.
+     *
+     * @param deltaY The pointer motion, in pixels, in the vertical direction, positive
+     *                         for moving down and negative for moving up.
+     * @param x The vertical position of the pointer.
+     * @return The amount of <code>deltaY</code> that has been consumed by the
+     * edge glow.
+     */
+    private int releaseVerticalGlow(int deltaY, float x) {
+        // First allow releasing existing overscroll effect:
+        float consumed = 0;
+        float displacement = x / getWidth();
+        float pullDistance = (float) deltaY / getHeight();
+        if (EdgeEffectCompat.getDistance(mEdgeGlowTop) != 0) {
+            consumed = -EdgeEffectCompat.onPullDistance(mEdgeGlowTop, -pullDistance, displacement);
+            if (EdgeEffectCompat.getDistance(mEdgeGlowTop) == 0) {
+                mEdgeGlowTop.onRelease();
+            }
+        } else if (EdgeEffectCompat.getDistance(mEdgeGlowBottom) != 0) {
+            consumed = EdgeEffectCompat.onPullDistance(mEdgeGlowBottom, pullDistance,
+                    1 - displacement);
+            if (EdgeEffectCompat.getDistance(mEdgeGlowBottom) == 0) {
+                mEdgeGlowBottom.onRelease();
+            }
+        }
+        int pixelsConsumed = Math.round(consumed * getHeight());
+        if (pixelsConsumed != 0) {
+            invalidate();
+        }
+        return pixelsConsumed;
+    }
+
+    private void runAnimatedScroll(boolean participateInNestedScrolling) {
+        if (participateInNestedScrolling) {
+            startNestedScroll(ViewCompat.SCROLL_AXIS_VERTICAL, ViewCompat.TYPE_NON_TOUCH);
+        } else {
+            stopNestedScroll(ViewCompat.TYPE_NON_TOUCH);
+        }
+        mLastScrollerY = getScrollY();
+        postInvalidateOnAnimation();
+    }
+
+    private void abortAnimatedScroll() {
+        mScroller.abortAnimation();
+        stopNestedScroll(ViewCompat.TYPE_NON_TOUCH);
+    }
+
+    /**
+     * Scrolls the view to the given child.
+     *
+     * @param child the View to scroll to
+     */
+    private void scrollToChild(View child) {
+        child.getDrawingRect(mTempRect);
+
+        /* Offset from child's local coordinates to ScrollView coordinates */
+        offsetDescendantRectToMyCoords(child, mTempRect);
+
+        int scrollDelta = computeScrollDeltaToGetChildRectOnScreen(mTempRect);
+
+        if (scrollDelta != 0) {
+            scrollBy(0, scrollDelta);
+        }
+    }
+
+    /**
+     * If rect is off screen, scroll just enough to get it (or at least the
+     * first screen size chunk of it) on screen.
+     *
+     * @param rect      The rectangle.
+     * @param immediate True to scroll immediately without animation
+     * @return true if scrolling was performed
+     */
+    private boolean scrollToChildRect(Rect rect, boolean immediate) {
+        final int delta = computeScrollDeltaToGetChildRectOnScreen(rect);
+        final boolean scroll = delta != 0;
+        if (scroll) {
+            if (immediate) {
+                scrollBy(0, delta);
+            } else {
+                smoothScrollBy(0, delta);
+            }
+        }
+        return scroll;
+    }
+
+    /**
+     * Compute the amount to scroll in the Y direction in order to get
+     * a rectangle completely on the screen (or, if taller than the screen,
+     * at least the first screen size chunk of it).
+     *
+     * @param rect The rect.
+     * @return The scroll delta.
+     */
+    protected int computeScrollDeltaToGetChildRectOnScreen(Rect rect) {
+        if (getChildCount() == 0) return 0;
+
+        int height = getHeight();
+        int screenTop = getScrollY();
+        int screenBottom = screenTop + height;
+        int actualScreenBottom = screenBottom;
+
+        int fadingEdge = getVerticalFadingEdgeLength();
+
+        // TODO: screenTop should be incremented by fadingEdge * getTopFadingEdgeStrength (but for
+        // the target scroll distance).
+        // leave room for top fading edge as long as rect isn't at very top
+        if (rect.top > 0) {
+            screenTop += fadingEdge;
+        }
+
+        // TODO: screenBottom should be decremented by fadingEdge * getBottomFadingEdgeStrength (but
+        // for the target scroll distance).
+        // leave room for bottom fading edge as long as rect isn't at very bottom
+        View child = getChildAt(0);
+        final LayoutParams lp = (LayoutParams) child.getLayoutParams();
+        if (rect.bottom < child.getHeight() + lp.topMargin + lp.bottomMargin) {
+            screenBottom -= fadingEdge;
+        }
+
+        int scrollYDelta = 0;
+
+        if (rect.bottom > screenBottom && rect.top > screenTop) {
+            // need to move down to get it in view: move down just enough so
+            // that the entire rectangle is in view (or at least the first
+            // screen size chunk).
+
+            if (rect.height() > height) {
+                // just enough to get screen size chunk on
+                scrollYDelta += (rect.top - screenTop);
+            } else {
+                // get entire rect at bottom of screen
+                scrollYDelta += (rect.bottom - screenBottom);
+            }
+
+            // make sure we aren't scrolling beyond the end of our content
+            int bottom = child.getBottom() + lp.bottomMargin;
+            int distanceToBottom = bottom - actualScreenBottom;
+            scrollYDelta = Math.min(scrollYDelta, distanceToBottom);
+
+        } else if (rect.top < screenTop && rect.bottom < screenBottom) {
+            // need to move up to get it in view: move up just enough so that
+            // entire rectangle is in view (or at least the first screen
+            // size chunk of it).
+
+            if (rect.height() > height) {
+                // screen size chunk
+                scrollYDelta -= (screenBottom - rect.bottom);
+            } else {
+                // entire rect at top
+                scrollYDelta -= (screenTop - rect.top);
+            }
+
+            // make sure we aren't scrolling any further than the top our content
+            scrollYDelta = Math.max(scrollYDelta, -getScrollY());
+        }
+        return scrollYDelta;
+    }
+
+    @Override
+    public void requestChildFocus(View child, View focused) {
+        onRequestChildFocus(child, focused);
+        super.requestChildFocus(child, focused);
+    }
+
+    protected void onRequestChildFocus(View child, View focused) {
+        if (!mIsLayoutDirty) {
+            scrollToChild(focused);
+        } else {
+            // The child may not be laid out yet, we can't compute the scroll yet
+            mChildToScrollTo = focused;
+        }
+    }
+
+
+    /**
+     * When looking for focus in children of a scroll view, need to be a little
+     * more careful not to give focus to something that is scrolled off screen.
+     *
+     * This is more expensive than the default {@link ViewGroup}
+     * implementation, otherwise this behavior might have been made the default.
+     */
+    @Override
+    protected boolean onRequestFocusInDescendants(int direction,
+            Rect previouslyFocusedRect) {
+
+        // convert from forward / backward notation to up / down / left / right
+        // (ugh).
+        if (direction == View.FOCUS_FORWARD) {
+            direction = View.FOCUS_DOWN;
+        } else if (direction == View.FOCUS_BACKWARD) {
+            direction = View.FOCUS_UP;
+        }
+
+        final View nextFocus = previouslyFocusedRect == null
+                ? FocusFinder.getInstance().findNextFocus(this, null, direction)
+                : FocusFinder.getInstance().findNextFocusFromRect(
+                        this, previouslyFocusedRect, direction);
+
+        if (nextFocus == null) {
+            return false;
+        }
+
+        if (isOffScreen(nextFocus)) {
+            return false;
+        }
+
+        return nextFocus.requestFocus(direction, previouslyFocusedRect);
+    }
+
+    @Override
+    public boolean requestChildRectangleOnScreen(@NonNull View child, Rect rectangle,
+            boolean immediate) {
+        // offset into coordinate space of this scroll view
+        rectangle.offset(child.getLeft() - child.getScrollX(),
+                child.getTop() - child.getScrollY());
+
+        return scrollToChildRect(rectangle, immediate);
+    }
+
+    @Override
+    public void requestLayout() {
+        mIsLayoutDirty = true;
+        super.requestLayout();
+    }
+
+    @Override
+    protected void onLayout(boolean changed, int l, int t, int r, int b) {
+        super.onLayout(changed, l, t, r, b);
+        mIsLayoutDirty = false;
+        // Give a child focus if it needs it
+        if (mChildToScrollTo != null && isViewDescendantOf(mChildToScrollTo, this)) {
+            scrollToChild(mChildToScrollTo);
+        }
+        mChildToScrollTo = null;
+
+        if (!mIsLaidOut) {
+            // If there is a saved state, scroll to the position saved in that state.
+            if (mSavedState != null) {
+                scrollTo(getScrollX(), mSavedState.scrollPosition);
+                mSavedState = null;
+            } // mScrollY default value is "0"
+
+            // Make sure current scrollY position falls into the scroll range.  If it doesn't,
+            // scroll such that it does.
+            int childSize = 0;
+            if (getChildCount() > 0) {
+                View child = getChildAt(0);
+                LayoutParams lp = (LayoutParams) child.getLayoutParams();
+                childSize = child.getMeasuredHeight() + lp.topMargin + lp.bottomMargin;
+            }
+            int parentSpace = b - t - getPaddingTop() - getPaddingBottom();
+            int currentScrollY = getScrollY();
+            int newScrollY = clamp(currentScrollY, parentSpace, childSize);
+            if (newScrollY != currentScrollY) {
+                scrollTo(getScrollX(), newScrollY);
+            }
+        }
+
+        // Calling this with the present values causes it to re-claim them
+        scrollTo(getScrollX(), getScrollY());
+        mIsLaidOut = true;
+    }
+
+    @Override
+    public void onAttachedToWindow() {
+        super.onAttachedToWindow();
+
+        mIsLaidOut = false;
+    }
+
+    @Override
+    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
+        super.onSizeChanged(w, h, oldw, oldh);
+
+        View currentFocused = findFocus();
+        if (null == currentFocused || this == currentFocused) {
+            return;
+        }
+
+        // If the currently-focused view was visible on the screen when the
+        // screen was at the old height, then scroll the screen to make that
+        // view visible with the new screen height.
+        if (isWithinDeltaOfScreen(currentFocused, 0, oldh)) {
+            currentFocused.getDrawingRect(mTempRect);
+            offsetDescendantRectToMyCoords(currentFocused, mTempRect);
+            int scrollDelta = computeScrollDeltaToGetChildRectOnScreen(mTempRect);
+            doScrollY(scrollDelta);
+        }
+    }
+
+    /**
+     * Return true if child is a descendant of parent, (or equal to the parent).
+     */
+    private static boolean isViewDescendantOf(View child, View parent) {
+        if (child == parent) {
+            return true;
+        }
+
+        final ViewParent theParent = child.getParent();
+        return (theParent instanceof ViewGroup) && isViewDescendantOf((View) theParent, parent);
+    }
+
+    /**
+     * Fling the scroll view
+     *
+     * @param velocityY The initial velocity in the Y direction. Positive
+     *                  numbers mean that the finger/cursor is moving down the screen,
+     *                  which means we want to scroll towards the top.
+     */
+    public void fling(int velocityY) {
+        if (getChildCount() > 0) {
+
+            mScroller.fling(getScrollX(), getScrollY(), // start
+                    0, velocityY, // velocities
+                    0, 0, // x
+                    Integer.MIN_VALUE, Integer.MAX_VALUE, // y
+                    0, 0); // overscroll
+            runAnimatedScroll(true);
+        }
+    }
+
+    /**
+     * {@inheritDoc}
+     *
+     * <p>This version also clamps the scrolling to the bounds of our child.
+     */
+    @Override
+    public void scrollTo(int x, int y) {
+        // we rely on the fact the View.scrollBy calls scrollTo.
+        if (getChildCount() > 0) {
+            View child = getChildAt(0);
+            final LayoutParams lp = (LayoutParams) child.getLayoutParams();
+            int parentSpaceHorizontal = getWidth() - getPaddingLeft() - getPaddingRight();
+            int childSizeHorizontal = child.getWidth() + lp.leftMargin + lp.rightMargin;
+            int parentSpaceVertical = getHeight() - getPaddingTop() - getPaddingBottom();
+            int childSizeVertical = child.getHeight() + lp.topMargin + lp.bottomMargin;
+            x = clamp(x, parentSpaceHorizontal, childSizeHorizontal);
+            y = clamp(y, parentSpaceVertical, childSizeVertical);
+            if (x != getScrollX() || y != getScrollY()) {
+                super.scrollTo(x, y);
+            }
+        }
+    }
+
+    @Override
+    public void draw(@NonNull Canvas canvas) {
+        super.draw(canvas);
+        final int scrollY = getScrollY();
+        if (!mEdgeGlowTop.isFinished()) {
+            final int restoreCount = canvas.save();
+            int width = getWidth();
+            int height = getHeight();
+            int xTranslation = 0;
+            int yTranslation = Math.min(0, scrollY);
+            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP
+                    || Api21Impl.getClipToPadding(this)) {
+                width -= getPaddingLeft() + getPaddingRight();
+                xTranslation += getPaddingLeft();
+            }
+            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP
+                    && Api21Impl.getClipToPadding(this)) {
+                height -= getPaddingTop() + getPaddingBottom();
+                yTranslation += getPaddingTop();
+            }
+            canvas.translate(xTranslation, yTranslation);
+            mEdgeGlowTop.setSize(width, height);
+            if (mEdgeGlowTop.draw(canvas)) {
+                postInvalidateOnAnimation();
+            }
+            canvas.restoreToCount(restoreCount);
+        }
+        if (!mEdgeGlowBottom.isFinished()) {
+            final int restoreCount = canvas.save();
+            int width = getWidth();
+            int height = getHeight();
+            int xTranslation = 0;
+            int yTranslation = Math.max(getScrollRange(), scrollY) + height;
+            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP
+                    || Api21Impl.getClipToPadding(this)) {
+                width -= getPaddingLeft() + getPaddingRight();
+                xTranslation += getPaddingLeft();
+            }
+            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP
+                    && Api21Impl.getClipToPadding(this)) {
+                height -= getPaddingTop() + getPaddingBottom();
+                yTranslation -= getPaddingBottom();
+            }
+            canvas.translate(xTranslation - width, yTranslation);
+            canvas.rotate(180, width, 0);
+            mEdgeGlowBottom.setSize(width, height);
+            if (mEdgeGlowBottom.draw(canvas)) {
+                postInvalidateOnAnimation();
+            }
+            canvas.restoreToCount(restoreCount);
+        }
+    }
+
+    private static int clamp(int n, int my, int child) {
+        if (my >= child || n < 0) {
+            /* my >= child is this case:
+             *                    |--------------- me ---------------|
+             *     |------ child ------|
+             * or
+             *     |--------------- me ---------------|
+             *            |------ child ------|
+             * or
+             *     |--------------- me ---------------|
+             *                                  |------ child ------|
+             *
+             * n < 0 is this case:
+             *     |------ me ------|
+             *                    |-------- child --------|
+             *     |-- mScrollX --|
+             */
+            return 0;
+        }
+        if ((my + n) > child) {
+            /* this case:
+             *                    |------ me ------|
+             *     |------ child ------|
+             *     |-- mScrollX --|
+             */
+            return child - my;
+        }
+        return n;
+    }
+
+    @Override
+    protected void onRestoreInstanceState(Parcelable state) {
+        if (!(state instanceof SavedState)) {
+            super.onRestoreInstanceState(state);
+            return;
+        }
+
+        SavedState ss = (SavedState) state;
+        super.onRestoreInstanceState(ss.getSuperState());
+        mSavedState = ss;
+        requestLayout();
+    }
+
+    @NonNull
+    @Override
+    protected Parcelable onSaveInstanceState() {
+        Parcelable superState = super.onSaveInstanceState();
+        SavedState ss = new SavedState(superState);
+        ss.scrollPosition = getScrollY();
+        return ss;
+    }
+
+    static class SavedState extends BaseSavedState {
+        public int scrollPosition;
+
+        SavedState(Parcelable superState) {
+            super(superState);
+        }
+
+        SavedState(Parcel source) {
+            super(source);
+            scrollPosition = source.readInt();
+        }
+
+        @Override
+        public void writeToParcel(Parcel dest, int flags) {
+            super.writeToParcel(dest, flags);
+            dest.writeInt(scrollPosition);
+        }
+
+        @NonNull
+        @Override
+        public String toString() {
+            return "HorizontalScrollView.SavedState{"
+                    + Integer.toHexString(System.identityHashCode(this))
+                    + " scrollPosition=" + scrollPosition + "}";
+        }
+
+        public static final Creator<SavedState> CREATOR =
+                new Creator<SavedState>() {
+            @Override
+            public SavedState createFromParcel(Parcel in) {
+                return new SavedState(in);
+            }
+
+            @Override
+            public SavedState[] newArray(int size) {
+                return new SavedState[size];
+            }
+        };
+    }
+
+    static class AccessibilityDelegate extends AccessibilityDelegateCompat {
+        @Override
+        public boolean performAccessibilityAction(View host, int action, Bundle arguments) {
+            if (super.performAccessibilityAction(host, action, arguments)) {
+                return true;
+            }
+            final NestedScrollView nsvHost = (NestedScrollView) host;
+            if (!nsvHost.isEnabled()) {
+                return false;
+            }
+            int height = nsvHost.getHeight();
+            Rect rect = new Rect();
+            // Gets the visible rect on the screen except for the rotation or scale cases which
+            // might affect the result.
+            if (nsvHost.getMatrix().isIdentity() && nsvHost.getGlobalVisibleRect(rect)) {
+                height = rect.height();
+            }
+            switch (action) {
+                case AccessibilityNodeInfoCompat.ACTION_SCROLL_FORWARD:
+                case android.R.id.accessibilityActionScrollDown: {
+                    final int viewportHeight = height - nsvHost.getPaddingBottom()
+                            - nsvHost.getPaddingTop();
+                    final int targetScrollY = Math.min(nsvHost.getScrollY() + viewportHeight,
+                            nsvHost.getScrollRange());
+                    if (targetScrollY != nsvHost.getScrollY()) {
+                        nsvHost.smoothScrollTo(0, targetScrollY, true);
+                        return true;
+                    }
+                }
+                return false;
+                case AccessibilityNodeInfoCompat.ACTION_SCROLL_BACKWARD:
+                case android.R.id.accessibilityActionScrollUp: {
+                    final int viewportHeight = height - nsvHost.getPaddingBottom()
+                            - nsvHost.getPaddingTop();
+                    final int targetScrollY = Math.max(nsvHost.getScrollY() - viewportHeight, 0);
+                    if (targetScrollY != nsvHost.getScrollY()) {
+                        nsvHost.smoothScrollTo(0, targetScrollY, true);
+                        return true;
+                    }
+                }
+                return false;
+            }
+            return false;
+        }
+
+        @Override
+        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
+            super.onInitializeAccessibilityNodeInfo(host, info);
+            final NestedScrollView nsvHost = (NestedScrollView) host;
+            info.setClassName(ScrollView.class.getName());
+            if (nsvHost.isEnabled()) {
+                final int scrollRange = nsvHost.getScrollRange();
+                if (scrollRange > 0) {
+                    info.setScrollable(true);
+                    if (nsvHost.getScrollY() > 0) {
+                        info.addAction(AccessibilityNodeInfoCompat.AccessibilityActionCompat
+                                .ACTION_SCROLL_BACKWARD);
+                        info.addAction(AccessibilityNodeInfoCompat.AccessibilityActionCompat
+                                .ACTION_SCROLL_UP);
+                    }
+                    if (nsvHost.getScrollY() < scrollRange) {
+                        info.addAction(AccessibilityNodeInfoCompat.AccessibilityActionCompat
+                                .ACTION_SCROLL_FORWARD);
+                        info.addAction(AccessibilityNodeInfoCompat.AccessibilityActionCompat
+                                .ACTION_SCROLL_DOWN);
+                    }
+                }
+            }
+        }
+
+        @Override
+        public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
+            super.onInitializeAccessibilityEvent(host, event);
+            final NestedScrollView nsvHost = (NestedScrollView) host;
+            event.setClassName(ScrollView.class.getName());
+            final boolean scrollable = nsvHost.getScrollRange() > 0;
+            event.setScrollable(scrollable);
+            event.setScrollX(nsvHost.getScrollX());
+            event.setScrollY(nsvHost.getScrollY());
+            AccessibilityRecordCompat.setMaxScrollX(event, nsvHost.getScrollX());
+            AccessibilityRecordCompat.setMaxScrollY(event, nsvHost.getScrollRange());
+        }
+    }
+
+    class DifferentialMotionFlingTargetImpl implements DifferentialMotionFlingTarget {
+        @Override
+        public boolean startDifferentialMotionFling(float velocity) {
+            if (velocity == 0) {
+                return false;
+            }
+            stopDifferentialMotionFling();
+            fling((int) velocity);
+            return true;
+        }
+
+        @Override
+        public void stopDifferentialMotionFling() {
+            mScroller.abortAnimation();
+        }
+
+        @Override
+        public float getScaledScrollFactor() {
+            return -getVerticalScrollFactorCompat();
+        }
+    }
+
+    @RequiresApi(21)
+    static class Api21Impl {
+        private Api21Impl() {
+            // This class is not instantiable.
+        }
+
+        @DoNotInline
+        static boolean getClipToPadding(ViewGroup viewGroup) {
+            return viewGroup.getClipToPadding();
+        }
+    }
+}
diff --git a/java/src/com/android/intentresolver/widget/NestedScrollView.java.patch b/java/src/com/android/intentresolver/widget/NestedScrollView.java.patch
new file mode 100644
index 00000000..913d3b1a
--- /dev/null
+++ b/java/src/com/android/intentresolver/widget/NestedScrollView.java.patch
@@ -0,0 +1,103 @@
+--- prebuilts/sdk/current/androidx/m2repository/androidx/core/core/1.13.0-beta01/core-1.13.0-beta01-sources.jar!/androidx/core/widget/NestedScrollView.java	1980-02-01 00:00:00.000000000 -0800
++++ packages/modules/IntentResolver/java/src/com/android/intentresolver/widget/NestedScrollView.java	2024-03-04 17:17:47.357059016 -0800
+@@ -1,5 +1,5 @@
+ /*
+- * Copyright (C) 2015 The Android Open Source Project
++ * Copyright 2024 The Android Open Source Project
+  *
+  * Licensed under the Apache License, Version 2.0 (the "License");
+  * you may not use this file except in compliance with the License.
+@@ -15,10 +15,9 @@
+  */
+ 
+ 
+-package androidx.core.widget;
++package com.android.intentresolver.widget;
+ 
+ import static androidx.annotation.RestrictTo.Scope.LIBRARY;
+-import static androidx.annotation.RestrictTo.Scope.LIBRARY_GROUP_PREFIX;
+ 
+ import android.content.Context;
+ import android.content.res.TypedArray;
+@@ -67,13 +66,19 @@
+ import androidx.core.view.ViewCompat;
+ import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
+ import androidx.core.view.accessibility.AccessibilityRecordCompat;
++import androidx.core.widget.EdgeEffectCompat;
+ 
+ import java.util.List;
+ 
+ /**
+- * NestedScrollView is just like {@link ScrollView}, but it supports acting
+- * as both a nested scrolling parent and child on both new and old versions of Android.
+- * Nested scrolling is enabled by default.
++ * A copy of the {@link androidx.core.widget.NestedScrollView} (from
++ * prebuilts/sdk/current/androidx/m2repository/androidx/core/core/1.13.0-beta01/core-1.13.0-beta01-sources.jar)
++ * without any functional changes with a pure refactoring of {@link #requestChildFocus(View, View)}:
++ * the method's body is extracted into the new protected method,
++ * {@link #onRequestChildFocus(View, View)}.
++ * <p>
++ * For the exact change see NestedScrollView.java.patch file.
++ * </p>
+  */
+ public class NestedScrollView extends FrameLayout implements NestedScrollingParent3,
+         NestedScrollingChild3, ScrollingView {
+@@ -1858,7 +1863,6 @@
+      * <p>The scroll range of a scroll view is the overall height of all of its
+      * children.</p>
+      */
+-    @RestrictTo(LIBRARY_GROUP_PREFIX)
+     @Override
+     public int computeVerticalScrollRange() {
+         final int count = getChildCount();
+@@ -1881,31 +1885,26 @@
+         return scrollRange;
+     }
+ 
+-    @RestrictTo(LIBRARY_GROUP_PREFIX)
+     @Override
+     public int computeVerticalScrollOffset() {
+         return Math.max(0, super.computeVerticalScrollOffset());
+     }
+ 
+-    @RestrictTo(LIBRARY_GROUP_PREFIX)
+     @Override
+     public int computeVerticalScrollExtent() {
+         return super.computeVerticalScrollExtent();
+     }
+ 
+-    @RestrictTo(LIBRARY_GROUP_PREFIX)
+     @Override
+     public int computeHorizontalScrollRange() {
+         return super.computeHorizontalScrollRange();
+     }
+ 
+-    @RestrictTo(LIBRARY_GROUP_PREFIX)
+     @Override
+     public int computeHorizontalScrollOffset() {
+         return super.computeHorizontalScrollOffset();
+     }
+ 
+-    @RestrictTo(LIBRARY_GROUP_PREFIX)
+     @Override
+     public int computeHorizontalScrollExtent() {
+         return super.computeHorizontalScrollExtent();
+@@ -2163,13 +2162,17 @@
+ 
+     @Override
+     public void requestChildFocus(View child, View focused) {
++        onRequestChildFocus(child, focused);
++        super.requestChildFocus(child, focused);
++    }
++
++    protected void onRequestChildFocus(View child, View focused) {
+         if (!mIsLayoutDirty) {
+             scrollToChild(focused);
+         } else {
+             // The child may not be laid out yet, we can't compute the scroll yet
+             mChildToScrollTo = focused;
+         }
+-        super.requestChildFocus(child, focused);
+     }
+ 
+ 
diff --git a/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java b/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java
index 2c8140d9..07693b25 100644
--- a/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java
+++ b/java/src/com/android/intentresolver/widget/ResolverDrawerLayout.java
@@ -61,7 +61,7 @@ public class ResolverDrawerLayout extends ViewGroup {
     /**
      * Max width of the whole drawer layout
      */
-    private final int mMaxWidth;
+    private int mMaxWidth;
 
     /**
      * Max total visible height of views not marked always-show when in the closed/initial state
@@ -264,6 +264,16 @@ public class ResolverDrawerLayout extends ViewGroup {
         invalidate();
     }
 
+    /**
+     * Sets max drawer width.
+     */
+    public void setMaxWidth(int maxWidth) {
+        if (mMaxWidth != maxWidth) {
+            mMaxWidth = maxWidth;
+            requestLayout();
+        }
+    }
+
     public void setDismissLocked(boolean locked) {
         mDismissLocked = locked;
     }
diff --git a/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt b/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt
index c706e3ee..935a8724 100644
--- a/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt
+++ b/java/src/com/android/intentresolver/widget/ScrollableImagePreviewView.kt
@@ -71,38 +71,39 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
     constructor(
         context: Context,
         attrs: AttributeSet?,
-        defStyleAttr: Int
+        defStyleAttr: Int,
     ) : super(context, attrs, defStyleAttr) {
         layoutManager = LinearLayoutManager(context, LinearLayoutManager.HORIZONTAL, false)
 
+        val editButtonRoleDescription: CharSequence?
         context
             .obtainStyledAttributes(attrs, R.styleable.ScrollableImagePreviewView, defStyleAttr, 0)
             .use { a ->
                 var innerSpacing =
                     a.getDimensionPixelSize(
                         R.styleable.ScrollableImagePreviewView_itemInnerSpacing,
-                        -1
+                        -1,
                     )
                 if (innerSpacing < 0) {
                     innerSpacing =
                         TypedValue.applyDimension(
                                 TypedValue.COMPLEX_UNIT_DIP,
                                 3f,
-                                context.resources.displayMetrics
+                                context.resources.displayMetrics,
                             )
                             .toInt()
                 }
                 outerSpacing =
                     a.getDimensionPixelSize(
                         R.styleable.ScrollableImagePreviewView_itemOuterSpacing,
-                        -1
+                        -1,
                     )
                 if (outerSpacing < 0) {
                     outerSpacing =
                         TypedValue.applyDimension(
                                 TypedValue.COMPLEX_UNIT_DIP,
                                 16f,
-                                context.resources.displayMetrics
+                                context.resources.displayMetrics,
                             )
                             .toInt()
                 }
@@ -110,10 +111,13 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
 
                 maxWidthHint =
                     a.getDimensionPixelSize(R.styleable.ScrollableImagePreviewView_maxWidthHint, -1)
+
+                editButtonRoleDescription =
+                    a.getText(R.styleable.ScrollableImagePreviewView_editButtonRoleDescription)
             }
         val itemAnimator = ItemAnimator()
         super.setItemAnimator(itemAnimator)
-        super.setAdapter(Adapter(context, itemAnimator.getAddDuration()))
+        super.setAdapter(Adapter(context, itemAnimator.getAddDuration(), editButtonRoleDescription))
     }
 
     private var batchLoader: BatchPreviewLoader? = null
@@ -125,7 +129,6 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
      */
     var maxWidthHint: Int = -1
 
-    private var requestedHeight: Int = 0
     private var isMeasured = false
     private var maxAspectRatio = MAX_ASPECT_RATIO
     private var maxAspectRatioString = MAX_ASPECT_RATIO_STRING
@@ -217,7 +220,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                         onNoPreviewCallback?.run()
                     }
                     previewAdapter.markLoaded()
-                }
+                },
             )
         maybeLoadAspectRatios()
     }
@@ -281,24 +284,25 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
         val type: PreviewType,
         val uri: Uri,
         val editAction: Runnable?,
-        internal var aspectRatioString: String
+        internal var aspectRatioString: String,
     ) {
         constructor(
             type: PreviewType,
             uri: Uri,
-            editAction: Runnable?
+            editAction: Runnable?,
         ) : this(type, uri, editAction, "1:1")
     }
 
     enum class PreviewType {
         Image,
         Video,
-        File
+        File,
     }
 
     private class Adapter(
         private val context: Context,
         private val fadeInDurationMs: Long,
+        private val editButtonRoleDescription: CharSequence?,
     ) : RecyclerView.Adapter<ViewHolder>() {
         private val previews = ArrayList<Preview>()
         private val imagePreviewDescription =
@@ -409,6 +413,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                         previewSize,
                         fadeInDurationMs,
                         isSharedTransitionElement = position == firstImagePos,
+                        editButtonRoleDescription,
                         previewReadyCallback =
                             if (
                                 position == firstImagePos && transitionStatusElementCallback != null
@@ -416,7 +421,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                                 this::onTransitionElementReady
                             } else {
                                 null
-                            }
+                            },
                     )
             }
         }
@@ -461,7 +466,8 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
             previewSize: Size,
             fadeInDurationMs: Long,
             isSharedTransitionElement: Boolean,
-            previewReadyCallback: ((String) -> Unit)?
+            editButtonRoleDescription: CharSequence?,
+            previewReadyCallback: ((String) -> Unit)?,
         ) {
             image.setImageDrawable(null)
             image.alpha = 1f
@@ -495,6 +501,12 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                 editActionContainer?.apply {
                     setOnClickListener { onClick.run() }
                     visibility = View.VISIBLE
+                    if (editButtonRoleDescription != null) {
+                        ViewCompat.setAccessibilityDelegate(
+                            this,
+                            ViewRoleDescriptionAccessibilityDelegate(editButtonRoleDescription),
+                        )
+                    }
                 }
             }
             resetScope().launch {
@@ -568,7 +580,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
                 PluralsMessageFormatter.format(
                     itemView.context.resources,
                     mapOf(PLURALS_COUNT to count),
-                    R.string.other_files
+                    R.string.other_files,
                 )
         }
 
@@ -611,7 +623,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
             state: State,
             viewHolder: RecyclerView.ViewHolder,
             changeFlags: Int,
-            payloads: MutableList<Any>
+            payloads: MutableList<Any>,
         ): ItemHolderInfo {
             return super.recordPreLayoutInformation(state, viewHolder, changeFlags, payloads).let {
                 holderInfo ->
@@ -626,7 +638,7 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
         override fun animateDisappearance(
             viewHolder: RecyclerView.ViewHolder,
             preLayoutInfo: ItemHolderInfo,
-            postLayoutInfo: ItemHolderInfo?
+            postLayoutInfo: ItemHolderInfo?,
         ): Boolean {
             if (viewHolder is LoadingItemViewHolder && preLayoutInfo is LoadingItemHolderInfo) {
                 val view = viewHolder.itemView
@@ -647,10 +659,8 @@ class ScrollableImagePreviewView : RecyclerView, ImagePreviewView {
             super.onRemoveFinished(viewHolder)
         }
 
-        private inner class LoadingItemHolderInfo(
-            holderInfo: ItemHolderInfo,
-            val parentLeft: Int,
-        ) : ItemHolderInfo() {
+        private inner class LoadingItemHolderInfo(holderInfo: ItemHolderInfo, val parentLeft: Int) :
+            ItemHolderInfo() {
             init {
                 left = holderInfo.left
                 top = holderInfo.top
diff --git a/java/src/com/android/intentresolver/widget/ViewRoleDescriptionAccessibilityDelegate.kt b/java/src/com/android/intentresolver/widget/ViewRoleDescriptionAccessibilityDelegate.kt
new file mode 100644
index 00000000..8fe7144a
--- /dev/null
+++ b/java/src/com/android/intentresolver/widget/ViewRoleDescriptionAccessibilityDelegate.kt
@@ -0,0 +1,29 @@
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
+package com.android.intentresolver.widget
+
+import android.view.View
+import androidx.core.view.AccessibilityDelegateCompat
+import androidx.core.view.accessibility.AccessibilityNodeInfoCompat
+
+class ViewRoleDescriptionAccessibilityDelegate(private val roleDescription: CharSequence) :
+    AccessibilityDelegateCompat() {
+    override fun onInitializeAccessibilityNodeInfo(host: View, info: AccessibilityNodeInfoCompat) {
+        super.onInitializeAccessibilityNodeInfo(host, info)
+        info.roleDescription = roleDescription
+    }
+}
diff --git a/lint-baseline.xml b/lint-baseline.xml
index c970b7a7..c1f51348 100644
--- a/lint-baseline.xml
+++ b/lint-baseline.xml
@@ -2083,8 +2083,8 @@
 
     <issue
         id="Overdraw"
-        message="Possible overdraw: Root element paints background `?androidprv:attr/materialColorSurfaceContainer` with a theme that also paints a background (inferred theme is `@android:style/Theme.Holo`)"
-        errorLine1="    android:background=&quot;?androidprv:attr/materialColorSurfaceContainer&quot;>"
+        message="Possible overdraw: Root element paints background `@androidprv:color/materialColorSurfaceContainer` with a theme that also paints a background (inferred theme is `@android:style/Theme.Holo`)"
+        errorLine1="    android:background=&quot;@androidprv:color/materialColorSurfaceContainer&quot;>"
         errorLine2="    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
         <location
             file="packages/modules/IntentResolver/java/res/layout/chooser_grid_preview_file.xml"
@@ -2094,8 +2094,8 @@
 
     <issue
         id="Overdraw"
-        message="Possible overdraw: Root element paints background `?androidprv:attr/materialColorSurfaceContainer` with a theme that also paints a background (inferred theme is `@android:style/Theme.Holo`)"
-        errorLine1="    android:background=&quot;?androidprv:attr/materialColorSurfaceContainer&quot;>"
+        message="Possible overdraw: Root element paints background `@androidprv:color/materialColorSurfaceContainer` with a theme that also paints a background (inferred theme is `@android:style/Theme.Holo`)"
+        errorLine1="    android:background=&quot;@androidprv:color/materialColorSurfaceContainer&quot;>"
         errorLine2="    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
         <location
             file="packages/modules/IntentResolver/java/res/layout/chooser_grid_preview_files_text.xml"
@@ -2105,8 +2105,8 @@
 
     <issue
         id="Overdraw"
-        message="Possible overdraw: Root element paints background `?androidprv:attr/materialColorSurfaceContainer` with a theme that also paints a background (inferred theme is `@android:style/Theme.Holo`)"
-        errorLine1="    android:background=&quot;?androidprv:attr/materialColorSurfaceContainer&quot;>"
+        message="Possible overdraw: Root element paints background `@androidprv:color/materialColorSurfaceContainer` with a theme that also paints a background (inferred theme is `@android:style/Theme.Holo`)"
+        errorLine1="    android:background=&quot;@androidprv:color/materialColorSurfaceContainer&quot;>"
         errorLine2="    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
         <location
             file="packages/modules/IntentResolver/java/res/layout/chooser_grid_preview_image.xml"
@@ -2116,8 +2116,8 @@
 
     <issue
         id="Overdraw"
-        message="Possible overdraw: Root element paints background `?androidprv:attr/materialColorSurfaceContainer` with a theme that also paints a background (inferred theme is `@android:style/Theme.Holo`)"
-        errorLine1="    android:background=&quot;?androidprv:attr/materialColorSurfaceContainer&quot;>"
+        message="Possible overdraw: Root element paints background `@androidprv:color/materialColorSurfaceContainer` with a theme that also paints a background (inferred theme is `@android:style/Theme.Holo`)"
+        errorLine1="    android:background=&quot;@androidprv:color/materialColorSurfaceContainer&quot;>"
         errorLine2="    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
         <location
             file="packages/modules/IntentResolver/java/res/layout/chooser_grid_preview_text.xml"
diff --git a/tests/activity/Android.bp b/tests/activity/Android.bp
index 9d673b4c..2e66a84d 100644
--- a/tests/activity/Android.bp
+++ b/tests/activity/Android.bp
@@ -57,7 +57,6 @@ android_test {
         "mockito-kotlin-nodeps",
         "testables",
         "truth",
-        "truth-java8-extension",
         "flag-junit",
         "platform-test-annotations",
     ],
diff --git a/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java b/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java
index 22633085..0d317dc3 100644
--- a/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java
+++ b/tests/activity/src/com/android/intentresolver/ResolverWrapperActivity.java
@@ -160,7 +160,7 @@ public class ResolverWrapperActivity extends ResolverActivity {
         }
     }
 
-    private static class TargetDataLoaderWrapper extends TargetDataLoader {
+    private static class TargetDataLoaderWrapper implements TargetDataLoader {
         private final TargetDataLoader mTargetDataLoader;
         private final CountingIdlingResource mLabelIdlingResource;
 
diff --git a/tests/integration/Android.bp b/tests/integration/Android.bp
index c968c128..9109507a 100644
--- a/tests/integration/Android.bp
+++ b/tests/integration/Android.bp
@@ -39,7 +39,6 @@ android_test {
         "IntentResolver-tests-shared",
         "junit",
         "truth",
-        "truth-java8-extension",
     ],
     test_suites: ["general-tests"],
 }
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index 850c447f..a3b30a3a 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -59,7 +59,6 @@ android_test {
         "platform-compat-test-rules", // PlatformCompatChangeRule
         "testables", // TestableContext/TestableResources
         "truth",
-        "truth-java8-extension",
         "flag-junit",
         "platform-test-annotations",
     ],
diff --git a/tests/unit/src/com/android/intentresolver/ShortcutSelectionLogicTest.kt b/tests/unit/src/com/android/intentresolver/ShortcutSelectionLogicTest.kt
index e26dffb8..d591d928 100644
--- a/tests/unit/src/com/android/intentresolver/ShortcutSelectionLogicTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ShortcutSelectionLogicTest.kt
@@ -21,13 +21,18 @@ import android.content.Context
 import android.content.Intent
 import android.content.pm.ShortcutInfo
 import android.os.UserHandle
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
 import android.service.chooser.ChooserTarget
 import androidx.test.filters.SmallTest
 import androidx.test.platform.app.InstrumentationRegistry
+import com.android.intentresolver.Flags.FLAG_REBUILD_ADAPTERS_ON_TARGET_PINNING
 import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.chooser.TargetInfo
-import org.junit.Assert.assertEquals
-import org.junit.Assert.assertTrue
+import com.google.common.truth.Correspondence
+import com.google.common.truth.Truth.assertThat
+import com.google.common.truth.Truth.assertWithMessage
+import org.junit.Rule
 import org.junit.Test
 import org.mockito.kotlin.doReturn
 import org.mockito.kotlin.mock
@@ -36,10 +41,12 @@ private const val PACKAGE_A = "package.a"
 private const val PACKAGE_B = "package.b"
 private const val CLASS_NAME = "./MainActivity"
 
+private val PERSONAL_USER_HANDLE: UserHandle =
+    InstrumentationRegistry.getInstrumentation().targetContext.user
+
 @SmallTest
 class ShortcutSelectionLogicTest {
-    private val PERSONAL_USER_HANDLE: UserHandle =
-        InstrumentationRegistry.getInstrumentation().getTargetContext().getUser()
+    @get:Rule val flagRule = SetFlagsRule()
 
     private val packageTargets =
         HashMap<String, Array<ChooserTarget>>().apply {
@@ -57,6 +64,14 @@ class ShortcutSelectionLogicTest {
                 this[pkg] = targets
             }
         }
+    private val targetInfoChooserTargetCorrespondence =
+        Correspondence.from<TargetInfo, ChooserTarget>(
+            { actual, expected ->
+                actual.chooserTargetComponentName == expected.componentName &&
+                    actual.displayLabel == expected.title
+            },
+            "",
+        )
 
     private val baseDisplayInfo =
         DisplayResolveInfo.newDisplayResolveInfo(
@@ -64,7 +79,7 @@ class ShortcutSelectionLogicTest {
             ResolverDataProvider.createResolveInfo(3, 0, PERSONAL_USER_HANDLE),
             "label",
             "extended info",
-            Intent()
+            Intent(),
         )
 
     private val otherBaseDisplayInfo =
@@ -73,7 +88,7 @@ class ShortcutSelectionLogicTest {
             ResolverDataProvider.createResolveInfo(4, 0, PERSONAL_USER_HANDLE),
             "label 2",
             "extended info 2",
-            Intent()
+            Intent(),
         )
 
     private operator fun Map<String, Array<ChooserTarget>>.get(pkg: String, idx: Int) =
@@ -87,7 +102,7 @@ class ShortcutSelectionLogicTest {
         val testSubject =
             ShortcutSelectionLogic(
                 /* maxShortcutTargetsPerApp = */ 1,
-                /* applySharingAppLimits = */ false
+                /* applySharingAppLimits = */ false,
             )
 
         val isUpdated =
@@ -102,15 +117,15 @@ class ShortcutSelectionLogicTest {
                 /* targetIntent = */ mock(),
                 /* refererFillInIntent = */ mock(),
                 /* maxRankedTargets = */ 4,
-                /* serviceTargets = */ serviceResults
+                /* serviceTargets = */ serviceResults,
             )
 
-        assertTrue("Updates are expected", isUpdated)
-        assertShortcutsInOrder(
-            listOf(sc2, sc1),
-            serviceResults,
-            "Two shortcuts are expected as we do not apply per-app shortcut limit"
-        )
+        assertWithMessage("Updates are expected").that(isUpdated).isTrue()
+        assertWithMessage("Two shortcuts are expected as we do not apply per-app shortcut limit")
+            .that(serviceResults)
+            .comparingElementsUsing(targetInfoChooserTargetCorrespondence)
+            .containsExactly(sc2, sc1)
+            .inOrder()
     }
 
     @Test
@@ -121,7 +136,7 @@ class ShortcutSelectionLogicTest {
         val testSubject =
             ShortcutSelectionLogic(
                 /* maxShortcutTargetsPerApp = */ 1,
-                /* applySharingAppLimits = */ true
+                /* applySharingAppLimits = */ true,
             )
 
         val isUpdated =
@@ -136,15 +151,15 @@ class ShortcutSelectionLogicTest {
                 /* targetIntent = */ mock(),
                 /* refererFillInIntent = */ mock(),
                 /* maxRankedTargets = */ 4,
-                /* serviceTargets = */ serviceResults
+                /* serviceTargets = */ serviceResults,
             )
 
-        assertTrue("Updates are expected", isUpdated)
-        assertShortcutsInOrder(
-            listOf(sc2),
-            serviceResults,
-            "One shortcut is expected as we apply per-app shortcut limit"
-        )
+        assertWithMessage("Updates are expected").that(isUpdated).isTrue()
+        assertWithMessage("One shortcut is expected as we apply per-app shortcut limit")
+            .that(serviceResults)
+            .comparingElementsUsing(targetInfoChooserTargetCorrespondence)
+            .containsExactly(sc2)
+            .inOrder()
     }
 
     @Test
@@ -155,7 +170,7 @@ class ShortcutSelectionLogicTest {
         val testSubject =
             ShortcutSelectionLogic(
                 /* maxShortcutTargetsPerApp = */ 1,
-                /* applySharingAppLimits = */ false
+                /* applySharingAppLimits = */ false,
             )
 
         val isUpdated =
@@ -170,15 +185,15 @@ class ShortcutSelectionLogicTest {
                 /* targetIntent = */ mock(),
                 /* refererFillInIntent = */ mock(),
                 /* maxRankedTargets = */ 1,
-                /* serviceTargets = */ serviceResults
+                /* serviceTargets = */ serviceResults,
             )
 
-        assertTrue("Updates are expected", isUpdated)
-        assertShortcutsInOrder(
-            listOf(sc2),
-            serviceResults,
-            "One shortcut is expected as we apply overall shortcut limit"
-        )
+        assertWithMessage("Updates are expected").that(isUpdated).isTrue()
+        assertWithMessage("One shortcut is expected as we apply overall shortcut limit")
+            .that(serviceResults)
+            .comparingElementsUsing(targetInfoChooserTargetCorrespondence)
+            .containsExactly(sc2)
+            .inOrder()
     }
 
     @Test
@@ -191,7 +206,7 @@ class ShortcutSelectionLogicTest {
         val testSubject =
             ShortcutSelectionLogic(
                 /* maxShortcutTargetsPerApp = */ 1,
-                /* applySharingAppLimits = */ true
+                /* applySharingAppLimits = */ true,
             )
 
         testSubject.addServiceResults(
@@ -205,7 +220,7 @@ class ShortcutSelectionLogicTest {
             /* targetIntent = */ mock(),
             /* refererFillInIntent = */ mock(),
             /* maxRankedTargets = */ 4,
-            /* serviceTargets = */ serviceResults
+            /* serviceTargets = */ serviceResults,
         )
         testSubject.addServiceResults(
             /* origTarget = */ otherBaseDisplayInfo,
@@ -218,14 +233,14 @@ class ShortcutSelectionLogicTest {
             /* targetIntent = */ mock(),
             /* refererFillInIntent = */ mock(),
             /* maxRankedTargets = */ 4,
-            /* serviceTargets = */ serviceResults
+            /* serviceTargets = */ serviceResults,
         )
 
-        assertShortcutsInOrder(
-            listOf(pkgBsc2, pkgAsc2),
-            serviceResults,
-            "Two shortcuts are expected as we apply per-app shortcut limit"
-        )
+        assertWithMessage("Two shortcuts are expected as we apply per-app shortcut limit")
+            .that(serviceResults)
+            .comparingElementsUsing(targetInfoChooserTargetCorrespondence)
+            .containsExactly(pkgBsc2, pkgAsc2)
+            .inOrder()
     }
 
     @Test
@@ -236,7 +251,7 @@ class ShortcutSelectionLogicTest {
         val testSubject =
             ShortcutSelectionLogic(
                 /* maxShortcutTargetsPerApp = */ 1,
-                /* applySharingAppLimits = */ false
+                /* applySharingAppLimits = */ false,
             )
 
         val isUpdated =
@@ -256,15 +271,15 @@ class ShortcutSelectionLogicTest {
                 /* targetIntent = */ mock(),
                 /* refererFillInIntent = */ mock(),
                 /* maxRankedTargets = */ 4,
-                /* serviceTargets = */ serviceResults
+                /* serviceTargets = */ serviceResults,
             )
 
-        assertTrue("Updates are expected", isUpdated)
-        assertShortcutsInOrder(
-            listOf(sc1, sc2),
-            serviceResults,
-            "Two shortcuts are expected as we do not apply per-app shortcut limit"
-        )
+        assertWithMessage("Updates are expected").that(isUpdated).isTrue()
+        assertWithMessage("Two shortcuts are expected as we do not apply per-app shortcut limit")
+            .that(serviceResults)
+            .comparingElementsUsing(targetInfoChooserTargetCorrespondence)
+            .containsExactly(sc1, sc2)
+            .inOrder()
     }
 
     @Test
@@ -276,7 +291,7 @@ class ShortcutSelectionLogicTest {
         val testSubject =
             ShortcutSelectionLogic(
                 /* maxShortcutTargetsPerApp = */ 1,
-                /* applySharingAppLimits = */ true
+                /* applySharingAppLimits = */ true,
             )
         val context = mock<Context> { on { packageManager } doReturn (mock()) }
 
@@ -291,36 +306,82 @@ class ShortcutSelectionLogicTest {
             /* targetIntent = */ mock(),
             /* refererFillInIntent = */ mock(),
             /* maxRankedTargets = */ 4,
-            /* serviceTargets = */ serviceResults
+            /* serviceTargets = */ serviceResults,
         )
 
-        assertShortcutsInOrder(
-            listOf(sc3, sc2),
-            serviceResults,
-            "At most two caller-provided shortcuts are allowed"
-        )
+        assertWithMessage("At most two caller-provided shortcuts are allowed")
+            .that(serviceResults)
+            .comparingElementsUsing(targetInfoChooserTargetCorrespondence)
+            .containsExactly(sc3, sc2)
+            .inOrder()
     }
 
-    // TODO: consider renaming. Not all `ChooserTarget`s are "shortcuts" and many of our test cases
-    // add results with `isShortcutResult = false` and `directShareToShortcutInfos = emptyMap()`.
-    private fun assertShortcutsInOrder(
-        expected: List<ChooserTarget>,
-        actual: List<TargetInfo>,
-        msg: String? = ""
-    ) {
-        assertEquals(msg, expected.size, actual.size)
-        for (i in expected.indices) {
-            assertEquals(
-                "Unexpected item at position $i",
-                expected[i].componentName,
-                actual[i].chooserTargetComponentName
+    @Test
+    @EnableFlags(FLAG_REBUILD_ADAPTERS_ON_TARGET_PINNING)
+    fun addServiceResults_sameShortcutWithDifferentPinnedStatus_shortcutUpdated() {
+        val serviceResults = ArrayList<TargetInfo>()
+        val sc1 =
+            createChooserTarget(
+                title = "Shortcut",
+                score = 1f,
+                ComponentName(PACKAGE_A, CLASS_NAME),
+                PACKAGE_A.shortcutId(0),
             )
-            assertEquals(
-                "Unexpected item at position $i",
-                expected[i].title,
-                actual[i].displayLabel
+        val sc2 =
+            createChooserTarget(
+                title = "Shortcut",
+                score = 1f,
+                ComponentName(PACKAGE_A, CLASS_NAME),
+                PACKAGE_A.shortcutId(0),
             )
-        }
+        val testSubject =
+            ShortcutSelectionLogic(
+                /* maxShortcutTargetsPerApp = */ 1,
+                /* applySharingAppLimits = */ false,
+            )
+
+        testSubject.addServiceResults(
+            /* origTarget = */ baseDisplayInfo,
+            /* origTargetScore = */ 0.1f,
+            /* targets = */ listOf(sc1),
+            /* isShortcutResult = */ true,
+            /* directShareToShortcutInfos = */ mapOf(
+                sc1 to createShortcutInfo(PACKAGE_A.shortcutId(1), sc1.componentName, 1)
+            ),
+            /* directShareToAppTargets = */ emptyMap(),
+            /* userContext = */ mock(),
+            /* targetIntent = */ mock(),
+            /* refererFillInIntent = */ mock(),
+            /* maxRankedTargets = */ 4,
+            /* serviceTargets = */ serviceResults,
+        )
+        val isUpdated =
+            testSubject.addServiceResults(
+                /* origTarget = */ baseDisplayInfo,
+                /* origTargetScore = */ 0.1f,
+                /* targets = */ listOf(sc1),
+                /* isShortcutResult = */ true,
+                /* directShareToShortcutInfos = */ mapOf(
+                    sc1 to
+                        createShortcutInfo(PACKAGE_A.shortcutId(1), sc1.componentName, 1).apply {
+                            addFlags(ShortcutInfo.FLAG_PINNED)
+                        }
+                ),
+                /* directShareToAppTargets = */ emptyMap(),
+                /* userContext = */ mock(),
+                /* targetIntent = */ mock(),
+                /* refererFillInIntent = */ mock(),
+                /* maxRankedTargets = */ 4,
+                /* serviceTargets = */ serviceResults,
+            )
+
+        assertWithMessage("Updates are expected").that(isUpdated).isTrue()
+        assertWithMessage("Updated shortcut is expected")
+            .that(serviceResults)
+            .comparingElementsUsing(targetInfoChooserTargetCorrespondence)
+            .containsExactly(sc2)
+            .inOrder()
+        assertThat(serviceResults[0].isPinned).isTrue()
     }
 
     private fun String.shortcutId(id: Int) = "$this.$id"
diff --git a/tests/unit/src/com/android/intentresolver/TargetPresentationGetterTest.kt b/tests/unit/src/com/android/intentresolver/TargetPresentationGetterTest.kt
index 92848b2c..b5b05eb9 100644
--- a/tests/unit/src/com/android/intentresolver/TargetPresentationGetterTest.kt
+++ b/tests/unit/src/com/android/intentresolver/TargetPresentationGetterTest.kt
@@ -32,32 +32,42 @@ class TargetPresentationGetterTest {
         withSubstitutePermission: Boolean,
         appLabel: String,
         activityLabel: String,
-        resolveInfoLabel: String
+        resolveInfoLabel: String,
     ): TargetPresentationGetter {
         val testPackageInfo =
             ResolverDataProvider.createPackageManagerMockedInfo(
                 withSubstitutePermission,
                 appLabel,
                 activityLabel,
-                resolveInfoLabel
+                resolveInfoLabel,
+            )
+        val factory =
+            TargetPresentationGetter.Factory(
+                { SimpleIconFactory.obtain(testPackageInfo.ctx) },
+                testPackageInfo.ctx.packageManager,
+                100,
             )
-        val factory = TargetPresentationGetter.Factory(testPackageInfo.ctx, 100)
         return factory.makePresentationGetter(testPackageInfo.resolveInfo)
     }
 
     fun makeActivityInfoPresentationGetter(
         withSubstitutePermission: Boolean,
         appLabel: String?,
-        activityLabel: String?
+        activityLabel: String?,
     ): TargetPresentationGetter {
         val testPackageInfo =
             ResolverDataProvider.createPackageManagerMockedInfo(
                 withSubstitutePermission,
                 appLabel,
                 activityLabel,
-                ""
+                "",
+            )
+        val factory =
+            TargetPresentationGetter.Factory(
+                { SimpleIconFactory.obtain(testPackageInfo.ctx) },
+                testPackageInfo.ctx.packageManager,
+                100,
             )
-        val factory = TargetPresentationGetter.Factory(testPackageInfo.ctx, 100)
         return factory.makePresentationGetter(testPackageInfo.activityInfo)
     }
 
@@ -158,7 +168,7 @@ class TargetPresentationGetterTest {
                 false,
                 "app_label",
                 "activity_label",
-                "resolve_info_label"
+                "resolve_info_label",
             )
         assertThat(presentationGetter.getLabel()).isEqualTo("app_label")
         assertThat(presentationGetter.getSubLabel()).isEqualTo("resolve_info_label")
@@ -192,7 +202,7 @@ class TargetPresentationGetterTest {
                 true,
                 "app_label",
                 "activity_label",
-                "resolve_info_label"
+                "resolve_info_label",
             )
         assertThat(presentationGetter.getLabel()).isEqualTo("activity_label")
         assertThat(presentationGetter.getSubLabel()).isEqualTo("resolve_info_label")
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUiTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUiTest.kt
index 905c8517..ef0703e6 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUiTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/ChooserContentPreviewUiTest.kt
@@ -61,11 +61,7 @@ class ChooserContentPreviewUiTest {
     private val transitionCallback = mock<ImagePreviewView.TransitionElementStatusCallback>()
     @get:Rule val checkFlagsRule: CheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule()
 
-    private fun createContentPreviewUi(
-        action: String,
-        sharedText: CharSequence? = null,
-        isPayloadTogglingEnabled: Boolean = false
-    ) =
+    private fun createContentPreviewUi(action: String, sharedText: CharSequence? = null) =
         ChooserContentPreviewUi(
             testScope,
             previewData,
@@ -81,7 +77,6 @@ class ChooserContentPreviewUiTest {
             headlineGenerator,
             ContentTypeHint.NONE,
             testMetadataText,
-            isPayloadTogglingEnabled,
         )
 
     @Test
@@ -114,10 +109,7 @@ class ChooserContentPreviewUiTest {
             .thenReturn(FileInfo.Builder(uri).withPreviewUri(uri).withMimeType("image/png").build())
         whenever(previewData.imagePreviewFileInfoFlow).thenReturn(MutableSharedFlow())
         val testSubject =
-            createContentPreviewUi(
-                action = Intent.ACTION_SEND,
-                sharedText = "Shared text",
-            )
+            createContentPreviewUi(action = Intent.ACTION_SEND, sharedText = "Shared text")
         assertThat(testSubject.mContentPreviewUi)
             .isInstanceOf(FilesPlusTextContentPreviewUi::class.java)
         verify(previewData, times(1)).imagePreviewFileInfoFlow
@@ -150,11 +142,7 @@ class ChooserContentPreviewUiTest {
         whenever(previewData.firstFileInfo)
             .thenReturn(FileInfo.Builder(uri).withPreviewUri(uri).withMimeType("image/png").build())
         whenever(previewData.imagePreviewFileInfoFlow).thenReturn(MutableSharedFlow())
-        val testSubject =
-            createContentPreviewUi(
-                action = Intent.ACTION_SEND,
-                isPayloadTogglingEnabled = true,
-            )
+        val testSubject = createContentPreviewUi(action = Intent.ACTION_SEND)
         assertThat(testSubject.mContentPreviewUi)
             .isInstanceOf(ShareouselContentPreviewUi::class.java)
         assertThat(testSubject.preferredContentPreview)
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt
index 370ee044..9884a675 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/PreviewDataProviderTest.kt
@@ -21,9 +21,13 @@ import android.content.Intent
 import android.database.MatrixCursor
 import android.media.MediaMetadata
 import android.net.Uri
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.FlagsParameterization
+import android.platform.test.flag.junit.SetFlagsRule
 import android.provider.DocumentsContract
-import android.service.chooser.FakeFeatureFlagsImpl
-import android.service.chooser.Flags
+import android.provider.Downloads
+import android.provider.OpenableColumns
+import com.android.intentresolver.Flags.FLAG_INDIVIDUAL_METADATA_TITLE_READ
 import com.google.common.truth.Truth.assertThat
 import kotlin.coroutines.EmptyCoroutineContext
 import kotlinx.coroutines.CoroutineScope
@@ -32,21 +36,26 @@ import kotlinx.coroutines.flow.toList
 import kotlinx.coroutines.test.TestScope
 import kotlinx.coroutines.test.UnconfinedTestDispatcher
 import kotlinx.coroutines.test.runTest
+import org.junit.Rule
 import org.junit.Test
+import org.junit.runner.RunWith
+import org.junit.runners.Parameterized
 import org.mockito.kotlin.any
+import org.mockito.kotlin.anyOrNull
+import org.mockito.kotlin.eq
 import org.mockito.kotlin.mock
 import org.mockito.kotlin.never
 import org.mockito.kotlin.times
 import org.mockito.kotlin.verify
 import org.mockito.kotlin.whenever
 
+@RunWith(Parameterized::class)
 @OptIn(ExperimentalCoroutinesApi::class)
-class PreviewDataProviderTest {
+class PreviewDataProviderTest(flags: FlagsParameterization) {
     private val contentResolver = mock<ContentInterface>()
     private val mimeTypeClassifier = DefaultMimeTypeClassifier
     private val testScope = TestScope(EmptyCoroutineContext + UnconfinedTestDispatcher())
-    private val featureFlags =
-        FakeFeatureFlagsImpl().apply { setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, false) }
+    @get:Rule val setFlagsRule = SetFlagsRule(flags)
 
     private fun createDataProvider(
         targetIntent: Intent,
@@ -54,15 +63,7 @@ class PreviewDataProviderTest {
         additionalContentUri: Uri? = null,
         resolver: ContentInterface = contentResolver,
         typeClassifier: MimeTypeClassifier = mimeTypeClassifier,
-    ) =
-        PreviewDataProvider(
-            scope,
-            targetIntent,
-            additionalContentUri,
-            resolver,
-            featureFlags,
-            typeClassifier,
-        )
+    ) = PreviewDataProvider(scope, targetIntent, additionalContentUri, resolver, typeClassifier)
 
     @Test
     fun test_nonSendIntentAction_resolvesToTextPreviewUiSynchronously() {
@@ -74,21 +75,49 @@ class PreviewDataProviderTest {
     }
 
     @Test
-    fun test_sendSingleTextFileWithoutPreview_resolvesToFilePreviewUi() {
-        val uri = Uri.parse("content://org.pkg.app/notes.txt")
-        val targetIntent =
-            Intent(Intent.ACTION_SEND).apply {
-                putExtra(Intent.EXTRA_STREAM, uri)
-                type = "text/plain"
-            }
-        whenever(contentResolver.getType(uri)).thenReturn("text/plain")
-        val testSubject = createDataProvider(targetIntent)
+    fun test_sendSingleTextFileWithoutPreview_resolvesToFilePreviewUi() =
+        testScope.runTest {
+            val fileName = "notes.txt"
+            val uri = Uri.parse("content://org.pkg.app/$fileName")
+            val targetIntent =
+                Intent(Intent.ACTION_SEND).apply {
+                    putExtra(Intent.EXTRA_STREAM, uri)
+                    type = "text/plain"
+                }
+            whenever(contentResolver.getType(uri)).thenReturn("text/plain")
+            val testSubject = createDataProvider(targetIntent)
 
-        assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
-        assertThat(testSubject.uriCount).isEqualTo(1)
-        assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
-        verify(contentResolver, times(1)).getType(any())
-    }
+            assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
+            assertThat(testSubject.uriCount).isEqualTo(1)
+            assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
+            assertThat(testSubject.getFirstFileName()).isEqualTo(fileName)
+            verify(contentResolver, times(1)).getType(any())
+        }
+
+    @Test
+    fun test_sendSingleTextFileWithDisplayNameAndTitle_displayNameTakesPrecedenceOverTitle() =
+        testScope.runTest {
+            val uri = Uri.parse("content://org.pkg.app/1234")
+            val targetIntent =
+                Intent(Intent.ACTION_SEND).apply {
+                    putExtra(Intent.EXTRA_STREAM, uri)
+                    type = "text/plain"
+                }
+            whenever(contentResolver.getType(uri)).thenReturn("text/plain")
+            val title = "Notes"
+            val displayName = "Notes.txt"
+            whenever(contentResolver.query(eq(uri), anyOrNull(), anyOrNull(), anyOrNull()))
+                .thenReturn(
+                    MatrixCursor(arrayOf(Downloads.Impl.COLUMN_TITLE, OpenableColumns.DISPLAY_NAME))
+                        .apply { addRow(arrayOf(title, displayName)) }
+                )
+            contentResolver.setTitle(uri, title)
+            contentResolver.setDisplayName(uri, displayName)
+            val testSubject = createDataProvider(targetIntent)
+
+            assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
+            assertThat(testSubject.getFirstFileName()).isEqualTo(displayName)
+        }
 
     @Test
     fun test_sendIntentWithoutUris_resolvesToTextPreviewUiSynchronously() {
@@ -114,60 +143,145 @@ class PreviewDataProviderTest {
     }
 
     @Test
-    fun test_sendSingleNonImage_resolvesToFilePreviewUi() {
-        val uri = Uri.parse("content://org.pkg.app/paper.pdf")
-        val targetIntent = Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_STREAM, uri) }
-        whenever(contentResolver.getType(uri)).thenReturn("application/pdf")
-        val testSubject = createDataProvider(targetIntent)
+    fun test_sendSingleFile_resolvesToFilePreviewUi() =
+        testScope.runTest {
+            val fileName = "paper.pdf"
+            val uri = Uri.parse("content://org.pkg.app/$fileName")
+            val targetIntent =
+                Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_STREAM, uri) }
+            whenever(contentResolver.getType(uri)).thenReturn("application/pdf")
+            val testSubject = createDataProvider(targetIntent)
 
-        assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
-        assertThat(testSubject.uriCount).isEqualTo(1)
-        assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
-        assertThat(testSubject.firstFileInfo?.previewUri).isNull()
-        verify(contentResolver, times(1)).getType(any())
-    }
+            assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
+            assertThat(testSubject.uriCount).isEqualTo(1)
+            assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
+            assertThat(testSubject.firstFileInfo?.previewUri).isNull()
+            assertThat(testSubject.getFirstFileName()).isEqualTo(fileName)
+            verify(contentResolver, times(1)).getType(any())
+        }
 
     @Test
-    fun test_sendSingleImageWithFailingGetType_resolvesToFilePreviewUi() {
-        val uri = Uri.parse("content://org.pkg.app/image.png")
-        val targetIntent =
-            Intent(Intent.ACTION_SEND).apply {
-                type = "image/png"
-                putExtra(Intent.EXTRA_STREAM, uri)
-            }
-        whenever(contentResolver.getType(uri)).thenThrow(SecurityException("test failure"))
-        val testSubject = createDataProvider(targetIntent)
+    fun test_sendSingleImageWithFailingGetType_resolvesToFilePreviewUi() =
+        testScope.runTest {
+            val fileName = "image.png"
+            val uri = Uri.parse("content://org.pkg.app/$fileName")
+            val targetIntent =
+                Intent(Intent.ACTION_SEND).apply {
+                    type = "image/png"
+                    putExtra(Intent.EXTRA_STREAM, uri)
+                }
+            whenever(contentResolver.getType(uri)).thenThrow(SecurityException("test failure"))
+            val testSubject = createDataProvider(targetIntent)
 
-        assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
-        assertThat(testSubject.uriCount).isEqualTo(1)
-        assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
-        assertThat(testSubject.firstFileInfo?.previewUri).isNull()
-        verify(contentResolver, times(1)).getType(any())
-    }
+            assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
+            assertThat(testSubject.uriCount).isEqualTo(1)
+            assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
+            assertThat(testSubject.firstFileInfo?.previewUri).isNull()
+            assertThat(testSubject.getFirstFileName()).isEqualTo(fileName)
+            verify(contentResolver, times(1)).getType(any())
+        }
 
     @Test
-    fun test_sendSingleImageWithFailingMetadata_resolvesToFilePreviewUi() {
-        val uri = Uri.parse("content://org.pkg.app/image.png")
-        val targetIntent =
-            Intent(Intent.ACTION_SEND).apply {
-                type = "image/png"
-                putExtra(Intent.EXTRA_STREAM, uri)
-            }
-        whenever(contentResolver.getStreamTypes(uri, "*/*"))
-            .thenThrow(SecurityException("test failure"))
-        whenever(contentResolver.query(uri, METADATA_COLUMNS, null, null))
-            .thenThrow(SecurityException("test failure"))
-        val testSubject = createDataProvider(targetIntent)
+    fun test_sendSingleFileWithFailingMetadata_resolvesToFilePreviewUi() =
+        testScope.runTest {
+            val fileName = "manual.pdf"
+            val uri = Uri.parse("content://org.pkg.app/$fileName")
+            val targetIntent =
+                Intent(Intent.ACTION_SEND).apply {
+                    type = "application/pdf"
+                    putExtra(Intent.EXTRA_STREAM, uri)
+                }
+            whenever(contentResolver.getType(uri)).thenReturn("application/pdf")
+            whenever(contentResolver.getStreamTypes(uri, "*/*"))
+                .thenThrow(SecurityException("test failure"))
+            whenever(contentResolver.query(eq(uri), anyOrNull(), anyOrNull(), anyOrNull()))
+                .thenThrow(SecurityException("test failure"))
+            val testSubject = createDataProvider(targetIntent)
 
-        assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
-        assertThat(testSubject.uriCount).isEqualTo(1)
-        assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
-        assertThat(testSubject.firstFileInfo?.previewUri).isNull()
-        verify(contentResolver, times(1)).getType(any())
-    }
+            assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
+            assertThat(testSubject.uriCount).isEqualTo(1)
+            assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
+            assertThat(testSubject.firstFileInfo?.previewUri).isNull()
+            assertThat(testSubject.getFirstFileName()).isEqualTo(fileName)
+            verify(contentResolver, times(1)).getType(any())
+        }
+
+    @Test
+    @EnableFlags(FLAG_INDIVIDUAL_METADATA_TITLE_READ)
+    fun test_sendSingleImageWithFailingGetTypeDisjointTitleRead_resolvesToFilePreviewUi() =
+        testScope.runTest {
+            val uri = Uri.parse("content://org.pkg.app/image.png")
+            val targetIntent =
+                Intent(Intent.ACTION_SEND).apply {
+                    type = "image/png"
+                    putExtra(Intent.EXTRA_STREAM, uri)
+                }
+            whenever(contentResolver.getType(uri)).thenThrow(SecurityException("test failure"))
+            val title = "Image Title"
+            contentResolver.setTitle(uri, title)
+            val testSubject = createDataProvider(targetIntent)
+
+            assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
+            assertThat(testSubject.uriCount).isEqualTo(1)
+            assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
+            assertThat(testSubject.firstFileInfo?.previewUri).isNull()
+            assertThat(testSubject.getFirstFileName()).isEqualTo(title)
+            verify(contentResolver, times(1)).getType(any())
+        }
 
     @Test
-    fun test_SingleNonImageUriWithImageTypeInGetStreamTypes_useImagePreviewUi() {
+    fun test_sendSingleFileWithFailingImageMetadata_resolvesToFilePreviewUi() =
+        testScope.runTest {
+            val fileName = "notes.pdf"
+            val uri = Uri.parse("content://org.pkg.app/$fileName")
+            val targetIntent =
+                Intent(Intent.ACTION_SEND).apply {
+                    type = "application/pdf"
+                    putExtra(Intent.EXTRA_STREAM, uri)
+                }
+            whenever(contentResolver.getType(uri)).thenReturn("application/pdf")
+            whenever(contentResolver.getStreamTypes(uri, "*/*"))
+                .thenThrow(SecurityException("test failure"))
+            whenever(contentResolver.query(eq(uri), anyOrNull(), anyOrNull(), anyOrNull()))
+                .thenThrow(SecurityException("test failure"))
+            val testSubject = createDataProvider(targetIntent)
+
+            assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
+            assertThat(testSubject.uriCount).isEqualTo(1)
+            assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
+            assertThat(testSubject.firstFileInfo?.previewUri).isNull()
+            assertThat(testSubject.getFirstFileName()).isEqualTo(fileName)
+            verify(contentResolver, times(1)).getType(any())
+        }
+
+    @Test
+    @EnableFlags(FLAG_INDIVIDUAL_METADATA_TITLE_READ)
+    fun test_sendSingleFileWithFailingImageMetadataIndividualTitleRead_resolvesToFilePreviewUi() =
+        testScope.runTest {
+            val uri = Uri.parse("content://org.pkg.app/image.png")
+            val targetIntent =
+                Intent(Intent.ACTION_SEND).apply {
+                    type = "image/png"
+                    putExtra(Intent.EXTRA_STREAM, uri)
+                }
+            whenever(contentResolver.getStreamTypes(uri, "*/*"))
+                .thenThrow(SecurityException("test failure"))
+            whenever(contentResolver.query(uri, ICON_METADATA_COLUMNS, null, null))
+                .thenThrow(SecurityException("test failure"))
+            val displayName = "display name"
+            contentResolver.setDisplayName(uri, displayName)
+            val testSubject = createDataProvider(targetIntent)
+
+            assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
+            assertThat(testSubject.uriCount).isEqualTo(1)
+            assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
+            assertThat(testSubject.firstFileInfo?.previewUri).isNull()
+            assertThat(testSubject.getFirstFileName()).isEqualTo(displayName)
+            verify(contentResolver, times(1)).getType(any())
+        }
+
+    @Test
+    fun test_SingleFileUriWithImageTypeInGetStreamTypes_useImagePreviewUi() {
         val uri = Uri.parse("content://org.pkg.app/paper.pdf")
         val targetIntent = Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_STREAM, uri) }
         whenever(contentResolver.getStreamTypes(uri, "*/*"))
@@ -189,7 +303,7 @@ class PreviewDataProviderTest {
                 arrayOf(
                     DocumentsContract.Document.FLAG_SUPPORTS_THUMBNAIL or
                         DocumentsContract.Document.FLAG_SUPPORTS_METADATA
-                )
+                ),
         )
     }
 
@@ -206,7 +320,8 @@ class PreviewDataProviderTest {
         val targetIntent = Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_STREAM, uri) }
         whenever(contentResolver.getType(uri)).thenReturn("application/pdf")
         val cursor = MatrixCursor(columns).apply { addRow(values) }
-        whenever(contentResolver.query(uri, METADATA_COLUMNS, null, null)).thenReturn(cursor)
+        whenever(contentResolver.query(eq(uri), anyOrNull(), anyOrNull(), anyOrNull()))
+            .thenReturn(cursor)
 
         val testSubject = createDataProvider(targetIntent)
 
@@ -224,12 +339,13 @@ class PreviewDataProviderTest {
         val targetIntent = Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_STREAM, uri) }
         whenever(contentResolver.getType(uri)).thenReturn("application/pdf")
         val cursor = MatrixCursor(emptyArray())
-        whenever(contentResolver.query(uri, METADATA_COLUMNS, null, null)).thenReturn(cursor)
+        whenever(contentResolver.query(eq(uri), anyOrNull(), anyOrNull(), anyOrNull()))
+            .thenReturn(cursor)
 
         val testSubject = createDataProvider(targetIntent)
 
         assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
-        verify(contentResolver, times(1)).query(uri, METADATA_COLUMNS, null, null)
+        verify(contentResolver, times(1)).query(eq(uri), anyOrNull(), anyOrNull(), anyOrNull())
         assertThat(cursor.isClosed).isTrue()
     }
 
@@ -244,7 +360,7 @@ class PreviewDataProviderTest {
                     ArrayList<Uri>().apply {
                         add(uri1)
                         add(uri2)
-                    }
+                    },
                 )
             }
         whenever(contentResolver.getType(uri1)).thenReturn("image/png")
@@ -272,7 +388,7 @@ class PreviewDataProviderTest {
                     ArrayList<Uri>().apply {
                         add(uri1)
                         add(uri2)
-                    }
+                    },
                 )
             }
         val testSubject = createDataProvider(targetIntent)
@@ -286,7 +402,7 @@ class PreviewDataProviderTest {
     }
 
     @Test
-    fun test_someNonImageUriWithPreview_useImagePreviewUi() {
+    fun test_someFileUrisWithPreview_useImagePreviewUi() {
         val uri1 = Uri.parse("content://org.pkg.app/test.mp4")
         val uri2 = Uri.parse("content://org.pkg.app/test.pdf")
         val targetIntent =
@@ -296,7 +412,7 @@ class PreviewDataProviderTest {
                     ArrayList<Uri>().apply {
                         add(uri1)
                         add(uri2)
-                    }
+                    },
                 )
             }
         whenever(contentResolver.getType(uri1)).thenReturn("video/mpeg4")
@@ -312,29 +428,32 @@ class PreviewDataProviderTest {
     }
 
     @Test
-    fun test_allNonImageUrisWithoutPreview_useFilePreviewUi() {
-        val uri1 = Uri.parse("content://org.pkg.app/test.html")
-        val uri2 = Uri.parse("content://org.pkg.app/test.pdf")
-        val targetIntent =
-            Intent(Intent.ACTION_SEND_MULTIPLE).apply {
-                putExtra(
-                    Intent.EXTRA_STREAM,
-                    ArrayList<Uri>().apply {
-                        add(uri1)
-                        add(uri2)
-                    }
-                )
-            }
-        whenever(contentResolver.getType(uri1)).thenReturn("text/html")
-        whenever(contentResolver.getType(uri2)).thenReturn("application/pdf")
-        val testSubject = createDataProvider(targetIntent)
+    fun test_allFileUrisWithoutPreview_useFilePreviewUi() =
+        testScope.runTest {
+            val firstFileName = "test.html"
+            val uri1 = Uri.parse("content://org.pkg.app/$firstFileName")
+            val uri2 = Uri.parse("content://org.pkg.app/test.pdf")
+            val targetIntent =
+                Intent(Intent.ACTION_SEND_MULTIPLE).apply {
+                    putExtra(
+                        Intent.EXTRA_STREAM,
+                        ArrayList<Uri>().apply {
+                            add(uri1)
+                            add(uri2)
+                        },
+                    )
+                }
+            whenever(contentResolver.getType(uri1)).thenReturn("text/html")
+            whenever(contentResolver.getType(uri2)).thenReturn("application/pdf")
+            val testSubject = createDataProvider(targetIntent)
 
-        assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
-        assertThat(testSubject.uriCount).isEqualTo(2)
-        assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri1)
-        assertThat(testSubject.firstFileInfo?.previewUri).isNull()
-        verify(contentResolver, times(2)).getType(any())
-    }
+            assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_FILE)
+            assertThat(testSubject.uriCount).isEqualTo(2)
+            assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri1)
+            assertThat(testSubject.firstFileInfo?.previewUri).isNull()
+            assertThat(testSubject.getFirstFileName()).isEqualTo(firstFileName)
+            verify(contentResolver, times(2)).getType(any())
+        }
 
     @Test
     fun test_imagePreviewFileInfoFlow_dataLoadedOnce() =
@@ -348,7 +467,7 @@ class PreviewDataProviderTest {
                         ArrayList<Uri>().apply {
                             add(uri1)
                             add(uri2)
-                        }
+                        },
                     )
                 }
             whenever(contentResolver.getType(uri1)).thenReturn("text/html")
@@ -372,11 +491,10 @@ class PreviewDataProviderTest {
         }
 
     @Test
-    fun sendItemsWithAdditionalContentUri_showPayloadTogglingUi() {
+    fun sendImageWithAdditionalContentUri_showPayloadTogglingUi() {
         val uri = Uri.parse("content://org.pkg.app/image.png")
         val targetIntent = Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_STREAM, uri) }
         whenever(contentResolver.getType(uri)).thenReturn("image/png")
-        featureFlags.setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, true)
         val testSubject =
             createDataProvider(
                 targetIntent,
@@ -391,30 +509,11 @@ class PreviewDataProviderTest {
         verify(contentResolver, times(1)).getType(any())
     }
 
-    @Test
-    fun sendItemsWithAdditionalContentUri_showImagePreviewUi() {
-        val uri = Uri.parse("content://org.pkg.app/image.png")
-        val targetIntent = Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_STREAM, uri) }
-        whenever(contentResolver.getType(uri)).thenReturn("image/png")
-        val testSubject =
-            createDataProvider(
-                targetIntent,
-                additionalContentUri = Uri.parse("content://org.pkg.app.extracontent"),
-            )
-
-        assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_IMAGE)
-        assertThat(testSubject.uriCount).isEqualTo(1)
-        assertThat(testSubject.firstFileInfo?.uri).isEqualTo(uri)
-        assertThat(testSubject.firstFileInfo?.previewUri).isEqualTo(uri)
-        verify(contentResolver, times(1)).getType(any())
-    }
-
     @Test
     fun sendItemsWithAdditionalContentUriWithSameAuthority_showImagePreviewUi() {
         val uri = Uri.parse("content://org.pkg.app/image.png")
         val targetIntent = Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_STREAM, uri) }
         whenever(contentResolver.getType(uri)).thenReturn("image/png")
-        featureFlags.setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, true)
         val testSubject =
             createDataProvider(
                 targetIntent,
@@ -434,10 +533,28 @@ class PreviewDataProviderTest {
         val testSubject =
             createDataProvider(
                 targetIntent,
-                additionalContentUri = Uri.parse("content://org.pkg.app/extracontent")
+                additionalContentUri = Uri.parse("content://org.pkg.app/extracontent"),
             )
 
         assertThat(testSubject.previewType).isEqualTo(ContentPreviewType.CONTENT_PREVIEW_TEXT)
         verify(contentResolver, never()).getType(any())
     }
+
+    companion object {
+        @JvmStatic
+        @Parameterized.Parameters(name = "{0}")
+        fun parameters(): List<FlagsParameterization> =
+            FlagsParameterization.allCombinationsOf(FLAG_INDIVIDUAL_METADATA_TITLE_READ)
+    }
+}
+
+private fun ContentInterface.setDisplayName(uri: Uri, displayName: String) =
+    setMetadata(uri, arrayOf(OpenableColumns.DISPLAY_NAME), arrayOf(displayName))
+
+private fun ContentInterface.setTitle(uri: Uri, title: String) =
+    setMetadata(uri, arrayOf(Downloads.Impl.COLUMN_TITLE), arrayOf(title))
+
+private fun ContentInterface.setMetadata(uri: Uri, columns: Array<String>, values: Array<String>) {
+    whenever(query(uri, columns, null, null))
+        .thenReturn(MatrixCursor(columns).apply { addRow(values) })
 }
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractorTest.kt
index c4ba8105..5d29b4f3 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/CursorPreviewsInteractorTest.kt
@@ -34,6 +34,7 @@ import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.p
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.TargetIntentModifier
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.targetIntentModifier
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.CursorRow
+import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewKey
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.contentpreview.readSize
 import com.android.intentresolver.contentpreview.uriMetadataReader
@@ -51,10 +52,10 @@ import org.junit.Test
 class CursorPreviewsInteractorTest {
 
     private fun runTestWithDeps(
-        initialSelection: Iterable<Int> = (1..2),
-        focusedItemIndex: Int = initialSelection.count() / 2,
-        cursor: Iterable<Int> = (0 until 4),
-        cursorStartPosition: Int = cursor.count() / 2,
+        initialSelection: Iterable<Int>,
+        focusedItemIndex: Int,
+        cursor: Iterable<Int>,
+        cursorStartPosition: Int,
         pageSize: Int = 16,
         maxLoadedPages: Int = 3,
         cursorSizes: Map<Int, Size> = emptyMap(),
@@ -81,6 +82,7 @@ class CursorPreviewsInteractorTest {
                 block(
                     TestDeps(
                         initialSelection,
+                        focusedItemIndex,
                         cursor,
                         cursorStartPosition,
                         cursorSizes,
@@ -92,6 +94,7 @@ class CursorPreviewsInteractorTest {
 
     private class TestDeps(
         initialSelectionRange: Iterable<Int>,
+        focusedItemIndex: Int,
         private val cursorRange: Iterable<Int>,
         private val cursorStartPosition: Int,
         private val cursorSizes: Map<Int, Size>,
@@ -117,14 +120,26 @@ class CursorPreviewsInteractorTest {
                     }
                 }
         val initialPreviews: List<PreviewModel> =
-            initialSelectionRange.map { i ->
-                PreviewModel(uri = uri(i), mimeType = "image/bitmap", order = i)
+            initialSelectionRange.mapIndexed { index, i ->
+                PreviewModel(
+                    key =
+                        if (index == focusedItemIndex) {
+                            PreviewKey.final(0)
+                        } else {
+                            PreviewKey.temp(index)
+                        },
+                    uri = uri(i),
+                    mimeType = "image/bitmap",
+                    order = i,
+                )
             }
     }
 
     @Test
     fun initialCursorLoad() =
         runTestWithDeps(
+            initialSelection = (1..2),
+            focusedItemIndex = 1,
             cursor = (0 until 10),
             cursorStartPosition = 2,
             cursorSizes = mapOf(0 to (200 x 100)),
@@ -143,6 +158,7 @@ class CursorPreviewsInteractorTest {
                     .containsExactlyElementsIn(
                         List(6) {
                             PreviewModel(
+                                key = PreviewKey.final((it - 2)),
                                 uri = Uri.fromParts("scheme$it", "ssp$it", "fragment$it"),
                                 mimeType = "image/bitmap",
                                 aspectRatio =
@@ -156,7 +172,7 @@ class CursorPreviewsInteractorTest {
                         }
                     )
                     .inOrder()
-                assertThat(startIdx).isEqualTo(0)
+                assertThat(startIdx).isEqualTo(2)
                 assertThat(loadMoreLeft).isNull()
                 assertThat(loadMoreRight).isNotNull()
                 assertThat(leftTriggerIndex).isEqualTo(2)
@@ -168,7 +184,9 @@ class CursorPreviewsInteractorTest {
     fun loadMoreLeft_evictRight() =
         runTestWithDeps(
             initialSelection = listOf(24),
+            focusedItemIndex = 0,
             cursor = (0 until 48),
+            cursorStartPosition = 24,
             pageSize = 16,
             maxLoadedPages = 1,
         ) { deps ->
@@ -201,7 +219,9 @@ class CursorPreviewsInteractorTest {
     fun loadMoreRight_evictLeft() =
         runTestWithDeps(
             initialSelection = listOf(24),
+            focusedItemIndex = 0,
             cursor = (0 until 48),
+            cursorStartPosition = 24,
             pageSize = 16,
             maxLoadedPages = 1,
         ) { deps ->
@@ -233,7 +253,9 @@ class CursorPreviewsInteractorTest {
     fun noMoreRight_appendUnclaimedFromInitialSelection() =
         runTestWithDeps(
             initialSelection = listOf(24, 50),
+            focusedItemIndex = 0,
             cursor = listOf(24),
+            cursorStartPosition = 0,
             pageSize = 16,
             maxLoadedPages = 2,
         ) { deps ->
@@ -255,7 +277,9 @@ class CursorPreviewsInteractorTest {
     fun noMoreLeft_appendUnclaimedFromInitialSelection() =
         runTestWithDeps(
             initialSelection = listOf(0, 24),
+            focusedItemIndex = 1,
             cursor = listOf(24),
+            cursorStartPosition = 0,
             pageSize = 16,
             maxLoadedPages = 2,
         ) { deps ->
@@ -283,6 +307,7 @@ class CursorPreviewsInteractorTest {
         ) { deps ->
             previewSelectionsRepository.selections.value =
                 PreviewModel(
+                        key = PreviewKey.final(0),
                         uri = uri(1),
                         mimeType = "image/png",
                         order = 0,
@@ -296,6 +321,7 @@ class CursorPreviewsInteractorTest {
             assertThat(previewSelectionsRepository.selections.value.values)
                 .containsExactly(
                     PreviewModel(
+                        key = PreviewKey.final(0),
                         uri = uri(1),
                         mimeType = "image/bitmap",
                         order = 1,
@@ -307,6 +333,7 @@ class CursorPreviewsInteractorTest {
     fun testReadFailedPages() =
         runTestWithDeps(
             initialSelection = listOf(4),
+            focusedItemIndex = 0,
             cursor = emptyList(),
             cursorStartPosition = 0,
             pageSize = 2,
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/FetchPreviewsInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/FetchPreviewsInteractorTest.kt
index 27c98dc0..0a56a2d0 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/FetchPreviewsInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/FetchPreviewsInteractorTest.kt
@@ -30,6 +30,7 @@ import com.android.intentresolver.contentpreview.payloadtoggle.domain.cursor.pay
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.TargetIntentModifier
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.targetIntentModifier
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.CursorRow
+import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewKey
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewsModel
 import com.android.intentresolver.contentpreview.uriMetadataReader
@@ -50,10 +51,10 @@ import org.junit.Test
 class FetchPreviewsInteractorTest {
 
     private fun runTest(
-        initialSelection: Iterable<Int> = (1..2),
-        focusedItemIndex: Int = initialSelection.count() / 2,
-        cursor: Iterable<Int> = (0 until 4),
-        cursorStartPosition: Int = cursor.count() / 2,
+        initialSelection: Iterable<Int>,
+        focusedItemIndex: Int,
+        cursor: Iterable<Int>,
+        cursorStartPosition: Int,
         pageSize: Int = 16,
         maxLoadedPages: Int = 8,
         previewSizes: Map<Int, Size> = emptyMap(),
@@ -110,7 +111,11 @@ class FetchPreviewsInteractorTest {
     fun setsInitialPreviews() =
         runTest(
             initialSelection = (1..3),
-            previewSizes = mapOf(1 to Size(100, 50))) {
+            focusedItemIndex = 1,
+            cursor = (0 until 4),
+            cursorStartPosition = 1,
+            previewSizes = mapOf(1 to Size(100, 50)),
+        ) {
             backgroundScope.launch { fetchPreviewsInteractor.activate() }
             runCurrent()
 
@@ -120,17 +125,20 @@ class FetchPreviewsInteractorTest {
                         previewModels =
                             listOf(
                                 PreviewModel(
+                                    key = PreviewKey.temp(0),
                                     uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
                                     mimeType = "image/bitmap",
                                     aspectRatio = 2f,
                                     order = Int.MIN_VALUE,
                                 ),
                                 PreviewModel(
+                                    key = PreviewKey.final(0),
                                     uri = Uri.fromParts("scheme2", "ssp2", "fragment2"),
                                     mimeType = "image/bitmap",
                                     order = 0,
                                 ),
                                 PreviewModel(
+                                    key = PreviewKey.temp(2),
                                     uri = Uri.fromParts("scheme3", "ssp3", "fragment3"),
                                     mimeType = "image/bitmap",
                                     order = Int.MAX_VALUE,
@@ -146,48 +154,60 @@ class FetchPreviewsInteractorTest {
         }
 
     @Test
-    fun lookupCursorFromContentResolver() = runTest {
-        backgroundScope.launch { fetchPreviewsInteractor.activate() }
-        fakeCursorResolver.complete()
-        runCurrent()
+    fun lookupCursorFromContentResolver() =
+        runTest(
+            initialSelection = (1..2),
+            focusedItemIndex = 1,
+            cursor = (0 until 4),
+            cursorStartPosition = 2,
+        ) {
+            backgroundScope.launch { fetchPreviewsInteractor.activate() }
+            fakeCursorResolver.complete()
+            runCurrent()
 
-        with(cursorPreviewsRepository) {
-            assertThat(previewsModel.value).isNotNull()
-            assertThat(previewsModel.value!!.startIdx).isEqualTo(0)
-            assertThat(previewsModel.value!!.loadMoreLeft).isNull()
-            assertThat(previewsModel.value!!.loadMoreRight).isNull()
-            assertThat(previewsModel.value!!.previewModels)
-                .containsExactly(
-                    PreviewModel(
-                        uri = Uri.fromParts("scheme0", "ssp0", "fragment0"),
-                        mimeType = "image/bitmap",
-                        order = 0,
-                    ),
-                    PreviewModel(
-                        uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
-                        mimeType = "image/bitmap",
-                        order = 1,
-                    ),
-                    PreviewModel(
-                        uri = Uri.fromParts("scheme2", "ssp2", "fragment2"),
-                        mimeType = "image/bitmap",
-                        order = 2,
-                    ),
-                    PreviewModel(
-                        uri = Uri.fromParts("scheme3", "ssp3", "fragment3"),
-                        mimeType = "image/bitmap",
-                        order = 3,
-                    ),
-                )
-                .inOrder()
+            with(cursorPreviewsRepository) {
+                assertThat(previewsModel.value).isNotNull()
+                assertThat(previewsModel.value!!.startIdx).isEqualTo(2)
+                assertThat(previewsModel.value!!.loadMoreLeft).isNull()
+                assertThat(previewsModel.value!!.loadMoreRight).isNull()
+                assertThat(previewsModel.value!!.previewModels)
+                    .containsExactly(
+                        PreviewModel(
+                            key = PreviewKey.final(-2),
+                            uri = Uri.fromParts("scheme0", "ssp0", "fragment0"),
+                            mimeType = "image/bitmap",
+                            order = 0,
+                        ),
+                        PreviewModel(
+                            key = PreviewKey.final(-1),
+                            uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
+                            mimeType = "image/bitmap",
+                            order = 1,
+                        ),
+                        PreviewModel(
+                            key = PreviewKey.final(0),
+                            uri = Uri.fromParts("scheme2", "ssp2", "fragment2"),
+                            mimeType = "image/bitmap",
+                            order = 2,
+                        ),
+                        PreviewModel(
+                            key = PreviewKey.final(1),
+                            uri = Uri.fromParts("scheme3", "ssp3", "fragment3"),
+                            mimeType = "image/bitmap",
+                            order = 3,
+                        ),
+                    )
+                    .inOrder()
+            }
         }
-    }
 
     @Test
     fun loadMoreLeft_evictRight() =
         runTest(
             initialSelection = listOf(24),
+            focusedItemIndex = 0,
             cursor = (0 until 48),
+            cursorStartPosition = 24,
             pageSize = 16,
             maxLoadedPages = 1,
         ) {
@@ -223,7 +243,9 @@ class FetchPreviewsInteractorTest {
     fun loadMoreRight_evictLeft() =
         runTest(
             initialSelection = listOf(24),
+            focusedItemIndex = 0,
             cursor = (0 until 48),
+            cursorStartPosition = 24,
             pageSize = 16,
             maxLoadedPages = 1,
         ) {
@@ -254,7 +276,9 @@ class FetchPreviewsInteractorTest {
     fun noMoreRight_appendUnclaimedFromInitialSelection() =
         runTest(
             initialSelection = listOf(24, 50),
+            focusedItemIndex = 0,
             cursor = listOf(24),
+            cursorStartPosition = 0,
             pageSize = 16,
             maxLoadedPages = 2,
         ) {
@@ -275,7 +299,9 @@ class FetchPreviewsInteractorTest {
     fun noMoreLeft_appendUnclaimedFromInitialSelection() =
         runTest(
             initialSelection = listOf(0, 24),
+            focusedItemIndex = 1,
             cursor = listOf(24),
+            cursorStartPosition = 0,
             pageSize = 16,
             maxLoadedPages = 2,
         ) {
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractorTest.kt
index 5d9ddbb6..0268a4d5 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewInteractorTest.kt
@@ -24,6 +24,7 @@ import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.p
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.previewSelectionsRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.TargetIntentModifier
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.targetIntentModifier
+import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewKey
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.data.repository.chooserRequestRepository
 import com.android.intentresolver.logging.FakeEventLog
@@ -44,6 +45,7 @@ class SelectablePreviewInteractorTest {
             SelectablePreviewInteractor(
                 key =
                     PreviewModel(
+                        key = PreviewKey.final(1),
                         uri = Uri.fromParts("scheme", "ssp", "fragment"),
                         mimeType = null,
                         order = 0,
@@ -63,6 +65,7 @@ class SelectablePreviewInteractorTest {
             SelectablePreviewInteractor(
                 key =
                     PreviewModel(
+                        key = PreviewKey.final(1),
                         uri = Uri.fromParts("scheme", "ssp", "fragment"),
                         mimeType = "image/bitmap",
                         order = 0,
@@ -75,6 +78,7 @@ class SelectablePreviewInteractorTest {
 
         previewSelectionsRepository.selections.value =
             PreviewModel(
+                    key = PreviewKey.final(1),
                     uri = Uri.fromParts("scheme", "ssp", "fragment"),
                     mimeType = "image/bitmap",
                     order = 0,
@@ -93,6 +97,7 @@ class SelectablePreviewInteractorTest {
             SelectablePreviewInteractor(
                 key =
                     PreviewModel(
+                        key = PreviewKey.final(1),
                         uri = Uri.fromParts("scheme", "ssp", "fragment"),
                         mimeType = "image/bitmap",
                         order = 0,
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewsInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewsInteractorTest.kt
index c50d2d3f..c90a3091 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewsInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectablePreviewsInteractorTest.kt
@@ -23,6 +23,7 @@ import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.c
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.previewSelectionsRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.TargetIntentModifier
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.intent.targetIntentModifier
+import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewKey
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewsModel
 import com.android.intentresolver.util.runKosmosTest
@@ -41,11 +42,13 @@ class SelectablePreviewsInteractorTest {
                 previewModels =
                     listOf(
                         PreviewModel(
+                            key = PreviewKey.final(1),
                             uri = Uri.fromParts("scheme", "ssp", "fragment"),
                             mimeType = "image/bitmap",
                             order = 0,
                         ),
                         PreviewModel(
+                            key = PreviewKey.final(2),
                             uri = Uri.fromParts("scheme2", "ssp2", "fragment2"),
                             mimeType = "image/bitmap",
                             order = 1,
@@ -59,6 +62,7 @@ class SelectablePreviewsInteractorTest {
             )
         previewSelectionsRepository.selections.value =
             PreviewModel(
+                    key = PreviewKey.final(1),
                     uri = Uri.fromParts("scheme", "ssp", "fragment"),
                     mimeType = null,
                     order = 0,
@@ -72,11 +76,13 @@ class SelectablePreviewsInteractorTest {
         assertThat(keySet.value!!.previewModels)
             .containsExactly(
                 PreviewModel(
+                    key = PreviewKey.final(1),
                     uri = Uri.fromParts("scheme", "ssp", "fragment"),
                     mimeType = "image/bitmap",
                     order = 0,
                 ),
                 PreviewModel(
+                    key = PreviewKey.final(2),
                     uri = Uri.fromParts("scheme2", "ssp2", "fragment2"),
                     mimeType = "image/bitmap",
                     order = 1,
@@ -90,6 +96,7 @@ class SelectablePreviewsInteractorTest {
         val firstModel =
             underTest.preview(
                 PreviewModel(
+                    key = PreviewKey.final(1),
                     uri = Uri.fromParts("scheme", "ssp", "fragment"),
                     mimeType = null,
                     order = 0,
@@ -100,6 +107,7 @@ class SelectablePreviewsInteractorTest {
         val secondModel =
             underTest.preview(
                 PreviewModel(
+                    key = PreviewKey.final(2),
                     uri = Uri.fromParts("scheme2", "ssp2", "fragment2"),
                     mimeType = null,
                     order = 1,
@@ -112,6 +120,7 @@ class SelectablePreviewsInteractorTest {
     fun keySet_reflectsRepositoryUpdate() = runKosmosTest {
         previewSelectionsRepository.selections.value =
             PreviewModel(
+                    key = PreviewKey.final(1),
                     uri = Uri.fromParts("scheme", "ssp", "fragment"),
                     mimeType = null,
                     order = 0,
@@ -124,6 +133,7 @@ class SelectablePreviewsInteractorTest {
         val firstModel =
             underTest.preview(
                 PreviewModel(
+                    key = PreviewKey.final(1),
                     uri = Uri.fromParts("scheme", "ssp", "fragment"),
                     mimeType = null,
                     order = 0,
@@ -140,11 +150,13 @@ class SelectablePreviewsInteractorTest {
                 previewModels =
                     listOf(
                         PreviewModel(
+                            key = PreviewKey.final(1),
                             uri = Uri.fromParts("scheme", "ssp", "fragment"),
                             mimeType = "image/bitmap",
                             order = 0,
                         ),
                         PreviewModel(
+                            key = PreviewKey.final(2),
                             uri = Uri.fromParts("scheme2", "ssp2", "fragment2"),
                             mimeType = "image/bitmap",
                             order = 1,
@@ -163,11 +175,13 @@ class SelectablePreviewsInteractorTest {
         assertThat(previews.value!!.previewModels)
             .containsExactly(
                 PreviewModel(
+                    key = PreviewKey.final(1),
                     uri = Uri.fromParts("scheme", "ssp", "fragment"),
                     mimeType = "image/bitmap",
                     order = 0,
                 ),
                 PreviewModel(
+                    key = PreviewKey.final(2),
                     uri = Uri.fromParts("scheme2", "ssp2", "fragment2"),
                     mimeType = "image/bitmap",
                     order = 1,
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt
index c8242333..c24138b8 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SelectionInteractorTest.kt
@@ -24,6 +24,7 @@ import android.platform.test.flag.junit.SetFlagsRule
 import com.android.intentresolver.Flags
 import com.android.intentresolver.contentpreview.mimetypeClassifier
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.previewSelectionsRepository
+import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewKey
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.util.runKosmosTest
 import com.google.common.truth.Truth.assertThat
@@ -39,9 +40,10 @@ class SelectionInteractorTest {
     fun singleSelection_removalPrevented() = runKosmosTest {
         val initialPreview =
             PreviewModel(
+                key = PreviewKey.final(1),
                 uri = Uri.fromParts("scheme", "ssp", "fragment"),
                 mimeType = null,
-                order = 0
+                order = 0,
             )
         previewSelectionsRepository.selections.value = mapOf(initialPreview.uri to initialPreview)
 
@@ -66,9 +68,10 @@ class SelectionInteractorTest {
     fun singleSelection_itemRemovedNoPendingIntentUpdates() = runKosmosTest {
         val initialPreview =
             PreviewModel(
+                key = PreviewKey.final(1),
                 uri = Uri.fromParts("scheme", "ssp", "fragment"),
                 mimeType = null,
-                order = 0
+                order = 0,
             )
         previewSelectionsRepository.selections.value = mapOf(initialPreview.uri to initialPreview)
 
@@ -92,15 +95,17 @@ class SelectionInteractorTest {
     fun multipleSelections_removalAllowed() = runKosmosTest {
         val first =
             PreviewModel(
+                key = PreviewKey.final(1),
                 uri = Uri.fromParts("scheme", "ssp", "fragment"),
                 mimeType = null,
-                order = 0
+                order = 0,
             )
         val second =
             PreviewModel(
+                key = PreviewKey.final(2),
                 uri = Uri.fromParts("scheme2", "ssp2", "fragment2"),
                 mimeType = null,
-                order = 1
+                order = 1,
             )
         previewSelectionsRepository.selections.value = listOf(first, second).associateBy { it.uri }
 
@@ -109,7 +114,7 @@ class SelectionInteractorTest {
                 previewSelectionsRepository,
                 { Intent() },
                 updateTargetIntentInteractor,
-                mimetypeClassifier
+                mimetypeClassifier,
             )
 
         underTest.unselect(first)
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SetCursorPreviewsInteractorTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SetCursorPreviewsInteractorTest.kt
index 748459cb..42f1a1b2 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SetCursorPreviewsInteractorTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/domain/interactor/SetCursorPreviewsInteractorTest.kt
@@ -21,6 +21,7 @@ package com.android.intentresolver.contentpreview.payloadtoggle.domain.interacto
 import android.net.Uri
 import com.android.intentresolver.contentpreview.payloadtoggle.data.repository.cursorPreviewsRepository
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.LoadDirection
+import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewKey
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.util.runKosmosTest
 import com.google.common.truth.Truth.assertThat
@@ -37,6 +38,7 @@ class SetCursorPreviewsInteractorTest {
                 previews =
                     listOf(
                         PreviewModel(
+                            key = PreviewKey.final(1),
                             uri = Uri.fromParts("scheme", "ssp", "fragment"),
                             mimeType = null,
                             order = 0,
@@ -59,9 +61,10 @@ class SetCursorPreviewsInteractorTest {
             assertThat(it.previewModels)
                 .containsExactly(
                     PreviewModel(
+                        key = PreviewKey.final(1),
                         uri = Uri.fromParts("scheme", "ssp", "fragment"),
                         mimeType = null,
-                        order = 0
+                        order = 0,
                     )
                 )
                 .inOrder()
@@ -76,6 +79,7 @@ class SetCursorPreviewsInteractorTest {
                     previews =
                         listOf(
                             PreviewModel(
+                                key = PreviewKey.final(1),
                                 uri = Uri.fromParts("scheme", "ssp", "fragment"),
                                 mimeType = null,
                                 order = 0,
diff --git a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt
index fc7ac751..6dd96040 100644
--- a/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt
+++ b/tests/unit/src/com/android/intentresolver/contentpreview/payloadtoggle/ui/viewmodel/ShareouselViewModelTest.kt
@@ -42,6 +42,7 @@ import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.interactor.selectionInteractor
 import com.android.intentresolver.contentpreview.payloadtoggle.domain.model.ValueUpdate
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.ContentType
+import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewKey
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewModel
 import com.android.intentresolver.contentpreview.payloadtoggle.shared.model.PreviewsModel
 import com.android.intentresolver.data.model.ChooserRequest
@@ -84,15 +85,17 @@ class ShareouselViewModelTest {
         previewSelectionsRepository.selections.value =
             listOf(
                     PreviewModel(
+                        key = PreviewKey.final(0),
                         uri = Uri.fromParts("scheme", "ssp", "fragment"),
                         mimeType = "image/png",
                         order = 0,
                     ),
                     PreviewModel(
+                        key = PreviewKey.final(1),
                         uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
                         mimeType = "image/jpeg",
                         order = 1,
-                    )
+                    ),
                 )
                 .associateBy { it.uri }
         runCurrent()
@@ -104,15 +107,17 @@ class ShareouselViewModelTest {
         previewSelectionsRepository.selections.value =
             listOf(
                     PreviewModel(
+                        key = PreviewKey.final(0),
                         uri = Uri.fromParts("scheme", "ssp", "fragment"),
                         mimeType = "video/mpeg",
                         order = 0,
                     ),
                     PreviewModel(
+                        key = PreviewKey.final(1),
                         uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
                         mimeType = "video/mpeg",
                         order = 1,
-                    )
+                    ),
                 )
                 .associateBy { it.uri }
         runCurrent()
@@ -124,15 +129,17 @@ class ShareouselViewModelTest {
         previewSelectionsRepository.selections.value =
             listOf(
                     PreviewModel(
+                        key = PreviewKey.final(0),
                         uri = Uri.fromParts("scheme", "ssp", "fragment"),
                         mimeType = "image/jpeg",
                         order = 0,
                     ),
                     PreviewModel(
+                        key = PreviewKey.final(1),
                         uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
                         mimeType = "video/mpeg",
                         order = 1,
-                    )
+                    ),
                 )
                 .associateBy { it.uri }
         runCurrent()
@@ -145,7 +152,7 @@ class ShareouselViewModelTest {
             ChooserRequest(
                 targetIntent = Intent(),
                 launchedFromPackage = "",
-                metadataText = "Hello"
+                metadataText = "Hello",
             )
         chooserRequestRepository.chooserRequest.value = request
 
@@ -162,15 +169,17 @@ class ShareouselViewModelTest {
                     previewModels =
                         listOf(
                             PreviewModel(
+                                key = PreviewKey.final(0),
                                 uri = Uri.fromParts("scheme", "ssp", "fragment"),
                                 mimeType = "image/png",
                                 order = 0,
                             ),
                             PreviewModel(
+                                key = PreviewKey.final(1),
                                 uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
                                 mimeType = "video/mpeg",
                                 order = 1,
-                            )
+                            ),
                         ),
                     startIdx = 1,
                     loadMoreLeft = null,
@@ -194,6 +203,7 @@ class ShareouselViewModelTest {
             val previewVm =
                 shareouselViewModel.preview.invoke(
                     PreviewModel(
+                        key = PreviewKey.final(1),
                         uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
                         mimeType = "video/mpeg",
                         order = 0,
@@ -225,15 +235,17 @@ class ShareouselViewModelTest {
                     previewModels =
                         listOf(
                             PreviewModel(
+                                key = PreviewKey.final(0),
                                 uri = Uri.fromParts("scheme", "ssp", "fragment"),
                                 mimeType = "image/png",
                                 order = 0,
                             ),
                             PreviewModel(
+                                key = PreviewKey.final(1),
                                 uri = Uri.fromParts("scheme1", "ssp1", "fragment1"),
                                 mimeType = "video/mpeg",
                                 order = 1,
-                            )
+                            ),
                         ),
                     startIdx = 1,
                     loadMoreLeft = null,
@@ -246,6 +258,7 @@ class ShareouselViewModelTest {
             val previewVm =
                 shareouselViewModel.preview.invoke(
                     PreviewModel(
+                        key = PreviewKey.final(0),
                         uri = Uri.fromParts("scheme", "ssp", "fragment"),
                         mimeType = "video/mpeg",
                         order = 1,
@@ -314,6 +327,7 @@ class ShareouselViewModelTest {
         this.targetIntentModifier = targetIntentModifier
         previewSelectionsRepository.selections.value =
             PreviewModel(
+                    key = PreviewKey.final(1),
                     uri = Uri.fromParts("scheme", "ssp", "fragment"),
                     mimeType = null,
                     order = 0,
diff --git a/tests/unit/src/com/android/intentresolver/ext/CreationExtrasExtTest.kt b/tests/unit/src/com/android/intentresolver/ext/CreationExtrasExtTest.kt
index c09047a1..dbaee3d0 100644
--- a/tests/unit/src/com/android/intentresolver/ext/CreationExtrasExtTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ext/CreationExtrasExtTest.kt
@@ -51,4 +51,19 @@ class CreationExtrasExtTest {
         assertThat(defaultArgs).parcelable<Point>("POINT1").marshallsEquallyTo(Point(1, 1))
         assertThat(defaultArgs).parcelable<Point>("POINT2").marshallsEquallyTo(Point(2, 2))
     }
+
+    @Test
+    fun replaceDefaultArgs_replacesExisting() {
+        val creationExtras: CreationExtras =
+            MutableCreationExtras().apply {
+                set(DEFAULT_ARGS_KEY, bundleOf("POINT1" to Point(1, 1)))
+            }
+
+        val updated = creationExtras.replaceDefaultArgs("POINT2" to Point(2, 2))
+
+        val defaultArgs = updated[DEFAULT_ARGS_KEY]
+        assertThat(defaultArgs).doesNotContainKey("POINT1")
+        assertThat(defaultArgs).containsKey("POINT2")
+        assertThat(defaultArgs).parcelable<Point>("POINT2").marshallsEquallyTo(Point(2, 2))
+    }
 }
diff --git a/tests/unit/src/com/android/intentresolver/icons/CachingTargetDataLoaderTest.kt b/tests/unit/src/com/android/intentresolver/icons/CachingTargetDataLoaderTest.kt
index a36b512b..2f0ed423 100644
--- a/tests/unit/src/com/android/intentresolver/icons/CachingTargetDataLoaderTest.kt
+++ b/tests/unit/src/com/android/intentresolver/icons/CachingTargetDataLoaderTest.kt
@@ -21,11 +21,16 @@ import android.content.Context
 import android.content.Intent
 import android.content.pm.ShortcutInfo
 import android.graphics.Bitmap
+import android.graphics.Color
 import android.graphics.drawable.BitmapDrawable
+import android.graphics.drawable.ColorDrawable
 import android.graphics.drawable.Drawable
 import android.graphics.drawable.Icon
 import android.os.UserHandle
+import com.android.intentresolver.ResolverDataProvider.createResolveInfo
+import com.android.intentresolver.chooser.DisplayResolveInfo
 import com.android.intentresolver.chooser.SelectableTargetInfo
+import com.android.intentresolver.chooser.TargetInfo
 import java.util.function.Consumer
 import org.junit.Test
 import org.mockito.kotlin.any
@@ -37,6 +42,7 @@ import org.mockito.kotlin.verify
 import org.mockito.kotlin.whenever
 
 class CachingTargetDataLoaderTest {
+    private val context = mock<Context>()
     private val userHandle = UserHandle.of(1)
 
     @Test
@@ -61,7 +67,7 @@ class CachingTargetDataLoaderTest {
                 on { getOrLoadDirectShareIcon(eq(callerTarget), eq(userHandle), any()) } doReturn
                     null
             }
-        val testSubject = CachingTargetDataLoader(targetDataLoader)
+        val testSubject = CachingTargetDataLoader(context, targetDataLoader)
         val callback = Consumer<Drawable> {}
 
         testSubject.getOrLoadDirectShareIcon(callerTarget, userHandle, callback)
@@ -102,7 +108,7 @@ class CachingTargetDataLoaderTest {
             }
             .whenever(targetDataLoader)
             .getOrLoadDirectShareIcon(eq(targetInfo), eq(userHandle), any())
-        val testSubject = CachingTargetDataLoader(targetDataLoader)
+        val testSubject = CachingTargetDataLoader(context, targetDataLoader)
         val callback = Consumer<Drawable> {}
 
         testSubject.getOrLoadDirectShareIcon(targetInfo, userHandle, callback)
@@ -112,6 +118,70 @@ class CachingTargetDataLoaderTest {
             1 * { getOrLoadDirectShareIcon(eq(targetInfo), eq(userHandle), any()) }
         }
     }
+
+    @Test
+    fun onlyBitmapsAreCached() {
+        val context =
+            mock<Context> {
+                on { userId } doReturn 1
+                on { packageName } doReturn "package"
+            }
+        val colorTargetInfo =
+            DisplayResolveInfo.newDisplayResolveInfo(
+                Intent(),
+                createResolveInfo(1, userHandle.identifier),
+                Intent(),
+            ) as DisplayResolveInfo
+        val bitmapTargetInfo =
+            DisplayResolveInfo.newDisplayResolveInfo(
+                Intent(),
+                createResolveInfo(2, userHandle.identifier),
+                Intent(),
+            ) as DisplayResolveInfo
+        val hoverBitmapTargetInfo =
+            DisplayResolveInfo.newDisplayResolveInfo(
+                Intent(),
+                createResolveInfo(3, userHandle.identifier),
+                Intent(),
+            ) as DisplayResolveInfo
+
+        val targetDataLoader = mock<TargetDataLoader>()
+        doAnswer {
+                val target = it.arguments[0] as TargetInfo
+                val callback = it.arguments[2] as Consumer<Drawable>
+                val drawable =
+                    if (target === bitmapTargetInfo) {
+                        BitmapDrawable(createBitmap())
+                    } else if (target === hoverBitmapTargetInfo) {
+                        HoverBitmapDrawable(createBitmap())
+                    } else {
+                        ColorDrawable(Color.RED)
+                    }
+                callback.accept(drawable)
+                null
+            }
+            .whenever(targetDataLoader)
+            .getOrLoadAppTargetIcon(any(), eq(userHandle), any())
+        val testSubject = CachingTargetDataLoader(context, targetDataLoader)
+        val callback = Consumer<Drawable> {}
+
+        testSubject.getOrLoadAppTargetIcon(colorTargetInfo, userHandle, callback)
+        testSubject.getOrLoadAppTargetIcon(colorTargetInfo, userHandle, callback)
+        testSubject.getOrLoadAppTargetIcon(bitmapTargetInfo, userHandle, callback)
+        testSubject.getOrLoadAppTargetIcon(bitmapTargetInfo, userHandle, callback)
+        testSubject.getOrLoadAppTargetIcon(hoverBitmapTargetInfo, userHandle, callback)
+        testSubject.getOrLoadAppTargetIcon(hoverBitmapTargetInfo, userHandle, callback)
+
+        verify(targetDataLoader) {
+            2 * { getOrLoadAppTargetIcon(eq(colorTargetInfo), eq(userHandle), any()) }
+        }
+        verify(targetDataLoader) {
+            1 * { getOrLoadAppTargetIcon(eq(bitmapTargetInfo), eq(userHandle), any()) }
+        }
+        verify(targetDataLoader) {
+            1 * { getOrLoadAppTargetIcon(eq(hoverBitmapTargetInfo), eq(userHandle), any()) }
+        }
+    }
 }
 
 private fun createBitmap() = Bitmap.createBitmap(100, 100, Bitmap.Config.ARGB_8888)
diff --git a/tests/unit/src/com/android/intentresolver/platform/NearbyShareModuleTest.kt b/tests/unit/src/com/android/intentresolver/platform/NearbyShareModuleTest.kt
index 6e5c97c2..a4bcad38 100644
--- a/tests/unit/src/com/android/intentresolver/platform/NearbyShareModuleTest.kt
+++ b/tests/unit/src/com/android/intentresolver/platform/NearbyShareModuleTest.kt
@@ -23,7 +23,7 @@ import android.provider.Settings
 import android.testing.TestableResources
 import androidx.test.platform.app.InstrumentationRegistry
 import com.android.intentresolver.R
-import com.google.common.truth.Truth8.assertThat
+import com.google.common.truth.Truth.assertThat
 import org.junit.Before
 import org.junit.Test
 
@@ -34,7 +34,7 @@ class NearbyShareModuleTest {
     /** Create Resources with overridden values. */
     private fun Context.fakeResources(
         config: Configuration? = null,
-        block: TestableResources.() -> Unit
+        block: TestableResources.() -> Unit,
     ) =
         TestableResources(resources)
             .apply { config?.let { overrideConfiguration(it) } }
@@ -64,7 +64,7 @@ class NearbyShareModuleTest {
             context.fakeResources {
                 addOverride(
                     R.string.config_defaultNearbySharingComponent,
-                    "com.example/.ComponentName"
+                    "com.example/.ComponentName",
                 )
             }
 
@@ -83,7 +83,7 @@ class NearbyShareModuleTest {
             context.fakeResources {
                 addOverride(
                     R.string.config_defaultNearbySharingComponent,
-                    "com.example/.AComponent"
+                    "com.example/.AComponent",
                 )
             }
 
diff --git a/tests/unit/src/com/android/intentresolver/ui/ShareResultSenderImplTest.kt b/tests/unit/src/com/android/intentresolver/ui/ShareResultSenderImplTest.kt
index 7b43360a..d8b1b175 100644
--- a/tests/unit/src/com/android/intentresolver/ui/ShareResultSenderImplTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ui/ShareResultSenderImplTest.kt
@@ -22,9 +22,7 @@ import android.content.ComponentName
 import android.content.Intent
 import android.os.Process
 import android.service.chooser.ChooserResult
-import android.service.chooser.Flags
 import androidx.test.platform.app.InstrumentationRegistry
-import com.android.intentresolver.inject.FakeChooserServiceFlags
 import com.android.intentresolver.ui.model.ShareAction
 import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.Truth.assertWithMessage
@@ -46,8 +44,6 @@ class ShareResultSenderImplTest {
 
     @get:Rule val compatChangeRule: TestRule = PlatformCompatChangeRule()
 
-    val flags = FakeChooserServiceFlags()
-
     @OptIn(ExperimentalCoroutinesApi::class)
     @EnableCompatChanges(ChooserResult.SEND_CHOOSER_RESULT)
     @Test
@@ -56,11 +52,8 @@ class ShareResultSenderImplTest {
         val deferred = CompletableDeferred<Intent>()
         val intentDispatcher = IntentSenderDispatcher { _, intent -> deferred.complete(intent) }
 
-        flags.setFlag(Flags.FLAG_ENABLE_CHOOSER_RESULT, true)
-
         val resultSender =
             ShareResultSenderImpl(
-                flags = flags,
                 scope = this,
                 backgroundDispatcher = UnconfinedTestDispatcher(testScheduler),
                 callerUid = Process.myUid(),
@@ -91,11 +84,8 @@ class ShareResultSenderImplTest {
         val deferred = CompletableDeferred<Intent>()
         val intentDispatcher = IntentSenderDispatcher { _, intent -> deferred.complete(intent) }
 
-        flags.setFlag(Flags.FLAG_ENABLE_CHOOSER_RESULT, true)
-
         val resultSender =
             ShareResultSenderImpl(
-                flags = flags,
                 scope = this,
                 backgroundDispatcher = UnconfinedTestDispatcher(testScheduler),
                 callerUid = Process.myUid(),
@@ -127,11 +117,8 @@ class ShareResultSenderImplTest {
         val deferred = CompletableDeferred<Intent>()
         val intentDispatcher = IntentSenderDispatcher { _, intent -> deferred.complete(intent) }
 
-        flags.setFlag(Flags.FLAG_ENABLE_CHOOSER_RESULT, true)
-
         val resultSender =
             ShareResultSenderImpl(
-                flags = flags,
                 scope = this,
                 backgroundDispatcher = UnconfinedTestDispatcher(testScheduler),
                 callerUid = Process.myUid(),
@@ -165,11 +152,8 @@ class ShareResultSenderImplTest {
         val deferred = CompletableDeferred<Intent>()
         val intentDispatcher = IntentSenderDispatcher { _, intent -> deferred.complete(intent) }
 
-        flags.setFlag(Flags.FLAG_ENABLE_CHOOSER_RESULT, true)
-
         val resultSender =
             ShareResultSenderImpl(
-                flags = flags,
                 scope = this,
                 backgroundDispatcher = UnconfinedTestDispatcher(testScheduler),
                 callerUid = Process.myUid(),
@@ -192,11 +176,8 @@ class ShareResultSenderImplTest {
         val deferred = CompletableDeferred<Intent>()
         val intentDispatcher = IntentSenderDispatcher { _, intent -> deferred.complete(intent) }
 
-        flags.setFlag(Flags.FLAG_ENABLE_CHOOSER_RESULT, true)
-
         val resultSender =
             ShareResultSenderImpl(
-                flags = flags,
                 scope = this,
                 backgroundDispatcher = UnconfinedTestDispatcher(testScheduler),
                 callerUid = Process.myUid(),
@@ -233,11 +214,8 @@ class ShareResultSenderImplTest {
         val deferred = CompletableDeferred<Intent>()
         val intentDispatcher = IntentSenderDispatcher { _, intent -> deferred.complete(intent) }
 
-        flags.setFlag(Flags.FLAG_ENABLE_CHOOSER_RESULT, true)
-
         val resultSender =
             ShareResultSenderImpl(
-                flags = flags,
                 scope = this,
                 backgroundDispatcher = UnconfinedTestDispatcher(testScheduler),
                 callerUid = Process.myUid(),
diff --git a/tests/unit/src/com/android/intentresolver/ui/model/ActivityModelTest.kt b/tests/unit/src/com/android/intentresolver/ui/model/ActivityModelTest.kt
index 737f02fe..5f86159c 100644
--- a/tests/unit/src/com/android/intentresolver/ui/model/ActivityModelTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ui/model/ActivityModelTest.kt
@@ -21,6 +21,7 @@ import android.content.Intent.ACTION_CHOOSER
 import android.content.Intent.EXTRA_TEXT
 import android.net.Uri
 import com.android.intentresolver.ext.toParcelAndBack
+import com.android.intentresolver.shared.model.ActivityModel
 import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.Truth.assertWithMessage
 import org.junit.Test
@@ -54,7 +55,7 @@ class ActivityModelTest {
                 intent = Intent(),
                 launchedFromUid = 1000,
                 launchedFromPackage = "other.example.com",
-                referrer = Uri.parse("android-app://app.example.com")
+                referrer = Uri.parse("android-app://app.example.com"),
             )
 
         assertThat(launch1.referrerPackage).isEqualTo("app.example.com")
@@ -67,7 +68,7 @@ class ActivityModelTest {
                 intent = Intent(),
                 launchedFromUid = 1000,
                 launchedFromPackage = "example.com",
-                referrer = Uri.parse("http://some.other.value")
+                referrer = Uri.parse("http://some.other.value"),
             )
 
         assertThat(launch.referrerPackage).isNull()
@@ -80,7 +81,7 @@ class ActivityModelTest {
                 intent = Intent(),
                 launchedFromUid = 1000,
                 launchedFromPackage = "example.com",
-                referrer = null
+                referrer = null,
             )
 
         assertThat(launch.referrerPackage).isNull()
diff --git a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
index 01904c7f..71f28950 100644
--- a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ChooserRequestTest.kt
@@ -28,13 +28,11 @@ import android.content.Intent.EXTRA_REFERRER
 import android.content.Intent.EXTRA_TEXT
 import android.content.Intent.EXTRA_TITLE
 import android.net.Uri
-import android.service.chooser.Flags
 import androidx.core.net.toUri
 import androidx.core.os.bundleOf
 import com.android.intentresolver.ContentTypeHint
 import com.android.intentresolver.data.model.ChooserRequest
-import com.android.intentresolver.inject.FakeChooserServiceFlags
-import com.android.intentresolver.ui.model.ActivityModel
+import com.android.intentresolver.shared.model.ActivityModel
 import com.android.intentresolver.validation.Importance
 import com.android.intentresolver.validation.Invalid
 import com.android.intentresolver.validation.NoValue
@@ -45,7 +43,7 @@ import org.junit.Test
 private fun createActivityModel(
     targetIntent: Intent?,
     referrer: Uri? = null,
-    additionalIntents: List<Intent>? = null
+    additionalIntents: List<Intent>? = null,
 ) =
     ActivityModel(
         Intent(ACTION_CHOOSER).apply {
@@ -54,18 +52,15 @@ private fun createActivityModel(
         },
         launchedFromUid = 10000,
         launchedFromPackage = "com.android.example",
-        referrer = referrer ?: "android-app://com.android.example".toUri()
+        referrer = referrer ?: "android-app://com.android.example".toUri(),
     )
 
 class ChooserRequestTest {
 
-    private val fakeChooserServiceFlags =
-        FakeChooserServiceFlags().apply { setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, false) }
-
     @Test
     fun missingIntent() {
         val model = createActivityModel(targetIntent = null)
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Invalid::class.java)
         result as Invalid<ChooserRequest>
@@ -80,7 +75,7 @@ class ChooserRequestTest {
         val model = createActivityModel(targetIntent = Intent(ACTION_SEND), referrer)
         model.intent.putExtras(bundleOf(EXTRA_REFERRER to referrer))
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -97,7 +92,7 @@ class ChooserRequestTest {
 
         val model = createActivityModel(targetIntent = intent, referrer = referrer)
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -112,7 +107,7 @@ class ChooserRequestTest {
 
         model.intent.putExtras(bundleOf(EXTRA_REFERRER to referrer))
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -126,7 +121,7 @@ class ChooserRequestTest {
         val intent2 = Intent(ACTION_SEND_MULTIPLE)
         val model = createActivityModel(targetIntent = intent1, additionalIntents = listOf(intent2))
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -139,7 +134,7 @@ class ChooserRequestTest {
         val intent = Intent().putExtras(bundleOf(EXTRA_INTENT to Intent(ACTION_SEND)))
         val model = createActivityModel(targetIntent = intent)
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -149,7 +144,6 @@ class ChooserRequestTest {
 
     @Test
     fun testRequest_actionSendWithAdditionalContentUri() {
-        fakeChooserServiceFlags.setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, true)
         val uri = Uri.parse("content://org.pkg/path")
         val position = 10
         val model =
@@ -158,7 +152,7 @@ class ChooserRequestTest {
                 intent.putExtra(EXTRA_CHOOSER_FOCUSED_ITEM_POSITION, position)
             }
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -167,36 +161,15 @@ class ChooserRequestTest {
         assertThat(result.value.focusedItemPosition).isEqualTo(position)
     }
 
-    @Test
-    fun testRequest_actionSendWithAdditionalContentUri_parametersIgnoredWhenFlagDisabled() {
-        fakeChooserServiceFlags.setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, false)
-        val uri = Uri.parse("content://org.pkg/path")
-        val position = 10
-        val model =
-            createActivityModel(targetIntent = Intent(ACTION_SEND)).apply {
-                intent.putExtra(EXTRA_CHOOSER_ADDITIONAL_CONTENT_URI, uri)
-                intent.putExtra(EXTRA_CHOOSER_FOCUSED_ITEM_POSITION, position)
-            }
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
-
-        assertThat(result).isInstanceOf(Valid::class.java)
-        result as Valid<ChooserRequest>
-
-        assertThat(result.value.additionalContentUri).isNull()
-        assertThat(result.value.focusedItemPosition).isEqualTo(0)
-        assertThat(result.warnings).isEmpty()
-    }
-
     @Test
     fun testRequest_actionSendWithInvalidAdditionalContentUri() {
-        fakeChooserServiceFlags.setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, true)
         val model =
             createActivityModel(targetIntent = Intent(ACTION_SEND)).apply {
                 intent.putExtra(EXTRA_CHOOSER_ADDITIONAL_CONTENT_URI, "__invalid__")
                 intent.putExtra(EXTRA_CHOOSER_FOCUSED_ITEM_POSITION, "__invalid__")
             }
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -207,10 +180,9 @@ class ChooserRequestTest {
 
     @Test
     fun testRequest_actionSendWithoutAdditionalContentUri() {
-        fakeChooserServiceFlags.setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, true)
         val model = createActivityModel(targetIntent = Intent(ACTION_SEND))
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -221,7 +193,6 @@ class ChooserRequestTest {
 
     @Test
     fun testRequest_actionViewWithAdditionalContentUri() {
-        fakeChooserServiceFlags.setFlag(Flags.FLAG_CHOOSER_PAYLOAD_TOGGLING, true)
         val uri = Uri.parse("content://org.pkg/path")
         val position = 10
         val model =
@@ -230,7 +201,7 @@ class ChooserRequestTest {
                 intent.putExtra(EXTRA_CHOOSER_FOCUSED_ITEM_POSITION, position)
             }
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -245,10 +216,10 @@ class ChooserRequestTest {
         val model = createActivityModel(Intent(ACTION_SEND))
         model.intent.putExtra(
             Intent.EXTRA_CHOOSER_CONTENT_TYPE_HINT,
-            Intent.CHOOSER_CONTENT_TYPE_ALBUM
+            Intent.CHOOSER_CONTENT_TYPE_ALBUM,
         )
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -266,7 +237,7 @@ class ChooserRequestTest {
                 intent.putExtra(Intent.EXTRA_METADATA_TEXT, metadataText)
             }
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         result as Valid<ChooserRequest>
@@ -285,7 +256,7 @@ class ChooserRequestTest {
             }
         val model = createActivityModel(targetIntent)
 
-        val result = readChooserRequest(model, fakeChooserServiceFlags)
+        val result = readChooserRequest(model)
 
         assertThat(result).isInstanceOf(Valid::class.java)
         (result as Valid<ChooserRequest>).value.let { request ->
diff --git a/tests/unit/src/com/android/intentresolver/ui/viewmodel/IntentExtTest.kt b/tests/unit/src/com/android/intentresolver/ui/viewmodel/IntentExtTest.kt
new file mode 100644
index 00000000..8fc162ca
--- /dev/null
+++ b/tests/unit/src/com/android/intentresolver/ui/viewmodel/IntentExtTest.kt
@@ -0,0 +1,174 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.intentresolver.ui.viewmodel
+
+import android.content.Intent
+import android.content.Intent.ACTION_SEND
+import android.content.Intent.EXTRA_STREAM
+import android.net.Uri
+import com.google.common.truth.Truth.assertThat
+import org.junit.Test
+
+class IntentExtTest {
+
+    @Test
+    fun noActionOrUris() {
+        val intent = Intent()
+
+        assertThat(intent.createIntentFilter()).isNull()
+    }
+
+    @Test
+    fun uriInData() {
+        val intent = Intent(ACTION_SEND)
+        intent.setDataAndType(
+            Uri.Builder().scheme("scheme1").encodedAuthority("auth1").path("path1").build(),
+            "image/png",
+        )
+
+        val filter = intent.createIntentFilter()
+
+        assertThat(filter).isNotNull()
+        assertThat(filter!!.dataTypes()[0]).isEqualTo("image/png")
+        assertThat(filter.actionsIterator().next()).isEqualTo(ACTION_SEND)
+        assertThat(filter.schemesIterator().next()).isEqualTo("scheme1")
+        assertThat(filter.authoritiesIterator().next().host).isEqualTo("auth1")
+        assertThat(filter.getDataPath(0).path).isEqualTo("/path1")
+    }
+
+    @Test
+    fun noAction() {
+        val intent = Intent()
+        intent.setDataAndType(
+            Uri.Builder().scheme("scheme1").encodedAuthority("auth1").path("path1").build(),
+            "image/png",
+        )
+
+        val filter = intent.createIntentFilter()
+
+        assertThat(filter).isNotNull()
+        assertThat(filter!!.dataTypes()[0]).isEqualTo("image/png")
+        assertThat(filter.countActions()).isEqualTo(0)
+        assertThat(filter.schemesIterator().next()).isEqualTo("scheme1")
+        assertThat(filter.authoritiesIterator().next().host).isEqualTo("auth1")
+        assertThat(filter.getDataPath(0).path).isEqualTo("/path1")
+    }
+
+    @Test
+    fun singleUriInExtraStream() {
+        val intent = Intent(ACTION_SEND)
+        intent.type = "image/png"
+        intent.putExtra(
+            EXTRA_STREAM,
+            Uri.Builder().scheme("scheme1").encodedAuthority("auth1").path("path1").build(),
+        )
+
+        val filter = intent.createIntentFilter()
+
+        assertThat(filter).isNotNull()
+        assertThat(filter!!.dataTypes()[0]).isEqualTo("image/png")
+        assertThat(filter.actionsIterator().next()).isEqualTo(ACTION_SEND)
+        assertThat(filter.schemesIterator().next()).isEqualTo("scheme1")
+        assertThat(filter.authoritiesIterator().next().host).isEqualTo("auth1")
+        assertThat(filter.getDataPath(0).path).isEqualTo("/path1")
+    }
+
+    @Test
+    fun uriInDataAndStream() {
+        val intent = Intent(ACTION_SEND)
+        intent.setDataAndType(
+            Uri.Builder().scheme("scheme1").encodedAuthority("auth1").path("path1").build(),
+            "image/png",
+        )
+
+        intent.putExtra(
+            EXTRA_STREAM,
+            Uri.Builder().scheme("scheme2").encodedAuthority("auth2").path("path2").build(),
+        )
+        val filter = intent.createIntentFilter()
+
+        assertThat(filter).isNotNull()
+        assertThat(filter!!.dataTypes()[0]).isEqualTo("image/png")
+        assertThat(filter.actionsIterator().next()).isEqualTo(ACTION_SEND)
+        assertThat(filter.getDataScheme(0)).isEqualTo("scheme1")
+        assertThat(filter.getDataScheme(1)).isEqualTo("scheme2")
+        assertThat(filter.getDataAuthority(0).host).isEqualTo("auth1")
+        assertThat(filter.getDataAuthority(1).host).isEqualTo("auth2")
+        assertThat(filter.getDataPath(0).path).isEqualTo("/path1")
+        assertThat(filter.getDataPath(1).path).isEqualTo("/path2")
+    }
+
+    @Test
+    fun multipleUris() {
+        val intent = Intent(ACTION_SEND)
+        intent.type = "image/png"
+        val uris =
+            arrayListOf(
+                Uri.Builder().scheme("scheme1").encodedAuthority("auth1").path("path1").build(),
+                Uri.Builder().scheme("scheme2").encodedAuthority("auth2").path("path2").build(),
+            )
+        intent.putExtra(EXTRA_STREAM, uris)
+
+        val filter = intent.createIntentFilter()
+
+        assertThat(filter).isNotNull()
+        assertThat(filter!!.dataTypes()[0]).isEqualTo("image/png")
+        assertThat(filter.actionsIterator().next()).isEqualTo(ACTION_SEND)
+        assertThat(filter.getDataScheme(0)).isEqualTo("scheme1")
+        assertThat(filter.getDataScheme(1)).isEqualTo("scheme2")
+        assertThat(filter.getDataAuthority(0).host).isEqualTo("auth1")
+        assertThat(filter.getDataAuthority(1).host).isEqualTo("auth2")
+        assertThat(filter.getDataPath(0).path).isEqualTo("/path1")
+        assertThat(filter.getDataPath(1).path).isEqualTo("/path2")
+    }
+
+    @Test
+    fun multipleUrisWithNullValues() {
+        val intent = Intent(ACTION_SEND)
+        intent.type = "image/png"
+        val uris =
+            arrayListOf(
+                null,
+                Uri.Builder().scheme("scheme1").encodedAuthority("auth1").path("path1").build(),
+                null,
+            )
+        intent.putExtra(EXTRA_STREAM, uris)
+
+        val filter = intent.createIntentFilter()
+
+        assertThat(filter).isNotNull()
+        assertThat(filter!!.dataTypes()[0]).isEqualTo("image/png")
+        assertThat(filter.actionsIterator().next()).isEqualTo(ACTION_SEND)
+        assertThat(filter.getDataScheme(0)).isEqualTo("scheme1")
+        assertThat(filter.getDataAuthority(0).host).isEqualTo("auth1")
+        assertThat(filter.getDataPath(0).path).isEqualTo("/path1")
+    }
+
+    @Test
+    fun badMimeType() {
+        val intent = Intent(ACTION_SEND)
+        intent.type = "badType"
+        intent.putExtra(
+            EXTRA_STREAM,
+            Uri.Builder().scheme("scheme1").encodedAuthority("authority1").path("path1").build(),
+        )
+
+        val filter = intent.createIntentFilter()
+
+        assertThat(filter).isNotNull()
+        assertThat(filter!!.countDataTypes()).isEqualTo(0)
+    }
+}
diff --git a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ResolverRequestTest.kt b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ResolverRequestTest.kt
index bd80235d..70512021 100644
--- a/tests/unit/src/com/android/intentresolver/ui/viewmodel/ResolverRequestTest.kt
+++ b/tests/unit/src/com/android/intentresolver/ui/viewmodel/ResolverRequestTest.kt
@@ -22,8 +22,8 @@ import android.os.UserHandle
 import androidx.core.net.toUri
 import androidx.core.os.bundleOf
 import com.android.intentresolver.ResolverActivity.PROFILE_WORK
+import com.android.intentresolver.shared.model.ActivityModel
 import com.android.intentresolver.shared.model.Profile.Type.WORK
-import com.android.intentresolver.ui.model.ActivityModel
 import com.android.intentresolver.ui.model.ResolverRequest
 import com.android.intentresolver.validation.Invalid
 import com.android.intentresolver.validation.UncaughtException
@@ -34,15 +34,12 @@ import org.junit.Test
 
 private val targetUri = Uri.parse("content://example.com/123")
 
-private fun createActivityModel(
-    targetIntent: Intent,
-    referrer: Uri? = null,
-) =
+private fun createActivityModel(targetIntent: Intent, referrer: Uri? = null) =
     ActivityModel(
         intent = targetIntent,
         launchedFromUid = 10000,
         launchedFromPackage = "com.android.example",
-        referrer = referrer ?: "android-app://com.android.example".toUri()
+        referrer = referrer ?: "android-app://com.android.example".toUri(),
     )
 
 class ResolverRequestTest {
```

