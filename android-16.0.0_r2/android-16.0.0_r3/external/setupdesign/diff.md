```diff
diff --git a/lottie_animation_view/Android.bp b/lottie_animation_view/Android.bp
new file mode 100644
index 0000000..26de191
--- /dev/null
+++ b/lottie_animation_view/Android.bp
@@ -0,0 +1,29 @@
+//
+// Build the setup design - lottie_animation_view.
+//
+
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "external_setupdesign_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["external_setupdesign_license"],
+}
+
+android_library {
+    name: "setupdesign-lottie-animation-view",
+    manifest: "AndroidManifest.xml",
+    static_libs: [
+        "androidx.annotation_annotation",
+        "lottie",
+        "setupcompat",
+        "setupdesign",
+        "setupdesign-strings",
+    ],
+    srcs: [
+        "src/**/*.kt",
+    ],
+    min_sdk_version: "16",
+    sdk_version: "current",
+}
diff --git a/lottie_animation_view/AndroidManifest.xml b/lottie_animation_view/AndroidManifest.xml
index 1b0b77e..789bcd1 100644
--- a/lottie_animation_view/AndroidManifest.xml
+++ b/lottie_animation_view/AndroidManifest.xml
@@ -16,7 +16,7 @@
 -->
 
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.google.android.setupdesign.lottieloadinglayout">
+    package="com.google.android.setupdesign.lottieanimationview">
 
   <uses-sdk
       android:minSdkVersion="23"
diff --git a/lottie_animation_view/src/com/google/android/setupdesign/view/SudLottieAnimationView.kt b/lottie_animation_view/src/com/google/android/setupdesign/view/SudLottieAnimationView.kt
index 78d676c..0c7fe2b 100644
--- a/lottie_animation_view/src/com/google/android/setupdesign/view/SudLottieAnimationView.kt
+++ b/lottie_animation_view/src/com/google/android/setupdesign/view/SudLottieAnimationView.kt
@@ -28,6 +28,7 @@ import androidx.core.view.accessibility.AccessibilityNodeInfoCompat
 import androidx.core.view.accessibility.AccessibilityNodeInfoCompat.AccessibilityActionCompat
 import com.airbnb.lottie.LottieAnimationView
 import com.google.android.setupcompat.util.Logger
+import com.google.android.setupdesign.strings.R;
 
 /** A [LottieAnimationView] that take response to pause and resume animation when user clicks. */
 class SudLottieAnimationView
diff --git a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_card.xml b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_card.xml
index cd50138..4288af3 100644
--- a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_card.xml
+++ b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_card.xml
@@ -17,7 +17,8 @@
 
 <!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
      See https://developer.android.com/privacy-and-security/risks/tapjacking -->
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+<com.google.android.setupdesign.view.InsetAdjustmentLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
@@ -50,4 +51,4 @@
         android:layout_weight="1"
         android:visibility="invisible" />
 
-</LinearLayout>
+</com.google.android.setupdesign.view.InsetAdjustmentLayout>
diff --git a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_card.xml b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_card.xml
index 9b14ca1..35f37c9 100644
--- a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_card.xml
+++ b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_card.xml
@@ -17,7 +17,8 @@
 
 <!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
      See https://developer.android.com/privacy-and-security/risks/tapjacking -->
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+<com.google.android.setupdesign.view.InsetAdjustmentLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
@@ -50,4 +51,4 @@
         android:layout_weight="1"
         android:visibility="invisible" />
 
-</LinearLayout>
+</com.google.android.setupdesign.view.InsetAdjustmentLayout>
diff --git a/lottie_loading_layout/res/values-w600dp-h840dp-v35/layouts.xml b/lottie_loading_layout/res/values-w600dp-h840dp-v35/layouts.xml
new file mode 100644
index 0000000..8cbd3b9
--- /dev/null
+++ b/lottie_loading_layout/res/values-w600dp-h840dp-v35/layouts.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<resources xmlns:tools="http://schemas.android.com/tools">
+  <item name="sud_glif_expressive_loading_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_expressive_loading_template_card</item>
+  <item name="sud_glif_expressive_loading_embedded_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_loading_embedded_template_card</item>
+  <item name="sud_glif_expressive_fullscreen_loading_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_expressive_fullscreen_loading_template_card</item>
+  <item name="sud_glif_expressive_fullscreen_loading_embedded_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_fullscreen_loading_embedded_template_card</item>
+</resources>
diff --git a/lottie_loading_layout/res/values-w600dp-h900dp-v35/layouts.xml b/lottie_loading_layout/res/values-w600dp-h900dp-v35/layouts.xml
index a084fcd..6c81184 100644
--- a/lottie_loading_layout/res/values-w600dp-h900dp-v35/layouts.xml
+++ b/lottie_loading_layout/res/values-w600dp-h900dp-v35/layouts.xml
@@ -20,4 +20,6 @@
   <item name="sud_glif_expressive_loading_embedded_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_loading_embedded_template_card</item>
   <item name="sud_glif_expressive_fullscreen_loading_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_expressive_fullscreen_loading_template_card</item>
   <item name="sud_glif_expressive_fullscreen_loading_embedded_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_fullscreen_loading_embedded_template_card</item>
+  <item name="sud_glif_expressive_loading_template_content_layout" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_expressive_loading_template_content</item>
+  <item name="sud_glif_expressive_fullscreen_loading_template_content_layout" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_expressive_fullscreen_loading_template_content</item>
 </resources>
diff --git a/lottie_loading_layout/res/values-w840dp-h900dp-v35/layouts.xml b/lottie_loading_layout/res/values-w840dp-h900dp-v35/layouts.xml
new file mode 100644
index 0000000..e4a2c5f
--- /dev/null
+++ b/lottie_loading_layout/res/values-w840dp-h900dp-v35/layouts.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<resources xmlns:tools="http://schemas.android.com/tools">
+  <item name="sud_glif_expressive_loading_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_expressive_loading_template_compat</item>
+  <item name="sud_glif_expressive_loading_embedded_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_loading_embedded_template_compat</item>
+  <item name="sud_glif_expressive_fullscreen_loading_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_expressive_loading_template_compat</item>
+  <item name="sud_glif_expressive_fullscreen_loading_embedded_template" type="layout"  tools:ignore="UnusedResources">@layout/sud_glif_loading_embedded_template_compat</item>
+  <item name="sud_glif_expressive_loading_template_content_layout" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_expressive_loading_template_content_wide</item>
+  <item name="sud_glif_expressive_fullscreen_loading_template_content_layout" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_expressive_fullscreen_loading_template_content_wide</item>
+</resources>
\ No newline at end of file
diff --git a/main/res/color/sud_back_button_ripple_color.xml b/main/res/color/sud_back_button_ripple_color.xml
new file mode 100644
index 0000000..bf51bcd
--- /dev/null
+++ b/main/res/color/sud_back_button_ripple_color.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="utf-8"?>
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+  <item android:state_pressed="true" android:alpha="0.1" android:color="?attr/colorOnSurface"/>
+  <item android:state_focused="true" android:alpha="0.1" android:color="?attr/colorOnSurface"/>
+  <item android:state_hovered="true" android:alpha="0.1" android:color="?attr/colorOnSurface"/>
+  <item android:alpha="0.1" android:color="?attr/colorOnSurface"/>
+</selector>
diff --git a/main/res/drawable/sud_ic_down_arrow.xml b/main/res/drawable/sud_ic_down_arrow.xml
index 0a4a0a3..800e76e 100644
--- a/main/res/drawable/sud_ic_down_arrow.xml
+++ b/main/res/drawable/sud_ic_down_arrow.xml
@@ -17,9 +17,9 @@
 <vector xmlns:android="http://schemas.android.com/apk/res/android"
     android:width="24dp"
     android:height="24dp"
-    android:viewportWidth="24"
-    android:viewportHeight="24">
+    android:viewportWidth="960"
+    android:viewportHeight="960">
   <path
       android:fillColor="@android:color/black"
-      android:pathData="M19,15l-1.41,-1.41L13,18.17V2H11v16.17l-4.59,-4.59L5,15l7,7L19,15z"/>
+      android:pathData="M440,160L440,647L216,423L160,480L480,800L800,480L744,423L520,647L520,160L440,160Z"/>
 </vector>
diff --git a/main/res/drawable/sud_ic_switch_check_mark_expressive.xml b/main/res/drawable/sud_ic_switch_check_mark_expressive.xml
new file mode 100644
index 0000000..07e68bb
--- /dev/null
+++ b/main/res/drawable/sud_ic_switch_check_mark_expressive.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+        http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="16dp"
+    android:height="16dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960">
+  <path
+      android:pathData="M389,693 L195,500l51,-52 143,143 325,-324 51,51 -376,375Z"
+      android:fillColor="?attr/colorPrimary"/>
+</vector>
diff --git a/main/res/drawable/sud_ic_switch_selector_expressive.xml b/main/res/drawable/sud_ic_switch_selector_expressive.xml
new file mode 100644
index 0000000..30d972f
--- /dev/null
+++ b/main/res/drawable/sud_ic_switch_selector_expressive.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2025 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+  -->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:drawable="@drawable/sud_ic_switch_check_mark_expressive" android:state_checked="true" />
+</selector>
\ No newline at end of file
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_card.xml b/main/res/layout-v35/sud_glif_expressive_list_template_card.xml
index a78047f..5c88087 100644
--- a/main/res/layout-v35/sud_glif_expressive_list_template_card.xml
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_card.xml
@@ -25,6 +25,8 @@
     android:fitsSystemWindows="true"
     android:gravity="center_horizontal"
     android:filterTouchesWhenObscured="true"
+    android:clipChildren="?attr/sudClipChildren"
+    android:clipToPadding="?attr/sudClipToPadding"
     android:orientation="vertical">
 
     <View
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_compact.xml b/main/res/layout-v35/sud_glif_expressive_list_template_compact.xml
index 197144b..aca55bc 100644
--- a/main/res/layout-v35/sud_glif_expressive_list_template_compact.xml
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_compact.xml
@@ -22,6 +22,8 @@
     android:id="@+id/suc_layout_status"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
+    android:clipChildren="?attr/sudClipChildren"
+    android:clipToPadding="?attr/sudClipToPadding"
     android:filterTouchesWhenObscured="true">
 
     <include layout="@layout/sud_glif_expressive_list_template_content_layout" />
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_content.xml b/main/res/layout-v35/sud_glif_expressive_list_template_content.xml
index c65b9ba..d4e053e 100644
--- a/main/res/layout-v35/sud_glif_expressive_list_template_content.xml
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_content.xml
@@ -24,7 +24,9 @@
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:filterTouchesWhenObscured="true"
-    android:orientation="vertical">
+    android:orientation="vertical"
+    android:clipChildren="?attr/sudClipChildren"
+    android:clipToPadding="?attr/sudClipToPadding">
 
     <ViewStub
         android:id="@+id/sud_layout_sticky_header"
@@ -35,6 +37,8 @@
         android:id="@+id/sud_layout_container"
         android:layout_width="match_parent"
         android:layout_height="0dp"
+        android:clipChildren="?attr/sudClipChildren"
+        android:clipToPadding="?attr/sudClipToPadding"
         android:layout_weight="1">
 
         <!-- Ignore UnusedAttribute: scrollIndicators is new in M. Default to no indicators in older
@@ -45,6 +49,8 @@
             android:layout_width="match_parent"
             android:layout_height="match_parent"
             android:scrollIndicators="?attr/sudScrollIndicators"
+            android:clipChildren="?attr/sudClipChildren"
+            android:clipToPadding="?attr/sudClipToPadding"
             app:sudHeader="@layout/sud_glif_header"
             app:sudShouldApplyAdditionalMargin="true"
             tools:ignore="UnusedAttribute" />
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml b/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml
index 410462a..a0b0616 100644
--- a/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml
@@ -23,13 +23,17 @@
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:filterTouchesWhenObscured="true"
-    android:orientation="vertical">
+    android:orientation="vertical"
+    android:clipChildren="?attr/sudClipChildren"
+    android:clipToPadding="?attr/sudClipToPadding">
 
     <FrameLayout
         android:id="@+id/sud_layout_container"
         android:layout_width="match_parent"
         android:layout_height="0dp"
-        android:layout_weight="1">
+        android:layout_weight="1"
+        android:clipChildren="?attr/sudClipChildren"
+        android:clipToPadding="?attr/sudClipToPadding">
 
         <LinearLayout
         android:layout_width="match_parent"
@@ -74,6 +78,8 @@
                 android:layout_height="0dp"
                 android:layout_weight="1"
                 app:sudShouldApplyAdditionalMargin="true"
+                android:clipChildren="?attr/sudClipChildren"
+                android:clipToPadding="?attr/sudClipToPadding"
                 android:scrollIndicators="?attr/sudScrollIndicators" />
 
         </LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml
index ccc6800..6b35a3c 100644
--- a/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml
@@ -25,6 +25,8 @@
     android:fitsSystemWindows="true"
     android:gravity="center_horizontal"
     android:filterTouchesWhenObscured="true"
+    android:clipChildren="?attr/sudClipChildren"
+    android:clipToPadding="?attr/sudClipToPadding"
     android:orientation="vertical">
 
     <View
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_compact.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_compact.xml
index c20aa6a..db12aff 100644
--- a/main/res/layout-v35/sud_glif_expressive_recycler_template_compact.xml
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_compact.xml
@@ -22,6 +22,8 @@
     android:id="@+id/suc_layout_status"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
+    android:clipChildren="?attr/sudClipChildren"
+    android:clipToPadding="?attr/sudClipToPadding"
     android:filterTouchesWhenObscured="true">
 
     <include layout="@layout/sud_glif_expressive_recycler_template_content_layout" />
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml
index 5a8efa1..071b68d 100644
--- a/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml
@@ -25,6 +25,8 @@
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:filterTouchesWhenObscured="true"
+    android:clipChildren="?attr/sudClipChildren"
+    android:clipToPadding="?attr/sudClipToPadding"
     android:orientation="vertical">
 
     <ViewStub
@@ -36,6 +38,8 @@
         android:id="@+id/sud_layout_container"
         android:layout_width="match_parent"
         android:layout_height="0dp"
+        android:clipChildren="?attr/sudClipChildren"
+        android:clipToPadding="?attr/sudClipToPadding"
         android:layout_weight="1">
 
         <!-- Ignore UnusedAttribute: scrollIndicators is new in M. Default to no indicators in older
@@ -46,6 +50,8 @@
             android:layout_height="match_parent"
             android:scrollbars="vertical"
             android:scrollIndicators="?attr/sudScrollIndicators"
+            android:clipChildren="?attr/sudClipChildren"
+            android:clipToPadding="?attr/sudClipToPadding"
             app:sudHeader="@layout/sud_glif_header"
             app:sudShouldApplyAdditionalMargin="true"
             tools:ignore="UnusedAttribute" />
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml
index b5116bc..f2346ba 100644
--- a/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml
@@ -24,12 +24,16 @@
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:filterTouchesWhenObscured="true"
+    android:clipChildren="?attr/sudClipChildren"
+    android:clipToPadding="?attr/sudClipToPadding"
     android:orientation="vertical">
 
     <FrameLayout
         android:id="@+id/sud_layout_container"
         android:layout_width="match_parent"
         android:layout_height="0dp"
+        android:clipChildren="?attr/sudClipChildren"
+        android:clipToPadding="?attr/sudClipToPadding"
         android:layout_weight="1">
 
         <LinearLayout
@@ -73,6 +77,8 @@
                 android:layout_width="match_parent"
                 android:layout_height="0dp"
                 android:layout_weight="1"
+                android:clipChildren="?attr/sudClipChildren"
+                android:clipToPadding="?attr/sudClipToPadding"
                 android:scrollbars="vertical"
                 android:scrollIndicators="?attr/sudScrollIndicators"
                 app:sudShouldApplyAdditionalMargin="true" />
diff --git a/main/res/layout-w840dp-h900dp-v35/sud_glif_expressive_preference_recycler_view.xml b/main/res/layout-w840dp-h900dp-v35/sud_glif_expressive_preference_recycler_view.xml
new file mode 100644
index 0000000..f0c438b
--- /dev/null
+++ b/main/res/layout-w840dp-h900dp-v35/sud_glif_expressive_preference_recycler_view.xml
@@ -0,0 +1,27 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+        http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<com.google.android.setupdesign.view.HeaderRecyclerView
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/sud_recycler_view"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:clipChildren="false"
+    android:scrollbars="vertical"
+    android:filterTouchesWhenObscured="true"
+    app:sudShouldApplyAdditionalMargin="true" />
diff --git a/main/res/layout/sud_back_button.xml b/main/res/layout/sud_back_button.xml
index 9452081..63a88cb 100644
--- a/main/res/layout/sud_back_button.xml
+++ b/main/res/layout/sud_back_button.xml
@@ -22,11 +22,13 @@
       style="?attr/materialIconButtonFilledStyle"
       android:layout_width="wrap_content"
       android:layout_height="wrap_content"
-      android:checkable="true"
+      android:minWidth="@dimen/sud_glif_expressive_back_button_min_size"
+      android:minHeight="@dimen/sud_glif_expressive_back_button_min_size"
       android:contentDescription="@string/sud_back_button_label"
       android:filterTouchesWhenObscured="true"
       android:visibility="gone"
       app:backgroundTint="?attr/colorSurfaceContainerHigh"
+      app:rippleColor="@color/sud_back_button_ripple_color"
       app:icon="@drawable/sud_ic_arrow_back"
       app:iconTint="?attr/colorOnSurface"
       tools:visibility="visible" />
diff --git a/main/res/layout/sud_glif_floating_back_button.xml b/main/res/layout/sud_glif_floating_back_button.xml
index 4443694..7ff0783 100644
--- a/main/res/layout/sud_glif_floating_back_button.xml
+++ b/main/res/layout/sud_glif_floating_back_button.xml
@@ -28,8 +28,6 @@
       android:id="@+id/sud_floating_back_button_stub"
       android:layout_width="wrap_content"
       android:layout_height="wrap_content"
-      android:checkable="true"
-      android:contentDescription="@string/sud_back_button_label"
       android:filterTouchesWhenObscured="true"
       android:visibility="gone"
       android:inflatedId="@+id/sud_floating_back_button"
diff --git a/main/res/layout/sud_glif_header.xml b/main/res/layout/sud_glif_header.xml
index e5955c3..490c070 100644
--- a/main/res/layout/sud_glif_header.xml
+++ b/main/res/layout/sud_glif_header.xml
@@ -99,7 +99,8 @@
         android:id="@+id/sud_glif_progress_indicator_stub"
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
-        android:layout_marginTop="@dimen/sud_glif_expressive_progress_indicator_margin_vertical"
+        android:layout_marginTop="@dimen/sud_glif_expressive_progress_indicator_margin_top"
+        android:layout_marginBottom="@dimen/sud_glif_expressive_progress_indicator_margin_bottom"
         android:layout_marginLeft="?attr/sudMarginStart"
         android:layout_marginRight="?attr/sudMarginStart"
         android:paddingBottom="@dimen/sud_glif_expressive_progress_indicator_padding_bottom"
diff --git a/main/res/layout/sud_items_check_box.xml b/main/res/layout/sud_items_check_box.xml
index 2272dfd..7b2bae8 100644
--- a/main/res/layout/sud_items_check_box.xml
+++ b/main/res/layout/sud_items_check_box.xml
@@ -73,6 +73,10 @@
         android:id="@+id/sud_items_check_box"
         android:layout_width="wrap_content"
         android:layout_height="match_parent"
-        android:layout_gravity="center_vertical" />
+        android:layout_gravity="center"
+        android:minHeight="@dimen/sud_items_check_box_min_size"
+        android:minWidth="@dimen/sud_items_check_box_min_size"
+        android:layout_marginTop="@dimen/sud_items_check_box_margin_top"
+        android:layout_marginBottom="@dimen/sud_items_check_box_margin_bottom" />
 
 </LinearLayout>
diff --git a/main/res/layout/sud_items_expandable.xml b/main/res/layout/sud_items_expandable.xml
index defe8e7..8405658 100644
--- a/main/res/layout/sud_items_expandable.xml
+++ b/main/res/layout/sud_items_expandable.xml
@@ -27,6 +27,8 @@
     <LinearLayout
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
+        android:layout_marginTop="@dimen/sud_items_expand_title_container_margin_top"
+        android:layout_marginBottom="@dimen/sud_items_expand_title_container_margin_bottom"
         android:baselineAligned="false"
         android:orientation="horizontal">
 
diff --git a/main/res/layout/sud_items_expandable_switch_expressive.xml b/main/res/layout/sud_items_expandable_switch_expressive.xml
index 78b217a..18243b1 100644
--- a/main/res/layout/sud_items_expandable_switch_expressive.xml
+++ b/main/res/layout/sud_items_expandable_switch_expressive.xml
@@ -27,6 +27,7 @@
         android:id="@+id/sud_items_expandable_switch_content"
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
+        android:layout_marginTop="@dimen/sud_glif_expressive_expandable_items_content_margin_top"
         android:baselineAligned="false"
         android:duplicateParentState="true"
         android:orientation="horizontal">
@@ -58,9 +59,10 @@
             android:textAlignment="viewStart"
             tools:ignore="UnusedAttribute" />
 
-        <androidx.appcompat.widget.SwitchCompat
+        <com.google.android.material.materialswitch.MaterialSwitch
             android:id="@+id/sud_items_switch"
             style="@style/SudExpressiveSwitchBarStyle"
+            android:theme="@style/Theme.Material3.DynamicColors.DayNight.NoActionBar"
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
             android:layout_alignParentEnd="true"
@@ -69,33 +71,40 @@
             android:paddingEnd="0dp" />
 
     </RelativeLayout>
-
-    <com.google.android.setupdesign.view.RichTextView
-        android:id="@+id/sud_items_summary"
-        style="?attr/sudItemSummaryStyle"
+    <LinearLayout
+        android:id="@+id/sud_items_summary_container"
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
-        android:duplicateParentState="true"
-        android:gravity="start"
-        android:layout_weight="1"
-        android:layout_marginTop="12dp"
-        android:layout_marginBottom="0dp"
-        android:textAlignment="viewStart"
-        android:visibility="gone"
-        android:textColor="?android:attr/textColorPrimary"
-        tools:ignore="UnusedAttribute" />
+        android:orientation="vertical">
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_summary"
+            style="?attr/sudItemSummaryStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:duplicateParentState="true"
+            android:gravity="start"
+            android:layout_weight="1"
+            android:paddingTop="@dimen/sud_glif_expressive_expandable_items_summary_padding_top"
+            android:layout_marginBottom="0dp"
+            android:textAlignment="viewStart"
+            android:visibility="gone"
+            android:textColor="?android:attr/textColorPrimary"
+            tools:ignore="UnusedAttribute" />
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_more_info"
+            style="?attr/sudItemMoreInfoStyle"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:layout_weight="1"
+            android:paddingTop="@dimen/sud_glif_expressive_expandable_items_more_info_padding_top"
+            android:paddingBottom="@dimen/sud_glif_expressive_expandable_items_more_info_padding_bottom"
+            android:text="@string/sud_more_info"
+            android:textColor="?attr/colorPrimary"
+            android:textAlignment="viewStart" />
+    </LinearLayout>
 
-    <com.google.android.setupdesign.view.RichTextView
-        android:id="@+id/sud_items_more_info"
-        style="?attr/sudItemSummaryStyle"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:gravity="start"
-        android:layout_weight="1"
-        android:layout_marginTop="16dp"
-        android:layout_marginBottom="0dp"
-        android:text="@string/sud_more_info"
-        android:textColor="?attr/colorPrimary"
-        android:textAlignment="viewStart" />
 
 </LinearLayout>
diff --git a/main/res/layout/sud_items_radio_button.xml b/main/res/layout/sud_items_radio_button.xml
index 9a25c91..006dc3e 100644
--- a/main/res/layout/sud_items_radio_button.xml
+++ b/main/res/layout/sud_items_radio_button.xml
@@ -26,6 +26,7 @@
 
     <com.google.android.material.radiobutton.MaterialRadioButton
         android:id="@+id/sud_items_radio_button"
+        style="?attr/sudItemRadioButtonStyle"
         android:layout_width="wrap_content"
         android:layout_height="match_parent"
         android:layout_gravity="center_vertical" />
diff --git a/main/res/values-w600dp-h900dp/dimens.xml b/main/res/values-w600dp-h900dp/dimens.xml
index d369e84..c70af2f 100644
--- a/main/res/values-w600dp-h900dp/dimens.xml
+++ b/main/res/values-w600dp-h900dp/dimens.xml
@@ -30,6 +30,11 @@
     <dimen name="sud_glif_expressive_header_title_size">45sp</dimen>
     <dimen name="sud_glif_expressive_header_title_line_height">52sp</dimen>
 
+    <!-- Material floating back button -->
+    <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_back_button_margin_start">68dp</dimen>
+
+
     <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
     <dimen name="sud_glif_expressive_button_margin_end">80dp</dimen>
     <!-- Calculated by (sud_glif_expressive_margin_start - sud_glif_expressive_button_padding) -->
diff --git a/main/res/values-w600dp/dimens.xml b/main/res/values-w600dp/dimens.xml
index ba4aa48..22d78c6 100644
--- a/main/res/values-w600dp/dimens.xml
+++ b/main/res/values-w600dp/dimens.xml
@@ -17,9 +17,7 @@
 <resources>
 
   <!-- Glif expressive footer bar padding -->
-  <!-- Calculated by (Spec = 12dp - 4dp internal padding of button) -->
-  <dimen name="sud_glif_expressive_footer_bar_padding_start">8dp</dimen>
-  <!-- Calculated by (Spec = 24dp - 4dp internal padding of button) -->
-  <dimen name="sud_glif_expressive_footer_bar_padding_end">20dp</dimen>
+  <dimen name="sud_glif_expressive_footer_bar_padding_start">4dp</dimen>
+  <dimen name="sud_glif_expressive_footer_bar_padding_end">24dp</dimen>
 
 </resources>
diff --git a/main/res/values-w840dp-h480dp/dimens.xml b/main/res/values-w840dp-h480dp/dimens.xml
index f061330..c183522 100644
--- a/main/res/values-w840dp-h480dp/dimens.xml
+++ b/main/res/values-w840dp-h480dp/dimens.xml
@@ -20,10 +20,8 @@
     <dimen name="sud_glif_expressive_margin_start">48dp</dimen>
     <dimen name="sud_glif_expressive_margin_end">48dp</dimen>
     <dimen name="sud_glif_expressive_land_middle_horizontal_spacing">72dp</dimen>
-    <!-- Calculated by (Spec = 36dp - 4dp internal padding of button) -->
-    <dimen name="sud_glif_expressive_footer_bar_padding_start">32dp</dimen>
-    <!-- Calculated by (Spec = 48dp - 4dp internal padding of button) -->
-    <dimen name="sud_glif_expressive_footer_bar_padding_end">44dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_start">28dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_end">48dp</dimen>
     <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
     <dimen name="sud_glif_expressive_button_margin_end">44dp</dimen>
     <!-- Calculated by (sud_glif_expressive_margin_start - sud_glif_expressive_button_padding) -->
@@ -34,4 +32,8 @@
     <dimen name="sud_glif_expressive_header_title_size">45sp</dimen>
     <dimen name="sud_glif_expressive_header_title_line_height">52sp</dimen>
 
+    <!-- Material floating back button -->
+    <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_back_button_margin_start">44dp</dimen>
+
 </resources>
diff --git a/main/res/values-w840dp-h900dp-v35/layouts.xml b/main/res/values-w840dp-h900dp-v35/layouts.xml
new file mode 100644
index 0000000..da40a08
--- /dev/null
+++ b/main/res/values-w840dp-h900dp-v35/layouts.xml
@@ -0,0 +1,24 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<resources xmlns:tools="http://schemas.android.com/tools">
+    <item name="sud_glif_expressive_template_content_layout" type="layout">@layout/sud_glif_expressive_template_content_wide</item>
+    <item name="sud_glif_expressive_list_template_content_layout" type="layout">@layout/sud_glif_expressive_list_template_content_wide</item>
+    <item name="sud_glif_expressive_blank_template_content_layout" type="layout">@layout/sud_glif_expressive_blank_template_content_wide</item>
+    <item name="sud_glif_expressive_preference_template_content_layout" type="layout">@layout/sud_glif_expressive_preference_template_content_wide</item>
+    <item name="sud_glif_expressive_recycler_template_content_layout" type="layout">@layout/sud_glif_expressive_recycler_template_content_wide</item>
+</resources>
diff --git a/main/res/values-w840dp-h900dp/dimens.xml b/main/res/values-w840dp-h900dp/dimens.xml
new file mode 100644
index 0000000..6806279
--- /dev/null
+++ b/main/res/values-w840dp-h900dp/dimens.xml
@@ -0,0 +1,41 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<resources>
+    <!-- Page Margins Glif Expressive -->
+    <dimen name="sud_glif_expressive_margin_start">48dp</dimen>
+    <dimen name="sud_glif_expressive_margin_end">48dp</dimen>
+    <dimen name="sud_glif_expressive_land_middle_horizontal_spacing">72dp</dimen>
+    <!-- Calculated by (Spec = 36dp - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_footer_bar_padding_start">32dp</dimen>
+    <!-- Calculated by (Spec = 48dp - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_footer_bar_padding_end">44dp</dimen>
+    <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_button_margin_end">44dp</dimen>
+    <!-- Calculated by (sud_glif_expressive_margin_start - sud_glif_expressive_button_padding) -->
+    <dimen name="sud_glif_expressive_button_margin_start">32dp</dimen>
+    <dimen name="sud_glif_expressive_content_padding_top">80dp</dimen>
+
+    <!-- Header layout expressive -->
+    <dimen name="sud_glif_expressive_header_title_size">45sp</dimen>
+    <dimen name="sud_glif_expressive_header_title_line_height">52sp</dimen>
+
+    <!-- Material floating back button -->
+    <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_back_button_margin_start">44dp</dimen>
+
+</resources>
diff --git a/main/res/values-w840dp/dimens.xml b/main/res/values-w840dp/dimens.xml
index 59170ab..e4fedd2 100644
--- a/main/res/values-w840dp/dimens.xml
+++ b/main/res/values-w840dp/dimens.xml
@@ -18,10 +18,8 @@
 <resources>
     <!-- General -->
     <dimen name="sud_glif_expressive_footer_bar_min_height">52dp</dimen>
-    <!-- Calculated by (Spec = 12dp - 4dp internal padding of button) -->
-    <dimen name="sud_glif_expressive_footer_bar_padding_start">8dp</dimen>
-    <!-- Calculated by (Spec = 24dp - 4dp internal padding of button) -->
-    <dimen name="sud_glif_expressive_footer_bar_padding_end">20dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_start">4dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_end">24dp</dimen>
 
     <dimen name="sud_glif_expressive_content_padding_top">8dp</dimen>
 </resources>
diff --git a/main/res/values/attrs.xml b/main/res/values/attrs.xml
index 68b495d..25b358d 100644
--- a/main/res/values/attrs.xml
+++ b/main/res/values/attrs.xml
@@ -81,6 +81,8 @@
     <attr name="sudGlifAccountContainerStyle" format="reference" />
     <attr name="sudGlifAccountAvatarSize" format="dimension" />
 
+    <attr name="sudBackButtonMarginStart" format="dimension" />
+
     <attr name="sudButtonAllCaps" format="boolean" />
     <attr name="sudButtonCornerRadius" format="dimension" />
     <attr name="sudButtonFontFamily" format="string|reference" />
@@ -140,6 +142,10 @@
     <!-- Custom the scroll bar indicator  -->
     <attr name="sudScrollBarThumb" format="reference" />
 
+    <!-- Edge to edge attributes -->
+    <attr name="sudClipToPadding" format="boolean" />
+    <attr name="sudClipChildren" format="boolean" />
+
     <!-- Custom view attributes -->
     <attr name="sudColorPrimary" format="color" />
     <attr name="sudHeader" format="reference" />
@@ -164,6 +170,7 @@
     <attr name="sudItemIconStyle" format="reference"/>
     <attr name="sudItemTitleStyle" format="reference"/>
     <attr name="sudItemSummaryStyle" format="reference"/>
+    <attr name="sudItemMoreInfoStyle" format="reference"/>
     <attr name="sudBulletPointTitleStyle" format="reference"/>
     <attr name="sudBulletPointSummaryStyle" format="reference"/>
     <attr name="sudItemDescriptionStyle" format="reference" />
@@ -173,6 +180,7 @@
     <attr name="sudSectionItemTitleStyle" format="reference" />
     <attr name="sudItemDescriptionTitleStyle" format="reference" />
     <attr name="sudItemDescriptionTitleTextAppearence" format="reference" />
+    <attr name="sudTextAppearanceBulletPoint" format="reference" />
     <attr name="sudItemVerboseTitleStyle" format="reference" />
     <attr name="sudItemIconContainerWidth" format="dimension|reference" />
     <attr name="sudItemPaddingTop" format="dimension|reference" />
@@ -190,6 +198,7 @@
     <attr name="sudItemBackgroundFirst" format="color|reference" />
     <attr name="sudItemBackgroundLast" format="color|reference" />
     <attr name="sudItemBackgroundSingle" format="color|reference" />
+    <attr name="sudSectionHeaderColor" format="color|reference" />
     <attr name="sudNonActionableItemBackground" format="color|reference" />
     <attr name="sudNonActionableItemBackgroundFirst" format="color|reference" />
     <attr name="sudNonActionableItemBackgroundLast" format="color|reference" />
@@ -213,6 +222,8 @@
     <attr name="sudQrFinishStyle" format="reference" />
     <attr name="sudExpandedContent" format="reference" />
     <attr name="sudAnimationId" format="reference" />
+    <attr name="sudItemRadioButtonStyle" format="reference" />
+    <attr name="sudItemIconDefaultTint" format="color" />
 
     <!-- EditBox -->
     <attr name="sudEditBoxStyle" format="reference" />
@@ -244,6 +255,7 @@
 
     <declare-styleable name="SudSectionItem">
         <attr name="android:title" />
+        <attr name="sudSectionHeaderColor" />
     </declare-styleable>
 
     <declare-styleable name="SudIllustrationVideoView">
diff --git a/main/res/values/config.xml b/main/res/values/config.xml
index 1ad4f2e..52d3e15 100644
--- a/main/res/values/config.xml
+++ b/main/res/values/config.xml
@@ -32,14 +32,15 @@
     <string name="sudFontSecondaryMedium" translatable="false">google-sans-medium</string>
     <!-- Material You button font family -->
     <string name="sudFontSecondaryMediumMaterialYou" translatable="false">google-sans-text-medium</string>
+    <string name="sudFontExpressive" translatable="false">google-sans-flex</string>
     <item name="sud_layout_description" type="id" />
 
     <!-- Glif expressive button styles -->
     <string name="sudExpressiveButtonFontFamily" translatable="false">google-sans-text-medium</string>
 
     <!-- Glif expressive alert dialog styles -->
-    <string name="sudGlifExpressiveDialogFontFamily" translatable="false">google-sans-text</string>
+    <string name="sudGlifExpressiveDialogFontFamily" translatable="false">google-sans-flex</string>
 
     <!-- Glif card view styles -->
-    <string name="sudCardViewFontFamily" translatable="false">google-sans-text</string>
+    <string name="sudCardViewFontFamily" translatable="false">google-sans-flex</string>
 </resources>
diff --git a/main/res/values/dimens.xml b/main/res/values/dimens.xml
index 4941c77..b1c955c 100644
--- a/main/res/values/dimens.xml
+++ b/main/res/values/dimens.xml
@@ -187,6 +187,7 @@
     <dimen name="sud_items_divder_width">2dp</dimen>
     <dimen name="sud_items_background_padding_start">16dp</dimen>
     <dimen name="sud_items_background_padding_end">16dp</dimen>
+    <dimen name="sud_items_radio_button_padding_end">16dp</dimen>
 
     <!-- General Material You -->
     <dimen name="sud_glif_land_middle_horizontal_spacing_material_you">48dp</dimen>
@@ -249,6 +250,7 @@
     <dimen name="sud_bullet_point_padding_top">16dp</dimen>
     <dimen name="sud_bullet_point_padding_bottom">16dp</dimen>
     <dimen name="sud_bullet_point_icon_padding_end">16dp</dimen>
+    <dimen name="sud_bullet_point_title_text_size">16sp</dimen>
 
     <!-- Info footer-->
     <dimen name="sud_info_footer_padding_top">16dp</dimen>
@@ -257,7 +259,7 @@
     <dimen name="sud_info_footer_icon_padding_bottom">8dp</dimen>
     <dimen name="sud_info_footer_icon_size">18dp</dimen>
     <dimen name="sud_info_footer_text_size">14sp</dimen>
-    <dimen name="sud_info_footer_text_line_spacing_extra">6sp</dimen>
+    <dimen name="sud_info_footer_text_line_height">20sp</dimen>
 
     <!-- Progress bar -->
     <dimen name="sud_progress_bar_margin_top_material_you">16dp</dimen>
@@ -353,17 +355,23 @@
     <dimen name="sud_items_padding_top_expressive">12dp</dimen>
     <dimen name="sud_items_padding_bottom_expressive">12dp</dimen>
     <dimen name="sud_items_padding_bottom_extra_expressive">0dp</dimen>
-    <dimen name="sud_items_expand_button_size">40dp</dimen>
+    <dimen name="sud_items_expand_button_size">48dp</dimen>
+    <dimen name="sud_items_expand_title_container_margin_top">-2dp</dimen>
+    <dimen name="sud_items_expand_title_container_margin_bottom">-2dp</dimen>
+    <!-- The check box need addtional 8dp to make the check box follow the Accessibility request-->
+    <dimen name="sud_items_check_box_margin_top">-4dp</dimen>
+    <dimen name="sud_items_check_box_margin_bottom">-4dp</dimen>
+    <dimen name="sud_items_check_box_min_size">48dp</dimen>
 
     <dimen name="sud_glif_expressive_button_padding">16dp</dimen>
     <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
     <dimen name="sud_glif_expressive_button_margin_end">20dp</dimen>
     <!-- Calculated by (sud_glif_expressive_margin_start - sud_glif_expressive_button_padding) -->
     <dimen name="sud_glif_expressive_button_margin_start">8dp</dimen>
-    <dimen name="sud_glif_expressive_description_margin_top">8dp</dimen>
-    <dimen name="sud_glif_expreesive_description_margin_bottom">0dp</dimen>
+    <dimen name="sud_glif_expressive_description_margin_top">0dp</dimen>
+    <dimen name="sud_glif_expreesive_description_margin_bottom">32dp</dimen>
     <dimen name="sud_glif_expressive_icon_margin_top">8dp</dimen>
-    <dimen name="sud_glif_expressive_content_padding_top">8dp</dimen>
+    <dimen name="sud_glif_expressive_content_padding_top">0dp</dimen>
     <dimen name="sud_glif_expressive_item_corner_radius">4dp</dimen>
     <dimen name="sud_glif_expressive_promo_card_icon_corner_radius">20dp</dimen>
     <dimen name="sud_glif_expressive_promo_card_icon_padding">18dp</dimen>
@@ -374,6 +382,13 @@
     <dimen name="sud_glif_expressive_items_icon_padding_start">0dp</dimen>
     <dimen name="sud_glif_expressive_items_icon_padding_end">0dp</dimen>
     <dimen name="sud_glif_expressive_items_icon_width">40dp</dimen>
+    <dimen name="sud_glif_expressive_item_summary_line_height">20sp</dimen>
+    <dimen name="sud_glif_expressive_item_title_line_height">24sp</dimen>
+    <!-- the switch toggle has 4dp for touch area top and bottom, should remove the item bound padding-->
+    <dimen name="sud_glif_expressive_expandable_items_content_margin_top">-4dp</dimen>
+    <dimen name="sud_glif_expressive_expandable_items_summary_padding_top">4dp</dimen>
+    <dimen name="sud_glif_expressive_expandable_items_more_info_padding_top">16dp</dimen>
+    <dimen name="sud_glif_expressive_expandable_items_more_info_padding_bottom">4dp</dimen>
     <dimen name="sud_glif_expressive_list_divider_height">24dp</dimen>
     <dimen name="sud_items_section_header_padding_top">20dp</dimen>
     <dimen name="sud_items_section_header_padding_bottom">8dp</dimen>
@@ -382,23 +397,36 @@
     <dimen name="sud_items_illustration_item_max_width">494dp</dimen>
     <dimen name="sud_expressive_switch_padding_start">12dp</dimen>
 
+    <!-- Promo card -->
+    <dimen name="sud_glif_promo_card_title_line_height">24sp</dimen>
+    <dimen name="sud_glif_promo_card_summary_line_height">20sp</dimen>
+
     <!-- Header layout expressive -->
+    <dimen name="sud_glif_expressive_header_container_margin_bottom">0dp</dimen>
     <dimen name="sud_glif_expressive_header_title_size">32sp</dimen>
     <dimen name="sud_glif_expressive_header_title_line_height">40sp</dimen>
+    <dimen name="sud_glif_expressive_header_title_margin_bottom">16dp</dimen>
     <dimen name="sud_glif_expressive_description_text_size">16sp</dimen>
-    <dimen name="sud_glif_expressive_description_line_spacing_extra">8sp</dimen>
+    <dimen name="sud_glif_expressive_description_line_height">24sp</dimen>
+    <dimen name="sud_glif_expressive_back_button_padding_start">4dp</dimen>
 
     <!-- Progress indicator -->
     <dimen name="sud_glif_expressive_progress_indicator_margin_vertical">16dp</dimen>
+    <dimen name="sud_glif_expressive_progress_indicator_margin_top">0dp</dimen>
+    <!-- The sum of margin bottom 16dp and progress indicator height 7dp -->
+    <dimen name="sud_glif_expressive_progress_indicator_margin_bottom">23dp</dimen>
     <dimen name="sud_glif_expressive_progress_indicator_padding_bottom">7dp</dimen>
 
     <!-- Material floating back button -->
     <dimen name="sud_glif_expressive_back_button_margin_top">8dp</dimen>
     <dimen name="sud_glif_expressive_back_button_height">48dp</dimen>
+    <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_back_button_margin_start">20dp</dimen>
+    <dimen name="sud_glif_expressive_back_button_min_size">48dp</dimen>
 
     <!-- Glif expressive Additional body text -->
     <dimen name="sud_glif_expressive_additional_body_text_size">16sp</dimen>
-    <dimen name="sud_glif_expressive_additional_body_text_line_spacing_extra">8sp</dimen>
+    <dimen name="sud_glif_expressive_additional_body_text_line_height">24sp</dimen>
     <dimen name="sud_additional_body_text_padding_bottom">32dp</dimen>
 
     <!-- Glif expressive Info footer -->
@@ -419,6 +447,8 @@
     <dimen name="sud_glif_expressive_footer_button_middle_spacing">8dp</dimen>
     <dimen name="sud_glif_expressive_footer_padding_top">16dp</dimen>
     <dimen name="sud_glif_expressive_footer_padding_bottom">8dp</dimen>
+    <dimen name="sud_glif_expressive_down_button_icon_size">24dp</dimen>
+
     <!-- Glif expressive alert dialog -->
     <dimen name="sud_glif_expressive_alert_dialog_title_font_size">24sp</dimen>
 
@@ -435,13 +465,14 @@
     <dimen name="sud_card_view_icon_size">24dp</dimen>
     <dimen name="sud_card_view_icon_container_margin_top">16dp</dimen>
     <!-- Card view title -->
-    <dimen name="sud_card_view_title_text_size">14sp</dimen>
+    <dimen name="sud_card_view_title_text_size">16sp</dimen>
     <dimen name="sud_card_view_title_line_spacing_extra">6sp</dimen>
     <dimen name="sud_card_view_title_spacing_top">4dp</dimen>
     <dimen name="sud_card_view_title_margin_bottom">16dp</dimen>
+    <dimen name="sud_card_view_title_font_weight">400</dimen>
 
     <!-- Camera preview -->
-    <dimen name="sud_expressive_camera_preview_corner_radius">28dp</dimen>
+    <dimen name="sud_expressive_camera_preview_corner_radius">36dp</dimen>
     <dimen name="sud_expressive_camera_preview_padding">8dp</dimen>
 
     <!-- Glif expressive progress indicator -->
@@ -450,4 +481,8 @@
     <dimen name="sud_glif_expressive_progress_indicator_wavelength_indeterminate">30dp</dimen>
     <item name="sud_glif_expressive_progress_indicator_indeterminate_animator_duration_scale" format="float" type="dimen">1.5</item>
 
+    <!-- Glif expressive account container -->
+    <dimen name="sud_glif_expressive_account_container_margin_top">0dp</dimen>
+    <dimen name="sud_glif_expressive_account_container_margin_bottom">16dp</dimen>
+
 </resources>
diff --git a/main/res/values/styles.xml b/main/res/values/styles.xml
index b260ccb..977ea65 100644
--- a/main/res/values/styles.xml
+++ b/main/res/values/styles.xml
@@ -99,12 +99,13 @@
         <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
         <item name="sudItemTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryGlif</item>
+        <item name="sudItemMoreInfoStyle">?attr/sudItemSummaryStyle</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
         <item name="sudSectionItemContainerStyle">@style/SudItemContainer</item>
         <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
         <item name="sudIllustrationItemStyle">@style/SudItemSummary.IllustrationStyle</item>
         <item name="sudSectionItemTitleStyle">@style/SudItemTitle.SectionHeader</item>
-        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointTitleStyle">@style/SudBulletPointTitle</item>
         <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
         <item name="sudPromoItemBackground">@drawable/sud_item_background</item>
         <item name="sudPromoItemContainerStyle">@style/SudPromoItemContainer</item>
@@ -119,6 +120,11 @@
         <item name="sudCameraPreviewStyle">@null</item>
         <item name="sudItemIconStyle">@style/SudItemIcon</item>
         <item name="sudQrFinishStyle">@null</item>
+        <item name="sudItemIconDefaultTint">@android:color/transparent</item>
+        <item name="sudItemRadioButtonStyle">@style/SudItemRadioButton</item>
+        <item name="sudTextAppearanceBulletPoint">@style/TextAppearance.SudBulletPoint</item>
+        <item name="sudClipChildren">true</item>
+        <item name="sudClipToPadding">true</item>
     </style>
 
     <style name="SudThemeMaterial.Light" parent="Theme.AppCompat.Light.NoActionBar">
@@ -201,12 +207,13 @@
         <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
         <item name="sudItemTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryGlif</item>
+        <item name="sudItemMoreInfoStyle">?attr/sudItemSummaryStyle</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
         <item name="sudSectionItemContainerStyle">@style/SudItemContainer</item>
         <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
         <item name="sudIllustrationItemStyle">@style/SudItemSummary.IllustrationStyle</item>
         <item name="sudSectionItemTitleStyle">@style/SudItemTitle.SectionHeader</item>
-        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointTitleStyle">@style/SudBulletPointTitle</item>
         <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
         <item name="sudPromoItemBackground">@drawable/sud_item_background</item>
         <item name="sudPromoItemContainerStyle">@style/SudPromoItemContainer</item>
@@ -221,6 +228,11 @@
         <item name="sudItemIconStyle">@style/SudItemIcon</item>
         <item name="sudCameraPreviewStyle">@null</item>
         <item name="sudQrFinishStyle">@null</item>
+        <item name="sudItemIconDefaultTint">@android:color/transparent</item>
+        <item name="sudItemRadioButtonStyle">@style/SudItemRadioButton</item>
+        <item name="sudTextAppearanceBulletPoint">@style/TextAppearance.SudBulletPoint</item>
+        <item name="sudClipChildren">true</item>
+        <item name="sudClipToPadding">true</item>
     </style>
 
     <style name="SudBaseThemeGlif" parent="Theme.AppCompat.NoActionBar">
@@ -288,6 +300,7 @@
         <item name="sudListItemIconColor">@color/sud_list_item_icon_color_dark</item>
         <item name="sudMarginStart">@dimen/sud_glif_margin_start</item>
         <item name="sudMarginEnd">@dimen/sud_glif_margin_end</item>
+        <item name="sudBackButtonMarginStart">?attr/sudMarginStart</item>
         <item name="sudScrollIndicators">bottom</item>
         <item name="sudScrollBarThumb">@drawable/sud_scroll_bar_dark</item>
         <item name="textAppearanceListItem">@style/TextAppearance.SudGlifItemTitle</item>
@@ -335,6 +348,7 @@
         <item name="sudItemDescriptionPaddingBottom">@dimen/sud_description_glif_margin_bottom_lists</item>
         <item name="sudItemTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryGlif</item>
+        <item name="sudItemMoreInfoStyle">?attr/sudItemSummaryStyle</item>
         <item name="sudItemSummaryPaddingTop">0dp</item>
         <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
@@ -354,7 +368,7 @@
         <item name="sudListDividerHeight">0dp</item>
         <item name="sudBulletPointIconContainerStyle">@style/sudBulletPointIconContainer</item>
         <item name="sudBulletPointContainerStyle">@style/sudBulletPointContainer</item>
-        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointTitleStyle">@style/SudBulletPointTitle</item>
         <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
         <item name="sudSectionItemContainerStyle">@style/SudItemContainer</item>
         <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
@@ -378,6 +392,11 @@
         <item name="sudItemIconStyle">@style/SudItemIcon</item>
         <item name="sudCameraPreviewStyle">@null</item>
         <item name="sudQrFinishStyle">@null</item>
+        <item name="sudItemIconDefaultTint">@android:color/transparent</item>
+        <item name="sudItemRadioButtonStyle">@style/SudItemRadioButton</item>
+        <item name="sudTextAppearanceBulletPoint">@style/TextAppearance.SudBulletPoint</item>
+        <item name="sudClipChildren">true</item>
+        <item name="sudClipToPadding">true</item>
     </style>
     <style name="SudThemeGlif" parent="SudBaseThemeGlif"/>
 
@@ -446,6 +465,7 @@
         <item name="sudListItemIconColor">@color/sud_list_item_icon_color_light</item>
         <item name="sudMarginStart">@dimen/sud_glif_margin_start</item>
         <item name="sudMarginEnd">@dimen/sud_glif_margin_end</item>
+        <item name="sudBackButtonMarginStart">?attr/sudMarginStart</item>
         <item name="sudScrollIndicators">bottom</item>
         <item name="sudScrollBarThumb">@drawable/sud_scroll_bar_light</item>
         <item name="textAppearanceListItem">@style/TextAppearance.SudGlifItemTitle</item>
@@ -493,6 +513,7 @@
         <item name="sudItemDescriptionPaddingBottom">@dimen/sud_description_glif_margin_bottom_lists</item>
         <item name="sudItemTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryGlif</item>
+        <item name="sudItemMoreInfoStyle">?attr/sudItemSummaryStyle</item>
         <item name="sudItemSummaryPaddingTop">0dp</item>
         <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
@@ -512,7 +533,7 @@
         <item name="sudListDividerHeight">0dp</item>
         <item name="sudBulletPointIconContainerStyle">@style/sudBulletPointIconContainer</item>
         <item name="sudBulletPointContainerStyle">@style/sudBulletPointContainer</item>
-        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointTitleStyle">@style/SudBulletPointTitle</item>
         <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
         <item name="sudSectionItemContainerStyle">@style/SudItemContainer</item>
         <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
@@ -536,6 +557,11 @@
         <item name="sudItemIconStyle">@style/SudItemIcon</item>
         <item name="sudCameraPreviewStyle">@null</item>
         <item name="sudQrFinishStyle">@null</item>
+        <item name="sudItemIconDefaultTint">@android:color/transparent</item>
+        <item name="sudItemRadioButtonStyle">@style/SudItemRadioButton</item>
+        <item name="sudTextAppearanceBulletPoint">@style/TextAppearance.SudBulletPoint</item>
+        <item name="sudClipChildren">true</item>
+        <item name="sudClipToPadding">true</item>
     </style>
     <style name="SudThemeGlif.Light" parent="SudBaseThemeGlif.Light"/>
 
@@ -759,7 +785,7 @@
         <item name="sudDividerInsetStart">?attr/sudMarginStart</item>
         <item name="sudDividerInsetStartNoIcon">?attr/sudMarginStart</item>
         <item name="sudGlifSubtitleGravity">center_horizontal</item>
-        <item name="sudScrollIndicators">top|bottom</item>
+        <item name="sudScrollIndicators">none</item>
         <item name="sudEditTextBackgroundColor">@color/sud_glif_edit_text_bg_dark_color</item>
         <item name="android:editTextStyle">@style/SudEditText</item>
         <item name="sucLightStatusBar" tools:targetApi="m">?android:attr/windowLightStatusBar</item>
@@ -774,16 +800,16 @@
         <!-- Copied from values style SudThemeGlifV4 -->
         <item name="sucFooterBarPaddingVertical">@dimen/sud_glif_footer_bar_padding_vertical_material_you</item>
         <item name="sucFooterBarMinHeight">@dimen/sud_glif_footer_bar_min_height_material_you</item>
-        <item name="sucHeaderContainerMarginBottom">@dimen/sud_header_container_margin_bottom_material_you</item>
+        <item name="sucHeaderContainerMarginBottom">@dimen/sud_glif_expressive_header_container_margin_bottom</item>
         <item name="sucFooterBarButtonAlignEnd">@bool/suc_footer_bar_button_align_end</item>
         <item name="sudButtonTertiaryGravity">center_horizontal</item>
         <item name="sudGlifIconSize">@dimen/sud_glif_icon_max_height_material_you</item>
-        <item name="sudGlifAccountContainerStyle">@style/SudGlifAccountContainerMaterialYou</item>
+        <item name="sudGlifAccountContainerStyle">@style/SudGlifAccountContainerExpressive</item>
         <item name="sudGlifHeaderTitleStyle">@style/SudGlifHeaderTitleExpressive</item>
         <item name="sudGlifHeaderGravity">start</item>
         <item name="sudGlifIconGravity">center_horizontal</item>
         <item name="sucGlifHeaderMarginTop">@dimen/sud_glif_header_title_margin_top_material_you</item>
-        <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_header_title_margin_bottom_material_you</item>
+        <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_expressive_header_title_margin_bottom</item>
         <item name="sudGlifDescriptionStyle">@style/SudGlifDescriptionExpressive</item>
         <item name="sudGlifDescriptionMarginBottom">@dimen/sud_glif_expreesive_description_margin_bottom</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudMaterialYouDescription</item>
@@ -802,6 +828,7 @@
         <item name="android:colorBackground" tools:ignore="NewApi">?attr/colorSurfaceContainer</item>
         <item name="sudMarginStart">@dimen/sud_glif_expressive_margin_start</item>
         <item name="sudMarginEnd">@dimen/sud_glif_expressive_margin_end</item>
+        <item name="sudBackButtonMarginStart">@dimen/sud_glif_expressive_back_button_margin_start</item>
         <item name="sudGlifContentPaddingTop">@dimen/sud_glif_expressive_content_padding_top</item>
         <item name="sucFooterButtonPaddingStart">@dimen/sud_glif_expressive_button_padding</item>
         <item name="sucFooterButtonPaddingEnd">@dimen/sud_glif_expressive_button_padding</item>
@@ -839,6 +866,7 @@
         <item name="sudNonActionableItemBackgroundColor" tools:ignore="NewApi">?attr/colorSurfaceContainerHigh</item>
         <item name="sudItemTitleStyle">@style/SudItemTitleExpressive</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryExpressive</item>
+        <item name="sudItemMoreInfoStyle">@style/SudItemMoreInfoExpressive</item>
         <item name="sudItemSummaryPaddingTop">@dimen/sud_items_summary_margin_top_expressive</item>
         <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width_expressive</item>
         <item name="sudBulletPointIconContainerStyle">@style/sudBulletPointIconContainer</item>
@@ -847,7 +875,7 @@
         <item name="sudInfoFooterContainerStyle">@style/sudInfoFooterContainerExpressive</item>
         <item name="sudInfoFooterIconContainerStyle">@style/sudInfoFooterIconContainer</item>
         <item name="sudInfoFooterIconStyle">@style/sudInfoFooterIconExpressive</item>
-        <item name="sudInfoFooterTitleStyle">@style/sudInfoFooterTitle</item>
+        <item name="sudInfoFooterTitleStyle">@style/sudInfoFooterTitleExpressive</item>
         <item name="sucFooterBarButtonFontWeight">@integer/sud_glif_expressive_footer_button_weight</item>
         <item name="sudButtonCornerRadius">@dimen/sud_glif_expressive_footer_button_radius</item>
         <item name="sucFooterBarButtonTextSize">@dimen/sud_glif_expressive_footer_button_text_size</item>
@@ -857,7 +885,7 @@
         <item name="textAppearanceListItem">@style/TextAppearance.SudExpressiveItemTitle</item>
         <item name="textAppearanceListItemSmall">@style/TextAppearance.SudExpressiveItemSummary</item>
         <item name="materialAlertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
-        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointTitleStyle">@style/SudBulletPointTitle</item>
         <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
         <item name="sudSectionItemContainerStyle">@style/SudGlifExpressiveItemContainer.SectionItem</item>
         <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
@@ -876,6 +904,11 @@
         <item name="sudItemIconStyle">@style/SudExpressiveItemIcon</item>
         <item name="sudCameraPreviewStyle">@style/SudExpressiveCameraPreview</item>
         <item name="sudQrFinishStyle">@style/SudExpressiveQrFinish</item>
+        <item name="sudItemIconDefaultTint">@color/sud_system_on_surface_variant_dark</item>
+        <item name="sudItemRadioButtonStyle">@style/SudExpressiveItemRadioButton</item>
+        <item name="sudTextAppearanceBulletPoint">@style/TextAppearance.SudBulletPoint</item>
+        <item name="sudClipChildren">false</item>
+        <item name="sudClipToPadding">false</item>
     </style>
 
     <style name="SudBaseThemeGlifExpressive.Light" parent="Theme.Material3.DynamicColors.Light.NoActionBar">
@@ -943,7 +976,7 @@
         <item name="sudDividerInsetStart">?attr/sudMarginStart</item>
         <item name="sudDividerInsetStartNoIcon">?attr/sudMarginStart</item>
         <item name="sudGlifSubtitleGravity">center_horizontal</item>
-        <item name="sudScrollIndicators">top|bottom</item>
+        <item name="sudScrollIndicators">none</item>
         <item name="sudEditTextBackgroundColor">@color/sud_glif_edit_text_bg_light_color</item>
         <item name="android:editTextStyle">@style/SudEditText</item>
         <item name="sucLightStatusBar" tools:targetApi="m">?android:attr/windowLightStatusBar</item>
@@ -958,15 +991,15 @@
         <item name="sucFooterBarPaddingVertical">@dimen/sud_glif_footer_bar_padding_vertical_material_you</item>
         <item name="sucFooterBarMinHeight">@dimen/sud_glif_footer_bar_min_height_material_you</item>
         <item name="sucFooterBarButtonAlignEnd">@bool/suc_footer_bar_button_align_end</item>
-        <item name="sucHeaderContainerMarginBottom">@dimen/sud_header_container_margin_bottom_material_you</item>
+        <item name="sucHeaderContainerMarginBottom">@dimen/sud_glif_expressive_header_container_margin_bottom</item>
         <item name="sudButtonTertiaryGravity">center_horizontal</item>
         <item name="sudGlifIconSize">@dimen/sud_glif_icon_max_height_material_you</item>
-        <item name="sudGlifAccountContainerStyle">@style/SudGlifAccountContainerMaterialYou</item>
+        <item name="sudGlifAccountContainerStyle">@style/SudGlifAccountContainerExpressive</item>
         <item name="sudGlifHeaderTitleStyle">@style/SudGlifHeaderTitleExpressive</item>
         <item name="sudGlifHeaderGravity">start</item>
         <item name="sudGlifIconGravity">center_horizontal</item>
         <item name="sucGlifHeaderMarginTop">@dimen/sud_glif_header_title_margin_top_material_you</item>
-        <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_header_title_margin_bottom_material_you</item>
+        <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_expressive_header_title_margin_bottom</item>
         <item name="sudGlifDescriptionStyle">@style/SudGlifDescriptionExpressive</item>
         <item name="sudGlifDescriptionMarginBottom">@dimen/sud_glif_expreesive_description_margin_bottom</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudMaterialYouDescription</item>
@@ -985,6 +1018,7 @@
         <item name="android:colorBackground" tools:ignore="NewApi">?attr/colorSurfaceContainer</item>
         <item name="sudMarginStart">@dimen/sud_glif_expressive_margin_start</item>
         <item name="sudMarginEnd">@dimen/sud_glif_expressive_margin_end</item>
+        <item name="sudBackButtonMarginStart">@dimen/sud_glif_expressive_back_button_margin_start</item>
         <item name="sucFooterButtonPaddingStart">@dimen/sud_glif_expressive_button_padding</item>
         <item name="sucFooterButtonPaddingEnd">@dimen/sud_glif_expressive_button_padding</item>
         <item name="sucGlifIconMarginTop">@dimen/sud_glif_expressive_icon_margin_top</item>
@@ -1022,6 +1056,7 @@
         <item name="sudNonActionableItemBackgroundColor" tools:ignore="NewApi">?attr/colorSurfaceContainerHigh</item>
         <item name="sudItemTitleStyle">@style/SudItemTitleExpressive</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryExpressive</item>
+        <item name="sudItemMoreInfoStyle">@style/SudItemMoreInfoExpressive</item>
         <item name="sudItemSummaryPaddingTop">@dimen/sud_items_summary_margin_top_expressive</item>
         <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width_expressive</item>
         <item name="sucFooterBarButtonFontWeight">@integer/sud_glif_expressive_footer_button_weight</item>
@@ -1035,12 +1070,12 @@
         <item name="sudInfoFooterContainerStyle">@style/sudInfoFooterContainerExpressive</item>
         <item name="sudInfoFooterIconContainerStyle">@style/sudInfoFooterIconContainer</item>
         <item name="sudInfoFooterIconStyle">@style/sudInfoFooterIconExpressive</item>
-        <item name="sudInfoFooterTitleStyle">@style/sudInfoFooterTitle</item>
+        <item name="sudInfoFooterTitleStyle">@style/sudInfoFooterTitleExpressive</item>
         <item name="sudItemIconContainerStyle">@style/SudExpressiveItemIconContainer</item>
         <item name="textAppearanceListItem">@style/TextAppearance.SudExpressiveItemTitle</item>
         <item name="textAppearanceListItemSmall">@style/TextAppearance.SudExpressiveItemSummary</item>
         <item name="materialAlertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
-        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointTitleStyle">@style/SudBulletPointTitle</item>
         <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
         <item name="sudSectionItemContainerStyle">@style/SudGlifExpressiveItemContainer.SectionItem</item>
         <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
@@ -1059,6 +1094,11 @@
         <item name="sudItemIconStyle">@style/SudExpressiveItemIcon</item>
         <item name="sudCameraPreviewStyle">@style/SudExpressiveCameraPreview</item>
         <item name="sudQrFinishStyle">@style/SudExpressiveQrFinish</item>
+        <item name="sudItemIconDefaultTint">@color/sud_system_on_surface_variant_light</item>
+        <item name="sudItemRadioButtonStyle">@style/SudExpressiveItemRadioButton</item>
+        <item name="sudTextAppearanceBulletPoint">@style/TextAppearance.SudBulletPoint</item>
+        <item name="sudClipChildren">false</item>
+        <item name="sudClipToPadding">false</item>
     </style>
 
     <style name="SudThemeGlifExpressive" parent="SudBaseThemeGlifExpressive" />
@@ -1508,9 +1548,17 @@
     <style name="SudPromoItemTitle">
         <item name="android:textAppearance">?attr/textAppearanceListItem</item>
         <item name="android:layout_marginBottom">@dimen/sud_items_summary_margin_top</item>
+        <item name="android:lineHeight" tools:targetApi="28">@dimen/sud_glif_promo_card_title_line_height</item>
+        <item name="android:textFontWeight" tools:targetApi="28">500</item>
+        <item name="fontFamily">google-sans-flex</item>
+        <item name="android:fontFamily">google-sans-flex</item>
+        <item name="fontVariationSettings">\'CRSV\' 0.0, \'FILL\' 0.0, \'GRAD\' 0.0, \'HEXP\' 0.0, \'ROND\' 100.0, \'opsz\' 16.0, \'slnt\' 0.0, \'wdth\' 100.0, \'wght\' 600.0</item>
+        <item name="android:fontVariationSettings" tools:targetApi="28">\'CRSV\' 0.0, \'FILL\' 0.0, \'GRAD\' 0.0, \'HEXP\' 0.0, \'ROND\' 100.0, \'opsz\' 16.0, \'slnt\' 0.0, \'wdth\' 100.0, \'wght\' 600.0</item>
     </style>
+
     <style name="SudPromoItemSummary">
         <item name="android:textAppearance">?attr/textAppearanceListItemSmall</item>
+        <item name="android:lineHeight" tools:targetApi="28">@dimen/sud_glif_promo_card_summary_line_height</item>
     </style>
 
     <style name="SudItemContainer.IllustrationItem" parent="SudItemContainer">
@@ -1544,15 +1592,44 @@
 
     <style name="SudItemSummaryExpressive">
         <item name="android:textAppearance">?attr/textAppearanceListItemSmall</item>
+        <item name="android:lineHeight" tools:targetApi="28">@dimen/sud_glif_expressive_item_summary_line_height</item>
         <item name="android:layout_marginBottom">?attr/sudItemSummaryPaddingBottom</item>
     </style>
 
+    <style name="SudItemMoreInfoExpressive">
+        <item name="android:textAppearance">?attr/textAppearanceListItemSmall</item>
+        <item name="android:lineHeight" tools:targetApi="28">@dimen/sud_glif_expressive_item_summary_line_height</item>
+        <item name="android:layout_marginBottom">?attr/sudItemSummaryPaddingBottom</item>
+        <item name="fontFamily">google-sans-flex</item>
+        <item name="android:fontFamily">google-sans-flex</item>
+        <item name="fontVariationSettings">\'CRSV\' 0.0, \'FILL\' 0.0, \'GRAD\' 0.0, \'HEXP\' 0.0, \'ROND\' 100.0, \'opsz\' 16.0, \'slnt\' 0.0, \'wdth\' 100.0, \'wght\' 500.0</item>
+        <item name="android:fontVariationSettings" tools:targetApi="28">\'CRSV\' 0.0, \'FILL\' 0.0, \'GRAD\' 0.0, \'HEXP\' 0.0, \'ROND\' 100.0, \'opsz\' 16.0, \'slnt\' 0.0, \'wdth\' 100.0, \'wght\' 500.0</item>
+    </style>
+
     <style name="SudItemContainerMaterialYou.Description" parent="SudItemContainerMaterialYou">
         <item name="android:minHeight">0dp</item>
         <item name="android:paddingTop">?attr/sudItemPaddingTop</item>
         <item name="android:paddingBottom">?attr/sudItemPaddingBottom</item>
     </style>
 
+    <style name="SudItemRadioButton">
+        <item name="android:paddingEnd">@dimen/sud_items_radio_button_padding_end</item>
+        <item name="android:paddingRight">@dimen/sud_items_radio_button_padding_end</item>
+    </style>
+
+    <!-- the expressive style for Item Radio button wiil provided by the material theme-->
+    <style name="SudExpressiveItemRadioButton" />
+
+    <style name="TextAppearance.SudBulletPoint" parent="android:TextAppearance">
+        <item name="android:textSize">@dimen/sud_bullet_point_title_text_size</item>
+        <item name="android:fontFamily">@string/sudFontExpressive</item>
+        <item name="android:textColor">?android:attr/textColorPrimary</item>
+    </style>
+
+    <style name="SudBulletPointTitle">
+        <item name="android:textAppearance">?attr/sudTextAppearanceBulletPoint</item>
+    </style>
+
     <style name="SudItemTitle">
         <item name="android:textAppearance">?attr/textAppearanceListItem</item>
     </style>
@@ -1563,7 +1640,13 @@
 
     <style name="SudItemTitleExpressive">
         <item name="android:textAppearance">?attr/textAppearanceListItem</item>
+        <item name="android:lineHeight" tools:targetApi="28">@dimen/sud_glif_expressive_item_title_line_height</item>
         <item name="android:layout_marginBottom">?attr/sudItemSummaryPaddingTop</item>
+        <item name="android:textFontWeight" tools:targetApi="28">500</item>
+        <item name="fontFamily">google-sans-flex</item>
+        <item name="android:fontFamily">google-sans-flex</item>
+        <item name="fontVariationSettings">\'CRSV\' 0.0, \'FILL\' 0.0, \'GRAD\' 0.0, \'HEXP\' 0.0, \'ROND\' 100.0, \'opsz\' 16.0, \'slnt\' 0.0, \'wdth\' 100.0, \'wght\' 500.0</item>
+        <item name="android:fontVariationSettings" tools:targetApi="28">\'CRSV\' 0.0, \'FILL\' 0.0, \'GRAD\' 0.0, \'HEXP\' 0.0, \'ROND\' 100.0, \'opsz\' 16.0, \'slnt\' 0.0, \'wdth\' 100.0, \'wght\' 500.0</item>
     </style>
 
     <style name="SudItemTitle.GlifDescription" parent="SudItemTitle">
@@ -1586,8 +1669,12 @@
 
     <style name="SudExpressiveItemTitle.SectionHeader" parent="SudItemTitle">
         <item name="android:textSize">@dimen/sud_items_section_header_text_size</item>
-        <item name="android:fontFamily">@string/sudFontSecondaryMedium</item>
         <item name="android:textColor">?attr/colorOnSurfaceVariant</item>
+        <item name="android:textFontWeight" tools:targetApi="28">500</item>
+        <item name="fontFamily">google-sans-flex</item>
+        <item name="android:fontFamily">google-sans-flex</item>
+        <item name="fontVariationSettings">\'CRSV\' 0.0, \'FILL\' 0.0, \'GRAD\' 0.0, \'HEXP\' 0.0, \'ROND\' 100.0, \'opsz\' 16.0, \'slnt\' 0.0, \'wdth\' 100.0, \'wght\' 500.0</item>
+        <item name="android:fontVariationSettings" tools:targetApi="28">\'CRSV\' 0.0, \'FILL\' 0.0, \'GRAD\' 0.0, \'HEXP\' 0.0, \'ROND\' 100.0, \'opsz\' 16.0, \'slnt\' 0.0, \'wdth\' 100.0, \'wght\' 500.0</item>
     </style>
 
     <style name="SudSwitchStyle">
@@ -1658,6 +1745,9 @@
         <item name="android:textFontWeight" tools:targetApi="28">500</item>
         <item name="fontFamily">google-sans-flex</item>
         <item name="android:fontFamily">google-sans-flex</item>
+        <item name="fontVariationSettings">\'CRSV\' 0.0, \'FILL\' 0.0, \'GRAD\' 0.0, \'HEXP\' 0.0, \'ROND\' 100.0, \'opsz\' 16.0, \'slnt\' 0.0, \'wdth\' 100.0, \'wght\' 500.0</item>
+        <item name="android:fontVariationSettings" tools:targetApi="28">\'CRSV\' 0.0, \'FILL\' 0.0, \'GRAD\' 0.0, \'HEXP\' 0.0, \'ROND\' 100.0, \'opsz\' 16.0, \'slnt\' 0.0, \'wdth\' 100.0, \'wght\' 500.0</item>
+        <item name="android:hyphenationFrequency" tools:targetApi="23">normal</item>
     </style>
 
     <style name="SudGlifDescription" parent="SudDescription.Glif">
@@ -1688,9 +1778,20 @@
         <item name="android:textSize">@dimen/sud_glif_description_text_size_material_you</item>
     </style>
 
-    <style name="SudGlifDescriptionExpressive" parent="SudGlifDescriptionMaterialYou">
+    <style name="SudGlifDescriptionExpressive">
+        <item name="fontFamily">google-sans-flex</item>
+        <item name="android:lineHeight" tools:targetApi="28">@dimen/sud_glif_expressive_description_line_height</item>
+        <item name="android:gravity">?attr/sudGlifHeaderGravity</item>
+        <item name="android:textAlignment">gravity</item>
+        <item name="android:layout_marginTop">?attr/sudGlifDescriptionMarginTop</item>
+        <item name="android:layout_marginBottom">?attr/sudGlifDescriptionMarginBottom</item>
+        <item name="android:layout_marginLeft">?attr/sudMarginStart</item>
+        <item name="android:layout_marginStart">?attr/sudMarginStart</item>
+        <item name="android:layout_marginRight">?attr/sudMarginEnd</item>
+        <item name="android:layout_marginEnd">?attr/sudMarginEnd</item>
+        <item name="android:textColor">?android:attr/textColorPrimary</item>
+        <item name="android:textDirection">locale</item>
         <item name="android:textSize">@dimen/sud_glif_expressive_description_text_size</item>
-        <item name="android:lineSpacingExtra">@dimen/sud_glif_expressive_description_line_spacing_extra</item>
     </style>
 
     <style name="SudGlifAccountContainerMaterialYou">
@@ -1703,6 +1804,11 @@
         <item name="android:gravity">?attr/sudGlifHeaderGravity</item>
     </style>
 
+    <style name="SudGlifAccountContainerExpressive" parent="SudGlifAccountContainerMaterialYou">
+        <item name="android:layout_marginTop">@dimen/sud_glif_expressive_account_container_margin_top</item>
+        <item name="android:layout_marginBottom">@dimen/sud_glif_expressive_account_container_margin_bottom</item>
+    </style>
+
     <style name="SudGlifAccountAvatar">
         <!--TODO create sudAccountAvatarMarginStart to let it as a pair with sudAccountAvatarMarginEnd -->
         <item name="android:layout_marginRight">?attr/sudAccountAvatarMarginEnd</item>
@@ -1720,7 +1826,7 @@
     </style>
 
     <style name="SudGlifExpressiveAccountName">
-        <item name="android:fontFamily">@string/sudFontSecondaryText</item>
+        <item name="android:fontFamily">@string/sudFontExpressive</item>
         <item name="android:textSize">?attr/sudAccountNameTextSize</item>
         <item name="android:textColor">?attr/sudAccountNameTextColor</item>
         <item name="android:textFontWeight" tools:ignore="NewApi">@integer/sud_glif_account_name_text_font_weight</item>
@@ -1766,7 +1872,7 @@
     </style>
 
     <style name="SudGlifButtonContainer">
-        <item name="android:layout_marginStart" tools:ignore="NewApi">?attr/sudMarginStart</item>
+        <item name="android:layout_marginStart" tools:ignore="NewApi">?attr/sudBackButtonMarginStart</item>
         <item name="android:layout_marginTop">@dimen/sud_glif_expressive_back_button_margin_top</item>
     </style>
 
@@ -1805,7 +1911,7 @@
 
     <style name="TextAppearance.SudExpressiveItemSummary" parent="android:TextAppearance">
         <item name="android:textSize">@dimen/sud_items_summary_text_size_expressive</item>
-        <item name="android:fontFamily">@string/sudFontSecondaryText</item>
+        <item name="android:fontFamily">@string/sudFontExpressive</item>
         <item name="android:textColor">?android:attr/textColorSecondary</item>
     </style>
 
@@ -1818,9 +1924,9 @@
     <!-- Additional body text styles -->
 
     <style name="SudAdditionalBodyTextExpressive">
-        <item name="android:fontFamily">@string/sudFontSecondaryText</item>
+        <item name="android:fontFamily">@string/sudFontExpressive</item>
         <item name="android:textSize">@dimen/sud_glif_expressive_additional_body_text_size</item>
-        <item name="android:lineSpacingExtra">@dimen/sud_glif_expressive_additional_body_text_line_spacing_extra</item>
+        <item name="android:lineHeight" tools:targetApi="28">@dimen/sud_glif_expressive_additional_body_text_line_height</item>
         <item name="android:textColor">@color/sud_color_on_surface</item>
         <item name="android:paddingBottom">@dimen/sud_additional_body_text_padding_bottom</item>
     </style>
@@ -1859,10 +1965,14 @@
     </style>
 
     <style name="sudInfoFooterTitle">
-        <item name="android:textAppearance">?attr/textAppearanceListItem</item>
+        <item name="android:fontFamily">google-sans-text-regular</item>
         <item name="android:textSize">@dimen/sud_info_footer_text_size</item>
         <item name="android:textColor">@color/sud_color_on_surface</item>
-        <item name="android:lineSpacingExtra">@dimen/sud_info_footer_text_line_spacing_extra</item>
+        <item name="android:lineHeight" tools:targetApi="28">@dimen/sud_info_footer_text_line_height</item>
+    </style>
+
+   <style name="sudInfoFooterTitleExpressive" parent="sudInfoFooterTitle">
+        <item name="android:fontFamily">@string/sudFontExpressive</item>
     </style>
 
     <!-- Navigation bar styles -->
@@ -1965,9 +2075,7 @@
 
     <style name="SudExpressiveSwitchBarStyle">
         <item name="android:layout_gravity">center_vertical|end</item>
-        <item name="track">@drawable/sud_switch_track_selector</item>
-        <item name="android:track">@drawable/sud_switch_track_selector</item>
-        <item name="android:thumb">@drawable/sud_switch_thumb_selector</item>
+        <item name="thumbIcon">@drawable/sud_ic_switch_selector_expressive</item>
         <item name="android:switchMinWidth">@dimen/sud_switch_min_width</item>
         <item name="android:paddingStart">@dimen/sud_expressive_switch_padding_start</item>
         <item name="android:paddingLeft">@dimen/sud_expressive_switch_padding_start</item>
@@ -2013,6 +2121,7 @@
     <style name="SudCardTitleStyle">
         <item name="android:textSize">@dimen/sud_card_view_title_text_size</item>
         <item name="android:fontFamily">@string/sudCardViewFontFamily</item>
+        <item name="android:fontWeight" tools:targetApi="p">@dimen/sud_card_view_title_font_weight</item>
         <item name="android:lineSpacingExtra">@dimen/sud_card_view_title_line_spacing_extra</item>
         <item name="android:textColor">@color/sud_card_view_text_color</item>
         <item name="android:paddingTop">@dimen/sud_card_view_title_spacing_top</item>
diff --git a/main/src/com/google/android/setupdesign/GlifLayout.java b/main/src/com/google/android/setupdesign/GlifLayout.java
index f8943c4..b1855b5 100644
--- a/main/src/com/google/android/setupdesign/GlifLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifLayout.java
@@ -30,6 +30,8 @@ import android.os.Build.VERSION;
 import android.os.Build.VERSION_CODES;
 import android.os.Handler;
 import android.os.Looper;
+import android.os.Parcel;
+import android.os.Parcelable;
 import android.os.PersistableBundle;
 import android.util.AttributeSet;
 import android.util.TypedValue;
@@ -38,6 +40,7 @@ import android.view.View;
 import android.view.ViewGroup;
 import android.view.ViewStub;
 import android.view.ViewTreeObserver;
+import android.view.WindowInsets;
 import android.widget.LinearLayout;
 import android.widget.ProgressBar;
 import android.widget.ScrollView;
@@ -107,11 +110,14 @@ public class GlifLayout extends PartnerCustomizationLayout {
         @Override
         public void onScrollChanged() {
           ScrollView scrollView = getScrollView();
-          if (scrollView != null) {
-            // direction > 0 means view can scroll down, direction < 0 means view can scroll
-            // up. Here we use direction > 0 to detect whether the view can be scrolling down
-            // or not.
-            onScrolling(!scrollView.canScrollVertically(/* direction= */ 1));
+          ScrollView headerScrollView = getHeaderScrollView();
+
+          if (scrollView != null || headerScrollView != null) {
+            boolean canHeaderViewScrollDown = canViewScrollDown(headerScrollView);
+            boolean canViewScrollDown = canViewScrollDown(scrollView);
+            boolean canWholeViewsScrollDown = canHeaderViewScrollDown || canViewScrollDown;
+
+            onScrolling(!canWholeViewsScrollDown);
           }
         }
       };
@@ -239,6 +245,59 @@ public class GlifLayout extends PartnerCustomizationLayout {
     tryApplyPartnerCustomizationStyleToShortDescription();
   }
 
+  @Override
+  protected Parcelable onSaveInstanceState() {
+    Parcelable superState = super.onSaveInstanceState();
+    GlifSavedState savedState = new GlifSavedState(superState);
+    // save the state of the scroll to bottom
+    savedState.everScrolledToBottom = getMixin(RequireScrollMixin.class).isEverScrolledToBottom();
+    return savedState;
+  }
+
+  @Override
+  protected void onRestoreInstanceState(Parcelable state) {
+    if (!(state instanceof GlifSavedState savedState)) {
+      super.onRestoreInstanceState(state);
+      return;
+    }
+    super.onRestoreInstanceState(savedState.getSuperState());
+    // assign the state of the scroll to bottom
+    getMixin(RequireScrollMixin.class)
+        .onRestoreEverScrolledToBottom(savedState.everScrolledToBottom);
+  }
+
+  static class GlifSavedState extends BaseSavedState {
+    boolean everScrolledToBottom = false;
+
+    GlifSavedState(Parcelable superState) {
+      super(superState);
+    }
+
+    private GlifSavedState(Parcel in) {
+      super(in);
+      this.everScrolledToBottom = (in.readInt() == 1);
+    }
+
+    @Override
+    public void writeToParcel(Parcel out, int flags) {
+      super.writeToParcel(out, flags);
+      out.writeInt(this.everScrolledToBottom ? 1 : 0);
+    }
+
+    public static final Parcelable.Creator<GlifSavedState> CREATOR =
+        new Parcelable.Creator<GlifSavedState>() {
+          @Override
+          public GlifSavedState createFromParcel(Parcel in) {
+            return new GlifSavedState(in);
+          }
+
+          @Override
+          public GlifSavedState[] newArray(int size) {
+            return new GlifSavedState[size];
+          }
+        };
+  }
+
   private void updateViewFocusable() {
     if (KeyboardHelper.isKeyboardFocusEnhancementEnabled(getContext())) {
       View headerView = this.findManagedViewById(R.id.sud_header_scroll_view);
@@ -265,6 +324,18 @@ public class GlifLayout extends PartnerCustomizationLayout {
     }
   }
 
+  protected boolean canViewScrollDown(ScrollView scrollView) {
+    if (scrollView == null) {
+      // If the scroll view is null, it means the view is not scrollable. So we should return true
+      // to indicate that the view is at the bottom.
+      return false;
+    }
+    // direction > 0 means view can scroll down, direction < 0 means view can scroll
+    // up. Here we use direction > 0 to detect whether the view can be scrolling down
+    // or not.
+    return scrollView != null && scrollView.canScrollVertically(/* direction= */ 1);
+  }
+
   protected void updateLandscapeMiddleHorizontalSpacing() {
     int horizontalSpacing =
         getResources().getDimensionPixelSize(R.dimen.sud_glif_land_middle_horizontal_spacing);
@@ -294,7 +365,7 @@ public class GlifLayout extends PartnerCustomizationLayout {
       }
       int paddingEnd = (horizontalSpacing / 2) - layoutMarginEnd;
       if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
-        headerView.setPadding(
+        headerView.setPaddingRelative(
             headerView.getPaddingStart(),
             headerView.getPaddingTop(),
             paddingEnd,
@@ -328,7 +399,7 @@ public class GlifLayout extends PartnerCustomizationLayout {
         paddingStart = (horizontalSpacing / 2) - layoutMarginStart;
       }
       if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
-        contentView.setPadding(
+        contentView.setPaddingRelative(
             paddingStart,
             contentView.getPaddingTop(),
             contentView.getPaddingEnd(),
@@ -398,6 +469,11 @@ public class GlifLayout extends PartnerCustomizationLayout {
     if (scrollView != null) {
       scrollView.getViewTreeObserver().removeOnScrollChangedListener(onScrollChangedListener);
     }
+
+    ScrollView headerScrollView = getHeaderScrollView();
+    if (headerScrollView != null) {
+      headerScrollView.getViewTreeObserver().removeOnScrollChangedListener(onScrollChangedListener);
+    }
   }
 
   /**
@@ -414,9 +490,20 @@ public class GlifLayout extends PartnerCustomizationLayout {
     return stickyHeaderStub.inflate();
   }
 
+  /** Returns the scroll view of the header. */
+  @Nullable
+  public ScrollView getHeaderScrollView() {
+    final View view = findManagedViewById(R.id.sud_header_scroll_view);
+    return view instanceof ScrollView scrollView ? scrollView : null;
+  }
+
+  /**
+   * Returns the scroll view of the layout. In the two pane mode, the view is the content area.
+   * Otherwsie, it's the whole layout.
+   */
   public ScrollView getScrollView() {
     final View view = findManagedViewById(R.id.sud_scroll_view);
-    return view instanceof ScrollView ? (ScrollView) view : null;
+    return view instanceof ScrollView scrollView ? scrollView : null;
   }
 
   public TextView getHeaderTextView() {
@@ -476,6 +563,10 @@ public class GlifLayout extends PartnerCustomizationLayout {
     getMixin(IconMixin.class).setIcon(icon);
   }
 
+  public void setIconVisible(boolean visible) {
+    getMixin(IconMixin.class).setVisibility(visible ? View.VISIBLE : View.INVISIBLE);
+  }
+
   public Drawable getIcon() {
     return getMixin(IconMixin.class).getIcon();
   }
@@ -640,16 +731,22 @@ public class GlifLayout extends PartnerCustomizationLayout {
   // TODO: b/397835857 - Add unit test for initScrollingListener.
   protected void initScrollingListener() {
     ScrollView scrollView = getScrollView();
-
     if (scrollView != null) {
       scrollView.getViewTreeObserver().addOnScrollChangedListener(onScrollChangedListener);
+    }
+
+    ScrollView headerScrollView = getHeaderScrollView();
+    if (headerScrollView != null) {
+      headerScrollView.getViewTreeObserver().addOnScrollChangedListener(onScrollChangedListener);
+    }
 
+    if (scrollView != null || headerScrollView != null) {
       // This is for the case that the view has been first visited to handle the initial state of
       // the footer bar.
       new Handler(Looper.getMainLooper())
           .postDelayed(
               () -> {
-                if (isContentScrollable(scrollView)) {
+                if (isContentScrollable(scrollView) || isContentScrollable(headerScrollView)) {
                   onScrolling(/* isBottom= */ false);
                 }
               },
@@ -658,6 +755,10 @@ public class GlifLayout extends PartnerCustomizationLayout {
   }
 
   private boolean isContentScrollable(ScrollView scrollView) {
+    // No scroll view, so we can't scroll.
+    if (scrollView == null) {
+      return false;
+    }
     View child = scrollView.getChildAt(0);
     if (child != null) {
       return child.getHeight() > scrollView.getHeight();
@@ -715,6 +816,27 @@ public class GlifLayout extends PartnerCustomizationLayout {
     return typedValue.data;
   }
 
+  // TODO: b/398407478 - Add test case for edge to edge to layout from library.
+  @Override
+  public WindowInsets onApplyWindowInsets(WindowInsets insets) {
+    if (isGlifExpressiveEnabled()) {
+      View container = findManagedViewById(R.id.sud_layout_container);
+      if (container != null) {
+        container.setPadding(
+            insets.getSystemWindowInsetLeft(),
+            container.getPaddingTop(),
+            insets.getSystemWindowInsetRight(),
+            container.getPaddingBottom());
+      }
+      FooterBarMixin footerBarMixin = getMixin(FooterBarMixin.class);
+      if (footerBarMixin != null) {
+        footerBarMixin.setWindowInsets(
+            insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetRight());
+      }
+    }
+    return super.onApplyWindowInsets(insets);
+  }
+
   protected boolean isGlifExpressiveEnabled() {
     return PartnerConfigHelper.isGlifExpressiveEnabled(getContext())
         && Build.VERSION.SDK_INT >= VERSION_CODES.VANILLA_ICE_CREAM;
diff --git a/main/src/com/google/android/setupdesign/GlifListLayout.java b/main/src/com/google/android/setupdesign/GlifListLayout.java
index bcae593..563f03f 100644
--- a/main/src/com/google/android/setupdesign/GlifListLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifListLayout.java
@@ -24,10 +24,12 @@ import android.util.AttributeSet;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
+import android.view.ViewTreeObserver;
 import android.widget.AbsListView;
 import android.widget.AbsListView.OnScrollListener;
 import android.widget.ListAdapter;
 import android.widget.ListView;
+import android.widget.ScrollView;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.util.ForceTwoPaneHelper;
 import com.google.android.setupdesign.template.ListMixin;
@@ -41,6 +43,8 @@ import com.google.android.setupdesign.template.RequireScrollMixin;
 public class GlifListLayout extends GlifLayout {
 
   private ListMixin listMixin;
+  private ViewTreeObserver.OnScrollChangedListener onScrollChangedListener;
+  private OnScrollListener onListViewScrollListener;
 
   public GlifListLayout(Context context) {
     this(context, 0, 0);
@@ -87,6 +91,18 @@ public class GlifListLayout extends GlifLayout {
     initBackButton();
   }
 
+  private boolean canWholeViewsScrollDown(ScrollView headerScrollView, ListView listView) {
+    if (headerScrollView == null && listView == null) {
+      // No views to scroll down.
+      return false;
+    }
+
+    boolean canHeaderViewScrollDown = canViewScrollDown(headerScrollView);
+    boolean canListViewScrollDown = listView.canScrollVertically(/* direction= */ 1);
+
+    return canHeaderViewScrollDown || canListViewScrollDown;
+  }
+
   @Override
   protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
     super.onLayout(changed, left, top, right, bottom);
@@ -131,7 +147,7 @@ public class GlifListLayout extends GlifLayout {
     ListView listView = null;
     if (listMixin != null) {
       listView = listMixin.getListView();
-      listView.setOnScrollListener(
+      onListViewScrollListener =
           new OnScrollListener() {
             @Override
             public void onScrollStateChanged(AbsListView absListView, int i) {}
@@ -139,10 +155,37 @@ public class GlifListLayout extends GlifLayout {
             @Override
             public void onScroll(
                 AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
-              onScrolling(
-                  firstVisibleItem + visibleItemCount >= totalItemCount && totalItemCount > 0);
+              onScrolling(!canWholeViewsScrollDown(getHeaderScrollView(), listMixin.getListView()));
+            }
+          };
+      listView.setOnScrollListener(onListViewScrollListener);
+    }
+
+    ScrollView headerScrollView = getHeaderScrollView();
+    if (headerScrollView != null) {
+      onScrollChangedListener =
+          new ViewTreeObserver.OnScrollChangedListener() {
+            @Override
+            public void onScrollChanged() {
+              onScrolling(!canWholeViewsScrollDown(getHeaderScrollView(), listMixin.getListView()));
             }
-          });
+          };
+      headerScrollView.getViewTreeObserver().addOnScrollChangedListener(onScrollChangedListener);
+    }
+  }
+
+  @Override
+  protected void onDetachedFromWindow() {
+    super.onDetachedFromWindow();
+
+    ScrollView headerScrollView = getHeaderScrollView();
+    if (headerScrollView != null && headerScrollView.getViewTreeObserver() != null) {
+      headerScrollView.getViewTreeObserver().removeOnScrollChangedListener(onScrollChangedListener);
+    }
+
+    ListView listView = listMixin.getListView();
+    if (listView != null) {
+      listView.setOnScrollListener(null);
     }
   }
 
diff --git a/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java b/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java
index d0254ae..07bc86c 100644
--- a/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java
@@ -28,6 +28,8 @@ import android.util.AttributeSet;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
+import android.view.ViewTreeObserver;
+import android.widget.ScrollView;
 import androidx.annotation.NonNull;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.util.ForceTwoPaneHelper;
@@ -42,6 +44,8 @@ import com.google.android.setupdesign.template.RequireScrollMixin;
 public class GlifRecyclerLayout extends GlifLayout {
 
   protected RecyclerMixin recyclerMixin;
+  private RecyclerView.OnScrollListener onRecyclerViewScrollListener;
+  private ViewTreeObserver.OnScrollChangedListener onScrollChangedListener;
 
   public GlifRecyclerLayout(Context context) {
     this(context, 0, 0);
@@ -92,6 +96,18 @@ public class GlifRecyclerLayout extends GlifLayout {
     initBackButton();
   }
 
+  private boolean canWholeViewsScrollDown(ScrollView headerScrollView, RecyclerView recyclerView) {
+    if (headerScrollView == null && recyclerView == null) {
+      // No views to scroll down.
+      return false;
+    }
+
+    boolean canHeaderViewScrollDown = canViewScrollDown(headerScrollView);
+    boolean canRecyclerViewScrollDown = recyclerView.canScrollVertically(/* direction= */ 1);
+
+    return canHeaderViewScrollDown || canRecyclerViewScrollDown;
+  }
+
   @Override
   protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
     super.onLayout(changed, left, top, right, bottom);
@@ -157,21 +173,50 @@ public class GlifRecyclerLayout extends GlifLayout {
   protected void initScrollingListener() {
     RecyclerView recyclerView = getRecyclerView();
     if (recyclerView != null) {
-      recyclerView.addOnScrollListener(
+      // We only can initialize the listener here for some unknown reason instead of in global
+      // variable. Othersie, we will see a runtime error.
+      onRecyclerViewScrollListener =
           new OnScrollListener() {
             @Override
             public void onScrolled(@NonNull RecyclerView recyclerView, int dx, int dy) {
               super.onScrolled(recyclerView, dx, dy);
-              // direction > 0 means view can scroll down, direction < 0 means view can scroll up.
-              // Here we use direction > 0 to detect whether the view can be scrolling down or not.
-              boolean isAtBottom = !recyclerView.canScrollVertically(/* direction= */ 1);
-              onScrolling(isAtBottom);
+              onScrolling(!canWholeViewsScrollDown(getHeaderScrollView(), recyclerView));
+            }
+          };
+      recyclerView.addOnScrollListener(onRecyclerViewScrollListener);
+    }
+
+    ScrollView headerScrollView = getHeaderScrollView();
+    if (headerScrollView != null) {
+      // We only can initialize the listener here for some unknown reason instead of in global
+      // variable. Othersie, we will see a runtime error.
+      onScrollChangedListener =
+          new ViewTreeObserver.OnScrollChangedListener() {
+            @Override
+            public void onScrollChanged() {
+              onScrolling(!canWholeViewsScrollDown(getHeaderScrollView(), getRecyclerView()));
             }
-          });
+          };
+      headerScrollView.getViewTreeObserver().addOnScrollChangedListener(onScrollChangedListener);
+    }
+  }
+
+  @Override
+  protected void onDetachedFromWindow() {
+    super.onDetachedFromWindow();
+
+    ScrollView headerScrollView = getHeaderScrollView();
+    if (headerScrollView != null && headerScrollView.getViewTreeObserver() != null) {
+      headerScrollView.getViewTreeObserver().removeOnScrollChangedListener(onScrollChangedListener);
+    }
+
+    RecyclerView recyclerView = getRecyclerView();
+    if (recyclerView != null && onRecyclerViewScrollListener != null) {
+      recyclerView.removeOnScrollListener(onRecyclerViewScrollListener);
     }
   }
 
-  /** @see RecyclerMixin#setDividerItemDecoration(DividerItemDecoration) */
+  /** See {@link RecyclerMixin#setDividerItemDecoration(DividerItemDecoration)}. */
   public void setDividerItemDecoration(DividerItemDecoration decoration) {
     recyclerMixin.setDividerItemDecoration(decoration);
   }
diff --git a/main/src/com/google/android/setupdesign/items/ButtonItem.java b/main/src/com/google/android/setupdesign/items/ButtonItem.java
index c6ae916..1007ad1 100644
--- a/main/src/com/google/android/setupdesign/items/ButtonItem.java
+++ b/main/src/com/google/android/setupdesign/items/ButtonItem.java
@@ -168,6 +168,11 @@ public class ButtonItem extends AbstractItem implements View.OnClickListener {
     return (Button) LayoutInflater.from(context).inflate(R.layout.sud_button, null, false);
   }
 
+  @Override
+  public boolean isGroupDivider() {
+    return true;
+  }
+
   @Override
   public void onClick(View v) {
     if (listener != null) {
diff --git a/main/src/com/google/android/setupdesign/items/CheckBoxItem.java b/main/src/com/google/android/setupdesign/items/CheckBoxItem.java
index 0bfe917..cbb9551 100644
--- a/main/src/com/google/android/setupdesign/items/CheckBoxItem.java
+++ b/main/src/com/google/android/setupdesign/items/CheckBoxItem.java
@@ -20,9 +20,11 @@ import android.content.Context;
 import android.content.res.TypedArray;
 import android.util.AttributeSet;
 import android.view.View;
+import android.view.View.OnClickListener;
 import android.widget.CheckBox;
 import android.widget.CompoundButton;
 import com.google.android.setupdesign.R;
+import com.google.android.setupdesign.util.ThemeHelper;
 
 /**
  * An item that is displayed with a check box, with methods to manipulate and listen to the checked
@@ -30,7 +32,8 @@ import com.google.android.setupdesign.R;
  * state. To change the check box state when tapping on the text, use the click handlers of list
  * view or RecyclerItemAdapter with {@link #toggle(View)}.
  */
-public class CheckBoxItem extends Item implements CompoundButton.OnCheckedChangeListener {
+public class CheckBoxItem extends Item
+    implements CompoundButton.OnCheckedChangeListener, OnClickListener {
 
   /** Listener for check state changes of this check box item. */
   public interface OnCheckedChangeListener {
@@ -102,12 +105,19 @@ public class CheckBoxItem extends Item implements CompoundButton.OnCheckedChange
     checked = !checked;
     final CheckBox checkBoxView = (CheckBox) view.findViewById(R.id.sud_items_check_box);
     checkBoxView.setChecked(checked);
+    if (listener != null) {
+      listener.onCheckedChange(this, checked);
+    }
   }
 
   @Override
   public void onBindView(View view) {
     super.onBindView(view);
+    view.setOnClickListener(this);
     final CheckBox checkBoxView = (CheckBox) view.findViewById(R.id.sud_items_check_box);
+    if (ThemeHelper.shouldApplyGlifExpressiveStyle(view.getContext())) {
+      checkBoxView.setClickable(false);
+    }
     checkBoxView.setOnCheckedChangeListener(null);
     checkBoxView.setChecked(checked);
     checkBoxView.setOnCheckedChangeListener(this);
@@ -122,6 +132,11 @@ public class CheckBoxItem extends Item implements CompoundButton.OnCheckedChange
     this.listener = listener;
   }
 
+  @Override
+  public void onClick(View v) {
+    toggle(v);
+  }
+
   @Override
   public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
     checked = isChecked;
diff --git a/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java b/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java
index d8f2600..181a4da 100644
--- a/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java
+++ b/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java
@@ -200,16 +200,21 @@ public class ExpandableSwitchItem extends SwitchItem
 
     if (PartnerConfigHelper.isGlifExpressiveEnabled(view.getContext())) {
       View moreInfo = view.findViewById(R.id.sud_items_more_info);
+      View contentContainer = view.findViewById(R.id.sud_items_summary_container);
+      if (canExpanded) {
+        if (contentContainer != null) {
+          contentContainer.setOnClickListener(this);
+        }
+      }
       if (moreInfo != null) {
-        if (canExpanded) {
-          moreInfo.setOnClickListener(this);
-        } else {
+        if (!canExpanded) {
           moreInfo.setVisibility(View.GONE);
         }
       }
       View switchItem = view.findViewById(R.id.sud_items_switch);
-      if (!isSwitchItem && switchItem != null) {
-        switchItem.setVisibility(View.GONE);
+
+      if (switchItem != null) {
+        switchItem.setVisibility(isSwitchItem ? View.VISIBLE : View.INVISIBLE);
       }
     } else {
       View content = view.findViewById(R.id.sud_items_expandable_switch_content);
@@ -247,11 +252,20 @@ public class ExpandableSwitchItem extends SwitchItem
     }
   }
 
+  private void updateSummary(View view) {
+    TextView summary = view.findViewById(R.id.sud_items_summary);
+    if (summary != null) {
+      summary.setText(getSummary());
+    }
+  }
+
   @Override
   public void onClick(View v) {
     if (PartnerConfigHelper.isGlifExpressiveEnabled(v.getContext())) {
-      if (v.getId() == R.id.sud_items_more_info) {
+      if (v.getId() == R.id.sud_items_summary_container) {
         setExpanded(!isExpanded());
+        // update the text on the summary to make talkback announce again when click more info
+        updateSummary(v);
         updateShowMoreLinkText(v);
       }
     } else {
diff --git a/main/src/com/google/android/setupdesign/items/Item.java b/main/src/com/google/android/setupdesign/items/Item.java
index 0015916..e770ceb 100644
--- a/main/src/com/google/android/setupdesign/items/Item.java
+++ b/main/src/com/google/android/setupdesign/items/Item.java
@@ -70,6 +70,7 @@ public class Item extends AbstractItem implements LinkSpan.OnLinkClickListener {
   @Nullable private OnItemTextLinkClickListener itemTextLinkClickListener;
   private boolean visible = true;
   @ColorInt private int iconTint = Color.TRANSPARENT;
+  @ColorInt private int titleColor = Color.TRANSPARENT;
   private int iconGravity = Gravity.CENTER_VERTICAL;
 
   public Item() {
@@ -125,6 +126,15 @@ public class Item extends AbstractItem implements LinkSpan.OnLinkClickListener {
     return icon;
   }
 
+  public void setTitleColor(@ColorInt int titleColor) {
+    this.titleColor = titleColor;
+  }
+
+  @ColorInt
+  public int getTitleColor() {
+    return titleColor;
+  }
+
   public void setIconTint(@ColorInt int iconTint) {
     this.iconTint = iconTint;
   }
@@ -263,6 +273,10 @@ public class Item extends AbstractItem implements LinkSpan.OnLinkClickListener {
       iconContainer.setVisibility(View.GONE);
     }
 
+    if (titleColor != Color.TRANSPARENT) {
+      label.setTextColor(titleColor);
+    }
+
     view.setId(getViewId());
 
     // ExpandableSwitchItem uses its child view to apply the style SudItemContainer. It is not
diff --git a/main/src/com/google/android/setupdesign/items/RadioButtonItem.java b/main/src/com/google/android/setupdesign/items/RadioButtonItem.java
index e53fb5c..fa78715 100644
--- a/main/src/com/google/android/setupdesign/items/RadioButtonItem.java
+++ b/main/src/com/google/android/setupdesign/items/RadioButtonItem.java
@@ -20,17 +20,20 @@ import android.content.Context;
 import android.content.res.TypedArray;
 import android.util.AttributeSet;
 import android.view.View;
+import android.view.View.OnClickListener;
 import android.widget.CompoundButton;
 import com.google.android.material.radiobutton.MaterialRadioButton;
 import com.google.android.setupdesign.R;
+import com.google.android.setupdesign.util.ThemeHelper;
 
 /**
- * An item that is displayed with a radio button, with methods to manipulate and listen to the checked
- * state of the radio button. Note that by default, only click on the radio button will change the on-off
- * state. To change the radio button state when tapping on the text, use the click handlers of list
- * view or RecyclerItemAdapter with {@link #toggle(View)}.
+ * An item that is displayed with a radio button, with methods to manipulate and listen to the
+ * checked state of the radio button. Note that by default, only click on the radio button will
+ * change the on-off state. To change the radio button state when tapping on the text, use the click
+ * handlers of list view or RecyclerItemAdapter with {@link #toggle(View)}.
  */
-public class RadioButtonItem extends Item implements CompoundButton.OnCheckedChangeListener {
+public class RadioButtonItem extends Item
+    implements CompoundButton.OnCheckedChangeListener, OnClickListener {
 
   /** Listener for check state changes of this radio button item. */
   public interface OnCheckedChangeListener {
@@ -94,13 +97,20 @@ public class RadioButtonItem extends Item implements CompoundButton.OnCheckedCha
     checked = !checked;
     final MaterialRadioButton radioButtonView = (MaterialRadioButton) view.findViewById(R.id.sud_items_radio_button);
     radioButtonView.setChecked(checked);
+    if (listener != null) {
+      listener.onCheckedChange(this, checked);
+    }
   }
 
   @Override
   public void onBindView(View view) {
     super.onBindView(view);
+    view.setOnClickListener(this);
     final MaterialRadioButton radioButtonView =
         (MaterialRadioButton) view.findViewById(R.id.sud_items_radio_button);
+    if (ThemeHelper.shouldApplyGlifExpressiveStyle(view.getContext())) {
+      radioButtonView.setClickable(false);
+    }
     radioButtonView.setOnCheckedChangeListener(null);
     radioButtonView.setChecked(checked);
     radioButtonView.setOnCheckedChangeListener(this);
@@ -115,6 +125,13 @@ public class RadioButtonItem extends Item implements CompoundButton.OnCheckedCha
     this.listener = listener;
   }
 
+  @Override
+  public void onClick(View v) {
+    if (checked != true) {
+      toggle(v);
+    }
+  }
+
   @Override
   public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
     checked = isChecked;
diff --git a/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java b/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java
index da338ed..3cef527 100644
--- a/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java
+++ b/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java
@@ -31,6 +31,7 @@ import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.ViewOutlineProvider;
+import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 import com.google.android.setupcompat.partnerconfig.PartnerConfig;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
@@ -71,6 +72,7 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
   @VisibleForTesting public final boolean useFullDynamicColor;
   private OnItemSelectedListener listener;
   private RecyclerView recyclerView = null;
+  @Nullable private Float groupCornerRadiusExternal;
 
   public RecyclerItemAdapter(ItemHierarchy hierarchy) {
     this(hierarchy, false);
@@ -209,12 +211,13 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
 
   private Drawable getMiddleBackground(Context context, int position) {
     IItem item = getItem(position);
-    TypedArray a = context
-        .getTheme()
-        .obtainStyledAttributes(
-            item.isActionable()
-                ? new int[] {R.attr.sudItemBackground}
-                : new int[] {R.attr.sudNonActionableItemBackground});
+    TypedArray a =
+        context
+            .getTheme()
+            .obtainStyledAttributes(
+                item.isActionable()
+                    ? new int[] {R.attr.sudItemBackground}
+                    : new int[] {R.attr.sudNonActionableItemBackground});
     Drawable middleBackground = a.getDrawable(0);
     a.recycle();
     return middleBackground;
@@ -222,12 +225,13 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
 
   private Drawable getSingleBackground(Context context, int position) {
     IItem item = getItem(position);
-    TypedArray a = context
-        .getTheme()
-        .obtainStyledAttributes(
-            item.isActionable()
-                ? new int[] {R.attr.sudItemBackgroundSingle}
-                : new int[] {R.attr.sudNonActionableItemBackgroundSingle});
+    TypedArray a =
+        context
+            .getTheme()
+            .obtainStyledAttributes(
+                item.isActionable()
+                    ? new int[] {R.attr.sudItemBackgroundSingle}
+                    : new int[] {R.attr.sudNonActionableItemBackgroundSingle});
     Drawable singleBackground = a.getDrawable(0);
     a.recycle();
     return singleBackground;
@@ -249,6 +253,14 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
     return position == getItemCount() - 1 || getItem(position + 1).isGroupDivider();
   }
 
+  /**
+   * Sets the group corner radius for the list item group by an externally defined value. Used by
+   * clients which cannot access the partner config.
+   */
+  public void setGroupCornerRadiusExternal(float groupCornerRadius) {
+    groupCornerRadiusExternal = groupCornerRadius;
+  }
+
   public void updateBackground(View view, int position) {
     if (TAG_NO_BACKGROUND.equals(view.getTag())) {
       return;
@@ -257,8 +269,10 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
       return;
     }
     float groupCornerRadius =
-        PartnerConfigHelper.get(view.getContext())
-            .getDimension(view.getContext(), PartnerConfig.CONFIG_ITEMS_GROUP_CORNER_RADIUS);
+        groupCornerRadiusExternal != null
+            ? groupCornerRadiusExternal
+            : PartnerConfigHelper.get(view.getContext())
+                .getDimension(view.getContext(), PartnerConfig.CONFIG_ITEMS_GROUP_CORNER_RADIUS);
     float cornerRadius = getCornerRadius(view.getContext());
     Drawable drawable = view.getBackground();
     // TODO add test case for list item group corner partner config
diff --git a/main/src/com/google/android/setupdesign/items/SectionHeaderItem.java b/main/src/com/google/android/setupdesign/items/SectionHeaderItem.java
index e921b5f..dd5f7c5 100644
--- a/main/src/com/google/android/setupdesign/items/SectionHeaderItem.java
+++ b/main/src/com/google/android/setupdesign/items/SectionHeaderItem.java
@@ -16,9 +16,12 @@
 
 package com.google.android.setupdesign.items;
 
+import android.graphics.Color;
 import android.view.View;
 import android.widget.TextView;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupdesign.R;
+import com.google.android.setupdesign.util.LayoutStyler;
 
 /** A section header item that represents a default style or bluechip styles. */
 public class SectionHeaderItem extends Item implements Dividable {
@@ -30,6 +33,9 @@ public class SectionHeaderItem extends Item implements Dividable {
   @Override
   public void onBindView(View view) {
     TextView label = (TextView) view.findViewById(R.id.sud_items_title);
+    if (getTitleColor() != Color.TRANSPARENT) {
+      label.setTextColor(getTitleColor());
+    }
     label.setText(getTitle());
     TextView summaryView = (TextView) view.findViewById(R.id.sud_items_summary);
     CharSequence summary = getSummary();
@@ -43,6 +49,9 @@ public class SectionHeaderItem extends Item implements Dividable {
     view.findViewById(R.id.sud_items_icon_container).setVisibility(View.GONE);
     view.setContentDescription(getContentDescription());
     view.setClickable(/* clickable= */ false);
+    if (!PartnerConfigHelper.isGlifExpressiveEnabled(view.getContext())) {
+      LayoutStyler.applyPartnerCustomizationLayoutPaddingStyle(view);
+    }
   }
 
   private boolean hasSummary(CharSequence summary) {
diff --git a/main/src/com/google/android/setupdesign/items/SectionItem.java b/main/src/com/google/android/setupdesign/items/SectionItem.java
index db2f567..2fbf997 100644
--- a/main/src/com/google/android/setupdesign/items/SectionItem.java
+++ b/main/src/com/google/android/setupdesign/items/SectionItem.java
@@ -18,7 +18,9 @@ package com.google.android.setupdesign.items;
 
 import android.content.Context;
 import android.content.res.TypedArray;
+import android.graphics.Color;
 import android.util.AttributeSet;
+import androidx.annotation.ColorInt;
 import com.google.android.setupdesign.R;
 
 /**
@@ -40,10 +42,14 @@ public class SectionItem extends ItemGroup {
     super(context, attrs);
     TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudSectionItem);
     CharSequence headerText = a.getText(R.styleable.SudSectionItem_android_title);
+    @ColorInt
+    int titleColor =
+        a.getColor(R.styleable.SudSectionItem_sudSectionHeaderColor, Color.TRANSPARENT);
     a.recycle();
     header = new SectionHeaderItem();
     header.setTitle(headerText);
     header.setVisible(false);
+    header.setTitleColor(titleColor);
     addChild(header);
   }
 
@@ -74,6 +80,13 @@ public class SectionItem extends ItemGroup {
     refreshHeader();
   }
 
+  @Override
+  public void clear() {
+    super.clear();
+    addChild(header);
+    refreshHeader();
+  }
+
   private void refreshHeader() {
     if (header.isVisible()) {
       if (getCount() == 1) {
diff --git a/main/src/com/google/android/setupdesign/items/SwitchItem.java b/main/src/com/google/android/setupdesign/items/SwitchItem.java
index 862197e..dab8036 100644
--- a/main/src/com/google/android/setupdesign/items/SwitchItem.java
+++ b/main/src/com/google/android/setupdesign/items/SwitchItem.java
@@ -18,11 +18,16 @@ package com.google.android.setupdesign.items;
 
 import android.content.Context;
 import android.content.res.TypedArray;
+import android.os.Build.VERSION_CODES;
+import android.os.Build.VERSION;
 import androidx.appcompat.widget.SwitchCompat;
 import android.util.AttributeSet;
 import android.view.View;
 import android.widget.CompoundButton;
+import androidx.annotation.RequiresApi;
+import com.google.android.material.materialswitch.MaterialSwitch;
 import com.google.android.setupdesign.R;
+import com.google.android.setupdesign.util.ThemeHelper;
 
 /**
  * An item that is displayed with a switch, with methods to manipulate and listen to the checked
@@ -94,6 +99,10 @@ public class SwitchItem extends Item implements CompoundButton.OnCheckedChangeLi
     checked = !checked;
     final SwitchCompat switchView = (SwitchCompat) view.findViewById(R.id.sud_items_switch);
     switchView.setChecked(checked);
+    if (ThemeHelper.shouldApplyGlifExpressiveStyle(view.getContext())
+        && VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP) {
+      updateThumbIconDrawable(switchView, checked);
+    }
   }
 
   @Override
@@ -102,6 +111,11 @@ public class SwitchItem extends Item implements CompoundButton.OnCheckedChangeLi
     final SwitchCompat switchView = (SwitchCompat) view.findViewById(R.id.sud_items_switch);
     switchView.setOnCheckedChangeListener(null);
     switchView.setChecked(checked);
+
+    if (ThemeHelper.shouldApplyGlifExpressiveStyle(view.getContext())
+        && VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP) {
+      updateThumbIconDrawable(switchView, checked);
+    }
     switchView.setOnCheckedChangeListener(this);
     switchView.setEnabled(isEnabled());
   }
@@ -117,8 +131,24 @@ public class SwitchItem extends Item implements CompoundButton.OnCheckedChangeLi
   @Override
   public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
     checked = isChecked;
+    if (ThemeHelper.shouldApplyGlifExpressiveStyle(buttonView.getContext())
+        && VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP) {
+      updateThumbIconDrawable(buttonView, isChecked);
+    }
     if (listener != null) {
       listener.onCheckedChange(this, isChecked);
     }
   }
+
+  @RequiresApi(VERSION_CODES.LOLLIPOP)
+  private void updateThumbIconDrawable(View view, boolean checked) {
+    if (view instanceof MaterialSwitch materialSwitch) {
+      if (checked) {
+        materialSwitch.setThumbIconDrawable(
+            view.getContext().getDrawable(R.drawable.sud_ic_switch_selector_expressive));
+      } else {
+        materialSwitch.setThumbIconDrawable(null);
+      }
+    }
+  }
 }
diff --git a/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java b/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java
index f940803..4adc911 100644
--- a/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java
+++ b/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java
@@ -34,7 +34,6 @@ import com.google.android.setupcompat.internal.TemplateLayout;
 import com.google.android.setupcompat.template.Mixin;
 import com.google.android.setupdesign.R;
 import com.google.android.setupdesign.util.HeaderAreaStyler;
-import com.google.android.setupdesign.util.LayoutStyler;
 import com.google.android.setupdesign.util.PartnerStyleHelper;
 
 /** A {@link Mixin} for controlling back button on the template layout. */
@@ -111,7 +110,6 @@ public class FloatingBackButtonMixin implements Mixin {
   public void tryApplyPartnerCustomizationStyle() {
     if (PartnerStyleHelper.shouldApplyPartnerResource(templateLayout)
         && getContainerView() != null) {
-      LayoutStyler.applyPartnerCustomizationExtraPaddingStyle(getContainerView());
       HeaderAreaStyler.applyPartnerCustomizationBackButtonStyle(getContainerView());
     }
   }
diff --git a/main/src/com/google/android/setupdesign/template/ProgressBarMixin.java b/main/src/com/google/android/setupdesign/template/ProgressBarMixin.java
index 06e3484..7e69d59 100644
--- a/main/src/com/google/android/setupdesign/template/ProgressBarMixin.java
+++ b/main/src/com/google/android/setupdesign/template/ProgressBarMixin.java
@@ -127,7 +127,11 @@ public class ProgressBarMixin implements Mixin {
     } else {
       View progressBar = peekProgressBar();
       if (progressBar != null) {
+        if (isGlifExpressiveEnabled) {
+          progressBar.setVisibility(View.GONE);
+        } else {
         progressBar.setVisibility(useBottomProgressBar ? View.INVISIBLE : View.GONE);
+        }
       }
     }
   }
diff --git a/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java b/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java
index 6d6f2a2..4ed3baf 100644
--- a/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java
+++ b/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java
@@ -26,9 +26,11 @@ import android.view.View;
 import android.view.View.OnClickListener;
 import android.widget.Button;
 import android.widget.LinearLayout;
+import android.widget.ScrollView;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.StringRes;
+import androidx.annotation.VisibleForTesting;
 import com.google.android.material.button.MaterialButton;
 import com.google.android.setupcompat.internal.TemplateLayout;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
@@ -193,11 +195,24 @@ public class RequireScrollMixin implements Mixin {
       @Nullable OnClickListener onClickListener) {
     final CharSequence nextText = button.getText();
     button.setOnClickListener(createOnClickListener(onClickListener));
+
+    ScrollView scrollView = ((GlifLayout) templateLayout).getScrollView();
+    if (scrollView != null) {
+      scrollView.post(
+          () -> {
+            // Check if the scroll view is not scrollable.
+            if (!isScrollViewScrollable(scrollView)) {
+              setEverScrolledToBottom(true);
+              button.setText(nextText);
+            }
+          });
+    }
+
     setOnRequireScrollStateChangedListener(
         new OnRequireScrollStateChangedListener() {
           @Override
           public void onRequireScrollStateChanged(boolean scrollNeeded) {
-            button.setText(scrollNeeded ? moreText : nextText);
+            button.setText(!isEverScrolledToBottom() ? moreText : nextText);
           }
         });
     requireScroll();
@@ -254,12 +269,24 @@ public class RequireScrollMixin implements Mixin {
       requireScrollWithDownButton(context, onClickListener);
     } else {
       final CharSequence nextText = button.getText();
+      ScrollView scrollView = ((GlifLayout) templateLayout).getScrollView();
+      if (scrollView != null) {
+        scrollView.post(
+            () -> {
+              // Check if the scroll view is not scrollable.
+              if (!isScrollViewScrollable(scrollView)) {
+                setEverScrolledToBottom(true);
+                button.setText(nextText);
+              }
+            });
+      }
+
       button.setOnClickListener(createOnClickListener(onClickListener));
       setOnRequireScrollStateChangedListener(
           new OnRequireScrollStateChangedListener() {
             @Override
             public void onRequireScrollStateChanged(boolean scrollNeeded) {
-              button.setText(scrollNeeded ? moreText : nextText);
+              button.setText(!isEverScrolledToBottom() ? moreText : nextText);
             }
           });
       requireScroll();
@@ -331,13 +358,28 @@ public class RequireScrollMixin implements Mixin {
       requireScrollWithDownButton(context, onClickListener);
     } else {
       final CharSequence nextText = primaryButton.getText();
+      ScrollView scrollView = ((GlifLayout) templateLayout).getScrollView();
+      if (scrollView != null) {
+        scrollView.post(
+            () -> {
+              // Check if the scroll view is not scrollable.
+              if (!isScrollViewScrollable(scrollView)) {
+                setEverScrolledToBottom(true);
+
+                primaryButton.setText(nextText);
+                secondaryButton.setVisibility(View.VISIBLE);
+              }
+            });
+      }
+
       primaryButton.setOnClickListener(createOnClickListener(onClickListener));
+      // TODO: b/422071888 - Consider to make scrollView as a callback in the RequireScrollMixin.
       setOnRequireScrollStateChangedListener(
           new OnRequireScrollStateChangedListener() {
             @Override
             public void onRequireScrollStateChanged(boolean scrollNeeded) {
-              primaryButton.setText(scrollNeeded ? moreText : nextText);
-              secondaryButton.setVisibility(scrollNeeded ? View.GONE : View.VISIBLE);
+              primaryButton.setText(!isEverScrolledToBottom() ? moreText : nextText);
+              secondaryButton.setVisibility(!isEverScrolledToBottom() ? View.GONE : View.VISIBLE);
             }
           });
       requireScroll();
@@ -354,42 +396,123 @@ public class RequireScrollMixin implements Mixin {
     primaryButtonView.setOnClickListener(createOnClickListener(onClickListener));
     footerBarMixin.setButtonWidthForExpressiveStyle();
     LinearLayout footerContainer = footerBarMixin.getButtonContainer();
+    CharSequence contentDescription = primaryButtonView.getContentDescription();
+    int initialFooterPaddingStart = footerContainer.getPaddingStart();
+
+    // Handle the case if the scroll view cannot scrollable, then show buttons when first landed on
+    // the screen.
+    ScrollView scrollView = ((GlifLayout) templateLayout).getScrollView();
+    if (scrollView != null) {
+      scrollView.post(
+          () -> {
+            // Check if the scroll view is not scrollable.
+            if (!scrollView.canScrollVertically(1)) {
+              // Set the state for indicating the scroll view has scrolled to bottom because for
+              // this case the scroll is not needed.
+              setEverScrolledToBottom(true);
+
+              // Set the secondary button as visible if it exists.
+              if (secondaryButtonView != null) {
+                secondaryButtonView.setVisibility(View.VISIBLE);
+              }
+              // Set the primary button as common button style.
+              setupPrimaryButtonStyleWhenReachedToBottom(
+                  primaryButtonView,
+                  nextText,
+                  footerContainer,
+                  contentDescription,
+                  initialFooterPaddingStart,
+                  footerBarMixin);
+            } else {
+              if (secondaryButtonView == null) {
+                return;
+              }
+              // Set the secondary button as visible if screen has never scrolled to the bottom. If
+              // the screen has ever scrolled to the bottom, the secondary button will be set as
+              // gone.
+              if (isEverScrolledToBottom()) {
+                secondaryButtonView.setVisibility(View.VISIBLE);
+              } else {
+                secondaryButtonView.setVisibility(View.GONE);
+              }
+            }
+          });
+    }
 
     setOnRequireScrollStateChangedListener(
         scrollNeeded -> {
-          if (scrollNeeded) {
+          if (!isEverScrolledToBottom()) {
             generateGlifExpressiveDownButton(context, primaryButtonView, footerBarMixin);
             footerContainer.setBackgroundColor(
                 ((GlifLayout) templateLayout).getFooterBackgroundColorFromStyle());
           } else {
-            // Switch style to glif expressive common button.
-            if (primaryButtonView instanceof MaterialButton) {
-              ((MaterialButton) primaryButtonView).setIcon(null);
-              primaryButtonView.setText(nextText);
-              footerBarMixin.setButtonWidthForExpressiveStyle();
-              // Screen no need to scroll, sets the secondary button as visible if it exists.
-              if (secondaryButtonView != null) {
-                secondaryButtonView.setVisibility(View.VISIBLE);
-              }
-              footerContainer.setBackgroundColor(Color.TRANSPARENT);
-            } else {
-              Log.i(LOG_TAG, "Cannot clean up icon for the button. Skipping set text.");
-            }
+            setupPrimaryButtonStyleWhenReachedToBottom(
+                primaryButtonView,
+                nextText,
+                footerContainer,
+                contentDescription,
+                initialFooterPaddingStart,
+                footerBarMixin);
           }
         });
     primaryButtonView.setVisibility(View.VISIBLE);
     requireScroll();
   }
 
-  private void generateGlifExpressiveDownButton(
+  private void setupPrimaryButtonStyleWhenReachedToBottom(
+      Button primaryButtonView,
+      CharSequence nextText,
+      LinearLayout footerContainer,
+      CharSequence contentDescription,
+      int initialFooterPaddingStart,
+      FooterBarMixin footerBarMixin) {
+    // Switch style to glif expressive common button.
+    if (primaryButtonView instanceof MaterialButton materialButton) {
+      // Set the padding back to the initial state due to we centered the down button and
+      // switch back to the common button style.
+      if (initialFooterPaddingStart != footerContainer.getPaddingStart()) {
+        footerContainer.setPadding(
+            initialFooterPaddingStart,
+            footerContainer.getPaddingTop(),
+            footerContainer.getPaddingEnd(),
+            footerContainer.getPaddingBottom());
+      }
+      // Set the secondary button as visible if it exists and the screen has scrolled to
+      // the bottom.
+      if (footerBarMixin.getSecondaryButton() != null) {
+        footerBarMixin.getSecondaryButton().setVisibility(View.VISIBLE);
+      }
+      // Set the primary button as invisible to avoid the button flicker and set to visible
+      // after button style is set up completely.
+      footerBarMixin.getPrimaryButton().setVisibility(View.INVISIBLE);
+      materialButton.setIcon(null);
+      footerBarMixin.getPrimaryButton().setText(nextText);
+      footerBarMixin.getPrimaryButton().setVisibility(View.VISIBLE);
+      primaryButtonView.setContentDescription(contentDescription);
+      footerContainer.setBackgroundColor(Color.TRANSPARENT);
+    } else {
+      Log.i(LOG_TAG, "Cannot clean up icon for the button. Skipping set text.");
+    }
+  }
+
+  @VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
+  public void generateGlifExpressiveDownButton(
       Context context, Button button, FooterBarMixin footerBarMixin) {
     Drawable icon = context.getResources().getDrawable(R.drawable.sud_ic_down_arrow);
-    if (button instanceof MaterialButton) {
+    if (button instanceof MaterialButton materialButton) {
       // Remove the text and set down arrow icon to the button.
-      button.setText("");
-      ((MaterialButton) button).setIcon(icon);
-      ((MaterialButton) button).setIconGravity(MaterialButton.ICON_GRAVITY_TEXT_START);
-      ((MaterialButton) button).setIconPadding(0);
+      materialButton.setText("");
+      materialButton.setIcon(icon);
+      materialButton.setIconGravity(MaterialButton.ICON_GRAVITY_TEXT_START);
+      materialButton.setIconPadding(0);
+      materialButton.setIconSize(
+          context
+              .getResources()
+              .getDimensionPixelSize(R.dimen.sud_glif_expressive_down_button_icon_size));
+      materialButton.setContentDescription(
+          context.getText(
+              com.google.android.setupdesign.strings.R.string
+                  .sud_expressive_accessibility_more_button_label));
       footerBarMixin.setDownButtonForExpressiveStyle();
     } else {
       Log.i(LOG_TAG, "Cannot set icon for the button. Skipping clean up text.");
@@ -426,17 +549,44 @@ public class RequireScrollMixin implements Mixin {
       return;
     }
     if (canScrollDown) {
-      if (!everScrolledToBottom) {
+      if (!isEverScrolledToBottom()) {
         postScrollStateChange(true);
         requiringScrollToBottom = true;
       }
     } else {
       postScrollStateChange(false);
       requiringScrollToBottom = false;
-      everScrolledToBottom = true;
+      setEverScrolledToBottom(true);
     }
   }
 
+  /**
+   * Restores the state of the scroll to bottom.
+   *
+   * @param value The state of the scroll to bottom.
+   */
+  public void onRestoreEverScrolledToBottom(boolean value) {
+    setEverScrolledToBottom(value);
+    // trigger the scroll state change to update the button style.
+    if (listener != null) {
+      listener.onRequireScrollStateChanged(true);
+    }
+  }
+
+  /**
+   * Set the state of the scroll to bottom.
+   *
+   * @param state The state of the scroll to bottom.
+   */
+  public void setEverScrolledToBottom(boolean state) {
+    everScrolledToBottom = state;
+  }
+
+  /** Returns true if the user has ever scrolled to the bottom. */
+  public boolean isEverScrolledToBottom() {
+    return everScrolledToBottom;
+  }
+
   private void postScrollStateChange(final boolean scrollNeeded) {
     handler.post(
         new Runnable() {
@@ -448,4 +598,8 @@ public class RequireScrollMixin implements Mixin {
           }
         });
   }
+
+  private boolean isScrollViewScrollable(ScrollView scrollView) {
+    return scrollView.canScrollVertically(1);
+  }
 }
diff --git a/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java b/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java
index 763baad..02ce1c7 100644
--- a/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java
+++ b/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java
@@ -118,13 +118,47 @@ public final class HeaderAreaStyler {
     if (lpIcon instanceof ViewGroup.MarginLayoutParams) {
       ViewGroup.MarginLayoutParams mlp = (ViewGroup.MarginLayoutParams) lpIcon;
 
-      int rightMargin =
-          (int)
-              PartnerConfigHelper.get(context)
-                  .getDimension(context, PartnerConfig.CONFIG_ACCOUNT_AVATAR_MARGIN_END);
+      int rightMargin;
+      if (PartnerConfigHelper.get(context)
+          .isPartnerConfigAvailable(PartnerConfig.CONFIG_ACCOUNT_AVATAR_MARGIN_END)) {
+        rightMargin =
+            (int)
+                PartnerConfigHelper.get(context)
+                    .getDimension(context, PartnerConfig.CONFIG_ACCOUNT_AVATAR_MARGIN_END);
+      } else {
+        rightMargin = mlp.rightMargin;
+      }
       mlp.setMargins(mlp.leftMargin, mlp.topMargin, rightMargin, mlp.bottomMargin);
     }
 
+    ViewGroup.LayoutParams lpContainer = container.getLayoutParams();
+    if (lpIcon instanceof ViewGroup.MarginLayoutParams) {
+      ViewGroup.MarginLayoutParams mlp = (ViewGroup.MarginLayoutParams) lpContainer;
+      int topMargin;
+      if (PartnerConfigHelper.get(context)
+          .isPartnerConfigAvailable(PartnerConfig.CONFIG_ACCOUNT_CONTAINER_MARGIN_TOP)) {
+        topMargin =
+            (int)
+                PartnerConfigHelper.get(context)
+                    .getDimension(context, PartnerConfig.CONFIG_ACCOUNT_CONTAINER_MARGIN_TOP);
+      } else {
+        topMargin = mlp.topMargin;
+      }
+
+      int bottomMargin;
+      if (PartnerConfigHelper.get(context)
+          .isPartnerConfigAvailable(PartnerConfig.CONFIG_ACCOUNT_CONTAINER_MARGIN_BOTTOM)) {
+        bottomMargin =
+            (int)
+                PartnerConfigHelper.get(context)
+                    .getDimension(context, PartnerConfig.CONFIG_ACCOUNT_CONTAINER_MARGIN_BOTTOM);
+      } else {
+        bottomMargin = mlp.bottomMargin;
+      }
+
+      mlp.setMargins(mlp.leftMargin, topMargin, mlp.rightMargin, bottomMargin);
+    }
+
     int maxHeight =
         (int)
             PartnerConfigHelper.get(context)
@@ -283,7 +317,12 @@ public final class HeaderAreaStyler {
           (int)
               PartnerConfigHelper.get(context)
                   .getDimension(context, PartnerConfig.CONFIG_ICON_MARGIN_TOP);
-      topMargin += reducedIconHeight;
+      if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+        // when glif expressive is enabled, adjust the icon margin top to align with the back button
+        topMargin += reducedIconHeight / 2;
+      } else {
+        topMargin += reducedIconHeight;
+      }
       mlp.setMargins(mlp.leftMargin, topMargin, mlp.rightMargin, mlp.bottomMargin);
     }
   }
@@ -322,10 +361,26 @@ public final class HeaderAreaStyler {
       adjustedTopMargin = topMargin + heightDifference / 2;
     }
 
-    if (adjustedTopMargin != mlp.topMargin) {
+    int leftMargin = mlp.leftMargin;
+    if (PartnerConfigHelper.get(context)
+        .isPartnerConfigAvailable(PartnerConfig.CONFIG_LAYOUT_MARGIN_START)) {
+      // TODO: Create a new partner config for the back button margin start.
+      leftMargin =
+          getPartnerConfigDimension(
+              context, PartnerConfig.CONFIG_LAYOUT_MARGIN_START, mlp.leftMargin);
+      leftMargin -=
+          (int)
+              context
+                  .getResources()
+                  .getDimension(R.dimen.sud_glif_expressive_back_button_padding_start);
+    }
+
+    if (adjustedTopMargin != mlp.topMargin || leftMargin != mlp.leftMargin) {
       FrameLayout.LayoutParams params =
           new FrameLayout.LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
       params.setMargins(mlp.leftMargin, adjustedTopMargin, mlp.rightMargin, mlp.bottomMargin);
+      // Call the setMarginStart method to support the RTL layout.
+      params.setMarginStart(leftMargin);
       buttonContainer.setLayoutParams(params);
     }
   }
diff --git a/main/src/com/google/android/setupdesign/util/ItemStyler.java b/main/src/com/google/android/setupdesign/util/ItemStyler.java
index 03b2734..e0fdf76 100644
--- a/main/src/com/google/android/setupdesign/util/ItemStyler.java
+++ b/main/src/com/google/android/setupdesign/util/ItemStyler.java
@@ -87,6 +87,8 @@ public final class ItemStyler {
     if (!PartnerStyleHelper.shouldApplyPartnerHeavyThemeResource(titleTextView)) {
       return;
     }
+    Context context = titleTextView.getContext();
+
     TextViewPartnerStyler.applyPartnerCustomizationStyle(
         titleTextView,
         new TextPartnerConfigs(
@@ -99,6 +101,19 @@ public final class ItemStyler {
             /* textMarginTopConfig= */ null,
             /* textMarginBottomConfig= */ null,
             PartnerStyleHelper.getLayoutGravity(titleTextView.getContext())));
+    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
+      if (PartnerConfigHelper.isGlifExpressiveEnabled(context)
+          && PartnerConfigHelper.get(context)
+              .isPartnerConfigAvailable(PartnerConfig.CONFIG_ITEMS_TITLE_FONT_VARIATION_SETTINGS)) {
+        // TODO: add unit test for this case.
+        String fontVariationSettings =
+            PartnerConfigHelper.get(context)
+                .getString(context, PartnerConfig.CONFIG_ITEMS_TITLE_FONT_VARIATION_SETTINGS);
+        if (fontVariationSettings != null && !fontVariationSettings.isEmpty()) {
+          titleTextView.setFontVariationSettings(fontVariationSettings);
+        }
+      }
+    }
   }
 
   /**
diff --git a/main/src/com/google/android/setupdesign/view/BulletPointView.java b/main/src/com/google/android/setupdesign/view/BulletPointView.java
index f64d48f..f190cb4 100644
--- a/main/src/com/google/android/setupdesign/view/BulletPointView.java
+++ b/main/src/com/google/android/setupdesign/view/BulletPointView.java
@@ -41,6 +41,7 @@ public class BulletPointView extends LinearLayout {
   private RichTextView titleView;
   private RichTextView summaryView;
   private ImageView iconView;
+  private View iconContainer;
 
   public BulletPointView(Context context) {
     super(context);
@@ -72,6 +73,7 @@ public class BulletPointView extends LinearLayout {
     titleView = findViewById(R.id.sud_items_title);
     summaryView = findViewById(R.id.sud_items_summary);
     iconView = findViewById(R.id.sud_items_icon);
+    iconContainer = findViewById(R.id.sud_items_icon_container);
     if (titleView != null && title != null) {
       titleView.setText(title);
       titleView.setVisibility(View.VISIBLE);
@@ -83,6 +85,9 @@ public class BulletPointView extends LinearLayout {
     if (iconView != null && icon != null) {
       iconView.setImageDrawable(icon);
       iconView.setVisibility(View.VISIBLE);
+      iconContainer.setVisibility(View.VISIBLE);
+    } else {
+      iconContainer.setVisibility(View.GONE);
     }
   }
 
@@ -107,6 +112,7 @@ public class BulletPointView extends LinearLayout {
     if (iconView != null) {
       iconView.setImageDrawable(icon);
       iconView.setVisibility(View.VISIBLE);
+      iconContainer.setVisibility(View.VISIBLE);
     }
   }
 
diff --git a/main/src/com/google/android/setupdesign/view/IconUniformityAppImageView.java b/main/src/com/google/android/setupdesign/view/IconUniformityAppImageView.java
index 7824b93..5aee897 100644
--- a/main/src/com/google/android/setupdesign/view/IconUniformityAppImageView.java
+++ b/main/src/com/google/android/setupdesign/view/IconUniformityAppImageView.java
@@ -31,6 +31,7 @@ import android.view.ViewOutlineProvider;
 import android.widget.ImageView;
 import androidx.annotation.ColorRes;
 import androidx.annotation.Nullable;
+import androidx.annotation.RequiresApi;
 import androidx.core.content.ContextCompat;
 import com.google.android.setupdesign.R;
 import com.google.android.setupdesign.widget.CardBackgroundDrawable;
@@ -46,6 +47,7 @@ public class IconUniformityAppImageView extends ImageView
   // Apps & games radius is 20% of icon height.
   private static final Float APPS_ICON_RADIUS_MULTIPLIER = 0.20f;
 
+  private boolean useCircleIcon;
   @ColorRes private int backdropColorResId = 0;
 
   private static final boolean ON_L_PLUS = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP;
@@ -82,6 +84,9 @@ public class IconUniformityAppImageView extends ImageView
 
   @Override
   public void bindView(IconUniformityAppImageViewData viewData) {
+    useCircleIcon = viewData.useCircleIcon;
+    float radius = getLayoutParams().height * APPS_ICON_RADIUS_MULTIPLIER;
+
     if (Build.VERSION.SDK_INT <= 17) {
       // clipPath is not supported on hardware accelerated canvas so won't take effect unless we
       // manually set to software.
@@ -94,23 +99,26 @@ public class IconUniformityAppImageView extends ImageView
         getLayoutParams().width,
         getLayoutParams().height);
 
-    float radius = getLayoutParams().height * APPS_ICON_RADIUS_MULTIPLIER;
-
     if (ON_L_PLUS) {
       setBackgroundColor(ContextCompat.getColor(getContext(), backdropColorResId));
-      backdropDrawable.setCornerRadius(radius);
       setElevation(getContext().getResources().getDimension(R.dimen.sud_icon_uniformity_elevation));
       setClipToOutline(true);
       setOutlineProvider(
           new ViewOutlineProvider() {
             @Override
             public void getOutline(View view, Outline outline) {
-              outline.setRoundRect(
-                  /* left= */ 0,
-                  /* top= */ 0,
-                  /* right= */ getLayoutParams().width,
-                  /* bottom= */ getLayoutParams().height,
-                  /* radius= */ radius);
+              if (useCircleIcon) {
+                setCircleIconTransformation(viewData, outline);
+
+              } else {
+                backdropDrawable.setCornerRadius(radius);
+                outline.setRoundRect(
+                    /* left= */ 0,
+                    /* top= */ 0,
+                    /* right= */ getLayoutParams().width,
+                    /* bottom= */ getLayoutParams().height,
+                    /* radius= */ radius);
+              }
             }
           });
     } else {
@@ -153,6 +161,49 @@ public class IconUniformityAppImageView extends ImageView
     backdropDrawable.setColor(ContextCompat.getColor(getContext(), backdropColorResId));
   }
 
+  @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
+  private void setCircleIconTransformation(
+      IconUniformityAppImageViewData viewData, Outline outline) {
+    float drawableWidth = viewData.icon.getMinimumWidth();
+    float drawableHeight = viewData.icon.getMinimumHeight();
+    float imageViewHeight = getLayoutParams().height;
+    float imageViewWidth = getLayoutParams().width;
+    float outlineWidth;
+    float outlineHeight;
+    float widthInset;
+    float heightInset;
+
+    final float drawableAspectRatio = drawableHeight / drawableWidth;
+    final float imageViewAspectRatio = imageViewHeight / imageViewWidth;
+    if (drawableAspectRatio > imageViewAspectRatio) {
+      // Fill height first
+      outlineHeight = imageViewHeight;
+      outlineWidth = outlineHeight / drawableAspectRatio;
+      widthInset = (imageViewWidth - outlineWidth) / 2;
+      heightInset = 0;
+    } else if (drawableAspectRatio < imageViewAspectRatio) {
+      // Fill width first
+      outlineWidth = imageViewWidth;
+      outlineHeight = outlineWidth * drawableAspectRatio;
+      widthInset = 0;
+      heightInset =
+          getScaleType() == ScaleType.FIT_START ? 0 : (imageViewHeight - outlineHeight) / 2;
+    } else {
+      // Equal aspect ratio
+      outlineHeight = imageViewHeight;
+      outlineWidth = imageViewWidth;
+      widthInset = 0;
+      heightInset = 0;
+    }
+    setScaleType(ScaleType.FIT_CENTER);
+
+    outline.setOval(
+        Math.round(widthInset),
+        Math.round(heightInset),
+        Math.round(widthInset + outlineWidth),
+        Math.round(heightInset + outlineHeight));
+  }
+
   private void setLegacyTransformationMatrix(
       float drawableWidth, float drawableHeight, float imageViewWidth, float imageViewHeight) {
     Matrix scaleMatrix = new Matrix();
diff --git a/main/src/com/google/android/setupdesign/view/IconUniformityAppImageViewBindable.java b/main/src/com/google/android/setupdesign/view/IconUniformityAppImageViewBindable.java
index 1eab81b..5d896d5 100644
--- a/main/src/com/google/android/setupdesign/view/IconUniformityAppImageViewBindable.java
+++ b/main/src/com/google/android/setupdesign/view/IconUniformityAppImageViewBindable.java
@@ -25,8 +25,19 @@ public interface IconUniformityAppImageViewBindable {
   class IconUniformityAppImageViewData {
     public Drawable icon;
 
+    /**
+     * True if the image uses a circular icon and API level is 21+. android.graphics.Outline#setOval
+     * requires API level 21.
+     */
+    public boolean useCircleIcon;
+
     public IconUniformityAppImageViewData(Drawable icon) {
+      this(icon, /* useCircleIcon= */ false);
+    }
+
+    public IconUniformityAppImageViewData(Drawable icon, boolean useCircleIcon) {
       this.icon = icon;
+      this.useCircleIcon = useCircleIcon;
     }
   }
 
diff --git a/main/src/com/google/android/setupdesign/view/InfoFooterView.java b/main/src/com/google/android/setupdesign/view/InfoFooterView.java
index 2f85d7d..f15b94e 100644
--- a/main/src/com/google/android/setupdesign/view/InfoFooterView.java
+++ b/main/src/com/google/android/setupdesign/view/InfoFooterView.java
@@ -77,13 +77,28 @@ public class InfoFooterView extends LinearLayout {
       iconView.setImageDrawable(icon);
       iconView.setVisibility(View.VISIBLE);
     }
-    if (!alignParentBottom) {
-      View infoFooterContainer = findViewById(R.id.sud_info_footer_container);
-      RelativeLayout.LayoutParams layoutParams =
-          (RelativeLayout.LayoutParams) infoFooterContainer.getLayoutParams();
-      // By default, ALIGN_PARENT_BOTTOM is set. Setting it to 0 removes the rule.
-      layoutParams.addRule(RelativeLayout.ALIGN_PARENT_BOTTOM, 0);
-      infoFooterContainer.setLayoutParams(layoutParams);
+    alignView();
+  }
+
+  private void alignView() {
+    View infoFooterContainer = findViewById(R.id.sud_info_footer_container);
+    RelativeLayout.LayoutParams layoutParams =
+        (RelativeLayout.LayoutParams) infoFooterContainer.getLayoutParams();
+    // sets the rule to update ALIGN_PARENT_BOTTOM to 1 if alignParentBottom is true and 0 if False.
+    layoutParams.addRule(RelativeLayout.ALIGN_PARENT_BOTTOM, alignParentBottom ? 1 : 0);
+    infoFooterContainer.setLayoutParams(layoutParams);
+  }
+
+  /**
+   * Sets whether the footer should align to the bottom of the parent layout.
+   *
+   * @param alignParentBottom True if the footer should align to the bottom of the parent layout,
+   *     false otherwise.
+   */
+  public void setAlignParentBottom(boolean alignParentBottom) {
+    if (this.alignParentBottom != alignParentBottom) {
+      this.alignParentBottom = alignParentBottom;
+      alignView();
     }
   }
 
diff --git a/main/src/com/google/android/setupdesign/view/InsetAdjustmentLayout.java b/main/src/com/google/android/setupdesign/view/InsetAdjustmentLayout.java
index 424bc58..d4dfc1d 100644
--- a/main/src/com/google/android/setupdesign/view/InsetAdjustmentLayout.java
+++ b/main/src/com/google/android/setupdesign/view/InsetAdjustmentLayout.java
@@ -22,6 +22,7 @@ import android.os.Build.VERSION_CODES;
 import android.util.AttributeSet;
 import android.view.WindowInsets;
 import android.widget.LinearLayout;
+import com.google.android.setupcompat.R;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.util.Logger;
 
@@ -62,10 +63,10 @@ public class InsetAdjustmentLayout extends LinearLayout {
         LOG.atDebug("NavigationBarHeight: " + insets.getSystemWindowInsetBottom());
         insets =
             insets.replaceSystemWindowInsets(
-                insets.getSystemWindowInsetLeft(),
+                0,
                 insets.getSystemWindowInsetTop(),
-                insets.getSystemWindowInsetRight(),
-                /* bottom= */ 0);
+                0,
+                findViewById(R.id.suc_layout_status).getPaddingBottom());
       }
     }
     return super.onApplyWindowInsets(insets);
diff --git a/main/src/com/google/android/setupdesign/view/IntrinsicSizeFrameLayout.java b/main/src/com/google/android/setupdesign/view/IntrinsicSizeFrameLayout.java
index 5f37b22..46579b3 100644
--- a/main/src/com/google/android/setupdesign/view/IntrinsicSizeFrameLayout.java
+++ b/main/src/com/google/android/setupdesign/view/IntrinsicSizeFrameLayout.java
@@ -18,7 +18,6 @@ package com.google.android.setupdesign.view;
 
 import static java.lang.Math.min;
 
-import android.annotation.TargetApi;
 import android.content.Context;
 import android.content.res.TypedArray;
 import android.graphics.Rect;
@@ -32,10 +31,12 @@ import android.view.WindowInsets;
 import android.view.WindowManager;
 import android.view.WindowMetrics;
 import android.widget.FrameLayout;
+import androidx.annotation.RequiresApi;
 import androidx.annotation.VisibleForTesting;
 import com.google.android.setupcompat.partnerconfig.PartnerConfig;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.util.BuildCompatUtils;
+import com.google.android.setupcompat.util.Logger;
 import com.google.android.setupdesign.R;
 
 /**
@@ -48,6 +49,8 @@ import com.google.android.setupdesign.R;
  */
 public class IntrinsicSizeFrameLayout extends FrameLayout {
 
+  private static final Logger LOG = new Logger(IntrinsicSizeFrameLayout.class);
+
   private int intrinsicHeight = 0;
   private int intrinsicWidth = 0;
   private Object lastInsets; // Use generic Object type for compatibility
@@ -65,7 +68,7 @@ public class IntrinsicSizeFrameLayout extends FrameLayout {
     init(context, attrs, 0);
   }
 
-  @TargetApi(VERSION_CODES.HONEYCOMB)
+  @RequiresApi(VERSION_CODES.HONEYCOMB)
   public IntrinsicSizeFrameLayout(Context context, AttributeSet attrs, int defStyleAttr) {
     super(context, attrs, defStyleAttr);
     init(context, attrs, defStyleAttr);
@@ -85,6 +88,8 @@ public class IntrinsicSizeFrameLayout extends FrameLayout {
         a.getDimensionPixelSize(R.styleable.SudIntrinsicSizeFrameLayout_android_width, 0);
     a.recycle();
 
+    LOG.atInfo("CardViewIntrinsicAttribute(" + intrinsicWidth + ", " + intrinsicHeight + ")");
+
     if (BuildCompatUtils.isAtLeastS()) {
       if (PartnerConfigHelper.get(context)
           .isPartnerConfigAvailable(PartnerConfig.CONFIG_CARD_VIEW_INTRINSIC_HEIGHT)) {
@@ -92,14 +97,21 @@ public class IntrinsicSizeFrameLayout extends FrameLayout {
             (int)
                 PartnerConfigHelper.get(context)
                     .getDimension(context, PartnerConfig.CONFIG_CARD_VIEW_INTRINSIC_HEIGHT);
+      } else {
+        LOG.atInfo("PartnerConfig.CONFIG_CARD_VIEW_INTRINSIC_HEIGHT not found");
       }
+
       if (PartnerConfigHelper.get(context)
           .isPartnerConfigAvailable(PartnerConfig.CONFIG_CARD_VIEW_INTRINSIC_WIDTH)) {
         intrinsicWidth =
             (int)
                 PartnerConfigHelper.get(context)
                     .getDimension(context, PartnerConfig.CONFIG_CARD_VIEW_INTRINSIC_WIDTH);
+      } else {
+        LOG.atInfo("PartnerConfig.CONFIG_CARD_VIEW_INTRINSIC_WIDTH not found");
       }
+
+      LOG.atInfo("CardViewIntrinsicPartnerConfig(" + intrinsicWidth + ", " + intrinsicHeight + ")");
     }
   }
 
diff --git a/strings/res/values/strings.xml b/strings/res/values/strings.xml
index 21505de..cff9656 100644
--- a/strings/res/values/strings.xml
+++ b/strings/res/values/strings.xml
@@ -28,6 +28,9 @@
     <!-- Button for scrolling down to reveal more content on the screen [CHAR LIMIT=20] -->
     <string name="sud_more_button_label">More</string>
 
+    <!-- Button for scrolling down to reveal more content on the screen for expressive style [CHAR LIMIT=NONE] -->
+    <string name="sud_expressive_accessibility_more_button_label">Scroll down</string>
+
     <!-- The default device name when other resources get the device name are not available [CHAR LIMIT=20] -->
     <string name="sud_default_device_name">device</string>
 
```

