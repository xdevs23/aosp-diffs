```diff
diff --git a/Android.bp b/Android.bp
index aa336ad..a9aee37 100644
--- a/Android.bp
+++ b/Android.bp
@@ -54,6 +54,10 @@ android_library {
     lint: {
         baseline_filename: "lint-baseline.xml",
     },
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.healthfitness",
+    ],
 }
 
 //
@@ -69,4 +73,8 @@ android_library {
     ],
     min_sdk_version: "19",
     sdk_version: "current",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.healthfitness",
+    ],
 }
diff --git a/lottie_loading_layout/res/layout-land-v31/sud_glif_loading_template_content.xml b/lottie_loading_layout/res/layout-land-v31/sud_glif_loading_template_content.xml
index ef0ba71..8bc650b 100644
--- a/lottie_loading_layout/res/layout-land-v31/sud_glif_loading_template_content.xml
+++ b/lottie_loading_layout/res/layout-land-v31/sud_glif_loading_template_content.xml
@@ -15,12 +15,15 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <LinearLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:tools="http://schemas.android.com/tools"
     android:id="@+id/sud_layout_template_content"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
     android:orientation="vertical">
 
     <LinearLayout
diff --git a/lottie_loading_layout/res/layout-sw600dp-land-v31/sud_glif_fullscreen_loading_template_content.xml b/lottie_loading_layout/res/layout-sw600dp-land-v31/sud_glif_fullscreen_loading_template_content.xml
index e5e1bb5..940121d 100644
--- a/lottie_loading_layout/res/layout-sw600dp-land-v31/sud_glif_fullscreen_loading_template_content.xml
+++ b/lottie_loading_layout/res/layout-sw600dp-land-v31/sud_glif_fullscreen_loading_template_content.xml
@@ -14,9 +14,13 @@
     See the License for the specific language governing permissions and
     limitations under the License.
 -->
+
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
 
     <ViewStub
         android:id="@+id/sud_loading_layout_lottie_stub"
diff --git a/lottie_loading_layout/res/layout-sw600dp-v31/sud_glif_fullscreen_loading_template_card.xml b/lottie_loading_layout/res/layout-sw600dp-v31/sud_glif_fullscreen_loading_template_card.xml
index 2aa254d..876d733 100644
--- a/lottie_loading_layout/res/layout-sw600dp-v31/sud_glif_fullscreen_loading_template_card.xml
+++ b/lottie_loading_layout/res/layout-sw600dp-v31/sud_glif_fullscreen_loading_template_card.xml
@@ -15,11 +15,14 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
     android:fitsSystemWindows="true"
     android:gravity="center_horizontal"
     android:orientation="vertical">
diff --git a/lottie_loading_layout/res/layout-sw600dp-v31/sud_glif_fullscreen_loading_template_content.xml b/lottie_loading_layout/res/layout-sw600dp-v31/sud_glif_fullscreen_loading_template_content.xml
index 97f86be..902a22e 100644
--- a/lottie_loading_layout/res/layout-sw600dp-v31/sud_glif_fullscreen_loading_template_content.xml
+++ b/lottie_loading_layout/res/layout-sw600dp-v31/sud_glif_fullscreen_loading_template_content.xml
@@ -14,10 +14,14 @@
     See the License for the specific language governing permissions and
     limitations under the License.
 -->
+
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:tools="http://schemas.android.com/tools"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
 
     <ViewStub
         android:id="@+id/sud_loading_layout_lottie_stub"
diff --git a/lottie_loading_layout/res/layout-sw600dp-v31/sud_loading_fullscreen_lottie_layout.xml b/lottie_loading_layout/res/layout-sw600dp-v31/sud_loading_fullscreen_lottie_layout.xml
index 8c98e74..0e0af86 100644
--- a/lottie_loading_layout/res/layout-sw600dp-v31/sud_loading_fullscreen_lottie_layout.xml
+++ b/lottie_loading_layout/res/layout-sw600dp-v31/sud_loading_fullscreen_lottie_layout.xml
@@ -15,11 +15,14 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <LinearLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
 
     <com.airbnb.lottie.LottieAnimationView
         android:id="@+id/sud_lottie_view"
diff --git a/lottie_loading_layout/res/layout-v31/sud_glif_loading_template_content.xml b/lottie_loading_layout/res/layout-v31/sud_glif_loading_template_content.xml
index c5d36ef..f3a3c4a 100644
--- a/lottie_loading_layout/res/layout-v31/sud_glif_loading_template_content.xml
+++ b/lottie_loading_layout/res/layout-v31/sud_glif_loading_template_content.xml
@@ -15,10 +15,13 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <LinearLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:tools="http://schemas.android.com/tools"
     android:id="@+id/sud_layout_template_content"
+    android:filterTouchesWhenObscured="true"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:orientation="vertical">
diff --git a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_card.xml b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_card.xml
new file mode 100644
index 0000000..cd50138
--- /dev/null
+++ b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_card.xml
@@ -0,0 +1,53 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    style="@style/SudGlifCardBackground"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:fitsSystemWindows="true"
+    android:gravity="center_horizontal"
+    android:orientation="vertical">
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+    <com.google.android.setupdesign.view.IntrinsicSizeFrameLayout
+        android:id="@+id/suc_intrinsic_size_layout"
+        style="@style/SudGlifCardContainer"
+        android:layout_width="@dimen/sud_glif_card_width"
+        android:layout_height="wrap_content"
+        android:height="@dimen/sud_glif_card_height">
+
+        <include layout="@layout/sud_glif_expressive_fullscreen_loading_template_content_layout" />
+
+    </com.google.android.setupdesign.view.IntrinsicSizeFrameLayout>
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+</LinearLayout>
diff --git a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_content.xml b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_content.xml
new file mode 100644
index 0000000..5ec6c79
--- /dev/null
+++ b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_content.xml
@@ -0,0 +1,101 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
+
+    <ViewStub
+        android:id="@+id/sud_loading_layout_lottie_stub"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:inflatedId="@+id/sud_layout_lottie_illustration"
+        android:layout="@layout/sud_loading_fullscreen_lottie_layout" />
+
+    <LinearLayout
+        android:id="@+id/sud_layout_template_content"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:orientation="vertical">
+
+        <ViewStub
+            android:id="@+id/sud_layout_sticky_header"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content" />
+
+        <LinearLayout
+            android:layout_width="match_parent"
+            android:layout_height="0dp"
+            android:layout_weight="1"
+            android:orientation="vertical">
+
+            <LinearLayout
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:orientation="vertical">
+
+                <!-- Ignore UnusedAttribute: scrollIndicators is new in M. Default to no indicators in older
+                    versions. -->
+                <com.google.android.setupdesign.view.BottomScrollView
+                    android:id="@+id/sud_header_scroll_view"
+                    android:layout_width="match_parent"
+                    android:layout_height="?attr/sudLoadingHeaderHeight"
+                    android:fillViewport="true"
+                    android:scrollIndicators="?attr/sudScrollIndicators"
+                    tools:ignore="UnusedAttribute">
+
+                    <include layout="@layout/sud_glif_header" />
+
+                </com.google.android.setupdesign.view.BottomScrollView>
+
+                <LinearLayout
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:orientation="vertical">
+
+                    <ViewStub
+                        android:id="@+id/sud_loading_layout_illustration_stub"
+                        android:layout_width="match_parent"
+                        android:layout_height="match_parent"
+                        android:inflatedId="@+id/sud_layout_progress_illustration"
+                        android:layout="@layout/sud_loading_illustration_layout" />
+
+                    <FrameLayout
+                        android:id="@+id/sud_layout_content"
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:visibility="gone" />
+
+                </LinearLayout>
+
+            </LinearLayout>
+
+        </LinearLayout>
+
+        <ViewStub
+            android:id="@+id/suc_layout_footer"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content" />
+
+    </LinearLayout>
+    <include layout="@layout/sud_glif_floating_back_button" />
+
+</FrameLayout>
diff --git a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_content_wide.xml b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_content_wide.xml
new file mode 100644
index 0000000..1aad5a0
--- /dev/null
+++ b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_fullscreen_loading_template_content_wide.xml
@@ -0,0 +1,108 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
+
+    <ViewStub
+        android:id="@+id/sud_loading_layout_lottie_stub"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:inflatedId="@+id/sud_layout_lottie_illustration"
+        android:layout="@layout/sud_loading_fullscreen_lottie_layout" />
+
+    <LinearLayout
+        android:id="@+id/sud_layout_template_content"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:orientation="vertical">
+
+        <LinearLayout
+            android:layout_width="match_parent"
+            android:layout_height="0dp"
+            android:layout_weight="1"
+            android:orientation="horizontal">
+
+            <LinearLayout
+                android:id="@+id/sud_landscape_header_area"
+                android:layout_width="0dp"
+                android:layout_height="match_parent"
+                android:layout_weight="@dimen/sud_glif_land_header_area_weight"
+                android:orientation="vertical">
+
+                <ViewStub
+                    android:id="@+id/sud_layout_sticky_header"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content" />
+
+                <com.google.android.setupdesign.view.BottomScrollView
+                    android:id="@+id/sud_header_scroll_view"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:fillViewport="true"
+                    android:scrollIndicators="?attr/sudScrollIndicators">
+
+                    <include layout="@layout/sud_glif_header" />
+
+                </com.google.android.setupdesign.view.BottomScrollView>
+
+            </LinearLayout>
+
+            <LinearLayout
+                android:id="@+id/sud_landscape_content_area"
+                style="@style/SudLandContentContianerStyle"
+                android:paddingTop="?attr/sudGlifContentPaddingTop"
+                android:focusedByDefault="false"
+                android:orientation="vertical">
+
+                <FrameLayout
+                    android:id="@+id/sud_layout_loading_content"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent">
+
+                    <ViewStub
+                        android:id="@+id/sud_loading_layout_illustration_stub"
+                        android:layout_width="match_parent"
+                        android:layout_height="match_parent"
+                        android:inflatedId="@+id/sud_layout_progress_illustration"
+                        android:layout="@layout/sud_loading_illustration_layout" />
+
+                    <FrameLayout
+                        android:id="@+id/sud_layout_content"
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:visibility="gone" />
+
+                </FrameLayout>
+
+            </LinearLayout>
+
+        </LinearLayout>
+
+        <ViewStub
+            android:id="@+id/suc_layout_footer"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content" />
+
+    </LinearLayout>
+    <include layout="@layout/sud_glif_floating_back_button" />
+
+</FrameLayout>
diff --git a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_card.xml b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_card.xml
new file mode 100644
index 0000000..9b14ca1
--- /dev/null
+++ b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_card.xml
@@ -0,0 +1,53 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    style="@style/SudGlifCardBackground"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:fitsSystemWindows="true"
+    android:gravity="center_horizontal"
+    android:orientation="vertical">
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+    <com.google.android.setupdesign.view.IntrinsicSizeFrameLayout
+        android:id="@+id/suc_intrinsic_size_layout"
+        style="@style/SudGlifCardContainer"
+        android:layout_width="@dimen/sud_glif_card_width"
+        android:layout_height="wrap_content"
+        android:height="@dimen/sud_glif_card_height">
+
+        <include layout="@layout/sud_glif_expressive_loading_template_content_layout" />
+
+    </com.google.android.setupdesign.view.IntrinsicSizeFrameLayout>
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+</LinearLayout>
diff --git a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_compat.xml b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_compat.xml
new file mode 100644
index 0000000..c4f0d8a
--- /dev/null
+++ b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_compat.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<com.google.android.setupcompat.view.StatusBarBackgroundLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
+
+  <include layout="@layout/sud_glif_expressive_loading_template_content_layout" />
+
+</com.google.android.setupcompat.view.StatusBarBackgroundLayout>
diff --git a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_content.xml b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_content.xml
new file mode 100644
index 0000000..32744f5
--- /dev/null
+++ b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_content.xml
@@ -0,0 +1,102 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:id="@+id/sud_layout_template_content"
+    android:filterTouchesWhenObscured="true"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:orientation="vertical">
+
+    <ViewStub
+        android:id="@+id/sud_layout_sticky_header"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:orientation="vertical">
+
+        <LinearLayout
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:orientation="vertical">
+
+            <!-- Ignore UnusedAttribute: scrollIndicators is new in M. Default to no indicators in older
+                versions. -->
+            <com.google.android.setupdesign.view.BottomScrollView
+                android:id="@+id/sud_header_scroll_view"
+                android:layout_width="match_parent"
+                android:layout_height="?attr/sudLoadingHeaderHeight"
+                android:fillViewport="true"
+                android:scrollIndicators="?attr/sudScrollIndicators"
+                tools:ignore="UnusedAttribute">
+
+                <include layout="@layout/sud_glif_header" />
+
+            </com.google.android.setupdesign.view.BottomScrollView>
+
+            <LinearLayout
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:orientation="vertical">
+
+                <ViewStub
+                    android:id="@+id/sud_loading_layout_lottie_stub"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:inflatedId="@+id/sud_layout_lottie_illustration"
+                    android:layout="@layout/sud_loading_lottie_layout" />
+
+                <ViewStub
+                    android:id="@+id/sud_loading_layout_illustration_stub"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:inflatedId="@+id/sud_layout_progress_illustration"
+                    android:layout="@layout/sud_loading_illustration_layout" />
+
+                <FrameLayout
+                    android:id="@+id/sud_layout_content"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:visibility="gone" />
+
+            </LinearLayout>
+
+        </LinearLayout>
+
+    </LinearLayout>
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+
+    <ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_content_wide.xml b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_content_wide.xml
new file mode 100644
index 0000000..62df2c8
--- /dev/null
+++ b/lottie_loading_layout/res/layout-v35/sud_glif_expressive_loading_template_content_wide.xml
@@ -0,0 +1,111 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:orientation="horizontal">
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_header_area"
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="@dimen/sud_glif_land_header_area_weight"
+            android:orientation="vertical">
+
+            <ViewStub
+                android:id="@+id/sud_layout_sticky_header"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content" />
+
+            <com.google.android.setupdesign.view.BottomScrollView
+                android:id="@+id/sud_header_scroll_view"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:fillViewport="true"
+                android:scrollIndicators="?attr/sudScrollIndicators">
+
+                <include layout="@layout/sud_glif_header" />
+
+            </com.google.android.setupdesign.view.BottomScrollView>
+
+        </LinearLayout>
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_content_area"
+            style="@style/SudLandContentContianerStyle"
+            android:focusedByDefault="false"
+            android:orientation="vertical">
+
+            <FrameLayout
+                android:id="@+id/sud_layout_loading_content"
+                android:paddingTop="?attr/sudGlifContentPaddingTop"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent">
+
+                <ViewStub
+                    android:id="@+id/sud_loading_layout_lottie_stub"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:inflatedId="@+id/sud_layout_lottie_illustration"
+                    android:layout="@layout/sud_loading_lottie_layout" />
+
+                <ViewStub
+                    android:id="@+id/sud_loading_layout_illustration_stub"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:inflatedId="@+id/sud_layout_progress_illustration"
+                    android:layout="@layout/sud_loading_illustration_layout" />
+
+                <FrameLayout
+                    android:id="@+id/sud_layout_content"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:visibility="gone" />
+
+            </FrameLayout>
+
+        </LinearLayout>
+
+    </LinearLayout>
+
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+
+    <ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/lottie_loading_layout/res/layout/sud_glif_fullscreen_loading_embedded_template_card.xml b/lottie_loading_layout/res/layout/sud_glif_fullscreen_loading_embedded_template_card.xml
index 56c0f9b..bb3f949 100644
--- a/lottie_loading_layout/res/layout/sud_glif_fullscreen_loading_embedded_template_card.xml
+++ b/lottie_loading_layout/res/layout/sud_glif_fullscreen_loading_embedded_template_card.xml
@@ -15,11 +15,14 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
     android:fitsSystemWindows="true"
     android:gravity="center_horizontal"
     android:orientation="vertical">
diff --git a/lottie_loading_layout/res/layout/sud_glif_fullscreen_loading_embedded_template_content.xml b/lottie_loading_layout/res/layout/sud_glif_fullscreen_loading_embedded_template_content.xml
index e1dc7c4..5176df0 100644
--- a/lottie_loading_layout/res/layout/sud_glif_fullscreen_loading_embedded_template_content.xml
+++ b/lottie_loading_layout/res/layout/sud_glif_fullscreen_loading_embedded_template_content.xml
@@ -14,10 +14,14 @@
     See the License for the specific language governing permissions and
     limitations under the License.
 -->
+
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:tools="http://schemas.android.com/tools"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
 
     <ViewStub
         android:id="@+id/sud_loading_layout_lottie_stub"
diff --git a/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_card.xml b/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_card.xml
index 6b26c68..3f3c445 100644
--- a/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_card.xml
+++ b/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_card.xml
@@ -15,11 +15,14 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
     android:fitsSystemWindows="true"
     android:gravity="center_horizontal"
     android:orientation="vertical">
diff --git a/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_compat.xml b/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_compat.xml
index b79851a..b48446a 100644
--- a/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_compat.xml
+++ b/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_compat.xml
@@ -15,11 +15,14 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <com.google.android.setupcompat.view.StatusBarBackgroundLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
 
   <include layout="@layout/sud_glif_loading_embedded_template_content" />
 
diff --git a/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_content.xml b/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_content.xml
index a49aead..2565206 100644
--- a/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_content.xml
+++ b/lottie_loading_layout/res/layout/sud_glif_loading_embedded_template_content.xml
@@ -15,12 +15,15 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <LinearLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:tools="http://schemas.android.com/tools"
     android:id="@+id/sud_layout_template_content"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
     android:orientation="vertical">
 
     <ViewStub
diff --git a/lottie_loading_layout/res/layout/sud_glif_loading_template_card.xml b/lottie_loading_layout/res/layout/sud_glif_loading_template_card.xml
index a2f907e..fb113cb 100644
--- a/lottie_loading_layout/res/layout/sud_glif_loading_template_card.xml
+++ b/lottie_loading_layout/res/layout/sud_glif_loading_template_card.xml
@@ -15,11 +15,14 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
     android:fitsSystemWindows="true"
     android:gravity="center_horizontal"
     android:orientation="vertical">
diff --git a/lottie_loading_layout/res/layout/sud_glif_loading_template_compat.xml b/lottie_loading_layout/res/layout/sud_glif_loading_template_compat.xml
index d8e9177..48f1b97 100644
--- a/lottie_loading_layout/res/layout/sud_glif_loading_template_compat.xml
+++ b/lottie_loading_layout/res/layout/sud_glif_loading_template_compat.xml
@@ -15,11 +15,14 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <com.google.android.setupcompat.view.StatusBarBackgroundLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
 
   <include layout="@layout/sud_glif_loading_template_content" />
 
diff --git a/lottie_loading_layout/res/layout/sud_glif_loading_template_content.xml b/lottie_loading_layout/res/layout/sud_glif_loading_template_content.xml
index e70edc1..66d67f9 100644
--- a/lottie_loading_layout/res/layout/sud_glif_loading_template_content.xml
+++ b/lottie_loading_layout/res/layout/sud_glif_loading_template_content.xml
@@ -15,12 +15,15 @@
     limitations under the License.
 -->
 
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <LinearLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:tools="http://schemas.android.com/tools"
     android:id="@+id/sud_layout_template_content"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
     android:orientation="vertical">
 
     <ViewStub
diff --git a/lottie_loading_layout/res/values-v35/layouts.xml b/lottie_loading_layout/res/values-v35/layouts.xml
new file mode 100644
index 0000000..728618a
--- /dev/null
+++ b/lottie_loading_layout/res/values-v35/layouts.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+
+  <item name="sud_glif_expressive_loading_template_content_layout" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_expressive_loading_template_content</item>
+  <item name="sud_glif_expressive_fullscreen_loading_template_content_layout" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_expressive_fullscreen_loading_template_content</item>
+</resources>
\ No newline at end of file
diff --git a/lottie_loading_layout/res/values-w600dp-h900dp-v35/layouts.xml b/lottie_loading_layout/res/values-w600dp-h900dp-v35/layouts.xml
new file mode 100644
index 0000000..a084fcd
--- /dev/null
+++ b/lottie_loading_layout/res/values-w600dp-h900dp-v35/layouts.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
diff --git a/lottie_loading_layout/res/values-w600dp-v35/layouts.xml b/lottie_loading_layout/res/values-w600dp-v35/layouts.xml
new file mode 100644
index 0000000..66e03ba
--- /dev/null
+++ b/lottie_loading_layout/res/values-w600dp-v35/layouts.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+  <item name="sud_glif_expressive_loading_template_content_layout" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_expressive_loading_template_content_wide</item>
+  <item name="sud_glif_expressive_fullscreen_loading_template_content_layout" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_expressive_fullscreen_loading_template_content_wide</item>
+</resources>
\ No newline at end of file
diff --git a/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java b/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java
index 5f4f9fb..4887044 100644
--- a/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java
+++ b/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java
@@ -34,7 +34,6 @@ import android.provider.Settings;
 import android.provider.Settings.SettingNotFoundException;
 import android.util.AttributeSet;
 import android.util.DisplayMetrics;
-import android.util.Log;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.View.MeasureSpec;
@@ -62,6 +61,7 @@ import com.google.android.setupcompat.partnerconfig.ResourceEntry;
 import com.google.android.setupcompat.template.FooterBarMixin;
 import com.google.android.setupcompat.util.BuildCompatUtils;
 import com.google.android.setupcompat.util.ForceTwoPaneHelper;
+import com.google.android.setupcompat.util.Logger;
 import com.google.android.setupdesign.lottieloadinglayout.R;
 import com.google.android.setupdesign.util.LayoutStyler;
 import com.google.android.setupdesign.util.LottieAnimationHelper;
@@ -81,8 +81,7 @@ import java.util.List;
  * app:sudLottieRes} can assign the json file of Lottie resource.
  */
 public class GlifLoadingLayout extends GlifLayout {
-
-  private static final String TAG = "GlifLoadingLayout";
+  private static final Logger LOG = new Logger(GlifLoadingLayout.class);
   View inflatedView;
 
   @VisibleForTesting @IllustrationType String illustrationType = IllustrationType.DEFAULT;
@@ -181,7 +180,7 @@ public class GlifLoadingLayout extends GlifLayout {
 
             @Override
             public void onAnimationEnd(Animator animation) {
-              Log.i(TAG, "Animate enable:" + isAnimateEnable() + ". Animation end.");
+              LOG.atInfo("Animate enable:" + isAnimateEnable() + ". Animation end.");
             }
 
             @Override
@@ -192,7 +191,7 @@ public class GlifLoadingLayout extends GlifLayout {
             @Override
             public void onAnimationRepeat(Animator animation) {
               if (workFinished) {
-                Log.i(TAG, "Animation repeat but work finished, run the register runnable.");
+                LOG.atInfo("Animation repeat but work finished, run the register runnable.");
                 finishRunnable(nextActionRunnable);
                 workFinished = false;
               }
@@ -200,6 +199,8 @@ public class GlifLoadingLayout extends GlifLayout {
           };
       lottieAnimationView.addAnimatorListener(animatorListener);
     }
+
+    initBackButton();
   }
 
   public void setHeaderFullTextEnabled(boolean enabled) {
@@ -386,8 +387,7 @@ public class GlifLoadingLayout extends GlifLayout {
       return false;
     }
 
-    Log.i(
-        TAG,
+    LOG.atInfo(
         "deviceHeightDp : "
             + deviceHeightDp
             + " viewHeightDp : "
@@ -402,7 +402,20 @@ public class GlifLoadingLayout extends GlifLayout {
   }
 
   private void showTopLinearProgress() {
-    View view = findViewById(com.google.android.setupdesign.R.id.sud_glif_top_progress_bar);
+    View view;
+    if (isGlifExpressiveEnabled()) {
+      view = peekProgressBar();
+      if (view == null) {
+        final ViewStub progressIndicatorStub =
+            findViewById(com.google.android.setupdesign.R.id.sud_glif_top_progress_indicator_stub);
+        if (progressIndicatorStub != null) {
+          progressIndicatorStub.inflate();
+        }
+        view = peekProgressBar();
+      }
+    } else {
+      view = findViewById(com.google.android.setupdesign.R.id.sud_glif_top_progress_bar);
+    }
     if (view == null) {
       return;
     }
@@ -519,10 +532,18 @@ public class GlifLoadingLayout extends GlifLayout {
   private void setLottieResource() {
     LottieAnimationView lottieView = findViewById(R.id.sud_lottie_view);
     if (lottieView == null) {
-      Log.w(TAG, "Lottie view not found, skip set resource. Wait for layout inflated.");
+      LOG.w("Lottie view not found, skip set resource. Wait for layout inflated.");
       return;
     }
     if (customLottieResource != 0) {
+      try {
+        LOG.atInfo(
+            "setCustom Lottie resource=" + getResources().getResourceName(customLottieResource));
+      } catch (Exception e) {
+        // Dump the resource id when it failed to get the resource name.
+        LOG.atInfo("setCustom Lottie resource 0x" + Integer.toHexString(customLottieResource));
+      }
+
       InputStream inputRaw = getResources().openRawResource(customLottieResource);
       lottieView.setAnimation(inputRaw, null);
       lottieView.playAnimation();
@@ -536,9 +557,13 @@ public class GlifLoadingLayout extends GlifLayout {
         InputStream inputRaw =
             resourceEntry.getResources().openRawResource(resourceEntry.getResourceId());
         try {
-          Log.i(TAG, "setAnimation " + resourceEntry.getResourceName() + " length=" + inputRaw.available());
+          LOG.atInfo(
+              "setAnimation "
+                  + resourceEntry.getResourceName()
+                  + " length="
+                  + inputRaw.available());
         } catch (IOException e) {
-          Log.w(TAG, "IOException while length of " + resourceEntry.getResourceName());
+          LOG.w("IOException while length of " + resourceEntry.getResourceName());
         }
 
         lottieView.setAnimation(inputRaw, null);
@@ -553,6 +578,9 @@ public class GlifLoadingLayout extends GlifLayout {
                     ? animationConfig.getDarkThemeCustomization()
                     : animationConfig.getLightThemeCustomization());
       } else {
+        LOG.w(
+            "Can not find the resource entry for "
+                + animationConfig.getLottieConfig().getResourceName());
         setLottieLayoutVisibility(View.GONE);
         setIllustrationLayoutVisibility(View.VISIBLE);
         inflateIllustrationStub();
@@ -583,7 +611,7 @@ public class GlifLoadingLayout extends GlifLayout {
   private void setIllustrationResource() {
     View illustrationLayout = findViewById(R.id.sud_layout_progress_illustration);
     if (illustrationLayout == null) {
-      Log.i(TAG, "Illustration stub not inflated, skip set resource");
+      LOG.atInfo("Illustration stub not inflated, skip set resource");
       return;
     }
 
@@ -709,7 +737,15 @@ public class GlifLoadingLayout extends GlifLayout {
 
         // if the activity is embedded should apply an embedded layout.
         if (isEmbeddedActivityOnePaneEnabled(context)) {
-          template = R.layout.sud_glif_fullscreen_loading_embedded_template;
+          // TODO add unit test for this case.
+          if (isGlifExpressiveEnabled()) {
+            template = R.layout.sud_glif_expressive_fullscreen_loading_embedded_template;
+          } else {
+            template = R.layout.sud_glif_fullscreen_loading_embedded_template;
+          }
+          // TODO add unit test for this case.
+        } else if (isGlifExpressiveEnabled()) {
+          template = R.layout.sud_glif_expressive_fullscreen_loading_template;
         } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
           template = R.layout.sud_glif_fullscreen_loading_template_two_pane;
         }
@@ -718,7 +754,15 @@ public class GlifLoadingLayout extends GlifLayout {
 
         // if the activity is embedded should apply an embedded layout.
         if (isEmbeddedActivityOnePaneEnabled(context)) {
-          template = R.layout.sud_glif_loading_embedded_template;
+          if (isGlifExpressiveEnabled()) {
+            template = R.layout.sud_glif_expressive_loading_embedded_template;
+            // TODO add unit test for this case.
+          } else {
+            template = R.layout.sud_glif_loading_embedded_template;
+          }
+          // TODO add unit test for this case.
+        } else if (isGlifExpressiveEnabled()) {
+          template = R.layout.sud_glif_expressive_loading_template;
         } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
           template = R.layout.sud_glif_loading_template_two_pane;
         }
@@ -886,7 +930,7 @@ public class GlifLoadingLayout extends GlifLayout {
           && lottieAnimationView.isAnimating()
           && !isZeroAnimatorDurationScale()
           && shouldAnimationBeFinished) {
-        Log.i(TAG, "Register animation finish.");
+        LOG.atInfo("Register animation finish.");
         lottieAnimationView.addAnimatorListener(animatorListener);
         lottieAnimationView.setRepeatCount(0);
       } else {
diff --git a/main/res/color-v31/gm3_dynamic_neutral_variant22.xml b/main/res/color-v31/gm3_dynamic_neutral_variant22.xml
new file mode 100644
index 0000000..6737f08
--- /dev/null
+++ b/main/res/color-v31/gm3_dynamic_neutral_variant22.xml
@@ -0,0 +1,5 @@
+<?xml version="1.0" encoding="utf-8"?>
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+  <item android:color="@android:color/system_neutral2_600" android:lStar="22"/>
+</selector>
\ No newline at end of file
diff --git a/main/res/drawable/sud_ic_arrow_back.xml b/main/res/drawable/sud_ic_arrow_back.xml
new file mode 100644
index 0000000..f1e1a83
--- /dev/null
+++ b/main/res/drawable/sud_ic_arrow_back.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:autoMirrored="true"
+    android:viewportWidth="24"
+    android:viewportHeight="24">
+    <path
+        android:fillColor="@color/sud_color_surface_container_highest"
+        android:pathData="M20,11H7.83l5.59,-5.59L12,4l-8,8 8,8 1.41,-1.41L7.83,13H20v-2z" />
+</vector>
\ No newline at end of file
diff --git a/main/res/drawable/sud_ic_down_arrow.xml b/main/res/drawable/sud_ic_down_arrow.xml
new file mode 100644
index 0000000..0a4a0a3
--- /dev/null
+++ b/main/res/drawable/sud_ic_down_arrow.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="24"
+    android:viewportHeight="24">
+  <path
+      android:fillColor="@android:color/black"
+      android:pathData="M19,15l-1.41,-1.41L13,18.17V2H11v16.17l-4.59,-4.59L5,15l7,7L19,15z"/>
+</vector>
diff --git a/main/res/drawable/sud_item_background.xml b/main/res/drawable/sud_item_background.xml
new file mode 100644
index 0000000..2dc1bc0
--- /dev/null
+++ b/main/res/drawable/sud_item_background.xml
@@ -0,0 +1,24 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="?attr/sudItemBackgroundColor"/>
+    <corners
+            android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+            android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+            android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+            android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+</shape>
\ No newline at end of file
diff --git a/main/res/drawable/sud_item_background_first.xml b/main/res/drawable/sud_item_background_first.xml
new file mode 100644
index 0000000..544352f
--- /dev/null
+++ b/main/res/drawable/sud_item_background_first.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!--
+    Android frame will make the drawable singleton, so it we use the same drawable in two or more
+    view but do some change in one view programatically, it will change the others together. So
+    we need to create a new drawable for item view which will be with different shape.
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="?attr/sudItemBackgroundColor"/>
+    <corners
+        android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+</shape>
\ No newline at end of file
diff --git a/main/res/drawable/sud_item_background_last.xml b/main/res/drawable/sud_item_background_last.xml
new file mode 100644
index 0000000..844f78b
--- /dev/null
+++ b/main/res/drawable/sud_item_background_last.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!--
+    Android frame will make the drawable singleton, so it we use the same drawable in two or more
+    view but do some change in one view programatically, it will change the others together. So
+    we need to create a new drawable for item view which will be withdifferent shape.
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="?attr/sudItemBackgroundColor"/>
+    <corners
+        android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+</shape>
\ No newline at end of file
diff --git a/main/res/drawable/sud_item_background_single.xml b/main/res/drawable/sud_item_background_single.xml
new file mode 100644
index 0000000..544352f
--- /dev/null
+++ b/main/res/drawable/sud_item_background_single.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!--
+    Android frame will make the drawable singleton, so it we use the same drawable in two or more
+    view but do some change in one view programatically, it will change the others together. So
+    we need to create a new drawable for item view which will be with different shape.
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="?attr/sudItemBackgroundColor"/>
+    <corners
+        android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+</shape>
\ No newline at end of file
diff --git a/main/res/layout-v35/sud_glif_expressive_blank_template_card.xml b/main/res/layout-v35/sud_glif_expressive_blank_template_card.xml
new file mode 100644
index 0000000..fa2da7d
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_blank_template_card.xml
@@ -0,0 +1,53 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    style="@style/SudGlifCardBackground"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:fitsSystemWindows="true"
+    android:gravity="center_horizontal"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+    <com.google.android.setupdesign.view.IntrinsicSizeFrameLayout
+        android:id="@+id/suc_intrinsic_size_layout"
+        style="@style/SudGlifCardContainer"
+        android:layout_width="@dimen/sud_glif_card_width"
+        android:layout_height="wrap_content"
+        android:height="@dimen/sud_glif_card_height">
+
+        <include layout="@layout/sud_glif_expressive_blank_template_content_layout" />
+
+    </com.google.android.setupdesign.view.IntrinsicSizeFrameLayout>
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_blank_template_compact.xml b/main/res/layout-v35/sud_glif_expressive_blank_template_compact.xml
new file mode 100644
index 0000000..2538455
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_blank_template_compact.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<com.google.android.setupcompat.view.StatusBarBackgroundLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
+
+    <include layout="@layout/sud_glif_expressive_blank_template_content_layout" />
+
+</com.google.android.setupcompat.view.StatusBarBackgroundLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_blank_template_content.xml b/main/res/layout-v35/sud_glif_expressive_blank_template_content.xml
new file mode 100644
index 0000000..7d1ebf3
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_blank_template_content.xml
@@ -0,0 +1,52 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <ViewStub
+        android:id="@+id/sud_layout_sticky_header"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+        <FrameLayout
+            android:id="@+id/sud_layout_content"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent" />
+
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+
+    <ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_blank_template_content_wide.xml b/main/res/layout-v35/sud_glif_expressive_blank_template_content_wide.xml
new file mode 100644
index 0000000..b7a7bc6
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_blank_template_content_wide.xml
@@ -0,0 +1,77 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+        <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:baselineAligned="false" android:orientation="horizontal">
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_header_area"
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="@dimen/sud_glif_land_header_area_weight"
+            android:orientation="vertical">
+
+            <ViewStub
+                android:id="@+id/sud_layout_sticky_header"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content" />
+
+        </LinearLayout>
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_content_area"
+            style="@style/SudLandContentContianerStyle"
+            android:paddingTop="?attr/sudGlifContentPaddingTop"
+            android:orientation="vertical">
+
+            <FrameLayout
+                android:id="@+id/sud_layout_content"
+                android:layout_width="match_parent"
+                android:layout_height="0dp"
+                android:layout_weight="1" />
+
+        </LinearLayout>
+
+    </LinearLayout>
+
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+
+    <ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_card.xml b/main/res/layout-v35/sud_glif_expressive_list_template_card.xml
new file mode 100644
index 0000000..d22235f
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_card.xml
@@ -0,0 +1,53 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    style="@style/SudGlifCardBackground"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:fitsSystemWindows="true"
+    android:gravity="center_horizontal"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+    <com.google.android.setupdesign.view.IntrinsicSizeFrameLayout
+        android:id="@+id/suc_intrinsic_size_layout"
+        style="@style/SudGlifCardContainer"
+        android:layout_width="@dimen/sud_glif_card_width"
+        android:layout_height="wrap_content"
+        android:height="@dimen/sud_glif_card_height">
+
+        <include layout="@layout/sud_glif_expressive_list_template_content_layout" />
+
+    </com.google.android.setupdesign.view.IntrinsicSizeFrameLayout>
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_compact.xml b/main/res/layout-v35/sud_glif_expressive_list_template_compact.xml
new file mode 100644
index 0000000..197144b
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_compact.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<com.google.android.setupcompat.view.StatusBarBackgroundLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
+
+    <include layout="@layout/sud_glif_expressive_list_template_content_layout" />
+
+</com.google.android.setupcompat.view.StatusBarBackgroundLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_content.xml b/main/res/layout-v35/sud_glif_expressive_list_template_content.xml
new file mode 100644
index 0000000..aba3f4d
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_content.xml
@@ -0,0 +1,59 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <ViewStub
+        android:id="@+id/sud_layout_sticky_header"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+        <!-- Ignore UnusedAttribute: scrollIndicators is new in M. Default to no indicators in older
+             versions. -->
+        <com.google.android.setupdesign.view.StickyHeaderListView
+            xmlns:app="http://schemas.android.com/apk/res-auto"
+            android:id="@android:id/list"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:scrollIndicators="?attr/sudScrollIndicators"
+            app:sudHeader="@layout/sud_glif_header"
+            tools:ignore="UnusedAttribute" />
+
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+
+    <ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml b/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml
new file mode 100644
index 0000000..b49e569
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml
@@ -0,0 +1,89 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+        <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:baselineAligned="false" android:orientation="horizontal">
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_header_area"
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="@dimen/sud_glif_land_header_area_weight"
+            android:orientation="vertical">
+
+            <ViewStub
+                android:id="@+id/sud_layout_sticky_header"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content" />
+
+            <com.google.android.setupdesign.view.BottomScrollView
+                android:id="@+id/sud_header_scroll_view"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:fillViewport="true"
+                android:scrollIndicators="?attr/sudScrollIndicators">
+
+                <include layout="@layout/sud_glif_header" />
+
+            </com.google.android.setupdesign.view.BottomScrollView>
+
+        </LinearLayout>
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_content_area"
+            style="@style/SudLandContentContianerStyle"
+            android:paddingTop="?attr/sudGlifContentPaddingTop"
+            android:orientation="vertical">
+
+            <com.google.android.setupdesign.view.StickyHeaderListView
+                xmlns:app="http://schemas.android.com/apk/res-auto"
+                android:id="@android:id/list"
+                android:layout_width="match_parent"
+                android:layout_height="0dp"
+                android:layout_weight="1"
+                android:scrollIndicators="?attr/sudScrollIndicators" />
+
+        </LinearLayout>
+
+    </LinearLayout>
+
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+<ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_preference_template_card.xml b/main/res/layout-v35/sud_glif_expressive_preference_template_card.xml
new file mode 100644
index 0000000..db235e9
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_preference_template_card.xml
@@ -0,0 +1,53 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    style="@style/SudGlifCardBackground"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:fitsSystemWindows="true"
+    android:gravity="center_horizontal"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+    <com.google.android.setupdesign.view.IntrinsicSizeFrameLayout
+        android:id="@+id/suc_intrinsic_size_layout"
+        style="@style/SudGlifCardContainer"
+        android:layout_width="@dimen/sud_glif_card_width"
+        android:layout_height="wrap_content"
+        android:height="@dimen/sud_glif_card_height">
+
+        <include layout="@layout/sud_glif_expressive_preference_template_content_layout" />
+
+    </com.google.android.setupdesign.view.IntrinsicSizeFrameLayout>
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_preference_template_compact.xml b/main/res/layout-v35/sud_glif_expressive_preference_template_compact.xml
new file mode 100644
index 0000000..8528f9f
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_preference_template_compact.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<com.google.android.setupcompat.view.StatusBarBackgroundLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
+
+    <include layout="@layout/sud_glif_expressive_preference_template_content_layout" />
+
+</com.google.android.setupcompat.view.StatusBarBackgroundLayout>
\ No newline at end of file
diff --git a/main/res/layout-v35/sud_glif_expressive_preference_template_content.xml b/main/res/layout-v35/sud_glif_expressive_preference_template_content.xml
new file mode 100644
index 0000000..dd364ed
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_preference_template_content.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:orientation="vertical"
+    android:filterTouchesWhenObscured="true">
+
+    <include layout="@layout/sud_glif_expressive_blank_template_content_layout" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_preference_template_content_wide.xml b/main/res/layout-v35/sud_glif_expressive_preference_template_content_wide.xml
new file mode 100644
index 0000000..c420bab
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_preference_template_content_wide.xml
@@ -0,0 +1,88 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+        <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:baselineAligned="false" android:orientation="horizontal">
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_header_area"
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="@dimen/sud_glif_land_header_area_weight"
+            android:orientation="vertical">
+
+            <ViewStub
+                android:id="@+id/sud_layout_sticky_header"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content" />
+
+            <com.google.android.setupdesign.view.BottomScrollView
+                android:id="@+id/sud_header_scroll_view"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:fillViewport="true"
+                android:scrollIndicators="?attr/sudScrollIndicators">
+
+                <include layout="@layout/sud_glif_header" />
+
+            </com.google.android.setupdesign.view.BottomScrollView>
+
+        </LinearLayout>
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_content_area"
+            style="@style/SudLandContentContianerStyle"
+            android:paddingTop="?attr/sudGlifContentPaddingTop"
+            android:orientation="vertical">
+
+            <FrameLayout
+                android:id="@+id/sud_layout_content"
+                android:layout_width="match_parent"
+                android:layout_height="0dp"
+                android:layout_weight="1" />
+
+        </LinearLayout>
+
+    </LinearLayout>
+
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+
+    <ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml
new file mode 100644
index 0000000..80b4f0b
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml
@@ -0,0 +1,53 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2015 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    style="@style/SudGlifCardBackground"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:fitsSystemWindows="true"
+    android:gravity="center_horizontal"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+    <com.google.android.setupdesign.view.IntrinsicSizeFrameLayout
+        android:id="@+id/suc_intrinsic_size_layout"
+        style="@style/SudGlifCardContainer"
+        android:layout_width="@dimen/sud_glif_card_width"
+        android:layout_height="wrap_content"
+        android:height="@dimen/sud_glif_card_height">
+
+        <include layout="@layout/sud_glif_expressive_recycler_template_content_layout" />
+
+    </com.google.android.setupdesign.view.IntrinsicSizeFrameLayout>
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_compact.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_compact.xml
new file mode 100644
index 0000000..c20aa6a
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_compact.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<com.google.android.setupcompat.view.StatusBarBackgroundLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
+
+    <include layout="@layout/sud_glif_expressive_recycler_template_content_layout" />
+
+</com.google.android.setupcompat.view.StatusBarBackgroundLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml
new file mode 100644
index 0000000..9067b52
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml
@@ -0,0 +1,60 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <ViewStub
+        android:id="@+id/sud_layout_sticky_header"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+        <!-- Ignore UnusedAttribute: scrollIndicators is new in M. Default to no indicators in older
+             versions. -->
+        <com.google.android.setupdesign.view.HeaderRecyclerView
+            android:id="@+id/sud_recycler_view"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:scrollbars="vertical"
+            android:scrollIndicators="?attr/sudScrollIndicators"
+            app:sudHeader="@layout/sud_glif_header"
+            tools:ignore="UnusedAttribute" />
+
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+
+    <ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml
new file mode 100644
index 0000000..64d6a53
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml
@@ -0,0 +1,91 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+        <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:baselineAligned="false" android:orientation="horizontal">
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_header_area"
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="@dimen/sud_glif_land_header_area_weight"
+            android:orientation="vertical">
+
+            <ViewStub
+                android:id="@+id/sud_layout_sticky_header"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content" />
+
+            <com.google.android.setupdesign.view.BottomScrollView
+                android:id="@+id/sud_header_scroll_view"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:fillViewport="true"
+                android:scrollIndicators="?attr/sudScrollIndicators">
+
+                <include layout="@layout/sud_glif_header" />
+
+            </com.google.android.setupdesign.view.BottomScrollView>
+
+        </LinearLayout>
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_content_area"
+            style="@style/SudLandContentContianerStyle"
+            android:paddingTop="?attr/sudGlifContentPaddingTop"
+            android:orientation="vertical">
+
+            <com.google.android.setupdesign.view.HeaderRecyclerView
+                android:id="@+id/sud_recycler_view"
+                android:layout_width="match_parent"
+                android:layout_height="0dp"
+                android:layout_weight="1"
+                android:scrollbars="vertical"
+                android:scrollIndicators="?attr/sudScrollIndicators" />
+
+        </LinearLayout>
+
+    </LinearLayout>
+
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+
+    <ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_template_card.xml b/main/res/layout-v35/sud_glif_expressive_template_card.xml
new file mode 100644
index 0000000..24adaa7
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_template_card.xml
@@ -0,0 +1,53 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2015 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    style="@style/SudGlifCardBackground"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:fitsSystemWindows="true"
+    android:gravity="center_horizontal"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+    <com.google.android.setupdesign.view.IntrinsicSizeFrameLayout
+        android:id="@+id/suc_intrinsic_size_layout"
+        style="@style/SudGlifCardContainer"
+        android:layout_width="@dimen/sud_glif_card_width"
+        android:layout_height="wrap_content"
+        android:height="@dimen/sud_glif_card_height">
+
+        <include layout="@layout/sud_glif_expressive_template_content_layout" />
+
+    </com.google.android.setupdesign.view.IntrinsicSizeFrameLayout>
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_weight="1"
+        android:visibility="invisible" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_template_compact.xml b/main/res/layout-v35/sud_glif_expressive_template_compact.xml
new file mode 100644
index 0000000..a78e165
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_template_compact.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<com.google.android.setupcompat.view.StatusBarBackgroundLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/suc_layout_status"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true">
+
+    <include layout="@layout/sud_glif_expressive_template_content_layout" />
+
+</com.google.android.setupcompat.view.StatusBarBackgroundLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_template_content.xml b/main/res/layout-v35/sud_glif_expressive_template_content.xml
new file mode 100644
index 0000000..6f4c1e6
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_template_content.xml
@@ -0,0 +1,82 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <ViewStub
+        android:id="@+id/sud_layout_sticky_header"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+        <!-- Ignore UnusedAttribute: scrollIndicators is new in M. Default to no indicators in older
+             versions. -->
+        <com.google.android.setupdesign.view.BottomScrollView
+            android:id="@+id/sud_scroll_view"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:fillViewport="true"
+            android:scrollIndicators="?attr/sudScrollIndicators"
+            tools:ignore="UnusedAttribute">
+
+            <LinearLayout
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:orientation="vertical">
+
+                <include layout="@layout/sud_glif_header" />
+
+                <ViewStub
+                    android:id="@+id/sud_layout_illustration_progress_stub"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:inflatedId="@+id/sud_layout_progress_illustration"
+                    android:layout="@layout/sud_progress_illustration_layout" />
+
+                <FrameLayout
+                    android:id="@+id/sud_layout_content"
+                    android:layout_width="match_parent"
+                    android:layout_height="0dp"
+                    android:layout_weight="1" />
+
+            </LinearLayout>
+
+        </com.google.android.setupdesign.view.BottomScrollView>
+
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+
+    <ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_template_content_wide.xml b/main/res/layout-v35/sud_glif_expressive_template_content_wide.xml
new file mode 100644
index 0000000..afaae98
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_template_content_wide.xml
@@ -0,0 +1,111 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
+     See https://developer.android.com/privacy-and-security/risks/tapjacking -->
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/sud_layout_template_content"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <FrameLayout
+        android:id="@+id/sud_layout_container"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:layout_weight="1">
+
+        <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:baselineAligned="false" android:orientation="horizontal">
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_header_area"
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="@dimen/sud_glif_land_header_area_weight"
+            android:orientation="vertical">
+
+            <ViewStub
+                android:id="@+id/sud_layout_sticky_header"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content" />
+
+            <com.google.android.setupdesign.view.BottomScrollView
+                android:id="@+id/sud_header_scroll_view"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:fillViewport="true"
+                android:scrollIndicators="?attr/sudScrollIndicators">
+
+                <include layout="@layout/sud_glif_header" />
+
+            </com.google.android.setupdesign.view.BottomScrollView>
+
+        </LinearLayout>
+
+        <LinearLayout
+            android:id="@+id/sud_landscape_content_area"
+            style="@style/SudLandContentContianerStyle"
+            android:orientation="vertical">
+
+            <com.google.android.setupdesign.view.BottomScrollView
+                android:id="@+id/sud_scroll_view"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:fillViewport="true"
+                android:scrollIndicators="?attr/sudScrollIndicators"
+                android:importantForAccessibility="no">
+
+                <LinearLayout
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:orientation="vertical">
+
+                    <FrameLayout
+                        android:id="@+id/sud_layout_content"
+                        android:paddingTop="?attr/sudGlifContentPaddingTop"
+                        android:layout_width="match_parent"
+                        android:layout_height="0dp"
+                        android:layout_weight="1" />
+
+                    <ViewStub
+                        android:id="@+id/sud_layout_illustration_progress_stub"
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:inflatedId="@+id/sud_layout_progress_illustration"
+                        android:layout="@layout/sud_progress_illustration_layout" />
+                </LinearLayout>
+
+            </com.google.android.setupdesign.view.BottomScrollView>
+
+        </LinearLayout>
+
+    </LinearLayout>
+
+        <include layout="@layout/sud_glif_floating_back_button" />
+    </FrameLayout>
+
+    <ViewStub
+        android:id="@+id/suc_layout_footer"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content" />
+
+</LinearLayout>
diff --git a/main/res/layout/sud_back_button.xml b/main/res/layout/sud_back_button.xml
new file mode 100644
index 0000000..095b22c
--- /dev/null
+++ b/main/res/layout/sud_back_button.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+  <com.google.android.material.button.MaterialButton
+    xmlns:android="http://schemas.android.com/apk/res/android"
+      xmlns:app="http://schemas.android.com/apk/res-auto"
+      xmlns:tools="http://schemas.android.com/tools"
+      android:id="@+id/floating_back_button"
+      style="?attr/materialIconButtonFilledStyle"
+      android:layout_width="wrap_content"
+      android:layout_height="wrap_content"
+      android:checkable="true"
+      android:contentDescription="@string/sud_back_button_label"
+      android:filterTouchesWhenObscured="true"
+      android:visibility="gone"
+      app:icon="@drawable/sud_ic_arrow_back"
+      tools:visibility="visible" />
diff --git a/main/res/layout/sud_empty_linear_layout.xml b/main/res/layout/sud_empty_linear_layout.xml
new file mode 100644
index 0000000..1bb9f16
--- /dev/null
+++ b/main/res/layout/sud_empty_linear_layout.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:clickable="false"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+</LinearLayout>
\ No newline at end of file
diff --git a/main/res/layout/sud_glif_floating_back_button.xml b/main/res/layout/sud_glif_floating_back_button.xml
new file mode 100644
index 0000000..4443694
--- /dev/null
+++ b/main/res/layout/sud_glif_floating_back_button.xml
@@ -0,0 +1,38 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    xmlns:tools="http://schemas.android.com/tools"
+    style="@style/SudGlifButtonContainer"
+    android:id="@+id/sud_layout_floating_back_button_container"
+    android:layout_width="wrap_content"
+    android:layout_height="wrap_content"
+    android:visibility="gone"
+    tools:visibility="visible">
+
+  <ViewStub
+      android:id="@+id/sud_floating_back_button_stub"
+      android:layout_width="wrap_content"
+      android:layout_height="wrap_content"
+      android:checkable="true"
+      android:contentDescription="@string/sud_back_button_label"
+      android:filterTouchesWhenObscured="true"
+      android:visibility="gone"
+      android:inflatedId="@+id/sud_floating_back_button"
+      android:layout="@layout/sud_back_button"
+      tools:visibility="visible" />
+</FrameLayout>
diff --git a/main/res/layout/sud_glif_header.xml b/main/res/layout/sud_glif_header.xml
index df30ff7..e5955c3 100644
--- a/main/res/layout/sud_glif_header.xml
+++ b/main/res/layout/sud_glif_header.xml
@@ -16,10 +16,12 @@
 -->
 
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
     android:id="@+id/sud_layout_header"
     style="@style/SudGlifHeaderContainer"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
+    android:filterTouchesWhenObscured="true"
     android:orientation="vertical">
 
     <ProgressBar
@@ -32,6 +34,16 @@
         android:visibility="gone"
         android:indeterminate="true" />
 
+    <ViewStub
+        android:id="@+id/sud_glif_top_progress_indicator_stub"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_marginLeft="?attr/sudMarginStart"
+        android:layout_marginRight="?attr/sudMarginStart"
+        android:paddingBottom="@dimen/sud_glif_expressive_progress_indicator_padding_bottom"
+        android:inflatedId="@+id/sud_layout_progress_indicator"
+        android:layout="@layout/sud_progress_indicator" />
+
     <FrameLayout
         android:id="@+id/sud_layout_icon_container"
         style="@style/SudGlifIconContainer"
@@ -83,4 +95,15 @@
         android:visibility="gone"
         android:indeterminate="true" />
 
+    <ViewStub
+        android:id="@+id/sud_glif_progress_indicator_stub"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="@dimen/sud_glif_expressive_progress_indicator_margin_vertical"
+        android:layout_marginLeft="?attr/sudMarginStart"
+        android:layout_marginRight="?attr/sudMarginStart"
+        android:paddingBottom="@dimen/sud_glif_expressive_progress_indicator_padding_bottom"
+        android:inflatedId="@+id/sud_layout_progress_indicator"
+        android:layout="@layout/sud_progress_indicator" />
+
 </LinearLayout>
diff --git a/main/res/layout/sud_progress_indicator.xml b/main/res/layout/sud_progress_indicator.xml
new file mode 100644
index 0000000..68250e4
--- /dev/null
+++ b/main/res/layout/sud_progress_indicator.xml
@@ -0,0 +1,27 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<com.google.android.material.progressindicator.LinearProgressIndicator 
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/progress_indicator"
+    style="@style/SudLinearProgressIndicatorWavy"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:layout_marginLeft="?attr/sudMarginStart"
+    android:layout_marginRight="?attr/sudMarginStart"
+    android:filterTouchesWhenObscured="true"
+    android:indeterminate="true" />
diff --git a/main/res/values-night-v31/colors.xml b/main/res/values-night-v31/colors.xml
index cd2a6d5..1fa9f19 100644
--- a/main/res/values-night-v31/colors.xml
+++ b/main/res/values-night-v31/colors.xml
@@ -32,4 +32,15 @@
   <color name="sud_system_hyperlink_text">@color/sud_system_accent1_300</color>
   <color name="sud_system_surface">@color/sud_system_neutral1_800</color>
 
+
+  <color name="sud_color_on_surface">@android:color/system_neutral1_100</color>
+  <color name="sud_color_surface_container_highest">@color/m3_ref_palette_dynamic_neutral_variant22</color>
+
+  <!-- Glif expressive colors -->
+  <color name="sud_glif_expressive_footer_bar_bg_color">@color/gm3_dynamic_neutral_variant22</color>
+  <color name="sud_glif_expressive_footer_button_bg_color">@color/sud_system_accent1_200</color>
+  <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@color/sud_system_accent1_800</color>
+  <color name="sud_glif_expressive_footer_primary_button_disable_text_color">@color/sud_system_neutral2_200</color>
+  <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">@color/sud_system_accent2_100</color>
+  <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">@color/sud_system_neutral2_200</color>
 </resources>
\ No newline at end of file
diff --git a/main/res/values-night-v34/colors.xml b/main/res/values-night-v34/colors.xml
new file mode 100644
index 0000000..a71c4de
--- /dev/null
+++ b/main/res/values-night-v34/colors.xml
@@ -0,0 +1,44 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+
+  <color name="sud_color_on_surface">@android:color/system_on_surface_dark</color>
+  <color name="sud_color_surface_container_highest">@android:color/system_surface_container_highest_dark</color>
+
+  <!-- Surface container color dark -->
+  <color name="sud_system_sc_highest_dark">@android:color/system_surface_container_highest_dark</color>
+  <!-- Primary dark -->
+  <color name="sud_color_primary">@android:color/system_primary_dark</color>
+  <!-- System on primary dark -->
+  <color name="sud_system_on_primary">@android:color/system_on_primary_dark</color>
+  <!-- On surface variant dark -->
+  <color name="sud_on_surface_variant">@android:color/system_on_surface_variant_dark</color>
+  <!-- On secondary container -->
+  <color name="sud_on_secondary_container">@android:color/system_on_secondary_container_dark</color>
+  <!-- Surface container high dark -->
+  <color name="sud_color_surface_container_high">@android:color/system_surface_container_high_dark</color>
+
+  <!-- Glif expressive colors -->
+
+  <color name="sud_glif_expressive_footer_bar_bg_color">@color/sud_system_sc_highest_dark</color>
+  <color name="sud_glif_expressive_footer_button_bg_color">@color/sud_color_primary</color>
+  <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@color/sud_system_on_primary</color>
+  <color name="sud_glif_expressive_footer_primary_button_disable_text_color">@color/sud_on_surface_variant</color>
+  <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">@color/sud_on_secondary_container</color>
+  <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">@color/sud_on_surface_variant</color>
+</resources>
\ No newline at end of file
diff --git a/main/res/values-night/colors.xml b/main/res/values-night/colors.xml
index 1062ea7..8eb370b 100644
--- a/main/res/values-night/colors.xml
+++ b/main/res/values-night/colors.xml
@@ -28,4 +28,20 @@
 
 
   <color name="sud_uniformity_backdrop_color">#2A2B2E</color>
+  <!-- Default color for the footer button bg (primary80) -->
+  <color name="sud_glif_expressive_footer_button_bg_color">#ffd0bcff</color>
+
+
+  <color name="sud_color_on_surface">@color/sud_neutral90</color>
+  <color name="sud_color_surface_container_highest">@color/sud_neutral22</color>
+
+  <!-- Glif expressive style -->
+  <!-- primary20 -->
+  <color name="sud_glif_expressive_footer_primary_button_enable_text_color">#ff062e6f</color>
+  <!-- neutral_variant80 -->
+  <color name="sud_glif_expressive_footer_primary_button_disable_text_color">#ffcac4d0</color>
+  <!-- secondary90 -->
+  <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">#ffe8def8</color>
+  <!-- neutral_variant80 -->
+  <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">#ffcac4d0</color>
 </resources>
\ No newline at end of file
diff --git a/main/res/values-night/styles.xml b/main/res/values-night/styles.xml
index 555473e..ca27a7b 100644
--- a/main/res/values-night/styles.xml
+++ b/main/res/values-night/styles.xml
@@ -23,6 +23,7 @@
     <style name="SudThemeGlifV2.DayNight" parent="SudThemeGlifV2" />
     <style name="SudThemeGlifV3.DayNight" parent="SudThemeGlifV3" />
     <style name="SudThemeGlifV4.DayNight" parent="SudThemeGlifV4" />
+    <style name="SudThemeGlifExpressive.DayNight" parent="SudThemeGlifExpressive" />
 
     <!-- DynamicColor DayNight themes -->
     <style name="SudDynamicColorThemeGlifV3.DayNight" parent="SudDynamicColorThemeGlifV3" />
diff --git a/main/res/values-v31/colors.xml b/main/res/values-v31/colors.xml
index 12b13eb..133d274 100644
--- a/main/res/values-v31/colors.xml
+++ b/main/res/values-v31/colors.xml
@@ -35,6 +35,8 @@
 
 
 
+  <color name="sud_system_accent1_0">@android:color/system_accent1_0</color>
+
   <color name="sud_system_accent1_100">@android:color/system_accent1_100</color>
 
   <color name="sud_system_accent1_200">@android:color/system_accent1_200</color>
@@ -43,6 +45,8 @@
 
   <color name="sud_system_accent1_600">@android:color/system_accent1_600</color>
 
+  <color name="sud_system_accent1_800">@android:color/system_accent1_800</color>
+
 
 
   <color name="sud_system_accent2_100">@android:color/system_accent2_100</color>
@@ -51,6 +55,8 @@
 
   <color name="sud_system_accent2_600">@android:color/system_accent2_600</color>
 
+  <color name="sud_system_accent2_900">@android:color/system_accent2_900</color>
+
 
 
   <color name="sud_system_accent3_100">@android:color/system_accent3_100</color>
@@ -128,4 +134,16 @@
   <color name="sud_dynamic_switch_thumb_on_light">@color/sud_system_accent1_100</color>
 
   <color name="sud_dynamic_switch_thumb_on_dark">@color/sud_system_accent1_100</color>
+
+
+  <color name="sud_color_on_surface">@color/sud_system_neutral1_900</color>
+  <color name="sud_color_surface_container_highest">@color/sud_system_neutral2_100</color>
+
+  <!-- Glif expressive colors -->
+  <color name="sud_glif_expressive_footer_bar_bg_color">@color/sud_system_neutral2_100</color>
+  <color name="sud_glif_expressive_footer_button_bg_color">@color/sud_system_accent1_600</color>
+  <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@color/sud_system_accent1_0</color>
+  <color name="sud_glif_expressive_footer_primary_button_disable_text_color">@color/sud_system_neutral2_700</color>
+  <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">@color/sud_system_accent2_900</color>
+  <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">@color/sud_system_neutral2_700</color>
 </resources>
diff --git a/main/res/values-v31/styles.xml b/main/res/values-v31/styles.xml
index 6230a07..55f5be8 100644
--- a/main/res/values-v31/styles.xml
+++ b/main/res/values-v31/styles.xml
@@ -379,4 +379,132 @@
     <item name="android:textAppearanceSmallPopupMenu">@android:style/TextAppearance.DeviceDefault.Widget.PopupMenu.Small</item>
   </style>
 
+    <style name="SudThemeGlifExpressive" parent="SudBaseThemeGlifExpressive">
+        <!-- Copied from v31 SudThemeGlif -->
+        <item name="sucSystemNavBarBackgroundColor">?android:attr/navigationBarColor</item>
+        <item name="android:windowSplashScreenBackground">?android:attr/colorBackground</item>
+
+        <!-- Copied from v31 SudThemeGlifV3 -->
+        <item name="android:navigationBarDividerColor" tools:ignore="NewApi">@color/sud_glif_v3_nav_bar_divider_color_dark</item>
+        <item name="android:windowLightNavigationBar" tools:ignore="NewApi">false</item>
+        <item name="sucLightSystemNavBar" tools:ignore="NewApi">?android:attr/windowLightNavigationBar</item>
+        <item name="sucSystemNavBarDividerColor" tools:ignore="NewApi">?android:attr/navigationBarDividerColor</item>
+        <!-- Default font family-->
+        <item name="android:textAppearance">@android:style/TextAppearance.DeviceDefault</item>
+        <item name="android:textAppearanceInverse">@android:style/TextAppearance.DeviceDefault.Inverse</item>
+        <item name="android:textAppearanceLarge">@android:style/TextAppearance.DeviceDefault.Large</item>
+        <item name="android:textAppearanceMedium">@android:style/TextAppearance.DeviceDefault.Medium</item>
+        <!-- For textView -->
+        <item name="android:textAppearanceSmall">@android:style/TextAppearance.DeviceDefault.Small</item>
+        <item name="android:textAppearanceLargeInverse">@android:style/TextAppearance.DeviceDefault.Large.Inverse</item>
+        <!-- For editText -->
+        <item name="android:textAppearanceMediumInverse">@android:style/TextAppearance.DeviceDefault.Medium.Inverse</item>
+        <item name="android:textAppearanceSmallInverse">@android:style/TextAppearance.DeviceDefault.Small.Inverse</item>
+        <item name="android:textAppearanceSearchResultTitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Title</item>
+        <item name="android:textAppearanceSearchResultSubtitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Subtitle</item>
+        <item name="android:textAppearanceButton">@android:style/TextAppearance.DeviceDefault.Widget.Button</item>
+
+        <!-- Copied from v31 SudDynamicColorBaseTheme -->
+        <item name="android:colorAccent">?attr/colorAccent</item>
+
+        <!-- Copied from v31 SudFullDynamicColorTheme -->
+        <item name="android:windowAnimationStyle">@style/Animation.SudWindowAnimation.DynamicColor</item>
+
+        <!-- Copied from v31 SudDynamicColorThemeGlifV3 -->
+        <item name="android:datePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme</item>
+        <item name="android:timePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme</item>
+        <item name="sudSwitchBarThumbOnColor">@color/sud_dynamic_switch_thumb_on_dark</item>
+        <item name="sudSwitchBarTrackOnColor">@color/sud_dynamic_switch_track_on_dark</item>
+        <item name="sudSwitchBarThumbOffColor">@color/sud_dynamic_switch_thumb_off_dark</item>
+        <item name="sudSwitchBarTrackOffColor">@color/sud_dynamic_switch_track_off_dark</item>
+        <item name="sudSwitchBarTrackOffOutlineColor">@color/sud_dynamic_switch_thumb_off_outline_dark</item>
+        <item name="sudEditBoxColor">@color/sud_dynamic_color_accent_glif_v3_dark</item>
+
+        <!-- Copied from v31 SudFullDynamicColorThemeGlifV3 -->
+        <item name="android:colorForeground">@android:color/system_neutral1_50</item>
+        <item name="android:colorForegroundInverse">@color/sud_system_background_surface</item>
+        <item name="android:colorBackgroundCacheHint">@color/sud_system_background_surface</item>
+        <item name="colorBackgroundFloating">@color/sud_system_background_surface</item>
+        <item name="android:navigationBarColor">@color/sud_system_background_surface</item>
+        <item name="colorControlNormal">?android:attr/textColorSecondary</item>
+        <item name="colorControlHighlight">@color/ripple_material_dark</item>
+        <item name="colorButtonNormal">@color/button_material_dark</item>
+        <item name="colorSwitchThumbNormal">@color/switch_thumb_material_dark</item>
+        <item name="android:alertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
+    </style>
+
+    <style name="SudThemeGlifExpressive.Light" parent="SudBaseThemeGlifExpressive.Light">
+        <!-- Copied from v31 SudThemeGlif.Light -->
+        <item name="sucSystemNavBarBackgroundColor">?android:attr/navigationBarColor</item>
+        <item name="android:windowSplashScreenBackground">?android:attr/colorBackground</item>
+
+        <!-- Copied from v31 SudThemeGlifV3.Light -->
+        <item name="android:navigationBarDividerColor">@color/sud_glif_v3_nav_bar_divider_color_light</item>
+        <item name="android:windowLightNavigationBar">true</item>
+        <item name="sucLightSystemNavBar" tools:ignore="NewApi">?android:attr/windowLightNavigationBar</item>
+        <item name="sucSystemNavBarDividerColor" tools:ignore="NewApi">?android:attr/navigationBarDividerColor</item>
+        <!-- Default font family-->
+        <item name="android:textAppearance">@android:style/TextAppearance.DeviceDefault</item>
+        <item name="android:textAppearanceInverse">@android:style/TextAppearance.DeviceDefault.Inverse</item>
+        <item name="android:textAppearanceLarge">@android:style/TextAppearance.DeviceDefault.Large</item>
+        <item name="android:textAppearanceMedium">@android:style/TextAppearance.DeviceDefault.Medium</item>
+        <!-- For textView -->
+        <item name="android:textAppearanceSmall">@android:style/TextAppearance.DeviceDefault.Small</item>
+        <item name="android:textAppearanceLargeInverse">@android:style/TextAppearance.DeviceDefault.Large.Inverse</item>
+        <!-- For editText -->
+        <item name="android:textAppearanceMediumInverse">@android:style/TextAppearance.DeviceDefault.Medium.Inverse</item>
+        <item name="android:textAppearanceSmallInverse">@android:style/TextAppearance.DeviceDefault.Small.Inverse</item>
+        <item name="android:textAppearanceSearchResultTitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Title</item>
+        <item name="android:textAppearanceSearchResultSubtitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Subtitle</item>
+        <item name="android:textAppearanceButton">@android:style/TextAppearance.DeviceDefault.Widget.Button</item>
+
+        <!-- Copied from v31 SudDynamicColorBaseTheme.Light -->
+        <item name="android:colorAccent">?attr/colorAccent</item>
+
+        <!-- Copied from v31 SudDynamicColorThemeGlifV3.Light -->
+        <item name="android:windowAnimationStyle">@style/Animation.SudWindowAnimation.DynamicColor</item>
+
+        <!-- Copied from v31 SudDynamicColorThemeGlifV3.Light -->
+        <item name="android:datePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme.Light</item>
+        <item name="android:timePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme.Light</item>
+        <item name="sudSwitchBarThumbOnColor">@color/sud_dynamic_switch_thumb_on_light</item>
+        <item name="sudSwitchBarTrackOnColor">@color/sud_dynamic_switch_track_on_light</item>
+        <item name="sudSwitchBarThumbOffColor">@color/sud_dynamic_switch_thumb_off_light</item>
+        <item name="sudSwitchBarTrackOffColor">@color/sud_dynamic_switch_track_off_light</item>
+        <item name="sudSwitchBarTrackOffOutlineColor">@color/sud_dynamic_switch_thumb_off_outline_light</item>
+        <item name="sudEditBoxColor">@color/sud_dynamic_color_accent_glif_v3_light</item>
+
+        <!-- Copied from v31 SudFullDynamicColorThemeGlifV3.Light -->
+        <item name="android:colorForeground">@android:color/system_neutral1_900</item>
+        <item name="android:colorForegroundInverse">@color/sud_system_background_surface</item>
+        <item name="android:colorBackgroundCacheHint">@color/sud_system_background_surface</item>
+        <item name="colorBackgroundFloating">@color/sud_system_background_surface</item>
+        <item name="android:navigationBarColor">@color/sud_system_background_surface</item>
+        <item name="colorControlNormal">?android:attr/textColorSecondary</item>
+        <item name="colorControlHighlight">@color/ripple_material_light</item>
+        <item name="colorButtonNormal">@color/button_material_light</item>
+        <item name="colorSwitchThumbNormal">@color/switch_thumb_material_light</item>
+        <item name="android:alertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
+    </style>
+
+  <style name="SudGlifExpressiveDialogTheme" parent="ThemeOverlay.Material3.MaterialAlertDialog">
+    <item name="alertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
+    <item name="android:textAllCaps">false</item>
+    <item name="android:fontFamily">@string/sudGlifExpressiveDialogFontFamily</item>
+    <item name="android:background">@color/sud_color_surface_container_high</item>
+    <item name="android:windowTitleStyle">@style/SudGlifExpressiveWindowTitleTextAppearance</item>
+    <item name="dialogCornerRadius">@dimen/sud_glif_device_default_dialog_corner_radius</item>
+    <!-- Body text color -->
+    <item name="android:textColorPrimary">@color/sud_on_surface_variant</item>
+  </style>
+
+  <style name="SudGlifExpressiveWindowTitleTextAppearance" parent="RtlOverlay.DialogWindowTitle.AppCompat">
+    <item name="android:textAppearance">@style/SudGlifExpressiveWindowTitleTextStyle</item>
+  </style>
+
+  <style name="SudGlifExpressiveWindowTitleTextStyle" parent="SudDeviceDefaultWindowTitleTextAppearance">
+    <item name="android:textSize">@dimen/sud_glif_expressive_alert_dialog_title_font_size</item>
+    <item name="android:textColor">@color/sud_color_on_surface</item>
+  </style>
+
 </resources>
diff --git a/main/res/values-v34/colors.xml b/main/res/values-v34/colors.xml
index 5d454ee..90c9d1a 100644
--- a/main/res/values-v34/colors.xml
+++ b/main/res/values-v34/colors.xml
@@ -20,6 +20,18 @@
   <color name="sud_dynamic_color_accent_glif_v3_dark">@color/sud_system_accent1_300</color>
   <!-- Surface container color -->
   <color name="sud_system_sc_highest_dark">@android:color/system_surface_container_highest_dark</color>
+  <!-- Surface container highest color light -->
+  <color name="sud_system_sc_highest_light">@android:color/system_surface_container_highest_light</color>
+  <!-- System on primary light -->
+  <color name="sud_system_on_primary">@android:color/system_on_primary_light</color>
+  <!-- On surface variant light -->
+  <color name="sud_on_surface_variant">@android:color/system_on_surface_variant_light</color>
+  <!-- On secondary container -->
+  <color name="sud_on_secondary_container">@android:color/system_on_secondary_container_light</color>
+  <!-- Primary light -->
+  <color name="sud_color_primary">@android:color/system_primary_light</color>
+  <!-- Surface container high light -->
+  <color name="sud_color_surface_container_high">@android:color/system_surface_container_high_light</color>
 
 
   <color name="sud_dynamic_switch_thumb_off_light">@color/sud_system_neutral2_500</color>
@@ -32,4 +44,16 @@
 
   <color name="sud_dynamic_switch_thumb_off_outline_dark">@color/sud_system_neutral2_400</color>
 
+
+  <color name="sud_color_on_surface">@android:color/system_on_surface_light</color>
+  <color name="sud_color_surface_container_highest">@android:color/system_surface_container_highest_light</color>
+
+  <!-- Glif expressive colors -->
+
+  <color name="sud_glif_expressive_footer_bar_bg_color">@color/sud_system_sc_highest_light</color>
+  <color name="sud_glif_expressive_footer_button_bg_color">@color/sud_color_primary</color>
+  <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@color/sud_system_on_primary</color>
+  <color name="sud_glif_expressive_footer_primary_button_disable_text_color">@color/sud_on_surface_variant</color>
+  <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">@color/sud_on_secondary_container</color>
+  <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">@color/sud_on_surface_variant</color>
 </resources>
\ No newline at end of file
diff --git a/main/res/values-v35/layouts.xml b/main/res/values-v35/layouts.xml
new file mode 100644
index 0000000..10e8059
--- /dev/null
+++ b/main/res/values-v35/layouts.xml
@@ -0,0 +1,35 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+    <item name="sud_glif_expressive_template" type="layout">@layout/sud_glif_expressive_template_compact</item>
+    <item name="sud_glif_expressive_embedded_template" type="layout">@layout/sud_glif_embedded_template_compact</item>
+    <item name="sud_glif_expressive_list_template" type="layout">@layout/sud_glif_expressive_list_template_compact</item>
+    <item name="sud_glif_expressive_list_embedded_template" type="layout">@layout/sud_glif_list_embedded_template_compact</item>
+    <!-- Ignore UnusedResources: can be used by clients -->
+    <item name="sud_glif_expressive_blank_template" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_expressive_blank_template_compact</item>
+    <item name="sud_glif_expressive_preference_template" type="layout">@layout/sud_glif_expressive_preference_template_compact</item>
+    <item name="sud_glif_expressive_preference_embedded_template" type="layout">@layout/sud_glif_blank_embedded_template_compact</item>
+    <item name="sud_glif_expressive_recycler_template" type="layout">@layout/sud_glif_expressive_recycler_template_compact</item>
+    <item name="sud_glif_expressive_recycler_embedded_template" type="layout">@layout/sud_glif_recycler_embedded_template_compact</item>
+
+    <item name="sud_glif_expressive_template_content_layout" type="layout">@layout/sud_glif_expressive_template_content</item>
+    <item name="sud_glif_expressive_list_template_content_layout" type="layout">@layout/sud_glif_expressive_list_template_content</item>
+    <item name="sud_glif_expressive_blank_template_content_layout" type="layout">@layout/sud_glif_expressive_blank_template_content</item>
+    <item name="sud_glif_expressive_preference_template_content_layout" type="layout">@layout/sud_glif_expressive_preference_template_content</item>
+    <item name="sud_glif_expressive_recycler_template_content_layout" type="layout">@layout/sud_glif_expressive_recycler_template_content</item>
+</resources>
diff --git a/main/res/values-w600dp-h480dp-v35/layouts.xml b/main/res/values-w600dp-h480dp-v35/layouts.xml
new file mode 100644
index 0000000..ddc3067
--- /dev/null
+++ b/main/res/values-w600dp-h480dp-v35/layouts.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+    <item name="sud_glif_expressive_template" type="layout">@layout/sud_glif_expressive_template_card</item>
+    <item name="sud_glif_expressive_embedded_template" type="layout">@layout/sud_glif_embedded_template_card</item>
+    <item name="sud_glif_expressive_list_template" type="layout">@layout/sud_glif_expressive_list_template_card</item>
+    <item name="sud_glif_expressive_list_embedded_template" type="layout">@layout/sud_glif_list_embedded_template_card</item>
+    <item name="sud_glif_expressive_blank_template" type="layout">@layout/sud_glif_expressive_blank_template_card</item>
+    <item name="sud_glif_expressive_preference_template" type="layout">@layout/sud_glif_expressive_preference_template_card</item>
+    <item name="sud_glif_expressive_preference_embedded_template" type="layout">@layout/sud_glif_blank_embedded_template_card</item>
+    <item name="sud_glif_expressive_recycler_template" type="layout">@layout/sud_glif_expressive_recycler_template_card</item>
+    <item name="sud_glif_expressive_recycler_embedded_template" type="layout">@layout/sud_glif_recycler_embedded_template_card</item>
+</resources>
\ No newline at end of file
diff --git a/main/res/values-w600dp-h900dp-v35/layouts.xml b/main/res/values-w600dp-h900dp-v35/layouts.xml
new file mode 100644
index 0000000..d7a0457
--- /dev/null
+++ b/main/res/values-w600dp-h900dp-v35/layouts.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+    <item name="sud_glif_expressive_template_content_layout" type="layout">@layout/sud_glif_expressive_template_content</item>
+    <item name="sud_glif_expressive_list_template_content_layout" type="layout">@layout/sud_glif_expressive_list_template_content</item>
+    <item name="sud_glif_expressive_blank_template_content_layout" type="layout">@layout/sud_glif_expressive_blank_template_content</item>
+    <item name="sud_glif_expressive_preference_template_content_layout" type="layout">@layout/sud_glif_expressive_preference_template_content</item>
+    <item name="sud_glif_expressive_recycler_template_content_layout" type="layout">@layout/sud_glif_expressive_recycler_template_content</item>
+
+</resources>
diff --git a/main/res/values-w600dp-h900dp/dimens.xml b/main/res/values-w600dp-h900dp/dimens.xml
new file mode 100644
index 0000000..d2c6984
--- /dev/null
+++ b/main/res/values-w600dp-h900dp/dimens.xml
@@ -0,0 +1,35 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+    <!-- General dimension for glif expressive theme -->
+    <!-- Calculated by (Spec = 72dp - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_footer_padding_start">68dp</dimen>
+    <!-- Calculated by (Spec = 72dp - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_footer_padding_end">68dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_start">104dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_end">116dp</dimen>
+
+    <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_button_margin_end">80dp</dimen>
+    <!-- Calculated by (sud_glif_expressive_margin_start - sud_glif_expressive_button_padding) -->
+    <dimen name="sud_glif_expressive_button_margin_start">92dp</dimen>
+    <dimen name="sud_glif_expressive_content_padding_top">0dp</dimen>
+    <dimen name="sud_glif_expressive_item_margin_start">64dp</dimen>
+    <dimen name="sud_glif_expressive_item_margin_end">64dp</dimen>
+
+</resources>
diff --git a/main/res/values-w600dp-v35/layouts.xml b/main/res/values-w600dp-v35/layouts.xml
new file mode 100644
index 0000000..753a15d
--- /dev/null
+++ b/main/res/values-w600dp-v35/layouts.xml
@@ -0,0 +1,24 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+    <item name="sud_glif_expressive_preference_template_content_layout" type="layout">@layout/sud_glif_expressive_preference_template_content</item>
+    <item name="sud_glif_expressive_recycler_template_content_layout" type="layout">@layout/sud_glif_expressive_recycler_template_content_wide</item>
+</resources>
diff --git a/main/res/values-w600dp/dimens.xml b/main/res/values-w600dp/dimens.xml
new file mode 100644
index 0000000..5169873
--- /dev/null
+++ b/main/res/values-w600dp/dimens.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<resources>
+
+  <!-- Glif expressive footer bar padding -->
+  <!-- Calculated by (Spec = 12dp - 4dp internal padding of button) -->
+  <dimen name="sud_glif_expressive_footer_padding_start">8dp</dimen>
+  <!-- Calculated by (Spec = 24dp - 4dp internal padding of button) -->
+  <dimen name="sud_glif_expressive_footer_padding_end">20dp</dimen>
+
+</resources>
diff --git a/main/res/values-w840dp-h480dp/dimens.xml b/main/res/values-w840dp-h480dp/dimens.xml
new file mode 100644
index 0000000..ab62dbe
--- /dev/null
+++ b/main/res/values-w840dp-h480dp/dimens.xml
@@ -0,0 +1,36 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+    <!-- General dimension for glif expressive theme -->
+    <!-- Calculated by (Spec = 36dp - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_footer_padding_start">32dp</dimen>
+    <!-- Calculated by (Spec = 48dp - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_footer_padding_end">44dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_vertical">6dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_start">32dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_end">44dp</dimen>
+
+    <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_button_margin_end">44dp</dimen>
+    <!-- Calculated by (sud_glif_expressive_margin_start - sud_glif_expressive_button_padding) -->
+    <dimen name="sud_glif_expressive_button_margin_start">32dp</dimen>
+    <dimen name="sud_glif_expressive_content_padding_top">80dp</dimen>
+    <dimen name="sud_glif_expressive_item_margin_start">28dp</dimen>
+    <dimen name="sud_glif_expressive_item_margin_end">40dp</dimen>
+
+</resources>
diff --git a/main/res/values-w840dp-v34/layouts.xml b/main/res/values-w840dp-v35/layouts.xml
similarity index 100%
rename from main/res/values-w840dp-v34/layouts.xml
rename to main/res/values-w840dp-v35/layouts.xml
diff --git a/main/res/values-w840dp/dimens.xml b/main/res/values-w840dp/dimens.xml
new file mode 100644
index 0000000..a3e386c
--- /dev/null
+++ b/main/res/values-w840dp/dimens.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+    <!-- General -->
+    <dimen name="sud_glif_expressive_footer_bar_min_height">52dp</dimen>
+    <dimen name="sud_glif_expressive_footer_padding_vertical">0dp</dimen>
+    <!-- Calculated by (Spec = 12dp - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_footer_bar_padding_start">8dp</dimen>
+    <!-- Calculated by (Spec = 24dp - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_footer_bar_padding_end">20dp</dimen>
+
+    <dimen name="sud_glif_expressive_content_padding_top">8dp</dimen>
+    <dimen name="sud_glif_expressive_item_margin_start">4dp</dimen>
+    <dimen name="sud_glif_expressive_item_margin_end">16dp</dimen>
+</resources>
diff --git a/main/res/values/attrs.xml b/main/res/values/attrs.xml
index 16b656d..5651f45 100644
--- a/main/res/values/attrs.xml
+++ b/main/res/values/attrs.xml
@@ -42,6 +42,21 @@
         <flag name="end" value="0x00800005" />
     </attr>
 
+    <attr name="sudGlifIconGravity">
+        <!-- Push object to the left of its container, not changing its size. -->
+        <flag name="left" value="0x03" />
+        <!-- Push object to the right of its container, not changing its size. -->
+        <flag name="right" value="0x05" />
+        <!-- Place object in the horizontal center of its container, not changing its size. -->
+        <flag name="center_horizontal" value="0x01" />
+        <!-- Grow the horizontal size of the object if needed so it completely fills its container. -->
+        <flag name="fill_horizontal" value="0x07" />
+        <!-- Push object to the beginning of its container, not changing its size. -->
+        <flag name="start" value="0x00800003" />
+        <!-- Push object to the end of its container, not changing its size. -->
+        <flag name="end" value="0x00800005" />
+    </attr>
+
     <attr name="sudGlifSubtitleGravity">
         <!-- Push object to the left of its container, not changing its size. -->
         <flag name="left" value="0x03" />
@@ -142,8 +157,27 @@
     <attr name="sudItemDescriptionTitleStyle" format="reference" />
     <attr name="sudItemDescriptionTitleTextAppearence" format="reference" />
     <attr name="sudItemVerboseTitleStyle" format="reference" />
+    <attr name="sudItemIconContainerWidth" format="dimension|reference" />
+    <attr name="sudItemPaddingTop" format="dimension|reference" />
+    <attr name="sudItemPaddingBottom" format="dimension|reference" />
+    <attr name="sudItemDividerWidth" format="dimension|reference" />
+    <attr name="sudItemBackgroundPaddingStart" format="dimension|reference" />
+    <attr name="sudItemBackgroundPaddingEnd" format="dimension|reference" />
+    <attr name="sudItemBackgroundColor" format="color|reference" />
+    <attr name="sudItemDescriptionPaddingTop" format="dimension|reference" />
+    <attr name="sudItemDescriptionPaddingBottom" format="dimension|reference" />
+    <attr name="sudItemSummaryPaddingTop" format="dimension|reference" />
+    <attr name="sudItemSummaryPaddingBottom" format="dimension|reference" />
+    <attr name="sudItemBackground" format="color|reference" />
+    <attr name="sudItemBackgroundFirst" format="color|reference" />
+    <attr name="sudItemBackgroundLast" format="color|reference" />
+    <attr name="sudItemBackgroundSingle" format="color|reference" />
+    <attr name="sudItemCornerRadius" format="dimension|reference" />
     <attr name="sudContentFramePaddingTop" format="dimension|reference" />
     <attr name="sudContentFramePaddingBottom" format="dimension|reference" />
+    <attr name="sudAccountAvatarMarginEnd" format="dimension|reference" />
+    <attr name="sudAccountAvatarMaxHeight" format="dimension|reference" />
+    <attr name="sudAccountNameTextSize" format="dimension|reference" />
 
     <!-- EditBox -->
     <attr name="sudEditBoxStyle" format="reference" />
@@ -308,4 +342,7 @@
     <attr name="sudSwitchBarTrackOnColor" format="color|reference" />
     <attr name="sudSwitchBarTrackOffColor" format="color|reference" />
     <attr name="sudSwitchBarTrackOffOutlineColor" format="color|reference" />
+
+    <!-- Footer bar style -->
+    <attr name="sudFooterBackgroundColor" format="color" />
 </resources>
diff --git a/main/res/values/colors.xml b/main/res/values/colors.xml
index d52e2b6..58bce17 100644
--- a/main/res/values/colors.xml
+++ b/main/res/values/colors.xml
@@ -198,4 +198,30 @@
 
 
     <color name="sud_autofilled_highlight_bg_color">#4dffeb3b</color>
+
+    <color name="sud_neutral10">#ff1f1f1f</color>
+    <color name="sud_neutral22">#ff343535</color>
+    <color name="sud_neutral90">#ffe3e3e3</color>
+
+
+    <color name="sud_color_on_surface">@color/sud_neutral10</color>
+    <color name="sud_color_surface_container_highest">@color/sud_neutral90</color>
+
+    <!-- Glif expressive style -->
+    <!-- Default color for the footer bg (transparent) -->
+    <color name="sud_glif_expressive_footer_bar_bg_color">#00000000</color>
+    <!-- Default color for the footer button bg (primary40) -->
+    <color name="sud_glif_expressive_footer_button_bg_color">#ff6750a4</color>
+
+    <!-- Default color for the floating back button-->
+    <color name="sud_glif_expressive_back_button_bg_color">@color/sud_color_surface_container_highest</color>
+    <color name="sud_glif_expressive_ic_back_arrow_color">@color/sud_color_on_surface</color>
+    <!-- white -->
+    <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@android:color/white</color>
+    <!-- neutral_variant30 -->
+    <color name="sud_glif_expressive_footer_primary_button_disable_text_color">#ff49454f</color>
+    <!-- secondary10 -->
+    <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">#ff1d192b</color>
+    <!-- neutral_variant30 -->
+    <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">#ff49454f</color>
 </resources>
diff --git a/main/res/values/config.xml b/main/res/values/config.xml
index 79a2779..bb1a88f 100644
--- a/main/res/values/config.xml
+++ b/main/res/values/config.xml
@@ -30,8 +30,13 @@
     <string name="sudFontSecondary" translatable="false">google-sans</string>
     <string name="sudFontSecondaryText" translatable="false">google-sans-text</string>
     <string name="sudFontSecondaryMedium" translatable="false">google-sans-medium</string>
-    <!-- Material You button font family-->
+    <!-- Material You button font family -->
     <string name="sudFontSecondaryMediumMaterialYou" translatable="false">google-sans-text-medium</string>
     <item name="sud_layout_description" type="id" />
 
+    <!-- Glif expressive button styles -->
+    <string name="sudExpressiveButtonFontFamily" translatable="false">Roboto</string>
+
+    <!-- Glif expressive alert dialog styles -->
+    <string name="sudGlifExpressiveDialogFontFamily" translatable="false">google-sans-text</string>
 </resources>
diff --git a/main/res/values/dimens.xml b/main/res/values/dimens.xml
index 8626945..da71a0e 100644
--- a/main/res/values/dimens.xml
+++ b/main/res/values/dimens.xml
@@ -49,6 +49,7 @@
     <!-- Calculated by (sud_glif_margin_end - 4dp internal padding of button) -->
     <dimen name="sud_glif_footer_padding_end">20dp</dimen>
     <dimen name="sud_glif_footer_bar_min_height">72dp</dimen>
+    <dimen name="sud_glif_footer_middle_spacing">0dp</dimen>
     <dimen name="sud_glif_margin_start">24dp</dimen>
     <dimen name="sud_glif_margin_end">24dp</dimen>
     <dimen name="sud_glif_icon_margin_top">56dp</dimen>
@@ -168,6 +169,7 @@
 
     <!-- Footer Button-->
     <dimen name="sud_glif_footer_button_text_size">14sp</dimen>
+    <dimen name="sud_glif_footer_button_line_spacing_extra">8sp</dimen>
     <dimen name="sud_glif_primary_button_button_margin_start">0dp</dimen>
     <dimen name="sud_glif_secondary_button_button_margin_start">0dp</dimen>
 
@@ -181,6 +183,9 @@
     <dimen name="sud_items_summary_margin_top">4dp</dimen>
     <dimen name="sud_items_padding_top">15dp</dimen>
     <dimen name="sud_items_padding_bottom">15dp</dimen>
+    <dimen name="sud_items_divder_width">2dp</dimen>
+    <dimen name="sud_items_background_padding_start">16dp</dimen>
+    <dimen name="sud_items_background_padding_end">16dp</dimen>
 
     <!-- General Material You -->
     <dimen name="sud_glif_land_middle_horizontal_spacing_material_you">48dp</dimen>
@@ -210,7 +215,6 @@
     <dimen name="sud_footer_bar_button_radius_material_you">20dp</dimen>
     <dimen name="sud_glif_button_min_height_material_you">48dp</dimen>
     <dimen name="sud_glif_footer_button_text_size_material_you">14sp</dimen>
-
     <dimen name="sud_glif_primary_button_button_margin_start_material_you">0dp</dimen>
 
     <!-- Footer Bar Material You -->
@@ -317,4 +321,61 @@
     <dimen name="sud_glif_margin_end_embedded_activity">24dp</dimen>
     <dimen name="sud_glif_header_title_margin_top_embedded_activity">24dp</dimen>
     <dimen name="sud_header_title_size_embedded_activity">44sp</dimen>
+
+
+    <!-- General dimension for glif expressive theme -->
+    <!-- Page Margins Glif Expressive -->
+    <dimen name="sud_glif_expressive_margin_start">24dp</dimen>
+    <dimen name="sud_glif_expressive_margin_end">24dp</dimen>
+
+    <dimen name="sud_glif_expressive_footer_padding_vertical">8dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_min_height">72dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_vertical">6dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_start">8dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_end">20dp</dimen>
+    <dimen name="sud_glif_expressive_footer_button_min_height">56dp</dimen>
+    <dimen name="sud_glif_expressive_footer_button_radius">28dp</dimen>
+    <dimen name="sud_glif_expressive_footer_button_text_size">16sp</dimen>
+    <dimen name="sud_glif_expressive_footer_button_text_line_spacing_extra">8dp</dimen>
+
+    <dimen name="sud_glif_expressive_button_padding">16dp</dimen>
+    <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_button_margin_end">20dp</dimen>
+    <!-- Calculated by (sud_glif_expressive_margin_start - sud_glif_expressive_button_padding) -->
+    <dimen name="sud_glif_expressive_button_margin_start">8dp</dimen>
+    <dimen name="sud_glif_expressive_description_margin_top">8dp</dimen>
+    <dimen name="sud_glif_expreesive_description_margin_bottom">0dp</dimen>
+    <dimen name="sud_glif_expressive_icon_margin_top">8dp</dimen>
+    <dimen name="sud_glif_expressive_content_padding_top">8dp</dimen>
+    <dimen name="sud_glif_expressive_item_margin_start">16dp</dimen>
+    <dimen name="sud_glif_expressive_item_margin_end">16dp</dimen>
+    <dimen name="sud_glif_expressive_item_corner_radius">2dp</dimen>
+    <dimen name="sud_glif_expressive_item_icon_padding_end">12dp</dimen>
+    <dimen name="sud_items_summary_text_size_expressive">14sp</dimen>
+    <dimen name="sud_items_title_text_size_expressive">16sp</dimen>
+    <dimen name="sud_expressive_switch_padding_start">12dp</dimen>
+    <dimen name="sud_glif_expressive_footer_button_middle_spacing">8dp</dimen>
+
+    <!-- Header layout expressive -->
+    <dimen name="sud_glif_expressive_header_title_line_spacing_extra">8sp</dimen>
+
+    <!-- Progress indicator-->
+    <dimen name="sud_glif_expressive_progress_indicator_margin_vertical">16dp</dimen>
+    <dimen name="sud_glif_expressive_progress_indicator_padding_bottom">7dp</dimen>
+
+    <!-- Material floating back button-->
+    <dimen name="sud_glif_expressive_back_button_margin_top">8dp</dimen>
+    <dimen name="sud_glif_expressive_back_button_height">48dp</dimen>
+
+    <!-- Glif expressive footer bar -->
+    <!-- footer bar padding -->
+    <!-- TODO: b/365906034 - Add padding attributes and values to the SUW side. -->
+    <!-- Calculated by (Spec = 24dp - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_footer_padding_start">20dp</dimen>
+    <!-- Calculated by (Spec = 24dp - 4dp internal padding of button) -->
+    <dimen name="sud_glif_expressive_footer_padding_end">20dp</dimen>
+    <dimen name="sud_glif_expressive_footer_padding_top">16dp</dimen>
+    <dimen name="sud_glif_expressive_footer_padding_bottom">8dp</dimen>
+    <!-- Glif expressive alert dialog -->
+    <dimen name="sud_glif_expressive_alert_dialog_title_font_size">24sp</dimen>
 </resources>
diff --git a/main/res/values/integers.xml b/main/res/values/integers.xml
new file mode 100644
index 0000000..f0c81f0
--- /dev/null
+++ b/main/res/values/integers.xml
@@ -0,0 +1,23 @@
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<resources>
+    <!-- Default button font weight -->
+    <integer name="sud_glif_footer_button_weight">400</integer>
+
+    <!-- Glif expressive button styles -->
+    <integer name="sud_glif_expressive_footer_button_weight">500</integer>
+
+</resources>
\ No newline at end of file
diff --git a/main/res/values/styles.xml b/main/res/values/styles.xml
index 5957865..992777f 100644
--- a/main/res/values/styles.xml
+++ b/main/res/values/styles.xml
@@ -55,6 +55,7 @@
         <item name="sudDividerShown">true</item>
         <item name="sudItemDescriptionStyle">@style/SudItemContainer.Description</item>
         <item name="sudItemDescriptionTitleStyle">@style/SudItemTitle</item>
+        <item name="sudItemBackground">@null</item>
         <item name="sudListItemIconColor">@color/sud_list_item_icon_color_dark</item>
         <item name="sudMarginStart">@dimen/sud_layout_margin_sides</item>
         <item name="sudMarginEnd">@dimen/sud_layout_margin_sides</item>
@@ -69,6 +70,13 @@
         <item name="sudEditBoxColor">@color/sud_color_accent_dark</item>
         <item name="sudItemContainerStyle">@style/SudItemContainer</item>
         <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
+        <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
+        <item name="sudItemPaddingTop">@dimen/sud_items_padding_top</item>
+        <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom</item>
+        <item name="sudItemDescriptionPaddingTop">@dimen/sud_description_margin_top</item>
+        <item name="sudItemDescriptionPaddingBottom">@dimen/sud_description_margin_bottom_lists</item>
+        <item name="sudItemSummaryPaddingTop">0dp</item>
+        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
         <item name="sudItemTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryGlif</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
@@ -110,6 +118,7 @@
         <item name="sudDividerShown">true</item>
         <item name="sudItemDescriptionStyle">@style/SudItemContainer.Description</item>
         <item name="sudItemDescriptionTitleStyle">@style/SudItemTitle</item>
+        <item name="sudItemBackground">@null</item>
         <item name="sudListItemIconColor">@color/sud_list_item_icon_color_light</item>
         <item name="sudMarginStart">@dimen/sud_layout_margin_sides</item>
         <item name="sudMarginEnd">@dimen/sud_layout_margin_sides</item>
@@ -123,7 +132,14 @@
         <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
         <item name="sudEditBoxColor">@color/sud_color_accent_light</item>
         <item name="sudItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
         <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
+        <item name="sudItemPaddingTop">@dimen/sud_items_padding_top</item>
+        <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom</item>
+        <item name="sudItemDescriptionPaddingTop">@dimen/sud_description_margin_top</item>
+        <item name="sudItemDescriptionPaddingBottom">@dimen/sud_description_margin_bottom_lists</item>
+        <item name="sudItemSummaryPaddingTop">0dp</item>
+        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
         <item name="sudItemTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryGlif</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
@@ -151,6 +167,9 @@
         <item name="colorPrimary">?attr/colorAccent</item>
         <item name="listPreferredItemPaddingLeft">?attr/sudMarginStart</item>
         <item name="listPreferredItemPaddingRight">?attr/sudMarginEnd</item>
+        <item name="sudAccountAvatarMarginEnd">@dimen/sud_account_avatar_margin_end</item>
+        <item name="sudAccountAvatarMaxHeight">@dimen/sud_account_avatar_max_height</item>
+        <item name="sudAccountNameTextSize">@dimen/sud_account_name_text_size</item>
         <item name="sudButtonAllCaps">true</item>
         <item name="sudButtonCornerRadius">@dimen/sud_glif_button_corner_radius</item>
         <item name="sudButtonFontFamily">sans-serif-medium</item>
@@ -174,6 +193,7 @@
         <item name="sudGlifAccountAvatarStyle">@style/SudGlifAccountAvatar</item>
         <item name="sudGlifHeaderTitleStyle">@style/SudGlifHeaderTitle</item>
         <item name="sudGlifHeaderGravity">start</item>
+        <item name="sudGlifIconGravity">?attr/sudGlifHeaderGravity</item>
         <item name="sudGlifSubtitleGravity">start</item>
         <item name="sucGlifHeaderMarginTop">@dimen/sud_glif_header_title_margin_top</item>
         <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_header_title_margin_bottom</item>
@@ -208,6 +228,11 @@
         <item name="sucFooterBarMinHeight">@dimen/sud_glif_footer_bar_min_height</item>
         <item name="sucFooterButtonPaddingStart">@dimen/sud_glif_button_padding</item>
         <item name="sucFooterButtonPaddingEnd">@dimen/sud_glif_button_padding</item>
+        <item name="sucFooterBarButtonMinHeight">@dimen/sud_glif_button_min_height</item>
+        <item name="sucFooterBarButtonMiddleSpacing">@dimen/sud_glif_footer_middle_spacing</item>
+        <item name="sucFooterBarButtonFontWeight">@integer/sud_glif_footer_button_weight</item>
+        <item name="sucFooterBarButtonTextSize">@dimen/sud_glif_footer_button_text_size</item>
+        <item name="sucFooterButtonTextLineSpacingExtra">@dimen/sud_glif_footer_button_line_spacing_extra</item>
         <item name="sudContentIllustrationMaxWidth">@dimen/sud_content_illustration_max_width</item>
         <item name="sudContentIllustrationMaxHeight">@dimen/sud_content_illustration_max_height</item>
         <item name="sudContentIllustrationPaddingTop">@dimen/sud_content_illustration_padding_vertical</item>
@@ -221,11 +246,23 @@
         <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
         <item name="sudEditBoxColor">@color/sud_color_accent_glif_dark</item>
         <item name="sudItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
         <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
+        <item name="sudItemPaddingTop">@dimen/sud_items_padding_top</item>
+        <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom</item>
+        <item name="sudItemDescriptionPaddingTop">@dimen/sud_description_glif_margin_top</item>
+        <item name="sudItemDescriptionPaddingBottom">@dimen/sud_description_glif_margin_bottom_lists</item>
         <item name="sudItemTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryGlif</item>
+        <item name="sudItemSummaryPaddingTop">0dp</item>
+        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
         <item name="sudItemVerboseTitleStyle">@style/SudItemTitle.Verbose</item>
+        <item name="sudItemBackground">@null</item>
+        <item name="sudItemBackgroundFirst">@null</item>
+        <item name="sudItemBackgroundLast">@null</item>
+        <item name="sudItemBackgroundSingle">@null</item>
+        <item name="sudItemCornerRadius">0dp</item>
     </style>
     <style name="SudThemeGlif" parent="SudBaseThemeGlif"/>
 
@@ -251,6 +288,9 @@
         <item name="colorPrimary">?attr/colorAccent</item>
         <item name="listPreferredItemPaddingLeft">?attr/sudMarginStart</item>
         <item name="listPreferredItemPaddingRight">?attr/sudMarginEnd</item>
+        <item name="sudAccountAvatarMarginEnd">@dimen/sud_account_avatar_margin_end</item>
+        <item name="sudAccountAvatarMaxHeight">@dimen/sud_account_avatar_max_height</item>
+        <item name="sudAccountNameTextSize">@dimen/sud_account_name_text_size</item>
         <item name="sudButtonAllCaps">true</item>
         <item name="sudButtonCornerRadius">@dimen/sud_glif_button_corner_radius</item>
         <item name="sudButtonFontFamily">sans-serif-medium</item>
@@ -274,6 +314,7 @@
         <item name="sudGlifAccountAvatarStyle">@style/SudGlifAccountAvatar</item>
         <item name="sudGlifHeaderTitleStyle">@style/SudGlifHeaderTitle</item>
         <item name="sudGlifHeaderGravity">start</item>
+        <item name="sudGlifIconGravity">?attr/sudGlifHeaderGravity</item>
         <item name="sudGlifSubtitleGravity">start</item>
         <item name="sucGlifHeaderMarginTop">@dimen/sud_glif_header_title_margin_top</item>
         <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_header_title_margin_bottom</item>
@@ -308,6 +349,11 @@
         <item name="sucFooterBarMinHeight">@dimen/sud_glif_footer_bar_min_height</item>
         <item name="sucFooterButtonPaddingStart">@dimen/sud_glif_button_padding</item>
         <item name="sucFooterButtonPaddingEnd">@dimen/sud_glif_button_padding</item>
+        <item name="sucFooterBarButtonMinHeight">@dimen/sud_glif_button_min_height</item>
+        <item name="sucFooterBarButtonMiddleSpacing">@dimen/sud_glif_footer_middle_spacing</item>
+        <item name="sucFooterBarButtonFontWeight">@integer/sud_glif_footer_button_weight</item>
+        <item name="sucFooterBarButtonTextSize">@dimen/sud_glif_footer_button_text_size</item>
+        <item name="sucFooterButtonTextLineSpacingExtra">@dimen/sud_glif_footer_button_line_spacing_extra</item>
         <item name="sudContentIllustrationMaxWidth">@dimen/sud_content_illustration_max_width</item>
         <item name="sudContentIllustrationMaxHeight">@dimen/sud_content_illustration_max_height</item>
         <item name="sudContentIllustrationPaddingTop">@dimen/sud_content_illustration_padding_vertical</item>
@@ -321,11 +367,23 @@
         <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
         <item name="sudEditBoxColor">@color/sud_color_accent_glif_light</item>
         <item name="sudItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
         <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
+        <item name="sudItemPaddingTop">@dimen/sud_items_padding_top</item>
+        <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom</item>
+        <item name="sudItemDescriptionPaddingTop">@dimen/sud_description_glif_margin_top</item>
+        <item name="sudItemDescriptionPaddingBottom">@dimen/sud_description_glif_margin_bottom_lists</item>
         <item name="sudItemTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryGlif</item>
+        <item name="sudItemSummaryPaddingTop">0dp</item>
+        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
         <item name="sudItemVerboseTitleStyle">@style/SudItemTitle.Verbose</item>
+        <item name="sudItemBackground">@null</item>
+        <item name="sudItemBackgroundFirst">@null</item>
+        <item name="sudItemBackgroundLast">@null</item>
+        <item name="sudItemBackgroundSingle">@null</item>
+        <item name="sudItemCornerRadius">0dp</item>
     </style>
     <style name="SudThemeGlif.Light" parent="SudBaseThemeGlif.Light"/>
 
@@ -339,6 +397,7 @@
         <item name="sudDividerInsetStart">?attr/sudMarginStart</item>
         <item name="sudDividerInsetStartNoIcon">?attr/sudMarginStart</item>
         <item name="sudGlifHeaderGravity">center_horizontal</item>
+        <item name="sudGlifIconGravity">?attr/sudGlifHeaderGravity</item>
         <item name="sudGlifSubtitleGravity">center_horizontal</item>
         <item name="sudScrollIndicators">top|bottom</item>
         <item name="sudEditTextBackgroundColor">@color/sud_glif_edit_text_bg_dark_color</item>
@@ -358,6 +417,7 @@
         <item name="sudDividerInsetStart">?attr/sudMarginStart</item>
         <item name="sudDividerInsetStartNoIcon">?attr/sudMarginStart</item>
         <item name="sudGlifHeaderGravity">center_horizontal</item>
+        <item name="sudGlifIconGravity">?attr/sudGlifHeaderGravity</item>
         <item name="sudGlifSubtitleGravity">center_horizontal</item>
         <item name="sudScrollIndicators">top|bottom</item>
         <item name="sudEditTextBackgroundColor">@color/sud_glif_edit_text_bg_light_color</item>
@@ -407,12 +467,14 @@
         <item name="sucFooterBarButtonFontFamily">@string/sudFontSecondaryMediumMaterialYou</item>
         <item name="sucGlifIconMarginTop">@dimen/sud_glif_icon_margin_top_material_you</item>
         <item name="sucFooterBarButtonAlignEnd">@bool/suc_footer_bar_button_align_end</item>
+        <item name="sucFooterBarButtonMinHeight">@dimen/sud_glif_button_min_height_material_you</item>
         <item name="sudButtonCornerRadius">@dimen/sud_footer_bar_button_radius_material_you</item>
         <item name="sudButtonTertiaryGravity">center_horizontal</item>
         <item name="sudGlifIconSize">@dimen/sud_glif_icon_max_height_material_you</item>
         <item name="sudGlifAccountContainerStyle">@style/SudGlifAccountContainerMaterialYou</item>
         <item name="sudGlifHeaderTitleStyle">@style/SudGlifHeaderTitleMaterialYou</item>
         <item name="sudGlifHeaderGravity">start</item>
+        <item name="sudGlifIconGravity">?attr/sudGlifHeaderGravity</item>
         <item name="sucGlifHeaderMarginTop">@dimen/sud_glif_header_title_margin_top_material_you</item>
         <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_header_title_margin_bottom_material_you</item>
         <item name="sudGlifDescriptionStyle">@style/SudGlifDescriptionMaterialYou</item>
@@ -423,8 +485,12 @@
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudMaterialYouDescription</item>
         <item name="sudDividerShown">false</item>
         <item name="sudItemContainerStyle">@style/SudItemContainerMaterialYou</item>
+        <item name="sudItemPaddingTop">@dimen/sud_items_padding_top_material_you</item>
+        <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
         <item name="sudItemTitleStyle">@style/SudItemTitleMaterialYou</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryMaterialYou</item>
+        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
+        <item name="sudItemSummaryPaddingTop">@dimen/sud_items_summary_margin_top_material_you</item>
         <item name="sudItemDescriptionTitleStyle">@style/SudItemTitleMaterialYou</item>
         <item name="sudItemDescriptionStyle">@style/SudItemContainerMaterialYou.Description</item>
         <item name="sudItemVerboseTitleStyle">@style/SudMaterialYouItemTitle.Verbose</item>
@@ -439,6 +505,7 @@
         <item name="sucFooterBarPaddingEnd">@dimen/sud_glif_footer_bar_padding_end_material_you</item>
         <item name="sucFooterBarMinHeight">@dimen/sud_glif_footer_bar_min_height_material_you</item>
         <item name="sucFooterBarButtonAlignEnd">@bool/suc_footer_bar_button_align_end</item>
+        <item name="sucFooterBarButtonMinHeight">@dimen/sud_glif_button_min_height_material_you</item>
         <item name="sudMarginEnd">@dimen/sud_glif_margin_end_material_you</item>
         <item name="sucHeaderContainerMarginBottom">@dimen/sud_header_container_margin_bottom_material_you</item>
         <item name="sucFooterBarButtonFontFamily">@string/sudFontSecondaryMediumMaterialYou</item>
@@ -449,6 +516,7 @@
         <item name="sudGlifAccountContainerStyle">@style/SudGlifAccountContainerMaterialYou</item>
         <item name="sudGlifHeaderTitleStyle">@style/SudGlifHeaderTitleMaterialYou</item>
         <item name="sudGlifHeaderGravity">start</item>
+        <item name="sudGlifIconGravity">?attr/sudGlifHeaderGravity</item>
         <item name="sucGlifHeaderMarginTop">@dimen/sud_glif_header_title_margin_top_material_you</item>
         <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_header_title_margin_bottom_material_you</item>
         <item name="sudGlifDescriptionStyle">@style/SudGlifDescriptionMaterialYou</item>
@@ -459,8 +527,12 @@
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudMaterialYouDescription</item>
         <item name="sudDividerShown">false</item>
         <item name="sudItemContainerStyle">@style/SudItemContainerMaterialYou</item>
+        <item name="sudItemPaddingTop">@dimen/sud_items_padding_top_material_you</item>
+        <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
         <item name="sudItemTitleStyle">@style/SudItemTitleMaterialYou</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryMaterialYou</item>
+        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
+        <item name="sudItemSummaryPaddingTop">@dimen/sud_items_summary_margin_top_material_you</item>
         <item name="sudItemDescriptionTitleStyle">@style/SudItemTitleMaterialYou</item>
         <item name="sudItemDescriptionStyle">@style/SudItemContainerMaterialYou.Description</item>
         <item name="sudItemVerboseTitleStyle">@style/SudMaterialYouItemTitle.Verbose</item>
@@ -468,6 +540,296 @@
         <item name="android:alertDialogTheme">@style/SudMaterialYouAlertDialogTheme.Light</item>
     </style>
 
+    <style name="SudBaseThemeGlifExpressive" parent="Theme.Material3.Dark.NoActionBar">
+        <!-- Copied from values style SudThemeBaseGlif -->
+        <item name="android:indeterminateTint" tools:ignore="NewApi">?attr/colorControlActivated</item>
+        <!-- Specify the indeterminateTintMode to work around a bug in Lollipop -->
+        <item name="android:indeterminateTintMode" tools:ignore="NewApi">src_in</item>
+        <item name="android:listPreferredItemHeight">@dimen/sud_items_preferred_height</item>
+        <item name="android:listPreferredItemPaddingEnd" tools:ignore="NewApi">@dimen/sud_glif_expressive_item_margin_start</item>
+        <item name="android:listPreferredItemPaddingStart" tools:ignore="NewApi">@dimen/sud_glif_expressive_item_margin_start</item>
+        <item name="android:statusBarColor" tools:ignore="NewApi">@android:color/transparent</item>
+        <item name="android:windowAnimationStyle">@style/Animation.SudWindowAnimation</item>
+        <item name="android:windowDisablePreview">true</item>
+        <item name="android:windowSoftInputMode">adjustResize</item>
+        <item name="android:colorError" tools:targetApi="26">@color/sud_color_error_text_dark</item>
+        <item name="android:scrollbarThumbVertical">?attr/sudScrollBarThumb</item>
+        <item name="listPreferredItemPaddingLeft">@dimen/sud_glif_expressive_item_margin_start</item>
+        <item name="listPreferredItemPaddingRight">@dimen/sud_glif_expressive_item_margin_end</item>
+        <item name="sudButtonHighlightAlpha">0.24</item>
+        <item name="sudColorPrimary">?attr/colorPrimary</item>
+        <item name="sudContentFramePaddingTop">@dimen/sud_content_frame_padding_top</item>
+        <item name="sudContentFramePaddingBottom">@dimen/sud_content_frame_padding_bottom</item>
+        <item name="sudLoadingContentFramePaddingTop">@dimen/sud_content_loading_frame_padding_top</item>
+        <item name="sudLoadingContentFramePaddingStart">@dimen/sud_content_loading_frame_padding_start</item>
+        <item name="sudLoadingContentFramePaddingEnd">@dimen/sud_content_loading_frame_padding_end</item>
+        <item name="sudLoadingContentFramePaddingBottom">@dimen/sud_content_loading_frame_padding_bottom</item>
+        <item name="sudFillContentLayoutStyle">@style/SudFillContentLayout</item>
+        <item name="sudGlifAccountNameStyle">@style/SudGlifAccountName</item>
+        <item name="sudGlifAccountAvatarSize">@dimen/sud_account_avatar_max_height</item>
+        <item name="sudGlifAccountAvatarStyle">@style/SudGlifAccountAvatar</item>
+        <item name="sudAccountNameTextSize">@dimen/sud_account_name_text_size</item>
+        <item name="sudGlifIconStyle">@style/SudGlifIcon</item>
+        <item name="sudListItemIconColor">@color/sud_list_item_icon_color_dark</item>
+        <item name="sudScrollBarThumb">@drawable/sud_scroll_bar_dark</item>
+        <item name="sucFooterBarButtonCornerRadius">?attr/sudButtonCornerRadius</item>
+        <item name="sucFooterBarButtonAllCaps">?attr/sudButtonAllCaps</item>
+        <item name="sucFooterBarButtonColorControlHighlightRipple">?attr/colorAccent</item>
+        <item name="sucFooterBarButtonHighlightAlpha">?attr/sudButtonHighlightAlpha</item>
+        <item name="sucStatusBarBackground">?android:attr/colorBackground</item>
+        <item name="sudContentIllustrationMaxWidth">@dimen/sud_content_illustration_max_width</item>
+        <item name="sudContentIllustrationMaxHeight">@dimen/sud_content_illustration_max_height</item>
+        <item name="sudContentIllustrationPaddingTop">@dimen/sud_content_illustration_padding_vertical</item>
+        <item name="sudContentIllustrationPaddingBottom">@dimen/sud_content_illustration_padding_vertical</item>
+        <item name="sudLoadingHeaderHeight">@dimen/sud_loading_header_height</item>
+        <item name="sudSwitchBarThumbOnColor">@color/sud_switch_thumb_on_dark</item>
+        <item name="sudSwitchBarTrackOnColor">@color/sud_switch_track_on_dark</item>
+        <item name="sudSwitchBarThumbOffColor">@color/sud_switch_thumb_off_dark</item>
+        <item name="sudSwitchBarTrackOffColor">@color/sud_switch_track_off_dark</item>
+        <item name="sudSwitchBarTrackOffOutlineColor">@color/sud_switch_track_outline_off_dark</item>
+        <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
+        <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
+        <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
+        <item name="sudAccountAvatarMarginEnd">@dimen/sud_account_avatar_margin_end</item>
+        <item name="sudAccountAvatarMaxHeight">@dimen/sud_account_avatar_max_height</item>
+
+        <!-- Copied from values style SudThemeGlifV2 -->
+        <item name="android:windowLightStatusBar" tools:targetApi="m">false</item>
+        <item name="sudBackgroundBaseColor">?android:attr/colorBackground</item>
+        <item name="sudBackgroundPatterned">false</item>
+        <item name="sudDividerInsetEnd">?attr/sudMarginEnd</item>
+        <item name="sudDividerInsetStart">?attr/sudMarginStart</item>
+        <item name="sudDividerInsetStartNoIcon">?attr/sudMarginStart</item>
+        <item name="sudGlifSubtitleGravity">center_horizontal</item>
+        <item name="sudScrollIndicators">top|bottom</item>
+        <item name="sudEditTextBackgroundColor">@color/sud_glif_edit_text_bg_dark_color</item>
+        <item name="android:editTextStyle">@style/SudEditText</item>
+        <item name="sucLightStatusBar" tools:targetApi="m">?android:attr/windowLightStatusBar</item>
+
+        <!-- Copied from values style SudBaseThemeGlifV3 -->
+        <item name="colorBackgroundFloating">@color/sud_glif_v3_dialog_background_color_dark</item>
+        <item name="android:datePickerDialogTheme">@style/SudDateTimePickerDialogTheme</item>
+        <item name="android:timePickerDialogTheme">@style/SudDateTimePickerDialogTheme</item>
+        <item name="sudButtonAllCaps">false</item>
+        <item name="sudEditBoxColor">@color/sud_color_accent_glif_v3_dark</item>
+
+        <!-- Copied from values style SudThemeGlifV4 -->
+        <item name="sucFooterBarPaddingVertical">@dimen/sud_glif_footer_bar_padding_vertical_material_you</item>
+        <item name="sucFooterBarMinHeight">@dimen/sud_glif_footer_bar_min_height_material_you</item>
+        <item name="sucHeaderContainerMarginBottom">@dimen/sud_header_container_margin_bottom_material_you</item>
+        <item name="sucFooterBarButtonAlignEnd">@bool/suc_footer_bar_button_align_end</item>
+        <item name="sudButtonTertiaryGravity">center_horizontal</item>
+        <item name="sudGlifIconSize">@dimen/sud_glif_icon_max_height_material_you</item>
+        <item name="sudGlifAccountContainerStyle">@style/SudGlifAccountContainerMaterialYou</item>
+        <item name="sudGlifHeaderTitleStyle">@style/SudGlifHeaderTitleExpressive</item>
+        <item name="sudGlifHeaderGravity">start</item>
+        <item name="sudGlifIconGravity">center_horizontal</item>
+        <item name="sucGlifHeaderMarginTop">@dimen/sud_glif_header_title_margin_top_material_you</item>
+        <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_header_title_margin_bottom_material_you</item>
+        <item name="sudGlifDescriptionStyle">@style/SudGlifDescriptionMaterialYou</item>
+        <item name="sudGlifDescriptionMarginBottom">@dimen/sud_glif_expreesive_description_margin_bottom</item>
+        <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudMaterialYouDescription</item>
+        <item name="sudDividerShown">false</item>
+        <item name="sudItemPaddingTop">@dimen/sud_items_padding_top_material_you</item>
+        <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
+        <item name="sudItemTitleStyle">@style/SudItemTitleMaterialYou</item>
+        <item name="sudItemSummaryStyle">@style/SudItemSummaryMaterialYou</item>
+        <item name="sudItemDescriptionTitleStyle">@style/SudItemTitleMaterialYou</item>
+        <item name="sudItemDescriptionStyle">@style/SudItemContainerMaterialYou.Description</item>
+        <item name="sudItemDescriptionPaddingTop">@dimen/sud_description_glif_margin_top</item>
+        <item name="sudItemDescriptionPaddingBottom">@dimen/sud_description_glif_margin_bottom_lists</item>
+        <item name="sudItemVerboseTitleStyle">@style/SudMaterialYouItemTitle.Verbose</item>
+        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
+        <item name="sudItemSummaryPaddingTop">@dimen/sud_items_summary_margin_top_material_you</item>
+        <item name="alertDialogTheme">@style/SudMaterialYouAlertDialogThemeCompat</item>
+        <item name="android:alertDialogTheme">@style/SudMaterialYouAlertDialogTheme</item>
+        <!-- new values for style SudBaseThemeGlifExpressive -->
+        <item name="android:colorBackground" tools:ignore="NewApi">?attr/colorSurfaceContainer</item>
+        <item name="sudMarginStart">@dimen/sud_glif_expressive_margin_start</item>
+        <item name="sudMarginEnd">@dimen/sud_glif_expressive_margin_end</item>
+        <item name="sudGlifContentPaddingTop">@dimen/sud_glif_expressive_content_padding_top</item>
+        <item name="sucFooterButtonPaddingStart">@dimen/sud_glif_expressive_button_padding</item>
+        <item name="sucFooterButtonPaddingEnd">@dimen/sud_glif_expressive_button_padding</item>
+        <item name="sucGlifIconMarginTop">@dimen/sud_glif_expressive_icon_margin_top</item>
+        <item name="sudGlifDescriptionMarginTop">@dimen/sud_glif_expressive_description_margin_top</item>
+        <item name="sucFooterBarButtonFontFamily">@string/sudExpressiveButtonFontFamily</item>
+        <item name="sudFooterBackgroundColor">@color/sud_glif_expressive_footer_bar_bg_color</item>
+        <item name="sucFooterBarPrimaryFooterBackground">@color/sud_glif_expressive_footer_button_bg_color</item>
+        <item name="sucFooterBarButtonMiddleSpacing">@dimen/sud_glif_expressive_footer_button_middle_spacing</item>
+        <item name="sudItemDividerWidth">@dimen/sud_items_divder_width</item>
+        <item name="sudItemBackgroundPaddingStart">@dimen/sud_items_background_padding_start</item>
+        <item name="sudItemBackgroundPaddingEnd">@dimen/sud_items_background_padding_end</item>
+        <item name="sudItemContainerStyle">@style/SudGlifExpressiveItemContainer</item>
+        <item name="sucFooterBarPrimaryFooterButtonEnabledTextColor">@color/sud_glif_expressive_footer_primary_button_enable_text_color</item>
+        <item name="sucFooterBarPrimaryFooterButtonDisabledTextColor">@color/sud_glif_expressive_footer_primary_button_disable_text_color</item>
+        <item name="sucFooterBarSecondaryFooterButtonEnabledTextColor">@color/sud_glif_expressive_footer_secondary_button_enable_text_color</item>
+        <item name="sucFooterBarSecondaryFooterButtonDisabledTextColor">@color/sud_glif_expressive_footer_secondary_button_disable_text_color</item>
+        <item name="sucFooterBarPaddingStart">@dimen/sud_glif_expressive_footer_padding_start</item>
+        <item name="sucFooterBarPaddingEnd">@dimen/sud_glif_expressive_footer_padding_end</item>
+        <item name="sucFooterBarPaddingTop">@dimen/sud_glif_expressive_footer_padding_top</item>
+        <item name="sucFooterBarPaddingBottom">@dimen/sud_glif_expressive_footer_padding_bottom</item>
+        <item name="sucFooterBarButtonMinHeight">@dimen/sud_glif_expressive_footer_button_min_height</item>
+        <item name="sudItemBackground">@drawable/sud_item_background</item>
+        <item name="sudItemBackgroundFirst">@drawable/sud_item_background_first</item>
+        <item name="sudItemBackgroundLast">@drawable/sud_item_background_last</item>
+        <item name="sudItemBackgroundSingle">@drawable/sud_item_background_single</item>
+        <item name="sudItemCornerRadius">@dimen/sud_glif_expressive_item_corner_radius</item>
+        <item name="sudItemBackgroundColor" tools:ignore="NewApi">?attr/colorSurfaceBright</item>
+        <item name="sucFooterBarButtonFontWeight">@integer/sud_glif_expressive_footer_button_weight</item>
+        <item name="sudButtonCornerRadius">@dimen/sud_glif_expressive_footer_button_radius</item>
+        <item name="sucFooterBarButtonTextSize">@dimen/sud_glif_expressive_footer_button_text_size</item>
+        <item name="sucFooterButtonTextLineSpacingExtra">@dimen/sud_glif_expressive_footer_button_text_line_spacing_extra</item>
+        <item name="textAppearanceListItem">@style/TextAppearance.SudExpressiveItemTitle</item>
+        <item name="textAppearanceListItemSmall">@style/TextAppearance.SudExpressiveItemSummary</item>
+        <item name="materialAlertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
+    </style>
+
+    <style name="SudBaseThemeGlifExpressive.Light" parent="Theme.Material3.Light.NoActionBar">
+        <!-- Copied from values style SudThemeBaseGlif.Light -->
+        <item name="android:indeterminateTint" tools:ignore="NewApi">?attr/colorControlActivated</item>
+        <!-- Specify the indeterminateTintMode to work around a bug in Lollipop -->
+        <item name="android:indeterminateTintMode" tools:ignore="NewApi">src_in</item>
+        <item name="android:listPreferredItemHeight">@dimen/sud_items_preferred_height</item>
+        <item name="android:listPreferredItemPaddingEnd" tools:ignore="NewApi">@dimen/sud_glif_expressive_item_margin_start</item>
+        <item name="android:listPreferredItemPaddingStart" tools:ignore="NewApi">@dimen/sud_glif_expressive_item_margin_start</item>
+        <item name="android:statusBarColor" tools:ignore="NewApi">@android:color/transparent</item>
+        <item name="android:windowAnimationStyle">@style/Animation.SudWindowAnimation</item>
+        <item name="android:windowDisablePreview">true</item>
+        <item name="android:windowSoftInputMode">adjustResize</item>
+        <item name="android:colorError" tools:targetApi="26">@color/sud_color_error_text_light</item>
+        <item name="android:scrollbarThumbVertical">?attr/sudScrollBarThumb</item>
+        <item name="listPreferredItemPaddingLeft">@dimen/sud_glif_expressive_item_margin_start</item>
+        <item name="listPreferredItemPaddingRight">@dimen/sud_glif_expressive_item_margin_end</item>
+        <item name="sudButtonHighlightAlpha">0.12</item>
+        <item name="sudColorPrimary">?attr/colorPrimary</item>
+        <item name="sudContentFramePaddingTop">@dimen/sud_content_frame_padding_top</item>
+        <item name="sudContentFramePaddingBottom">@dimen/sud_content_frame_padding_bottom</item>
+        <item name="sudLoadingContentFramePaddingTop">@dimen/sud_content_loading_frame_padding_top</item>
+        <item name="sudLoadingContentFramePaddingStart">@dimen/sud_content_loading_frame_padding_start</item>
+        <item name="sudLoadingContentFramePaddingEnd">@dimen/sud_content_loading_frame_padding_end</item>
+        <item name="sudLoadingContentFramePaddingBottom">@dimen/sud_content_loading_frame_padding_bottom</item>
+        <item name="sudFillContentLayoutStyle">@style/SudFillContentLayout</item>
+        <item name="sudGlifAccountNameStyle">@style/SudGlifAccountName</item>
+        <item name="sudGlifAccountAvatarSize">@dimen/sud_account_avatar_max_height</item>
+        <item name="sudGlifAccountAvatarStyle">@style/SudGlifAccountAvatar</item>
+        <item name="sudAccountNameTextSize">@dimen/sud_account_name_text_size</item>
+        <item name="sudGlifIconStyle">@style/SudGlifIcon</item>
+        <item name="sudListItemIconColor">@color/sud_list_item_icon_color_light</item>
+        <item name="sudScrollBarThumb">@drawable/sud_scroll_bar_light</item>
+        <item name="sucFooterBarButtonCornerRadius">?attr/sudButtonCornerRadius</item>
+        <item name="sucFooterBarButtonAllCaps">?attr/sudButtonAllCaps</item>
+        <item name="sucFooterBarButtonColorControlHighlightRipple">?attr/colorAccent</item>
+        <item name="sucFooterBarButtonHighlightAlpha">?attr/sudButtonHighlightAlpha</item>
+        <item name="sucStatusBarBackground">?android:attr/colorBackground</item>
+        <item name="sudContentIllustrationMaxWidth">@dimen/sud_content_illustration_max_width</item>
+        <item name="sudContentIllustrationMaxHeight">@dimen/sud_content_illustration_max_height</item>
+        <item name="sudContentIllustrationPaddingTop">@dimen/sud_content_illustration_padding_vertical</item>
+        <item name="sudContentIllustrationPaddingBottom">@dimen/sud_content_illustration_padding_vertical</item>
+        <item name="sudLoadingHeaderHeight">@dimen/sud_loading_header_height</item>
+        <item name="sudSwitchBarThumbOnColor">@color/sud_switch_thumb_on_light</item>
+        <item name="sudSwitchBarTrackOnColor">@color/sud_switch_track_on_light</item>
+        <item name="sudSwitchBarThumbOffColor">@color/sud_switch_thumb_off_light</item>
+        <item name="sudSwitchBarTrackOffColor">@color/sud_switch_track_off_light</item>
+        <item name="sudSwitchBarTrackOffOutlineColor">@color/sud_switch_track_outline_off_light</item>
+        <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
+        <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
+        <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
+        <item name="sudAccountAvatarMarginEnd">@dimen/sud_account_avatar_margin_end</item>
+        <item name="sudAccountAvatarMaxHeight">@dimen/sud_account_avatar_max_height</item>
+
+        <!-- Copied from values style SudThemeGlifV2.Light -->
+        <item name="android:windowLightStatusBar" tools:targetApi="m">true</item>
+        <item name="sudBackgroundBaseColor">?android:attr/colorBackground</item>
+        <item name="sudBackgroundPatterned">false</item>
+        <item name="sudDividerInsetEnd">?attr/sudMarginEnd</item>
+        <item name="sudDividerInsetStart">?attr/sudMarginStart</item>
+        <item name="sudDividerInsetStartNoIcon">?attr/sudMarginStart</item>
+        <item name="sudGlifSubtitleGravity">center_horizontal</item>
+        <item name="sudScrollIndicators">top|bottom</item>
+        <item name="sudEditTextBackgroundColor">@color/sud_glif_edit_text_bg_light_color</item>
+        <item name="android:editTextStyle">@style/SudEditText</item>
+        <item name="sucLightStatusBar" tools:targetApi="m">?android:attr/windowLightStatusBar</item>
+
+        <!-- Copied from values style SudBaseThemeGlifV3.Light -->
+        <item name="android:datePickerDialogTheme">@style/SudDateTimePickerDialogTheme.Light</item>
+        <item name="android:timePickerDialogTheme">@style/SudDateTimePickerDialogTheme.Light</item>
+        <item name="sudButtonAllCaps">false</item>
+        <item name="sudEditBoxColor">@color/sud_color_accent_glif_v3_light</item>
+
+        <!-- Copied from values style SudThemeGlifV4.Light -->
+        <item name="sucFooterBarPaddingVertical">@dimen/sud_glif_footer_bar_padding_vertical_material_you</item>
+        <item name="sucFooterBarMinHeight">@dimen/sud_glif_footer_bar_min_height_material_you</item>
+        <item name="sucFooterBarButtonAlignEnd">@bool/suc_footer_bar_button_align_end</item>
+        <item name="sucHeaderContainerMarginBottom">@dimen/sud_header_container_margin_bottom_material_you</item>
+        <item name="sudButtonTertiaryGravity">center_horizontal</item>
+        <item name="sudGlifIconSize">@dimen/sud_glif_icon_max_height_material_you</item>
+        <item name="sudGlifAccountContainerStyle">@style/SudGlifAccountContainerMaterialYou</item>
+        <item name="sudGlifHeaderTitleStyle">@style/SudGlifHeaderTitleExpressive</item>
+        <item name="sudGlifHeaderGravity">start</item>
+        <item name="sudGlifIconGravity">center_horizontal</item>
+        <item name="sucGlifHeaderMarginTop">@dimen/sud_glif_header_title_margin_top_material_you</item>
+        <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_header_title_margin_bottom_material_you</item>
+        <item name="sudGlifDescriptionStyle">@style/SudGlifDescriptionMaterialYou</item>
+        <item name="sudGlifDescriptionMarginBottom">@dimen/sud_glif_expreesive_description_margin_bottom</item>
+        <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudMaterialYouDescription</item>
+        <item name="sudDividerShown">false</item>
+        <item name="sudItemPaddingTop">@dimen/sud_items_padding_top_material_you</item>
+        <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
+        <item name="sudItemTitleStyle">@style/SudItemTitleMaterialYou</item>
+        <item name="sudItemSummaryStyle">@style/SudItemSummaryMaterialYou</item>
+        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
+        <item name="sudItemSummaryPaddingTop">@dimen/sud_items_summary_margin_top_material_you</item>
+        <item name="sudItemDescriptionTitleStyle">@style/SudItemTitleMaterialYou</item>
+        <item name="sudItemDescriptionStyle">@style/SudItemContainerMaterialYou.Description</item>
+        <item name="sudItemDescriptionPaddingTop">@dimen/sud_description_glif_margin_top</item>
+        <item name="sudItemDescriptionPaddingBottom">@dimen/sud_description_glif_margin_bottom_lists</item>
+        <item name="sudItemVerboseTitleStyle">@style/SudMaterialYouItemTitle.Verbose</item>
+        <item name="alertDialogTheme">@style/SudMaterialYouAlertDialogThemeCompat.Light</item>
+        <item name="android:alertDialogTheme">@style/SudMaterialYouAlertDialogTheme.Light</item>
+        <!-- new values for style SudBaseThemeGlifExpressive.Light -->
+        <item name="android:colorBackground" tools:ignore="NewApi">?attr/colorSurfaceContainer</item>
+        <item name="sudMarginStart">@dimen/sud_glif_expressive_margin_start</item>
+        <item name="sudMarginEnd">@dimen/sud_glif_expressive_margin_end</item>
+        <item name="sucFooterButtonPaddingStart">@dimen/sud_glif_expressive_button_padding</item>
+        <item name="sucFooterButtonPaddingEnd">@dimen/sud_glif_expressive_button_padding</item>
+        <item name="sucGlifIconMarginTop">@dimen/sud_glif_expressive_icon_margin_top</item>
+        <item name="sudGlifContentPaddingTop">@dimen/sud_glif_expressive_content_padding_top</item>
+        <item name="sudGlifDescriptionMarginTop">@dimen/sud_glif_expressive_description_margin_top</item>
+        <item name="sucFooterBarButtonFontFamily">@string/sudExpressiveButtonFontFamily</item>
+        <item name="sudFooterBackgroundColor">@color/sud_glif_expressive_footer_bar_bg_color</item>
+        <item name="sucFooterBarPrimaryFooterBackground">@color/sud_glif_expressive_footer_button_bg_color</item>
+        <item name="sucFooterBarButtonMiddleSpacing">@dimen/sud_glif_expressive_footer_button_middle_spacing</item>
+        <item name="sudItemDividerWidth">@dimen/sud_items_divder_width</item>
+        <item name="sudItemBackgroundPaddingStart">@dimen/sud_items_background_padding_start</item>
+        <item name="sudItemBackgroundPaddingEnd">@dimen/sud_items_background_padding_end</item>
+        <item name="sudItemContainerStyle">@style/SudGlifExpressiveItemContainer</item>
+        <item name="sucFooterBarPrimaryFooterButtonEnabledTextColor">@color/sud_glif_expressive_footer_primary_button_enable_text_color</item>
+        <item name="sucFooterBarPrimaryFooterButtonDisabledTextColor">@color/sud_glif_expressive_footer_primary_button_disable_text_color</item>
+        <item name="sucFooterBarSecondaryFooterButtonEnabledTextColor">@color/sud_glif_expressive_footer_secondary_button_enable_text_color</item>
+        <item name="sucFooterBarSecondaryFooterButtonDisabledTextColor">@color/sud_glif_expressive_footer_secondary_button_disable_text_color</item>
+        <item name="sucFooterBarPaddingStart">@dimen/sud_glif_expressive_footer_padding_start</item>
+        <item name="sucFooterBarPaddingEnd">@dimen/sud_glif_expressive_footer_padding_end</item>
+        <item name="sucFooterBarPaddingTop">@dimen/sud_glif_expressive_footer_padding_top</item>
+        <item name="sucFooterBarPaddingBottom">@dimen/sud_glif_expressive_footer_padding_bottom</item>
+        <item name="sucFooterBarButtonMinHeight">@dimen/sud_glif_expressive_footer_button_min_height</item>
+        <item name="sudItemBackground">@drawable/sud_item_background</item>
+        <item name="sudItemBackgroundFirst">@drawable/sud_item_background_first</item>
+        <item name="sudItemBackgroundLast">@drawable/sud_item_background_last</item>
+        <item name="sudItemBackgroundSingle">@drawable/sud_item_background_single</item>
+        <item name="sudItemCornerRadius">@dimen/sud_glif_expressive_item_corner_radius</item>
+        <item name="sudItemBackgroundColor" tools:ignore="NewApi">?attr/colorSurfaceBright</item>
+        <item name="sucFooterBarButtonFontWeight">@integer/sud_glif_expressive_footer_button_weight</item>
+        <item name="sudButtonCornerRadius">@dimen/sud_glif_expressive_footer_button_radius</item>
+        <item name="sucFooterBarButtonTextSize">@dimen/sud_glif_expressive_footer_button_text_size</item>
+        <item name="sucFooterButtonTextLineSpacingExtra">@dimen/sud_glif_expressive_footer_button_text_line_spacing_extra</item>
+        <item name="textAppearanceListItem">@style/TextAppearance.SudExpressiveItemTitle</item>
+        <item name="textAppearanceListItemSmall">@style/TextAppearance.SudExpressiveItemSummary</item>
+        <item name="materialAlertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
+    </style>
+
+    <style name="SudThemeGlifExpressive" parent="SudBaseThemeGlifExpressive" />
+    <style name="SudThemeGlifExpressive.Light" parent="SudBaseThemeGlifExpressive.Light" />
+
     <style name="SudDynamicColorTheme" />
     <style name="SudDynamicColorTheme.Light"  />
     <style name="SudFullDynamicColorTheme" parent="SudDynamicColorTheme"/>
@@ -480,6 +842,7 @@
     <style name="SudThemeGlifV2.DayNight" parent="SudThemeGlifV2.Light" />
     <style name="SudThemeGlifV3.DayNight" parent="SudThemeGlifV3.Light" />
     <style name="SudThemeGlifV4.DayNight" parent="SudThemeGlifV4.Light" />
+    <style name="SudThemeGlifExpressive.DayNight" parent="SudThemeGlifExpressive.Light" />
 
     <!-- DynamicColor DayNight themes -->
     <style name="SudDynamicColorThemeGlifV3.DayNight" parent="SudDynamicColorThemeGlifV3.Light" />
@@ -779,37 +1142,53 @@
 
     <style name="SudItemContainer">
         <item name="android:minHeight">?android:attr/listPreferredItemHeight</item>
-        <item name="android:paddingBottom">@dimen/sud_items_padding_bottom</item>
+        <item name="android:paddingBottom">?attr/sudItemPaddingBottom</item>
         <item name="android:paddingEnd" tools:ignore="NewApi">?attr/listPreferredItemPaddingRight</item>
         <item name="android:paddingLeft">?attr/listPreferredItemPaddingLeft</item>
         <item name="android:paddingRight">?attr/listPreferredItemPaddingRight</item>
         <item name="android:paddingStart" tools:ignore="NewApi">?attr/listPreferredItemPaddingLeft</item>
-        <item name="android:paddingTop">@dimen/sud_items_padding_top</item>
+        <item name="android:paddingTop">?attr/sudItemPaddingTop</item>
     </style>
 
     <style name="SudItemContainerMaterialYou">
-        <item name="android:paddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
+        <item name="android:paddingBottom">?attr/sudItemPaddingBottom</item>
         <item name="android:paddingEnd" tools:ignore="NewApi">?attr/listPreferredItemPaddingRight</item>
         <item name="android:paddingLeft">?attr/listPreferredItemPaddingLeft</item>
         <item name="android:paddingRight">?attr/listPreferredItemPaddingRight</item>
         <item name="android:paddingStart" tools:ignore="NewApi">?attr/listPreferredItemPaddingLeft</item>
+        <item name="android:paddingTop">?attr/sudItemPaddingTop</item>
+        <item name="android:minHeight">@dimen/sud_items_min_height_material_you</item>
+    </style>
+
+    <style name="SudGlifExpressiveItemContainer">
+        <item name="android:layout_marginEnd" tools:ignore="NewApi">?attr/listPreferredItemPaddingRight</item>
+        <item name="android:layout_marginLeft">?attr/listPreferredItemPaddingLeft</item>
+        <item name="android:layout_marginRight">?attr/listPreferredItemPaddingRight</item>
+        <item name="android:layout_marginStart" tools:ignore="NewApi">?attr/listPreferredItemPaddingLeft</item>
+        <item name="android:layout_marginBottom">?attr/sudItemDividerWidth</item>
+        <item name="android:background">?attr/sudItemBackground</item>
+        <item name="android:paddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
+        <item name="android:paddingEnd" tools:ignore="NewApi">?attr/sudItemBackgroundPaddingEnd</item>
+        <item name="android:paddingLeft">?attr/sudItemBackgroundPaddingStart</item>
+        <item name="android:paddingRight">?attr/sudItemBackgroundPaddingEnd</item>
+        <item name="android:paddingStart" tools:ignore="NewApi">?attr/sudItemBackgroundPaddingStart</item>
         <item name="android:paddingTop">@dimen/sud_items_padding_top_material_you</item>
         <item name="android:minHeight">@dimen/sud_items_min_height_material_you</item>
     </style>
 
     <style name="SudItemIconContainer">
-        <item name="android:layout_width">@dimen/sud_items_icon_container_width</item>
+        <item name="android:layout_width">?attr/sudItemIconContainerWidth</item>
     </style>
 
     <style name="SudItemContainer.Description" parent="SudItemContainer">
-        <item name="android:paddingTop">@dimen/sud_description_margin_top</item>
-        <item name="android:paddingBottom">@dimen/sud_description_margin_bottom_lists</item>
+        <item name="android:paddingTop">?attr/sudItemDescriptionPaddingTop</item>
+        <item name="android:paddingBottom">?attr/sudItemDescriptionPaddingBottom</item>
     </style>
 
     <style name="SudItemContainer.Description.Glif" parent="SudItemContainer.Description">
         <item name="android:minHeight">0dp</item>
-        <item name="android:paddingTop">@dimen/sud_description_glif_margin_top</item>
-        <item name="android:paddingBottom">@dimen/sud_description_glif_margin_bottom_lists</item>
+        <item name="android:paddingTop">?attr/sudItemDescriptionPaddingTop</item>
+        <item name="android:paddingBottom">?attr/sudItemDescriptionPaddingBottom</item>
     </style>
 
     <style name="SudItemContainer.Verbose" parent="SudItemContainer">
@@ -823,19 +1202,19 @@
 
     <style name="SudItemSummaryGlif">
         <item name="android:textAppearance">?attr/textAppearanceListItemSmall</item>
-        <item name="android:layout_marginBottom">@dimen/sud_items_padding_bottom_extra</item>
+        <item name="android:layout_marginBottom">?attr/sudItemSummaryPaddingBottom</item>
     </style>
 
     <style name="SudItemSummaryMaterialYou">
         <item name="android:textAppearance">?attr/textAppearanceListItemSmall</item>
-        <item name="android:layout_marginBottom">@dimen/sud_items_padding_bottom_extra</item>
-        <item name="android:layout_marginTop">@dimen/sud_items_summary_margin_top_material_you</item>
+        <item name="android:layout_marginBottom">?attr/sudItemSummaryPaddingBottom</item>
+        <item name="android:layout_marginTop">?attr/sudItemSummaryPaddingTop</item>
     </style>
 
     <style name="SudItemContainerMaterialYou.Description" parent="SudItemContainerMaterialYou">
         <item name="android:minHeight">0dp</item>
-        <item name="android:paddingTop">@dimen/sud_items_padding_top_material_you</item>
-        <item name="android:paddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
+        <item name="android:paddingTop">?attr/sudItemPaddingTop</item>
+        <item name="android:paddingBottom">?attr/sudItemPaddingBottom</item>
     </style>
 
     <style name="SudItemTitle">
@@ -915,6 +1294,10 @@
         <item name="android:hyphenationFrequency" tools:targetApi="23">full</item>
     </style>
 
+    <style name="SudGlifHeaderTitleExpressive" parent="SudGlifHeaderTitleMaterialYou">
+        <item name="android:lineSpacingExtra">@dimen/sud_glif_expressive_header_title_line_spacing_extra</item>
+    </style>
+
     <style name="SudGlifDescription" parent="SudDescription.Glif">
         <item name="android:layout_marginTop">?attr/sudGlifDescriptionMarginTop</item>
         <item name="android:layout_marginBottom">?attr/sudGlifDescriptionMarginBottom</item>
@@ -944,8 +1327,8 @@
     </style>
 
     <style name="SudGlifAccountContainerMaterialYou">
-        <item name="android:layout_marginBottom">@dimen/sud_glif_header_title_margin_bottom_material_you</item>
-        <item name="android:layout_marginTop">@dimen/sud_glif_header_title_margin_top_material_you</item>
+        <item name="android:layout_marginBottom">?attr/sucGlifHeaderMarginBottom</item>
+        <item name="android:layout_marginTop">?attr/sucGlifHeaderMarginTop</item>
         <item name="android:layout_marginLeft">?attr/sudMarginStart</item>
         <item name="android:layout_marginStart" tools:ignore="NewApi">?attr/sudMarginStart</item>
         <item name="android:layout_marginRight">?attr/sudMarginEnd</item>
@@ -954,17 +1337,18 @@
     </style>
 
     <style name="SudGlifAccountAvatar">
-        <item name="android:layout_marginRight">@dimen/sud_account_avatar_margin_end</item>
-        <item name="android:layout_marginEnd">@dimen/sud_account_avatar_margin_end</item>
+        <!--TODO create sudAccountAvatarMarginStart to let it as a pair with sudAccountAvatarMarginEnd -->
+        <item name="android:layout_marginRight">?attr/sudAccountAvatarMarginEnd</item>
+        <item name="android:layout_marginEnd">?attr/sudAccountAvatarMarginEnd</item>
         <item name="android:adjustViewBounds">true</item>
-        <item name="android:maxHeight">@dimen/sud_account_avatar_max_height</item>
+        <item name="android:maxHeight">?attr/sudAccountAvatarMaxHeight</item>
         <item name="android:layout_gravity">center_vertical</item>
     </style>
 
     <style name="SudGlifAccountName">
         <item name="android:fontFamily">@string/sudFontSecondary</item>
         <item name="android:textColor">?android:attr/textColorPrimary</item>
-        <item name="android:textSize">@dimen/sud_account_name_text_size</item>
+        <item name="android:textSize">?attr/sudAccountNameTextSize</item>
         <item name="android:layout_gravity">center_vertical</item>
     </style>
 
@@ -974,8 +1358,8 @@
     </style>
 
     <style name="SudGlifAccountContainer">
-        <item name="android:layout_marginBottom">@dimen/sud_glif_header_title_margin_bottom_material_you</item>
-        <item name="android:layout_marginTop">@dimen/sud_glif_header_title_margin_top_material_you</item>
+        <item name="android:layout_marginBottom">?attr/sucGlifHeaderMarginBottom</item>
+        <item name="android:layout_marginTop">?attr/sucGlifHeaderMarginTop</item>
         <item name="android:layout_marginLeft">?attr/sudMarginStart</item>
         <item name="android:layout_marginStart" tools:ignore="NewApi">?attr/sudMarginStart</item>
         <item name="android:layout_marginRight">?attr/sudMarginEnd</item>
@@ -1002,7 +1386,12 @@
         <item name="android:adjustViewBounds">true</item>
         <item name="android:maxHeight">?attr/sudGlifIconSize</item>
         <item name="android:scaleType">centerInside</item>
-        <item name="android:layout_gravity">?attr/sudGlifHeaderGravity</item>
+        <item name="android:layout_gravity">?attr/sudGlifIconGravity</item>
+    </style>
+
+    <style name="SudGlifButtonContainer">
+        <item name="android:layout_marginStart" tools:ignore="NewApi">?attr/sudMarginStart</item>
+        <item name="android:layout_marginTop">@dimen/sud_glif_expressive_back_button_margin_top</item>
     </style>
 
     <style name="TextAppearance.SudGlifBody" parent="android:TextAppearance">
@@ -1026,12 +1415,24 @@
         <item name="android:textColor">?android:attr/textColorPrimary</item>
     </style>
 
+    <style name="TextAppearance.SudExpressiveItemTitle" parent="android:TextAppearance">
+        <item name="android:textSize">@dimen/sud_items_title_text_size_expressive</item>
+        <item name="android:fontFamily">@string/sudFontSecondaryText</item>
+        <item name="android:textColor">?android:attr/textColorPrimary</item>
+    </style>
+
     <style name="TextAppearance.SudMaterialYouItemSummary" parent="android:TextAppearance">
         <item name="android:textSize">@dimen/sud_items_summary_text_size_material_you</item>
         <item name="android:fontFamily">@string/sudFontSecondaryText</item>
         <item name="android:textColor">?android:attr/textColorSecondary</item>
     </style>
 
+    <style name="TextAppearance.SudExpressiveItemSummary" parent="android:TextAppearance">
+        <item name="android:textSize">@dimen/sud_items_summary_text_size_expressive</item>
+        <item name="android:fontFamily">@string/sudFontSecondaryText</item>
+        <item name="android:textColor">?android:attr/textColorSecondary</item>
+    </style>
+
     <style name="TextAppearance.SudMaterialYouDescription" parent="TextAppearance.AppCompat.Medium">
         <item name="android:textColor">?android:attr/textColorPrimary</item>
         <item name="android:textSize">@dimen/sud_items_title_text_size_material_you</item>
@@ -1107,6 +1508,10 @@
     <style name="SudMaterialYouAlertDialogTheme" parent="SudMaterialYouAlertDialogThemeCompat"/>
     <style name="SudMaterialYouAlertDialogTheme.Light" parent="SudMaterialYouAlertDialogThemeCompat.Light"/>
 
+    <style name="SudGlifExpressiveDialogTheme" parent="ThemeOverlay.Material3.MaterialAlertDialog">
+        <item name="android:fontFamily">@string/sudGlifExpressiveDialogFontFamily</item>
+    </style>
+
     <style name="SudDateTimePickerDialogTheme" parent="Theme.AppCompat.Dialog">
         <item name="android:textAllCaps">false</item>
         <item name="colorAccent">@color/sud_color_accent_glif_v3_dark</item>
@@ -1135,4 +1540,15 @@
       <item name="android:layout_weight">@dimen/sud_glif_land_content_area_weight</item>
       <item name="android:focusedByDefault" tools:targetApi="o">true</item>
     </style>
+
+    <!-- corner size of the floating back button -->
+    <style name="SudShapeAppearanceOverlayExtended">
+        <item name="cornerFamily">rounded</item>
+        <item name="cornerSize">45%</item>
+    </style>
+
+    <style name="SudLinearProgressIndicatorWavy">
+        <!-- TODO(b/379571805): Update after material library related attributes drop to main branch -->
+    </style>
+
 </resources>
diff --git a/main/src/com/google/android/setupdesign/GlifLayout.java b/main/src/com/google/android/setupdesign/GlifLayout.java
index cc06bf2..b1bd41a 100644
--- a/main/src/com/google/android/setupdesign/GlifLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifLayout.java
@@ -17,18 +17,23 @@
 package com.google.android.setupdesign;
 
 import android.annotation.TargetApi;
+import android.app.Activity;
 import android.content.Context;
 import android.content.res.ColorStateList;
+import android.content.res.Resources.Theme;
 import android.content.res.TypedArray;
+import android.graphics.Color;
 import android.graphics.drawable.ColorDrawable;
 import android.graphics.drawable.Drawable;
 import android.os.Build;
 import android.os.Build.VERSION_CODES;
 import android.util.AttributeSet;
+import android.util.TypedValue;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.ViewStub;
+import android.widget.LinearLayout;
 import android.widget.ProgressBar;
 import android.widget.ScrollView;
 import android.widget.TextView;
@@ -41,10 +46,13 @@ import androidx.window.embedding.ActivityEmbeddingController;
 import com.google.android.setupcompat.PartnerCustomizationLayout;
 import com.google.android.setupcompat.partnerconfig.PartnerConfig;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
+import com.google.android.setupcompat.template.FooterBarMixin;
 import com.google.android.setupcompat.template.StatusBarMixin;
 import com.google.android.setupcompat.util.ForceTwoPaneHelper;
+import com.google.android.setupcompat.util.KeyboardHelper;
 import com.google.android.setupcompat.util.Logger;
 import com.google.android.setupdesign.template.DescriptionMixin;
+import com.google.android.setupdesign.template.FloatingBackButtonMixin;
 import com.google.android.setupdesign.template.HeaderMixin;
 import com.google.android.setupdesign.template.IconMixin;
 import com.google.android.setupdesign.template.IllustrationProgressMixin;
@@ -54,6 +62,8 @@ import com.google.android.setupdesign.template.RequireScrollMixin;
 import com.google.android.setupdesign.template.ScrollViewScrollHandlingDelegate;
 import com.google.android.setupdesign.util.DescriptionStyler;
 import com.google.android.setupdesign.util.LayoutStyler;
+import com.google.android.setupdesign.view.BottomScrollView;
+import com.google.android.setupdesign.view.BottomScrollView.BottomScrollListener;
 
 /**
  * Layout for the GLIF theme used in Setup Wizard for N.
@@ -130,6 +140,8 @@ public class GlifLayout extends PartnerCustomizationLayout {
     registerMixin(ProfileMixin.class, new ProfileMixin(this, attrs, defStyleAttr));
     registerMixin(ProgressBarMixin.class, new ProgressBarMixin(this, attrs, defStyleAttr));
     registerMixin(IllustrationProgressMixin.class, new IllustrationProgressMixin(this));
+    registerMixin(
+        FloatingBackButtonMixin.class, new FloatingBackButtonMixin(this, attrs, defStyleAttr));
     final RequireScrollMixin requireScrollMixin = new RequireScrollMixin(this);
     registerMixin(RequireScrollMixin.class, requireScrollMixin);
 
@@ -154,7 +166,7 @@ public class GlifLayout extends PartnerCustomizationLayout {
         // cannot obtain the content resource ID of the client, so the value of the content margin
         // cannot be adjusted through GlifLayout. If the margin sides are changed through the
         // partner config, it can only be based on the increased or decreased value to adjust the
-        // value of pading. In this way, the value of content margin plus padding will be equal to
+        // value of padding. In this way, the value of content margin plus padding will be equal to
         // the value of partner config.
         LayoutStyler.applyPartnerCustomizationExtraPaddingStyle(view);
       }
@@ -169,6 +181,8 @@ public class GlifLayout extends PartnerCustomizationLayout {
 
     updateLandscapeMiddleHorizontalSpacing();
 
+    updateViewFocusable();
+
     ColorStateList backgroundColor =
         a.getColorStateList(R.styleable.SudGlifLayout_sudBackgroundBaseColor);
     setBackgroundBaseColor(backgroundColor);
@@ -181,6 +195,13 @@ public class GlifLayout extends PartnerCustomizationLayout {
     if (stickyHeader != 0) {
       inflateStickyHeader(stickyHeader);
     }
+
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
+      initScrollingListener();
+    }
+
+    initBackButton();
+
     a.recycle();
   }
 
@@ -192,9 +213,23 @@ public class GlifLayout extends PartnerCustomizationLayout {
     getMixin(DescriptionMixin.class).tryApplyPartnerCustomizationStyle();
     getMixin(ProgressBarMixin.class).tryApplyPartnerCustomizationStyle();
     getMixin(ProfileMixin.class).tryApplyPartnerCustomizationStyle();
+    getMixin(FloatingBackButtonMixin.class).tryApplyPartnerCustomizationStyle();
     tryApplyPartnerCustomizationStyleToShortDescription();
   }
 
+  private void updateViewFocusable() {
+    if (KeyboardHelper.isKeyboardFocusEnhancementEnabled(getContext())) {
+      View headerView = this.findManagedViewById(R.id.sud_header_scroll_view);
+      if (headerView != null) {
+        headerView.setFocusable(false);
+      }
+      View view = this.findManagedViewById(R.id.sud_scroll_view);
+      if (view != null) {
+        view.setFocusable(false);
+      }
+    }
+  }
+
   // TODO: remove when all sud_layout_description has migrated to
   // DescriptionMixin(sud_layout_subtitle)
   private void tryApplyPartnerCustomizationStyleToShortDescription() {
@@ -290,9 +325,17 @@ public class GlifLayout extends PartnerCustomizationLayout {
   protected View onInflateTemplate(LayoutInflater inflater, @LayoutRes int template) {
     if (template == 0) {
       template = R.layout.sud_glif_template;
+
       // if the activity is embedded should apply an embedded layout.
       if (isEmbeddedActivityOnePaneEnabled(getContext())) {
-        template = R.layout.sud_glif_embedded_template;
+        if (isGlifExpressiveEnabled()) {
+          template = R.layout.sud_glif_expressive_embedded_template;
+        } else {
+          template = R.layout.sud_glif_embedded_template;
+        }
+        // TODO add unit test for this case.
+      } else if (isGlifExpressiveEnabled()) {
+        template = R.layout.sud_glif_expressive_template;
       } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
         template = R.layout.sud_glif_template_two_pane;
       }
@@ -390,7 +433,7 @@ public class GlifLayout extends PartnerCustomizationLayout {
   }
 
   /**
-   * Sets the visibility of header area in landscape mode. These views inlcudes icon, header title
+   * Sets the visibility of header area in landscape mode. These views includes icon, header title
    * and subtitle. It can make the content view become full screen when set false.
    */
   @TargetApi(Build.VERSION_CODES.S)
@@ -545,4 +588,72 @@ public class GlifLayout extends PartnerCustomizationLayout {
       }
     }
   }
+
+  protected void initScrollingListener() {
+    ScrollView scrollView = getScrollView();
+
+    if (scrollView instanceof BottomScrollView) {
+      ((BottomScrollView) scrollView)
+          .setBottomScrollListener(
+              new BottomScrollListener() {
+                @Override
+                public void onScrolledToBottom() {
+                  onScrolling(true);
+                }
+
+                @Override
+                public void onRequiresScroll() {
+                  onScrolling(false);
+                }
+              });
+    }
+  }
+
+  protected void onScrolling(boolean isBottom) {
+    FooterBarMixin footerBarMixin = getMixin(FooterBarMixin.class);
+    if (footerBarMixin != null) {
+      LinearLayout footerContainer = footerBarMixin.getButtonContainer();
+      if (footerContainer != null) {
+        if (isBottom) {
+          footerContainer.setBackgroundColor(Color.TRANSPARENT);
+        } else {
+          footerContainer.setBackgroundColor(getFooterBackgroundColorFromStyle());
+        }
+      }
+    }
+  }
+
+  /**
+   * Make button visible and register the {@link Activity#onBackPressed()} to the on click event of
+   * the floating back button. It works when {@link
+   * PartnerConfigHelper#isGlifExpressiveEnabled(Context)} return true.
+   */
+  protected void initBackButton() {
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
+      Activity activity = PartnerCustomizationLayout.lookupActivityFromContext(getContext());
+
+      FloatingBackButtonMixin floatingBackButtonMixin = getMixin(FloatingBackButtonMixin.class);
+      if (floatingBackButtonMixin != null) {
+        floatingBackButtonMixin.setVisibility(VISIBLE);
+        floatingBackButtonMixin.setOnClickListener(v -> activity.onBackPressed());
+      } else {
+        LOG.w("FloatingBackButtonMixin button is null");
+      }
+    } else {
+      LOG.atDebug("isGlifExpressiveEnabled is false");
+    }
+  }
+
+  /** Gets footer bar background color from theme style. */
+  public int getFooterBackgroundColorFromStyle() {
+    TypedValue typedValue = new TypedValue();
+    Theme theme = getContext().getTheme();
+    theme.resolveAttribute(R.attr.sudFooterBackgroundColor, typedValue, true);
+    return typedValue.data;
+  }
+
+  protected boolean isGlifExpressiveEnabled() {
+    return PartnerConfigHelper.isGlifExpressiveEnabled(getContext())
+        && Build.VERSION.SDK_INT >= VERSION_CODES.VANILLA_ICE_CREAM;
+  }
 }
diff --git a/main/src/com/google/android/setupdesign/GlifListLayout.java b/main/src/com/google/android/setupdesign/GlifListLayout.java
index ce69bd1..566eefd 100644
--- a/main/src/com/google/android/setupdesign/GlifListLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifListLayout.java
@@ -24,8 +24,11 @@ import android.util.AttributeSet;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
+import android.widget.AbsListView;
+import android.widget.AbsListView.OnScrollListener;
 import android.widget.ListAdapter;
 import android.widget.ListView;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.util.ForceTwoPaneHelper;
 import com.google.android.setupdesign.template.ListMixin;
 import com.google.android.setupdesign.template.ListViewScrollHandlingDelegate;
@@ -80,6 +83,12 @@ public class GlifListLayout extends GlifLayout {
       tryApplyPartnerCustomizationContentPaddingTopStyle(view);
     }
     updateLandscapeMiddleHorizontalSpacing();
+
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
+      initScrollingListener();
+    }
+
+    initBackButton();
   }
 
   @Override
@@ -92,9 +101,17 @@ public class GlifListLayout extends GlifLayout {
   protected View onInflateTemplate(LayoutInflater inflater, int template) {
     if (template == 0) {
       template = R.layout.sud_glif_list_template;
+
       // if the activity is embedded should apply an embedded layout.
       if (isEmbeddedActivityOnePaneEnabled(getContext())) {
-        template = R.layout.sud_glif_list_embedded_template;
+        if (isGlifExpressiveEnabled()) {
+          template = R.layout.sud_glif_expressive_list_embedded_template;
+        } else {
+          template = R.layout.sud_glif_list_embedded_template;
+        }
+        // TODO add unit test for this case.
+      } else if (isGlifExpressiveEnabled()) {
+        template = R.layout.sud_glif_expressive_list_template;
       } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
         template = R.layout.sud_glif_list_template_two_pane;
       }
@@ -110,6 +127,29 @@ public class GlifListLayout extends GlifLayout {
     return super.findContainer(containerId);
   }
 
+  @Override
+  protected void initScrollingListener() {
+    ListView listView = null;
+    if (listMixin != null) {
+      listView = listMixin.getListView();
+    }
+
+    if (listView != null) {
+      listView.setOnScrollListener(
+          new OnScrollListener() {
+            @Override
+            public void onScrollStateChanged(AbsListView absListView, int i) {}
+
+            @Override
+            public void onScroll(
+                AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
+              onScrolling(
+                  firstVisibleItem + visibleItemCount >= totalItemCount && totalItemCount > 0);
+            }
+          });
+    }
+  }
+
   public ListView getListView() {
     return listMixin.getListView();
   }
diff --git a/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java b/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java
index 433ca60..bb9d739 100644
--- a/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java
@@ -100,9 +100,17 @@ public class GlifPreferenceLayout extends GlifRecyclerLayout {
   protected View onInflateTemplate(LayoutInflater inflater, int template) {
     if (template == 0) {
       template = R.layout.sud_glif_preference_template;
+
       // if the activity is embedded should apply an embedded layout.
       if (isEmbeddedActivityOnePaneEnabled(getContext())) {
-        template = R.layout.sud_glif_preference_embedded_template;
+        if (isGlifExpressiveEnabled()) {
+          template = R.layout.sud_glif_expressive_preference_embedded_template;
+        } else {
+          template = R.layout.sud_glif_preference_embedded_template;
+        }
+        // TODO add unit test for this case.
+      } else if (isGlifExpressiveEnabled()) {
+        template = R.layout.sud_glif_expressive_preference_template;
       } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
         template = R.layout.sud_glif_preference_template_two_pane;
       }
diff --git a/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java b/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java
index eed799c..d0254ae 100644
--- a/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java
@@ -22,11 +22,14 @@ import android.graphics.drawable.Drawable;
 import android.os.Build.VERSION_CODES;
 import androidx.recyclerview.widget.RecyclerView;
 import androidx.recyclerview.widget.RecyclerView.Adapter;
+import androidx.recyclerview.widget.RecyclerView.OnScrollListener;
 import androidx.recyclerview.widget.RecyclerView.ViewHolder;
 import android.util.AttributeSet;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
+import androidx.annotation.NonNull;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.util.ForceTwoPaneHelper;
 import com.google.android.setupdesign.template.RecyclerMixin;
 import com.google.android.setupdesign.template.RecyclerViewScrollHandlingDelegate;
@@ -81,6 +84,12 @@ public class GlifRecyclerLayout extends GlifLayout {
       tryApplyPartnerCustomizationContentPaddingTopStyle(view);
     }
     updateLandscapeMiddleHorizontalSpacing();
+
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
+      initScrollingListener();
+    }
+
+    initBackButton();
   }
 
   @Override
@@ -93,9 +102,17 @@ public class GlifRecyclerLayout extends GlifLayout {
   protected View onInflateTemplate(LayoutInflater inflater, int template) {
     if (template == 0) {
       template = R.layout.sud_glif_recycler_template;
+
       // if the activity is embedded should apply an embedded layout.
       if (isEmbeddedActivityOnePaneEnabled(getContext())) {
+        if (isGlifExpressiveEnabled()) {
+          template = R.layout.sud_glif_expressive_recycler_embedded_template;
+        } else {
         template = R.layout.sud_glif_recycler_embedded_template;
+        }
+        // TODO add unit test for this case.
+      } else if (isGlifExpressiveEnabled()) {
+        template = R.layout.sud_glif_expressive_recycler_template;
       } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
         template = R.layout.sud_glif_recycler_template_two_pane;
       }
@@ -136,6 +153,24 @@ public class GlifRecyclerLayout extends GlifLayout {
     return super.findViewById(id);
   }
 
+  @Override
+  protected void initScrollingListener() {
+    RecyclerView recyclerView = getRecyclerView();
+    if (recyclerView != null) {
+      recyclerView.addOnScrollListener(
+          new OnScrollListener() {
+            @Override
+            public void onScrolled(@NonNull RecyclerView recyclerView, int dx, int dy) {
+              super.onScrolled(recyclerView, dx, dy);
+              // direction > 0 means view can scroll down, direction < 0 means view can scroll up.
+              // Here we use direction > 0 to detect whether the view can be scrolling down or not.
+              boolean isAtBottom = !recyclerView.canScrollVertically(/* direction= */ 1);
+              onScrolling(isAtBottom);
+            }
+          });
+    }
+  }
+
   /** @see RecyclerMixin#setDividerItemDecoration(DividerItemDecoration) */
   public void setDividerItemDecoration(DividerItemDecoration decoration) {
     recyclerMixin.setDividerItemDecoration(decoration);
diff --git a/main/src/com/google/android/setupdesign/items/Item.java b/main/src/com/google/android/setupdesign/items/Item.java
index 407eacb..f8a6606 100644
--- a/main/src/com/google/android/setupdesign/items/Item.java
+++ b/main/src/com/google/android/setupdesign/items/Item.java
@@ -29,6 +29,7 @@ import android.widget.LinearLayout;
 import android.widget.TextView;
 import androidx.annotation.ColorInt;
 import androidx.annotation.Nullable;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupdesign.R;
 import com.google.android.setupdesign.util.ItemStyler;
 import com.google.android.setupdesign.util.LayoutStyler;
@@ -228,7 +229,9 @@ public class Item extends AbstractItem {
     // If the item view is a header layout, it doesn't need to adjust the layout padding start/end
     // here. It will be adjusted by HeaderMixin.
     // TODO: Add partner resource enable check
-    if (!(this instanceof ExpandableSwitchItem) && view.getId() != R.id.sud_layout_header) {
+    if (!(this instanceof ExpandableSwitchItem)
+        && view.getId() != R.id.sud_layout_header
+        && !(PartnerConfigHelper.isGlifExpressiveEnabled(view.getContext()))) {
       LayoutStyler.applyPartnerCustomizationLayoutPaddingStyle(view);
     }
     ItemStyler.applyPartnerCustomizationItemStyle(view);
diff --git a/main/src/com/google/android/setupdesign/items/ItemAdapter.java b/main/src/com/google/android/setupdesign/items/ItemAdapter.java
index ac13402..ebb761e 100644
--- a/main/src/com/google/android/setupdesign/items/ItemAdapter.java
+++ b/main/src/com/google/android/setupdesign/items/ItemAdapter.java
@@ -16,11 +16,23 @@
 
 package com.google.android.setupdesign.items;
 
+import android.annotation.TargetApi;
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.graphics.drawable.Drawable;
+import android.graphics.drawable.GradientDrawable;
+import android.graphics.drawable.LayerDrawable;
+import android.os.Build;
+import android.os.Build.VERSION_CODES;
 import android.util.SparseIntArray;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
 import android.widget.BaseAdapter;
+import android.widget.LinearLayout;
+import com.google.android.setupcompat.partnerconfig.PartnerConfig;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
+import com.google.android.setupdesign.R;
 
 /**
  * An adapter typically used with ListView to display an {@link
@@ -72,15 +84,143 @@ public class ItemAdapter extends BaseAdapter implements ItemHierarchy.Observer {
     }
   }
 
+  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
+  private Drawable getFirstBackground(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundFirst});
+    Drawable firstBackground = a.getDrawable(0);
+    a.recycle();
+    return firstBackground;
+  }
+
+  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
+  private Drawable getLastBackground(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundLast});
+    Drawable lastBackground = a.getDrawable(0);
+    a.recycle();
+    return lastBackground;
+  }
+
+  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
+  private Drawable getMiddleBackground(Context context) {
+    TypedArray a = context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackground});
+    Drawable middleBackground = a.getDrawable(0);
+    a.recycle();
+    return middleBackground;
+  }
+
+  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
+  private Drawable getSingleBackground(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundSingle});
+    Drawable singleBackground = a.getDrawable(0);
+    a.recycle();
+    return singleBackground;
+  }
+
+  private float getCornerRadius(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemCornerRadius});
+    float conerRadius = a.getDimension(0, 0);
+    a.recycle();
+    return conerRadius;
+  }
+
+  public void updateBackground(View convertView, int position) {
+    float groupCornerRadius =
+        PartnerConfigHelper.get(convertView.getContext())
+            .getDimension(convertView.getContext(), PartnerConfig.CONFIG_ITEMS_GROUP_CORNER_RADIUS);
+    float cornerRadius = getCornerRadius(convertView.getContext());
+    Drawable drawable = convertView.getBackground();
+    Drawable clickDrawable = null;
+    Drawable backgroundDrawable = null;
+    GradientDrawable background = null;
+
+    if (position == 0 && getCount() == 1) {
+      backgroundDrawable = getSingleBackground(convertView.getContext());
+    } else if (position == 0) {
+      backgroundDrawable = getFirstBackground(convertView.getContext());
+    } else if (position == getCount() - 1) {
+      backgroundDrawable = getLastBackground(convertView.getContext());
+    } else {
+      backgroundDrawable = getMiddleBackground(convertView.getContext());
+    }
+    // TODO add test case for list item group corner partner config
+    if (drawable instanceof LayerDrawable && ((LayerDrawable) drawable).getNumberOfLayers() >= 2) {
+      clickDrawable = ((LayerDrawable) drawable).getDrawable(1);
+    } else {
+      TypedArray a =
+          convertView
+              .getContext()
+              .getTheme()
+              .obtainStyledAttributes(new int[] {R.attr.selectableItemBackground});
+      clickDrawable = a.getDrawable(0);
+      a.recycle();
+    }
+    if (backgroundDrawable instanceof GradientDrawable) {
+      float topCornerRadius = cornerRadius;
+      float bottomCornerRadius = cornerRadius;
+      if (position == 0) {
+        topCornerRadius = groupCornerRadius;
+      }
+      if (position == getCount() - 1) {
+        bottomCornerRadius = groupCornerRadius;
+      }
+      background = (GradientDrawable) backgroundDrawable;
+      background.setCornerRadii(
+          new float[] {
+            topCornerRadius,
+            topCornerRadius,
+            topCornerRadius,
+            topCornerRadius,
+            bottomCornerRadius,
+            bottomCornerRadius,
+            bottomCornerRadius,
+            bottomCornerRadius
+          });
+      final Drawable[] layers = {background, clickDrawable};
+      convertView.setBackgroundDrawable(new LayerDrawable(layers));
+    }
+  }
+
   @Override
   public View getView(int position, View convertView, ViewGroup parent) {
-    IItem item = getItem(position);
-    if (convertView == null) {
-      LayoutInflater inflater = LayoutInflater.from(parent.getContext());
-      convertView = inflater.inflate(item.getLayoutResource(), parent, false);
+
+    // TODO  when getContext is not activity context then fallback to out suw behavior
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(parent.getContext())
+        && Build.VERSION.SDK_INT >= VERSION_CODES.VANILLA_ICE_CREAM) {
+      IItem item = getItem(position);
+      LinearLayout linearLayout = null;
+      // The ListView can not handle the margin for the child view. So we need to use the
+      // LinearLayout to wrap the child view.
+      // The getView will trigger several times, for the same position, when the first time
+      // the convertView will be null, we should create the view which we want by ourself.
+      // The second and following times, we should return the same view which we created before.
+      // And for the item#onBindView, we should pass the child view with the wrap linear layout.
+      if (convertView == null) {
+        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
+        linearLayout =
+            (LinearLayout) inflater.inflate(R.layout.sud_empty_linear_layout, parent, false);
+        LayoutInflater linearLayoutInflater = LayoutInflater.from(linearLayout.getContext());
+        convertView = linearLayoutInflater.inflate(item.getLayoutResource(), linearLayout, false);
+        linearLayout.addView(convertView);
+      } else {
+        linearLayout = (LinearLayout) convertView;
+        convertView = linearLayout.getChildAt(0);
+      }
+      updateBackground(convertView, position);
+      item.onBindView(convertView);
+      return linearLayout;
+    } else {
+      IItem item = getItem(position);
+      if (convertView == null) {
+        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
+        convertView = inflater.inflate(item.getLayoutResource(), parent, false);
+      }
+      item.onBindView(convertView);
+      return convertView;
     }
-    item.onBindView(convertView);
-    return convertView;
   }
 
   @Override
diff --git a/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java b/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java
index dbbda29..7172d8d 100644
--- a/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java
+++ b/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java
@@ -16,11 +16,16 @@
 
 package com.google.android.setupdesign.items;
 
+import android.annotation.TargetApi;
+import android.content.Context;
 import android.content.res.TypedArray;
 import android.graphics.Rect;
 import android.graphics.drawable.ColorDrawable;
 import android.graphics.drawable.Drawable;
+import android.graphics.drawable.GradientDrawable;
 import android.graphics.drawable.LayerDrawable;
+import android.os.Build;
+import android.os.Build.VERSION_CODES;
 import androidx.recyclerview.widget.RecyclerView;
 import android.util.Log;
 import android.view.LayoutInflater;
@@ -113,7 +118,6 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
     final View view = inflater.inflate(viewType, parent, false);
     final ItemViewHolder viewHolder = new ItemViewHolder(view);
     Drawable background = null;
-
     final Object viewTag = view.getTag();
     if (!TAG_NO_BACKGROUND.equals(viewTag)) {
       final TypedArray typedArray =
@@ -140,7 +144,6 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
           }
         }
       }
-
       if (selectableItemBackground == null || background == null) {
         Log.e(
             TAG,
@@ -171,11 +174,111 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
     return viewHolder;
   }
 
+  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
+  private Drawable getFirstBackground(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundFirst});
+    Drawable firstBackground = a.getDrawable(0);
+    a.recycle();
+    return firstBackground;
+  }
+
+  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
+  private Drawable getLastBackground(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundLast});
+    Drawable lastBackground = a.getDrawable(0);
+    a.recycle();
+    return lastBackground;
+  }
+
+  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
+  private Drawable getMiddleBackground(Context context) {
+    TypedArray a = context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackground});
+    Drawable middleBackground = a.getDrawable(0);
+    a.recycle();
+    return middleBackground;
+  }
+
+  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
+  private Drawable getSingleBackground(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundSingle});
+    Drawable singleBackground = a.getDrawable(0);
+    a.recycle();
+    return singleBackground;
+  }
+
+  private float getCornerRadius(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemCornerRadius});
+    float conerRadius = a.getDimension(0, 0);
+    a.recycle();
+    return conerRadius;
+  }
+
+  public void updateBackground(View view, int position) {
+    if (TAG_NO_BACKGROUND.equals(view.getTag())) {
+      return;
+    }
+    float groupCornerRadius =
+        PartnerConfigHelper.get(view.getContext())
+            .getDimension(view.getContext(), PartnerConfig.CONFIG_ITEMS_GROUP_CORNER_RADIUS);
+    float cornerRadius = getCornerRadius(view.getContext());
+    Drawable drawable = view.getBackground();
+    // TODO add test case for list item group corner partner config
+    if (drawable instanceof LayerDrawable && ((LayerDrawable) drawable).getNumberOfLayers() >= 2) {
+      Drawable clickDrawable = ((LayerDrawable) drawable).getDrawable(1);
+      Drawable backgroundDrawable = null;
+      GradientDrawable background = null;
+
+      if (position == 0 && getItemCount() == 1) {
+        backgroundDrawable = getSingleBackground(view.getContext());
+      } else if (position == 0) {
+        backgroundDrawable = getFirstBackground(view.getContext());
+      } else if (position == getItemCount() - 1) {
+        backgroundDrawable = getLastBackground(view.getContext());
+      } else {
+        backgroundDrawable = getMiddleBackground(view.getContext());
+      }
+
+      if (backgroundDrawable instanceof GradientDrawable) {
+        float topCornerRadius = cornerRadius;
+        float bottomCornerRadius = cornerRadius;
+        if (position == 0) {
+          topCornerRadius = groupCornerRadius;
+        }
+        if (position == getItemCount() - 1) {
+          bottomCornerRadius = groupCornerRadius;
+        }
+        background = (GradientDrawable) backgroundDrawable;
+        background.setCornerRadii(
+            new float[] {
+              topCornerRadius,
+              topCornerRadius,
+              topCornerRadius,
+              topCornerRadius,
+              bottomCornerRadius,
+              bottomCornerRadius,
+              bottomCornerRadius,
+              bottomCornerRadius
+            });
+        final Drawable[] layers = {background, clickDrawable};
+        view.setBackgroundDrawable(new PatchedLayerDrawable(layers));
+      }
+    }
+  }
+
   @Override
   public void onBindViewHolder(ItemViewHolder holder, int position) {
     final IItem item = getItem(position);
     holder.setEnabled(item.isEnabled());
     holder.setItem(item);
+    // TODO  when getContext is not activity context then fallback to out suw behavior
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(holder.itemView.getContext())
+        && Build.VERSION.SDK_INT >= VERSION_CODES.VANILLA_ICE_CREAM) {
+      updateBackground(holder.itemView, position);
+    }
     item.onBindView(holder.itemView);
   }
 
diff --git a/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java b/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java
new file mode 100644
index 0000000..4257984
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java
@@ -0,0 +1,148 @@
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
+package com.google.android.setupdesign.template;
+
+import android.util.AttributeSet;
+import android.util.Log;
+import android.view.InflateException;
+import android.view.LayoutInflater;
+import android.view.View;
+import android.view.View.OnClickListener;
+import android.view.ViewStub;
+import android.widget.Button;
+import android.widget.FrameLayout;
+import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
+import com.google.android.setupcompat.internal.TemplateLayout;
+import com.google.android.setupcompat.template.Mixin;
+import com.google.android.setupdesign.R;
+import com.google.android.setupdesign.util.HeaderAreaStyler;
+import com.google.android.setupdesign.util.LayoutStyler;
+import com.google.android.setupdesign.util.PartnerStyleHelper;
+
+/** A {@link Mixin} for controlling back button on the template layout. */
+public class FloatingBackButtonMixin implements Mixin {
+
+  private final TemplateLayout templateLayout;
+  private static final String TAG = "FloatingBackButtonMixin";
+
+  @Nullable private OnClickListener listener;
+
+  @VisibleForTesting boolean tryInflatingBackButton = false;
+
+  /**
+   * A {@link Mixin} for setting and getting the back button.
+   *
+   * @param layout The template layout that this Mixin is a part of
+   * @param attrs XML attributes given to the layout
+   * @param defStyleAttr The default style attribute as given to the constructor of the layout
+   */
+  public FloatingBackButtonMixin(TemplateLayout layout, AttributeSet attrs, int defStyleAttr) {
+    templateLayout = layout;
+  }
+
+  /**
+   * Sets the visibility of the back button. gone map to 8 invisible map to 4 visible map to 0
+   *
+   * @param visibility Set it visible or not
+   */
+  public void setVisibility(int visibility) {
+    final Button backbutton = getBackButton();
+    if (backbutton != null) {
+      backbutton.setVisibility(visibility);
+      getContainerView().setVisibility(visibility);
+    }
+  }
+
+  /** Sets the {@link OnClickListener} of the back button. */
+  public void setOnClickListener(@Nullable OnClickListener listener) {
+    final Button backbutton = getBackButton();
+    if (backbutton != null) {
+      this.listener = listener;
+      backbutton.setOnClickListener(listener);
+    }
+  }
+
+  /** Tries to apply the partner customization to the back button. */
+  public void tryApplyPartnerCustomizationStyle() {
+    if (PartnerStyleHelper.shouldApplyPartnerResource(templateLayout)
+        && getContainerView() != null) {
+      LayoutStyler.applyPartnerCustomizationExtraPaddingStyle(getContainerView());
+      HeaderAreaStyler.applyPartnerCustomizationBackButtonStyle(getContainerView());
+    }
+  }
+
+  /**
+   * Check the back button exist or not. If exists, return the button. Otherwise try to inflate it
+   * and check again.
+   */
+  @Nullable
+  @VisibleForTesting
+  Button getBackButton() {
+    final Button button = findBackButton();
+    if (button != null) {
+      return button;
+    }
+
+    // Try to inflate the back button if it's not inflated before.
+    if (!tryInflatingBackButton) {
+      tryInflatingBackButton = true;
+      final ViewStub buttonViewStub =
+          (ViewStub) templateLayout.findManagedViewById(R.id.sud_floating_back_button_stub);
+      if (buttonViewStub != null) {
+        try {
+          inflateButton(buttonViewStub);
+        } catch (InflateException e) {
+          Log.w(TAG, "Incorrect theme:" + e.toString());
+          return null;
+        }
+      }
+    }
+    return findBackButton();
+  }
+
+  private Button findBackButton() {
+    Button backbutton = templateLayout.findManagedViewById(R.id.sud_floating_back_button);
+    if (backbutton == null) {
+      Log.w(TAG, "Can't find the back button.");
+    }
+    return backbutton;
+  }
+
+  @VisibleForTesting
+  void inflateButton(ViewStub viewStub) {
+    LayoutInflater inflater = LayoutInflater.from(templateLayout.getContext());
+
+    viewStub.setLayoutInflater(inflater);
+    viewStub.inflate();
+  }
+
+  protected FrameLayout getContainerView() {
+    return templateLayout.findManagedViewById(R.id.sud_layout_floating_back_button_container);
+  }
+
+  /** Returns the current visibility of the back button. */
+  public int getVisibility() {
+    final Button backbutton = getBackButton();
+    return (backbutton != null) ? getBackButton().getVisibility() : View.GONE;
+  }
+
+  /** Gets the {@link OnClickListener} of the back button. */
+  public OnClickListener getOnClickListener() {
+    return this.listener;
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/template/IllustrationProgressMixin.java b/main/src/com/google/android/setupdesign/template/IllustrationProgressMixin.java
index 23b9fa0..7347e2c 100644
--- a/main/src/com/google/android/setupdesign/template/IllustrationProgressMixin.java
+++ b/main/src/com/google/android/setupdesign/template/IllustrationProgressMixin.java
@@ -33,6 +33,7 @@ import com.google.android.setupcompat.partnerconfig.PartnerConfig.ResourceType;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.partnerconfig.ResourceEntry;
 import com.google.android.setupcompat.template.Mixin;
+import com.google.android.setupcompat.util.Logger;
 import com.google.android.setupdesign.GlifLayout;
 import com.google.android.setupdesign.R;
 import com.google.android.setupdesign.view.IllustrationVideoView;
@@ -46,6 +47,7 @@ import com.google.android.setupdesign.view.IllustrationVideoView;
 @TargetApi(VERSION_CODES.ICE_CREAM_SANDWICH)
 @Deprecated
 public class IllustrationProgressMixin implements Mixin {
+  private static final Logger LOG = new Logger(IllustrationProgressMixin.class);
 
   private final GlifLayout glifLayout;
   private final Context context;
@@ -66,6 +68,7 @@ public class IllustrationProgressMixin implements Mixin {
    *     GONE}
    */
   public void setShown(boolean shown) {
+    LOG.atInfo("setShown(" + shown + ")");
     if (!shown) {
       View view = peekProgressIllustrationLayout();
       if (view != null) {
diff --git a/main/src/com/google/android/setupdesign/template/ProgressBarMixin.java b/main/src/com/google/android/setupdesign/template/ProgressBarMixin.java
index ac5ac69..06e3484 100644
--- a/main/src/com/google/android/setupdesign/template/ProgressBarMixin.java
+++ b/main/src/com/google/android/setupdesign/template/ProgressBarMixin.java
@@ -22,6 +22,7 @@ import android.content.res.TypedArray;
 import android.os.Build;
 import android.os.Build.VERSION_CODES;
 import android.util.AttributeSet;
+import android.util.Log;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.ViewStub;
@@ -29,7 +30,10 @@ import android.widget.ProgressBar;
 import androidx.annotation.AttrRes;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
+import com.google.android.material.progressindicator.LinearProgressIndicator;
 import com.google.android.setupcompat.internal.TemplateLayout;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.template.Mixin;
 import com.google.android.setupdesign.R;
 import com.google.android.setupdesign.util.HeaderAreaStyler;
@@ -38,9 +42,10 @@ import com.google.android.setupdesign.util.PartnerStyleHelper;
 /** A {@link Mixin} for showing a progress bar. */
 public class ProgressBarMixin implements Mixin {
 
+  private static final String TAG = "ProgressBarMixin";
   private final TemplateLayout templateLayout;
   private final boolean useBottomProgressBar;
-
+  private final boolean isGlifExpressiveEnabled;
   @Nullable private ColorStateList color;
 
   /** @param layout The layout this mixin belongs to. */
@@ -57,6 +62,7 @@ public class ProgressBarMixin implements Mixin {
   public ProgressBarMixin(@NonNull TemplateLayout layout, boolean useBottomProgressBar) {
     templateLayout = layout;
     this.useBottomProgressBar = useBottomProgressBar;
+    isGlifExpressiveEnabled = PartnerConfigHelper.isGlifExpressiveEnabled(layout.getContext());
   }
 
   /**
@@ -90,13 +96,19 @@ public class ProgressBarMixin implements Mixin {
     }
 
     this.useBottomProgressBar = useBottomProgressBar;
+    isGlifExpressiveEnabled = PartnerConfigHelper.isGlifExpressiveEnabled(layout.getContext());
   }
 
   /** @return True if the progress bar is currently shown. */
   public boolean isShown() {
-    final View progressBar =
-        templateLayout.findManagedViewById(
-            useBottomProgressBar ? R.id.sud_glif_progress_bar : R.id.sud_layout_progress);
+    final View progressBar;
+    if (isGlifExpressiveEnabled) {
+      progressBar = templateLayout.findManagedViewById(R.id.sud_layout_progress_indicator);
+    } else {
+      progressBar =
+          templateLayout.findManagedViewById(
+              useBottomProgressBar ? R.id.sud_glif_progress_bar : R.id.sud_layout_progress);
+    }
     return progressBar != null && progressBar.getVisibility() == View.VISIBLE;
   }
 
@@ -127,15 +139,24 @@ public class ProgressBarMixin implements Mixin {
    * @return The progress bar of this layout. May be null only if the template used doesn't have a
    *     progress bar built-in.
    */
-  private ProgressBar getProgressBar() {
+  @VisibleForTesting
+  protected View getProgressBar() {
     final View progressBarView = peekProgressBar();
-    if (progressBarView == null && !useBottomProgressBar) {
-      final ViewStub progressBarStub =
-          (ViewStub) templateLayout.findManagedViewById(R.id.sud_layout_progress_stub);
-      if (progressBarStub != null) {
-        progressBarStub.inflate();
+    if (progressBarView == null) {
+      if (isGlifExpressiveEnabled) {
+        final ViewStub progressIndicatorStub =
+            (ViewStub) templateLayout.findManagedViewById(R.id.sud_glif_progress_indicator_stub);
+        if (progressIndicatorStub != null) {
+          progressIndicatorStub.inflate();
+        }
+      } else if (!useBottomProgressBar) {
+        final ViewStub progressBarStub =
+            (ViewStub) templateLayout.findManagedViewById(R.id.sud_layout_progress_stub);
+        if (progressBarStub != null) {
+          progressBarStub.inflate();
+        }
+        setColor(color);
       }
-      setColor(color);
     }
     return peekProgressBar();
   }
@@ -149,26 +170,43 @@ public class ProgressBarMixin implements Mixin {
    *     or if the template does not contain a progress bar.
    */
   public ProgressBar peekProgressBar() {
-    return (ProgressBar)
-        templateLayout.findManagedViewById(
-            useBottomProgressBar ? R.id.sud_glif_progress_bar : R.id.sud_layout_progress);
+    if (isGlifExpressiveEnabled) {
+      LinearProgressIndicator progressIndicator =
+          templateLayout.findManagedViewById(R.id.sud_layout_progress_indicator);
+      return (ProgressBar) progressIndicator;
+    } else {
+      return (ProgressBar)
+          templateLayout.findManagedViewById(
+              useBottomProgressBar ? R.id.sud_glif_progress_bar : R.id.sud_layout_progress);
+    }
   }
 
   /** Sets the color of the indeterminate progress bar. This method is a no-op on SDK < 21. */
+  /**
+   * @deprecated Use {@link ProgressBar#setProgressBackgroundTintList(int)} or {@link
+   *     LinearProgressIndicator#setIndeterminateTintList(int)} and {@link
+   *     LinearProgressIndicator#setTrackColor(int)} instead.
+   */
+  @Deprecated
   public void setColor(@Nullable ColorStateList color) {
     this.color = color;
     if (Build.VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP) {
-      final ProgressBar bar = peekProgressBar();
-      if (bar != null) {
-        bar.setIndeterminateTintList(color);
-        if (Build.VERSION.SDK_INT >= VERSION_CODES.M || color != null) {
-          // There is a bug in Lollipop where setting the progress tint color to null
-          // will crash with "java.lang.NullPointerException: Attempt to invoke virtual
-          // method 'int android.graphics.Paint.getAlpha()' on a null object reference"
-          // at android.graphics.drawable.NinePatchDrawable.draw(:250)
-          // The bug doesn't affect ProgressBar on M because it uses ShapeDrawable instead
-          // of NinePatchDrawable. (commit 6a8253fdc9f4574c28b4beeeed90580ffc93734a)
-          bar.setProgressBackgroundTintList(color);
+      final View view = peekProgressBar();
+      if (view != null) {
+        if (view instanceof ProgressBar) {
+          ProgressBar bar = (ProgressBar) view;
+          bar.setIndeterminateTintList(color);
+          if (Build.VERSION.SDK_INT >= VERSION_CODES.M || color != null) {
+            // There is a bug in Lollipop where setting the progress tint color to null
+            // will crash with "java.lang.NullPointerException: Attempt to invoke virtual
+            // method 'int android.graphics.Paint.getAlpha()' on a null object reference"
+            // at android.graphics.drawable.NinePatchDrawable.draw(:250)
+            // The bug doesn't affect ProgressBar on M because it uses ShapeDrawable instead
+            // of NinePatchDrawable. (commit 6a8253fdc9f4574c28b4beeeed90580ffc93734a)
+            bar.setProgressBackgroundTintList(color);
+          }
+        } else if (view instanceof LinearProgressIndicator) {
+          // TODO: b/377241556 - Set color from the view LinearProgressIndicator.
         }
       }
     }
@@ -188,7 +226,7 @@ public class ProgressBarMixin implements Mixin {
    * partner config isn't enable.
    */
   public void tryApplyPartnerCustomizationStyle() {
-    ProgressBar progressBar = peekProgressBar();
+    View progressBar = peekProgressBar();
     if (!useBottomProgressBar || progressBar == null) {
       return;
     }
@@ -196,7 +234,11 @@ public class ProgressBarMixin implements Mixin {
     boolean partnerHeavyThemeLayout = PartnerStyleHelper.isPartnerHeavyThemeLayout(templateLayout);
 
     if (partnerHeavyThemeLayout) {
-      HeaderAreaStyler.applyPartnerCustomizationProgressBarStyle(progressBar);
+      if (progressBar instanceof ProgressBar) {
+        HeaderAreaStyler.applyPartnerCustomizationProgressBarStyle((ProgressBar) progressBar);
+      } else {
+        Log.w(TAG, "The view is not a ProgressBar");
+      }
     } else {
       Context context = progressBar.getContext();
       final ViewGroup.LayoutParams lp = progressBar.getLayoutParams();
diff --git a/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java b/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java
index 62c503c..6f1bb33 100644
--- a/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java
+++ b/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java
@@ -17,17 +17,26 @@
 package com.google.android.setupdesign.template;
 
 import android.content.Context;
+import android.graphics.Color;
+import android.graphics.drawable.Drawable;
 import android.os.Handler;
 import android.os.Looper;
+import android.util.Log;
 import android.view.View;
 import android.view.View.OnClickListener;
 import android.widget.Button;
+import android.widget.LinearLayout;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.StringRes;
+import com.google.android.material.button.MaterialButton;
 import com.google.android.setupcompat.internal.TemplateLayout;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
+import com.google.android.setupcompat.template.FooterBarMixin;
 import com.google.android.setupcompat.template.FooterButton;
 import com.google.android.setupcompat.template.Mixin;
+import com.google.android.setupdesign.GlifLayout;
+import com.google.android.setupdesign.R;
 import com.google.android.setupdesign.view.NavigationBar;
 
 /**
@@ -36,6 +45,8 @@ import com.google.android.setupdesign.view.NavigationBar;
  */
 public class RequireScrollMixin implements Mixin {
 
+  private static final String LOG_TAG = "RequireScrollMixin";
+
   /* static section */
 
   /**
@@ -78,10 +89,15 @@ public class RequireScrollMixin implements Mixin {
 
   private ScrollHandlingDelegate delegate;
 
+  private final TemplateLayout templateLayout;
+
   @Nullable private OnRequireScrollStateChangedListener listener;
 
-  /** @param templateLayout The template containing this mixin */
+  /**
+   * @param templateLayout The template containing this mixin
+   */
   public RequireScrollMixin(@NonNull TemplateLayout templateLayout) {
+    this.templateLayout = templateLayout;
   }
 
   /**
@@ -102,7 +118,7 @@ public class RequireScrollMixin implements Mixin {
     this.listener = listener;
   }
 
-  /** @return The scroll state listener previously set, or {@code null} if none is registered. */
+  /** Returns the scroll state listener previously set, or {@code null} if none is registered. */
   public OnRequireScrollStateChangedListener getOnRequireScrollStateChangedListener() {
     return listener;
   }
@@ -148,7 +164,7 @@ public class RequireScrollMixin implements Mixin {
     requireScroll();
   }
 
-  /** @see #requireScrollWithButton(Button, CharSequence, OnClickListener) */
+  /** See {@link #requireScrollWithButton(Button, CharSequence, OnClickListener)}. */
   public void requireScrollWithButton(
       @NonNull Button button, @StringRes int moreText, @Nullable OnClickListener onClickListener) {
     requireScrollWithButton(button, button.getContext().getText(moreText), onClickListener);
@@ -233,18 +249,153 @@ public class RequireScrollMixin implements Mixin {
       @NonNull final FooterButton button,
       final CharSequence moreText,
       @Nullable OnClickListener onClickListener) {
-    final CharSequence nextText = button.getText();
-    button.setOnClickListener(createOnClickListener(onClickListener));
+    Context context = templateLayout.getContext();
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      requireScrollWithDownButton(context, onClickListener);
+    } else {
+      final CharSequence nextText = button.getText();
+      button.setOnClickListener(createOnClickListener(onClickListener));
+      setOnRequireScrollStateChangedListener(
+          new OnRequireScrollStateChangedListener() {
+            @Override
+            public void onRequireScrollStateChanged(boolean scrollNeeded) {
+              button.setText(scrollNeeded ? moreText : nextText);
+            }
+          });
+      requireScroll();
+    }
+  }
+
+  /**
+   * Use the given {@code primaryButton} to require scrolling. When scrolling is required, the
+   * primary button label will change to {@code moreText}, and the secondary button will be hidden.
+   * Tapping the primary button will cause the page to scroll down and reveal both the primary and
+   * secondary buttons.
+   *
+   * <p>Note: Calling {@link View#setOnClickListener} on the primary button after this method will
+   * remove its link to the require-scroll mechanism. If you need to do that, obtain the click
+   * listener from {@link #createOnClickListener(OnClickListener)}.
+   *
+   * <p>Note: The normal button label is taken from the primary button's text at the time of calling
+   * this method. Calling {@link android.widget.TextView#setText} after calling this method causes
+   * undefined behavior.
+   *
+   * @param context The context used to resolve resource IDs.
+   * @param primaryButton The button to use for require scroll. The button's "normal" label is taken
+   *     from the text at the time of calling this method, and the click listener of it will be
+   *     replaced.
+   * @param secondaryButton The secondary button. This button will be hidden when scrolling is
+   *     required.
+   * @param moreText The primary button label when scroll is required.
+   * @param onClickListener The listener for primary button clicks when scrolling is not required.
+   */
+  public void requireScrollWithButton(
+      @NonNull Context context,
+      @NonNull FooterButton primaryButton,
+      @NonNull FooterButton secondaryButton,
+      @StringRes int moreText,
+      @Nullable OnClickListener onClickListener) {
+    requireScrollWithButton(
+        primaryButton, secondaryButton, context.getText(moreText), onClickListener);
+  }
+
+  /**
+   * Use the given {@code primaryButton} to require scrolling. When scrolling is required, the
+   * primary button label will change to {@code moreText}, and the secondary button will be hidden.
+   * Tapping the primary button will cause the page to scroll down and reveal both the primary and
+   * secondary buttons.
+   *
+   * <p>Note: Calling {@link View#setOnClickListener} on the primary button after this method will
+   * remove its link to the require-scroll mechanism. If you need to do that, obtain the click
+   * listener from {@link #createOnClickListener(OnClickListener)}.
+   *
+   * <p>Note: The normal button label is taken from the primary button's text at the time of calling
+   * this method. Calling {@link android.widget.TextView#setText} after calling this method causes
+   * undefined behavior.
+   *
+   * @param primaryButton The button to use for require scroll. The button's "normal" label is taken
+   *     from the text at the time of calling this method, and the click listener of it will be
+   *     replaced.
+   * @param secondaryButton The secondary button. This button will be hidden when scrolling is
+   *     required.
+   * @param moreText The primary button label when scroll is required.
+   * @param onClickListener The listener for primary button clicks when scrolling is not required.
+   */
+  public void requireScrollWithButton(
+      @NonNull final FooterButton primaryButton,
+      @NonNull final FooterButton secondaryButton,
+      final CharSequence moreText,
+      @Nullable OnClickListener onClickListener) {
+    Context context = templateLayout.getContext();
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      requireScrollWithDownButton(context, onClickListener);
+    } else {
+      final CharSequence nextText = primaryButton.getText();
+      primaryButton.setOnClickListener(createOnClickListener(onClickListener));
+      setOnRequireScrollStateChangedListener(
+          new OnRequireScrollStateChangedListener() {
+            @Override
+            public void onRequireScrollStateChanged(boolean scrollNeeded) {
+              primaryButton.setText(scrollNeeded ? moreText : nextText);
+              secondaryButton.setVisibility(scrollNeeded ? View.GONE : View.VISIBLE);
+            }
+          });
+      requireScroll();
+    }
+  }
+
+  public void requireScrollWithDownButton(
+      @NonNull Context context, @Nullable OnClickListener onClickListener) {
+    FooterBarMixin footerBarMixin = templateLayout.getMixin(FooterBarMixin.class);
+    Button primaryButtonView = footerBarMixin.getPrimaryButtonView();
+    Button secondaryButtonView = footerBarMixin.getSecondaryButtonView();
+    CharSequence nextText = primaryButtonView.getText();
+    primaryButtonView.setVisibility(View.INVISIBLE);
+    primaryButtonView.setOnClickListener(createOnClickListener(onClickListener));
+    footerBarMixin.setButtonWidthForExpressiveStyle(/* isDownButton= */ false);
+    LinearLayout footerContainer = footerBarMixin.getButtonContainer();
+
     setOnRequireScrollStateChangedListener(
-        new OnRequireScrollStateChangedListener() {
-          @Override
-          public void onRequireScrollStateChanged(boolean scrollNeeded) {
-            button.setText(scrollNeeded ? moreText : nextText);
+        scrollNeeded -> {
+          if (scrollNeeded) {
+            generateGlifExpressiveDownButton(context, primaryButtonView, footerBarMixin);
+            footerContainer.setBackgroundColor(
+                ((GlifLayout) templateLayout).getFooterBackgroundColorFromStyle());
+          } else {
+            // Switch style to glif expressive common button.
+            if (primaryButtonView instanceof MaterialButton) {
+              ((MaterialButton) primaryButtonView).setIcon(null);
+              primaryButtonView.setText(nextText);
+              footerBarMixin.setButtonWidthForExpressiveStyle(/* isDownButton= */ false);
+              // Screen no need to scroll, sets the secondary button as visible if it exists.
+              if (secondaryButtonView != null) {
+                secondaryButtonView.setVisibility(View.VISIBLE);
+              }
+              footerContainer.setBackgroundColor(Color.TRANSPARENT);
+            } else {
+              Log.i(LOG_TAG, "Cannot clean up icon for the button. Skipping set text.");
+            }
           }
         });
+    primaryButtonView.setVisibility(View.VISIBLE);
     requireScroll();
   }
 
+  private void generateGlifExpressiveDownButton(
+      Context context, Button button, FooterBarMixin footerBarMixin) {
+    Drawable icon = context.getResources().getDrawable(R.drawable.sud_ic_down_arrow);
+    if (button instanceof MaterialButton) {
+      // Remove the text and set down arrow icon to the button.
+      button.setText("");
+      ((MaterialButton) button).setIcon(icon);
+      ((MaterialButton) button).setIconGravity(MaterialButton.ICON_GRAVITY_TEXT_START);
+      ((MaterialButton) button).setIconPadding(0);
+      footerBarMixin.setButtonWidthForExpressiveStyle(/* isDownButton= */ true);
+    } else {
+      Log.i(LOG_TAG, "Cannot set icon for the button. Skipping clean up text.");
+    }
+  }
+
   /**
    * @return True if scrolling is required. Note that this mixin only requires the user to scroll to
    *     the bottom once - if the user scrolled to the bottom and back-up, scrolling to bottom is
diff --git a/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java b/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java
index a52101d..05db85c 100644
--- a/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java
+++ b/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java
@@ -243,7 +243,8 @@ public final class HeaderAreaStyler {
     Context context = iconImage.getContext();
     int reducedIconHeight = 0;
     int gravity = PartnerStyleHelper.getLayoutGravity(context);
-    if (gravity != 0) {
+    // Skip the partner customization when isGlifExpressiveEnabled is true
+    if (gravity != 0 && !PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
       setGravity(iconImage, gravity);
     }
 
@@ -286,6 +287,57 @@ public final class HeaderAreaStyler {
     }
   }
 
+  /**
+   * Applies the partner style of back button to center align the icon. It needs to check if it
+   * should apply partner resource first, and then adjust the margin top according to the partner
+   * icon size.
+   *
+   * @param buttonContainer The container of the back button
+   */
+  public static void applyPartnerCustomizationBackButtonStyle(FrameLayout buttonContainer) {
+    if (buttonContainer == null) {
+      return;
+    }
+
+    Context context = buttonContainer.getContext();
+    int heightDifference = 0;
+
+    // Calculate the difference of icon height & button height
+    ViewGroup.LayoutParams lpButtonContainer = buttonContainer.getLayoutParams();
+    int backButtonHeight =
+        (int) context.getResources().getDimension(R.dimen.sud_glif_expressive_back_button_height);
+    int iconHeight = getPartnerConfigDimension(context, PartnerConfig.CONFIG_ICON_SIZE, 0);
+    if (iconHeight > backButtonHeight) {
+      heightDifference = iconHeight - backButtonHeight;
+    }
+
+    // Adjust margin top of button container to vertically center align the icon
+      ViewGroup.MarginLayoutParams mlp = (ViewGroup.MarginLayoutParams) lpButtonContainer;
+      // The default topMargin should align with the icon margin top
+      int topMargin =
+          getPartnerConfigDimension(context, PartnerConfig.CONFIG_ICON_MARGIN_TOP, mlp.topMargin);
+    int adjustedTopMargin = topMargin;
+    if (heightDifference != 0) {
+      adjustedTopMargin = topMargin + heightDifference / 2;
+    }
+
+    if (adjustedTopMargin != mlp.topMargin) {
+      FrameLayout.LayoutParams params =
+          new FrameLayout.LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
+      params.setMargins(mlp.leftMargin, adjustedTopMargin, mlp.rightMargin, mlp.bottomMargin);
+      buttonContainer.setLayoutParams(params);
+    }
+  }
+
+  private static int getPartnerConfigDimension(
+      Context context, PartnerConfig config, int defaultValue) {
+    if (PartnerConfigHelper.get(context).isPartnerConfigAvailable(config)) {
+      return (int) PartnerConfigHelper.get(context).getDimension(context, config);
+    }
+
+    return defaultValue;
+  }
+
   private static void checkImageType(ImageView imageView) {
     ViewTreeObserver vto = imageView.getViewTreeObserver();
     vto.addOnPreDrawListener(
diff --git a/main/src/com/google/android/setupdesign/util/PartnerStyleHelper.java b/main/src/com/google/android/setupdesign/util/PartnerStyleHelper.java
index fb4466a..a23fb15 100644
--- a/main/src/com/google/android/setupdesign/util/PartnerStyleHelper.java
+++ b/main/src/com/google/android/setupdesign/util/PartnerStyleHelper.java
@@ -167,35 +167,22 @@ public final class PartnerStyleHelper {
     if (view == null) {
       return false;
     }
-    return getDynamicColorAttributeFromTheme(view.getContext());
+    return getDynamicColorPatnerConfig(view.getContext());
   }
 
-  static boolean getDynamicColorAttributeFromTheme(Context context) {
+  static boolean getDynamicColorPatnerConfig(Context context) {
     try {
       Activity activity = PartnerCustomizationLayout.lookupActivityFromContext(context);
       TemplateLayout layout = findLayoutFromActivity(activity);
       if (layout instanceof GlifLayout) {
         return ((GlifLayout) layout).shouldApplyDynamicColor();
       }
+      return PartnerConfigHelper.isSetupWizardFullDynamicColorEnabled(activity);
     } catch (IllegalArgumentException | ClassCastException ex) {
       // fall through
     }
 
-    // try best to get dynamic color settings from attr
-    TypedArray a =
-        context.obtainStyledAttributes(
-            new int[] {com.google.android.setupcompat.R.attr.sucFullDynamicColor});
-    boolean useDynamicColorTheme =
-        a.hasValue(
-            com.google
-                .android
-                .setupcompat
-                .R
-                .styleable
-                .SucPartnerCustomizationLayout_sucFullDynamicColor);
-    a.recycle();
-
-    return useDynamicColorTheme;
+    return false;
   }
 
   private static TemplateLayout findLayoutFromActivity(Activity activity) {
diff --git a/main/src/com/google/android/setupdesign/util/ThemeHelper.java b/main/src/com/google/android/setupdesign/util/ThemeHelper.java
index cdc6f37..cb541cd 100644
--- a/main/src/com/google/android/setupdesign/util/ThemeHelper.java
+++ b/main/src/com/google/android/setupdesign/util/ThemeHelper.java
@@ -84,6 +84,18 @@ public final class ThemeHelper {
    */
   public static final String THEME_GLIF_V4_LIGHT = "glif_v4_light";
 
+  /**
+   * Passed in a setup wizard intent as {@link WizardManagerHelper#EXTRA_THEME}. This is the dark
+   * variant of the theme used in setup wizard for Android W.
+   */
+  public static final String THEME_GLIF_EXPRESSIVE = "glif_expressive";
+
+  /**
+   * Passed in a setup wizard intent as {@link WizardManagerHelper#EXTRA_THEME}. This is the default
+   * theme used in setup wizard for Android W.
+   */
+  public static final String THEME_GLIF_EXPRESSIVE_LIGHT = "glif_expressive_light";
+
   public static final String THEME_HOLO = "holo";
   public static final String THEME_HOLO_LIGHT = "holo_light";
   public static final String THEME_MATERIAL = "material";
@@ -118,14 +130,16 @@ public final class ThemeHelper {
         || THEME_GLIF_LIGHT.equals(theme)
         || THEME_GLIF_V2_LIGHT.equals(theme)
         || THEME_GLIF_V3_LIGHT.equals(theme)
-        || THEME_GLIF_V4_LIGHT.equals(theme)) {
+        || THEME_GLIF_V4_LIGHT.equals(theme)
+        || THEME_GLIF_EXPRESSIVE_LIGHT.equals(theme)) {
       return true;
     } else if (THEME_HOLO.equals(theme)
         || THEME_MATERIAL.equals(theme)
         || THEME_GLIF.equals(theme)
         || THEME_GLIF_V2.equals(theme)
         || THEME_GLIF_V3.equals(theme)
-        || THEME_GLIF_V4.equals(theme)) {
+        || THEME_GLIF_V4.equals(theme)
+        || THEME_GLIF_EXPRESSIVE.equals(theme)) {
       return false;
     } else {
       return def;
@@ -180,6 +194,11 @@ public final class ThemeHelper {
     return PartnerConfigHelper.isSetupWizardDynamicColorEnabled(context);
   }
 
+  /** Returns {@code true} if this {@code context} should applied Glif expressive style. */
+  public static boolean shouldApplyGlifExpressiveStyle(@NonNull Context context) {
+    return PartnerConfigHelper.isGlifExpressiveEnabled(context);
+  }
+
   /**
    * Returns a theme resource id if the {@link com.google.android.setupdesign.GlifLayout} should
    * apply dynamic color.
@@ -190,6 +209,11 @@ public final class ThemeHelper {
   public static int getDynamicColorTheme(@NonNull Context context) {
     @StyleRes int resId = 0;
 
+    // Don't return the dynamic theme when glif expressive is enabled.
+    if (shouldApplyGlifExpressiveStyle(context)) {
+      return resId;
+    }
+
     Activity activity;
     try {
       activity = PartnerCustomizationLayout.lookupActivityFromContext(context);
@@ -243,29 +267,40 @@ public final class ThemeHelper {
   /** Returns a default theme resource id which provides by setup wizard. */
   @StyleRes
   public static int getSuwDefaultTheme(@NonNull Context context) {
+    boolean isDayNightEnabled = ThemeHelper.isSetupWizardDayNightEnabled(context);
     String themeName = PartnerConfigHelper.getSuwDefaultThemeString(context);
     @StyleRes int defaultTheme;
+
+    if (shouldApplyGlifExpressiveStyle(context)) {
+      LOG.atInfo(
+          "Return "
+              + (isDayNightEnabled
+                  ? "SudThemeGlifExpressive_DayNight"
+                  : "SudThemeGlifExpressive_Light"));
+      return isDayNightEnabled
+          ? R.style.SudThemeGlifExpressive_DayNight
+          : R.style.SudThemeGlifExpressive_Light;
+    }
+
+    String themeResToString = "";
     if (VERSION.SDK_INT < VERSION_CODES.O) {
-      defaultTheme =
-          ThemeHelper.isSetupWizardDayNightEnabled(context)
-              ? R.style.SudThemeGlif_DayNight
-              : R.style.SudThemeGlif_Light;
+      defaultTheme = isDayNightEnabled ? R.style.SudThemeGlif_DayNight : R.style.SudThemeGlif_Light;
+      themeResToString = isDayNightEnabled ? "SudThemeGlif_DayNight" : "SudThemeGlif_Light";
     } else if (VERSION.SDK_INT < VERSION_CODES.P) {
       defaultTheme =
-          ThemeHelper.isSetupWizardDayNightEnabled(context)
-              ? R.style.SudThemeGlifV2_DayNight
-              : R.style.SudThemeGlifV2_Light;
+          isDayNightEnabled ? R.style.SudThemeGlifV2_DayNight : R.style.SudThemeGlifV2_Light;
+      themeResToString = isDayNightEnabled ? "SudThemeGlifV2_DayNight" : "SudThemeGlifV2_Light";
     } else if (VERSION.SDK_INT < VERSION_CODES.TIRAMISU) {
       defaultTheme =
-          ThemeHelper.isSetupWizardDayNightEnabled(context)
-              ? R.style.SudThemeGlifV3_DayNight
-              : R.style.SudThemeGlifV3_Light;
+          isDayNightEnabled ? R.style.SudThemeGlifV3_DayNight : R.style.SudThemeGlifV3_Light;
+      themeResToString = isDayNightEnabled ? "SudThemeGlifV3_DayNight" : "SudThemeGlifV3_Light";
     } else {
       defaultTheme =
-          ThemeHelper.isSetupWizardDayNightEnabled(context)
-              ? R.style.SudThemeGlifV4_DayNight
-              : R.style.SudThemeGlifV4_Light;
+          isDayNightEnabled ? R.style.SudThemeGlifV4_DayNight : R.style.SudThemeGlifV4_Light;
+      themeResToString = isDayNightEnabled ? "SudThemeGlifV4_DayNight" : "SudThemeGlifV4_Light";
     }
+    LOG.atInfo("Default theme: " + themeResToString + ", return theme: " + themeName);
+
     return new ThemeResolver.Builder()
         .setDefaultTheme(defaultTheme)
         .setUseDayNight(isSetupWizardDayNightEnabled(context))
@@ -273,6 +308,38 @@ public final class ThemeHelper {
         .resolve(themeName, /* suppressDayNight= */ !isSetupWizardDayNightEnabled(context));
   }
 
+  /** Returns {@code true} if the SUW theme is set. */
+  public static boolean trySetSuwTheme(@NonNull Context context) {
+    @StyleRes int theme = getSuwDefaultTheme(context);
+    Activity activity;
+    try {
+      activity = PartnerCustomizationLayout.lookupActivityFromContext(context);
+    } catch (IllegalArgumentException ex) {
+      LOG.e(Objects.requireNonNull(ex.getMessage()));
+      return false;
+    }
+    // Apply theme
+    if (theme != 0) {
+      activity.setTheme(theme);
+    } else {
+      LOG.w("Error occurred on getting suw default theme.");
+      return false;
+    }
+
+    if (!BuildCompatUtils.isAtLeastS()) {
+      LOG.w("Skip set theme with dynamic color, it is require platform version at least S.");
+      return true;
+    }
+
+    // Don't apply dynamic theme when glif expressive is enabled.
+    if (shouldApplyGlifExpressiveStyle(context)) {
+      LOG.w("Skip set theme with dynamic color, due to glif expressive sytle enabled.");
+      return true;
+    }
+
+    return trySetDynamicColor(context);
+  }
+
   /** Returns {@code true} if the dynamic color is set. */
   public static boolean trySetDynamicColor(@NonNull Context context) {
     if (!BuildCompatUtils.isAtLeastS()) {
@@ -280,6 +347,12 @@ public final class ThemeHelper {
       return false;
     }
 
+    // Don't apply dynamic theme when glif expressive is enabled.
+    if (shouldApplyGlifExpressiveStyle(context)) {
+      LOG.w("Dynamic color theme isn't needed to set in glif expressive theme.");
+      return false;
+    }
+
     if (!shouldApplyDynamicColor(context)) {
       LOG.w("SetupWizard does not support the dynamic color or supporting status unknown.");
       return false;
```

