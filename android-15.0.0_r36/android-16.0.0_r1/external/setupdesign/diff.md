```diff
diff --git a/Android.bp b/Android.bp
index a9aee37..3f97cc6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -36,6 +36,7 @@ android_library {
         "androidx.window_window",
         "com.google.android.material_material",
         "error_prone_annotations",
+        "lottie",
         "setupcompat",
         "setupdesign-strings",
     ],
diff --git a/OWNERS b/OWNERS
index b050f57..c36ae50 100644
--- a/OWNERS
+++ b/OWNERS
@@ -8,3 +8,4 @@ pihuei@google.com
 prochinwang@google.com
 
 cipson@google.com  #{LAST_RESORT_SUGGESTION}
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/exempting_lint_checks.txt b/exempting_lint_checks.txt
index fb01c62..ad83b73 100644
--- a/exempting_lint_checks.txt
+++ b/exempting_lint_checks.txt
@@ -116,3 +116,58 @@ third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupd
 third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/RichTextView.java: NewApi: text = getRichText(getContext(), text);
 third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/StickyHeaderListView.java: CustomViewStyleable: .obtainStyledAttributes(attrs, R.styleable.SudStickyHeaderListView, defStyleAttr, 0);
 third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/StickyHeaderScrollView.java: ObsoleteSdkInt: if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
+third_party/java_src/android_libs/setupdesign/AndroidManifest.xml: ExpiredTargetSdkVersion: <uses-sdk android:minSdkVersion="14" android:targetSdkVersion="30" />
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/GlifLayout.java: CustomViewStyleable: getContext().obtainStyledAttributes(attrs, R.styleable.SudGlifLayout, defStyleAttr, 0);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/GlifLayout.java: NewApi: LayoutStyler.applyPartnerCustomizationExtraPaddingStyle(view);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/GlifLayout.java: NewApi: tryApplyPartnerCustomizationContentPaddingTopStyle(view);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/GlifLayout.java: UseRequiresApi: @TargetApi(Build.VERSION_CODES.S)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/GlifLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/GlifLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.JELLY_BEAN_MR1)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/GlifListLayout.java: NewApi: tryApplyPartnerCustomizationContentPaddingTopStyle(view);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/GlifListLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java: NewApi: tryApplyPartnerCustomizationContentPaddingTopStyle(view);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/SetupWizardLayout.java: CustomViewStyleable: .obtainStyledAttributes(attrs, R.styleable.SudSetupWizardLayout, defStyleAttr, 0);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/SetupWizardLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/SetupWizardListLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java: NewApi: LayoutStyler.applyPartnerCustomizationLayoutPaddingStyle(content);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/items/Item.java: NewApi: ItemStyler.applyPartnerCustomizationItemStyle(view);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/items/Item.java: NewApi: LayoutStyler.applyPartnerCustomizationLayoutPaddingStyle(view);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/items/ItemAdapter.java: UseRequiresApi: @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java: NotifyDataSetChanged: notifyDataSetChanged();
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java: UseRequiresApi: @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java: UseRequiresApi: @TargetApi(VERSION_CODES.Q)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/template/HeaderMixin.java: NewApi: LayoutStyler.applyPartnerCustomizationExtraPaddingStyle(headerAreaView);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/template/IllustrationProgressMixin.java: UseRequiresApi: @TargetApi(VERSION_CODES.ICE_CREAM_SANDWICH)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/transition/TransitionHelper.java: UseRequiresApi: @TargetApi(VERSION_CODES.LOLLIPOP)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/transition/TransitionHelper.java: UseRequiresApi: @TargetApi(VERSION_CODES.M)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/transition/support/TransitionHelper.java: UseRequiresApi: @TargetApi(VERSION_CODES.M)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/util/ItemStyler.java: UseRequiresApi: @TargetApi(VERSION_CODES.JELLY_BEAN_MR1)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/util/LayoutStyler.java: UseRequiresApi: @TargetApi(VERSION_CODES.JELLY_BEAN_MR1)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/util/Partner.java: DiscouragedApi: return resources.getIdentifier(name, defType, packageName);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/util/TextViewPartnerStyler.java: NewApi: ((RichTextView) textView).setSpanTypeface(linkFont);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/CheckableLinearLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/CheckableLinearLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.LOLLIPOP)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/FillContentLayout.java: CustomViewStyleable: context.obtainStyledAttributes(attrs, R.styleable.SudFillContentLayout, defStyleAttr, 0);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/HeaderRecyclerView.java: CustomViewStyleable: .obtainStyledAttributes(attrs, R.styleable.SudHeaderRecyclerView, defStyleAttr, 0);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/HeaderRecyclerView.java: NotifyDataSetChanged: notifyDataSetChanged();
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/IconUniformityAppImageView.java: AnnotateVersionCheck: private static final boolean ON_L_PLUS = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP;
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/IconUniformityAppImageView.java: UseRequiresApi: @TargetApi(23)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/Illustration.java: CustomViewStyleable: getContext().obtainStyledAttributes(attrs, R.styleable.SudIllustration, defStyleAttr, 0);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/Illustration.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/IllustrationVideoView.java: CustomViewStyleable: context.obtainStyledAttributes(attrs, R.styleable.SudIllustrationVideoView);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/IllustrationVideoView.java: UseRequiresApi: @TargetApi(VERSION_CODES.ICE_CREAM_SANDWICH)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/IntrinsicSizeFrameLayout.java: CustomViewStyleable: attrs, R.styleable.SudIntrinsicSizeFrameLayout, defStyleAttr, 0);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/IntrinsicSizeFrameLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/NavigationBar.java: ResourceType: @StyleableRes int colorBackground = 2;
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/NavigationBar.java: ResourceType: @StyleableRes int colorForeground = 1;
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/NavigationBar.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/RichTextView.java: DiscouragedApi: .getIdentifier(textAppearance, "style", context.getPackageName());
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/RichTextView.java: NewApi: text = getRichText(getContext(), text);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/RichTextView.java: UseRequiresApi: @TargetApi(28)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/RichTextView.java: UseRequiresApi: @TargetApi(VERSION_CODES.P)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/StickyHeaderListView.java: CustomViewStyleable: .obtainStyledAttributes(attrs, R.styleable.SudStickyHeaderListView, defStyleAttr, 0);
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/StickyHeaderListView.java: UseRequiresApi: @TargetApi(Build.VERSION_CODES.LOLLIPOP)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/StickyHeaderRecyclerView.java: UseRequiresApi: @TargetApi(Build.VERSION_CODES.LOLLIPOP)
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/StickyHeaderScrollView.java: ObsoleteSdkInt: if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
+third_party/java_src/android_libs/setupdesign/main/src/com/google/android/setupdesign/view/StickyHeaderScrollView.java: UseRequiresApi: @TargetApi(Build.VERSION_CODES.LOLLIPOP)
diff --git a/lottie_animation_view/AndroidManifest.xml b/lottie_animation_view/AndroidManifest.xml
new file mode 100644
index 0000000..1b0b77e
--- /dev/null
+++ b/lottie_animation_view/AndroidManifest.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2020 The Android Open Source Project
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.google.android.setupdesign.lottieloadinglayout">
+
+  <uses-sdk
+      android:minSdkVersion="23"
+      android:targetSdkVersion="34" />
+
+</manifest>
diff --git a/lottie_animation_view/src/com/google/android/setupdesign/view/SudLottieAnimationView.kt b/lottie_animation_view/src/com/google/android/setupdesign/view/SudLottieAnimationView.kt
new file mode 100644
index 0000000..78d676c
--- /dev/null
+++ b/lottie_animation_view/src/com/google/android/setupdesign/view/SudLottieAnimationView.kt
@@ -0,0 +1,123 @@
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
+package com.google.android.setupdesign.view
+
+import android.animation.Animator
+import android.animation.Animator.AnimatorListener
+import android.content.Context
+import android.util.AttributeSet
+import android.view.View
+import androidx.annotation.StringRes
+import androidx.core.view.AccessibilityDelegateCompat
+import androidx.core.view.ViewCompat
+import androidx.core.view.accessibility.AccessibilityNodeInfoCompat
+import androidx.core.view.accessibility.AccessibilityNodeInfoCompat.AccessibilityActionCompat
+import com.airbnb.lottie.LottieAnimationView
+import com.google.android.setupcompat.util.Logger
+
+/** A [LottieAnimationView] that take response to pause and resume animation when user clicks. */
+class SudLottieAnimationView
+@JvmOverloads
+constructor(context: Context, attrs: AttributeSet? = null) :
+  LottieAnimationView(context, attrs),
+  View.OnClickListener,
+  AnimatorListener,
+  Animator.AnimatorPauseListener {
+  var clickListener: OnClickListener? = null
+
+  private val actionInfoAnimatorPlaying =
+    buildAccessibilityAction(R.string.sud_lottie_animation_view_accessibility_action_pause)
+
+  private val actionInfoAnimatorPaused =
+    buildAccessibilityAction(R.string.sud_lottie_animation_view_accessibility_action_resume)
+
+  init {
+    super.setOnClickListener(this)
+    setContentDescription(
+      resources.getString(R.string.sud_lottie_animation_view_accessibility_description)
+    )
+    addAnimatorListener(this)
+    addAnimatorPauseListener(this)
+  }
+
+  private fun buildAccessibilityAction(@StringRes stringId: Int) =
+    AccessibilityActionCompat(
+      AccessibilityNodeInfoCompat.ACTION_CLICK,
+      resources.getString(stringId),
+    )
+
+  override fun setOnClickListener(listener: OnClickListener?) {
+    clickListener = listener
+  }
+
+  private fun setAccessibilityDelegate(
+    accessibilityAction: AccessibilityNodeInfoCompat.AccessibilityActionCompat
+  ) {
+    ViewCompat.setAccessibilityDelegate(
+      this,
+      object : AccessibilityDelegateCompat() {
+        override fun onInitializeAccessibilityNodeInfo(
+          host: View,
+          info: AccessibilityNodeInfoCompat,
+        ) {
+          super.onInitializeAccessibilityNodeInfo(host, info)
+          info.addAction(accessibilityAction)
+        }
+      },
+    )
+  }
+
+  override fun onClick(v: View) {
+    clickListener?.onClick(v)
+    if (isAnimating) {
+      pauseAnimation()
+    } else {
+      resumeAnimation()
+    }
+  }
+
+  override fun onAnimationPause(animation: Animator) {
+    LOG.atInfo("onAnimationPause")
+    setAccessibilityDelegate(actionInfoAnimatorPaused)
+  }
+
+  override fun onAnimationResume(animation: Animator) {
+    LOG.atInfo("onAnimationResume")
+    setAccessibilityDelegate(actionInfoAnimatorPlaying)
+  }
+
+  override fun onAnimationStart(animation: Animator) {
+    LOG.atInfo("onAnimationStart")
+    setAccessibilityDelegate(actionInfoAnimatorPlaying)
+  }
+
+  override fun onAnimationEnd(animation: Animator) {
+    // Do nothing
+  }
+
+  override fun onAnimationCancel(animation: Animator) {
+    // Do nothing
+  }
+
+  override fun onAnimationRepeat(animation: Animator) {
+    // Do nothing
+  }
+
+  private companion object {
+    val LOG = Logger(SudLottieAnimationView::class.java)
+  }
+}
diff --git a/lottie_loading_layout/res/layout-sw600dp-v31/sud_loading_fullscreen_lottie_layout.xml b/lottie_loading_layout/res/layout-sw600dp-v31/sud_loading_fullscreen_lottie_layout.xml
index 0e0af86..0e7bbd3 100644
--- a/lottie_loading_layout/res/layout-sw600dp-v31/sud_loading_fullscreen_lottie_layout.xml
+++ b/lottie_loading_layout/res/layout-sw600dp-v31/sud_loading_fullscreen_lottie_layout.xml
@@ -30,7 +30,7 @@
         android:layout_height="match_parent"
         android:importantForAccessibility="no"
         android:layout_gravity="start|bottom"
-        android:scaleType="fitStart"
+        android:scaleType="centerCrop"
         app:lottie_autoPlay="false"
         app:lottie_loop="true" />
 
diff --git a/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java b/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java
index 4887044..e92b191 100644
--- a/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java
+++ b/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java
@@ -839,19 +839,19 @@ public class GlifLoadingLayout extends GlifLayout {
       this.darkThemeCustomization = darkThemeCustomization;
     }
 
-    PartnerConfig getIllustrationConfig() {
+    public PartnerConfig getIllustrationConfig() {
       return illustrationConfig;
     }
 
-    PartnerConfig getLottieConfig() {
+    public PartnerConfig getLottieConfig() {
       return lottieConfig;
     }
 
-    PartnerConfig getLightThemeCustomization() {
+    public PartnerConfig getLightThemeCustomization() {
       return lightThemeCustomization;
     }
 
-    PartnerConfig getDarkThemeCustomization() {
+    public PartnerConfig getDarkThemeCustomization() {
       return darkThemeCustomization;
     }
   }
diff --git a/main/res/color-night/sud_card_view_icon_color.xml b/main/res/color-night/sud_card_view_icon_color.xml
new file mode 100644
index 0000000..c1df8ce
--- /dev/null
+++ b/main/res/color-night/sud_card_view_icon_color.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2024 The Android Open Source Project
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
+-->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_selected="true" android:color="@color/sud_system_on_primary_container_dark" />
+    <item android:color="@color/sud_system_primary_dark" />
+</selector>
diff --git a/main/res/color-night/sud_card_view_text_color.xml b/main/res/color-night/sud_card_view_text_color.xml
new file mode 100644
index 0000000..110d3da
--- /dev/null
+++ b/main/res/color-night/sud_card_view_text_color.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2024 The Android Open Source Project
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
+-->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_selected="true" android:color="@color/sud_system_on_primary_container_dark" />
+    <item android:color="@color/sud_system_on_surface_dark" />
+</selector>
diff --git a/main/res/color-v31/gm3_dynamic_neutral_variant22.xml b/main/res/color-v31/gm3_dynamic_neutral_variant22.xml
deleted file mode 100644
index 6737f08..0000000
--- a/main/res/color-v31/gm3_dynamic_neutral_variant22.xml
+++ /dev/null
@@ -1,5 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-
-<selector xmlns:android="http://schemas.android.com/apk/res/android">
-  <item android:color="@android:color/system_neutral2_600" android:lStar="22"/>
-</selector>
\ No newline at end of file
diff --git a/main/res/color/sud_card_view_icon_color.xml b/main/res/color/sud_card_view_icon_color.xml
new file mode 100644
index 0000000..e6b3764
--- /dev/null
+++ b/main/res/color/sud_card_view_icon_color.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2024 The Android Open Source Project
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
+-->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_selected="true" android:color="@color/sud_system_on_primary_container_light" />
+    <item android:color="@color/sud_system_primary_light" />
+</selector>
diff --git a/main/res/color/sud_card_view_text_color.xml b/main/res/color/sud_card_view_text_color.xml
new file mode 100644
index 0000000..5926b8f
--- /dev/null
+++ b/main/res/color/sud_card_view_text_color.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2024 The Android Open Source Project
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
+-->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_selected="true" android:color="@color/sud_system_on_primary_container_light" />
+    <item android:color="@color/sud_system_on_surface_light" />
+</selector>
diff --git a/main/res/color/sud_qr_finish_bg_color.xml b/main/res/color/sud_qr_finish_bg_color.xml
new file mode 100644
index 0000000..8fc0cf1
--- /dev/null
+++ b/main/res/color/sud_qr_finish_bg_color.xml
@@ -0,0 +1,20 @@
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?attr/colorSurfaceContainer"
+        android:alpha="0.7" />
+  </selector>
\ No newline at end of file
diff --git a/main/res/drawable-night/sud_card_view_container_background_normal.xml b/main/res/drawable-night/sud_card_view_container_background_normal.xml
new file mode 100644
index 0000000..4925823
--- /dev/null
+++ b/main/res/drawable-night/sud_card_view_container_background_normal.xml
@@ -0,0 +1,22 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2024 The Android Open Source Project
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
+-->
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <solid android:color="@color/sud_system_surface_bright_dark" />
+    <corners android:radius="@dimen/sud_card_view_container_default_radius" />
+ </shape>
diff --git a/main/res/drawable-night/sud_card_view_container_background_selected.xml b/main/res/drawable-night/sud_card_view_container_background_selected.xml
new file mode 100644
index 0000000..c6c535c
--- /dev/null
+++ b/main/res/drawable-night/sud_card_view_container_background_selected.xml
@@ -0,0 +1,22 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2024 The Android Open Source Project
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
+-->
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <solid android:color="@color/sud_system_primary_container_dark" />
+    <corners android:radius="@dimen/sud_card_view_container_selected_radius" />
+ </shape>
diff --git a/main/res/drawable/sud_camera_preview_background.xml b/main/res/drawable/sud_camera_preview_background.xml
new file mode 100644
index 0000000..8290120
--- /dev/null
+++ b/main/res/drawable/sud_camera_preview_background.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools" android:shape="rectangle">
+
+    <corners
+        android:topLeftRadius="@dimen/sud_expressive_camera_preview_corner_radius"
+        android:topRightRadius="@dimen/sud_expressive_camera_preview_corner_radius"
+        android:bottomRightRadius="@dimen/sud_expressive_camera_preview_corner_radius"
+        android:bottomLeftRadius="@dimen/sud_expressive_camera_preview_corner_radius" />
+
+    <!-- Ignore PrivateResource: This should be fixed -->
+    <solid android:color="?attr/colorSecondary" tools:ignore="PrivateResource" />
+
+</shape>
diff --git a/main/res/drawable/sud_card_view_container_background.xml b/main/res/drawable/sud_card_view_container_background.xml
new file mode 100644
index 0000000..ca07e79
--- /dev/null
+++ b/main/res/drawable/sud_card_view_container_background.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2024 The Android Open Source Project
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
+-->
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_selected="true" android:drawable="@drawable/sud_card_view_container_background_selected" />
+    <item android:drawable="@drawable/sud_card_view_container_background_normal" />
+</selector>
diff --git a/main/res/drawable/sud_card_view_container_background_normal.xml b/main/res/drawable/sud_card_view_container_background_normal.xml
new file mode 100644
index 0000000..6ad369f
--- /dev/null
+++ b/main/res/drawable/sud_card_view_container_background_normal.xml
@@ -0,0 +1,22 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2024 The Android Open Source Project
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
+-->
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <solid android:color="@color/sud_system_surface_bright_light" />
+    <corners android:radius="@dimen/sud_card_view_container_default_radius" />
+ </shape>
diff --git a/main/res/drawable/sud_card_view_container_background_selected.xml b/main/res/drawable/sud_card_view_container_background_selected.xml
new file mode 100644
index 0000000..2b179f0
--- /dev/null
+++ b/main/res/drawable/sud_card_view_container_background_selected.xml
@@ -0,0 +1,22 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright (C) 2024 The Android Open Source Project
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
+-->
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <solid android:color="@color/sud_system_primary_container_light" />
+    <corners android:radius="@dimen/sud_card_view_container_selected_radius" />
+ </shape>
diff --git a/main/res/drawable/sud_ic_arrow_back.xml b/main/res/drawable/sud_ic_arrow_back.xml
index f1e1a83..f4e9c7c 100644
--- a/main/res/drawable/sud_ic_arrow_back.xml
+++ b/main/res/drawable/sud_ic_arrow_back.xml
@@ -21,6 +21,6 @@
     android:viewportWidth="24"
     android:viewportHeight="24">
     <path
-        android:fillColor="@color/sud_color_surface_container_highest"
+        android:fillColor="?attr/colorOnSurface"
         android:pathData="M20,11H7.83l5.59,-5.59L12,4l-8,8 8,8 1.41,-1.41L7.83,13H20v-2z" />
 </vector>
\ No newline at end of file
diff --git a/main/res/drawable/sud_ic_check_mark.xml b/main/res/drawable/sud_ic_check_mark.xml
new file mode 100644
index 0000000..54364ae
--- /dev/null
+++ b/main/res/drawable/sud_ic_check_mark.xml
@@ -0,0 +1,24 @@
+<!--
+  Copyright (C) 2024 The Android Open Source Project
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
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="24"
+    android:viewportHeight="24">
+    <path
+        android:fillColor="@android:color/white"
+        android:pathData="M9,16.17L4.83,12l-1.42,1.41L9,19 21,7l-1.41,-1.41z" />
+</vector>
\ No newline at end of file
diff --git a/main/res/drawable/sud_item_background_first_with_ripple.xml b/main/res/drawable/sud_item_background_first_with_ripple.xml
new file mode 100644
index 0000000..fd2f0ec
--- /dev/null
+++ b/main/res/drawable/sud_item_background_first_with_ripple.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<ripple xmlns:android="http://schemas.android.com/apk/res/android"
+    android:color="?android:attr/colorControlHighlight">
+    <item android:id="@android:id/mask">
+        <shape android:shape="rectangle">
+            <solid android:color="@android:color/white" />
+            <corners
+                android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+        </shape>
+    </item>
+
+    <item>
+        <shape android:shape="rectangle">
+            <solid android:color="?attr/sudItemBackgroundColor"/>
+            <corners
+                android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+        </shape>
+    </item>
+</ripple>
\ No newline at end of file
diff --git a/main/res/drawable/sud_item_background_last_with_ripple.xml b/main/res/drawable/sud_item_background_last_with_ripple.xml
new file mode 100644
index 0000000..fd2f0ec
--- /dev/null
+++ b/main/res/drawable/sud_item_background_last_with_ripple.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<ripple xmlns:android="http://schemas.android.com/apk/res/android"
+    android:color="?android:attr/colorControlHighlight">
+    <item android:id="@android:id/mask">
+        <shape android:shape="rectangle">
+            <solid android:color="@android:color/white" />
+            <corners
+                android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+        </shape>
+    </item>
+
+    <item>
+        <shape android:shape="rectangle">
+            <solid android:color="?attr/sudItemBackgroundColor"/>
+            <corners
+                android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+        </shape>
+    </item>
+</ripple>
\ No newline at end of file
diff --git a/main/res/drawable/sud_item_background_middle_with_ripple.xml b/main/res/drawable/sud_item_background_middle_with_ripple.xml
new file mode 100644
index 0000000..fd2f0ec
--- /dev/null
+++ b/main/res/drawable/sud_item_background_middle_with_ripple.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<ripple xmlns:android="http://schemas.android.com/apk/res/android"
+    android:color="?android:attr/colorControlHighlight">
+    <item android:id="@android:id/mask">
+        <shape android:shape="rectangle">
+            <solid android:color="@android:color/white" />
+            <corners
+                android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+        </shape>
+    </item>
+
+    <item>
+        <shape android:shape="rectangle">
+            <solid android:color="?attr/sudItemBackgroundColor"/>
+            <corners
+                android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+                android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+        </shape>
+    </item>
+</ripple>
\ No newline at end of file
diff --git a/main/res/drawable/sud_items_collapse_button_icon.xml b/main/res/drawable/sud_items_collapse_button_icon.xml
new file mode 100644
index 0000000..ff0d6a5
--- /dev/null
+++ b/main/res/drawable/sud_items_collapse_button_icon.xml
@@ -0,0 +1,25 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960">
+  <path
+      android:pathData="M352.33,569.33 L480,441.67l127.67,127.66 47.66,-46.66L480,347.33 304.67,522.67l47.66,46.66ZM480,880q-83,0 -156,-31.5T197,763q-54,-54 -85.5,-127T80,480q0,-83 31.5,-155.67 31.5,-72.66 85.5,-127Q251,143 324,111.5T480,80q83,0 155.67,31.5 72.66,31.5 127,85.83 54.33,54.34 85.83,127Q880,397 880,480q0,83 -31.5,156t-85.83,127q-54.34,54 -127,85.5Q563,880 480,880ZM480,813.33q138.67,0 236,-97 97.33,-97 97.33,-236.33 0,-138.67 -97.33,-236 -97.33,-97.33 -236,-97.33 -139.33,0 -236.33,97.33t-97,236q0,139.33 97,236.33t236.33,97ZM480,480Z"
+      android:fillColor="@color/sud_on_surface_variant"/>
+</vector>
diff --git a/main/res/drawable/sud_items_expand_button_icon.xml b/main/res/drawable/sud_items_expand_button_icon.xml
new file mode 100644
index 0000000..00a46cc
--- /dev/null
+++ b/main/res/drawable/sud_items_expand_button_icon.xml
@@ -0,0 +1,25 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960">
+  <path
+      android:pathData="m480,612.67 l175.33,-175.34 -47.66,-46.66L480,518.33 352.33,390.67l-47.66,46.66L480,612.67ZM480,880q-82.33,0 -155.33,-31.5 -73,-31.5 -127.34,-85.83Q143,708.33 111.5,635.33T80,480q0,-83 31.5,-156t85.83,-127q54.34,-54 127.34,-85.5T480,80q83,0 156,31.5T763,197q54,54 85.5,127T880,480q0,82.33 -31.5,155.33 -31.5,73 -85.5,127.34Q709,817 636,848.5T480,880ZM480,813.33q139.33,0 236.33,-97.33t97,-236q0,-139.33 -97,-236.33t-236.33,-97q-138.67,0 -236,97 -97.33,97 -97.33,236.33 0,138.67 97.33,236 97.33,97.33 236,97.33ZM480,480Z"
+      android:fillColor="@color/sud_on_surface_variant"/>
+</vector>
diff --git a/main/res/drawable/sud_non_actionable_item_background.xml b/main/res/drawable/sud_non_actionable_item_background.xml
new file mode 100644
index 0000000..5bf51ab
--- /dev/null
+++ b/main/res/drawable/sud_non_actionable_item_background.xml
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
+    <solid android:color="?attr/sudNonActionableItemBackgroundColor"/>
+    <corners
+            android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+            android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+            android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+            android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+</shape>
\ No newline at end of file
diff --git a/main/res/drawable/sud_non_actionable_item_background_first.xml b/main/res/drawable/sud_non_actionable_item_background_first.xml
new file mode 100644
index 0000000..142b637
--- /dev/null
+++ b/main/res/drawable/sud_non_actionable_item_background_first.xml
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
+    <solid android:color="?attr/sudNonActionableItemBackgroundColor"/>
+    <corners
+        android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+</shape>
\ No newline at end of file
diff --git a/main/res/drawable/sud_non_actionable_item_background_last.xml b/main/res/drawable/sud_non_actionable_item_background_last.xml
new file mode 100644
index 0000000..74f5ce1
--- /dev/null
+++ b/main/res/drawable/sud_non_actionable_item_background_last.xml
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
+    <solid android:color="?attr/sudNonActionableItemBackgroundColor"/>
+    <corners
+        android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+</shape>
\ No newline at end of file
diff --git a/main/res/drawable/sud_non_actionable_item_background_single.xml b/main/res/drawable/sud_non_actionable_item_background_single.xml
new file mode 100644
index 0000000..142b637
--- /dev/null
+++ b/main/res/drawable/sud_non_actionable_item_background_single.xml
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
+    <solid android:color="?attr/sudNonActionableItemBackgroundColor"/>
+    <corners
+        android:bottomLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:bottomRightRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topLeftRadius="@dimen/sud_glif_expressive_item_corner_radius"
+        android:topRightRadius="@dimen/sud_glif_expressive_item_corner_radius" />
+</shape>
\ No newline at end of file
diff --git a/main/res/drawable/sud_promo_card_icon_background.xml b/main/res/drawable/sud_promo_card_icon_background.xml
new file mode 100644
index 0000000..09da9bf
--- /dev/null
+++ b/main/res/drawable/sud_promo_card_icon_background.xml
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
+    <solid android:color="?attr/sudPromoCardIconBackgroundColor"/>
+    <corners
+            android:bottomLeftRadius="@dimen/sud_glif_expressive_promo_card_icon_corner_radius"
+            android:bottomRightRadius="@dimen/sud_glif_expressive_promo_card_icon_corner_radius"
+            android:topLeftRadius="@dimen/sud_glif_expressive_promo_card_icon_corner_radius"
+            android:topRightRadius="@dimen/sud_glif_expressive_promo_card_icon_corner_radius" />
+</shape>
\ No newline at end of file
diff --git a/main/res/drawable/sud_qr_finish_icon.xml b/main/res/drawable/sud_qr_finish_icon.xml
new file mode 100644
index 0000000..5ede425
--- /dev/null
+++ b/main/res/drawable/sud_qr_finish_icon.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="160dp"
+    android:height="160dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960">
+  <path
+      android:pathData="m378,628 l363,-363q9.27,-9 21.64,-9 12.36,0 21.36,9.05 9,9.06 9,21.5 0,12.45 -9,21.45L399,693q-9,9 -21,9t-21,-9L175,511q-9,-9.07 -8.5,-21.53 0.5,-12.47 9.55,-21.47 9.06,-9 21.5,-9 12.45,0 21.45,9l159,160Z"
+      android:fillColor="?attr/colorSecondary"/>
+</vector>
+
diff --git a/main/res/layout-land-v31/sud_glif_list_template_content.xml b/main/res/layout-land-v31/sud_glif_list_template_content.xml
index 9b0dd5d..92464a3 100644
--- a/main/res/layout-land-v31/sud_glif_list_template_content.xml
+++ b/main/res/layout-land-v31/sud_glif_list_template_content.xml
@@ -65,6 +65,7 @@
                 android:layout_width="match_parent"
                 android:layout_height="0dp"
                 android:layout_weight="1"
+                app:sudShouldApplyAdditionalMargin="true"
                 android:scrollIndicators="?attr/sudScrollIndicators" />
 
         </LinearLayout>
diff --git a/main/res/layout-land-v31/sud_glif_preference_recycler_view.xml b/main/res/layout-land-v31/sud_glif_preference_recycler_view.xml
index c304aef..024abdb 100644
--- a/main/res/layout-land-v31/sud_glif_preference_recycler_view.xml
+++ b/main/res/layout-land-v31/sud_glif_preference_recycler_view.xml
@@ -23,4 +23,5 @@
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:clipChildren="false"
-    android:scrollbars="vertical" />
+    android:scrollbars="vertical"
+    app:sudShouldApplyAdditionalMargin="true" />
diff --git a/main/res/layout-land-v31/sud_glif_recycler_template_content.xml b/main/res/layout-land-v31/sud_glif_recycler_template_content.xml
index a75c068..7180b3d 100644
--- a/main/res/layout-land-v31/sud_glif_recycler_template_content.xml
+++ b/main/res/layout-land-v31/sud_glif_recycler_template_content.xml
@@ -65,6 +65,7 @@
                 android:layout_width="match_parent"
                 android:layout_height="0dp"
                 android:layout_weight="1"
+                app:sudShouldApplyAdditionalMargin="true"
                 android:scrollbars="vertical"
                 android:scrollIndicators="?attr/sudScrollIndicators" />
 
diff --git a/main/res/layout-v23/sud_glif_preference_recycler_view.xml b/main/res/layout-v23/sud_glif_preference_recycler_view.xml
index f4efc6f..daa80da 100644
--- a/main/res/layout-v23/sud_glif_preference_recycler_view.xml
+++ b/main/res/layout-v23/sud_glif_preference_recycler_view.xml
@@ -24,4 +24,5 @@
     android:layout_height="match_parent"
     android:clipChildren="false"
     android:scrollbars="vertical"
+    app:sudShouldApplyAdditionalMargin="true"
     app:sudHeader="@layout/sud_glif_header" />
diff --git a/main/res/layout-v34/sud_glif_list_template_content_two_pane.xml b/main/res/layout-v34/sud_glif_list_template_content_two_pane.xml
index fd14379..e146483 100644
--- a/main/res/layout-v34/sud_glif_list_template_content_two_pane.xml
+++ b/main/res/layout-v34/sud_glif_list_template_content_two_pane.xml
@@ -67,6 +67,7 @@
                 android:layout_width="match_parent"
                 android:layout_height="0dp"
                 android:layout_weight="1"
+                app:sudShouldApplyAdditionalMargin="true"
                 android:scrollIndicators="?attr/sudScrollIndicators" />
 
         </LinearLayout>
diff --git a/main/res/layout-v34/sud_glif_preference_recycler_view_two_pane.xml b/main/res/layout-v34/sud_glif_preference_recycler_view_two_pane.xml
index d81324e..e1d12da 100644
--- a/main/res/layout-v34/sud_glif_preference_recycler_view_two_pane.xml
+++ b/main/res/layout-v34/sud_glif_preference_recycler_view_two_pane.xml
@@ -26,4 +26,5 @@
     android:filterTouchesWhenObscured="true"
     android:scrollIndicators="?attr/sudScrollIndicators"
     android:scrollbars="vertical"
-    app:sudHeader="@layout/sud_glif_header" />
\ No newline at end of file
+    app:sudHeader="@layout/sud_glif_header"
+    app:sudShouldApplyAdditionalMargin="true" />
\ No newline at end of file
diff --git a/main/res/layout-v34/sud_glif_recycler_template_content_two_pane.xml b/main/res/layout-v34/sud_glif_recycler_template_content_two_pane.xml
index ea47dfc..c852ef1 100644
--- a/main/res/layout-v34/sud_glif_recycler_template_content_two_pane.xml
+++ b/main/res/layout-v34/sud_glif_recycler_template_content_two_pane.xml
@@ -68,6 +68,7 @@
                 android:layout_height="0dp"
                 android:layout_weight="1"
                 android:scrollbars="vertical"
+                app:sudShouldApplyAdditionalMargin="true"
                 android:scrollIndicators="?attr/sudScrollIndicators" />
 
         </LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_blank_template_card.xml b/main/res/layout-v35/sud_glif_expressive_blank_template_card.xml
index fa2da7d..3cda3f0 100644
--- a/main/res/layout-v35/sud_glif_expressive_blank_template_card.xml
+++ b/main/res/layout-v35/sud_glif_expressive_blank_template_card.xml
@@ -17,7 +17,7 @@
 
 <!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
      See https://developer.android.com/privacy-and-security/risks/tapjacking -->
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+<com.google.android.setupdesign.view.InsetAdjustmentLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
@@ -50,4 +50,4 @@
         android:layout_weight="1"
         android:visibility="invisible" />
 
-</LinearLayout>
+</com.google.android.setupdesign.view.InsetAdjustmentLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_card.xml b/main/res/layout-v35/sud_glif_expressive_list_template_card.xml
index d22235f..a78047f 100644
--- a/main/res/layout-v35/sud_glif_expressive_list_template_card.xml
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_card.xml
@@ -17,7 +17,7 @@
 
 <!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
      See https://developer.android.com/privacy-and-security/risks/tapjacking -->
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+<com.google.android.setupdesign.view.InsetAdjustmentLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
@@ -50,4 +50,4 @@
         android:layout_weight="1"
         android:visibility="invisible" />
 
-</LinearLayout>
+</com.google.android.setupdesign.view.InsetAdjustmentLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_content.xml b/main/res/layout-v35/sud_glif_expressive_list_template_content.xml
index aba3f4d..c65b9ba 100644
--- a/main/res/layout-v35/sud_glif_expressive_list_template_content.xml
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_content.xml
@@ -46,6 +46,7 @@
             android:layout_height="match_parent"
             android:scrollIndicators="?attr/sudScrollIndicators"
             app:sudHeader="@layout/sud_glif_header"
+            app:sudShouldApplyAdditionalMargin="true"
             tools:ignore="UnusedAttribute" />
 
         <include layout="@layout/sud_glif_floating_back_button" />
diff --git a/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml b/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml
index b49e569..410462a 100644
--- a/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml
+++ b/main/res/layout-v35/sud_glif_expressive_list_template_content_wide.xml
@@ -73,6 +73,7 @@
                 android:layout_width="match_parent"
                 android:layout_height="0dp"
                 android:layout_weight="1"
+                app:sudShouldApplyAdditionalMargin="true"
                 android:scrollIndicators="?attr/sudScrollIndicators" />
 
         </LinearLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_preference_recycler_view.xml b/main/res/layout-v35/sud_glif_expressive_preference_recycler_view.xml
new file mode 100644
index 0000000..eede736
--- /dev/null
+++ b/main/res/layout-v35/sud_glif_expressive_preference_recycler_view.xml
@@ -0,0 +1,28 @@
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
+    app:sudShouldApplyAdditionalMargin="true"
+    app:sudHeader="@layout/sud_glif_header" />
diff --git a/main/res/layout-v35/sud_glif_expressive_preference_template_card.xml b/main/res/layout-v35/sud_glif_expressive_preference_template_card.xml
index db235e9..d2d14ae 100644
--- a/main/res/layout-v35/sud_glif_expressive_preference_template_card.xml
+++ b/main/res/layout-v35/sud_glif_expressive_preference_template_card.xml
@@ -17,7 +17,7 @@
 
 <!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
      See https://developer.android.com/privacy-and-security/risks/tapjacking -->
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+<com.google.android.setupdesign.view.InsetAdjustmentLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
@@ -50,4 +50,4 @@
         android:layout_weight="1"
         android:visibility="invisible" />
 
-</LinearLayout>
+</com.google.android.setupdesign.view.InsetAdjustmentLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml
index 80b4f0b..ccc6800 100644
--- a/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_card.xml
@@ -17,7 +17,7 @@
 
 <!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
      See https://developer.android.com/privacy-and-security/risks/tapjacking -->
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+<com.google.android.setupdesign.view.InsetAdjustmentLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
@@ -50,4 +50,4 @@
         android:layout_weight="1"
         android:visibility="invisible" />
 
-</LinearLayout>
+</com.google.android.setupdesign.view.InsetAdjustmentLayout>
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml
index 9067b52..5a8efa1 100644
--- a/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_content.xml
@@ -47,6 +47,7 @@
             android:scrollbars="vertical"
             android:scrollIndicators="?attr/sudScrollIndicators"
             app:sudHeader="@layout/sud_glif_header"
+            app:sudShouldApplyAdditionalMargin="true"
             tools:ignore="UnusedAttribute" />
 
         <include layout="@layout/sud_glif_floating_back_button" />
diff --git a/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml b/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml
index 64d6a53..b5116bc 100644
--- a/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml
+++ b/main/res/layout-v35/sud_glif_expressive_recycler_template_content_wide.xml
@@ -74,7 +74,8 @@
                 android:layout_height="0dp"
                 android:layout_weight="1"
                 android:scrollbars="vertical"
-                android:scrollIndicators="?attr/sudScrollIndicators" />
+                android:scrollIndicators="?attr/sudScrollIndicators"
+                app:sudShouldApplyAdditionalMargin="true" />
 
         </LinearLayout>
 
diff --git a/main/res/layout-v35/sud_glif_expressive_template_card.xml b/main/res/layout-v35/sud_glif_expressive_template_card.xml
index 24adaa7..d7023ed 100644
--- a/main/res/layout-v35/sud_glif_expressive_template_card.xml
+++ b/main/res/layout-v35/sud_glif_expressive_template_card.xml
@@ -17,7 +17,7 @@
 
 <!-- Please keep filterTouchesWhenObscured=true; it's to prevent tapjacking.
      See https://developer.android.com/privacy-and-security/risks/tapjacking -->
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+<com.google.android.setupdesign.view.InsetAdjustmentLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/suc_layout_status"
     style="@style/SudGlifCardBackground"
     android:layout_width="match_parent"
@@ -50,4 +50,4 @@
         android:layout_weight="1"
         android:visibility="invisible" />
 
-</LinearLayout>
+</com.google.android.setupdesign.view.InsetAdjustmentLayout>
diff --git a/main/res/layout-w600dp-h900dp-v35/sud_glif_expressive_preference_recycler_view.xml b/main/res/layout-w600dp-h900dp-v35/sud_glif_expressive_preference_recycler_view.xml
new file mode 100644
index 0000000..eede736
--- /dev/null
+++ b/main/res/layout-w600dp-h900dp-v35/sud_glif_expressive_preference_recycler_view.xml
@@ -0,0 +1,28 @@
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
+    app:sudShouldApplyAdditionalMargin="true"
+    app:sudHeader="@layout/sud_glif_header" />
diff --git a/main/res/layout-w600dp-v35/sud_glif_expressive_preference_recycler_view.xml b/main/res/layout-w600dp-v35/sud_glif_expressive_preference_recycler_view.xml
new file mode 100644
index 0000000..f0c438b
--- /dev/null
+++ b/main/res/layout-w600dp-v35/sud_glif_expressive_preference_recycler_view.xml
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
diff --git a/main/res/layout-w840dp-v34/sud_glif_list_template_content_two_pane.xml b/main/res/layout-w840dp-v34/sud_glif_list_template_content_two_pane.xml
index a408da2..5df571d 100644
--- a/main/res/layout-w840dp-v34/sud_glif_list_template_content_two_pane.xml
+++ b/main/res/layout-w840dp-v34/sud_glif_list_template_content_two_pane.xml
@@ -67,7 +67,8 @@
                 android:layout_width="match_parent"
                 android:layout_height="0dp"
                 android:layout_weight="1"
-                android:scrollIndicators="?attr/sudScrollIndicators" />
+                android:scrollIndicators="?attr/sudScrollIndicators"
+                app:sudShouldApplyAdditionalMargin="true" />
 
         </LinearLayout>
 
diff --git a/main/res/layout-w840dp-v34/sud_glif_preference_recycler_view_two_pane.xml b/main/res/layout-w840dp-v34/sud_glif_preference_recycler_view_two_pane.xml
index 7804b2b..fbb13c4 100644
--- a/main/res/layout-w840dp-v34/sud_glif_preference_recycler_view_two_pane.xml
+++ b/main/res/layout-w840dp-v34/sud_glif_preference_recycler_view_two_pane.xml
@@ -18,10 +18,12 @@
      See https://developer.android.com/privacy-and-security/risks/tapjacking -->
 <com.google.android.setupdesign.view.HeaderRecyclerView
     xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
     android:id="@+id/sud_recycler_view"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:clipChildren="false"
     android:filterTouchesWhenObscured="true"
     android:scrollIndicators="?attr/sudScrollIndicators"
-    android:scrollbars="vertical" />
\ No newline at end of file
+    android:scrollbars="vertical"
+    app:sudShouldApplyAdditionalMargin="true" />
\ No newline at end of file
diff --git a/main/res/layout-w840dp-v34/sud_glif_recycler_template_content_two_pane.xml b/main/res/layout-w840dp-v34/sud_glif_recycler_template_content_two_pane.xml
index ea47dfc..b5fd855 100644
--- a/main/res/layout-w840dp-v34/sud_glif_recycler_template_content_two_pane.xml
+++ b/main/res/layout-w840dp-v34/sud_glif_recycler_template_content_two_pane.xml
@@ -68,7 +68,8 @@
                 android:layout_height="0dp"
                 android:layout_weight="1"
                 android:scrollbars="vertical"
-                android:scrollIndicators="?attr/sudScrollIndicators" />
+                android:scrollIndicators="?attr/sudScrollIndicators"
+                app:sudShouldApplyAdditionalMargin="true" />
 
         </LinearLayout>
 
diff --git a/main/res/layout/sud_back_button.xml b/main/res/layout/sud_back_button.xml
index 095b22c..9452081 100644
--- a/main/res/layout/sud_back_button.xml
+++ b/main/res/layout/sud_back_button.xml
@@ -26,5 +26,7 @@
       android:contentDescription="@string/sud_back_button_label"
       android:filterTouchesWhenObscured="true"
       android:visibility="gone"
+      app:backgroundTint="?attr/colorSurfaceContainerHigh"
       app:icon="@drawable/sud_ic_arrow_back"
+      app:iconTint="?attr/colorOnSurface"
       tools:visibility="visible" />
diff --git a/main/res/layout/sud_bullet_point_default.xml b/main/res/layout/sud_bullet_point_default.xml
new file mode 100644
index 0000000..1307c10
--- /dev/null
+++ b/main/res/layout/sud_bullet_point_default.xml
@@ -0,0 +1,74 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    style="?attr/sudBulletPointContainerStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:baselineAligned="false"
+    android:orientation="horizontal"
+    android:filterTouchesWhenObscured="true">
+
+    <FrameLayout
+        android:id="@+id/sud_items_icon_container"
+        style="?attr/sudBulletPointIconContainerStyle"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_gravity="top"
+        android:gravity="start">
+
+        <ImageView
+            android:id="@+id/sud_items_icon"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            tools:ignore="ContentDescription" />
+
+    </FrameLayout>
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:layout_gravity="center_vertical"
+        android:gravity="center_vertical"
+        android:orientation="vertical">
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_title"
+            style="?attr/sudBulletPointTitleStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:textAlignment="viewStart"
+            android:visibility="gone"
+            tools:ignore="UnusedAttribute" />
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_summary"
+            style="?attr/sudBulletPointSummaryStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:textAlignment="viewStart"
+            android:visibility="gone"
+            tools:ignore="UnusedAttribute" />
+
+    </LinearLayout>
+
+</LinearLayout>
diff --git a/main/res/layout/sud_card_view_default.xml b/main/res/layout/sud_card_view_default.xml
new file mode 100644
index 0000000..2500a57
--- /dev/null
+++ b/main/res/layout/sud_card_view_default.xml
@@ -0,0 +1,62 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:id="@+id/sud_card_view_default"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    style="?attr/sudCardContainerStyle"
+    android:filterTouchesWhenObscured="true"
+    android:orientation="vertical">
+
+    <FrameLayout
+        android:id="@+id/sud_items_icon_container"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        style="?attr/sudCardIconContainerStyle"
+        android:duplicateParentState="true">
+
+        <ImageView
+            android:id="@+id/sud_items_icon"
+            style="?attr/sudCardIconStyle"
+            android:layout_gravity="center"
+            android:duplicateParentState="true"
+            tools:ignore="ContentDescription" />
+
+    </FrameLayout>
+
+    <com.google.android.setupdesign.view.WrapTextView
+        android:id="@+id/sud_items_title"
+        style="?attr/sudCardTitleStyle"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:breakStrategy="high_quality"
+        android:duplicateParentState="true"
+        android:ellipsize="end"
+        android:hyphenationFrequency="none"
+        android:minLines="2"
+        android:textAlignment="center"
+        tools:ignore="UnusedAttribute" />
+
+    <TextView
+        android:id="@+id/sud_items_summary"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:visibility="gone" />
+
+</LinearLayout>
diff --git a/main/res/layout/sud_glif_list_embedded_template_content.xml b/main/res/layout/sud_glif_list_embedded_template_content.xml
index 4644c80..611be22 100644
--- a/main/res/layout/sud_glif_list_embedded_template_content.xml
+++ b/main/res/layout/sud_glif_list_embedded_template_content.xml
@@ -38,6 +38,7 @@
         android:layout_weight="1"
         android:scrollIndicators="?attr/sudScrollIndicators"
         app:sudHeader="@layout/sud_glif_header"
+        app:sudShouldApplyAdditionalMargin="true"
         tools:ignore="UnusedAttribute" />
 
     <ViewStub
diff --git a/main/res/layout/sud_glif_list_template_content.xml b/main/res/layout/sud_glif_list_template_content.xml
index 09c56d2..75013fb 100644
--- a/main/res/layout/sud_glif_list_template_content.xml
+++ b/main/res/layout/sud_glif_list_template_content.xml
@@ -38,6 +38,7 @@
         android:layout_weight="1"
         android:scrollIndicators="?attr/sudScrollIndicators"
         app:sudHeader="@layout/sud_glif_header"
+        app:sudShouldApplyAdditionalMargin="true"
         tools:ignore="UnusedAttribute" />
 
     <ViewStub
diff --git a/main/res/layout/sud_glif_preference_recycler_view.xml b/main/res/layout/sud_glif_preference_recycler_view.xml
index e973e04..695acd4 100644
--- a/main/res/layout/sud_glif_preference_recycler_view.xml
+++ b/main/res/layout/sud_glif_preference_recycler_view.xml
@@ -23,4 +23,5 @@
     android:layout_height="match_parent"
     android:clipChildren="false"
     android:scrollbars="vertical"
+    app:sudShouldApplyAdditionalMargin="true"
     app:sudHeader="@layout/sud_glif_header" />
diff --git a/main/res/layout/sud_glif_recycler_embedded_template_content.xml b/main/res/layout/sud_glif_recycler_embedded_template_content.xml
index dafd3c8..7ef5016 100644
--- a/main/res/layout/sud_glif_recycler_embedded_template_content.xml
+++ b/main/res/layout/sud_glif_recycler_embedded_template_content.xml
@@ -39,6 +39,7 @@
         android:scrollbars="vertical"
         android:scrollIndicators="?attr/sudScrollIndicators"
         app:sudHeader="@layout/sud_glif_header"
+        app:sudShouldApplyAdditionalMargin="true"
         tools:ignore="UnusedAttribute" />
 
     <ViewStub
diff --git a/main/res/layout/sud_glif_recycler_template_content.xml b/main/res/layout/sud_glif_recycler_template_content.xml
index c2cccf0..4476690 100644
--- a/main/res/layout/sud_glif_recycler_template_content.xml
+++ b/main/res/layout/sud_glif_recycler_template_content.xml
@@ -39,6 +39,7 @@
         android:scrollbars="vertical"
         android:scrollIndicators="?attr/sudScrollIndicators"
         app:sudHeader="@layout/sud_glif_header"
+        app:sudShouldApplyAdditionalMargin="true"
         tools:ignore="UnusedAttribute" />
 
     <ViewStub
diff --git a/main/res/layout/sud_illustration_item.xml b/main/res/layout/sud_illustration_item.xml
new file mode 100644
index 0000000..08805ca
--- /dev/null
+++ b/main/res/layout/sud_illustration_item.xml
@@ -0,0 +1,17 @@
+<?xml version="1.0" encoding="utf-8"?>
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    style="?attr/sudIllustrationItemContainerStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:filterTouchesWhenObscured="true">
+
+  <ImageView
+      android:id="@+id/sud_item_illustration"
+      android:layout_width="wrap_content"
+      android:layout_height="wrap_content"
+      style="?attr/sudIllustrationItemStyle"
+      android:adjustViewBounds="true"
+      tools:ignore="ContentDescription" />
+
+</LinearLayout>
\ No newline at end of file
diff --git a/main/res/layout/sud_info_footer_default.xml b/main/res/layout/sud_info_footer_default.xml
new file mode 100644
index 0000000..66f4bff
--- /dev/null
+++ b/main/res/layout/sud_info_footer_default.xml
@@ -0,0 +1,70 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:orientation="vertical"
+    android:filterTouchesWhenObscured="true">
+
+    <LinearLayout
+        xmlns:tools="http://schemas.android.com/tools"
+        android:id="@+id/sud_info_footer_container"
+        style="?attr/sudInfoFooterContainerStyle"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_alignParentBottom="true"
+        android:baselineAligned="false">
+
+        <FrameLayout
+            android:id="@+id/sud_items_icon_container"
+            style="?attr/sudInfoFooterIconContainerStyle"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_gravity="top"
+            android:gravity="start">
+
+            <ImageView
+                android:id="@+id/sud_info_footer_icon"
+                style="?attr/sudInfoFooterIconStyle"
+                android:visibility="gone"
+                tools:ignore="ContentDescription" />
+
+        </FrameLayout>
+
+        <LinearLayout
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:layout_weight="1"
+            android:layout_gravity="center_vertical"
+            android:gravity="center_vertical"
+            android:orientation="vertical">
+
+            <com.google.android.setupdesign.view.RichTextView
+                android:id="@+id/sud_info_footer_title"
+                style="?attr/sudInfoFooterTitleStyle"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:gravity="start"
+                android:textAlignment="viewStart"
+                android:visibility="gone"
+                tools:ignore="UnusedAttribute" />
+
+        </LinearLayout>
+
+    </LinearLayout>
+
+</RelativeLayout>
diff --git a/main/res/layout/sud_items_button_bar.xml b/main/res/layout/sud_items_button_bar.xml
index 8536338..5fadc89 100644
--- a/main/res/layout/sud_items_button_bar.xml
+++ b/main/res/layout/sud_items_button_bar.xml
@@ -16,7 +16,7 @@
 -->
 
 <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
-    style="@style/SudItemContainer"
+    style="?attr/sudItemContainerStyle"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:clipToPadding="false"
diff --git a/main/res/layout/sud_items_check_box.xml b/main/res/layout/sud_items_check_box.xml
new file mode 100644
index 0000000..2272dfd
--- /dev/null
+++ b/main/res/layout/sud_items_check_box.xml
@@ -0,0 +1,78 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    style="?attr/sudItemContainerStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:baselineAligned="false"
+    android:orientation="horizontal"
+    android:filterTouchesWhenObscured="true">
+
+    <FrameLayout
+        android:id="@+id/sud_items_icon_container"
+        style="?attr/sudItemIconContainerStyle"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_vertical"
+        android:gravity="start">
+
+        <ImageView
+            android:id="@+id/sud_items_icon"
+            style="?attr/sudItemIconStyle"
+            android:layout_height="wrap_content"
+            tools:ignore="ContentDescription" />
+
+    </FrameLayout>
+
+    <LinearLayout
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:layout_gravity="center_vertical"
+        android:gravity="center_vertical"
+        android:orientation="vertical">
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_title"
+            style="?attr/sudItemTitleStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:labelFor="@+id/sud_items_check_box"
+            android:textAlignment="viewStart"
+            tools:ignore="UnusedAttribute" />
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_summary"
+            style="?attr/sudItemSummaryStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:textAlignment="viewStart"
+            android:visibility="gone"
+            tools:ignore="UnusedAttribute" />
+
+    </LinearLayout>
+
+    <CheckBox
+        android:id="@+id/sud_items_check_box"
+        android:layout_width="wrap_content"
+        android:layout_height="match_parent"
+        android:layout_gravity="center_vertical" />
+
+</LinearLayout>
diff --git a/main/res/layout/sud_items_default.xml b/main/res/layout/sud_items_default.xml
index 11f89fa..7c9ca83 100644
--- a/main/res/layout/sud_items_default.xml
+++ b/main/res/layout/sud_items_default.xml
@@ -32,7 +32,7 @@
 
         <ImageView
             android:id="@+id/sud_items_icon"
-            android:layout_width="wrap_content"
+            style="?attr/sudItemIconStyle"
             android:layout_height="wrap_content"
             tools:ignore="ContentDescription" />
 
diff --git a/main/res/layout/sud_items_expandable.xml b/main/res/layout/sud_items_expandable.xml
new file mode 100644
index 0000000..defe8e7
--- /dev/null
+++ b/main/res/layout/sud_items_expandable.xml
@@ -0,0 +1,93 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:id="@+id/sud_items_expandable_content"
+    style="?attr/sudItemContainerStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:baselineAligned="false"
+    android:orientation="vertical"
+    android:filterTouchesWhenObscured="true">
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:baselineAligned="false"
+        android:orientation="horizontal">
+
+        <FrameLayout
+            android:id="@+id/sud_items_icon_container"
+            style="?attr/sudItemIconContainerStyle"
+            android:layout_height="wrap_content"
+            android:layout_gravity="center_vertical"
+            android:gravity="start">
+
+            <ImageView
+                android:id="@+id/sud_items_icon"
+                style="?attr/sudItemIconStyle"
+                android:layout_height="wrap_content"
+                tools:ignore="ContentDescription" />
+
+        </FrameLayout>
+
+        <LinearLayout
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_weight="1"
+            android:layout_gravity="center_vertical"
+            android:gravity="center_vertical"
+            android:orientation="vertical">
+
+            <com.google.android.setupdesign.view.RichTextView
+                android:id="@+id/sud_items_title"
+                style="?attr/sudItemTitleStyle"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:gravity="start"
+                android:textAlignment="viewStart"
+                tools:ignore="UnusedAttribute" />
+
+            <com.google.android.setupdesign.view.RichTextView
+                android:id="@+id/sud_items_summary"
+                style="?attr/sudItemSummaryStyle"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:gravity="start"
+                android:textAlignment="viewStart"
+                android:visibility="gone"
+                tools:ignore="UnusedAttribute" />
+
+        </LinearLayout>
+
+        <ImageView
+          android:id="@+id/sud_items_expand_button"
+          android:layout_width="@dimen/sud_items_expand_button_size"
+          android:layout_height="@dimen/sud_items_expand_button_size"
+          android:layout_gravity="center_vertical"
+          android:scaleType="center"
+          android:src="@drawable/sud_items_expand_button_icon" />
+
+    </LinearLayout>
+
+    <FrameLayout
+        android:id="@+id/sud_items_expandable_content_container"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:visibility="gone" />
+
+</LinearLayout>
\ No newline at end of file
diff --git a/main/res/layout/sud_items_expandable_switch_expressive.xml b/main/res/layout/sud_items_expandable_switch_expressive.xml
new file mode 100644
index 0000000..78b217a
--- /dev/null
+++ b/main/res/layout/sud_items_expandable_switch_expressive.xml
@@ -0,0 +1,101 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    style="?attr/sudItemContainerStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="vertical"
+    android:filterTouchesWhenObscured="true">
+
+    <RelativeLayout
+        android:id="@+id/sud_items_expandable_switch_content"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:baselineAligned="false"
+        android:duplicateParentState="true"
+        android:orientation="horizontal">
+
+        <FrameLayout
+            android:id="@+id/sud_items_icon_container"
+            style="?attr/sudItemIconContainerStyle"
+            android:layout_centerVertical="true"
+            android:layout_height="wrap_content">
+
+            <ImageView
+                android:id="@+id/sud_items_icon"
+                style="?attr/sudItemIconStyle"
+                android:layout_height="wrap_content"
+                tools:ignore="ContentDescription" />
+        </FrameLayout>
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_title"
+            style="?attr/sudItemTitleStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:layout_centerVertical="true"
+            android:layout_toEndOf="@id/sud_items_icon_container"
+            android:layout_toStartOf="@id/sud_items_switch"
+            android:duplicateParentState="true"
+            android:gravity="start"
+            android:labelFor="@+id/sud_items_switch"
+            android:textAlignment="viewStart"
+            tools:ignore="UnusedAttribute" />
+
+        <androidx.appcompat.widget.SwitchCompat
+            android:id="@+id/sud_items_switch"
+            style="@style/SudExpressiveSwitchBarStyle"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_alignParentEnd="true"
+            android:layout_centerVertical="true"
+            android:layout_gravity="center_vertical|end"
+            android:paddingEnd="0dp" />
+
+    </RelativeLayout>
+
+    <com.google.android.setupdesign.view.RichTextView
+        android:id="@+id/sud_items_summary"
+        style="?attr/sudItemSummaryStyle"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:duplicateParentState="true"
+        android:gravity="start"
+        android:layout_weight="1"
+        android:layout_marginTop="12dp"
+        android:layout_marginBottom="0dp"
+        android:textAlignment="viewStart"
+        android:visibility="gone"
+        android:textColor="?android:attr/textColorPrimary"
+        tools:ignore="UnusedAttribute" />
+
+    <com.google.android.setupdesign.view.RichTextView
+        android:id="@+id/sud_items_more_info"
+        style="?attr/sudItemSummaryStyle"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:gravity="start"
+        android:layout_weight="1"
+        android:layout_marginTop="16dp"
+        android:layout_marginBottom="0dp"
+        android:text="@string/sud_more_info"
+        android:textColor="?attr/colorPrimary"
+        android:textAlignment="viewStart" />
+
+</LinearLayout>
diff --git a/main/res/layout/sud_items_radio_button.xml b/main/res/layout/sud_items_radio_button.xml
new file mode 100644
index 0000000..9a25c91
--- /dev/null
+++ b/main/res/layout/sud_items_radio_button.xml
@@ -0,0 +1,78 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    style="?attr/sudItemContainerStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:baselineAligned="false"
+    android:orientation="horizontal"
+    android:filterTouchesWhenObscured="true">
+
+    <com.google.android.material.radiobutton.MaterialRadioButton
+        android:id="@+id/sud_items_radio_button"
+        android:layout_width="wrap_content"
+        android:layout_height="match_parent"
+        android:layout_gravity="center_vertical" />
+
+    <FrameLayout
+        android:id="@+id/sud_items_icon_container"
+        style="?attr/sudItemIconContainerStyle"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_vertical"
+        android:visibility="gone"
+        android:gravity="start">
+
+        <ImageView
+            android:id="@+id/sud_items_icon"
+            style="?attr/sudItemIconStyle"
+            android:layout_height="wrap_content"
+            tools:ignore="ContentDescription" />
+
+    </FrameLayout>
+
+    <LinearLayout
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:layout_gravity="center_vertical"
+        android:gravity="center_vertical"
+        android:orientation="vertical">
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_title"
+            style="?attr/sudItemTitleStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:labelFor="@+id/sud_items_radio_button"
+            android:textAlignment="viewStart"
+            tools:ignore="UnusedAttribute" />
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_summary"
+            style="?attr/sudItemSummaryStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:textAlignment="viewStart"
+            android:visibility="gone"
+            tools:ignore="UnusedAttribute" />
+
+    </LinearLayout>
+</LinearLayout>
\ No newline at end of file
diff --git a/main/res/layout/sud_items_section_header.xml b/main/res/layout/sud_items_section_header.xml
new file mode 100644
index 0000000..477cbfa
--- /dev/null
+++ b/main/res/layout/sud_items_section_header.xml
@@ -0,0 +1,57 @@
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    style="?attr/sudSectionItemContainerStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:baselineAligned="false"
+    android:minHeight="0dp"
+    android:orientation="horizontal"
+    android:filterTouchesWhenObscured="true">
+
+    <!-- unused icon container, which just make the adapter get work on this well-->
+    <FrameLayout
+        android:id="@+id/sud_items_icon_container"
+        android:layout_width="@dimen/sud_items_icon_container_width"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_vertical"
+        android:gravity="start">
+
+        <ImageView
+            android:id="@+id/sud_items_icon"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            tools:ignore="ContentDescription" />
+
+    </FrameLayout>
+
+    <LinearLayout
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:gravity="center_vertical"
+        android:orientation="vertical">
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_title"
+            style="?attr/sudSectionItemTitleStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:textAlignment="viewStart"
+            tools:ignore="UnusedAttribute" />
+
+        <!-- unused text view, which just make the adapter get work on this well-->
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_summary"
+            style="@style/SudItemSummary"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/sud_items_padding_bottom_extra"
+            android:gravity="start"
+            android:textAlignment="viewStart"
+            android:visibility="gone"
+            tools:ignore="UnusedAttribute" />
+
+    </LinearLayout>
+
+</LinearLayout>
diff --git a/main/res/layout/sud_lottie_illustration_item.xml b/main/res/layout/sud_lottie_illustration_item.xml
new file mode 100644
index 0000000..f37aa90
--- /dev/null
+++ b/main/res/layout/sud_lottie_illustration_item.xml
@@ -0,0 +1,17 @@
+<?xml version="1.0" encoding="utf-8"?>
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    style="?attr/sudIllustrationItemContainerStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:filterTouchesWhenObscured="true">
+
+  <com.airbnb.lottie.LottieAnimationView
+      android:id="@+id/sud_item_lottie_illustration"
+      android:layout_width="wrap_content"
+      android:layout_height="wrap_content"
+      style="?attr/sudIllustrationItemStyle"
+      android:adjustViewBounds="true"
+      tools:ignore="ContentDescription" />
+
+</LinearLayout>
\ No newline at end of file
diff --git a/main/res/layout/sud_non_actionable_items_default.xml b/main/res/layout/sud_non_actionable_items_default.xml
new file mode 100644
index 0000000..6303d3e
--- /dev/null
+++ b/main/res/layout/sud_non_actionable_items_default.xml
@@ -0,0 +1,71 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2015 The Android Open Source Project
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    style="?attr/sudNonActionableItemContainerStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:baselineAligned="false"
+    android:orientation="horizontal"
+    android:filterTouchesWhenObscured="true">
+
+    <FrameLayout
+        android:id="@+id/sud_items_icon_container"
+        style="?attr/sudItemIconContainerStyle"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_vertical"
+        android:gravity="start">
+
+        <ImageView
+            android:id="@+id/sud_items_icon"
+            style="?attr/sudItemIconStyle"
+            android:layout_height="wrap_content"
+            tools:ignore="ContentDescription" />
+
+    </FrameLayout>
+
+    <LinearLayout
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:layout_gravity="center_vertical"
+        android:gravity="center_vertical"
+        android:orientation="vertical">
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_title"
+            style="?attr/sudItemTitleStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:textAlignment="viewStart"
+            tools:ignore="UnusedAttribute" />
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_summary"
+            style="?attr/sudItemSummaryStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:textAlignment="viewStart"
+            android:visibility="gone"
+            tools:ignore="UnusedAttribute" />
+
+    </LinearLayout>
+
+</LinearLayout>
diff --git a/main/res/layout/sud_promo_card_default.xml b/main/res/layout/sud_promo_card_default.xml
new file mode 100644
index 0000000..2c9649c
--- /dev/null
+++ b/main/res/layout/sud_promo_card_default.xml
@@ -0,0 +1,74 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+    Copyright (C) 2024 The Android Open Source Project
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    style="?attr/sudPromoItemContainerStyle"
+    android:id="@+id/sud_promo_card_container"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:baselineAligned="false"
+    android:orientation="horizontal"
+    android:filterTouchesWhenObscured="true">
+
+    <FrameLayout
+        android:id="@+id/sud_items_icon_container"
+        style="?attr/sudPromoItemIconContainerStyle"
+        android:layout_height="wrap_content"
+        android:layout_width="wrap_content"
+        android:layout_gravity="center_vertical"
+        android:gravity="start">
+
+        <ImageView
+            android:id="@+id/sud_items_icon"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            tools:ignore="ContentDescription" />
+
+    </FrameLayout>
+
+    <LinearLayout
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:layout_gravity="center_vertical"
+        android:gravity="center_vertical"
+        android:orientation="vertical">
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_title"
+            style="?attr/sudPromoItemTitleStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:textAlignment="viewStart"
+            android:visibility="gone"
+            tools:ignore="UnusedAttribute" />
+
+        <com.google.android.setupdesign.view.RichTextView
+            android:id="@+id/sud_items_summary"
+            style="?attr/sudPromoItemSummaryStyle"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="start"
+            android:textAlignment="viewStart"
+            android:visibility="gone"
+            tools:ignore="UnusedAttribute" />
+
+    </LinearLayout>
+
+</LinearLayout>
diff --git a/main/res/values-h480dp/dimens.xml b/main/res/values-h480dp/dimens.xml
new file mode 100644
index 0000000..61a5992
--- /dev/null
+++ b/main/res/values-h480dp/dimens.xml
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
+
+    <!-- Header layout expressive -->
+    <dimen name="sud_glif_expressive_header_title_size">36sp</dimen>
+    <dimen name="sud_glif_expressive_header_title_line_height">44sp</dimen>
+
+</resources>
diff --git a/main/res/values-night-v31/colors.xml b/main/res/values-night-v31/colors.xml
index 1fa9f19..2c4c46b 100644
--- a/main/res/values-night-v31/colors.xml
+++ b/main/res/values-night-v31/colors.xml
@@ -37,10 +37,6 @@
   <color name="sud_color_surface_container_highest">@color/m3_ref_palette_dynamic_neutral_variant22</color>
 
   <!-- Glif expressive colors -->
-  <color name="sud_glif_expressive_footer_bar_bg_color">@color/gm3_dynamic_neutral_variant22</color>
-  <color name="sud_glif_expressive_footer_button_bg_color">@color/sud_system_accent1_200</color>
-  <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@color/sud_system_accent1_800</color>
-  <color name="sud_glif_expressive_footer_primary_button_disable_text_color">@color/sud_system_neutral2_200</color>
-  <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">@color/sud_system_accent2_100</color>
   <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">@color/sud_system_neutral2_200</color>
+
 </resources>
\ No newline at end of file
diff --git a/main/res/values-night-v34/colors.xml b/main/res/values-night-v34/colors.xml
index a71c4de..8eef200 100644
--- a/main/res/values-night-v34/colors.xml
+++ b/main/res/values-night-v34/colors.xml
@@ -15,30 +15,11 @@
     limitations under the License.
 -->
 
-<resources>
+<resources xmlns:tools="http://schemas.android.com/tools"
+    tools:keep="@color/sud_system_*">
 
   <color name="sud_color_on_surface">@android:color/system_on_surface_dark</color>
   <color name="sud_color_surface_container_highest">@android:color/system_surface_container_highest_dark</color>
 
-  <!-- Surface container color dark -->
-  <color name="sud_system_sc_highest_dark">@android:color/system_surface_container_highest_dark</color>
-  <!-- Primary dark -->
-  <color name="sud_color_primary">@android:color/system_primary_dark</color>
-  <!-- System on primary dark -->
-  <color name="sud_system_on_primary">@android:color/system_on_primary_dark</color>
-  <!-- On surface variant dark -->
-  <color name="sud_on_surface_variant">@android:color/system_on_surface_variant_dark</color>
-  <!-- On secondary container -->
-  <color name="sud_on_secondary_container">@android:color/system_on_secondary_container_dark</color>
-  <!-- Surface container high dark -->
-  <color name="sud_color_surface_container_high">@android:color/system_surface_container_high_dark</color>
 
-  <!-- Glif expressive colors -->
-
-  <color name="sud_glif_expressive_footer_bar_bg_color">@color/sud_system_sc_highest_dark</color>
-  <color name="sud_glif_expressive_footer_button_bg_color">@color/sud_color_primary</color>
-  <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@color/sud_system_on_primary</color>
-  <color name="sud_glif_expressive_footer_primary_button_disable_text_color">@color/sud_on_surface_variant</color>
-  <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">@color/sud_on_secondary_container</color>
-  <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">@color/sud_on_surface_variant</color>
 </resources>
\ No newline at end of file
diff --git a/main/res/values-night/colors.xml b/main/res/values-night/colors.xml
index 8eb370b..3abe9ea 100644
--- a/main/res/values-night/colors.xml
+++ b/main/res/values-night/colors.xml
@@ -28,20 +28,18 @@
 
 
   <color name="sud_uniformity_backdrop_color">#2A2B2E</color>
-  <!-- Default color for the footer button bg (primary80) -->
-  <color name="sud_glif_expressive_footer_button_bg_color">#ffd0bcff</color>
 
 
+  <color name="sud_color_primary">@color/sud_system_primary_dark</color>
+  <color name="sud_system_on_primary">@color/sud_system_on_primary_dark</color>
+  <color name="sud_on_secondary_container">@color/sud_system_on_secondary_container_dark</color>
   <color name="sud_color_on_surface">@color/sud_neutral90</color>
+  <color name="sud_color_surface_container_high">@color/sud_system_surface_container_high_dark</color>
   <color name="sud_color_surface_container_highest">@color/sud_neutral22</color>
+  <color name="sud_on_surface_variant">@color/sud_system_on_surface_variant_dark</color>
 
   <!-- Glif expressive style -->
-  <!-- primary20 -->
-  <color name="sud_glif_expressive_footer_primary_button_enable_text_color">#ff062e6f</color>
-  <!-- neutral_variant80 -->
-  <color name="sud_glif_expressive_footer_primary_button_disable_text_color">#ffcac4d0</color>
-  <!-- secondary90 -->
-  <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">#ffe8def8</color>
   <!-- neutral_variant80 -->
   <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">#ffcac4d0</color>
+
 </resources>
\ No newline at end of file
diff --git a/main/res/values-night/styles.xml b/main/res/values-night/styles.xml
index ca27a7b..d9d581e 100644
--- a/main/res/values-night/styles.xml
+++ b/main/res/values-night/styles.xml
@@ -25,6 +25,8 @@
     <style name="SudThemeGlifV4.DayNight" parent="SudThemeGlifV4" />
     <style name="SudThemeGlifExpressive.DayNight" parent="SudThemeGlifExpressive" />
 
+    <style name="SudMaterialYouAlertDialogTheme.DayNight" parent="SudMaterialYouAlertDialogTheme"/>
+
     <!-- DynamicColor DayNight themes -->
     <style name="SudDynamicColorThemeGlifV3.DayNight" parent="SudDynamicColorThemeGlifV3" />
     <style name="SudFullDynamicColorThemeGlifV3.DayNight" parent="SudFullDynamicColorThemeGlifV3" />
diff --git a/main/res/values-v31/colors.xml b/main/res/values-v31/colors.xml
index 133d274..46dcd5e 100644
--- a/main/res/values-v31/colors.xml
+++ b/main/res/values-v31/colors.xml
@@ -16,7 +16,7 @@
 -->
 
 <resources xmlns:tools="http://schemas.android.com/tools"
-    tools:keep="@color/sud_system_accent*,@color/sud_system_neutral*">
+    tools:keep="@color/sud_system_*">
   <!-- Default color for BC -->
 
   <color name="sud_color_accent_glif_v3_dark">#ff669df6</color>
@@ -139,11 +139,106 @@
   <color name="sud_color_on_surface">@color/sud_system_neutral1_900</color>
   <color name="sud_color_surface_container_highest">@color/sud_system_neutral2_100</color>
 
-  <!-- Glif expressive colors -->
-  <color name="sud_glif_expressive_footer_bar_bg_color">@color/sud_system_neutral2_100</color>
-  <color name="sud_glif_expressive_footer_button_bg_color">@color/sud_system_accent1_600</color>
-  <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@color/sud_system_accent1_0</color>
-  <color name="sud_glif_expressive_footer_primary_button_disable_text_color">@color/sud_system_neutral2_700</color>
-  <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">@color/sud_system_accent2_900</color>
-  <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">@color/sud_system_neutral2_700</color>
+  <!-- Light dynamic system palette -->
+  <color name="sud_system_primary_light">@android:color/system_accent1_600</color>
+  <color name="sud_system_on_primary_light">@android:color/system_accent1_0</color>
+  <color name="sud_system_primary_container_light">@android:color/system_accent1_100</color>
+  <color name="sud_system_on_primary_container_light">@android:color/system_accent1_900</color>
+  <color name="sud_system_primary_inverse_light">@android:color/system_accent1_200</color>
+  <color name="sud_system_primary_fixed_light">@android:color/system_accent1_100</color>
+  <color name="sud_system_primary_fixed_dim_light">@android:color/system_accent1_200</color>
+  <color name="sud_system_on_primary_fixed_light">@android:color/system_accent1_900</color>
+  <color name="sud_system_on_primary_fixed_variant_light">@android:color/system_accent1_700</color>
+
+  <color name="sud_system_secondary_light">@android:color/system_accent2_600</color>
+  <color name="sud_system_on_secondary_light">@android:color/system_accent2_0</color>
+  <color name="sud_system_secondary_container_light">@android:color/system_accent2_100</color>
+  <color name="sud_system_on_secondary_container_light">@android:color/system_accent2_900</color>
+  <color name="sud_system_secondary_fixed_light">@android:color/system_accent2_100</color>
+  <color name="sud_system_secondary_fixed_dim_light">@android:color/system_accent2_200</color>
+  <color name="sud_system_on_secondary_fixed_light">@android:color/system_accent2_900</color>
+  <color name="sud_system_on_secondary_fixed_variant_light">@android:color/system_accent2_700</color>
+
+  <color name="sud_system_tertiary_light">@android:color/system_accent3_600</color>
+  <color name="sud_system_on_tertiary_light">@android:color/system_accent3_0</color>
+  <color name="sud_system_tertiary_container_light">@android:color/system_accent3_100</color>
+  <color name="sud_system_on_tertiary_container_light">@android:color/system_accent3_900</color>
+  <color name="sud_system_tertiary_fixed_light">@android:color/system_accent3_100</color>
+  <color name="sud_system_tertiary_fixed_dim_light">@android:color/system_accent3_200</color>
+  <color name="sud_system_on_tertiary_fixed_light">@android:color/system_accent3_900</color>
+  <color name="sud_system_on_tertiary_fixed_variant_light">@android:color/system_accent3_700</color>
+
+  <color name="sud_system_error_light">@color/m3_ref_palette_error40</color>
+  <color name="sud_system_on_error_light">@android:color/white</color>
+  <color name="sud_system_error_container_light">@color/m3_ref_palette_error90</color>
+  <color name="sud_system_on_error_container_light">@color/m3_ref_palette_error10</color>
+  <color name="sud_system_outline_light">@android:color/system_neutral2_500</color>
+  <color name="sud_system_outline_variant_light">@android:color/system_neutral2_200</color>
+  <color name="sud_system_background_light">@color/m3_ref_palette_dynamic_neutral_variant98</color>
+  <color name="sud_system_on_background_light">@android:color/system_neutral1_900</color>
+  <color name="sud_system_surface_light">@color/m3_ref_palette_dynamic_neutral_variant98</color>
+  <color name="sud_system_on_surface_light">@android:color/system_neutral1_900</color>
+  <color name="sud_system_surface_variant_light">@android:color/system_neutral2_100</color>
+  <color name="sud_system_on_surface_variant_light">@android:color/system_neutral2_700</color>
+  <color name="sud_system_surface_inverse_light">@android:color/system_neutral1_800</color>
+  <color name="sud_system_on_surface_inverse_light">@android:color/system_neutral1_50</color>
+  <color name="sud_system_surface_bright_light">@color/m3_ref_palette_dynamic_neutral_variant98</color>
+  <color name="sud_system_surface_dim_light">@color/m3_ref_palette_dynamic_neutral_variant87</color>
+  <color name="sud_system_surface_container_light">@color/m3_ref_palette_dynamic_neutral_variant94</color>
+  <color name="sud_system_surface_container_low_light">@color/m3_ref_palette_dynamic_neutral_variant96</color>
+  <color name="sud_system_surface_container_lowest_light">@android:color/system_neutral2_0</color>
+  <color name="sud_system_surface_container_high_light">@color/m3_ref_palette_dynamic_neutral_variant92</color>
+  <color name="sud_system_surface_container_highest_light">@android:color/system_neutral2_100</color>
+
+
+  <!-- Dark dynamic system palette -->
+  <color name="sud_system_primary_dark">@android:color/system_accent1_200</color>
+  <color name="sud_system_on_primary_dark">@android:color/system_accent1_800</color>
+  <color name="sud_system_primary_container_dark">@android:color/system_accent1_700</color>
+  <color name="sud_system_on_primary_container_dark">@android:color/system_accent1_100</color>
+  <color name="sud_system_primary_inverse_dark">@android:color/system_accent1_600</color>
+  <color name="sud_system_primary_fixed_dark">@android:color/system_accent1_100</color>
+  <color name="sud_system_primary_fixed_dim_dark">@android:color/system_accent1_200</color>
+  <color name="sud_system_on_primary_fixed_dark">@android:color/system_accent1_900</color>
+  <color name="sud_system_on_primary_fixed_variant_dark">@android:color/system_accent1_700</color>
+
+  <color name="sud_system_secondary_dark">@android:color/system_accent2_200</color>
+  <color name="sud_system_on_secondary_dark">@android:color/system_accent2_800</color>
+  <color name="sud_system_secondary_container_dark">@android:color/system_accent2_700</color>
+  <color name="sud_system_on_secondary_container_dark">@android:color/system_accent2_100</color>
+  <color name="sud_system_secondary_fixed_dark">@android:color/system_accent2_100</color>
+  <color name="sud_system_secondary_fixed_dim_dark">@android:color/system_accent2_200</color>
+  <color name="sud_system_on_secondary_fixed_dark">@android:color/system_accent2_900</color>
+  <color name="sud_system_on_secondary_fixed_variant_dark">@android:color/system_accent2_700</color>
+
+  <color name="sud_system_tertiary_dark">@android:color/system_accent3_200</color>
+  <color name="sud_system_on_tertiary_dark">@android:color/system_accent3_800</color>
+  <color name="sud_system_tertiary_container_dark">@android:color/system_accent3_700</color>
+  <color name="sud_system_on_tertiary_container_dark">@android:color/system_accent3_100</color>
+  <color name="sud_system_tertiary_fixed_dark">@android:color/system_accent3_100</color>
+  <color name="sud_system_tertiary_fixed_dim_dark">@android:color/system_accent3_200</color>
+  <color name="sud_system_on_tertiary_fixed_dark">@android:color/system_accent3_900</color>
+  <color name="sud_system_on_tertiary_fixed_variant_dark">@android:color/system_accent3_700</color>
+
+  <color name="sud_system_error_dark">@color/m3_ref_palette_error80</color>
+  <color name="sud_system_on_error_dark">@color/m3_ref_palette_error20</color>
+  <color name="sud_system_error_container_dark">@color/m3_ref_palette_error30</color>
+  <color name="sud_system_on_error_container_dark">@color/m3_ref_palette_error90</color>
+  <color name="sud_system_outline_dark">@android:color/system_neutral2_400</color>
+  <color name="sud_system_outline_variant_dark">@android:color/system_neutral2_700</color>
+  <color name="sud_system_background_dark">@color/m3_ref_palette_dynamic_neutral_variant6</color>
+  <color name="sud_system_on_background_dark">@android:color/system_neutral1_100</color>
+  <color name="sud_system_surface_dark">@color/m3_ref_palette_dynamic_neutral_variant6</color>
+  <color name="sud_system_on_surface_dark">@android:color/system_neutral1_100</color>
+  <color name="sud_system_surface_variant_dark">@android:color/system_neutral2_700</color>
+  <color name="sud_system_on_surface_variant_dark">@android:color/system_neutral2_200</color>
+  <color name="sud_system_surface_inverse_dark">@android:color/system_neutral1_100</color>
+  <color name="sud_system_on_surface_inverse_dark">@android:color/system_neutral1_800</color>
+  <color name="sud_system_surface_bright_dark">@color/m3_ref_palette_dynamic_neutral_variant24</color>
+  <color name="sud_system_surface_dim_dark">@color/m3_ref_palette_dynamic_neutral_variant6</color>
+  <color name="sud_system_surface_container_dark">@color/m3_ref_palette_dynamic_neutral_variant12</color>
+  <color name="sud_system_surface_container_low_dark">@android:color/system_neutral2_900</color>
+  <color name="sud_system_surface_container_lowest_dark">@color/m3_ref_palette_dynamic_neutral_variant4</color>
+  <color name="sud_system_surface_container_high_dark">@color/m3_ref_palette_dynamic_neutral_variant17</color>
+  <color name="sud_system_surface_container_highest_dark">@color/m3_ref_palette_dynamic_neutral_variant22</color>
 </resources>
diff --git a/main/res/values-v31/styles.xml b/main/res/values-v31/styles.xml
index 55f5be8..73b72aa 100644
--- a/main/res/values-v31/styles.xml
+++ b/main/res/values-v31/styles.xml
@@ -379,113 +379,115 @@
     <item name="android:textAppearanceSmallPopupMenu">@android:style/TextAppearance.DeviceDefault.Widget.PopupMenu.Small</item>
   </style>
 
-    <style name="SudThemeGlifExpressive" parent="SudBaseThemeGlifExpressive">
-        <!-- Copied from v31 SudThemeGlif -->
-        <item name="sucSystemNavBarBackgroundColor">?android:attr/navigationBarColor</item>
-        <item name="android:windowSplashScreenBackground">?android:attr/colorBackground</item>
-
-        <!-- Copied from v31 SudThemeGlifV3 -->
-        <item name="android:navigationBarDividerColor" tools:ignore="NewApi">@color/sud_glif_v3_nav_bar_divider_color_dark</item>
-        <item name="android:windowLightNavigationBar" tools:ignore="NewApi">false</item>
-        <item name="sucLightSystemNavBar" tools:ignore="NewApi">?android:attr/windowLightNavigationBar</item>
-        <item name="sucSystemNavBarDividerColor" tools:ignore="NewApi">?android:attr/navigationBarDividerColor</item>
-        <!-- Default font family-->
-        <item name="android:textAppearance">@android:style/TextAppearance.DeviceDefault</item>
-        <item name="android:textAppearanceInverse">@android:style/TextAppearance.DeviceDefault.Inverse</item>
-        <item name="android:textAppearanceLarge">@android:style/TextAppearance.DeviceDefault.Large</item>
-        <item name="android:textAppearanceMedium">@android:style/TextAppearance.DeviceDefault.Medium</item>
-        <!-- For textView -->
-        <item name="android:textAppearanceSmall">@android:style/TextAppearance.DeviceDefault.Small</item>
-        <item name="android:textAppearanceLargeInverse">@android:style/TextAppearance.DeviceDefault.Large.Inverse</item>
-        <!-- For editText -->
-        <item name="android:textAppearanceMediumInverse">@android:style/TextAppearance.DeviceDefault.Medium.Inverse</item>
-        <item name="android:textAppearanceSmallInverse">@android:style/TextAppearance.DeviceDefault.Small.Inverse</item>
-        <item name="android:textAppearanceSearchResultTitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Title</item>
-        <item name="android:textAppearanceSearchResultSubtitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Subtitle</item>
-        <item name="android:textAppearanceButton">@android:style/TextAppearance.DeviceDefault.Widget.Button</item>
-
-        <!-- Copied from v31 SudDynamicColorBaseTheme -->
-        <item name="android:colorAccent">?attr/colorAccent</item>
-
-        <!-- Copied from v31 SudFullDynamicColorTheme -->
-        <item name="android:windowAnimationStyle">@style/Animation.SudWindowAnimation.DynamicColor</item>
-
-        <!-- Copied from v31 SudDynamicColorThemeGlifV3 -->
-        <item name="android:datePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme</item>
-        <item name="android:timePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme</item>
-        <item name="sudSwitchBarThumbOnColor">@color/sud_dynamic_switch_thumb_on_dark</item>
-        <item name="sudSwitchBarTrackOnColor">@color/sud_dynamic_switch_track_on_dark</item>
-        <item name="sudSwitchBarThumbOffColor">@color/sud_dynamic_switch_thumb_off_dark</item>
-        <item name="sudSwitchBarTrackOffColor">@color/sud_dynamic_switch_track_off_dark</item>
-        <item name="sudSwitchBarTrackOffOutlineColor">@color/sud_dynamic_switch_thumb_off_outline_dark</item>
-        <item name="sudEditBoxColor">@color/sud_dynamic_color_accent_glif_v3_dark</item>
-
-        <!-- Copied from v31 SudFullDynamicColorThemeGlifV3 -->
-        <item name="android:colorForeground">@android:color/system_neutral1_50</item>
-        <item name="android:colorForegroundInverse">@color/sud_system_background_surface</item>
-        <item name="android:colorBackgroundCacheHint">@color/sud_system_background_surface</item>
-        <item name="colorBackgroundFloating">@color/sud_system_background_surface</item>
-        <item name="android:navigationBarColor">@color/sud_system_background_surface</item>
-        <item name="colorControlNormal">?android:attr/textColorSecondary</item>
-        <item name="colorControlHighlight">@color/ripple_material_dark</item>
-        <item name="colorButtonNormal">@color/button_material_dark</item>
-        <item name="colorSwitchThumbNormal">@color/switch_thumb_material_dark</item>
-        <item name="android:alertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
-    </style>
-
-    <style name="SudThemeGlifExpressive.Light" parent="SudBaseThemeGlifExpressive.Light">
-        <!-- Copied from v31 SudThemeGlif.Light -->
-        <item name="sucSystemNavBarBackgroundColor">?android:attr/navigationBarColor</item>
-        <item name="android:windowSplashScreenBackground">?android:attr/colorBackground</item>
-
-        <!-- Copied from v31 SudThemeGlifV3.Light -->
-        <item name="android:navigationBarDividerColor">@color/sud_glif_v3_nav_bar_divider_color_light</item>
-        <item name="android:windowLightNavigationBar">true</item>
-        <item name="sucLightSystemNavBar" tools:ignore="NewApi">?android:attr/windowLightNavigationBar</item>
-        <item name="sucSystemNavBarDividerColor" tools:ignore="NewApi">?android:attr/navigationBarDividerColor</item>
-        <!-- Default font family-->
-        <item name="android:textAppearance">@android:style/TextAppearance.DeviceDefault</item>
-        <item name="android:textAppearanceInverse">@android:style/TextAppearance.DeviceDefault.Inverse</item>
-        <item name="android:textAppearanceLarge">@android:style/TextAppearance.DeviceDefault.Large</item>
-        <item name="android:textAppearanceMedium">@android:style/TextAppearance.DeviceDefault.Medium</item>
-        <!-- For textView -->
-        <item name="android:textAppearanceSmall">@android:style/TextAppearance.DeviceDefault.Small</item>
-        <item name="android:textAppearanceLargeInverse">@android:style/TextAppearance.DeviceDefault.Large.Inverse</item>
-        <!-- For editText -->
-        <item name="android:textAppearanceMediumInverse">@android:style/TextAppearance.DeviceDefault.Medium.Inverse</item>
-        <item name="android:textAppearanceSmallInverse">@android:style/TextAppearance.DeviceDefault.Small.Inverse</item>
-        <item name="android:textAppearanceSearchResultTitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Title</item>
-        <item name="android:textAppearanceSearchResultSubtitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Subtitle</item>
-        <item name="android:textAppearanceButton">@android:style/TextAppearance.DeviceDefault.Widget.Button</item>
-
-        <!-- Copied from v31 SudDynamicColorBaseTheme.Light -->
-        <item name="android:colorAccent">?attr/colorAccent</item>
-
-        <!-- Copied from v31 SudDynamicColorThemeGlifV3.Light -->
-        <item name="android:windowAnimationStyle">@style/Animation.SudWindowAnimation.DynamicColor</item>
-
-        <!-- Copied from v31 SudDynamicColorThemeGlifV3.Light -->
-        <item name="android:datePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme.Light</item>
-        <item name="android:timePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme.Light</item>
-        <item name="sudSwitchBarThumbOnColor">@color/sud_dynamic_switch_thumb_on_light</item>
-        <item name="sudSwitchBarTrackOnColor">@color/sud_dynamic_switch_track_on_light</item>
-        <item name="sudSwitchBarThumbOffColor">@color/sud_dynamic_switch_thumb_off_light</item>
-        <item name="sudSwitchBarTrackOffColor">@color/sud_dynamic_switch_track_off_light</item>
-        <item name="sudSwitchBarTrackOffOutlineColor">@color/sud_dynamic_switch_thumb_off_outline_light</item>
-        <item name="sudEditBoxColor">@color/sud_dynamic_color_accent_glif_v3_light</item>
-
-        <!-- Copied from v31 SudFullDynamicColorThemeGlifV3.Light -->
-        <item name="android:colorForeground">@android:color/system_neutral1_900</item>
-        <item name="android:colorForegroundInverse">@color/sud_system_background_surface</item>
-        <item name="android:colorBackgroundCacheHint">@color/sud_system_background_surface</item>
-        <item name="colorBackgroundFloating">@color/sud_system_background_surface</item>
-        <item name="android:navigationBarColor">@color/sud_system_background_surface</item>
-        <item name="colorControlNormal">?android:attr/textColorSecondary</item>
-        <item name="colorControlHighlight">@color/ripple_material_light</item>
-        <item name="colorButtonNormal">@color/button_material_light</item>
-        <item name="colorSwitchThumbNormal">@color/switch_thumb_material_light</item>
-        <item name="android:alertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
-    </style>
+  <style name="SudThemeGlifExpressive" parent="SudBaseThemeGlifExpressive">
+    <!-- Copied from v31 SudThemeGlif -->
+    <item name="sucSystemNavBarBackgroundColor">?android:attr/navigationBarColor</item>
+    <item name="android:windowSplashScreenBackground">?android:attr/colorBackground</item>
+
+    <!-- Copied from v31 SudThemeGlifV3 -->
+    <item name="android:navigationBarDividerColor" tools:ignore="NewApi">@color/sud_glif_v3_nav_bar_divider_color_dark</item>
+    <item name="android:windowLightNavigationBar" tools:ignore="NewApi">false</item>
+    <item name="sucLightSystemNavBar" tools:ignore="NewApi">?android:attr/windowLightNavigationBar</item>
+    <item name="sucSystemNavBarDividerColor" tools:ignore="NewApi">?android:attr/navigationBarDividerColor</item>
+    <!-- Default font family-->
+    <item name="android:textAppearance">@android:style/TextAppearance.DeviceDefault</item>
+    <item name="android:textAppearanceInverse">@android:style/TextAppearance.DeviceDefault.Inverse</item>
+    <item name="android:textAppearanceLarge">@android:style/TextAppearance.DeviceDefault.Large</item>
+    <item name="android:textAppearanceMedium">@android:style/TextAppearance.DeviceDefault.Medium</item>
+    <!-- For textView -->
+    <item name="android:textAppearanceSmall">@android:style/TextAppearance.DeviceDefault.Small</item>
+    <item name="android:textAppearanceLargeInverse">@android:style/TextAppearance.DeviceDefault.Large.Inverse</item>
+    <!-- For editText -->
+    <item name="android:textAppearanceMediumInverse">@android:style/TextAppearance.DeviceDefault.Medium.Inverse</item>
+    <item name="android:textAppearanceSmallInverse">@android:style/TextAppearance.DeviceDefault.Small.Inverse</item>
+    <item name="android:textAppearanceSearchResultTitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Title</item>
+    <item name="android:textAppearanceSearchResultSubtitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Subtitle</item>
+    <item name="android:textAppearanceButton">@android:style/TextAppearance.DeviceDefault.Widget.Button</item>
+
+    <!-- Copied from v31 SudDynamicColorBaseTheme -->
+    <item name="android:colorAccent">?attr/colorAccent</item>
+
+    <!-- Copied from v31 SudFullDynamicColorTheme -->
+    <item name="android:windowAnimationStyle">@style/Animation.SudWindowAnimation.DynamicColor</item>
+
+    <!-- Copied from v31 SudDynamicColorThemeGlifV3 -->
+    <item name="android:datePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme</item>
+    <item name="android:timePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme</item>
+    <item name="sudSwitchBarThumbOnColor">@color/sud_dynamic_switch_thumb_on_dark</item>
+    <item name="sudSwitchBarTrackOnColor">@color/sud_dynamic_switch_track_on_dark</item>
+    <item name="sudSwitchBarThumbOffColor">@color/sud_dynamic_switch_thumb_off_dark</item>
+    <item name="sudSwitchBarTrackOffColor">@color/sud_dynamic_switch_track_off_dark</item>
+    <item name="sudSwitchBarTrackOffOutlineColor">@color/sud_dynamic_switch_thumb_off_outline_dark</item>
+    <item name="sudEditBoxColor">@color/sud_dynamic_color_accent_glif_v3_dark</item>
+
+    <!-- Copied from v31 SudFullDynamicColorThemeGlifV3 -->
+    <item name="android:colorForeground">@android:color/system_neutral1_50</item>
+    <item name="android:colorForegroundInverse">@color/sud_system_background_surface</item>
+    <item name="android:colorBackgroundCacheHint">@color/sud_system_background_surface</item>
+    <item name="colorBackgroundFloating">@color/sud_system_background_surface</item>
+    <item name="android:navigationBarColor">@color/sud_system_background_surface</item>
+    <item name="colorControlNormal">?android:attr/textColorSecondary</item>
+    <item name="colorControlHighlight">@color/ripple_material_dark</item>
+    <item name="colorButtonNormal">@color/button_material_dark</item>
+    <item name="colorSwitchThumbNormal">@color/switch_thumb_material_dark</item>
+    <item name="android:alertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
+    <item name="alertDialogTheme">@style/SudGlifExpressiveDialogThemeCompat</item>
+  </style>
+
+  <style name="SudThemeGlifExpressive.Light" parent="SudBaseThemeGlifExpressive.Light">
+    <!-- Copied from v31 SudThemeGlif.Light -->
+    <item name="sucSystemNavBarBackgroundColor">?android:attr/navigationBarColor</item>
+    <item name="android:windowSplashScreenBackground">?android:attr/colorBackground</item>
+
+    <!-- Copied from v31 SudThemeGlifV3.Light -->
+    <item name="android:navigationBarDividerColor">@color/sud_glif_v3_nav_bar_divider_color_light</item>
+    <item name="android:windowLightNavigationBar">true</item>
+    <item name="sucLightSystemNavBar" tools:ignore="NewApi">?android:attr/windowLightNavigationBar</item>
+    <item name="sucSystemNavBarDividerColor" tools:ignore="NewApi">?android:attr/navigationBarDividerColor</item>
+    <!-- Default font family-->
+    <item name="android:textAppearance">@android:style/TextAppearance.DeviceDefault</item>
+    <item name="android:textAppearanceInverse">@android:style/TextAppearance.DeviceDefault.Inverse</item>
+    <item name="android:textAppearanceLarge">@android:style/TextAppearance.DeviceDefault.Large</item>
+    <item name="android:textAppearanceMedium">@android:style/TextAppearance.DeviceDefault.Medium</item>
+    <!-- For textView -->
+    <item name="android:textAppearanceSmall">@android:style/TextAppearance.DeviceDefault.Small</item>
+    <item name="android:textAppearanceLargeInverse">@android:style/TextAppearance.DeviceDefault.Large.Inverse</item>
+    <!-- For editText -->
+    <item name="android:textAppearanceMediumInverse">@android:style/TextAppearance.DeviceDefault.Medium.Inverse</item>
+    <item name="android:textAppearanceSmallInverse">@android:style/TextAppearance.DeviceDefault.Small.Inverse</item>
+    <item name="android:textAppearanceSearchResultTitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Title</item>
+    <item name="android:textAppearanceSearchResultSubtitle">@android:style/TextAppearance.DeviceDefault.SearchResult.Subtitle</item>
+    <item name="android:textAppearanceButton">@android:style/TextAppearance.DeviceDefault.Widget.Button</item>
+
+    <!-- Copied from v31 SudDynamicColorBaseTheme.Light -->
+    <item name="android:colorAccent">?attr/colorAccent</item>
+
+    <!-- Copied from v31 SudDynamicColorThemeGlifV3.Light -->
+    <item name="android:windowAnimationStyle">@style/Animation.SudWindowAnimation.DynamicColor</item>
+
+    <!-- Copied from v31 SudDynamicColorThemeGlifV3.Light -->
+    <item name="android:datePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme.Light</item>
+    <item name="android:timePickerDialogTheme">@style/SudDynamicColorDateTimePickerDialogTheme.Light</item>
+    <item name="sudSwitchBarThumbOnColor">@color/sud_dynamic_switch_thumb_on_light</item>
+    <item name="sudSwitchBarTrackOnColor">@color/sud_dynamic_switch_track_on_light</item>
+    <item name="sudSwitchBarThumbOffColor">@color/sud_dynamic_switch_thumb_off_light</item>
+    <item name="sudSwitchBarTrackOffColor">@color/sud_dynamic_switch_track_off_light</item>
+    <item name="sudSwitchBarTrackOffOutlineColor">@color/sud_dynamic_switch_thumb_off_outline_light</item>
+    <item name="sudEditBoxColor">@color/sud_dynamic_color_accent_glif_v3_light</item>
+
+    <!-- Copied from v31 SudFullDynamicColorThemeGlifV3.Light -->
+    <item name="android:colorForeground">@android:color/system_neutral1_900</item>
+    <item name="android:colorForegroundInverse">@color/sud_system_background_surface</item>
+    <item name="android:colorBackgroundCacheHint">@color/sud_system_background_surface</item>
+    <item name="colorBackgroundFloating">@color/sud_system_background_surface</item>
+    <item name="android:navigationBarColor">@color/sud_system_background_surface</item>
+    <item name="colorControlNormal">?android:attr/textColorSecondary</item>
+    <item name="colorControlHighlight">@color/ripple_material_light</item>
+    <item name="colorButtonNormal">@color/button_material_light</item>
+    <item name="colorSwitchThumbNormal">@color/switch_thumb_material_light</item>
+    <item name="android:alertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
+    <item name="alertDialogTheme">@style/SudGlifExpressiveDialogThemeCompat</item>
+  </style>
 
   <style name="SudGlifExpressiveDialogTheme" parent="ThemeOverlay.Material3.MaterialAlertDialog">
     <item name="alertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
@@ -498,6 +500,12 @@
     <item name="android:textColorPrimary">@color/sud_on_surface_variant</item>
   </style>
 
+  <style name="SudGlifExpressiveDialogThemeCompat" parent="ThemeOverlay.Material3.MaterialAlertDialog">
+    <item name="android:textAllCaps">false</item>
+    <item name="android:fontFamily">@string/sudGlifExpressiveDialogFontFamily</item>
+    <item name="dialogCornerRadius">@dimen/sud_glif_device_default_dialog_corner_radius</item>
+  </style>
+
   <style name="SudGlifExpressiveWindowTitleTextAppearance" parent="RtlOverlay.DialogWindowTitle.AppCompat">
     <item name="android:textAppearance">@style/SudGlifExpressiveWindowTitleTextStyle</item>
   </style>
diff --git a/main/res/values-v33/styles.xml b/main/res/values-v33/styles.xml
index 5d02f04..b8b53b2 100644
--- a/main/res/values-v33/styles.xml
+++ b/main/res/values-v33/styles.xml
@@ -22,4 +22,12 @@
   <style name="SudDynamicColorTheme.Light" parent="SudDynamicColorBaseTheme.Light">
     <item name="colorSurface">@color/sud_system_surface</item>
   </style>
+  <style name="SudMaterialYouAlertDialogTheme" parent="SudAlertDialogTheme">
+      <item name="android:textAllCaps">false</item>
+      <item name="android:windowTitleStyle">@style/SudMaterialYouWindowTitleStyle</item>
+  </style>
+  <style name="SudMaterialYouAlertDialogTheme.Light" parent="SudAlertDialogTheme.Light">
+      <item name="android:textAllCaps">false</item>
+      <item name="android:windowTitleStyle">@style/SudMaterialYouWindowTitleStyle</item>
+  </style>
 </resources>
\ No newline at end of file
diff --git a/main/res/values-v34/colors.xml b/main/res/values-v34/colors.xml
index 90c9d1a..df7cd49 100644
--- a/main/res/values-v34/colors.xml
+++ b/main/res/values-v34/colors.xml
@@ -15,23 +15,12 @@
     limitations under the License.
 -->
 
-<resources>
+<resources xmlns:tools="http://schemas.android.com/tools"
+    tools:keep="@color/sud_system_*">
   <!-- Accent color -->
   <color name="sud_dynamic_color_accent_glif_v3_dark">@color/sud_system_accent1_300</color>
   <!-- Surface container color -->
   <color name="sud_system_sc_highest_dark">@android:color/system_surface_container_highest_dark</color>
-  <!-- Surface container highest color light -->
-  <color name="sud_system_sc_highest_light">@android:color/system_surface_container_highest_light</color>
-  <!-- System on primary light -->
-  <color name="sud_system_on_primary">@android:color/system_on_primary_light</color>
-  <!-- On surface variant light -->
-  <color name="sud_on_surface_variant">@android:color/system_on_surface_variant_light</color>
-  <!-- On secondary container -->
-  <color name="sud_on_secondary_container">@android:color/system_on_secondary_container_light</color>
-  <!-- Primary light -->
-  <color name="sud_color_primary">@android:color/system_primary_light</color>
-  <!-- Surface container high light -->
-  <color name="sud_color_surface_container_high">@android:color/system_surface_container_high_light</color>
 
 
   <color name="sud_dynamic_switch_thumb_off_light">@color/sud_system_neutral2_500</color>
@@ -48,12 +37,107 @@
   <color name="sud_color_on_surface">@android:color/system_on_surface_light</color>
   <color name="sud_color_surface_container_highest">@android:color/system_surface_container_highest_light</color>
 
-  <!-- Glif expressive colors -->
+  <!-- Light dynamic system palette -->
+  <color name="sud_system_primary_light">@android:color/system_primary_light</color>
+  <color name="sud_system_on_primary_light">@android:color/system_on_primary_light</color>
+  <color name="sud_system_primary_container_light">@android:color/system_primary_container_light</color>
+  <color name="sud_system_on_primary_container_light">@android:color/system_on_primary_container_light</color>
+  <color name="sud_system_primary_inverse_light">@android:color/system_primary_dark</color>
+  <color name="sud_system_primary_fixed_light">@android:color/system_primary_fixed</color>
+  <color name="sud_system_primary_fixed_dim_light">@android:color/system_primary_fixed_dim</color>
+  <color name="sud_system_on_primary_fixed_light">@android:color/system_on_primary_fixed</color>
+  <color name="sud_system_on_primary_fixed_variant_light">@android:color/system_on_primary_fixed_variant</color>
+
+  <color name="sud_system_secondary_light">@android:color/system_secondary_light</color>
+  <color name="sud_system_on_secondary_light">@android:color/system_on_secondary_light</color>
+  <color name="sud_system_secondary_container_light">@android:color/system_secondary_container_light</color>
+  <color name="sud_system_on_secondary_container_light">@android:color/system_on_secondary_container_light</color>
+  <color name="sud_system_secondary_fixed_light">@android:color/system_secondary_fixed</color>
+  <color name="sud_system_secondary_fixed_dim_light">@android:color/system_secondary_fixed_dim</color>
+  <color name="sud_system_on_secondary_fixed_light">@android:color/system_on_secondary_fixed</color>
+  <color name="sud_system_on_secondary_fixed_variant_light">@android:color/system_on_secondary_fixed_variant</color>
+
+  <color name="sud_system_tertiary_light">@android:color/system_tertiary_light</color>
+  <color name="sud_system_on_tertiary_light">@android:color/system_on_tertiary_light</color>
+  <color name="sud_system_tertiary_container_light">@android:color/system_tertiary_container_light</color>
+  <color name="sud_system_on_tertiary_container_light">@android:color/system_on_tertiary_container_light</color>
+  <color name="sud_system_tertiary_fixed_light">@android:color/system_tertiary_fixed</color>
+  <color name="sud_system_tertiary_fixed_dim_light">@android:color/system_tertiary_fixed_dim</color>
+  <color name="sud_system_on_tertiary_fixed_light">@android:color/system_on_tertiary_fixed</color>
+  <color name="sud_system_on_tertiary_fixed_variant_light">@android:color/system_on_tertiary_fixed_variant</color>
+
+  <color name="sud_system_error_light">@android:color/system_error_light</color>
+  <color name="sud_system_on_error_light">@android:color/system_on_error_light</color>
+  <color name="sud_system_error_container_light">@android:color/system_error_container_light</color>
+  <color name="sud_system_on_error_container_light">@android:color/system_on_error_container_light</color>
+  <color name="sud_system_outline_light">@android:color/system_outline_light</color>
+  <color name="sud_system_outline_variant_light">@android:color/system_outline_variant_light</color>
+  <color name="sud_system_background_light">@android:color/system_background_light</color>
+  <color name="sud_system_on_background_light">@android:color/system_on_background_light</color>
+  <color name="sud_system_surface_light">@android:color/system_surface_light</color>
+  <color name="sud_system_on_surface_light">@android:color/system_on_surface_light</color>
+  <color name="sud_system_surface_variant_light">@android:color/system_surface_variant_light</color>
+  <color name="sud_system_on_surface_variant_light">@android:color/system_on_surface_variant_light</color>
+  <color name="sud_system_surface_inverse_light">@android:color/system_surface_dark</color>
+  <color name="sud_system_on_surface_inverse_light">@android:color/system_on_surface_dark</color>
+  <color name="sud_system_surface_bright_light">@android:color/system_surface_bright_light</color>
+  <color name="sud_system_surface_dim_light">@android:color/system_surface_dim_light</color>
+  <color name="sud_system_surface_container_light">@android:color/system_surface_container_light</color>
+  <color name="sud_system_surface_container_low_light">@android:color/system_surface_container_low_light</color>
+  <color name="sud_system_surface_container_lowest_light">@android:color/system_surface_container_lowest_light</color>
+  <color name="sud_system_surface_container_high_light">@android:color/system_surface_container_high_light</color>
+  <color name="sud_system_surface_container_highest_light">@android:color/system_surface_container_highest_light</color>
+
+
+  <!-- Dark dynamic system palette -->
+  <color name="sud_system_primary_dark">@android:color/system_primary_dark</color>
+  <color name="sud_system_on_primary_dark">@android:color/system_on_primary_dark</color>
+  <color name="sud_system_primary_container_dark">@android:color/system_primary_container_dark</color>
+  <color name="sud_system_on_primary_container_dark">@android:color/system_on_primary_container_dark</color>
+  <color name="sud_system_primary_inverse_dark">@android:color/system_primary_light</color>
+  <color name="sud_system_primary_fixed_dark">@android:color/system_primary_fixed</color>
+  <color name="sud_system_primary_fixed_dim_dark">@android:color/system_primary_fixed_dim</color>
+  <color name="sud_system_on_primary_fixed_dark">@android:color/system_on_primary_fixed</color>
+  <color name="sud_system_on_primary_fixed_variant_dark">@android:color/system_on_primary_fixed_variant</color>
+
+  <color name="sud_system_secondary_dark">@android:color/system_secondary_dark</color>
+  <color name="sud_system_on_secondary_dark">@android:color/system_on_secondary_dark</color>
+  <color name="sud_system_secondary_container_dark">@android:color/system_secondary_container_dark</color>
+  <color name="sud_system_on_secondary_container_dark">@android:color/system_on_secondary_container_dark</color>
+  <color name="sud_system_secondary_fixed_dark">@android:color/system_secondary_fixed</color>
+  <color name="sud_system_secondary_fixed_dim_dark">@android:color/system_secondary_fixed_dim</color>
+  <color name="sud_system_on_secondary_fixed_dark">@android:color/system_on_secondary_fixed</color>
+  <color name="sud_system_on_secondary_fixed_variant_dark">@android:color/system_on_secondary_fixed_variant</color>
+
+  <color name="sud_system_tertiary_dark">@android:color/system_tertiary_dark</color>
+  <color name="sud_system_on_tertiary_dark">@android:color/system_on_tertiary_dark</color>
+  <color name="sud_system_tertiary_container_dark">@android:color/system_tertiary_container_dark</color>
+  <color name="sud_system_on_tertiary_container_dark">@android:color/system_on_tertiary_container_dark</color>
+  <color name="sud_system_tertiary_fixed_dark">@android:color/system_tertiary_fixed</color>
+  <color name="sud_system_tertiary_fixed_dim_dark">@android:color/system_tertiary_fixed_dim</color>
+  <color name="sud_system_on_tertiary_fixed_dark">@android:color/system_on_tertiary_fixed</color>
+  <color name="sud_system_on_tertiary_fixed_variant_dark">@android:color/system_on_tertiary_fixed_variant</color>
+
+  <color name="sud_system_error_dark">@android:color/system_error_dark</color>
+  <color name="sud_system_on_error_dark">@android:color/system_on_error_dark</color>
+  <color name="sud_system_error_container_dark">@android:color/system_error_container_dark</color>
+  <color name="sud_system_on_error_container_dark">@android:color/system_on_error_container_dark</color>
+  <color name="sud_system_outline_dark">@android:color/system_outline_dark</color>
+  <color name="sud_system_outline_variant_dark">@android:color/system_outline_variant_dark</color>
+  <color name="sud_system_background_dark">@android:color/system_background_dark</color>
+  <color name="sud_system_on_background_dark">@android:color/system_on_background_dark</color>
+  <color name="sud_system_surface_dark">@android:color/system_surface_dark</color>
+  <color name="sud_system_on_surface_dark">@android:color/system_on_surface_dark</color>
+  <color name="sud_system_surface_variant_dark">@android:color/system_surface_variant_dark</color>
+  <color name="sud_system_on_surface_variant_dark">@android:color/system_on_surface_variant_dark</color>
+  <color name="sud_system_surface_inverse_dark">@android:color/system_surface_light</color>
+  <color name="sud_system_on_surface_inverse_dark">@android:color/system_on_surface_light</color>
+  <color name="sud_system_surface_bright_dark">@android:color/system_surface_bright_dark</color>
+  <color name="sud_system_surface_dim_dark">@android:color/system_surface_dim_dark</color>
+  <color name="sud_system_surface_container_dark">@android:color/system_surface_container_dark</color>
+  <color name="sud_system_surface_container_low_dark">@android:color/system_surface_container_low_dark</color>
+  <color name="sud_system_surface_container_lowest_dark">@android:color/system_surface_container_lowest_dark</color>
+  <color name="sud_system_surface_container_high_dark">@android:color/system_surface_container_high_dark</color>
+  <color name="sud_system_surface_container_highest_dark">@android:color/system_surface_container_highest_dark</color>
 
-  <color name="sud_glif_expressive_footer_bar_bg_color">@color/sud_system_sc_highest_light</color>
-  <color name="sud_glif_expressive_footer_button_bg_color">@color/sud_color_primary</color>
-  <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@color/sud_system_on_primary</color>
-  <color name="sud_glif_expressive_footer_primary_button_disable_text_color">@color/sud_on_surface_variant</color>
-  <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">@color/sud_on_secondary_container</color>
-  <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">@color/sud_on_surface_variant</color>
 </resources>
\ No newline at end of file
diff --git a/main/res/values-w600dp-h900dp/dimens.xml b/main/res/values-w600dp-h900dp/dimens.xml
index d2c6984..d369e84 100644
--- a/main/res/values-w600dp-h900dp/dimens.xml
+++ b/main/res/values-w600dp-h900dp/dimens.xml
@@ -16,20 +16,24 @@
 -->
 
 <resources>
+    <!-- Page Margins Glif Expressive -->
+    <dimen name="sud_glif_expressive_margin_start">72dp</dimen>
+    <dimen name="sud_glif_expressive_margin_end">72dp</dimen>
+
     <!-- General dimension for glif expressive theme -->
     <!-- Calculated by (Spec = 72dp - 4dp internal padding of button) -->
-    <dimen name="sud_glif_expressive_footer_padding_start">68dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_start">68dp</dimen>
     <!-- Calculated by (Spec = 72dp - 4dp internal padding of button) -->
-    <dimen name="sud_glif_expressive_footer_padding_end">68dp</dimen>
-    <dimen name="sud_glif_expressive_footer_bar_padding_start">104dp</dimen>
-    <dimen name="sud_glif_expressive_footer_bar_padding_end">116dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_end">68dp</dimen>
+
+    <!-- Header layout expressive -->
+    <dimen name="sud_glif_expressive_header_title_size">45sp</dimen>
+    <dimen name="sud_glif_expressive_header_title_line_height">52sp</dimen>
 
     <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
     <dimen name="sud_glif_expressive_button_margin_end">80dp</dimen>
     <!-- Calculated by (sud_glif_expressive_margin_start - sud_glif_expressive_button_padding) -->
     <dimen name="sud_glif_expressive_button_margin_start">92dp</dimen>
     <dimen name="sud_glif_expressive_content_padding_top">0dp</dimen>
-    <dimen name="sud_glif_expressive_item_margin_start">64dp</dimen>
-    <dimen name="sud_glif_expressive_item_margin_end">64dp</dimen>
 
 </resources>
diff --git a/main/res/values-w600dp-v35/layouts.xml b/main/res/values-w600dp-v35/layouts.xml
index 753a15d..b0c10c1 100644
--- a/main/res/values-w600dp-v35/layouts.xml
+++ b/main/res/values-w600dp-v35/layouts.xml
@@ -19,6 +19,6 @@
     <item name="sud_glif_expressive_template_content_layout" type="layout">@layout/sud_glif_expressive_template_content_wide</item>
     <item name="sud_glif_expressive_list_template_content_layout" type="layout">@layout/sud_glif_expressive_list_template_content_wide</item>
     <item name="sud_glif_expressive_blank_template_content_layout" type="layout">@layout/sud_glif_expressive_blank_template_content_wide</item>
-    <item name="sud_glif_expressive_preference_template_content_layout" type="layout">@layout/sud_glif_expressive_preference_template_content</item>
+    <item name="sud_glif_expressive_preference_template_content_layout" type="layout">@layout/sud_glif_expressive_preference_template_content_wide</item>
     <item name="sud_glif_expressive_recycler_template_content_layout" type="layout">@layout/sud_glif_expressive_recycler_template_content_wide</item>
 </resources>
diff --git a/main/res/values-w600dp/dimens.xml b/main/res/values-w600dp/dimens.xml
index 5169873..ba4aa48 100644
--- a/main/res/values-w600dp/dimens.xml
+++ b/main/res/values-w600dp/dimens.xml
@@ -18,8 +18,8 @@
 
   <!-- Glif expressive footer bar padding -->
   <!-- Calculated by (Spec = 12dp - 4dp internal padding of button) -->
-  <dimen name="sud_glif_expressive_footer_padding_start">8dp</dimen>
+  <dimen name="sud_glif_expressive_footer_bar_padding_start">8dp</dimen>
   <!-- Calculated by (Spec = 24dp - 4dp internal padding of button) -->
-  <dimen name="sud_glif_expressive_footer_padding_end">20dp</dimen>
+  <dimen name="sud_glif_expressive_footer_bar_padding_end">20dp</dimen>
 
 </resources>
diff --git a/main/res/values-w840dp-h480dp/dimens.xml b/main/res/values-w840dp-h480dp/dimens.xml
index ab62dbe..f061330 100644
--- a/main/res/values-w840dp-h480dp/dimens.xml
+++ b/main/res/values-w840dp-h480dp/dimens.xml
@@ -16,21 +16,22 @@
 -->
 
 <resources>
-    <!-- General dimension for glif expressive theme -->
+    <!-- Page Margins Glif Expressive -->
+    <dimen name="sud_glif_expressive_margin_start">48dp</dimen>
+    <dimen name="sud_glif_expressive_margin_end">48dp</dimen>
+    <dimen name="sud_glif_expressive_land_middle_horizontal_spacing">72dp</dimen>
     <!-- Calculated by (Spec = 36dp - 4dp internal padding of button) -->
-    <dimen name="sud_glif_expressive_footer_padding_start">32dp</dimen>
-    <!-- Calculated by (Spec = 48dp - 4dp internal padding of button) -->
-    <dimen name="sud_glif_expressive_footer_padding_end">44dp</dimen>
-    <dimen name="sud_glif_expressive_footer_bar_padding_vertical">6dp</dimen>
     <dimen name="sud_glif_expressive_footer_bar_padding_start">32dp</dimen>
+    <!-- Calculated by (Spec = 48dp - 4dp internal padding of button) -->
     <dimen name="sud_glif_expressive_footer_bar_padding_end">44dp</dimen>
-
     <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
     <dimen name="sud_glif_expressive_button_margin_end">44dp</dimen>
     <!-- Calculated by (sud_glif_expressive_margin_start - sud_glif_expressive_button_padding) -->
     <dimen name="sud_glif_expressive_button_margin_start">32dp</dimen>
     <dimen name="sud_glif_expressive_content_padding_top">80dp</dimen>
-    <dimen name="sud_glif_expressive_item_margin_start">28dp</dimen>
-    <dimen name="sud_glif_expressive_item_margin_end">40dp</dimen>
+
+    <!-- Header layout expressive -->
+    <dimen name="sud_glif_expressive_header_title_size">45sp</dimen>
+    <dimen name="sud_glif_expressive_header_title_line_height">52sp</dimen>
 
 </resources>
diff --git a/main/res/values-w840dp/dimens.xml b/main/res/values-w840dp/dimens.xml
index a3e386c..59170ab 100644
--- a/main/res/values-w840dp/dimens.xml
+++ b/main/res/values-w840dp/dimens.xml
@@ -18,13 +18,10 @@
 <resources>
     <!-- General -->
     <dimen name="sud_glif_expressive_footer_bar_min_height">52dp</dimen>
-    <dimen name="sud_glif_expressive_footer_padding_vertical">0dp</dimen>
     <!-- Calculated by (Spec = 12dp - 4dp internal padding of button) -->
     <dimen name="sud_glif_expressive_footer_bar_padding_start">8dp</dimen>
     <!-- Calculated by (Spec = 24dp - 4dp internal padding of button) -->
     <dimen name="sud_glif_expressive_footer_bar_padding_end">20dp</dimen>
 
     <dimen name="sud_glif_expressive_content_padding_top">8dp</dimen>
-    <dimen name="sud_glif_expressive_item_margin_start">4dp</dimen>
-    <dimen name="sud_glif_expressive_item_margin_end">16dp</dimen>
 </resources>
diff --git a/main/res/values/attrs.xml b/main/res/values/attrs.xml
index 5651f45..68b495d 100644
--- a/main/res/values/attrs.xml
+++ b/main/res/values/attrs.xml
@@ -143,17 +143,34 @@
     <!-- Custom view attributes -->
     <attr name="sudColorPrimary" format="color" />
     <attr name="sudHeader" format="reference" />
+    <attr name="sudShouldApplyAdditionalMargin" format="boolean" />
     <!-- Deprecated. Use sudDividerInsetStart and sudDividerInsetEnd instead -->
     <attr name="sudDividerInset" format="dimension|reference" />
     <attr name="sudDividerInsetEnd" format="dimension|reference" />
     <attr name="sudDividerInsetStart" format="dimension|reference" />
     <attr name="sudDividerInsetStartNoIcon" format="dimension|reference" />
     <attr name="sudDividerShown" format="boolean"/>
+    <attr name="sudTopRoundedCorner" format="boolean" />
+    <attr name="sudBottomRoundedCorner" format="boolean" />
     <attr name="sudItemContainerStyle" format="reference"/>
+    <attr name="sudNonActionableItemContainerStyle" format="reference"/>
+    <attr name="sudPromoItemContainerStyle" format="reference"/>
+    <attr name="sudPromoItemIconContainerStyle" format="reference"/>
+    <attr name="sudPromoItemTitleStyle" format="reference"/>
+    <attr name="sudPromoItemSummaryStyle" format="reference"/>
+    <attr name="sudPromoCardIconBackgroundColor" format="color|reference"/>
+    <attr name="sudPromoItemBackground" format="color|reference"/>
     <attr name="sudItemIconContainerStyle" format="reference"/>
+    <attr name="sudItemIconStyle" format="reference"/>
     <attr name="sudItemTitleStyle" format="reference"/>
     <attr name="sudItemSummaryStyle" format="reference"/>
+    <attr name="sudBulletPointTitleStyle" format="reference"/>
+    <attr name="sudBulletPointSummaryStyle" format="reference"/>
     <attr name="sudItemDescriptionStyle" format="reference" />
+    <attr name="sudSectionItemContainerStyle" format="reference" />
+    <attr name="sudIllustrationItemContainerStyle" format="reference" />
+    <attr name="sudIllustrationItemStyle" format="reference" />
+    <attr name="sudSectionItemTitleStyle" format="reference" />
     <attr name="sudItemDescriptionTitleStyle" format="reference" />
     <attr name="sudItemDescriptionTitleTextAppearence" format="reference" />
     <attr name="sudItemVerboseTitleStyle" format="reference" />
@@ -164,6 +181,7 @@
     <attr name="sudItemBackgroundPaddingStart" format="dimension|reference" />
     <attr name="sudItemBackgroundPaddingEnd" format="dimension|reference" />
     <attr name="sudItemBackgroundColor" format="color|reference" />
+    <attr name="sudNonActionableItemBackgroundColor" format="color|reference" />
     <attr name="sudItemDescriptionPaddingTop" format="dimension|reference" />
     <attr name="sudItemDescriptionPaddingBottom" format="dimension|reference" />
     <attr name="sudItemSummaryPaddingTop" format="dimension|reference" />
@@ -172,12 +190,29 @@
     <attr name="sudItemBackgroundFirst" format="color|reference" />
     <attr name="sudItemBackgroundLast" format="color|reference" />
     <attr name="sudItemBackgroundSingle" format="color|reference" />
+    <attr name="sudNonActionableItemBackground" format="color|reference" />
+    <attr name="sudNonActionableItemBackgroundFirst" format="color|reference" />
+    <attr name="sudNonActionableItemBackgroundLast" format="color|reference" />
+    <attr name="sudNonActionableItemBackgroundSingle" format="color|reference" />
     <attr name="sudItemCornerRadius" format="dimension|reference" />
+    <attr name="sudListDividerHeight" format="dimension|reference" />
+    <attr name="sudBulletPointContainerStyle" format="reference" />
+    <attr name="sudBulletPointIconContainerStyle" format="reference" />
+    <attr name="sudAdditionalBodyTextStyle" format="reference" />
+    <attr name="sudInfoFooterContainerStyle" format="reference" />
+    <attr name="sudInfoFooterIconContainerStyle" format="reference" />
+    <attr name="sudInfoFooterIconStyle" format="reference" />
+    <attr name="sudInfoFooterTitleStyle" format="reference" />
     <attr name="sudContentFramePaddingTop" format="dimension|reference" />
     <attr name="sudContentFramePaddingBottom" format="dimension|reference" />
     <attr name="sudAccountAvatarMarginEnd" format="dimension|reference" />
     <attr name="sudAccountAvatarMaxHeight" format="dimension|reference" />
     <attr name="sudAccountNameTextSize" format="dimension|reference" />
+    <attr name="sudAccountNameTextColor" format="color" />
+    <attr name="sudCameraPreviewStyle" format="reference" />
+    <attr name="sudQrFinishStyle" format="reference" />
+    <attr name="sudExpandedContent" format="reference" />
+    <attr name="sudAnimationId" format="reference" />
 
     <!-- EditBox -->
     <attr name="sudEditBoxStyle" format="reference" />
@@ -199,10 +234,16 @@
 
     <declare-styleable name="SudStickyHeaderListView">
         <attr name="sudHeader" />
+        <attr name="sudShouldApplyAdditionalMargin" />
     </declare-styleable>
 
     <declare-styleable name="SudHeaderRecyclerView">
         <attr name="sudHeader" />
+        <attr name="sudShouldApplyAdditionalMargin" />
+    </declare-styleable>
+
+    <declare-styleable name="SudSectionItem">
+        <attr name="android:title" />
     </declare-styleable>
 
     <declare-styleable name="SudIllustrationVideoView">
@@ -230,6 +271,9 @@
     <attr name="sudContentIllustrationMaxHeight" format="dimension" />
     <attr name="sudContentIllustrationPaddingTop" format="dimension" />
     <attr name="sudContentIllustrationPaddingBottom" format="dimension" />
+
+    <attr name="sudContentIllustrationStyle" format="reference" />
+
     <declare-styleable name="SudFillContentLayout">
         <attr name="android:maxHeight" />
         <attr name="android:maxWidth" />
@@ -277,6 +321,7 @@
         <attr name="android:enabled" />
         <attr name="android:text" />
         <attr name="android:theme" />
+        <attr name="android:icon" />
     </declare-styleable>
 
     <declare-styleable name="SudIconMixin">
@@ -311,11 +356,48 @@
         <attr name="android:checked" />
     </declare-styleable>
 
+    <declare-styleable name="SudExpandableItem">
+        <attr name="sudExpandedContent" />
+    </declare-styleable>
+
+    <declare-styleable name="SudRadioButtonItem">
+        <attr name="android:checked" />
+    </declare-styleable>
+
+    <declare-styleable name="SudCheckBoxItem">
+        <attr name="android:checked" />
+    </declare-styleable>
+
+    <declare-styleable name="SudIllustrationItem">
+        <attr name="sudAnimationId" />
+        <attr name="android:drawable" />
+    </declare-styleable>
+
     <declare-styleable name="SudExpandableSwitchItem">
         <attr name="sudCollapsedSummary" format="string" localization="suggested" />
         <attr name="sudExpandedSummary" format="string" localization="suggested" />
     </declare-styleable>
 
+    <declare-styleable name="SudBulletPointView">
+        <attr name="android:icon" />
+        <attr name="android:summary" />
+        <attr name="android:title" />
+    </declare-styleable>
+
+    <declare-styleable name="SudPromoCardView">
+        <attr name="android:icon" />
+        <attr name="android:summary" />
+        <attr name="android:title" />
+        <attr name="sudTopRoundedCorner" />
+        <attr name="sudBottomRoundedCorner" />
+    </declare-styleable>
+
+    <declare-styleable name="SudInfoFooterView">
+        <attr name="android:icon" />
+        <attr name="android:title" />
+        <attr name="sudAlignParentBottom" format="boolean" />
+    </declare-styleable>
+
     <declare-styleable name="SudDescriptionMixin">
         <attr name="sudDescriptionText" format="string" localization="suggested" />
         <attr name="sudDescriptionTextColor" format="reference|color" />
@@ -345,4 +427,17 @@
 
     <!-- Footer bar style -->
     <attr name="sudFooterBackgroundColor" format="color" />
+
+    <!-- Card view style -->
+    <declare-styleable name="SudCardView">
+        <attr name="sudIcon" format="reference" />
+        <attr name="sudTitleText" format="string|reference" />
+        <attr name="sudCardViewSkipClickSelection" format="boolean" />
+        <attr name="android:lineHeight" />
+    </declare-styleable>
+
+    <attr name="sudCardContainerStyle" format="reference" />
+    <attr name="sudCardTitleStyle" format="reference" />
+    <attr name="sudCardIconContainerStyle" format="reference" />
+    <attr name="sudCardIconStyle" format="reference" />
 </resources>
diff --git a/main/res/values/colors.xml b/main/res/values/colors.xml
index 58bce17..e663c3c 100644
--- a/main/res/values/colors.xml
+++ b/main/res/values/colors.xml
@@ -16,7 +16,7 @@
 -->
 
 <resources xmlns:tools="http://schemas.android.com/tools"
-    tools:keep="@color/sud_system_accent*,@color/sud_system_neutral*">
+    tools:keep="@color/sud_system_*">
 
     <!-- General colors -->
     <color name="sud_color_accent_dark">#ff448aff</color>
@@ -204,24 +204,127 @@
     <color name="sud_neutral90">#ffe3e3e3</color>
 
 
+    <color name="sud_color_primary">@color/sud_system_primary_light</color>
+    <color name="sud_system_on_primary">@color/sud_system_on_primary_light</color>
+    <color name="sud_on_secondary_container">@color/sud_system_on_secondary_container_light</color>
     <color name="sud_color_on_surface">@color/sud_neutral10</color>
+    <color name="sud_color_surface_container_high">@color/sud_system_surface_container_high_light</color>
     <color name="sud_color_surface_container_highest">@color/sud_neutral90</color>
+    <color name="sud_on_surface_variant">@color/sud_system_on_surface_variant_light</color>
 
     <!-- Glif expressive style -->
-    <!-- Default color for the footer bg (transparent) -->
-    <color name="sud_glif_expressive_footer_bar_bg_color">#00000000</color>
-    <!-- Default color for the footer button bg (primary40) -->
-    <color name="sud_glif_expressive_footer_button_bg_color">#ff6750a4</color>
+    <!-- Default color for the footer button bg -->
+    <color name="sud_glif_expressive_footer_button_bg_color">@color/sud_color_primary</color>
 
     <!-- Default color for the floating back button-->
     <color name="sud_glif_expressive_back_button_bg_color">@color/sud_color_surface_container_highest</color>
     <color name="sud_glif_expressive_ic_back_arrow_color">@color/sud_color_on_surface</color>
-    <!-- white -->
-    <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@android:color/white</color>
-    <!-- neutral_variant30 -->
-    <color name="sud_glif_expressive_footer_primary_button_disable_text_color">#ff49454f</color>
-    <!-- secondary10 -->
-    <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">#ff1d192b</color>
-    <!-- neutral_variant30 -->
-    <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">#ff49454f</color>
+    <color name="sud_glif_expressive_footer_primary_button_enable_text_color">@color/sud_system_on_primary</color>
+    <color name="sud_glif_expressive_footer_primary_button_disable_text_color">@color/sud_on_surface_variant</color>
+    <color name="sud_glif_expressive_footer_secondary_button_enable_text_color">@color/sud_on_secondary_container</color>
+    <color name="sud_glif_expressive_footer_secondary_button_disable_text_color">@color/sud_on_surface_variant</color>
+
+  <!-- Light dynamic system palette -->
+  <color name="sud_system_primary_light">#ff006b5f</color>
+  <color name="sud_system_on_primary_light">#ffffffff</color>
+  <color name="sud_system_primary_container_light">#ffc5eae2</color>
+  <color name="sud_system_on_primary_container_light">#ff00201c</color>
+  <color name="sud_system_primary_inverse_light">#ff83d6c7</color>
+  <color name="sud_system_primary_fixed_light">#ffc5eae2</color>
+  <color name="sud_system_primary_fixed_dim_light">#ff82d5c6</color>
+  <color name="sud_system_on_primary_fixed_light">#ff00201c</color>
+  <color name="sud_system_on_primary_fixed_variant_light">#ff005047</color>
+
+  <color name="sud_system_secondary_light">#ff4a635e</color>
+  <color name="sud_system_on_secondary_light">#ffffffff</color>
+  <color name="sud_system_secondary_container_light">#ffcce8e2</color>
+  <color name="sud_system_on_secondary_container_light">#ff051f1b</color>
+  <color name="sud_system_secondary_fixed_light">#ffcce8e2</color>
+  <color name="sud_system_secondary_fixed_dim_light">#ffb1ccc6</color>
+  <color name="sud_system_on_secondary_fixed_light">#ff051f1b</color>
+  <color name="sud_system_on_secondary_fixed_variant_light">#ff334c47</color>
+
+  <color name="sud_system_tertiary_light">#ff456179</color>
+  <color name="sud_system_on_tertiary_light">#ffffffff</color>
+  <color name="sud_system_tertiary_container_light">#ffcb16ff</color>
+  <color name="sud_system_on_tertiary_container_light">#ff001e31</color>
+  <color name="sud_system_tertiary_fixed_light">#ffcbe5ff</color>
+  <color name="sud_system_tertiary_fixed_dim_light">#ffadcae5</color>
+  <color name="sud_system_on_tertiary_fixed_light">#ff001e31</color>
+  <color name="sud_system_on_tertiary_fixed_variant_light">#ff2d4a60</color>
+
+  <color name="sud_system_error_light">#ffb3261e</color>
+  <color name="sud_system_on_error_light">#ffffffff</color>
+  <color name="sud_system_error_container_light">#fff9dedc</color>
+  <color name="sud_system_on_error_container_light">#ff3a0a08</color>
+  <color name="sud_system_outline_light">#ff777777</color>
+  <color name="sud_system_outline_variant_light">#ffc7c6c5</color>
+  <color name="sud_system_background_light">#fff9faf8</color>
+  <color name="sud_system_on_background_light">#ff1b1b1b</color>
+  <color name="sud_system_surface_light">#fff9faf8</color>
+  <color name="sud_system_on_surface_light">#ff1b1b1b</color>
+  <color name="sud_system_surface_variant_light">#ffe3e3e3</color>
+  <color name="sud_system_on_surface_variant_light">#ff474747</color>
+  <color name="sud_system_surface_inverse_light">#ff303030</color>
+  <color name="sud_system_on_surface_inverse_light">#fff1f1f1</color>
+  <color name="sud_system_surface_bright_light">#fff9faf8</color>
+  <color name="sud_system_surface_dim_light">#ffdadada</color>
+  <color name="sud_system_surface_container_light">#ffeeeeee</color>
+  <color name="sud_system_surface_container_low_light">#fff4f4f4</color>
+  <color name="sud_system_surface_container_lowest_light">#ffffffff</color>
+  <color name="sud_system_surface_container_high_light">#ffe8e8e8</color>
+  <color name="sud_system_surface_container_highest_light">#ffe3e3e3</color>
+
+
+  <!-- Dark dynamic system palette -->
+  <color name="sud_system_primary_dark">#ff83d6c7</color>
+  <color name="sud_system_on_primary_dark">#ff003730</color>
+  <color name="sud_system_primary_container_dark">#ff005047</color>
+  <color name="sud_system_on_primary_container_dark">#ffa1f1e2</color>
+  <color name="sud_system_primary_inverse_dark">#ff006b5f</color>
+  <color name="sud_system_primary_fixed_dark">#ffc5eae2</color>
+  <color name="sud_system_primary_fixed_dim_dark">#ff82d5c6</color>
+  <color name="sud_system_on_primary_fixed_dark">#ff00201c</color>
+  <color name="sud_system_on_primary_fixed_variant_dark">#ff005047</color>
+
+  <color name="sud_system_secondary_dark">#ffb1ccc6</color>
+  <color name="sud_system_on_secondary_dark">#ff1c342f</color>
+  <color name="sud_system_secondary_container_dark">#ff334c47</color>
+  <color name="sud_system_on_secondary_container_dark">#ffcce8e2</color>
+  <color name="sud_system_secondary_fixed_dark">#ffcce8e2</color>
+  <color name="sud_system_secondary_fixed_dim_dark">#ffb1ccc6</color>
+  <color name="sud_system_on_secondary_fixed_dark">#ff051f1b</color>
+  <color name="sud_system_on_secondary_fixed_variant_dark">#ff334c47</color>
+
+  <color name="sud_system_tertiary_dark">#ffadcae5</color>
+  <color name="sud_system_on_tertiary_dark">#ff123349</color>
+  <color name="sud_system_tertiary_container_dark">#ff2d4960</color>
+  <color name="sud_system_on_tertiary_container_dark">#ffcee7ff</color>
+  <color name="sud_system_tertiary_fixed_dark">#ffcbe5ff</color>
+  <color name="sud_system_tertiary_fixed_dim_dark">#ffadcae5</color>
+  <color name="sud_system_on_tertiary_fixed_dark">#ff001e31</color>
+  <color name="sud_system_on_tertiary_fixed_variant_dark">#ff2d4a60</color>
+
+  <color name="sud_system_error_dark">#fff2b8b5</color>
+  <color name="sud_system_on_error_dark">#ff601410</color>
+  <color name="sud_system_error_container_dark">#ff8c1d18</color>
+  <color name="sud_system_on_error_container_dark">#fff9dedc</color>
+  <color name="sud_system_outline_dark">#ff919191</color>
+  <color name="sud_system_outline_variant_dark">#ff474747</color>
+  <color name="sud_system_background_dark">#ff131313</color>
+  <color name="sud_system_on_background_dark">#ffe5e2e1</color>
+  <color name="sud_system_surface_dark">#ff131313</color>
+  <color name="sud_system_on_surface_dark">#ffe5e2e1</color>
+  <color name="sud_system_surface_variant_dark">#ff474747</color>
+  <color name="sud_system_on_surface_variant_dark">#ffc7c7c7</color>
+  <color name="sud_system_surface_inverse_dark">#ffe5e2e1</color>
+  <color name="sud_system_on_surface_inverse_dark">#ff303030</color>
+  <color name="sud_system_surface_bright_dark">#ff393939</color>
+  <color name="sud_system_surface_dim_dark">#ff131313</color>
+  <color name="sud_system_surface_container_dark">#ff1f1f1f</color>
+  <color name="sud_system_surface_container_low_dark">#ff1b1b1b</color>
+  <color name="sud_system_surface_container_lowest_dark">#ff0e0e0e</color>
+  <color name="sud_system_surface_container_high_dark">#ff2a2a2a</color>
+  <color name="sud_system_surface_container_highest_dark">#ff343434</color>
+
 </resources>
diff --git a/main/res/values/config.xml b/main/res/values/config.xml
index bb1a88f..1ad4f2e 100644
--- a/main/res/values/config.xml
+++ b/main/res/values/config.xml
@@ -35,8 +35,11 @@
     <item name="sud_layout_description" type="id" />
 
     <!-- Glif expressive button styles -->
-    <string name="sudExpressiveButtonFontFamily" translatable="false">Roboto</string>
+    <string name="sudExpressiveButtonFontFamily" translatable="false">google-sans-text-medium</string>
 
     <!-- Glif expressive alert dialog styles -->
     <string name="sudGlifExpressiveDialogFontFamily" translatable="false">google-sans-text</string>
+
+    <!-- Glif card view styles -->
+    <string name="sudCardViewFontFamily" translatable="false">google-sans-text</string>
 </resources>
diff --git a/main/res/values/dimens.xml b/main/res/values/dimens.xml
index da71a0e..4941c77 100644
--- a/main/res/values/dimens.xml
+++ b/main/res/values/dimens.xml
@@ -156,6 +156,7 @@
 
     <!-- Account information -->
     <dimen name="sud_account_name_text_size">14sp</dimen>
+    <dimen name="sud_account_name_text_spacing_extra">6sp</dimen>
     <dimen name="sud_account_avatar_margin_end">8dp</dimen>
     <dimen name="sud_account_avatar_max_height">24dp</dimen>
 
@@ -244,6 +245,20 @@
     <dimen name="sud_items_summary_margin_top_material_you">4dp</dimen>
     <dimen name="sud_items_min_height_material_you">72dp</dimen>
 
+    <!-- Bullet Point-->
+    <dimen name="sud_bullet_point_padding_top">16dp</dimen>
+    <dimen name="sud_bullet_point_padding_bottom">16dp</dimen>
+    <dimen name="sud_bullet_point_icon_padding_end">16dp</dimen>
+
+    <!-- Info footer-->
+    <dimen name="sud_info_footer_padding_top">16dp</dimen>
+    <dimen name="sud_info_footer_padding_bottom">16dp</dimen>
+    <dimen name="sud_info_footer_icon_padding_end">16dp</dimen>
+    <dimen name="sud_info_footer_icon_padding_bottom">8dp</dimen>
+    <dimen name="sud_info_footer_icon_size">18dp</dimen>
+    <dimen name="sud_info_footer_text_size">14sp</dimen>
+    <dimen name="sud_info_footer_text_line_spacing_extra">6sp</dimen>
+
     <!-- Progress bar -->
     <dimen name="sud_progress_bar_margin_top_material_you">16dp</dimen>
     <dimen name="sud_progress_bar_margin_bottom_material_you">-7dp</dimen>
@@ -327,16 +342,18 @@
     <!-- Page Margins Glif Expressive -->
     <dimen name="sud_glif_expressive_margin_start">24dp</dimen>
     <dimen name="sud_glif_expressive_margin_end">24dp</dimen>
+    <dimen name="sud_glif_expressive_land_middle_horizontal_spacing">24dp</dimen>
 
-    <dimen name="sud_glif_expressive_footer_padding_vertical">8dp</dimen>
-    <dimen name="sud_glif_expressive_footer_bar_min_height">72dp</dimen>
-    <dimen name="sud_glif_expressive_footer_bar_padding_vertical">6dp</dimen>
-    <dimen name="sud_glif_expressive_footer_bar_padding_start">8dp</dimen>
-    <dimen name="sud_glif_expressive_footer_bar_padding_end">20dp</dimen>
-    <dimen name="sud_glif_expressive_footer_button_min_height">56dp</dimen>
-    <dimen name="sud_glif_expressive_footer_button_radius">28dp</dimen>
-    <dimen name="sud_glif_expressive_footer_button_text_size">16sp</dimen>
-    <dimen name="sud_glif_expressive_footer_button_text_line_spacing_extra">8dp</dimen>
+    <!-- Items Expressive -->
+    <dimen name="sud_items_summary_margin_top_expressive">0dp</dimen>
+    <dimen name="sud_items_icon_container_width_expressive">52dp</dimen>
+    <dimen name="sud_items_min_height_expressive">56dp</dimen>
+    <dimen name="sud_items_summary_text_size_expressive">14sp</dimen>
+    <dimen name="sud_items_title_text_size_expressive">16sp</dimen>
+    <dimen name="sud_items_padding_top_expressive">12dp</dimen>
+    <dimen name="sud_items_padding_bottom_expressive">12dp</dimen>
+    <dimen name="sud_items_padding_bottom_extra_expressive">0dp</dimen>
+    <dimen name="sud_items_expand_button_size">40dp</dimen>
 
     <dimen name="sud_glif_expressive_button_padding">16dp</dimen>
     <!-- Calculated by (sud_glif_expressive_margin_start - 4dp internal padding of button) -->
@@ -347,35 +364,90 @@
     <dimen name="sud_glif_expreesive_description_margin_bottom">0dp</dimen>
     <dimen name="sud_glif_expressive_icon_margin_top">8dp</dimen>
     <dimen name="sud_glif_expressive_content_padding_top">8dp</dimen>
-    <dimen name="sud_glif_expressive_item_margin_start">16dp</dimen>
-    <dimen name="sud_glif_expressive_item_margin_end">16dp</dimen>
-    <dimen name="sud_glif_expressive_item_corner_radius">2dp</dimen>
+    <dimen name="sud_glif_expressive_item_corner_radius">4dp</dimen>
+    <dimen name="sud_glif_expressive_promo_card_icon_corner_radius">20dp</dimen>
+    <dimen name="sud_glif_expressive_promo_card_icon_padding">18dp</dimen>
+    <dimen name="sud_glif_expressive_promo_card_icon_margin_end">16dp</dimen>
     <dimen name="sud_glif_expressive_item_icon_padding_end">12dp</dimen>
-    <dimen name="sud_items_summary_text_size_expressive">14sp</dimen>
-    <dimen name="sud_items_title_text_size_expressive">16sp</dimen>
+    <dimen name="sud_glif_expressive_items_icon_padding_top">-4dp</dimen>
+    <dimen name="sud_glif_expressive_items_icon_padding_bottom">-4dp</dimen>
+    <dimen name="sud_glif_expressive_items_icon_padding_start">0dp</dimen>
+    <dimen name="sud_glif_expressive_items_icon_padding_end">0dp</dimen>
+    <dimen name="sud_glif_expressive_items_icon_width">40dp</dimen>
+    <dimen name="sud_glif_expressive_list_divider_height">24dp</dimen>
+    <dimen name="sud_items_section_header_padding_top">20dp</dimen>
+    <dimen name="sud_items_section_header_padding_bottom">8dp</dimen>
+    <dimen name="sud_items_section_header_text_size">14sp</dimen>
+    <dimen name="sud_items_illustration_item_padding_bottom">32dp</dimen>
+    <dimen name="sud_items_illustration_item_max_width">494dp</dimen>
     <dimen name="sud_expressive_switch_padding_start">12dp</dimen>
-    <dimen name="sud_glif_expressive_footer_button_middle_spacing">8dp</dimen>
 
     <!-- Header layout expressive -->
-    <dimen name="sud_glif_expressive_header_title_line_spacing_extra">8sp</dimen>
+    <dimen name="sud_glif_expressive_header_title_size">32sp</dimen>
+    <dimen name="sud_glif_expressive_header_title_line_height">40sp</dimen>
+    <dimen name="sud_glif_expressive_description_text_size">16sp</dimen>
+    <dimen name="sud_glif_expressive_description_line_spacing_extra">8sp</dimen>
 
-    <!-- Progress indicator-->
+    <!-- Progress indicator -->
     <dimen name="sud_glif_expressive_progress_indicator_margin_vertical">16dp</dimen>
     <dimen name="sud_glif_expressive_progress_indicator_padding_bottom">7dp</dimen>
 
-    <!-- Material floating back button-->
+    <!-- Material floating back button -->
     <dimen name="sud_glif_expressive_back_button_margin_top">8dp</dimen>
     <dimen name="sud_glif_expressive_back_button_height">48dp</dimen>
 
+    <!-- Glif expressive Additional body text -->
+    <dimen name="sud_glif_expressive_additional_body_text_size">16sp</dimen>
+    <dimen name="sud_glif_expressive_additional_body_text_line_spacing_extra">8sp</dimen>
+    <dimen name="sud_additional_body_text_padding_bottom">32dp</dimen>
+
+    <!-- Glif expressive Info footer -->
+    <dimen name="sud_glif_expressive_info_footer_icon_size">24dp</dimen>
+
     <!-- Glif expressive footer bar -->
     <!-- footer bar padding -->
     <!-- TODO: b/365906034 - Add padding attributes and values to the SUW side. -->
+    <dimen name="sud_glif_expressive_footer_bar_min_height">72dp</dimen>
     <!-- Calculated by (Spec = 24dp - 4dp internal padding of button) -->
-    <dimen name="sud_glif_expressive_footer_padding_start">20dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_start">20dp</dimen>
     <!-- Calculated by (Spec = 24dp - 4dp internal padding of button) -->
-    <dimen name="sud_glif_expressive_footer_padding_end">20dp</dimen>
+    <dimen name="sud_glif_expressive_footer_bar_padding_end">20dp</dimen>
+    <dimen name="sud_glif_expressive_footer_button_min_height">56dp</dimen>
+    <dimen name="sud_glif_expressive_footer_button_radius">28dp</dimen>
+    <dimen name="sud_glif_expressive_footer_button_text_size">16sp</dimen>
+    <dimen name="sud_glif_expressive_footer_button_text_line_spacing_extra">8dp</dimen>
+    <dimen name="sud_glif_expressive_footer_button_middle_spacing">8dp</dimen>
     <dimen name="sud_glif_expressive_footer_padding_top">16dp</dimen>
     <dimen name="sud_glif_expressive_footer_padding_bottom">8dp</dimen>
     <!-- Glif expressive alert dialog -->
     <dimen name="sud_glif_expressive_alert_dialog_title_font_size">24sp</dimen>
+
+    <!-- GLif card view styles -->
+    <!-- Card view container -->
+    <dimen name="sud_card_view_container_padding_start">16dp</dimen>
+    <dimen name="sud_card_view_container_padding_end">16dp</dimen>
+    <dimen name="sud_card_view_container_min_height">100dp</dimen>
+    <dimen name="sud_card_view_container_default_radius">12dp</dimen>
+    <!-- TODO: b/390040419 - Update card view's corner radius to 12dp for AOSP. -->
+    <!-- Set 999dp to make radius to be full radius -->
+    <dimen name="sud_card_view_container_selected_radius">999dp</dimen>
+    <!-- Card view icon -->
+    <dimen name="sud_card_view_icon_size">24dp</dimen>
+    <dimen name="sud_card_view_icon_container_margin_top">16dp</dimen>
+    <!-- Card view title -->
+    <dimen name="sud_card_view_title_text_size">14sp</dimen>
+    <dimen name="sud_card_view_title_line_spacing_extra">6sp</dimen>
+    <dimen name="sud_card_view_title_spacing_top">4dp</dimen>
+    <dimen name="sud_card_view_title_margin_bottom">16dp</dimen>
+
+    <!-- Camera preview -->
+    <dimen name="sud_expressive_camera_preview_corner_radius">28dp</dimen>
+    <dimen name="sud_expressive_camera_preview_padding">8dp</dimen>
+
+    <!-- Glif expressive progress indicator -->
+    <dimen name="sud_glif_expressive_progress_indicator_waveAmplitude">3dp</dimen>
+    <dimen name="sud_glif_expressive_progress_indicator_wavelength">40dp</dimen>
+    <dimen name="sud_glif_expressive_progress_indicator_wavelength_indeterminate">30dp</dimen>
+    <item name="sud_glif_expressive_progress_indicator_indeterminate_animator_duration_scale" format="float" type="dimen">1.5</item>
+
 </resources>
diff --git a/main/res/values/integers.xml b/main/res/values/integers.xml
index f0c81f0..2bfc8bc 100644
--- a/main/res/values/integers.xml
+++ b/main/res/values/integers.xml
@@ -20,4 +20,7 @@
     <!-- Glif expressive button styles -->
     <integer name="sud_glif_expressive_footer_button_weight">500</integer>
 
+    <!-- Glif expressive account name font weight -->
+    <integer name="sud_glif_account_name_text_font_weight">600</integer>
+
 </resources>
\ No newline at end of file
diff --git a/main/res/values/styles.xml b/main/res/values/styles.xml
index 992777f..b260ccb 100644
--- a/main/res/values/styles.xml
+++ b/main/res/values/styles.xml
@@ -56,6 +56,17 @@
         <item name="sudItemDescriptionStyle">@style/SudItemContainer.Description</item>
         <item name="sudItemDescriptionTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemBackground">@null</item>
+        <item name="sudItemBackgroundPaddingStart">@dimen/sud_items_background_padding_start</item>
+        <item name="sudItemBackgroundPaddingEnd">@dimen/sud_items_background_padding_end</item>
+        <item name="sudItemDividerWidth">@dimen/sud_items_divder_width</item>
+        <item name="sudItemBackgroundFirst">@null</item>
+        <item name="sudItemBackgroundLast">@null</item>
+        <item name="sudItemBackgroundSingle">@null</item>
+        <item name="sudNonActionableItemBackground">@null</item>
+        <item name="sudNonActionableItemBackgroundFirst">@null</item>
+        <item name="sudNonActionableItemBackgroundLast">@null</item>
+        <item name="sudNonActionableItemBackgroundSingle">@null</item>
+        <item name="sudListDividerHeight">0dp</item>
         <item name="sudListItemIconColor">@color/sud_list_item_icon_color_dark</item>
         <item name="sudMarginStart">@dimen/sud_layout_margin_sides</item>
         <item name="sudMarginEnd">@dimen/sud_layout_margin_sides</item>
@@ -65,10 +76,19 @@
         <item name="sudContentIllustrationMaxHeight">@dimen/sud_content_illustration_max_height</item>
         <item name="sudContentIllustrationPaddingTop">@dimen/sud_content_illustration_padding_vertical</item>
         <item name="sudContentIllustrationPaddingBottom">@dimen/sud_content_illustration_padding_vertical</item>
+        <item name="sudContentIllustrationStyle">@style/SudContentIllustration</item>
         <item name="sudLoadingHeaderHeight">@dimen/sud_loading_header_height</item>
         <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
         <item name="sudEditBoxColor">@color/sud_color_accent_dark</item>
         <item name="sudItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudNonActionableItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudBulletPointIconContainerStyle">@style/sudBulletPointIconContainer</item>
+        <item name="sudBulletPointContainerStyle">@style/sudBulletPointContainer</item>
+        <item name="sudAdditionalBodyTextStyle">@style/SudAdditionalBodyText</item>
+        <item name="sudInfoFooterContainerStyle">@style/sudInfoFooterContainer</item>
+        <item name="sudInfoFooterIconContainerStyle">@style/sudInfoFooterIconContainer</item>
+        <item name="sudInfoFooterIconStyle">@style/sudInfoFooterIcon</item>
+        <item name="sudInfoFooterTitleStyle">@style/sudInfoFooterTitle</item>
         <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
         <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
         <item name="sudItemPaddingTop">@dimen/sud_items_padding_top</item>
@@ -80,6 +100,25 @@
         <item name="sudItemTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryGlif</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
+        <item name="sudSectionItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
+        <item name="sudIllustrationItemStyle">@style/SudItemSummary.IllustrationStyle</item>
+        <item name="sudSectionItemTitleStyle">@style/SudItemTitle.SectionHeader</item>
+        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
+        <item name="sudPromoItemBackground">@drawable/sud_item_background</item>
+        <item name="sudPromoItemContainerStyle">@style/SudPromoItemContainer</item>
+        <item name="sudPromoCardIconBackgroundColor">@color/sud_system_secondary_fixed_dim_light</item>
+        <item name="sudPromoItemIconContainerStyle">@style/SudPromoItemIconContainer</item>
+        <item name="sudPromoItemTitleStyle">@style/SudPromoItemTitle</item>
+        <item name="sudPromoItemSummaryStyle">@style/SudPromoItemSummary</item>
+        <item name="sudCardContainerStyle">@style/SudCardContainerStyle</item>
+        <item name="sudCardIconContainerStyle">@style/SudCardIconContainerStyle</item>
+        <item name="sudCardIconStyle">@style/SudCardIconStyle</item>
+        <item name="sudCardTitleStyle">@style/SudCardTitleStyle</item>
+        <item name="sudCameraPreviewStyle">@null</item>
+        <item name="sudItemIconStyle">@style/SudItemIcon</item>
+        <item name="sudQrFinishStyle">@null</item>
     </style>
 
     <style name="SudThemeMaterial.Light" parent="Theme.AppCompat.Light.NoActionBar">
@@ -119,6 +158,17 @@
         <item name="sudItemDescriptionStyle">@style/SudItemContainer.Description</item>
         <item name="sudItemDescriptionTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemBackground">@null</item>
+        <item name="sudItemBackgroundPaddingStart">@dimen/sud_items_background_padding_start</item>
+        <item name="sudItemBackgroundPaddingEnd">@dimen/sud_items_background_padding_end</item>
+        <item name="sudItemDividerWidth">@dimen/sud_items_divder_width</item>
+        <item name="sudItemBackgroundFirst">@null</item>
+        <item name="sudItemBackgroundLast">@null</item>
+        <item name="sudItemBackgroundSingle">@null</item>
+        <item name="sudNonActionableItemBackground">@null</item>
+        <item name="sudNonActionableItemBackgroundFirst">@null</item>
+        <item name="sudNonActionableItemBackgroundLast">@null</item>
+        <item name="sudNonActionableItemBackgroundSingle">@null</item>
+        <item name="sudListDividerHeight">0dp</item>
         <item name="sudListItemIconColor">@color/sud_list_item_icon_color_light</item>
         <item name="sudMarginStart">@dimen/sud_layout_margin_sides</item>
         <item name="sudMarginEnd">@dimen/sud_layout_margin_sides</item>
@@ -128,10 +178,19 @@
         <item name="sudContentIllustrationMaxHeight">@dimen/sud_content_illustration_max_height</item>
         <item name="sudContentIllustrationPaddingTop">@dimen/sud_content_illustration_padding_vertical</item>
         <item name="sudContentIllustrationPaddingBottom">@dimen/sud_content_illustration_padding_vertical</item>
+        <item name="sudContentIllustrationStyle">@style/SudContentIllustration</item>
         <item name="sudLoadingHeaderHeight">@dimen/sud_loading_header_height</item>
         <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
         <item name="sudEditBoxColor">@color/sud_color_accent_light</item>
         <item name="sudItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudNonActionableItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudBulletPointIconContainerStyle">@style/sudBulletPointIconContainer</item>
+        <item name="sudBulletPointContainerStyle">@style/sudBulletPointContainer</item>
+        <item name="sudAdditionalBodyTextStyle">@style/SudAdditionalBodyText</item>
+        <item name="sudInfoFooterContainerStyle">@style/sudInfoFooterContainer</item>
+        <item name="sudInfoFooterIconContainerStyle">@style/sudInfoFooterIconContainer</item>
+        <item name="sudInfoFooterIconStyle">@style/sudInfoFooterIcon</item>
+        <item name="sudInfoFooterTitleStyle">@style/sudInfoFooterTitle</item>
         <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
         <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
         <item name="sudItemPaddingTop">@dimen/sud_items_padding_top</item>
@@ -143,6 +202,25 @@
         <item name="sudItemTitleStyle">@style/SudItemTitle</item>
         <item name="sudItemSummaryStyle">@style/SudItemSummaryGlif</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
+        <item name="sudSectionItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
+        <item name="sudIllustrationItemStyle">@style/SudItemSummary.IllustrationStyle</item>
+        <item name="sudSectionItemTitleStyle">@style/SudItemTitle.SectionHeader</item>
+        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
+        <item name="sudPromoItemBackground">@drawable/sud_item_background</item>
+        <item name="sudPromoItemContainerStyle">@style/SudPromoItemContainer</item>
+        <item name="sudPromoCardIconBackgroundColor">@color/sud_system_secondary_fixed_dim_light</item>
+        <item name="sudPromoItemIconContainerStyle">@style/SudPromoItemIconContainer</item>
+        <item name="sudPromoItemTitleStyle">@style/SudPromoItemTitle</item>
+        <item name="sudPromoItemSummaryStyle">@style/SudPromoItemSummary</item>
+        <item name="sudCardContainerStyle">@style/SudCardContainerStyle</item>
+        <item name="sudCardIconContainerStyle">@style/SudCardIconContainerStyle</item>
+        <item name="sudCardIconStyle">@style/SudCardIconStyle</item>
+        <item name="sudCardTitleStyle">@style/SudCardTitleStyle</item>
+        <item name="sudItemIconStyle">@style/SudItemIcon</item>
+        <item name="sudCameraPreviewStyle">@null</item>
+        <item name="sudQrFinishStyle">@null</item>
     </style>
 
     <style name="SudBaseThemeGlif" parent="Theme.AppCompat.NoActionBar">
@@ -233,10 +311,12 @@
         <item name="sucFooterBarButtonFontWeight">@integer/sud_glif_footer_button_weight</item>
         <item name="sucFooterBarButtonTextSize">@dimen/sud_glif_footer_button_text_size</item>
         <item name="sucFooterButtonTextLineSpacingExtra">@dimen/sud_glif_footer_button_line_spacing_extra</item>
+        <item name="sucFooterBarButtonOutlinedColor">@color/sud_system_outline_variant_dark</item>
         <item name="sudContentIllustrationMaxWidth">@dimen/sud_content_illustration_max_width</item>
         <item name="sudContentIllustrationMaxHeight">@dimen/sud_content_illustration_max_height</item>
         <item name="sudContentIllustrationPaddingTop">@dimen/sud_content_illustration_padding_vertical</item>
         <item name="sudContentIllustrationPaddingBottom">@dimen/sud_content_illustration_padding_vertical</item>
+        <item name="sudContentIllustrationStyle">@style/SudContentIllustration</item>
         <item name="sudLoadingHeaderHeight">@dimen/sud_loading_header_height</item>
         <item name="sudSwitchBarThumbOnColor">@color/sud_switch_thumb_on_dark</item>
         <item name="sudSwitchBarTrackOnColor">@color/sud_switch_track_on_dark</item>
@@ -246,6 +326,7 @@
         <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
         <item name="sudEditBoxColor">@color/sud_color_accent_glif_dark</item>
         <item name="sudItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudNonActionableItemContainerStyle">@style/SudItemContainer</item>
         <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
         <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
         <item name="sudItemPaddingTop">@dimen/sud_items_padding_top</item>
@@ -258,11 +339,45 @@
         <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
         <item name="sudItemVerboseTitleStyle">@style/SudItemTitle.Verbose</item>
+        <item name="sudItemBackgroundPaddingStart">@dimen/sud_items_background_padding_start</item>
+        <item name="sudItemBackgroundPaddingEnd">@dimen/sud_items_background_padding_end</item>
+        <item name="sudItemDividerWidth">@dimen/sud_items_divder_width</item>
         <item name="sudItemBackground">@null</item>
         <item name="sudItemBackgroundFirst">@null</item>
         <item name="sudItemBackgroundLast">@null</item>
         <item name="sudItemBackgroundSingle">@null</item>
+        <item name="sudNonActionableItemBackground">@null</item>
+        <item name="sudNonActionableItemBackgroundFirst">@null</item>
+        <item name="sudNonActionableItemBackgroundLast">@null</item>
+        <item name="sudNonActionableItemBackgroundSingle">@null</item>
         <item name="sudItemCornerRadius">0dp</item>
+        <item name="sudListDividerHeight">0dp</item>
+        <item name="sudBulletPointIconContainerStyle">@style/sudBulletPointIconContainer</item>
+        <item name="sudBulletPointContainerStyle">@style/sudBulletPointContainer</item>
+        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
+        <item name="sudSectionItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
+        <item name="sudIllustrationItemStyle">@style/SudItemSummary.IllustrationStyle</item>
+        <item name="sudSectionItemTitleStyle">@style/SudItemTitle.SectionHeader</item>
+        <item name="sudAdditionalBodyTextStyle">@style/SudAdditionalBodyText</item>
+        <item name="sudInfoFooterContainerStyle">@style/sudInfoFooterContainer</item>
+        <item name="sudInfoFooterIconContainerStyle">@style/sudInfoFooterIconContainer</item>
+        <item name="sudInfoFooterIconStyle">@style/sudInfoFooterIcon</item>
+        <item name="sudInfoFooterTitleStyle">@style/sudInfoFooterTitle</item>
+        <item name="sudCardContainerStyle">@style/SudCardContainerStyle</item>
+        <item name="sudCardIconContainerStyle">@style/SudCardIconContainerStyle</item>
+        <item name="sudCardIconStyle">@style/SudCardIconStyle</item>
+        <item name="sudCardTitleStyle">@style/SudCardTitleStyle</item>
+        <item name="sudPromoItemBackground">@drawable/sud_item_background</item>
+        <item name="sudPromoItemContainerStyle">@style/SudPromoItemContainer</item>
+        <item name="sudPromoCardIconBackgroundColor">@color/sud_system_secondary_fixed_dim_light</item>
+        <item name="sudPromoItemIconContainerStyle">@style/SudPromoItemIconContainer</item>
+        <item name="sudPromoItemTitleStyle">@style/SudPromoItemTitle</item>
+        <item name="sudPromoItemSummaryStyle">@style/SudPromoItemSummary</item>
+        <item name="sudItemIconStyle">@style/SudItemIcon</item>
+        <item name="sudCameraPreviewStyle">@null</item>
+        <item name="sudQrFinishStyle">@null</item>
     </style>
     <style name="SudThemeGlif" parent="SudBaseThemeGlif"/>
 
@@ -354,10 +469,12 @@
         <item name="sucFooterBarButtonFontWeight">@integer/sud_glif_footer_button_weight</item>
         <item name="sucFooterBarButtonTextSize">@dimen/sud_glif_footer_button_text_size</item>
         <item name="sucFooterButtonTextLineSpacingExtra">@dimen/sud_glif_footer_button_line_spacing_extra</item>
+        <item name="sucFooterBarButtonOutlinedColor">@color/sud_system_outline_variant_light</item>
         <item name="sudContentIllustrationMaxWidth">@dimen/sud_content_illustration_max_width</item>
         <item name="sudContentIllustrationMaxHeight">@dimen/sud_content_illustration_max_height</item>
         <item name="sudContentIllustrationPaddingTop">@dimen/sud_content_illustration_padding_vertical</item>
         <item name="sudContentIllustrationPaddingBottom">@dimen/sud_content_illustration_padding_vertical</item>
+        <item name="sudContentIllustrationStyle">@style/SudContentIllustration</item>
         <item name="sudLoadingHeaderHeight">@dimen/sud_loading_header_height</item>
         <item name="sudSwitchBarThumbOnColor">@color/sud_switch_thumb_on_light</item>
         <item name="sudSwitchBarTrackOnColor">@color/sud_switch_track_on_light</item>
@@ -367,6 +484,7 @@
         <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
         <item name="sudEditBoxColor">@color/sud_color_accent_glif_light</item>
         <item name="sudItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudNonActionableItemContainerStyle">@style/SudItemContainer</item>
         <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
         <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
         <item name="sudItemPaddingTop">@dimen/sud_items_padding_top</item>
@@ -379,11 +497,45 @@
         <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudDescription</item>
         <item name="sudItemVerboseTitleStyle">@style/SudItemTitle.Verbose</item>
+        <item name="sudItemBackgroundPaddingStart">@dimen/sud_items_background_padding_start</item>
+        <item name="sudItemBackgroundPaddingEnd">@dimen/sud_items_background_padding_end</item>
+        <item name="sudItemDividerWidth">@dimen/sud_items_divder_width</item>
         <item name="sudItemBackground">@null</item>
         <item name="sudItemBackgroundFirst">@null</item>
         <item name="sudItemBackgroundLast">@null</item>
         <item name="sudItemBackgroundSingle">@null</item>
+        <item name="sudNonActionableItemBackground">@null</item>
+        <item name="sudNonActionableItemBackgroundFirst">@null</item>
+        <item name="sudNonActionableItemBackgroundLast">@null</item>
+        <item name="sudNonActionableItemBackgroundSingle">@null</item>
         <item name="sudItemCornerRadius">0dp</item>
+        <item name="sudListDividerHeight">0dp</item>
+        <item name="sudBulletPointIconContainerStyle">@style/sudBulletPointIconContainer</item>
+        <item name="sudBulletPointContainerStyle">@style/sudBulletPointContainer</item>
+        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
+        <item name="sudSectionItemContainerStyle">@style/SudItemContainer</item>
+        <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
+        <item name="sudIllustrationItemStyle">@style/SudItemSummary.IllustrationStyle</item>
+        <item name="sudSectionItemTitleStyle">@style/SudItemTitle.SectionHeader</item>
+        <item name="sudAdditionalBodyTextStyle">@style/SudAdditionalBodyText</item>
+        <item name="sudInfoFooterContainerStyle">@style/sudInfoFooterContainer</item>
+        <item name="sudInfoFooterIconContainerStyle">@style/sudInfoFooterIconContainer</item>
+        <item name="sudInfoFooterIconStyle">@style/sudInfoFooterIcon</item>
+        <item name="sudInfoFooterTitleStyle">@style/sudInfoFooterTitle</item>
+        <item name="sudCardContainerStyle">@style/SudCardContainerStyle</item>
+        <item name="sudCardIconContainerStyle">@style/SudCardIconContainerStyle</item>
+        <item name="sudCardIconStyle">@style/SudCardIconStyle</item>
+        <item name="sudCardTitleStyle">@style/SudCardTitleStyle</item>
+        <item name="sudPromoItemBackground">@drawable/sud_item_background</item>
+        <item name="sudPromoItemContainerStyle">@style/SudPromoItemContainer</item>
+        <item name="sudPromoCardIconBackgroundColor">@color/sud_system_secondary_fixed_dim_light</item>
+        <item name="sudPromoItemIconContainerStyle">@style/SudPromoItemIconContainer</item>
+        <item name="sudPromoItemTitleStyle">@style/SudPromoItemTitle</item>
+        <item name="sudPromoItemSummaryStyle">@style/SudPromoItemSummary</item>
+        <item name="sudItemIconStyle">@style/SudItemIcon</item>
+        <item name="sudCameraPreviewStyle">@null</item>
+        <item name="sudQrFinishStyle">@null</item>
     </style>
     <style name="SudThemeGlif.Light" parent="SudBaseThemeGlif.Light"/>
 
@@ -485,6 +637,7 @@
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudMaterialYouDescription</item>
         <item name="sudDividerShown">false</item>
         <item name="sudItemContainerStyle">@style/SudItemContainerMaterialYou</item>
+        <item name="sudNonActionableItemContainerStyle">@style/SudItemContainerMaterialYou</item>
         <item name="sudItemPaddingTop">@dimen/sud_items_padding_top_material_you</item>
         <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
         <item name="sudItemTitleStyle">@style/SudItemTitleMaterialYou</item>
@@ -527,6 +680,7 @@
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudMaterialYouDescription</item>
         <item name="sudDividerShown">false</item>
         <item name="sudItemContainerStyle">@style/SudItemContainerMaterialYou</item>
+        <item name="sudNonActionableItemContainerStyle">@style/SudItemContainerMaterialYou</item>
         <item name="sudItemPaddingTop">@dimen/sud_items_padding_top_material_you</item>
         <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
         <item name="sudItemTitleStyle">@style/SudItemTitleMaterialYou</item>
@@ -540,22 +694,26 @@
         <item name="android:alertDialogTheme">@style/SudMaterialYouAlertDialogTheme.Light</item>
     </style>
 
-    <style name="SudBaseThemeGlifExpressive" parent="Theme.Material3.Dark.NoActionBar">
+    <style name="SudBaseThemeGlifExpressive" parent="Theme.Material3.DynamicColors.Dark.NoActionBar">
         <!-- Copied from values style SudThemeBaseGlif -->
         <item name="android:indeterminateTint" tools:ignore="NewApi">?attr/colorControlActivated</item>
+        <!-- Ensure that the navigation bar has enough contrast when a fully transparent background
+             is requested. This is disabled for 3-button mode navigation bar color. -->
+        <item name="android:enforceNavigationBarContrast" tools:ignore="NewApi">false</item>
+        <item name="android:windowOptOutEdgeToEdgeEnforcement" tools:targetApi="35">false</item>
         <!-- Specify the indeterminateTintMode to work around a bug in Lollipop -->
         <item name="android:indeterminateTintMode" tools:ignore="NewApi">src_in</item>
         <item name="android:listPreferredItemHeight">@dimen/sud_items_preferred_height</item>
-        <item name="android:listPreferredItemPaddingEnd" tools:ignore="NewApi">@dimen/sud_glif_expressive_item_margin_start</item>
-        <item name="android:listPreferredItemPaddingStart" tools:ignore="NewApi">@dimen/sud_glif_expressive_item_margin_start</item>
+        <item name="android:listPreferredItemPaddingEnd" tools:ignore="NewApi">?attr/sudMarginEnd</item>
+        <item name="android:listPreferredItemPaddingStart" tools:ignore="NewApi">?attr/sudMarginStart</item>
         <item name="android:statusBarColor" tools:ignore="NewApi">@android:color/transparent</item>
         <item name="android:windowAnimationStyle">@style/Animation.SudWindowAnimation</item>
         <item name="android:windowDisablePreview">true</item>
         <item name="android:windowSoftInputMode">adjustResize</item>
         <item name="android:colorError" tools:targetApi="26">@color/sud_color_error_text_dark</item>
         <item name="android:scrollbarThumbVertical">?attr/sudScrollBarThumb</item>
-        <item name="listPreferredItemPaddingLeft">@dimen/sud_glif_expressive_item_margin_start</item>
-        <item name="listPreferredItemPaddingRight">@dimen/sud_glif_expressive_item_margin_end</item>
+        <item name="listPreferredItemPaddingLeft">?attr/sudMarginStart</item>
+        <item name="listPreferredItemPaddingRight">?attr/sudMarginEnd</item>
         <item name="sudButtonHighlightAlpha">0.24</item>
         <item name="sudColorPrimary">?attr/colorPrimary</item>
         <item name="sudContentFramePaddingTop">@dimen/sud_content_frame_padding_top</item>
@@ -565,10 +723,11 @@
         <item name="sudLoadingContentFramePaddingEnd">@dimen/sud_content_loading_frame_padding_end</item>
         <item name="sudLoadingContentFramePaddingBottom">@dimen/sud_content_loading_frame_padding_bottom</item>
         <item name="sudFillContentLayoutStyle">@style/SudFillContentLayout</item>
-        <item name="sudGlifAccountNameStyle">@style/SudGlifAccountName</item>
+        <item name="sudGlifAccountNameStyle">@style/SudGlifExpressiveAccountName</item>
         <item name="sudGlifAccountAvatarSize">@dimen/sud_account_avatar_max_height</item>
         <item name="sudGlifAccountAvatarStyle">@style/SudGlifAccountAvatar</item>
         <item name="sudAccountNameTextSize">@dimen/sud_account_name_text_size</item>
+        <item name="sudAccountNameTextColor">@color/sud_system_on_surface_dark</item>
         <item name="sudGlifIconStyle">@style/SudGlifIcon</item>
         <item name="sudListItemIconColor">@color/sud_list_item_icon_color_dark</item>
         <item name="sudScrollBarThumb">@drawable/sud_scroll_bar_dark</item>
@@ -581,15 +740,14 @@
         <item name="sudContentIllustrationMaxHeight">@dimen/sud_content_illustration_max_height</item>
         <item name="sudContentIllustrationPaddingTop">@dimen/sud_content_illustration_padding_vertical</item>
         <item name="sudContentIllustrationPaddingBottom">@dimen/sud_content_illustration_padding_vertical</item>
+        <item name="sudContentIllustrationStyle">@style/SudContentIllustration.GlifExpressive</item>
         <item name="sudLoadingHeaderHeight">@dimen/sud_loading_header_height</item>
         <item name="sudSwitchBarThumbOnColor">@color/sud_switch_thumb_on_dark</item>
         <item name="sudSwitchBarTrackOnColor">@color/sud_switch_track_on_dark</item>
         <item name="sudSwitchBarThumbOffColor">@color/sud_switch_thumb_off_dark</item>
         <item name="sudSwitchBarTrackOffColor">@color/sud_switch_track_off_dark</item>
         <item name="sudSwitchBarTrackOffOutlineColor">@color/sud_switch_track_outline_off_dark</item>
-        <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
-        <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
-        <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
+        <item name="sudEditBoxStyle">@style/SudGlifExpressiveEditBoxTheme</item>
         <item name="sudAccountAvatarMarginEnd">@dimen/sud_account_avatar_margin_end</item>
         <item name="sudAccountAvatarMaxHeight">@dimen/sud_account_avatar_max_height</item>
 
@@ -626,21 +784,18 @@
         <item name="sudGlifIconGravity">center_horizontal</item>
         <item name="sucGlifHeaderMarginTop">@dimen/sud_glif_header_title_margin_top_material_you</item>
         <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_header_title_margin_bottom_material_you</item>
-        <item name="sudGlifDescriptionStyle">@style/SudGlifDescriptionMaterialYou</item>
+        <item name="sudGlifDescriptionStyle">@style/SudGlifDescriptionExpressive</item>
         <item name="sudGlifDescriptionMarginBottom">@dimen/sud_glif_expreesive_description_margin_bottom</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudMaterialYouDescription</item>
         <item name="sudDividerShown">false</item>
         <item name="sudItemPaddingTop">@dimen/sud_items_padding_top_material_you</item>
         <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
-        <item name="sudItemTitleStyle">@style/SudItemTitleMaterialYou</item>
-        <item name="sudItemSummaryStyle">@style/SudItemSummaryMaterialYou</item>
         <item name="sudItemDescriptionTitleStyle">@style/SudItemTitleMaterialYou</item>
         <item name="sudItemDescriptionStyle">@style/SudItemContainerMaterialYou.Description</item>
         <item name="sudItemDescriptionPaddingTop">@dimen/sud_description_glif_margin_top</item>
         <item name="sudItemDescriptionPaddingBottom">@dimen/sud_description_glif_margin_bottom_lists</item>
         <item name="sudItemVerboseTitleStyle">@style/SudMaterialYouItemTitle.Verbose</item>
-        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
-        <item name="sudItemSummaryPaddingTop">@dimen/sud_items_summary_margin_top_material_you</item>
+        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra_expressive</item>
         <item name="alertDialogTheme">@style/SudMaterialYouAlertDialogThemeCompat</item>
         <item name="android:alertDialogTheme">@style/SudMaterialYouAlertDialogTheme</item>
         <!-- new values for style SudBaseThemeGlifExpressive -->
@@ -653,19 +808,20 @@
         <item name="sucGlifIconMarginTop">@dimen/sud_glif_expressive_icon_margin_top</item>
         <item name="sudGlifDescriptionMarginTop">@dimen/sud_glif_expressive_description_margin_top</item>
         <item name="sucFooterBarButtonFontFamily">@string/sudExpressiveButtonFontFamily</item>
-        <item name="sudFooterBackgroundColor">@color/sud_glif_expressive_footer_bar_bg_color</item>
+        <item name="sudFooterBackgroundColor">@color/sud_system_surface_container_high_dark</item>
         <item name="sucFooterBarPrimaryFooterBackground">@color/sud_glif_expressive_footer_button_bg_color</item>
         <item name="sucFooterBarButtonMiddleSpacing">@dimen/sud_glif_expressive_footer_button_middle_spacing</item>
         <item name="sudItemDividerWidth">@dimen/sud_items_divder_width</item>
         <item name="sudItemBackgroundPaddingStart">@dimen/sud_items_background_padding_start</item>
         <item name="sudItemBackgroundPaddingEnd">@dimen/sud_items_background_padding_end</item>
         <item name="sudItemContainerStyle">@style/SudGlifExpressiveItemContainer</item>
+        <item name="sudNonActionableItemContainerStyle">@style/SudGlifExpressiveItemContainer.NonActionable</item>
         <item name="sucFooterBarPrimaryFooterButtonEnabledTextColor">@color/sud_glif_expressive_footer_primary_button_enable_text_color</item>
         <item name="sucFooterBarPrimaryFooterButtonDisabledTextColor">@color/sud_glif_expressive_footer_primary_button_disable_text_color</item>
         <item name="sucFooterBarSecondaryFooterButtonEnabledTextColor">@color/sud_glif_expressive_footer_secondary_button_enable_text_color</item>
         <item name="sucFooterBarSecondaryFooterButtonDisabledTextColor">@color/sud_glif_expressive_footer_secondary_button_disable_text_color</item>
-        <item name="sucFooterBarPaddingStart">@dimen/sud_glif_expressive_footer_padding_start</item>
-        <item name="sucFooterBarPaddingEnd">@dimen/sud_glif_expressive_footer_padding_end</item>
+        <item name="sucFooterBarPaddingStart">@dimen/sud_glif_expressive_footer_bar_padding_start</item>
+        <item name="sucFooterBarPaddingEnd">@dimen/sud_glif_expressive_footer_bar_padding_end</item>
         <item name="sucFooterBarPaddingTop">@dimen/sud_glif_expressive_footer_padding_top</item>
         <item name="sucFooterBarPaddingBottom">@dimen/sud_glif_expressive_footer_padding_bottom</item>
         <item name="sucFooterBarButtonMinHeight">@dimen/sud_glif_expressive_footer_button_min_height</item>
@@ -674,32 +830,74 @@
         <item name="sudItemBackgroundLast">@drawable/sud_item_background_last</item>
         <item name="sudItemBackgroundSingle">@drawable/sud_item_background_single</item>
         <item name="sudItemCornerRadius">@dimen/sud_glif_expressive_item_corner_radius</item>
+        <item name="sudListDividerHeight">@dimen/sud_glif_expressive_list_divider_height</item>
         <item name="sudItemBackgroundColor" tools:ignore="NewApi">?attr/colorSurfaceBright</item>
+        <item name="sudNonActionableItemBackground">@drawable/sud_non_actionable_item_background</item>
+        <item name="sudNonActionableItemBackgroundFirst">@drawable/sud_non_actionable_item_background_first</item>
+        <item name="sudNonActionableItemBackgroundLast">@drawable/sud_non_actionable_item_background_last</item>
+        <item name="sudNonActionableItemBackgroundSingle">@drawable/sud_non_actionable_item_background_single</item>
+        <item name="sudNonActionableItemBackgroundColor" tools:ignore="NewApi">?attr/colorSurfaceContainerHigh</item>
+        <item name="sudItemTitleStyle">@style/SudItemTitleExpressive</item>
+        <item name="sudItemSummaryStyle">@style/SudItemSummaryExpressive</item>
+        <item name="sudItemSummaryPaddingTop">@dimen/sud_items_summary_margin_top_expressive</item>
+        <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width_expressive</item>
+        <item name="sudBulletPointIconContainerStyle">@style/sudBulletPointIconContainer</item>
+        <item name="sudBulletPointContainerStyle">@style/sudBulletPointContainer</item>
+        <item name="sudAdditionalBodyTextStyle">@style/SudAdditionalBodyTextExpressive</item>
+        <item name="sudInfoFooterContainerStyle">@style/sudInfoFooterContainerExpressive</item>
+        <item name="sudInfoFooterIconContainerStyle">@style/sudInfoFooterIconContainer</item>
+        <item name="sudInfoFooterIconStyle">@style/sudInfoFooterIconExpressive</item>
+        <item name="sudInfoFooterTitleStyle">@style/sudInfoFooterTitle</item>
         <item name="sucFooterBarButtonFontWeight">@integer/sud_glif_expressive_footer_button_weight</item>
         <item name="sudButtonCornerRadius">@dimen/sud_glif_expressive_footer_button_radius</item>
         <item name="sucFooterBarButtonTextSize">@dimen/sud_glif_expressive_footer_button_text_size</item>
         <item name="sucFooterButtonTextLineSpacingExtra">@dimen/sud_glif_expressive_footer_button_text_line_spacing_extra</item>
+        <item name="sucFooterBarButtonOutlinedColor">@color/sud_system_outline_variant_dark</item>
+        <item name="sudItemIconContainerStyle">@style/SudExpressiveItemIconContainer</item>
         <item name="textAppearanceListItem">@style/TextAppearance.SudExpressiveItemTitle</item>
         <item name="textAppearanceListItemSmall">@style/TextAppearance.SudExpressiveItemSummary</item>
         <item name="materialAlertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
-    </style>
-
-    <style name="SudBaseThemeGlifExpressive.Light" parent="Theme.Material3.Light.NoActionBar">
+        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
+        <item name="sudSectionItemContainerStyle">@style/SudGlifExpressiveItemContainer.SectionItem</item>
+        <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
+        <item name="sudIllustrationItemStyle">@style/SudItemSummary.IllustrationStyle</item>
+        <item name="sudSectionItemTitleStyle">@style/SudExpressiveItemTitle.SectionHeader</item>
+        <item name="sudCardContainerStyle">@style/SudCardContainerStyle</item>
+        <item name="sudCardIconContainerStyle">@style/SudCardIconContainerStyle</item>
+        <item name="sudCardIconStyle">@style/SudCardIconStyle</item>
+        <item name="sudCardTitleStyle">@style/SudCardTitleStyle</item>
+        <item name="sudPromoItemContainerStyle">@style/SudPromoItemContainer</item>
+        <item name="sudPromoItemBackground">@drawable/sud_item_background</item>
+        <item name="sudPromoCardIconBackgroundColor">@color/sud_system_secondary_fixed_dim_dark</item>
+        <item name="sudPromoItemIconContainerStyle">@style/SudPromoItemIconContainer</item>
+        <item name="sudPromoItemTitleStyle">@style/SudPromoItemTitle</item>
+        <item name="sudPromoItemSummaryStyle">@style/SudPromoItemSummary</item>
+        <item name="sudItemIconStyle">@style/SudExpressiveItemIcon</item>
+        <item name="sudCameraPreviewStyle">@style/SudExpressiveCameraPreview</item>
+        <item name="sudQrFinishStyle">@style/SudExpressiveQrFinish</item>
+    </style>
+
+    <style name="SudBaseThemeGlifExpressive.Light" parent="Theme.Material3.DynamicColors.Light.NoActionBar">
         <!-- Copied from values style SudThemeBaseGlif.Light -->
         <item name="android:indeterminateTint" tools:ignore="NewApi">?attr/colorControlActivated</item>
+        <!-- Ensure that the navigation bar has enough contrast when a fully transparent background
+             is requested. This is disabled for 3-button mode navigation bar color. -->
+        <item name="android:enforceNavigationBarContrast" tools:ignore="NewApi">false</item>
+        <item name="android:windowOptOutEdgeToEdgeEnforcement" tools:targetApi="35">false</item>
         <!-- Specify the indeterminateTintMode to work around a bug in Lollipop -->
         <item name="android:indeterminateTintMode" tools:ignore="NewApi">src_in</item>
         <item name="android:listPreferredItemHeight">@dimen/sud_items_preferred_height</item>
-        <item name="android:listPreferredItemPaddingEnd" tools:ignore="NewApi">@dimen/sud_glif_expressive_item_margin_start</item>
-        <item name="android:listPreferredItemPaddingStart" tools:ignore="NewApi">@dimen/sud_glif_expressive_item_margin_start</item>
+        <item name="android:listPreferredItemPaddingEnd" tools:ignore="NewApi">?attr/sudMarginEnd</item>
+        <item name="android:listPreferredItemPaddingStart" tools:ignore="NewApi">?attr/sudMarginStart</item>
         <item name="android:statusBarColor" tools:ignore="NewApi">@android:color/transparent</item>
         <item name="android:windowAnimationStyle">@style/Animation.SudWindowAnimation</item>
         <item name="android:windowDisablePreview">true</item>
         <item name="android:windowSoftInputMode">adjustResize</item>
         <item name="android:colorError" tools:targetApi="26">@color/sud_color_error_text_light</item>
         <item name="android:scrollbarThumbVertical">?attr/sudScrollBarThumb</item>
-        <item name="listPreferredItemPaddingLeft">@dimen/sud_glif_expressive_item_margin_start</item>
-        <item name="listPreferredItemPaddingRight">@dimen/sud_glif_expressive_item_margin_end</item>
+        <item name="listPreferredItemPaddingLeft">?attr/sudMarginStart</item>
+        <item name="listPreferredItemPaddingRight">?attr/sudMarginEnd</item>
         <item name="sudButtonHighlightAlpha">0.12</item>
         <item name="sudColorPrimary">?attr/colorPrimary</item>
         <item name="sudContentFramePaddingTop">@dimen/sud_content_frame_padding_top</item>
@@ -709,10 +907,11 @@
         <item name="sudLoadingContentFramePaddingEnd">@dimen/sud_content_loading_frame_padding_end</item>
         <item name="sudLoadingContentFramePaddingBottom">@dimen/sud_content_loading_frame_padding_bottom</item>
         <item name="sudFillContentLayoutStyle">@style/SudFillContentLayout</item>
-        <item name="sudGlifAccountNameStyle">@style/SudGlifAccountName</item>
+        <item name="sudGlifAccountNameStyle">@style/SudGlifExpressiveAccountName</item>
         <item name="sudGlifAccountAvatarSize">@dimen/sud_account_avatar_max_height</item>
         <item name="sudGlifAccountAvatarStyle">@style/SudGlifAccountAvatar</item>
         <item name="sudAccountNameTextSize">@dimen/sud_account_name_text_size</item>
+        <item name="sudAccountNameTextColor">@color/sud_system_on_surface_light</item>
         <item name="sudGlifIconStyle">@style/SudGlifIcon</item>
         <item name="sudListItemIconColor">@color/sud_list_item_icon_color_light</item>
         <item name="sudScrollBarThumb">@drawable/sud_scroll_bar_light</item>
@@ -725,15 +924,14 @@
         <item name="sudContentIllustrationMaxHeight">@dimen/sud_content_illustration_max_height</item>
         <item name="sudContentIllustrationPaddingTop">@dimen/sud_content_illustration_padding_vertical</item>
         <item name="sudContentIllustrationPaddingBottom">@dimen/sud_content_illustration_padding_vertical</item>
+        <item name="sudContentIllustrationStyle">@style/SudContentIllustration.GlifExpressive</item>
         <item name="sudLoadingHeaderHeight">@dimen/sud_loading_header_height</item>
         <item name="sudSwitchBarThumbOnColor">@color/sud_switch_thumb_on_light</item>
         <item name="sudSwitchBarTrackOnColor">@color/sud_switch_track_on_light</item>
         <item name="sudSwitchBarThumbOffColor">@color/sud_switch_thumb_off_light</item>
         <item name="sudSwitchBarTrackOffColor">@color/sud_switch_track_off_light</item>
         <item name="sudSwitchBarTrackOffOutlineColor">@color/sud_switch_track_outline_off_light</item>
-        <item name="sudEditBoxStyle">@style/SudEditBoxTheme</item>
-        <item name="sudItemIconContainerStyle">@style/SudItemIconContainer</item>
-        <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width</item>
+        <item name="sudEditBoxStyle">@style/SudGlifExpressiveEditBoxTheme</item>
         <item name="sudAccountAvatarMarginEnd">@dimen/sud_account_avatar_margin_end</item>
         <item name="sudAccountAvatarMaxHeight">@dimen/sud_account_avatar_max_height</item>
 
@@ -769,16 +967,13 @@
         <item name="sudGlifIconGravity">center_horizontal</item>
         <item name="sucGlifHeaderMarginTop">@dimen/sud_glif_header_title_margin_top_material_you</item>
         <item name="sucGlifHeaderMarginBottom">@dimen/sud_glif_header_title_margin_bottom_material_you</item>
-        <item name="sudGlifDescriptionStyle">@style/SudGlifDescriptionMaterialYou</item>
+        <item name="sudGlifDescriptionStyle">@style/SudGlifDescriptionExpressive</item>
         <item name="sudGlifDescriptionMarginBottom">@dimen/sud_glif_expreesive_description_margin_bottom</item>
         <item name="sudItemDescriptionTitleTextAppearence">@style/TextAppearance.SudMaterialYouDescription</item>
         <item name="sudDividerShown">false</item>
         <item name="sudItemPaddingTop">@dimen/sud_items_padding_top_material_you</item>
         <item name="sudItemPaddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
-        <item name="sudItemTitleStyle">@style/SudItemTitleMaterialYou</item>
-        <item name="sudItemSummaryStyle">@style/SudItemSummaryMaterialYou</item>
-        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra</item>
-        <item name="sudItemSummaryPaddingTop">@dimen/sud_items_summary_margin_top_material_you</item>
+        <item name="sudItemSummaryPaddingBottom">@dimen/sud_items_padding_bottom_extra_expressive</item>
         <item name="sudItemDescriptionTitleStyle">@style/SudItemTitleMaterialYou</item>
         <item name="sudItemDescriptionStyle">@style/SudItemContainerMaterialYou.Description</item>
         <item name="sudItemDescriptionPaddingTop">@dimen/sud_description_glif_margin_top</item>
@@ -796,19 +991,20 @@
         <item name="sudGlifContentPaddingTop">@dimen/sud_glif_expressive_content_padding_top</item>
         <item name="sudGlifDescriptionMarginTop">@dimen/sud_glif_expressive_description_margin_top</item>
         <item name="sucFooterBarButtonFontFamily">@string/sudExpressiveButtonFontFamily</item>
-        <item name="sudFooterBackgroundColor">@color/sud_glif_expressive_footer_bar_bg_color</item>
+        <item name="sudFooterBackgroundColor">@color/sud_system_surface_container_high_light</item>
         <item name="sucFooterBarPrimaryFooterBackground">@color/sud_glif_expressive_footer_button_bg_color</item>
         <item name="sucFooterBarButtonMiddleSpacing">@dimen/sud_glif_expressive_footer_button_middle_spacing</item>
         <item name="sudItemDividerWidth">@dimen/sud_items_divder_width</item>
         <item name="sudItemBackgroundPaddingStart">@dimen/sud_items_background_padding_start</item>
         <item name="sudItemBackgroundPaddingEnd">@dimen/sud_items_background_padding_end</item>
         <item name="sudItemContainerStyle">@style/SudGlifExpressiveItemContainer</item>
+        <item name="sudNonActionableItemContainerStyle">@style/SudGlifExpressiveItemContainer.NonActionable</item>
         <item name="sucFooterBarPrimaryFooterButtonEnabledTextColor">@color/sud_glif_expressive_footer_primary_button_enable_text_color</item>
         <item name="sucFooterBarPrimaryFooterButtonDisabledTextColor">@color/sud_glif_expressive_footer_primary_button_disable_text_color</item>
         <item name="sucFooterBarSecondaryFooterButtonEnabledTextColor">@color/sud_glif_expressive_footer_secondary_button_enable_text_color</item>
         <item name="sucFooterBarSecondaryFooterButtonDisabledTextColor">@color/sud_glif_expressive_footer_secondary_button_disable_text_color</item>
-        <item name="sucFooterBarPaddingStart">@dimen/sud_glif_expressive_footer_padding_start</item>
-        <item name="sucFooterBarPaddingEnd">@dimen/sud_glif_expressive_footer_padding_end</item>
+        <item name="sucFooterBarPaddingStart">@dimen/sud_glif_expressive_footer_bar_padding_start</item>
+        <item name="sucFooterBarPaddingEnd">@dimen/sud_glif_expressive_footer_bar_padding_end</item>
         <item name="sucFooterBarPaddingTop">@dimen/sud_glif_expressive_footer_padding_top</item>
         <item name="sucFooterBarPaddingBottom">@dimen/sud_glif_expressive_footer_padding_bottom</item>
         <item name="sucFooterBarButtonMinHeight">@dimen/sud_glif_expressive_footer_button_min_height</item>
@@ -817,14 +1013,52 @@
         <item name="sudItemBackgroundLast">@drawable/sud_item_background_last</item>
         <item name="sudItemBackgroundSingle">@drawable/sud_item_background_single</item>
         <item name="sudItemCornerRadius">@dimen/sud_glif_expressive_item_corner_radius</item>
+        <item name="sudListDividerHeight">@dimen/sud_glif_expressive_list_divider_height</item>
         <item name="sudItemBackgroundColor" tools:ignore="NewApi">?attr/colorSurfaceBright</item>
+        <item name="sudNonActionableItemBackground">@drawable/sud_non_actionable_item_background</item>
+        <item name="sudNonActionableItemBackgroundFirst">@drawable/sud_non_actionable_item_background_first</item>
+        <item name="sudNonActionableItemBackgroundLast">@drawable/sud_non_actionable_item_background_last</item>
+        <item name="sudNonActionableItemBackgroundSingle">@drawable/sud_non_actionable_item_background_single</item>
+        <item name="sudNonActionableItemBackgroundColor" tools:ignore="NewApi">?attr/colorSurfaceContainerHigh</item>
+        <item name="sudItemTitleStyle">@style/SudItemTitleExpressive</item>
+        <item name="sudItemSummaryStyle">@style/SudItemSummaryExpressive</item>
+        <item name="sudItemSummaryPaddingTop">@dimen/sud_items_summary_margin_top_expressive</item>
+        <item name="sudItemIconContainerWidth">@dimen/sud_items_icon_container_width_expressive</item>
         <item name="sucFooterBarButtonFontWeight">@integer/sud_glif_expressive_footer_button_weight</item>
         <item name="sudButtonCornerRadius">@dimen/sud_glif_expressive_footer_button_radius</item>
         <item name="sucFooterBarButtonTextSize">@dimen/sud_glif_expressive_footer_button_text_size</item>
         <item name="sucFooterButtonTextLineSpacingExtra">@dimen/sud_glif_expressive_footer_button_text_line_spacing_extra</item>
+        <item name="sucFooterBarButtonOutlinedColor">@color/sud_system_outline_variant_light</item>
+        <item name="sudBulletPointIconContainerStyle">@style/sudBulletPointIconContainer</item>
+        <item name="sudAdditionalBodyTextStyle">@style/SudAdditionalBodyTextExpressive</item>
+        <item name="sudBulletPointContainerStyle">@style/sudBulletPointContainer</item>
+        <item name="sudInfoFooterContainerStyle">@style/sudInfoFooterContainerExpressive</item>
+        <item name="sudInfoFooterIconContainerStyle">@style/sudInfoFooterIconContainer</item>
+        <item name="sudInfoFooterIconStyle">@style/sudInfoFooterIconExpressive</item>
+        <item name="sudInfoFooterTitleStyle">@style/sudInfoFooterTitle</item>
+        <item name="sudItemIconContainerStyle">@style/SudExpressiveItemIconContainer</item>
         <item name="textAppearanceListItem">@style/TextAppearance.SudExpressiveItemTitle</item>
         <item name="textAppearanceListItemSmall">@style/TextAppearance.SudExpressiveItemSummary</item>
         <item name="materialAlertDialogTheme">@style/SudGlifExpressiveDialogTheme</item>
+        <item name="sudBulletPointTitleStyle">?attr/sudItemTitleStyle</item>
+        <item name="sudBulletPointSummaryStyle">?attr/sudItemSummaryStyle</item>
+        <item name="sudSectionItemContainerStyle">@style/SudGlifExpressiveItemContainer.SectionItem</item>
+        <item name="sudIllustrationItemContainerStyle">@style/SudItemContainer.IllustrationItem</item>
+        <item name="sudIllustrationItemStyle">@style/SudItemSummary.IllustrationStyle</item>
+        <item name="sudSectionItemTitleStyle">@style/SudExpressiveItemTitle.SectionHeader</item>
+        <item name="sudCardContainerStyle">@style/SudCardContainerStyle</item>
+        <item name="sudCardIconContainerStyle">@style/SudCardIconContainerStyle</item>
+        <item name="sudCardIconStyle">@style/SudCardIconStyle</item>
+        <item name="sudCardTitleStyle">@style/SudCardTitleStyle</item>
+        <item name="sudPromoItemBackground">@drawable/sud_item_background</item>
+        <item name="sudPromoItemContainerStyle">@style/SudPromoItemContainer</item>
+        <item name="sudPromoCardIconBackgroundColor">@color/sud_system_secondary_fixed_dim_light</item>
+        <item name="sudPromoItemIconContainerStyle">@style/SudPromoItemIconContainer</item>
+        <item name="sudPromoItemTitleStyle">@style/SudPromoItemTitle</item>
+        <item name="sudPromoItemSummaryStyle">@style/SudPromoItemSummary</item>
+        <item name="sudItemIconStyle">@style/SudExpressiveItemIcon</item>
+        <item name="sudCameraPreviewStyle">@style/SudExpressiveCameraPreview</item>
+        <item name="sudQrFinishStyle">@style/SudExpressiveQrFinish</item>
     </style>
 
     <style name="SudThemeGlifExpressive" parent="SudBaseThemeGlifExpressive" />
@@ -968,12 +1202,16 @@
         <item name="android:paddingBottom">?attr/sudContentIllustrationPaddingBottom</item>
     </style>
 
-    <!-- Ignore UnusedResources: used by clients -->
-    <style name="SudContentIllustration" tools:ignore="UnusedResources">
+    <style name="SudContentIllustration">
         <item name="android:layout_gravity">center</item>
         <item name="android:scaleType">fitCenter</item>
     </style>
 
+    <style name="SudContentIllustration.GlifExpressive">
+        <item name="android:layout_gravity">top</item>
+        <item name="android:scaleType">fitCenter</item>
+    </style>
+
     <!-- Card layout (for tablets) -->
 
     <style name="SudBaseCardTitle">
@@ -1138,6 +1376,10 @@
         <item name="boxCornerRadiusBottomEnd">@dimen/sud_edit_text_corner_radius</item>
     </style>
 
+    <style name="SudGlifExpressiveEditBoxTheme">
+        <item name="colorPrimary">?attr/sudEditBoxColor</item>
+    </style>
+
     <!-- Items styles -->
 
     <style name="SudItemContainer">
@@ -1161,25 +1403,60 @@
     </style>
 
     <style name="SudGlifExpressiveItemContainer">
-        <item name="android:layout_marginEnd" tools:ignore="NewApi">?attr/listPreferredItemPaddingRight</item>
+        <item name="android:layout_marginEnd" tools:ignore="NewApi">?android:attr/listPreferredItemPaddingEnd</item>
         <item name="android:layout_marginLeft">?attr/listPreferredItemPaddingLeft</item>
         <item name="android:layout_marginRight">?attr/listPreferredItemPaddingRight</item>
-        <item name="android:layout_marginStart" tools:ignore="NewApi">?attr/listPreferredItemPaddingLeft</item>
+        <item name="android:layout_marginStart" tools:ignore="NewApi">?android:attr/listPreferredItemPaddingStart</item>
         <item name="android:layout_marginBottom">?attr/sudItemDividerWidth</item>
         <item name="android:background">?attr/sudItemBackground</item>
-        <item name="android:paddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
+        <item name="android:paddingBottom">@dimen/sud_items_padding_bottom_expressive</item>
         <item name="android:paddingEnd" tools:ignore="NewApi">?attr/sudItemBackgroundPaddingEnd</item>
         <item name="android:paddingLeft">?attr/sudItemBackgroundPaddingStart</item>
         <item name="android:paddingRight">?attr/sudItemBackgroundPaddingEnd</item>
         <item name="android:paddingStart" tools:ignore="NewApi">?attr/sudItemBackgroundPaddingStart</item>
-        <item name="android:paddingTop">@dimen/sud_items_padding_top_material_you</item>
-        <item name="android:minHeight">@dimen/sud_items_min_height_material_you</item>
+        <item name="android:paddingTop">@dimen/sud_items_padding_top_expressive</item>
+        <item name="android:minHeight">@dimen/sud_items_min_height_expressive</item>
+    </style>
+
+    <style name="SudGlifExpressiveItemContainer.NonActionable" parent="SudGlifExpressiveItemContainer">
+        <item name="android:background">?attr/sudNonActionableItemBackground</item>
     </style>
 
     <style name="SudItemIconContainer">
         <item name="android:layout_width">?attr/sudItemIconContainerWidth</item>
     </style>
 
+    <style name="SudItemIcon">
+        <item name="android:layout_width">wrap_content</item>
+    </style>
+
+    <style name="SudExpressiveItemIcon">
+        <item name="android:layout_width">@dimen/sud_glif_expressive_items_icon_width</item>
+        <item name="android:gravity">center</item>
+    </style>
+
+    <style name="SudExpressiveItemIconContainer">
+        <item name="android:layout_width">?attr/sudItemIconContainerWidth</item>
+        <item name="android:paddingBottom">@dimen/sud_glif_expressive_items_icon_padding_bottom</item>
+        <item name="android:paddingEnd" tools:ignore="NewApi">@dimen/sud_glif_expressive_items_icon_padding_end</item>
+        <item name="android:paddingLeft">@dimen/sud_glif_expressive_items_icon_padding_start</item>
+        <item name="android:paddingRight">@dimen/sud_glif_expressive_items_icon_padding_end</item>
+        <item name="android:paddingStart" tools:ignore="NewApi">@dimen/sud_glif_expressive_items_icon_padding_start</item>
+        <item name="android:paddingTop">@dimen/sud_glif_expressive_items_icon_padding_top</item>
+        <item name="android:layout_gravity">center_vertical</item>
+        <item name="android:gravity">start</item>
+    </style>
+
+    <style name="sudBulletPointContainer">
+        <item name="android:paddingTop">@dimen/sud_bullet_point_padding_top</item>
+        <item name="android:paddingBottom">@dimen/sud_bullet_point_padding_bottom</item>
+    </style>
+
+    <style name="sudBulletPointIconContainer">
+        <item name="android:paddingRight">@dimen/sud_bullet_point_icon_padding_end</item>
+        <item name="android:paddingEnd">@dimen/sud_bullet_point_icon_padding_end</item>
+    </style>
+
     <style name="SudItemContainer.Description" parent="SudItemContainer">
         <item name="android:paddingTop">?attr/sudItemDescriptionPaddingTop</item>
         <item name="android:paddingBottom">?attr/sudItemDescriptionPaddingBottom</item>
@@ -1196,6 +1473,60 @@
         <item name="android:paddingTop">@dimen/sud_items_verbose_padding_vertical</item>
     </style>
 
+    <style name="SudGlifExpressiveItemContainer.SectionItem" parent="SudGlifExpressiveItemContainer">
+        <item name="android:paddingTop">@dimen/sud_items_section_header_padding_top</item>
+        <item name="android:paddingBottom">@dimen/sud_items_section_header_padding_bottom</item>
+        <item name="android:paddingLeft">0dp</item>
+        <item name="android:paddingRight">0dp</item>
+        <item name="android:paddingStart">0dp</item>
+        <item name="android:paddingEnd">0dp</item>
+        <item name="android:background">@null</item>
+    </style>
+
+    <style name="SudPromoItemContainer">
+        <item name="android:layout_marginBottom">?attr/sudItemDividerWidth</item>
+        <item name="android:background">?attr/sudPromoItemBackground</item>
+        <item name="android:paddingBottom">@dimen/sud_items_padding_bottom_material_you</item>
+        <item name="android:paddingEnd" tools:ignore="NewApi">?attr/sudItemBackgroundPaddingEnd</item>
+        <item name="android:paddingLeft">?attr/sudItemBackgroundPaddingStart</item>
+        <item name="android:paddingRight">?attr/sudItemBackgroundPaddingEnd</item>
+        <item name="android:paddingStart" tools:ignore="NewApi">?attr/sudItemBackgroundPaddingStart</item>
+        <item name="android:paddingTop">@dimen/sud_items_padding_top_material_you</item>
+        <item name="android:minHeight">@dimen/sud_items_min_height_material_you</item>
+    </style>
+    <style name="SudPromoItemIconContainer">
+        <item name="android:background">@drawable/sud_promo_card_icon_background</item>
+        <item name="android:paddingBottom">@dimen/sud_glif_expressive_promo_card_icon_padding</item>
+        <item name="android:paddingEnd" tools:ignore="NewApi">@dimen/sud_glif_expressive_promo_card_icon_padding</item>
+        <item name="android:paddingLeft">@dimen/sud_glif_expressive_promo_card_icon_padding</item>
+        <item name="android:paddingRight">@dimen/sud_glif_expressive_promo_card_icon_padding</item>
+        <item name="android:paddingStart" tools:ignore="NewApi">@dimen/sud_glif_expressive_promo_card_icon_padding</item>
+        <item name="android:paddingTop">@dimen/sud_glif_expressive_promo_card_icon_padding</item>
+        <item name="android:layout_marginRight">@dimen/sud_glif_expressive_promo_card_icon_margin_end</item>
+        <item name="android:layout_marginEnd" tools:ignore="NewApi">@dimen/sud_glif_expressive_promo_card_icon_margin_end</item>
+    </style>
+    <style name="SudPromoItemTitle">
+        <item name="android:textAppearance">?attr/textAppearanceListItem</item>
+        <item name="android:layout_marginBottom">@dimen/sud_items_summary_margin_top</item>
+    </style>
+    <style name="SudPromoItemSummary">
+        <item name="android:textAppearance">?attr/textAppearanceListItemSmall</item>
+    </style>
+
+    <style name="SudItemContainer.IllustrationItem" parent="SudItemContainer">
+        <item name="android:paddingTop">0dp</item>
+        <item name="android:paddingBottom">@dimen/sud_items_illustration_item_padding_bottom</item>
+        <item name="android:paddingLeft">0dp</item>
+        <item name="android:paddingRight">0dp</item>
+        <item name="android:gravity">center</item>
+        <item name="android:background">@null</item>
+    </style>
+
+    <style name="SudItemSummary.IllustrationStyle" parent="SudItemSummary">
+        <item name="android:maxWidth">@dimen/sud_items_illustration_item_max_width</item>
+        <item name="android:adjustViewBounds">true</item>
+    </style>
+
     <style name="SudItemSummary">
         <item name="android:textAppearance">?attr/textAppearanceListItemSmall</item>
     </style>
@@ -1211,6 +1542,11 @@
         <item name="android:layout_marginTop">?attr/sudItemSummaryPaddingTop</item>
     </style>
 
+    <style name="SudItemSummaryExpressive">
+        <item name="android:textAppearance">?attr/textAppearanceListItemSmall</item>
+        <item name="android:layout_marginBottom">?attr/sudItemSummaryPaddingBottom</item>
+    </style>
+
     <style name="SudItemContainerMaterialYou.Description" parent="SudItemContainerMaterialYou">
         <item name="android:minHeight">0dp</item>
         <item name="android:paddingTop">?attr/sudItemPaddingTop</item>
@@ -1225,6 +1561,11 @@
         <item name="android:textAppearance">?attr/textAppearanceListItem</item>
     </style>
 
+    <style name="SudItemTitleExpressive">
+        <item name="android:textAppearance">?attr/textAppearanceListItem</item>
+        <item name="android:layout_marginBottom">?attr/sudItemSummaryPaddingTop</item>
+    </style>
+
     <style name="SudItemTitle.GlifDescription" parent="SudItemTitle">
         <item name="android:gravity">?attr/sudGlifHeaderGravity</item>
         <item name="android:textAlignment">gravity</item>
@@ -1243,6 +1584,12 @@
         <item name="android:fontFamily">@string/sudFontSecondaryMedium</item>
     </style>
 
+    <style name="SudExpressiveItemTitle.SectionHeader" parent="SudItemTitle">
+        <item name="android:textSize">@dimen/sud_items_section_header_text_size</item>
+        <item name="android:fontFamily">@string/sudFontSecondaryMedium</item>
+        <item name="android:textColor">?attr/colorOnSurfaceVariant</item>
+    </style>
+
     <style name="SudSwitchStyle">
         <item name="android:paddingEnd" tools:ignore="NewApi">@dimen/sud_switch_padding_end</item>
         <item name="android:paddingLeft">@dimen/sud_switch_padding_start</item>
@@ -1260,6 +1607,17 @@
         <item name="android:textColor">?android:attr/textColorSecondary</item>
     </style>
 
+    <style name="SudExpressiveCameraPreview">
+        <item name="android:padding">@dimen/sud_expressive_camera_preview_padding</item>
+        <item name="android:background">@drawable/sud_camera_preview_background</item>
+    </style>
+
+    <style name="SudExpressiveQrFinish">
+        <item name="android:src">@drawable/sud_qr_finish_icon</item>
+        <item name="android:background">@color/sud_qr_finish_bg_color</item>
+        <item name="android:scaleType">center</item>
+    </style>
+
     <!-- GLIF layout -->
 
     <style name="SudGlifHeaderTitle" parent="SudBaseHeaderTitle">
@@ -1295,7 +1653,11 @@
     </style>
 
     <style name="SudGlifHeaderTitleExpressive" parent="SudGlifHeaderTitleMaterialYou">
-        <item name="android:lineSpacingExtra">@dimen/sud_glif_expressive_header_title_line_spacing_extra</item>
+        <item name="android:lineHeight" tools:targetApi="28">@dimen/sud_glif_expressive_header_title_line_height</item>
+        <item name="android:textSize">@dimen/sud_glif_expressive_header_title_size</item>
+        <item name="android:textFontWeight" tools:targetApi="28">500</item>
+        <item name="fontFamily">google-sans-flex</item>
+        <item name="android:fontFamily">google-sans-flex</item>
     </style>
 
     <style name="SudGlifDescription" parent="SudDescription.Glif">
@@ -1326,6 +1688,11 @@
         <item name="android:textSize">@dimen/sud_glif_description_text_size_material_you</item>
     </style>
 
+    <style name="SudGlifDescriptionExpressive" parent="SudGlifDescriptionMaterialYou">
+        <item name="android:textSize">@dimen/sud_glif_expressive_description_text_size</item>
+        <item name="android:lineSpacingExtra">@dimen/sud_glif_expressive_description_line_spacing_extra</item>
+    </style>
+
     <style name="SudGlifAccountContainerMaterialYou">
         <item name="android:layout_marginBottom">?attr/sucGlifHeaderMarginBottom</item>
         <item name="android:layout_marginTop">?attr/sucGlifHeaderMarginTop</item>
@@ -1352,6 +1719,15 @@
         <item name="android:layout_gravity">center_vertical</item>
     </style>
 
+    <style name="SudGlifExpressiveAccountName">
+        <item name="android:fontFamily">@string/sudFontSecondaryText</item>
+        <item name="android:textSize">?attr/sudAccountNameTextSize</item>
+        <item name="android:textColor">?attr/sudAccountNameTextColor</item>
+        <item name="android:textFontWeight" tools:ignore="NewApi">@integer/sud_glif_account_name_text_font_weight</item>
+        <item name="android:lineSpacingExtra">@dimen/sud_account_name_text_spacing_extra</item>
+        <item name="android:layout_gravity">center_vertical</item>
+    </style>
+
     <style name="SudGlifHeaderContainer">
         <item name="android:gravity">?attr/sudGlifHeaderGravity</item>
         <item name="android:layout_marginBottom">?attr/sucHeaderContainerMarginBottom</item>
@@ -1417,7 +1793,7 @@
 
     <style name="TextAppearance.SudExpressiveItemTitle" parent="android:TextAppearance">
         <item name="android:textSize">@dimen/sud_items_title_text_size_expressive</item>
-        <item name="android:fontFamily">@string/sudFontSecondaryText</item>
+        <item name="android:fontFamily">@string/sudFontSecondaryMediumMaterialYou</item>
         <item name="android:textColor">?android:attr/textColorPrimary</item>
     </style>
 
@@ -1438,6 +1814,57 @@
         <item name="android:textSize">@dimen/sud_items_title_text_size_material_you</item>
         <item name="android:fontFamily">@string/sudFontSecondary</item>
     </style>
+
+    <!-- Additional body text styles -->
+
+    <style name="SudAdditionalBodyTextExpressive">
+        <item name="android:fontFamily">@string/sudFontSecondaryText</item>
+        <item name="android:textSize">@dimen/sud_glif_expressive_additional_body_text_size</item>
+        <item name="android:lineSpacingExtra">@dimen/sud_glif_expressive_additional_body_text_line_spacing_extra</item>
+        <item name="android:textColor">@color/sud_color_on_surface</item>
+        <item name="android:paddingBottom">@dimen/sud_additional_body_text_padding_bottom</item>
+    </style>
+
+    <style name="SudAdditionalBodyText" parent="@style/TextAppearance.SudDescription.Secondary">
+        <item name="android:paddingBottom">@dimen/sud_additional_body_text_padding_bottom</item>
+    </style>
+
+    <!-- Info footer styles -->
+
+    <style name="sudInfoFooterContainer">
+        <item name="android:paddingTop">@dimen/sud_info_footer_padding_top</item>
+        <item name="android:paddingBottom">@dimen/sud_info_footer_padding_bottom</item>
+        <item name="android:orientation">horizontal</item>
+    </style>
+
+    <style name="sudInfoFooterContainerExpressive" parent="sudInfoFooterContainer">
+        <item name="android:orientation">vertical</item>
+    </style>
+
+    <style name="sudInfoFooterIconContainer">
+        <item name="android:paddingRight">@dimen/sud_info_footer_icon_padding_end</item>
+        <item name="android:paddingEnd">@dimen/sud_info_footer_icon_padding_end</item>
+        <item name="android:paddingBottom">@dimen/sud_info_footer_icon_padding_bottom</item>
+    </style>
+
+    <style name="sudInfoFooterIcon">
+        <item name="android:tint">@color/sud_color_on_surface</item>
+        <item name="android:layout_width">@dimen/sud_info_footer_icon_size</item>
+        <item name="android:layout_height">@dimen/sud_info_footer_icon_size</item>
+    </style>
+
+    <style name="sudInfoFooterIconExpressive" parent="sudInfoFooterIcon">
+        <item name="android:layout_width">@dimen/sud_glif_expressive_info_footer_icon_size</item>
+        <item name="android:layout_height">@dimen/sud_glif_expressive_info_footer_icon_size</item>
+    </style>
+
+    <style name="sudInfoFooterTitle">
+        <item name="android:textAppearance">?attr/textAppearanceListItem</item>
+        <item name="android:textSize">@dimen/sud_info_footer_text_size</item>
+        <item name="android:textColor">@color/sud_color_on_surface</item>
+        <item name="android:lineSpacingExtra">@dimen/sud_info_footer_text_line_spacing_extra</item>
+    </style>
+
     <!-- Navigation bar styles -->
 
     <style name="SudNavBarTheme">
@@ -1512,6 +1939,8 @@
         <item name="android:fontFamily">@string/sudGlifExpressiveDialogFontFamily</item>
     </style>
 
+    <style name="SudMaterialYouAlertDialogTheme.DayNight" parent="SudMaterialYouAlertDialogTheme.Light"/>
+
     <style name="SudDateTimePickerDialogTheme" parent="Theme.AppCompat.Dialog">
         <item name="android:textAllCaps">false</item>
         <item name="colorAccent">@color/sud_color_accent_glif_v3_dark</item>
@@ -1534,6 +1963,16 @@
         <item name="android:switchMinWidth">@dimen/sud_switch_min_width</item>
     </style>
 
+    <style name="SudExpressiveSwitchBarStyle">
+        <item name="android:layout_gravity">center_vertical|end</item>
+        <item name="track">@drawable/sud_switch_track_selector</item>
+        <item name="android:track">@drawable/sud_switch_track_selector</item>
+        <item name="android:thumb">@drawable/sud_switch_thumb_selector</item>
+        <item name="android:switchMinWidth">@dimen/sud_switch_min_width</item>
+        <item name="android:paddingStart">@dimen/sud_expressive_switch_padding_start</item>
+        <item name="android:paddingLeft">@dimen/sud_expressive_switch_padding_start</item>
+    </style>
+
     <style name="SudLandContentContianerStyle">
       <item name="android:layout_width">0dp</item>
       <item name="android:layout_height">match_parent</item>
@@ -1548,7 +1987,36 @@
     </style>
 
     <style name="SudLinearProgressIndicatorWavy">
-        <!-- TODO(b/379571805): Update after material library related attributes drop to main branch -->
+        <item name="waveAmplitude">@dimen/sud_glif_expressive_progress_indicator_waveAmplitude</item>
+        <item name="wavelength">@dimen/sud_glif_expressive_progress_indicator_wavelength</item>
+        <item name="wavelengthIndeterminate">@dimen/sud_glif_expressive_progress_indicator_wavelength_indeterminate</item>
+        <item name="indeterminateAnimatorDurationScale">@dimen/sud_glif_expressive_progress_indicator_indeterminate_animator_duration_scale</item>
+    </style>
+
+    <style name="SudCardContainerStyle">
+        <item name="android:background">@drawable/sud_card_view_container_background</item>
+        <item name="android:paddingStart">@dimen/sud_card_view_container_padding_start</item>
+        <item name="android:paddingEnd">@dimen/sud_card_view_container_padding_end</item>
+        <item name="android:minHeight">@dimen/sud_card_view_container_min_height</item>
+    </style>
+
+    <style name="SudCardIconContainerStyle">
+        <item name="android:layout_marginTop">@dimen/sud_card_view_icon_container_margin_top</item>
+    </style>
+
+    <style name="SudCardIconStyle">
+        <item name="android:layout_width">@dimen/sud_card_view_icon_size</item>
+        <item name="android:layout_height">@dimen/sud_card_view_icon_size</item>
+        <item name="android:tint">@color/sud_card_view_icon_color</item>
+    </style>
+
+    <style name="SudCardTitleStyle">
+        <item name="android:textSize">@dimen/sud_card_view_title_text_size</item>
+        <item name="android:fontFamily">@string/sudCardViewFontFamily</item>
+        <item name="android:lineSpacingExtra">@dimen/sud_card_view_title_line_spacing_extra</item>
+        <item name="android:textColor">@color/sud_card_view_text_color</item>
+        <item name="android:paddingTop">@dimen/sud_card_view_title_spacing_top</item>
+        <item name="android:layout_marginBottom">@dimen/sud_card_view_title_margin_bottom</item>
     </style>
 
 </resources>
diff --git a/main/src/com/google/android/setupdesign/GlifLayout.java b/main/src/com/google/android/setupdesign/GlifLayout.java
index b1bd41a..f8943c4 100644
--- a/main/src/com/google/android/setupdesign/GlifLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifLayout.java
@@ -26,13 +26,18 @@ import android.graphics.Color;
 import android.graphics.drawable.ColorDrawable;
 import android.graphics.drawable.Drawable;
 import android.os.Build;
+import android.os.Build.VERSION;
 import android.os.Build.VERSION_CODES;
+import android.os.Handler;
+import android.os.Looper;
+import android.os.PersistableBundle;
 import android.util.AttributeSet;
 import android.util.TypedValue;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.ViewStub;
+import android.view.ViewTreeObserver;
 import android.widget.LinearLayout;
 import android.widget.ProgressBar;
 import android.widget.ScrollView;
@@ -44,13 +49,18 @@ import androidx.annotation.Nullable;
 import androidx.annotation.StringRes;
 import androidx.window.embedding.ActivityEmbeddingController;
 import com.google.android.setupcompat.PartnerCustomizationLayout;
+import com.google.android.setupcompat.logging.CustomEvent;
+import com.google.android.setupcompat.logging.MetricKey;
+import com.google.android.setupcompat.logging.SetupMetricsLogger;
 import com.google.android.setupcompat.partnerconfig.PartnerConfig;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.template.FooterBarMixin;
 import com.google.android.setupcompat.template.StatusBarMixin;
+import com.google.android.setupcompat.template.SystemNavBarMixin;
 import com.google.android.setupcompat.util.ForceTwoPaneHelper;
 import com.google.android.setupcompat.util.KeyboardHelper;
 import com.google.android.setupcompat.util.Logger;
+import com.google.android.setupcompat.util.WizardManagerHelper;
 import com.google.android.setupdesign.template.DescriptionMixin;
 import com.google.android.setupdesign.template.FloatingBackButtonMixin;
 import com.google.android.setupdesign.template.HeaderMixin;
@@ -62,8 +72,6 @@ import com.google.android.setupdesign.template.RequireScrollMixin;
 import com.google.android.setupdesign.template.ScrollViewScrollHandlingDelegate;
 import com.google.android.setupdesign.util.DescriptionStyler;
 import com.google.android.setupdesign.util.LayoutStyler;
-import com.google.android.setupdesign.view.BottomScrollView;
-import com.google.android.setupdesign.view.BottomScrollView.BottomScrollListener;
 
 /**
  * Layout for the GLIF theme used in Setup Wizard for N.
@@ -94,6 +102,20 @@ public class GlifLayout extends PartnerCustomizationLayout {
 
   private boolean applyPartnerHeavyThemeResource = false;
 
+  private ViewTreeObserver.OnScrollChangedListener onScrollChangedListener =
+      new ViewTreeObserver.OnScrollChangedListener() {
+        @Override
+        public void onScrollChanged() {
+          ScrollView scrollView = getScrollView();
+          if (scrollView != null) {
+            // direction > 0 means view can scroll down, direction < 0 means view can scroll
+            // up. Here we use direction > 0 to detect whether the view can be scrolling down
+            // or not.
+            onScrolling(!scrollView.canScrollVertically(/* direction= */ 1));
+          }
+        }
+      };
+
   /** The color of the background. If null, the color will inherit from primaryColor. */
   @Nullable private ColorStateList backgroundBaseColor;
 
@@ -352,6 +374,32 @@ public class GlifLayout extends PartnerCustomizationLayout {
     return super.findContainer(containerId);
   }
 
+  @Override
+  protected void onDetachedFromWindow() {
+    super.onDetachedFromWindow();
+    // Log metrics of UI component
+    if (VERSION.SDK_INT >= Build.VERSION_CODES.Q
+        && WizardManagerHelper.isAnySetupWizard(activity.getIntent())
+        && PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
+
+      FloatingBackButtonMixin floatingBackButtonMixin = getMixin(FloatingBackButtonMixin.class);
+      PersistableBundle backButtonMetrics =
+          floatingBackButtonMixin != null
+              ? floatingBackButtonMixin.getMetrics()
+              : PersistableBundle.EMPTY;
+
+      CustomEvent customEvent =
+          CustomEvent.create(MetricKey.get("SetupDesignMetrics", activity), backButtonMetrics);
+      SetupMetricsLogger.logCustomEvent(getContext(), customEvent);
+
+      LOG.atVerbose("SetupDesignMetrics=" + CustomEvent.toBundle(customEvent));
+    }
+    ScrollView scrollView = getScrollView();
+    if (scrollView != null) {
+      scrollView.getViewTreeObserver().removeOnScrollChangedListener(onScrollChangedListener);
+    }
+  }
+
   /**
    * Sets the sticky header (i.e. header that doesn't scroll) of the layout, which is at the top of
    * the content area outside of the scrolling container. The header can only be inflated once per
@@ -589,35 +637,50 @@ public class GlifLayout extends PartnerCustomizationLayout {
     }
   }
 
+  // TODO: b/397835857 - Add unit test for initScrollingListener.
   protected void initScrollingListener() {
     ScrollView scrollView = getScrollView();
 
-    if (scrollView instanceof BottomScrollView) {
-      ((BottomScrollView) scrollView)
-          .setBottomScrollListener(
-              new BottomScrollListener() {
-                @Override
-                public void onScrolledToBottom() {
-                  onScrolling(true);
+    if (scrollView != null) {
+      scrollView.getViewTreeObserver().addOnScrollChangedListener(onScrollChangedListener);
+
+      // This is for the case that the view has been first visited to handle the initial state of
+      // the footer bar.
+      new Handler(Looper.getMainLooper())
+          .postDelayed(
+              () -> {
+                if (isContentScrollable(scrollView)) {
+                  onScrolling(/* isBottom= */ false);
                 }
+              },
+              100L);
+    }
+  }
 
-                @Override
-                public void onRequiresScroll() {
-                  onScrolling(false);
-                }
-              });
+  private boolean isContentScrollable(ScrollView scrollView) {
+    View child = scrollView.getChildAt(0);
+    if (child != null) {
+      return child.getHeight() > scrollView.getHeight();
     }
+    return false;
   }
 
   protected void onScrolling(boolean isBottom) {
     FooterBarMixin footerBarMixin = getMixin(FooterBarMixin.class);
+    SystemNavBarMixin systemNavBarMixin = getMixin(SystemNavBarMixin.class);
     if (footerBarMixin != null) {
       LinearLayout footerContainer = footerBarMixin.getButtonContainer();
       if (footerContainer != null) {
         if (isBottom) {
           footerContainer.setBackgroundColor(Color.TRANSPARENT);
+          if (systemNavBarMixin != null) {
+            systemNavBarMixin.setSystemNavBarBackground(Color.TRANSPARENT);
+          }
         } else {
           footerContainer.setBackgroundColor(getFooterBackgroundColorFromStyle());
+          if (systemNavBarMixin != null) {
+            systemNavBarMixin.setSystemNavBarBackground(getFooterBackgroundColorFromStyle());
+          }
         }
       }
     }
diff --git a/main/src/com/google/android/setupdesign/GlifListLayout.java b/main/src/com/google/android/setupdesign/GlifListLayout.java
index 566eefd..bcae593 100644
--- a/main/src/com/google/android/setupdesign/GlifListLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifListLayout.java
@@ -84,10 +84,6 @@ public class GlifListLayout extends GlifLayout {
     }
     updateLandscapeMiddleHorizontalSpacing();
 
-    if (PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
-      initScrollingListener();
-    }
-
     initBackButton();
   }
 
@@ -95,6 +91,9 @@ public class GlifListLayout extends GlifLayout {
   protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
     super.onLayout(changed, left, top, right, bottom);
     listMixin.onLayout();
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
+      initScrollingListener();
+    }
   }
 
   @Override
@@ -132,9 +131,6 @@ public class GlifListLayout extends GlifLayout {
     ListView listView = null;
     if (listMixin != null) {
       listView = listMixin.getListView();
-    }
-
-    if (listView != null) {
       listView.setOnScrollListener(
           new OnScrollListener() {
             @Override
diff --git a/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java b/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java
index bb9d739..49b3055 100644
--- a/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java
@@ -25,6 +25,7 @@ import android.view.View;
 import android.view.ViewGroup;
 import com.google.android.setupcompat.util.ForceTwoPaneHelper;
 import com.google.android.setupdesign.template.RecyclerMixin;
+import com.google.android.setupdesign.util.ThemeHelper;
 
 /**
  * A layout to be used with {@code PreferenceFragment} in v14 support library. This can be specified
@@ -129,6 +130,9 @@ public class GlifPreferenceLayout extends GlifRecyclerLayout {
       // sud_glif_preference_recycler_view layout is not compatible with original layout.
       recyclerViewLayoutId = R.layout.sud_glif_preference_recycler_view_compat_two_pane;
     }
+    if (ThemeHelper.shouldApplyGlifExpressiveStyle(getContext())) {
+      recyclerViewLayoutId = R.layout.sud_glif_expressive_preference_recycler_view;
+    }
     RecyclerView recyclerView = (RecyclerView) inflater.inflate(recyclerViewLayoutId, this, false);
     recyclerMixin = new RecyclerMixin(this, recyclerView);
   }
diff --git a/main/src/com/google/android/setupdesign/items/ButtonItem.java b/main/src/com/google/android/setupdesign/items/ButtonItem.java
index a2e746e..c6ae916 100644
--- a/main/src/com/google/android/setupdesign/items/ButtonItem.java
+++ b/main/src/com/google/android/setupdesign/items/ButtonItem.java
@@ -19,12 +19,16 @@ package com.google.android.setupdesign.items;
 import android.annotation.SuppressLint;
 import android.content.Context;
 import android.content.res.TypedArray;
+import android.graphics.drawable.Drawable;
 import android.util.AttributeSet;
 import android.view.ContextThemeWrapper;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
 import android.widget.Button;
+import androidx.annotation.Nullable;
+import com.google.android.material.button.MaterialButton;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupdesign.R;
 
 /**
@@ -41,6 +45,7 @@ public class ButtonItem extends AbstractItem implements View.OnClickListener {
   private CharSequence text;
   private int theme = R.style.SudButtonItem;
   private OnClickListener listener;
+  @Nullable private Drawable icon;
 
   private Button button;
 
@@ -54,6 +59,7 @@ public class ButtonItem extends AbstractItem implements View.OnClickListener {
     enabled = a.getBoolean(R.styleable.SudButtonItem_android_enabled, true);
     text = a.getText(R.styleable.SudButtonItem_android_text);
     theme = a.getResourceId(R.styleable.SudButtonItem_android_theme, R.style.SudButtonItem);
+    icon = a.getDrawable(R.styleable.SudButtonItem_android_icon);
     a.recycle();
   }
 
@@ -86,6 +92,17 @@ public class ButtonItem extends AbstractItem implements View.OnClickListener {
     return theme;
   }
 
+  /** The icon to set to this button. */
+  public void setIcon(@Nullable Drawable icon) {
+    this.icon = icon;
+  }
+
+  /** The icon can be get from this button. */
+  @Nullable
+  public Drawable getIcon() {
+    return icon;
+  }
+
   public void setEnabled(boolean enabled) {
     this.enabled = enabled;
   }
@@ -135,6 +152,11 @@ public class ButtonItem extends AbstractItem implements View.OnClickListener {
     button.setEnabled(enabled);
     button.setText(text);
     button.setId(getViewId());
+    if (button instanceof MaterialButton materialButton) {
+      materialButton.setIcon(icon);
+    } else {
+      button.setCompoundDrawablesWithIntrinsicBounds(icon, null, null, null);
+    }
     return button;
   }
 
diff --git a/main/src/com/google/android/setupdesign/items/CheckBoxItem.java b/main/src/com/google/android/setupdesign/items/CheckBoxItem.java
new file mode 100644
index 0000000..0bfe917
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/items/CheckBoxItem.java
@@ -0,0 +1,132 @@
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
+package com.google.android.setupdesign.items;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.util.AttributeSet;
+import android.view.View;
+import android.widget.CheckBox;
+import android.widget.CompoundButton;
+import com.google.android.setupdesign.R;
+
+/**
+ * An item that is displayed with a check box, with methods to manipulate and listen to the checked
+ * state of the check box. Note that by default, only click on the check box will change the on-off
+ * state. To change the check box state when tapping on the text, use the click handlers of list
+ * view or RecyclerItemAdapter with {@link #toggle(View)}.
+ */
+public class CheckBoxItem extends Item implements CompoundButton.OnCheckedChangeListener {
+
+  /** Listener for check state changes of this check box item. */
+  public interface OnCheckedChangeListener {
+
+    /**
+     * Callback when checked state of a {@link CheckBoxItem} is changed.
+     *
+     * @see #setOnCheckedChangeListener(OnCheckedChangeListener)
+     */
+    void onCheckedChange(CheckBoxItem item, boolean isChecked);
+  }
+
+  private boolean checked = false;
+  private OnCheckedChangeListener listener;
+
+  /** Creates a default check box item. */
+  public CheckBoxItem() {
+    super();
+  }
+
+  /**
+   * Creates a check box item. This constructor is used for inflation from XML.
+   *
+   * @param context The context which this item is inflated in.
+   * @param attrs The XML attributes defined on the item.
+   */
+  public CheckBoxItem(Context context, AttributeSet attrs) {
+    super(context, attrs);
+    final TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudCheckBoxItem);
+    checked = a.getBoolean(R.styleable.SudCheckBoxItem_android_checked, false);
+    a.recycle();
+  }
+
+  /** Sets whether this item should be checked. */
+  public void setChecked(boolean checked) {
+    if (this.checked != checked) {
+      this.checked = checked;
+      notifyItemChanged();
+      if (listener != null) {
+        listener.onCheckedChange(this, checked);
+      }
+    }
+  }
+
+  /** Sets whether this item should be checked and does not notify the listener. */
+  public void setCheckedWithoutNotify(boolean checked) {
+    if (this.checked != checked) {
+      this.checked = checked;
+      notifyItemChanged();
+    }
+  }
+
+  /** Returns true if this check box item is currently checked. */
+  public boolean isChecked() {
+    return checked;
+  }
+
+  @Override
+  protected int getDefaultLayoutResource() {
+    return R.layout.sud_items_check_box;
+  }
+
+  /**
+   * Toggle the checked state of the check box, without invalidating the entire item.
+   *
+   * @param view The root view of this item, typically from the argument of onItemClick.
+   */
+  public void toggle(View view) {
+    checked = !checked;
+    final CheckBox checkBoxView = (CheckBox) view.findViewById(R.id.sud_items_check_box);
+    checkBoxView.setChecked(checked);
+  }
+
+  @Override
+  public void onBindView(View view) {
+    super.onBindView(view);
+    final CheckBox checkBoxView = (CheckBox) view.findViewById(R.id.sud_items_check_box);
+    checkBoxView.setOnCheckedChangeListener(null);
+    checkBoxView.setChecked(checked);
+    checkBoxView.setOnCheckedChangeListener(this);
+    checkBoxView.setEnabled(isEnabled());
+  }
+
+  /**
+   * Sets a listener to listen for changes in checked state. This listener is invoked in both user
+   * toggling the check box and calls to {@link #setChecked(boolean)}.
+   */
+  public void setOnCheckedChangeListener(OnCheckedChangeListener listener) {
+    this.listener = listener;
+  }
+
+  @Override
+  public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
+    checked = isChecked;
+    if (listener != null) {
+      listener.onCheckedChange(this, isChecked);
+    }
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/items/ExpandableItem.java b/main/src/com/google/android/setupdesign/items/ExpandableItem.java
new file mode 100644
index 0000000..5c71c1e
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/items/ExpandableItem.java
@@ -0,0 +1,199 @@
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
+package com.google.android.setupdesign.items;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.os.Bundle;
+import android.util.AttributeSet;
+import android.view.LayoutInflater;
+import android.view.View;
+import android.view.View.OnClickListener;
+import android.view.ViewGroup;
+import android.widget.ImageView;
+import androidx.core.view.AccessibilityDelegateCompat;
+import androidx.core.view.ViewCompat;
+import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
+import androidx.core.view.accessibility.AccessibilityNodeInfoCompat.AccessibilityActionCompat;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
+import com.google.android.setupdesign.R;
+import com.google.android.setupdesign.util.LayoutStyler;
+
+/**
+ * A expandable item which is has a button in the end to expand or collapse the item. The item can
+ * show the layout which is set by the layout resource.
+ */
+public class ExpandableItem extends Item implements OnClickListener {
+
+  private boolean isExpanded = false;
+  private boolean canExpanded = true;
+  private int expandedLayoutRes = 0;
+  private View expandedContent = null;
+
+  private final AccessibilityDelegateCompat accessibilityDelegate =
+      new AccessibilityDelegateCompat() {
+        @Override
+        public void onInitializeAccessibilityNodeInfo(
+            View view, AccessibilityNodeInfoCompat nodeInfo) {
+          super.onInitializeAccessibilityNodeInfo(view, nodeInfo);
+          nodeInfo.addAction(
+              isExpanded()
+                  ? AccessibilityActionCompat.ACTION_COLLAPSE
+                  : AccessibilityActionCompat.ACTION_EXPAND);
+        }
+
+        @Override
+        public boolean performAccessibilityAction(View view, int action, Bundle args) {
+          boolean result;
+          switch (action) {
+            case AccessibilityNodeInfoCompat.ACTION_COLLAPSE:
+            case AccessibilityNodeInfoCompat.ACTION_EXPAND:
+              setExpanded(!isExpanded());
+              result = true;
+              break;
+            default:
+              result = super.performAccessibilityAction(view, action, args);
+              break;
+          }
+          return result;
+        }
+      };
+
+  public ExpandableItem() {
+    super();
+  }
+
+  public ExpandableItem(Context context) {
+    super();
+  }
+
+  public ExpandableItem(Context context, AttributeSet attrs) {
+    super(context, attrs);
+    final TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudExpandableItem);
+    expandedLayoutRes = a.getResourceId(R.styleable.SudExpandableItem_sudExpandedContent, 0);
+    a.recycle();
+  }
+
+  public ExpandableItem(Context context, AttributeSet attrs, boolean canExpanded) {
+    super(context, attrs);
+    final TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudExpandableItem);
+    expandedLayoutRes = a.getResourceId(R.styleable.SudExpandableItem_sudExpandedContent, 0);
+    a.recycle();
+    this.canExpanded = canExpanded;
+  }
+
+  @Override
+  protected int getDefaultLayoutResource() {
+    return R.layout.sud_items_expandable;
+  }
+
+  /** Returns true if the item is currently expanded. */
+  public boolean isExpanded() {
+    return isExpanded;
+  }
+
+  /** Sets whether the item should be expanded. */
+  public void setExpanded(boolean expanded) {
+    if (isExpanded == expanded) {
+      return;
+    }
+    isExpanded = expanded;
+    notifyItemChanged();
+  }
+
+  /** Sets whether the item can be expanded. */
+  public void setCanExpanded(boolean canExpanded) {
+    this.canExpanded = canExpanded;
+    notifyItemChanged();
+  }
+
+  /** Sets the view for the expanded content. */
+  public void setExpandedView(View expandedContent) {
+    this.expandedContent = expandedContent;
+  }
+
+  /** Sets the layout resource for the expanded content. */
+  public void setExpandedLayoutRes(int expandedLayoutRes) {
+    this.expandedLayoutRes = expandedLayoutRes;
+  }
+
+  @Override
+  public void onBindView(View view) {
+    super.onBindView(view);
+
+    // Expandable item is using this view's child to listen clickable event, to avoid
+    // accessibility issue, remove clickable event in this view.
+    view.setClickable(false);
+
+    View expandButton = view.findViewById(R.id.sud_items_expand_button);
+    if (expandButton != null) {
+      if (canExpanded) {
+        expandButton.setOnClickListener(this);
+      } else {
+        expandButton.setVisibility(View.GONE);
+      }
+    }
+    View expandableContentContainer =
+        view.findViewById(R.id.sud_items_expandable_content_container);
+    if (expandableContentContainer != null) {
+      if (expandedContent != null) {
+        ((ViewGroup) expandedContent.getParent()).removeView(expandedContent);
+        ((ViewGroup) expandableContentContainer).addView(expandedContent);
+      } else {
+        if (expandedLayoutRes != 0) {
+          LayoutInflater inflater = LayoutInflater.from(expandableContentContainer.getContext());
+          View expandableContent =
+              inflater.inflate(expandedLayoutRes, (ViewGroup) expandableContentContainer, false);
+          ((ViewGroup) expandableContentContainer).addView(expandableContent);
+        }
+        if (isExpanded) {
+          expandableContentContainer.setVisibility(View.VISIBLE);
+        } else {
+          expandableContentContainer.setVisibility(View.GONE);
+        }
+      }
+    }
+    ViewCompat.setAccessibilityDelegate(view, accessibilityDelegate);
+    if (!PartnerConfigHelper.isGlifExpressiveEnabled(view.getContext())) {
+      LayoutStyler.applyPartnerCustomizationLayoutPaddingStyle(view);
+    }
+
+    // Expandable item has focusability on the expandable layout on the left, and the
+    // expand button on the right, but not the item itself.
+    view.setFocusable(false);
+    updateExpandButtonImage(view);
+  }
+
+  private void updateExpandButtonImage(View view) {
+    ImageView expandButton = view.findViewById(R.id.sud_items_expand_button);
+    if (expandButton != null) {
+      if (isExpanded()) {
+        expandButton.setImageResource(R.drawable.sud_items_collapse_button_icon);
+      } else {
+        expandButton.setImageResource(R.drawable.sud_items_expand_button_icon);
+      }
+    }
+  }
+
+  @Override
+  public void onClick(View v) {
+    if (v.getId() == R.id.sud_items_expand_button && canExpanded) {
+      setExpanded(!isExpanded());
+      updateExpandButtonImage(v);
+    }
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java b/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java
index 51d9e9f..d8f2600 100644
--- a/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java
+++ b/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java
@@ -34,6 +34,7 @@ import androidx.core.view.AccessibilityDelegateCompat;
 import androidx.core.view.ViewCompat;
 import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
 import androidx.core.view.accessibility.AccessibilityNodeInfoCompat.AccessibilityActionCompat;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupdesign.R;
 import com.google.android.setupdesign.util.LayoutStyler;
 import com.google.android.setupdesign.view.CheckableLinearLayout;
@@ -54,6 +55,8 @@ public class ExpandableSwitchItem extends SwitchItem
   private CharSequence collapsedSummary;
   private CharSequence expandedSummary;
   private boolean isExpanded = false;
+  private boolean canExpanded = true;
+  private boolean isSwitchItem = true;
 
   private final AccessibilityDelegateCompat accessibilityDelegate =
       new AccessibilityDelegateCompat() {
@@ -89,15 +92,47 @@ public class ExpandableSwitchItem extends SwitchItem
     setIconGravity(Gravity.TOP);
   }
 
+  public ExpandableSwitchItem(Context context) {
+    super();
+    if (!PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      setIconGravity(Gravity.TOP);
+    } else {
+      setLayoutResource(R.layout.sud_items_expandable_switch_expressive);
+      setIconGravity(Gravity.CENTER_VERTICAL);
+    }
+  }
+
   public ExpandableSwitchItem(Context context, AttributeSet attrs) {
     super(context, attrs);
     final TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudExpandableSwitchItem);
     collapsedSummary = a.getText(R.styleable.SudExpandableSwitchItem_sudCollapsedSummary);
     expandedSummary = a.getText(R.styleable.SudExpandableSwitchItem_sudExpandedSummary);
-    setIconGravity(a.getInt(R.styleable.SudItem_sudIconGravity, Gravity.TOP));
+    if (!PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      setIconGravity(a.getInt(R.styleable.SudItem_sudIconGravity, Gravity.TOP));
+    } else {
+      setLayoutResource(R.layout.sud_items_expandable_switch_expressive);
+      setIconGravity(a.getInt(R.styleable.SudItem_sudIconGravity, Gravity.CENTER_VERTICAL));
+    }
     a.recycle();
   }
 
+  public ExpandableSwitchItem(
+      Context context, AttributeSet attrs, boolean isSwitchItem, boolean canExpanded) {
+    super(context, attrs);
+    final TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudExpandableSwitchItem);
+    collapsedSummary = a.getText(R.styleable.SudExpandableSwitchItem_sudCollapsedSummary);
+    expandedSummary = a.getText(R.styleable.SudExpandableSwitchItem_sudExpandedSummary);
+    if (!PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      setIconGravity(a.getInt(R.styleable.SudItem_sudIconGravity, Gravity.TOP));
+    } else {
+      setLayoutResource(R.layout.sud_items_expandable_switch_expressive);
+      setIconGravity(a.getInt(R.styleable.SudItem_sudIconGravity, Gravity.CENTER_VERTICAL));
+    }
+    a.recycle();
+    this.isSwitchItem = isSwitchItem;
+    this.canExpanded = canExpanded;
+  }
+
   @Override
   protected int getDefaultLayoutResource() {
     return R.layout.sud_items_expandable_switch;
@@ -163,35 +198,65 @@ public class ExpandableSwitchItem extends SwitchItem
     // accessibility issue, remove clickable event in this view.
     view.setClickable(false);
 
-    View content = view.findViewById(R.id.sud_items_expandable_switch_content);
-    content.setOnClickListener(this);
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(view.getContext())) {
+      View moreInfo = view.findViewById(R.id.sud_items_more_info);
+      if (moreInfo != null) {
+        if (canExpanded) {
+          moreInfo.setOnClickListener(this);
+        } else {
+          moreInfo.setVisibility(View.GONE);
+        }
+      }
+      View switchItem = view.findViewById(R.id.sud_items_switch);
+      if (!isSwitchItem && switchItem != null) {
+        switchItem.setVisibility(View.GONE);
+      }
+    } else {
+      View content = view.findViewById(R.id.sud_items_expandable_switch_content);
+      content.setOnClickListener(this);
 
-    if (content instanceof CheckableLinearLayout) {
-      CheckableLinearLayout checkableLinearLayout = (CheckableLinearLayout) content;
-      checkableLinearLayout.setChecked(isExpanded());
+      if (content instanceof CheckableLinearLayout checkableLinearLayout) {
+        checkableLinearLayout.setChecked(isExpanded());
 
-      // On lower versions
-      ViewCompat.setAccessibilityLiveRegion(
-          checkableLinearLayout,
-          isExpanded()
-              ? ViewCompat.ACCESSIBILITY_LIVE_REGION_POLITE
-              : ViewCompat.ACCESSIBILITY_LIVE_REGION_NONE);
+        // On lower versions
+        checkableLinearLayout.setAccessibilityLiveRegion(
+            isExpanded()
+                ? ViewCompat.ACCESSIBILITY_LIVE_REGION_POLITE
+                : ViewCompat.ACCESSIBILITY_LIVE_REGION_NONE);
 
-      ViewCompat.setAccessibilityDelegate(checkableLinearLayout, accessibilityDelegate);
+        ViewCompat.setAccessibilityDelegate(checkableLinearLayout, accessibilityDelegate);
+      }
+      LayoutStyler.applyPartnerCustomizationLayoutPaddingStyle(content);
     }
-
     tintCompoundDrawables(view);
 
     // Expandable switch item has focusability on the expandable layout on the left, and the
     // switch on the right, but not the item itself.
     view.setFocusable(false);
+    updateShowMoreLinkText(view);
+  }
 
-    LayoutStyler.applyPartnerCustomizationLayoutPaddingStyle(content);
+  private void updateShowMoreLinkText(View view) {
+    TextView showMoreLink = view.findViewById(R.id.sud_items_more_info);
+    if (showMoreLink != null) {
+      if (isExpanded()) {
+        showMoreLink.setText(com.google.android.setupdesign.strings.R.string.sud_less_info);
+      } else {
+        showMoreLink.setText(com.google.android.setupdesign.strings.R.string.sud_more_info);
+      }
+    }
   }
 
   @Override
   public void onClick(View v) {
-    setExpanded(!isExpanded());
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(v.getContext())) {
+      if (v.getId() == R.id.sud_items_more_info) {
+        setExpanded(!isExpanded());
+        updateShowMoreLinkText(v);
+      }
+    } else {
+      setExpanded(!isExpanded());
+    }
   }
 
   // Tint the expand arrow with the text color
diff --git a/main/src/com/google/android/setupdesign/items/IItem.java b/main/src/com/google/android/setupdesign/items/IItem.java
index 72b9623..c58081f 100644
--- a/main/src/com/google/android/setupdesign/items/IItem.java
+++ b/main/src/com/google/android/setupdesign/items/IItem.java
@@ -41,4 +41,32 @@ public interface IItem {
 
   /** @return True if this item is enabled. */
   boolean isEnabled();
+
+  /**
+   * @return True if this item is a group divider. The divider will split the last item and next
+   *     item to a different group.
+   */
+  default boolean isGroupDivider() {
+    return false;
+  }
+
+  /**
+   * Check if the item is recycler able when in recycler view.
+   *
+   * @return True if this item is recycler able which is the default behavior of recycler view.
+   * @return False if this item is not recycler able, so that {@link ViewHolder} will not be
+   *     recycled for this item, but it may have the performance impact.
+   */
+  default boolean isRecyclable() {
+    return true;
+  }
+
+  /**
+   * Check if the item is Actionable in the list view to update the actionable background.
+   *
+   * @return True if this item is actionable.
+   */
+  default boolean isActionable() {
+    return true;
+  }
 }
diff --git a/main/src/com/google/android/setupdesign/items/IllustrationItem.java b/main/src/com/google/android/setupdesign/items/IllustrationItem.java
new file mode 100644
index 0000000..2dbf5c9
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/items/IllustrationItem.java
@@ -0,0 +1,86 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+package com.google.android.setupdesign.items;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.graphics.drawable.Drawable;
+import android.util.AttributeSet;
+import android.view.View;
+import android.widget.ImageView;
+import com.google.android.setupdesign.R;
+import org.jetbrains.annotations.Nullable;
+
+/**
+ * An item that is displayed with a Illustration, with methods to manipulate state of the imageView.
+ */
+public class IllustrationItem extends Item {
+
+  private Drawable illustration;
+
+  IllustrationItem() {
+    super();
+  }
+
+  public IllustrationItem(Context context, AttributeSet attrs) {
+    super(context, attrs);
+    TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudIllustrationItem);
+    this.illustration = a.getDrawable(R.styleable.SudIllustrationItem_android_drawable);
+    a.recycle();
+  }
+
+  public Drawable getIllustration() {
+    return illustration;
+  }
+
+  public void setIllustration(Drawable value) {
+    this.illustration = value;
+    this.notifyItemChanged();
+  }
+
+  @Override
+  protected int getDefaultLayoutResource() {
+    return R.layout.sud_illustration_item;
+  }
+
+  @Override
+  public void onBindView(@Nullable View view) {
+    if (view != null) {
+      view.setContentDescription(getContentDescription());
+      ImageView imageView = view.findViewById(R.id.sud_item_illustration);
+      imageView.setImageDrawable(getIllustration());
+    }
+
+  }
+
+  /**
+   * IllustrationItem is set as GroupDivider to remove the default item background that are set in
+   * ListView and RecyclerViews for all the items that are not group divider.
+   */
+  @Override
+  public boolean isGroupDivider() {
+    return true;
+  }
+
+  /**
+   * This is disabled to remove the touch feedback for imageView items. If there is any touch event
+   * for the IllustrationItem, override this method to set isEnabled() true
+   */
+  @Override
+  public boolean isEnabled() {
+    return false;
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/items/Item.java b/main/src/com/google/android/setupdesign/items/Item.java
index f8a6606..0015916 100644
--- a/main/src/com/google/android/setupdesign/items/Item.java
+++ b/main/src/com/google/android/setupdesign/items/Item.java
@@ -31,14 +31,34 @@ import androidx.annotation.ColorInt;
 import androidx.annotation.Nullable;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupdesign.R;
+import com.google.android.setupdesign.span.LinkSpan;
 import com.google.android.setupdesign.util.ItemStyler;
 import com.google.android.setupdesign.util.LayoutStyler;
+import com.google.android.setupdesign.view.RichTextView;
 
 /**
  * Definition of an item in an {@link ItemHierarchy}. An item is usually defined in XML and inflated
  * using {@link ItemInflater}.
  */
-public class Item extends AbstractItem {
+public class Item extends AbstractItem implements LinkSpan.OnLinkClickListener {
+
+  /**
+   * Listener that is invoked when a link span is clicked in summary RichTextView.
+   * If the containing view of this span implements this interface, this will be invoked when the
+   * link is clicked.
+   * @apiNote Make sure to use RichTextView for the textViews wherever Linking of text is expected.
+   * This OnLinkClickListener can be extended to Title TextViews based on use case.
+   */
+  public interface OnItemTextLinkClickListener {
+
+    /**
+     * Called when a link has been clicked.
+     *
+     * @param span The span that was clicked.
+     * @return True if the click was handled, stopping further propagation of the click event.
+     */
+    boolean onItemTextLinkClicked(LinkSpan span);
+  }
 
   private boolean enabled = true;
   @Nullable private Drawable icon;
@@ -46,6 +66,8 @@ public class Item extends AbstractItem {
   @Nullable private CharSequence summary;
   @Nullable private CharSequence title;
   @Nullable private CharSequence contentDescription;
+  @Nullable private Boolean isClickable;
+  @Nullable private OnItemTextLinkClickListener itemTextLinkClickListener;
   private boolean visible = true;
   @ColorInt private int iconTint = Color.TRANSPARENT;
   private int iconGravity = Gravity.CENTER_VERTICAL;
@@ -76,6 +98,9 @@ public class Item extends AbstractItem {
   }
 
   public void setEnabled(boolean enabled) {
+    if (this.enabled == enabled) {
+      return;
+    }
     this.enabled = enabled;
     notifyItemChanged();
   }
@@ -113,6 +138,14 @@ public class Item extends AbstractItem {
     this.iconGravity = iconGravity;
   }
 
+  public Boolean getClickable() {
+    return isClickable;
+  }
+
+  public void setClickable(Boolean isClickable) {
+    this.isClickable = isClickable;
+  }
+
   public int getIconGravity() {
     return iconGravity;
   }
@@ -137,6 +170,10 @@ public class Item extends AbstractItem {
     return summary;
   }
 
+  public void setOnItemTextLinkClickListener(@Nullable OnItemTextLinkClickListener itemTextLinkClickListener) {
+    this.itemTextLinkClickListener = itemTextLinkClickListener;
+  }
+
   public void setTitle(@Nullable CharSequence title) {
     this.title = title;
     notifyItemChanged();
@@ -186,11 +223,16 @@ public class Item extends AbstractItem {
   public void onBindView(View view) {
     TextView label = (TextView) view.findViewById(R.id.sud_items_title);
     label.setText(getTitle());
-
+    if (isClickable != null) {
+      view.setClickable(isClickable);
+    }
     TextView summaryView = (TextView) view.findViewById(R.id.sud_items_summary);
     CharSequence summary = getSummary();
     if (hasSummary(summary)) {
       summaryView.setText(summary);
+      if (summaryView instanceof RichTextView tv) {
+        tv.setOnLinkClickListener(this);
+      }
       summaryView.setVisibility(View.VISIBLE);
     } else {
       summaryView.setVisibility(View.GONE);
@@ -229,10 +271,10 @@ public class Item extends AbstractItem {
     // If the item view is a header layout, it doesn't need to adjust the layout padding start/end
     // here. It will be adjusted by HeaderMixin.
     // TODO: Add partner resource enable check
-    if (!(this instanceof ExpandableSwitchItem)
-        && view.getId() != R.id.sud_layout_header
-        && !(PartnerConfigHelper.isGlifExpressiveEnabled(view.getContext()))) {
-      LayoutStyler.applyPartnerCustomizationLayoutPaddingStyle(view);
+    if (!(this instanceof ExpandableSwitchItem) && view.getId() != R.id.sud_layout_header) {
+      if (!PartnerConfigHelper.isGlifExpressiveEnabled(view.getContext())) {
+        LayoutStyler.applyPartnerCustomizationLayoutPaddingStyle(view);
+      }
     }
     ItemStyler.applyPartnerCustomizationItemStyle(view);
   }
@@ -246,4 +288,13 @@ public class Item extends AbstractItem {
     iconView.setImageState(icon.getState(), false /* merge */);
     iconView.setImageLevel(icon.getLevel());
   }
+
+  @Override
+  public boolean onLinkClick(LinkSpan span) {
+    if (itemTextLinkClickListener != null) {
+      return itemTextLinkClickListener.onItemTextLinkClicked(span);
+    }
+    return false;
+  }
+
 }
diff --git a/main/src/com/google/android/setupdesign/items/ItemAdapter.java b/main/src/com/google/android/setupdesign/items/ItemAdapter.java
index ebb761e..8d2f0e3 100644
--- a/main/src/com/google/android/setupdesign/items/ItemAdapter.java
+++ b/main/src/com/google/android/setupdesign/items/ItemAdapter.java
@@ -16,14 +16,11 @@
 
 package com.google.android.setupdesign.items;
 
-import android.annotation.TargetApi;
 import android.content.Context;
 import android.content.res.TypedArray;
 import android.graphics.drawable.Drawable;
 import android.graphics.drawable.GradientDrawable;
 import android.graphics.drawable.LayerDrawable;
-import android.os.Build;
-import android.os.Build.VERSION_CODES;
 import android.util.SparseIntArray;
 import android.view.LayoutInflater;
 import android.view.View;
@@ -33,6 +30,8 @@ import android.widget.LinearLayout;
 import com.google.android.setupcompat.partnerconfig.PartnerConfig;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupdesign.R;
+import com.google.android.setupdesign.util.ItemStyler;
+import com.google.android.setupdesign.view.StickyHeaderListView;
 
 /**
  * An adapter typically used with ListView to display an {@link
@@ -44,12 +43,18 @@ public class ItemAdapter extends BaseAdapter implements ItemHierarchy.Observer {
   private final ItemHierarchy itemHierarchy;
   private final ViewTypes viewTypes = new ViewTypes();
 
+  private View listView = null;
+
   public ItemAdapter(ItemHierarchy hierarchy) {
     itemHierarchy = hierarchy;
     itemHierarchy.registerObserver(this);
     refreshViewTypes();
   }
 
+  public void setListView(View listView) {
+    this.listView = listView;
+  }
+
   @Override
   public int getCount() {
     return itemHierarchy.getCount();
@@ -84,36 +89,53 @@ public class ItemAdapter extends BaseAdapter implements ItemHierarchy.Observer {
     }
   }
 
-  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
-  private Drawable getFirstBackground(Context context) {
-    TypedArray a =
-        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundFirst});
+  private Drawable getFirstBackground(Context context, int position) {
+    IItem item = getItem(position);
+    TypedArray a = context
+            .getTheme()
+            .obtainStyledAttributes(
+                item.isActionable()
+                    ? new int[] {R.attr.sudItemBackgroundFirst}
+                    : new int[] {R.attr.sudNonActionableItemBackgroundFirst});
     Drawable firstBackground = a.getDrawable(0);
     a.recycle();
     return firstBackground;
   }
 
-  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
-  private Drawable getLastBackground(Context context) {
-    TypedArray a =
-        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundLast});
+  private Drawable getLastBackground(Context context, int position) {
+    IItem item = getItem(position);
+    TypedArray a = context
+            .getTheme()
+            .obtainStyledAttributes(
+                item.isActionable()
+                    ? new int[] {R.attr.sudItemBackgroundLast}
+                    : new int[] {R.attr.sudNonActionableItemBackgroundLast});
     Drawable lastBackground = a.getDrawable(0);
     a.recycle();
     return lastBackground;
   }
 
-  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
-  private Drawable getMiddleBackground(Context context) {
-    TypedArray a = context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackground});
+  private Drawable getMiddleBackground(Context context, int position) {
+    IItem item = getItem(position);
+    TypedArray a = context
+            .getTheme()
+            .obtainStyledAttributes(
+                item.isActionable()
+                    ? new int[] {R.attr.sudItemBackground}
+                    : new int[] {R.attr.sudNonActionableItemBackground});
     Drawable middleBackground = a.getDrawable(0);
     a.recycle();
     return middleBackground;
   }
 
-  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
-  private Drawable getSingleBackground(Context context) {
-    TypedArray a =
-        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundSingle});
+  private Drawable getSingleBackground(Context context, int position) {
+    IItem item = getItem(position);
+    TypedArray a = context
+            .getTheme()
+            .obtainStyledAttributes(
+                item.isActionable()
+                    ? new int[] {R.attr.sudItemBackgroundSingle}
+                    : new int[] {R.attr.sudNonActionableItemBackgroundSingle});
     Drawable singleBackground = a.getDrawable(0);
     a.recycle();
     return singleBackground;
@@ -127,7 +149,19 @@ public class ItemAdapter extends BaseAdapter implements ItemHierarchy.Observer {
     return conerRadius;
   }
 
+  private boolean isFirstItemOfGroup(int position) {
+    return position == 0 || getItem(position - 1).isGroupDivider();
+  }
+
+  private boolean isLastItemOfGroup(int position) {
+    return position == getCount() - 1 || getItem(position + 1).isGroupDivider();
+  }
+
   public void updateBackground(View convertView, int position) {
+    if (getItem(position).isGroupDivider()) {
+      return;
+    }
+
     float groupCornerRadius =
         PartnerConfigHelper.get(convertView.getContext())
             .getDimension(convertView.getContext(), PartnerConfig.CONFIG_ITEMS_GROUP_CORNER_RADIUS);
@@ -137,14 +171,15 @@ public class ItemAdapter extends BaseAdapter implements ItemHierarchy.Observer {
     Drawable backgroundDrawable = null;
     GradientDrawable background = null;
 
-    if (position == 0 && getCount() == 1) {
-      backgroundDrawable = getSingleBackground(convertView.getContext());
-    } else if (position == 0) {
-      backgroundDrawable = getFirstBackground(convertView.getContext());
-    } else if (position == getCount() - 1) {
-      backgroundDrawable = getLastBackground(convertView.getContext());
+    // TODO add test case in updateBackground for list item to get background for Item
+    if (isFirstItemOfGroup(position) && isLastItemOfGroup(position)) {
+      backgroundDrawable = getSingleBackground(convertView.getContext(), position);
+    } else if (isFirstItemOfGroup(position)) {
+      backgroundDrawable = getFirstBackground(convertView.getContext(), position);
+    } else if (isLastItemOfGroup(position)) {
+      backgroundDrawable = getLastBackground(convertView.getContext(), position);
     } else {
-      backgroundDrawable = getMiddleBackground(convertView.getContext());
+      backgroundDrawable = getMiddleBackground(convertView.getContext(), position);
     }
     // TODO add test case for list item group corner partner config
     if (drawable instanceof LayerDrawable && ((LayerDrawable) drawable).getNumberOfLayers() >= 2) {
@@ -161,10 +196,10 @@ public class ItemAdapter extends BaseAdapter implements ItemHierarchy.Observer {
     if (backgroundDrawable instanceof GradientDrawable) {
       float topCornerRadius = cornerRadius;
       float bottomCornerRadius = cornerRadius;
-      if (position == 0) {
+      if (isFirstItemOfGroup(position)) {
         topCornerRadius = groupCornerRadius;
       }
-      if (position == getCount() - 1) {
+      if (isLastItemOfGroup(position)) {
         bottomCornerRadius = groupCornerRadius;
       }
       background = (GradientDrawable) backgroundDrawable;
@@ -188,8 +223,7 @@ public class ItemAdapter extends BaseAdapter implements ItemHierarchy.Observer {
   public View getView(int position, View convertView, ViewGroup parent) {
 
     // TODO  when getContext is not activity context then fallback to out suw behavior
-    if (PartnerConfigHelper.isGlifExpressiveEnabled(parent.getContext())
-        && Build.VERSION.SDK_INT >= VERSION_CODES.VANILLA_ICE_CREAM) {
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(parent.getContext())) {
       IItem item = getItem(position);
       LinearLayout linearLayout = null;
       // The ListView can not handle the margin for the child view. So we need to use the
@@ -211,6 +245,7 @@ public class ItemAdapter extends BaseAdapter implements ItemHierarchy.Observer {
       }
       updateBackground(convertView, position);
       item.onBindView(convertView);
+      updateMargin(convertView);
       return linearLayout;
     } else {
       IItem item = getItem(position);
@@ -223,6 +258,34 @@ public class ItemAdapter extends BaseAdapter implements ItemHierarchy.Observer {
     }
   }
 
+  private void updateMargin(View view) {
+    // If the item view is inside a recycler layout or list layout with attribute
+    // shouldApplyAdditionalMargin, it needs to adjust the
+    // layout margin start/end here to align other component activity margin. If it is not
+    // inside a recycler layout or list layout with attribute shouldApplyAdditionalMargin, it
+    // will be adjusted by each activity themselves.
+    if (shouldApplyAdditionalMargin()) {
+      ItemStyler.applyPartnerCustomizationLayoutMarginStyle(view);
+    } else {
+      resetMarginStartEnd(view);
+    }
+  }
+
+  private boolean shouldApplyAdditionalMargin() {
+    if (listView instanceof StickyHeaderListView stickyHeaderListView) {
+      return stickyHeaderListView.shouldApplyAdditionalMargin();
+    }
+    return false;
+  }
+
+  private void resetMarginStartEnd(View itemView) {
+    ViewGroup.MarginLayoutParams layoutParams =
+        (ViewGroup.MarginLayoutParams) itemView.getLayoutParams();
+    layoutParams.setMarginStart(0);
+    layoutParams.setMarginEnd(0);
+    itemView.setLayoutParams(layoutParams);
+  }
+
   @Override
   public void onChanged(ItemHierarchy hierarchy) {
     refreshViewTypes();
diff --git a/main/src/com/google/android/setupdesign/items/LottieIllustrationItem.java b/main/src/com/google/android/setupdesign/items/LottieIllustrationItem.java
new file mode 100644
index 0000000..7457323
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/items/LottieIllustrationItem.java
@@ -0,0 +1,105 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+package com.google.android.setupdesign.items;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.util.AttributeSet;
+import android.view.View;
+import com.airbnb.lottie.LottieAnimationView;
+import com.google.android.setupdesign.R;
+import org.jetbrains.annotations.Nullable;
+
+/** An item that is displayed with a Lottie animation. */
+public class LottieIllustrationItem extends Item {
+  private int animationId;
+  @Nullable private AnimationViewListener animationViewListener;
+
+  /** Listener for the state of the LottieAnimationView. */
+  public interface AnimationViewListener {
+    /**
+     * Called when a LottieAnimationView is bound to the item. This enables applying any additional
+     * customizations to the animation view.
+     */
+    void onAnimationViewBound(LottieAnimationView animationView);
+  }
+
+  LottieIllustrationItem() {
+    super();
+  }
+
+  public LottieIllustrationItem(Context context, AttributeSet attrs) {
+    super(context, attrs);
+    TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudIllustrationItem);
+    this.animationId = a.getResourceId(R.styleable.SudIllustrationItem_sudAnimationId, 0);
+    a.recycle();
+  }
+
+  /**
+   * Sets the animation and prepares to play it once the view is bound.
+   *
+   * @param animationId the resource id of the Lottie animation.
+   * @param animationViewListener see {@link AnimationViewListener}.
+   */
+  public void setAnimation(int animationId, AnimationViewListener animationViewListener) {
+    this.animationId = animationId;
+    this.animationViewListener = animationViewListener;
+    this.notifyItemChanged();
+  }
+
+  public int getAnimationId() {
+    return animationId;
+  }
+
+  @Override
+  protected int getDefaultLayoutResource() {
+    return R.layout.sud_lottie_illustration_item;
+  }
+
+  @Override
+  public void onBindView(@Nullable View view) {
+    if (view != null) {
+      view.setContentDescription(getContentDescription());
+
+      LottieAnimationView animationView = view.findViewById(R.id.sud_item_lottie_illustration);
+      if (animationId != 0) {
+        animationView.setAnimation(animationId);
+      }
+      if (animationViewListener != null) {
+        animationViewListener.onAnimationViewBound(animationView);
+      }
+      animationView.playAnimation();
+    }
+  }
+
+  /**
+   * IllustrationItem is set as GroupDivider to remove the default item background that are set in
+   * ListView and RecyclerViews for all the items that are not group divider.
+   */
+  @Override
+  public boolean isGroupDivider() {
+    return true;
+  }
+
+  /**
+   * This is disabled to remove the touch feedback for imageView items. If there is any touch event
+   * for the IllustrationItem, override this method to set isEnabled() true
+   */
+  @Override
+  public boolean isEnabled() {
+    return false;
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/items/NonActionableItem.java b/main/src/com/google/android/setupdesign/items/NonActionableItem.java
new file mode 100644
index 0000000..5967bbc
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/items/NonActionableItem.java
@@ -0,0 +1,49 @@
+/*
+ * Copyright (C) 2015 The Android Open Source Project
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
+package com.google.android.setupdesign.items;
+
+import android.content.Context;
+import android.util.AttributeSet;
+import com.google.android.setupdesign.R;
+
+/** Definition of an non-actionable item in an {@link ItemHierarchy}. */
+public class NonActionableItem extends Item {
+
+  public NonActionableItem() {
+    super();
+  }
+
+  public NonActionableItem(Context context, AttributeSet attrs) {
+    super(context, attrs);
+  }
+
+  @Override
+  protected int getDefaultLayoutResource() {
+    return R.layout.sud_non_actionable_items_default;
+  }
+
+  @Override
+  public boolean isEnabled() {
+    // There will be no action corresponding to NonActionableItem, so it will always be disabled.
+    return false;
+  }
+
+  @Override
+  public boolean isActionable() {
+    return false;
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/items/RadioButtonItem.java b/main/src/com/google/android/setupdesign/items/RadioButtonItem.java
new file mode 100644
index 0000000..e53fb5c
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/items/RadioButtonItem.java
@@ -0,0 +1,125 @@
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
+package com.google.android.setupdesign.items;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.util.AttributeSet;
+import android.view.View;
+import android.widget.CompoundButton;
+import com.google.android.material.radiobutton.MaterialRadioButton;
+import com.google.android.setupdesign.R;
+
+/**
+ * An item that is displayed with a radio button, with methods to manipulate and listen to the checked
+ * state of the radio button. Note that by default, only click on the radio button will change the on-off
+ * state. To change the radio button state when tapping on the text, use the click handlers of list
+ * view or RecyclerItemAdapter with {@link #toggle(View)}.
+ */
+public class RadioButtonItem extends Item implements CompoundButton.OnCheckedChangeListener {
+
+  /** Listener for check state changes of this radio button item. */
+  public interface OnCheckedChangeListener {
+
+    /**
+     * Callback when checked state of a {@link RadioButtonItem} is changed.
+     *
+     * @see #setOnCheckedChangeListener(OnCheckedChangeListener)
+     */
+    void onCheckedChange(RadioButtonItem item, boolean isChecked);
+  }
+
+  private boolean checked = false;
+  private OnCheckedChangeListener listener;
+
+  /** Creates a default radio button item. */
+  public RadioButtonItem() {
+    super();
+  }
+
+  /**
+   * Creates a radio button item. This constructor is used for inflation from XML.
+   *
+   * @param context The context which this item is inflated in.
+   * @param attrs The XML attributes defined on the item.
+   */
+  public RadioButtonItem(Context context, AttributeSet attrs) {
+    super(context, attrs);
+    final TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudRadioButtonItem);
+    checked = a.getBoolean(R.styleable.SudRadioButtonItem_android_checked, false);
+    a.recycle();
+  }
+
+  /** Sets whether this item should be checked. */
+  public void setChecked(boolean checked) {
+    if (this.checked != checked) {
+      this.checked = checked;
+      notifyItemChanged();
+      if (listener != null) {
+        listener.onCheckedChange(this, checked);
+      }
+    }
+  }
+
+  /** Returns true if this radio button item is currently checked. */
+  public boolean isChecked() {
+    return checked;
+  }
+
+  @Override
+  protected int getDefaultLayoutResource() {
+    return R.layout.sud_items_radio_button;
+  }
+
+  /**
+   * Toggle the checked state of the radio button, without invalidating the entire item.
+   *
+   * @param view The root view of this item, typically from the argument of onItemClick.
+   */
+  public void toggle(View view) {
+    checked = !checked;
+    final MaterialRadioButton radioButtonView = (MaterialRadioButton) view.findViewById(R.id.sud_items_radio_button);
+    radioButtonView.setChecked(checked);
+  }
+
+  @Override
+  public void onBindView(View view) {
+    super.onBindView(view);
+    final MaterialRadioButton radioButtonView =
+        (MaterialRadioButton) view.findViewById(R.id.sud_items_radio_button);
+    radioButtonView.setOnCheckedChangeListener(null);
+    radioButtonView.setChecked(checked);
+    radioButtonView.setOnCheckedChangeListener(this);
+    radioButtonView.setEnabled(isEnabled());
+  }
+
+  /**
+   * Sets a listener to listen for changes in checked state. This listener is invoked in both user
+   * toggling the radio button and calls to {@link #setChecked(boolean)}.
+   */
+  public void setOnCheckedChangeListener(OnCheckedChangeListener listener) {
+    this.listener = listener;
+  }
+
+  @Override
+  public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
+    checked = isChecked;
+    if (listener != null) {
+      listener.onCheckedChange(this, isChecked);
+    }
+  }
+}
\ No newline at end of file
diff --git a/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java b/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java
index 7172d8d..da338ed 100644
--- a/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java
+++ b/main/src/com/google/android/setupdesign/items/RecyclerItemAdapter.java
@@ -16,7 +16,6 @@
 
 package com.google.android.setupdesign.items;
 
-import android.annotation.TargetApi;
 import android.content.Context;
 import android.content.res.TypedArray;
 import android.graphics.Rect;
@@ -31,10 +30,13 @@ import android.util.Log;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
+import android.view.ViewOutlineProvider;
 import androidx.annotation.VisibleForTesting;
 import com.google.android.setupcompat.partnerconfig.PartnerConfig;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupdesign.R;
+import com.google.android.setupdesign.util.ItemStyler;
+import com.google.android.setupdesign.view.HeaderRecyclerView;
 
 /**
  * An adapter used with RecyclerView to display an {@link ItemHierarchy}. The item hierarchy used to
@@ -68,6 +70,7 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
   @VisibleForTesting public final boolean applyPartnerHeavyThemeResource;
   @VisibleForTesting public final boolean useFullDynamicColor;
   private OnItemSelectedListener listener;
+  private RecyclerView recyclerView = null;
 
   public RecyclerItemAdapter(ItemHierarchy hierarchy) {
     this(hierarchy, false);
@@ -87,6 +90,10 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
     itemHierarchy.registerObserver(this);
   }
 
+  public void setRecyclerView(RecyclerView recyclerView) {
+    this.recyclerView = recyclerView;
+  }
+
   /**
    * Gets the item at the given position.
    *
@@ -174,36 +181,53 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
     return viewHolder;
   }
 
-  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
-  private Drawable getFirstBackground(Context context) {
-    TypedArray a =
-        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundFirst});
+  private Drawable getFirstBackground(Context context, int position) {
+    IItem item = getItem(position);
+    TypedArray a = context
+        .getTheme()
+        .obtainStyledAttributes(
+            item.isActionable()
+                ? new int[] {R.attr.sudItemBackgroundFirst}
+                : new int[] {R.attr.sudNonActionableItemBackgroundFirst});
     Drawable firstBackground = a.getDrawable(0);
     a.recycle();
     return firstBackground;
   }
 
-  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
-  private Drawable getLastBackground(Context context) {
-    TypedArray a =
-        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundLast});
+  private Drawable getLastBackground(Context context, int position) {
+    IItem item = getItem(position);
+    TypedArray a = context
+        .getTheme()
+        .obtainStyledAttributes(
+            item.isActionable()
+                ? new int[] {R.attr.sudItemBackgroundLast}
+                : new int[] {R.attr.sudNonActionableItemBackgroundLast});
     Drawable lastBackground = a.getDrawable(0);
     a.recycle();
     return lastBackground;
   }
 
-  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
-  private Drawable getMiddleBackground(Context context) {
-    TypedArray a = context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackground});
+  private Drawable getMiddleBackground(Context context, int position) {
+    IItem item = getItem(position);
+    TypedArray a = context
+        .getTheme()
+        .obtainStyledAttributes(
+            item.isActionable()
+                ? new int[] {R.attr.sudItemBackground}
+                : new int[] {R.attr.sudNonActionableItemBackground});
     Drawable middleBackground = a.getDrawable(0);
     a.recycle();
     return middleBackground;
   }
 
-  @TargetApi(VERSION_CODES.VANILLA_ICE_CREAM)
-  private Drawable getSingleBackground(Context context) {
-    TypedArray a =
-        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundSingle});
+  private Drawable getSingleBackground(Context context, int position) {
+    IItem item = getItem(position);
+    TypedArray a = context
+        .getTheme()
+        .obtainStyledAttributes(
+            item.isActionable()
+                ? new int[] {R.attr.sudItemBackgroundSingle}
+                : new int[] {R.attr.sudNonActionableItemBackgroundSingle});
     Drawable singleBackground = a.getDrawable(0);
     a.recycle();
     return singleBackground;
@@ -217,10 +241,21 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
     return conerRadius;
   }
 
+  private boolean isFirstItemOfGroup(int position) {
+    return position == 0 || getItem(position - 1).isGroupDivider();
+  }
+
+  private boolean isLastItemOfGroup(int position) {
+    return position == getItemCount() - 1 || getItem(position + 1).isGroupDivider();
+  }
+
   public void updateBackground(View view, int position) {
     if (TAG_NO_BACKGROUND.equals(view.getTag())) {
       return;
     }
+    if (getItem(position).isGroupDivider()) {
+      return;
+    }
     float groupCornerRadius =
         PartnerConfigHelper.get(view.getContext())
             .getDimension(view.getContext(), PartnerConfig.CONFIG_ITEMS_GROUP_CORNER_RADIUS);
@@ -232,23 +267,24 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
       Drawable backgroundDrawable = null;
       GradientDrawable background = null;
 
-      if (position == 0 && getItemCount() == 1) {
-        backgroundDrawable = getSingleBackground(view.getContext());
-      } else if (position == 0) {
-        backgroundDrawable = getFirstBackground(view.getContext());
-      } else if (position == getItemCount() - 1) {
-        backgroundDrawable = getLastBackground(view.getContext());
+      // TODO add test case in updateBackground for list item to get background for Item
+      if (isFirstItemOfGroup(position) && isLastItemOfGroup(position)) {
+        backgroundDrawable = getSingleBackground(view.getContext(), position);
+      } else if (isFirstItemOfGroup(position)) {
+        backgroundDrawable = getFirstBackground(view.getContext(), position);
+      } else if (isLastItemOfGroup(position)) {
+        backgroundDrawable = getLastBackground(view.getContext(), position);
       } else {
-        backgroundDrawable = getMiddleBackground(view.getContext());
+        backgroundDrawable = getMiddleBackground(view.getContext(), position);
       }
 
       if (backgroundDrawable instanceof GradientDrawable) {
         float topCornerRadius = cornerRadius;
         float bottomCornerRadius = cornerRadius;
-        if (position == 0) {
+        if (isFirstItemOfGroup(position)) {
           topCornerRadius = groupCornerRadius;
         }
-        if (position == getItemCount() - 1) {
+        if (isLastItemOfGroup(position)) {
           bottomCornerRadius = groupCornerRadius;
         }
         background = (GradientDrawable) backgroundDrawable;
@@ -265,6 +301,10 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
             });
         final Drawable[] layers = {background, clickDrawable};
         view.setBackgroundDrawable(new PatchedLayerDrawable(layers));
+        if (Build.VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP) {
+          view.setClipToOutline(true);
+          view.setOutlineProvider(ViewOutlineProvider.BACKGROUND);
+        }
       }
     }
   }
@@ -274,14 +314,45 @@ public class RecyclerItemAdapter extends RecyclerView.Adapter<ItemViewHolder>
     final IItem item = getItem(position);
     holder.setEnabled(item.isEnabled());
     holder.setItem(item);
+    if (holder.isRecyclable() != item.isRecyclable()) {
+      holder.setIsRecyclable(item.isRecyclable());
+    }
     // TODO  when getContext is not activity context then fallback to out suw behavior
-    if (PartnerConfigHelper.isGlifExpressiveEnabled(holder.itemView.getContext())
-        && Build.VERSION.SDK_INT >= VERSION_CODES.VANILLA_ICE_CREAM) {
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(holder.itemView.getContext())) {
       updateBackground(holder.itemView, position);
+      updateMargin(holder.itemView);
     }
     item.onBindView(holder.itemView);
   }
 
+  private void updateMargin(View view) {
+    // If the item view is inside a recycler layout or list layout with attribute
+    // shouldApplyAdditionalMargin, it needs to adjust the
+    // layout margin start/end here to align other component activity margin. If it is not
+    // inside a recycler layout or list layout with attribute shouldApplyAdditionalMargin, it
+    // will be adjusted by each activity themselves.
+    if (shouldApplyAdditionalMargin()) {
+      ItemStyler.applyPartnerCustomizationLayoutMarginStyle(view);
+    } else {
+      resetMarginStartEnd(view);
+    }
+  }
+
+  private boolean shouldApplyAdditionalMargin() {
+    if (recyclerView instanceof HeaderRecyclerView headerRecyclerView) {
+      return headerRecyclerView.shouldApplyAdditionalMargin();
+    }
+    return false;
+  }
+
+  private void resetMarginStartEnd(View itemView) {
+    ViewGroup.MarginLayoutParams layoutParams =
+        (ViewGroup.MarginLayoutParams) itemView.getLayoutParams();
+    layoutParams.setMarginStart(0);
+    layoutParams.setMarginEnd(0);
+    itemView.setLayoutParams(layoutParams);
+  }
+
   @Override
   public int getItemViewType(int position) {
     // Use layout resource as item view type. RecyclerView item type does not have to be
diff --git a/main/src/com/google/android/setupdesign/items/SectionHeaderItem.java b/main/src/com/google/android/setupdesign/items/SectionHeaderItem.java
new file mode 100644
index 0000000..e921b5f
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/items/SectionHeaderItem.java
@@ -0,0 +1,75 @@
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
+package com.google.android.setupdesign.items;
+
+import android.view.View;
+import android.widget.TextView;
+import com.google.android.setupdesign.R;
+
+/** A section header item that represents a default style or bluechip styles. */
+public class SectionHeaderItem extends Item implements Dividable {
+
+  public SectionHeaderItem() {}
+
+  // dereference of possibly-null reference params
+  @SuppressWarnings("nullness:dereference.of.nullable")
+  @Override
+  public void onBindView(View view) {
+    TextView label = (TextView) view.findViewById(R.id.sud_items_title);
+    label.setText(getTitle());
+    TextView summaryView = (TextView) view.findViewById(R.id.sud_items_summary);
+    CharSequence summary = getSummary();
+    if (hasSummary(summary)) {
+      summaryView.setText(summary);
+      summaryView.setVisibility(View.VISIBLE);
+    } else {
+      summaryView.setVisibility(View.GONE);
+    }
+    view.setId(getViewId());
+    view.findViewById(R.id.sud_items_icon_container).setVisibility(View.GONE);
+    view.setContentDescription(getContentDescription());
+    view.setClickable(/* clickable= */ false);
+  }
+
+  private boolean hasSummary(CharSequence summary) {
+    return summary != null && summary.length() > 0;
+  }
+
+  @Override
+  protected int getDefaultLayoutResource() {
+    return R.layout.sud_items_section_header;
+  }
+
+  @Override
+  public boolean isDividerAllowedAbove() {
+    // Keep hiding the divide behavior when we set enable as true to prevent talkback speaks
+    // "disabled" for header item.
+    return false;
+  }
+
+  @Override
+  public boolean isDividerAllowedBelow() {
+    // Keep hiding the divide behavior when we set enable as true to prevent talkback speaks
+    // "disabled" for header item.
+    return false;
+  }
+
+  @Override
+  public boolean isGroupDivider() {
+    return true;
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/items/SectionItem.java b/main/src/com/google/android/setupdesign/items/SectionItem.java
new file mode 100644
index 0000000..db2f567
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/items/SectionItem.java
@@ -0,0 +1,92 @@
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
+package com.google.android.setupdesign.items;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.util.AttributeSet;
+import com.google.android.setupdesign.R;
+
+/**
+ * An {@link ItemGroup} which also displays a header item if there are any visible child (ignoring
+ * the header itself).
+ */
+public class SectionItem extends ItemGroup {
+
+  private final Item header;
+
+  public SectionItem() {
+    super();
+    header = new SectionHeaderItem();
+    header.setVisible(false);
+    addChild(header);
+  }
+
+  public SectionItem(Context context, AttributeSet attrs) {
+    super(context, attrs);
+    TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudSectionItem);
+    CharSequence headerText = a.getText(R.styleable.SudSectionItem_android_title);
+    a.recycle();
+    header = new SectionHeaderItem();
+    header.setTitle(headerText);
+    header.setVisible(false);
+    addChild(header);
+  }
+
+  public Item getHeader() {
+    return header;
+  }
+
+  public void setHeaderTitle(CharSequence headerText) {
+    header.setTitle(headerText);
+    refreshHeader();
+  }
+
+  @Override
+  public void addChild(ItemHierarchy child) {
+    super.addChild(child);
+    refreshHeader();
+  }
+
+  @Override
+  public void onItemRangeRemoved(ItemHierarchy itemHierarchy, int positionStart, int itemCount) {
+    super.onItemRangeRemoved(itemHierarchy, positionStart, itemCount);
+    refreshHeader();
+  }
+
+  @Override
+  public void onItemRangeInserted(ItemHierarchy itemHierarchy, int positionStart, int itemCount) {
+    super.onItemRangeInserted(itemHierarchy, positionStart, itemCount);
+    refreshHeader();
+  }
+
+  private void refreshHeader() {
+    if (header.isVisible()) {
+      if (getCount() == 1) {
+        // The header is the only visible item in this group. Hide it so the entire group is not
+        // shown.
+        header.setVisible(false);
+      }
+    } else {
+      if (getCount() > 0 && header.getTitle() != null) {
+        // Header is not currently visible but there are children in this group. Show the header as
+        // well.
+        header.setVisible(true);
+      }
+    }
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java b/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java
index 4257984..f940803 100644
--- a/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java
+++ b/main/src/com/google/android/setupdesign/template/FloatingBackButtonMixin.java
@@ -16,6 +16,9 @@
 
 package com.google.android.setupdesign.template;
 
+import android.annotation.TargetApi;
+import android.os.Build.VERSION_CODES;
+import android.os.PersistableBundle;
 import android.util.AttributeSet;
 import android.util.Log;
 import android.view.InflateException;
@@ -40,10 +43,23 @@ public class FloatingBackButtonMixin implements Mixin {
   private final TemplateLayout templateLayout;
   private static final String TAG = "FloatingBackButtonMixin";
 
+  @VisibleForTesting static final String KEY_BACK_BUTTON_ON_CLICK_COUNT = "BackButton_onClickCount";
+
   @Nullable private OnClickListener listener;
 
   @VisibleForTesting boolean tryInflatingBackButton = false;
 
+  private BackButtonListener backButtonListener;
+
+  private int clickCount = 0;
+
+  /** Interface definition for a callback to be invoked. */
+  public interface BackButtonListener {
+
+    /** Called when the back button has been clicked. */
+    void onBackPressed();
+  }
+
   /**
    * A {@link Mixin} for setting and getting the back button.
    *
@@ -73,10 +89,24 @@ public class FloatingBackButtonMixin implements Mixin {
     final Button backbutton = getBackButton();
     if (backbutton != null) {
       this.listener = listener;
-      backbutton.setOnClickListener(listener);
+      backbutton.setOnClickListener(
+          v -> {
+            if (listener != null) {
+              listener.onClick(v);
+              clickCount++;
+            }
+
+            if (backButtonListener != null) {
+              backButtonListener.onBackPressed();
+            }
+          });
     }
   }
 
+  public void setOnBackPressedCallback(BackButtonListener buttonEventListener) {
+    this.backButtonListener = buttonEventListener;
+  }
+
   /** Tries to apply the partner customization to the back button. */
   public void tryApplyPartnerCustomizationStyle() {
     if (PartnerStyleHelper.shouldApplyPartnerResource(templateLayout)
@@ -145,4 +175,19 @@ public class FloatingBackButtonMixin implements Mixin {
   public OnClickListener getOnClickListener() {
     return this.listener;
   }
+
+  public BackButtonListener getBackButtonListener() {
+    return this.backButtonListener;
+  }
+
+  /**
+   * Returns back button related metrics bundle for PartnerCustomizationLayout to log to
+   * SetupWizard.
+   */
+  @TargetApi(VERSION_CODES.Q)
+  public PersistableBundle getMetrics() {
+    PersistableBundle bundle = new PersistableBundle();
+    bundle.putInt(KEY_BACK_BUTTON_ON_CLICK_COUNT, clickCount);
+    return bundle;
+  }
 }
diff --git a/main/src/com/google/android/setupdesign/template/IconMixin.java b/main/src/com/google/android/setupdesign/template/IconMixin.java
index 3c2b6d0..1aac833 100644
--- a/main/src/com/google/android/setupdesign/template/IconMixin.java
+++ b/main/src/com/google/android/setupdesign/template/IconMixin.java
@@ -30,6 +30,7 @@ import android.widget.ImageView;
 import androidx.annotation.ColorInt;
 import androidx.annotation.DrawableRes;
 import com.google.android.setupcompat.internal.TemplateLayout;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.template.Mixin;
 import com.google.android.setupdesign.R;
 import com.google.android.setupdesign.util.HeaderAreaStyler;
@@ -73,7 +74,7 @@ public class IconMixin implements Mixin {
 
     @DrawableRes
     final int icon = a.getResourceId(R.styleable.SudIconMixin_android_icon, /* defValue= */ 0);
-    if (icon != 0) {
+    if (icon != 0 || PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
       setIcon(icon);
     }
 
@@ -112,7 +113,12 @@ public class IconMixin implements Mixin {
         }
       }
       iconView.setImageDrawable(icon);
-      iconView.setVisibility(icon != null ? View.VISIBLE : View.GONE);
+      if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+        iconView.setVisibility(icon != null ? View.VISIBLE : View.INVISIBLE);
+      } else {
+        iconView.setVisibility(icon != null ? View.VISIBLE : View.GONE);
+      }
+
       setIconContainerVisibility(iconView.getVisibility());
       tryApplyPartnerCustomizationStyle();
     }
@@ -129,7 +135,11 @@ public class IconMixin implements Mixin {
       // Note: setImageResource on the ImageView is overridden in AppCompatImageView for
       // support lib users, which enables vector drawable compat to work on versions pre-L.
       iconView.setImageResource(icon);
-      iconView.setVisibility(icon != 0 ? View.VISIBLE : View.GONE);
+      if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+        iconView.setVisibility(icon != 0 ? View.VISIBLE : View.INVISIBLE);
+      } else {
+        iconView.setVisibility(icon != 0 ? View.VISIBLE : View.GONE);
+      }
       setIconContainerVisibility(iconView.getVisibility());
     }
   }
diff --git a/main/src/com/google/android/setupdesign/template/ListMixin.java b/main/src/com/google/android/setupdesign/template/ListMixin.java
index 1cd55f2..f84d7d1 100644
--- a/main/src/com/google/android/setupdesign/template/ListMixin.java
+++ b/main/src/com/google/android/setupdesign/template/ListMixin.java
@@ -64,7 +64,9 @@ public class ListMixin implements Mixin {
     final int entries = a.getResourceId(R.styleable.SudListMixin_android_entries, 0);
     if (entries != 0) {
       final ItemGroup inflated = (ItemGroup) new ItemInflater(context).inflate(entries);
-      setAdapter(new ItemAdapter(inflated));
+      ItemAdapter adapter = new ItemAdapter(inflated);
+      adapter.setListView(getListView());
+      setAdapter(adapter);
     }
 
     boolean isDividerDisplay = a.getBoolean(R.styleable.SudListMixin_sudDividerShown, true);
diff --git a/main/src/com/google/android/setupdesign/template/RecyclerMixin.java b/main/src/com/google/android/setupdesign/template/RecyclerMixin.java
index 46b2faf..76dad45 100644
--- a/main/src/com/google/android/setupdesign/template/RecyclerMixin.java
+++ b/main/src/com/google/android/setupdesign/template/RecyclerMixin.java
@@ -237,6 +237,9 @@ public class RecyclerMixin implements Mixin {
 
   /** Sets the adapter on the recycler view in this layout. */
   public void setAdapter(Adapter<? extends ViewHolder> adapter) {
+    if (adapter instanceof RecyclerItemAdapter) {
+      ((RecyclerItemAdapter) adapter).setRecyclerView(recyclerView);
+    }
     recyclerView.setAdapter(adapter);
   }
 
diff --git a/main/src/com/google/android/setupdesign/template/RecyclerViewScrollHandlingDelegate.java b/main/src/com/google/android/setupdesign/template/RecyclerViewScrollHandlingDelegate.java
index b7a8d4a..ce18ed4 100644
--- a/main/src/com/google/android/setupdesign/template/RecyclerViewScrollHandlingDelegate.java
+++ b/main/src/com/google/android/setupdesign/template/RecyclerViewScrollHandlingDelegate.java
@@ -18,6 +18,7 @@ package com.google.android.setupdesign.template;
 
 import androidx.recyclerview.widget.RecyclerView;
 import android.util.Log;
+import android.view.ViewTreeObserver;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import com.google.android.setupdesign.template.RequireScrollMixin.ScrollHandlingDelegate;
@@ -53,8 +54,8 @@ public class RecyclerViewScrollHandlingDelegate implements ScrollHandlingDelegat
 
   @Override
   public void startListening() {
-    if (this.recyclerView != null) {
-      this.recyclerView.addOnScrollListener(
+    if (recyclerView != null) {
+      recyclerView.addOnScrollListener(
           new RecyclerView.OnScrollListener() {
             @Override
             public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
@@ -62,6 +63,17 @@ public class RecyclerViewScrollHandlingDelegate implements ScrollHandlingDelegat
             }
           });
 
+      // Because the view hierarchy could be changed for any reasons(e.g. view is added), we need
+      // to check the scrollability again after the layout is changed.
+      recyclerView
+          .getViewTreeObserver()
+          .addOnGlobalLayoutListener(
+              new ViewTreeObserver.OnGlobalLayoutListener() {
+                @Override
+                public void onGlobalLayout() {
+                  requireScrollMixin.notifyScrollabilityChange(canScrollDown());
+                }
+              });
       if (canScrollDown()) {
         requireScrollMixin.notifyScrollabilityChange(true);
       }
diff --git a/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java b/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java
index 6f1bb33..6d6f2a2 100644
--- a/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java
+++ b/main/src/com/google/android/setupdesign/template/RequireScrollMixin.java
@@ -352,7 +352,7 @@ public class RequireScrollMixin implements Mixin {
     CharSequence nextText = primaryButtonView.getText();
     primaryButtonView.setVisibility(View.INVISIBLE);
     primaryButtonView.setOnClickListener(createOnClickListener(onClickListener));
-    footerBarMixin.setButtonWidthForExpressiveStyle(/* isDownButton= */ false);
+    footerBarMixin.setButtonWidthForExpressiveStyle();
     LinearLayout footerContainer = footerBarMixin.getButtonContainer();
 
     setOnRequireScrollStateChangedListener(
@@ -366,7 +366,7 @@ public class RequireScrollMixin implements Mixin {
             if (primaryButtonView instanceof MaterialButton) {
               ((MaterialButton) primaryButtonView).setIcon(null);
               primaryButtonView.setText(nextText);
-              footerBarMixin.setButtonWidthForExpressiveStyle(/* isDownButton= */ false);
+              footerBarMixin.setButtonWidthForExpressiveStyle();
               // Screen no need to scroll, sets the secondary button as visible if it exists.
               if (secondaryButtonView != null) {
                 secondaryButtonView.setVisibility(View.VISIBLE);
@@ -390,7 +390,7 @@ public class RequireScrollMixin implements Mixin {
       ((MaterialButton) button).setIcon(icon);
       ((MaterialButton) button).setIconGravity(MaterialButton.ICON_GRAVITY_TEXT_START);
       ((MaterialButton) button).setIconPadding(0);
-      footerBarMixin.setButtonWidthForExpressiveStyle(/* isDownButton= */ true);
+      footerBarMixin.setDownButtonForExpressiveStyle();
     } else {
       Log.i(LOG_TAG, "Cannot set icon for the button. Skipping clean up text.");
     }
diff --git a/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java b/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java
index 05db85c..763baad 100644
--- a/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java
+++ b/main/src/com/google/android/setupdesign/util/HeaderAreaStyler.java
@@ -77,6 +77,7 @@ public final class HeaderAreaStyler {
             /* textLinkFontFamilyConfig= */ null,
             PartnerConfig.CONFIG_HEADER_TEXT_MARGIN_TOP,
             PartnerConfig.CONFIG_HEADER_TEXT_MARGIN_BOTTOM,
+            PartnerConfig.CONFIG_HEADER_FONT_VARIATION_SETTINGS,
             PartnerStyleHelper.getLayoutGravity(header.getContext())));
   }
 
diff --git a/main/src/com/google/android/setupdesign/util/ItemStyler.java b/main/src/com/google/android/setupdesign/util/ItemStyler.java
index e6d0131..03b2734 100644
--- a/main/src/com/google/android/setupdesign/util/ItemStyler.java
+++ b/main/src/com/google/android/setupdesign/util/ItemStyler.java
@@ -22,6 +22,7 @@ import android.os.Build;
 import android.os.Build.VERSION_CODES;
 import android.view.Gravity;
 import android.view.View;
+import android.view.ViewGroup;
 import android.widget.LinearLayout;
 import android.widget.TextView;
 import androidx.annotation.Nullable;
@@ -125,7 +126,59 @@ public final class ItemStyler {
             PartnerStyleHelper.getLayoutGravity(summaryTextView.getContext())));
   }
 
-  private static void applyPartnerCustomizationItemViewLayoutStyle(@Nullable View listItemView) {
+  /**
+   * Applies the partner layout margin style to the given list item view {@code listItemView}. The
+   * theme should set partner heavy theme config first, and then the partner layout style would be
+   * applied.
+   *
+   * @param listItemView A view would be applied partner layout margin style
+   */
+  @TargetApi(VERSION_CODES.JELLY_BEAN_MR1)
+  public static void applyPartnerCustomizationLayoutMarginStyle(@Nullable View listItemView) {
+    if (listItemView == null) {
+      return;
+    }
+
+    Context context = listItemView.getContext();
+    boolean partnerMarginStartAvailable =
+        PartnerConfigHelper.get(context)
+            .isPartnerConfigAvailable(PartnerConfig.CONFIG_LAYOUT_MARGIN_START);
+    boolean partnerMarginEndAvailable =
+        PartnerConfigHelper.get(context)
+            .isPartnerConfigAvailable(PartnerConfig.CONFIG_LAYOUT_MARGIN_END);
+
+    // TODO: After all users added the check before calling the API, this check can be
+    // deleted.
+    if (PartnerStyleHelper.shouldApplyPartnerResource(listItemView)
+        && (partnerMarginStartAvailable || partnerMarginEndAvailable)) {
+      int marginStart;
+      int marginEnd;
+      if (listItemView.getLayoutParams() instanceof ViewGroup.MarginLayoutParams) {
+        ViewGroup.MarginLayoutParams layoutParams =
+            (ViewGroup.MarginLayoutParams) listItemView.getLayoutParams();
+        if (partnerMarginStartAvailable) {
+          marginStart =
+              (int)
+                  PartnerConfigHelper.get(context)
+                      .getDimension(context, PartnerConfig.CONFIG_LAYOUT_MARGIN_START);
+        } else {
+          marginStart = layoutParams.leftMargin;
+        }
+        if (partnerMarginEndAvailable) {
+          marginEnd =
+              (int)
+                  PartnerConfigHelper.get(context)
+                      .getDimension(context, PartnerConfig.CONFIG_LAYOUT_MARGIN_END);
+        } else {
+          marginEnd = layoutParams.rightMargin;
+        }
+        layoutParams.setMargins(
+            marginStart, layoutParams.topMargin, marginEnd, layoutParams.bottomMargin);
+      }
+    }
+  }
+
+  public static void applyPartnerCustomizationItemViewLayoutStyle(@Nullable View listItemView) {
     Context context = listItemView.getContext();
     float paddingTop;
     if (PartnerConfigHelper.get(context)
diff --git a/main/src/com/google/android/setupdesign/util/LayoutStyler.java b/main/src/com/google/android/setupdesign/util/LayoutStyler.java
index 9e1d66b..b43de3d 100644
--- a/main/src/com/google/android/setupdesign/util/LayoutStyler.java
+++ b/main/src/com/google/android/setupdesign/util/LayoutStyler.java
@@ -163,7 +163,10 @@ public final class LayoutStyler {
             marginLayoutParams = new ViewGroup.MarginLayoutParams(params);
           }
           marginLayoutParams.setMargins(
-              extraPaddingStart, view.getPaddingTop(), extraPaddingEnd, view.getPaddingBottom());
+              extraPaddingStart,
+              marginLayoutParams.topMargin,
+              extraPaddingEnd,
+              marginLayoutParams.bottomMargin);
         } else {
           view.setPadding(
               extraPaddingStart, view.getPaddingTop(), extraPaddingEnd, view.getPaddingBottom());
diff --git a/main/src/com/google/android/setupdesign/util/TextViewPartnerStyler.java b/main/src/com/google/android/setupdesign/util/TextViewPartnerStyler.java
index ced6fd4..d784f02 100644
--- a/main/src/com/google/android/setupdesign/util/TextViewPartnerStyler.java
+++ b/main/src/com/google/android/setupdesign/util/TextViewPartnerStyler.java
@@ -21,6 +21,8 @@ import static com.google.android.setupcompat.partnerconfig.PartnerConfigHelper.i
 import android.annotation.SuppressLint;
 import android.content.Context;
 import android.graphics.Typeface;
+import android.text.TextUtils;
+import android.util.Log;
 import android.util.TypedValue;
 import android.view.ViewGroup;
 import android.widget.LinearLayout;
@@ -34,6 +36,8 @@ import com.google.android.setupdesign.view.RichTextView;
 /** Helper class to apply partner configurations to a textView. */
 final class TextViewPartnerStyler {
 
+  private static final String TAG = "TextViewPartnerStyler";
+
   /** Normal font weight. */
   private static final int FONT_WEIGHT_NORMAL = 400;
 
@@ -81,10 +85,26 @@ final class TextViewPartnerStyler {
       }
     }
 
+    String fontVariationSettings = null;
+    boolean isFontVariationSettingsEnabled = false;
+    if (textPartnerConfigs.getTextFontVariationSettingsConfig() != null
+        && PartnerConfigHelper.get(context)
+            .isPartnerConfigAvailable(textPartnerConfigs.getTextFontVariationSettingsConfig())) {
+      fontVariationSettings =
+          PartnerConfigHelper.get(context)
+              .getString(context, textPartnerConfigs.getTextFontVariationSettingsConfig());
+      if (isFontVariationSupported(fontVariationSettings)) {
+        isFontVariationSettingsEnabled = true;
+      }
+    }
+
     Typeface fontFamily = null;
+    // If the font variation settings is enabled, we will skip the font family from the partner
+    // config to avoid font variation settings can't be applied.
     if (textPartnerConfigs.getTextFontFamilyConfig() != null
         && PartnerConfigHelper.get(context)
-            .isPartnerConfigAvailable(textPartnerConfigs.getTextFontFamilyConfig())) {
+            .isPartnerConfigAvailable(textPartnerConfigs.getTextFontFamilyConfig())
+        && !isFontVariationSettingsEnabled) {
       String fontFamilyName =
           PartnerConfigHelper.get(context)
               .getString(context, textPartnerConfigs.getTextFontFamilyConfig());
@@ -92,10 +112,13 @@ final class TextViewPartnerStyler {
     }
 
     Typeface font;
+    // If the font variation settings is enabled, we will skip the font weight from the partner
+    // config to avoid font variation settings can't be applied.
     if (isFontWeightEnabled(context)
         && textPartnerConfigs.getTextFontWeightConfig() != null
         && PartnerConfigHelper.get(context)
-            .isPartnerConfigAvailable(textPartnerConfigs.getTextFontWeightConfig())) {
+            .isPartnerConfigAvailable(textPartnerConfigs.getTextFontWeightConfig())
+        && !isFontVariationSettingsEnabled) {
       int weight =
           PartnerConfigHelper.get(context)
               .getInteger(
@@ -112,6 +135,14 @@ final class TextViewPartnerStyler {
       textView.setTypeface(font);
     }
 
+    if (textView != null && isFontVariationSupported(fontVariationSettings)) {
+      try {
+        textView.setFontVariationSettings(fontVariationSettings);
+      } catch (Exception ex) {
+        Log.e(TAG, "Failed to set font variation settings: " + ex.getMessage());
+      }
+    }
+
     if (textView instanceof RichTextView && textPartnerConfigs.getLinkTextFontFamilyConfig() != null
         && PartnerConfigHelper.get(context)
         .isPartnerConfigAvailable(textPartnerConfigs.getLinkTextFontFamilyConfig())) {
@@ -128,6 +159,10 @@ final class TextViewPartnerStyler {
     textView.setGravity(textPartnerConfigs.getTextGravity());
   }
 
+  private static boolean isFontVariationSupported(String fontVariationSettings) {
+    return fontVariationSettings != null && !TextUtils.isEmpty(fontVariationSettings);
+  }
+
   /**
    * Applies given partner configurations {@code textPartnerConfigs} to the {@code textView}.
    *
@@ -192,6 +227,7 @@ final class TextViewPartnerStyler {
     private final PartnerConfig textLinkFontFamilyConfig;
     private final PartnerConfig textMarginTopConfig;
     private final PartnerConfig textMarginBottomConfig;
+    private PartnerConfig textFontVariationSettingsConfig = null;
     private final int textGravity;
 
     public TextPartnerConfigs(
@@ -215,6 +251,29 @@ final class TextViewPartnerStyler {
       this.textGravity = textGravity;
     }
 
+    public TextPartnerConfigs(
+        @Nullable PartnerConfig textColorConfig,
+        @Nullable PartnerConfig textLinkedColorConfig,
+        @Nullable PartnerConfig textSizeConfig,
+        @Nullable PartnerConfig textFontFamilyConfig,
+        @Nullable PartnerConfig textFontWeightConfig,
+        @Nullable PartnerConfig textLinkFontFamilyConfig,
+        @Nullable PartnerConfig textMarginTopConfig,
+        @Nullable PartnerConfig textMarginBottomConfig,
+        @Nullable PartnerConfig textFontVariationSettingsConfig,
+        int textGravity) {
+      this.textColorConfig = textColorConfig;
+      this.textLinkedColorConfig = textLinkedColorConfig;
+      this.textSizeConfig = textSizeConfig;
+      this.textFontFamilyConfig = textFontFamilyConfig;
+      this.textFontWeightConfig = textFontWeightConfig;
+      this.textLinkFontFamilyConfig = textLinkFontFamilyConfig;
+      this.textMarginTopConfig = textMarginTopConfig;
+      this.textMarginBottomConfig = textMarginBottomConfig;
+      this.textFontVariationSettingsConfig = textFontVariationSettingsConfig;
+      this.textGravity = textGravity;
+    }
+
     public PartnerConfig getTextColorConfig() {
       return textColorConfig;
     }
@@ -247,6 +306,10 @@ final class TextViewPartnerStyler {
       return textMarginBottomConfig;
     }
 
+    public PartnerConfig getTextFontVariationSettingsConfig() {
+      return textFontVariationSettingsConfig;
+    }
+
     public int getTextGravity() {
       return textGravity;
     }
diff --git a/main/src/com/google/android/setupdesign/view/BulletPointView.java b/main/src/com/google/android/setupdesign/view/BulletPointView.java
new file mode 100644
index 0000000..f64d48f
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/view/BulletPointView.java
@@ -0,0 +1,124 @@
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
+package com.google.android.setupdesign.view;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.graphics.drawable.Drawable;
+import android.util.AttributeSet;
+import android.view.View;
+import android.widget.ImageView;
+import android.widget.LinearLayout;
+import androidx.annotation.Nullable;
+import com.google.android.setupdesign.R;
+
+/**
+ * Bullet points are a versatile design element used in screen layouts to present information in a
+ * concise, organized, and visually appealing manner. They break down complex information or lists
+ * into easily digestible chunks, improving readability and scannability. Bullet points can be used
+ * to highlight key features, list steps in a process, or summarize benefits.
+ */
+public class BulletPointView extends LinearLayout {
+
+  @Nullable private Drawable icon;
+  @Nullable private CharSequence title;
+  @Nullable private CharSequence summary;
+
+  private RichTextView titleView;
+  private RichTextView summaryView;
+  private ImageView iconView;
+
+  public BulletPointView(Context context) {
+    super(context);
+    init();
+  }
+
+  public BulletPointView(Context context, AttributeSet attrs) {
+    super(context, attrs);
+    TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudBulletPointView);
+    icon = a.getDrawable(R.styleable.SudBulletPointView_android_icon);
+    title = a.getText(R.styleable.SudBulletPointView_android_title);
+    summary = a.getText(R.styleable.SudBulletPointView_android_summary);
+    a.recycle();
+    init();
+  }
+
+  public BulletPointView(Context context, AttributeSet attrs, int defStyle) {
+    super(context, attrs, defStyle);
+    TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudBulletPointView);
+    icon = a.getDrawable(R.styleable.SudBulletPointView_android_icon);
+    title = a.getText(R.styleable.SudBulletPointView_android_title);
+    summary = a.getText(R.styleable.SudBulletPointView_android_summary);
+    a.recycle();
+    init();
+  }
+
+  private void init() {
+    View.inflate(getContext(), R.layout.sud_bullet_point_default, this);
+    titleView = findViewById(R.id.sud_items_title);
+    summaryView = findViewById(R.id.sud_items_summary);
+    iconView = findViewById(R.id.sud_items_icon);
+    if (titleView != null && title != null) {
+      titleView.setText(title);
+      titleView.setVisibility(View.VISIBLE);
+    }
+    if (summaryView != null && summary != null) {
+      summaryView.setText(summary);
+      summaryView.setVisibility(View.VISIBLE);
+    }
+    if (iconView != null && icon != null) {
+      iconView.setImageDrawable(icon);
+      iconView.setVisibility(View.VISIBLE);
+    }
+  }
+
+  public void setTitle(CharSequence title) {
+    this.title = title;
+    if (titleView != null) {
+      titleView.setText(title);
+      titleView.setVisibility(View.VISIBLE);
+    }
+  }
+
+  public void setSummary(CharSequence summary) {
+    this.summary = summary;
+    if (summaryView != null) {
+      summaryView.setText(summary);
+      summaryView.setVisibility(View.VISIBLE);
+    }
+  }
+
+  public void setIcon(Drawable icon) {
+    this.icon = icon;
+    if (iconView != null) {
+      iconView.setImageDrawable(icon);
+      iconView.setVisibility(View.VISIBLE);
+    }
+  }
+
+  public Drawable getIcon() {
+    return icon;
+  }
+
+  public CharSequence getTitle() {
+    return title;
+  }
+
+  public CharSequence getSummary() {
+    return summary;
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/view/CardView.java b/main/src/com/google/android/setupdesign/view/CardView.java
new file mode 100644
index 0000000..0082ba2
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/view/CardView.java
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
+package com.google.android.setupdesign.view;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.graphics.drawable.Drawable;
+import android.util.AttributeSet;
+import android.view.View;
+import android.widget.ImageView;
+import android.widget.LinearLayout;
+import androidx.annotation.Nullable;
+import androidx.core.content.ContextCompat;
+import com.google.android.setupdesign.R;
+
+/** A card view that can be used to display a title and an icon. */
+public class CardView extends LinearLayout implements View.OnClickListener {
+
+  private Drawable icon;
+  private CharSequence title;
+
+  /* The line height of the title. */
+  private int lineHeight;
+
+  private ImageView iconView;
+  protected WrapTextView titleView;
+  private OnClickListener onClickListener;
+  protected boolean skipClickSelection;
+
+  public CardView(Context context) {
+    this(context, /* attrs= */ null, /* defStyleAttr= */ 0);
+  }
+
+  public CardView(Context context, AttributeSet attrs) {
+    this(context, attrs, /* defStyleAttr= */ 0);
+  }
+
+  public CardView(Context context, AttributeSet attrs, int defStyleAttr) {
+    super(context, attrs, defStyleAttr);
+    TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudCardView);
+    icon = a.getDrawable(R.styleable.SudCardView_sudIcon);
+    title = a.getText(R.styleable.SudCardView_sudTitleText);
+    skipClickSelection =
+        a.getBoolean(R.styleable.SudCardView_sudCardViewSkipClickSelection, /* defValue= */ false);
+    lineHeight =
+        a.getDimensionPixelSize(R.styleable.SudCardView_android_lineHeight, /* defValue= */ 0);
+    a.recycle();
+    init();
+  }
+
+  private void init() {
+    View.inflate(getContext(), R.layout.sud_card_view_default, this);
+    // set on click listener to this view to handle the internal click event.
+    super.setOnClickListener(this);
+    iconView = findViewById(R.id.sud_items_icon);
+    titleView = findViewById(R.id.sud_items_title);
+    if (iconView != null && icon != null) {
+      iconView.setImageDrawable(icon);
+    }
+    if (titleView != null) {
+      titleView.setLineHeight(lineHeight);
+      if (title != null) {
+        titleView.setText(title);
+      }
+    }
+  }
+
+  public void setCardTitle(CharSequence title) {
+    this.title = title;
+    if (titleView != null) {
+      titleView.setText(title);
+    }
+  }
+
+  public void setCardIcon(Drawable icon) {
+    this.icon = icon;
+    if (iconView != null) {
+      iconView.setImageDrawable(icon);
+    }
+  }
+
+  public CharSequence getCardTitle() {
+    return title;
+  }
+
+  public Drawable getCardIcon() {
+    return icon;
+  }
+
+  /** Sets the line height of the title. */
+  public void setLineHeight(int lineHeight) {
+    this.lineHeight = lineHeight;
+    if (titleView != null) {
+      titleView.setLineHeight(lineHeight);
+    }
+  }
+
+  /** Returns the line height of the title. */
+  public int getLineHeight() {
+    if (titleView != null) {
+      return titleView.getLineHeight();
+    }
+    return lineHeight;
+  }
+
+  @Override
+  public void onClick(View v) {
+    if (!skipClickSelection) {
+      v.setSelected(true);
+      if (iconView != null) {
+        iconView.setImageDrawable(
+            ContextCompat.getDrawable(this.getContext(), R.drawable.sud_ic_check_mark));
+        iconView.setSelected(true);
+        v.setContentDescription(
+            getContext()
+                .getString(
+                    com.google.android.setupdesign.strings.R.string
+                        .sud_card_view_check_mark_icon_label));
+      }
+      if (titleView != null) {
+        titleView.setSelected(true);
+      }
+    }
+    if (onClickListener != null) {
+      // handle the external click event.
+      onClickListener.onClick(v);
+    }
+  }
+
+  @Override
+  public final void setOnClickListener(@Nullable OnClickListener listener) {
+    onClickListener = listener;
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/view/HeaderRecyclerView.java b/main/src/com/google/android/setupdesign/view/HeaderRecyclerView.java
index 57fc35d..e6a7c0d 100644
--- a/main/src/com/google/android/setupdesign/view/HeaderRecyclerView.java
+++ b/main/src/com/google/android/setupdesign/view/HeaderRecyclerView.java
@@ -200,6 +200,7 @@ public class HeaderRecyclerView extends RecyclerView {
   }
 
   private View header;
+  private boolean shouldApplyAdditionalMargin;
   private int headerRes;
 
   public HeaderRecyclerView(Context context) {
@@ -226,9 +227,15 @@ public class HeaderRecyclerView extends RecyclerView {
         getContext()
             .obtainStyledAttributes(attrs, R.styleable.SudHeaderRecyclerView, defStyleAttr, 0);
     headerRes = a.getResourceId(R.styleable.SudHeaderRecyclerView_sudHeader, 0);
+    shouldApplyAdditionalMargin =
+        a.getBoolean(R.styleable.SudHeaderRecyclerView_sudShouldApplyAdditionalMargin, false);
     a.recycle();
   }
 
+  public boolean shouldApplyAdditionalMargin() {
+    return shouldApplyAdditionalMargin;
+  }
+
   @Override
   public void onInitializeAccessibilityEvent(AccessibilityEvent event) {
     super.onInitializeAccessibilityEvent(event);
diff --git a/main/src/com/google/android/setupdesign/view/IconUniformityAppImageView.java b/main/src/com/google/android/setupdesign/view/IconUniformityAppImageView.java
index d4e6ad8..7824b93 100644
--- a/main/src/com/google/android/setupdesign/view/IconUniformityAppImageView.java
+++ b/main/src/com/google/android/setupdesign/view/IconUniformityAppImageView.java
@@ -143,6 +143,16 @@ public class IconUniformityAppImageView extends ImageView
     super.onDraw(canvas);
   }
 
+  /**
+   * Sets the color of backdrop drawable.
+   *
+   * @param backdropColorResId the resource id of the backdrop color
+   */
+  public void setBackdropDrawableColor(int backdropColorResId) {
+    this.backdropColorResId = backdropColorResId;
+    backdropDrawable.setColor(ContextCompat.getColor(getContext(), backdropColorResId));
+  }
+
   private void setLegacyTransformationMatrix(
       float drawableWidth, float drawableHeight, float imageViewWidth, float imageViewHeight) {
     Matrix scaleMatrix = new Matrix();
diff --git a/main/src/com/google/android/setupdesign/view/InfoFooterView.java b/main/src/com/google/android/setupdesign/view/InfoFooterView.java
new file mode 100644
index 0000000..2f85d7d
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/view/InfoFooterView.java
@@ -0,0 +1,113 @@
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
+package com.google.android.setupdesign.view;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.graphics.drawable.Drawable;
+import android.util.AttributeSet;
+import android.view.View;
+import android.widget.ImageView;
+import android.widget.LinearLayout;
+import android.widget.RelativeLayout;
+import androidx.annotation.Nullable;
+import com.google.android.setupdesign.R;
+
+/**
+ * An extension of ScrollView that will invoke a listener callback when the ScrollView needs
+ * scrolling, and when the ScrollView is being scrolled to the bottom. This is often used in Setup
+ * Wizard as a way to ensure that users see all the content before proceeding.
+ */
+public class InfoFooterView extends LinearLayout {
+
+  @Nullable private Drawable icon;
+  @Nullable private CharSequence title;
+  private Boolean alignParentBottom = true;
+
+  private RichTextView titleView;
+  private ImageView iconView;
+
+  public InfoFooterView(Context context) {
+    super(context);
+    init();
+  }
+
+  public InfoFooterView(Context context, AttributeSet attrs) {
+    super(context, attrs);
+    TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudInfoFooterView);
+    icon = a.getDrawable(R.styleable.SudInfoFooterView_android_icon);
+    title = a.getText(R.styleable.SudInfoFooterView_android_title);
+    alignParentBottom = a.getBoolean(R.styleable.SudInfoFooterView_sudAlignParentBottom, true);
+    a.recycle();
+    init();
+  }
+
+  public InfoFooterView(Context context, AttributeSet attrs, int defStyle) {
+    super(context, attrs, defStyle);
+    TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudInfoFooterView);
+    icon = a.getDrawable(R.styleable.SudInfoFooterView_android_icon);
+    title = a.getText(R.styleable.SudInfoFooterView_android_title);
+    a.recycle();
+    init();
+  }
+
+  private void init() {
+    View.inflate(getContext(), R.layout.sud_info_footer_default, this);
+    titleView = findViewById(R.id.sud_info_footer_title);
+    iconView = findViewById(R.id.sud_info_footer_icon);
+    if (titleView != null && title != null) {
+      titleView.setText(title);
+      titleView.setVisibility(View.VISIBLE);
+    }
+    if (iconView != null && icon != null) {
+      iconView.setImageDrawable(icon);
+      iconView.setVisibility(View.VISIBLE);
+    }
+    if (!alignParentBottom) {
+      View infoFooterContainer = findViewById(R.id.sud_info_footer_container);
+      RelativeLayout.LayoutParams layoutParams =
+          (RelativeLayout.LayoutParams) infoFooterContainer.getLayoutParams();
+      // By default, ALIGN_PARENT_BOTTOM is set. Setting it to 0 removes the rule.
+      layoutParams.addRule(RelativeLayout.ALIGN_PARENT_BOTTOM, 0);
+      infoFooterContainer.setLayoutParams(layoutParams);
+    }
+  }
+
+  public void setTitle(CharSequence title) {
+    this.title = title;
+    if (titleView != null) {
+      titleView.setText(title);
+      titleView.setVisibility(View.VISIBLE);
+    }
+  }
+
+  public void setIcon(Drawable icon) {
+    this.icon = icon;
+    if (iconView != null) {
+      iconView.setImageDrawable(icon);
+      iconView.setVisibility(View.VISIBLE);
+    }
+  }
+
+  public Drawable getIcon() {
+    return icon;
+  }
+
+  public CharSequence getTitle() {
+    return title;
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/view/InsetAdjustmentLayout.java b/main/src/com/google/android/setupdesign/view/InsetAdjustmentLayout.java
new file mode 100644
index 0000000..424bc58
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/view/InsetAdjustmentLayout.java
@@ -0,0 +1,73 @@
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
+package com.google.android.setupdesign.view;
+
+import android.content.Context;
+import android.os.Build.VERSION;
+import android.os.Build.VERSION_CODES;
+import android.util.AttributeSet;
+import android.view.WindowInsets;
+import android.widget.LinearLayout;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
+import com.google.android.setupcompat.util.Logger;
+
+/**
+ * A custom LinearLayout that modifies system window insets, specifically the bottom inset, based on
+ * partner configuration.
+ *
+ * <p>This layout for large screen is designed to handle edge-to-edge display scenarios,
+ * particularly when {@link PartnerConfigHelper#isGlifExpressiveEnabled(Context)} is true. It
+ * removes the bottom system window inset, effectively extending the layout to the bottom edge of
+ * the screen.
+ *
+ * <p>This layout should be used as a root layout or within a view hierarchy where edge-to-edge
+ * behavior is desired. It ensures that content extends to the bottom of the screen when the Glif
+ * Expressive feature is enabled.
+ */
+public class InsetAdjustmentLayout extends LinearLayout {
+
+  private static final Logger LOG = new Logger("InsetAdjustmentLayout");
+
+  public InsetAdjustmentLayout(Context context) {
+    super(context);
+  }
+
+  public InsetAdjustmentLayout(Context context, AttributeSet attrs) {
+    super(context, attrs);
+  }
+
+  public InsetAdjustmentLayout(Context context, AttributeSet attrs, int defStyleAttr) {
+    super(context, attrs, defStyleAttr);
+  }
+
+  @Override
+  public WindowInsets onApplyWindowInsets(WindowInsets insets) {
+    // TODO: b/398407478 - Add test case for edge to edge to layout from library.
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
+      if (VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP && insets.getSystemWindowInsetBottom() > 0) {
+        LOG.atDebug("NavigationBarHeight: " + insets.getSystemWindowInsetBottom());
+        insets =
+            insets.replaceSystemWindowInsets(
+                insets.getSystemWindowInsetLeft(),
+                insets.getSystemWindowInsetTop(),
+                insets.getSystemWindowInsetRight(),
+                /* bottom= */ 0);
+      }
+    }
+    return super.onApplyWindowInsets(insets);
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/view/PromoCardView.java b/main/src/com/google/android/setupdesign/view/PromoCardView.java
new file mode 100644
index 0000000..b0facc8
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/view/PromoCardView.java
@@ -0,0 +1,224 @@
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
+package com.google.android.setupdesign.view;
+
+import android.content.Context;
+import android.content.res.TypedArray;
+import android.graphics.drawable.Drawable;
+import android.graphics.drawable.GradientDrawable;
+import android.util.AttributeSet;
+import android.view.View;
+import android.widget.ImageView;
+import android.widget.LinearLayout;
+import androidx.annotation.Nullable;
+import com.google.android.setupcompat.partnerconfig.PartnerConfig;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
+import com.google.android.setupdesign.R;
+
+/**
+ * The promo card item is extension of a linear layout with an icon with title and summary and with
+ * some modifications to make it more suitable for promo items. For example, the promo card item
+ * layout has a larger icon size and a different background color.
+ */
+public class PromoCardView extends LinearLayout {
+
+  @Nullable private Drawable icon;
+  @Nullable private CharSequence title;
+  @Nullable private CharSequence summary;
+
+  private RichTextView titleView;
+  private RichTextView summaryView;
+  private ImageView iconView;
+  private boolean topRoundedCorner;
+  private boolean bottomRoundedCorner;
+
+  public PromoCardView(Context context) {
+    super(context);
+    init();
+  }
+
+  public PromoCardView(Context context, AttributeSet attrs) {
+    super(context, attrs);
+    TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudPromoCardView);
+    icon = a.getDrawable(R.styleable.SudPromoCardView_android_icon);
+    title = a.getText(R.styleable.SudPromoCardView_android_title);
+    summary = a.getText(R.styleable.SudPromoCardView_android_summary);
+    topRoundedCorner = a.getBoolean(R.styleable.SudPromoCardView_sudTopRoundedCorner, false);
+    bottomRoundedCorner = a.getBoolean(R.styleable.SudPromoCardView_sudBottomRoundedCorner, false);
+    a.recycle();
+    init();
+  }
+
+  public PromoCardView(Context context, AttributeSet attrs, int defStyle) {
+    super(context, attrs, defStyle);
+    TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SudPromoCardView);
+    icon = a.getDrawable(R.styleable.SudPromoCardView_android_icon);
+    title = a.getText(R.styleable.SudPromoCardView_android_title);
+    summary = a.getText(R.styleable.SudPromoCardView_android_summary);
+    topRoundedCorner = a.getBoolean(R.styleable.SudPromoCardView_sudTopRoundedCorner, false);
+    bottomRoundedCorner = a.getBoolean(R.styleable.SudPromoCardView_sudBottomRoundedCorner, false);
+    a.recycle();
+    init();
+  }
+
+  private void init() {
+    View.inflate(getContext(), R.layout.sud_promo_card_default, this);
+    titleView = findViewById(R.id.sud_items_title);
+    summaryView = findViewById(R.id.sud_items_summary);
+    iconView = findViewById(R.id.sud_items_icon);
+    if (titleView != null && title != null) {
+      titleView.setText(title);
+      titleView.setVisibility(View.VISIBLE);
+    }
+    if (summaryView != null && summary != null) {
+      summaryView.setText(summary);
+      summaryView.setVisibility(View.VISIBLE);
+    }
+    if (iconView != null && icon != null) {
+      iconView.setImageDrawable(icon);
+      iconView.setVisibility(View.VISIBLE);
+    }
+    updateBackground();
+  }
+
+  private Drawable getFirstBackground(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundFirst});
+    Drawable firstBackground = a.getDrawable(0);
+    a.recycle();
+    return firstBackground;
+  }
+
+  private Drawable getLastBackground(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundLast});
+    Drawable lastBackground = a.getDrawable(0);
+    a.recycle();
+    return lastBackground;
+  }
+
+  private Drawable getMiddleBackground(Context context) {
+    TypedArray a = context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackground});
+    Drawable middleBackground = a.getDrawable(0);
+    a.recycle();
+    return middleBackground;
+  }
+
+  private Drawable getSingleBackground(Context context) {
+    TypedArray a =
+        context.getTheme().obtainStyledAttributes(new int[] {R.attr.sudItemBackgroundSingle});
+    Drawable singleBackground = a.getDrawable(0);
+    a.recycle();
+    return singleBackground;
+  }
+
+  private void updateBackground() {
+    float cornerRadius =
+        getResources().getDimension(R.dimen.sud_glif_expressive_item_corner_radius);
+    float groupCornerRadius =
+        PartnerConfigHelper.get(getContext())
+            .getDimension(
+                getContext(), PartnerConfig.CONFIG_ITEMS_GROUP_CORNER_RADIUS, cornerRadius);
+    Drawable background = getMiddleBackground(getContext());
+
+    if (topRoundedCorner && bottomRoundedCorner) {
+      background = getSingleBackground(getContext());
+    } else if (topRoundedCorner) {
+      background = getFirstBackground(getContext());
+    } else if (bottomRoundedCorner) {
+      background = getLastBackground(getContext());
+    }
+
+    if (background instanceof GradientDrawable) {
+      float topCornerRadius = cornerRadius;
+      float bottomCornerRadius = cornerRadius;
+      if (topRoundedCorner) {
+        topCornerRadius = groupCornerRadius;
+      }
+      if (bottomRoundedCorner) {
+        bottomCornerRadius = groupCornerRadius;
+      }
+      ((GradientDrawable) background)
+          .setCornerRadii(
+              new float[] {
+                topCornerRadius,
+                topCornerRadius,
+                topCornerRadius,
+                topCornerRadius,
+                bottomCornerRadius,
+                bottomCornerRadius,
+                bottomCornerRadius,
+                bottomCornerRadius
+              });
+      findViewById(R.id.sud_promo_card_container).setBackgroundDrawable(background);
+    }
+  }
+
+  public void setTopRoundedCorner(boolean topRoundedCorner) {
+    this.topRoundedCorner = topRoundedCorner;
+    updateBackground();
+  }
+
+  public void setBottomRoundedCorner(boolean bottomRoundedCorner) {
+    this.bottomRoundedCorner = bottomRoundedCorner;
+    updateBackground();
+  }
+
+  public void setTitle(CharSequence title) {
+    this.title = title;
+    if (titleView != null) {
+      titleView.setText(title);
+      titleView.setVisibility(View.VISIBLE);
+    }
+  }
+
+  public void setSummary(CharSequence summary) {
+    this.summary = summary;
+    if (summaryView != null) {
+      summaryView.setText(summary);
+      summaryView.setVisibility(View.VISIBLE);
+    }
+  }
+
+  public void setIcon(Drawable icon) {
+    this.icon = icon;
+    if (iconView != null) {
+      iconView.setImageDrawable(icon);
+      iconView.setVisibility(View.VISIBLE);
+    }
+  }
+
+  public Drawable getIcon() {
+    return icon;
+  }
+
+  public CharSequence getTitle() {
+    return title;
+  }
+
+  public CharSequence getSummary() {
+    return summary;
+  }
+
+  public boolean isTopRoundedCorner() {
+    return topRoundedCorner;
+  }
+
+  public boolean isBottomRoundedCorner() {
+    return bottomRoundedCorner;
+  }
+}
diff --git a/main/src/com/google/android/setupdesign/view/StickyHeaderListView.java b/main/src/com/google/android/setupdesign/view/StickyHeaderListView.java
index 07d1781..901ae3c 100644
--- a/main/src/com/google/android/setupdesign/view/StickyHeaderListView.java
+++ b/main/src/com/google/android/setupdesign/view/StickyHeaderListView.java
@@ -55,6 +55,7 @@ public class StickyHeaderListView extends ListView {
   private View sticky;
   private View stickyContainer;
   private int statusBarInset = 0;
+  private boolean shouldApplyAdditionalMargin;
   private final RectF stickyRect = new RectF();
 
   public StickyHeaderListView(Context context) {
@@ -81,6 +82,9 @@ public class StickyHeaderListView extends ListView {
         getContext()
             .obtainStyledAttributes(attrs, R.styleable.SudStickyHeaderListView, defStyleAttr, 0);
     int headerResId = a.getResourceId(R.styleable.SudStickyHeaderListView_sudHeader, 0);
+
+    shouldApplyAdditionalMargin =
+        a.getBoolean(R.styleable.SudStickyHeaderListView_sudShouldApplyAdditionalMargin, false);
     if (headerResId != 0) {
       LayoutInflater inflater = LayoutInflater.from(getContext());
       View header = inflater.inflate(headerResId, this, false);
@@ -97,6 +101,10 @@ public class StickyHeaderListView extends ListView {
     }
   }
 
+  public boolean shouldApplyAdditionalMargin() {
+    return shouldApplyAdditionalMargin;
+  }
+
   public void updateStickyView() {
     sticky = findViewWithTag("sticky");
     stickyContainer = findViewWithTag("stickyContainer");
diff --git a/main/src/com/google/android/setupdesign/view/WrapTextView.java b/main/src/com/google/android/setupdesign/view/WrapTextView.java
new file mode 100644
index 0000000..d6686ac
--- /dev/null
+++ b/main/src/com/google/android/setupdesign/view/WrapTextView.java
@@ -0,0 +1,76 @@
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
+package com.google.android.setupdesign.view;
+
+import static java.lang.Math.max;
+
+import android.content.Context;
+import androidx.appcompat.widget.AppCompatTextView;
+import android.text.Layout;
+import android.util.AttributeSet;
+import android.view.View;
+import androidx.annotation.VisibleForTesting;
+
+/**
+ * A TextView that, when its width is wrap_content, will repeatedly measure until we get a width
+ * that actually wraps its text label.
+ */
+public class WrapTextView extends AppCompatTextView {
+
+  public WrapTextView(Context context) {
+    super(context);
+  }
+
+  public WrapTextView(Context context, AttributeSet attrs) {
+    super(context, attrs);
+  }
+
+  public WrapTextView(Context context, AttributeSet attrs, int defStyleAttr) {
+    super(context, attrs, defStyleAttr);
+  }
+
+  @Override
+  public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
+    super.onMeasure(widthMeasureSpec, heightMeasureSpec);
+    int newWidthSpec = wrapMeasure(widthMeasureSpec);
+    if (newWidthSpec != widthMeasureSpec) {
+      super.onMeasure(newWidthSpec, heightMeasureSpec);
+    }
+  }
+
+  @VisibleForTesting
+  int wrapMeasure(int widthMeasureSpec) {
+    if (View.MeasureSpec.getMode(widthMeasureSpec) == View.MeasureSpec.AT_MOST) {
+      final Layout layout = getLayout();
+      final int lineCount = layout.getLineCount();
+      if (lineCount > 1) {
+        float maxLineWidth = 0;
+        for (int i = 0; i < lineCount; i++) {
+          // Find the longest line width
+          maxLineWidth = max(maxLineWidth, layout.getLineWidth(i));
+        }
+        final int newTotalWidth =
+            (int) Math.ceil(maxLineWidth) + getTotalPaddingLeft() + getTotalPaddingRight();
+        if (newTotalWidth < getMeasuredWidth()) {
+          // Re-measure with the longest line length if it has changed.
+          return View.MeasureSpec.makeMeasureSpec(newTotalWidth, View.MeasureSpec.AT_MOST);
+        }
+      }
+    }
+    return widthMeasureSpec;
+  }
+}
diff --git a/strings/res/values/strings.xml b/strings/res/values/strings.xml
index 0b976a5..21505de 100644
--- a/strings/res/values/strings.xml
+++ b/strings/res/values/strings.xml
@@ -30,4 +30,31 @@
 
     <!-- The default device name when other resources get the device name are not available [CHAR LIMIT=20] -->
     <string name="sud_default_device_name">device</string>
+
+    <!-- Expandable switch item text to show more information [CHAR LIMIT=30] -->
+    <string name="sud_more_info">More info</string>
+
+    <!-- Expandable switch item text to collapse the information [CHAR LIMIT=30] -->
+    <string name="sud_less_info">Less info</string>
+
+    <!-- Label for card view check mark icon [CHAR LIMIT=40] -->
+    <string name="sud_card_view_check_mark_icon_label">checked</string>
+
+    <!-- Label for SudLottieAnimationView animation playing status [CHAR LIMIT=NONE] -->
+    <string name="sud_lottie_animation_view_accessibility_animation_playing_status">animation playing</string>
+
+    <!-- Label for SudLottieAnimationView animation paused status  [CHAR LIMIT=NONE] -->
+    <string name="sud_lottie_animation_view_accessibility_animation_paused_status">animation paused</string>
+
+    <!-- Label for SudLottieAnimationView role description [CHAR LIMIT=NONE] -->
+    <string name="sud_lottie_animation_view_role_description">Stoppable animation</string>
+
+    <!-- Label for triggering pause animation action on SudLottieAnimationView [CHAR LIMIT=NONE] -->
+    <string name="sud_lottie_animation_view_accessibility_action_pause">pause</string>
+
+    <!-- Label for triggering resume animation action on SudLottieAnimationView [CHAR LIMIT=NONE] -->
+    <string name="sud_lottie_animation_view_accessibility_action_resume">resume</string>
+
+    <!-- Label for SuwLottieAnimationView description [CHAR LIMIT=NONE] -->
+    <string name="sud_lottie_animation_view_accessibility_description">Animation</string>
 </resources>
```

