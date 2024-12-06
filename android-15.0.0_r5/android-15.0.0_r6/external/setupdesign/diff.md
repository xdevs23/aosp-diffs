```diff
diff --git a/lottie_loading_layout/res/values-v34/layouts.xml b/lottie_loading_layout/res/values-v34/layouts.xml
index 7d5a5d3..ad908d3 100644
--- a/lottie_loading_layout/res/values-v34/layouts.xml
+++ b/lottie_loading_layout/res/values-v34/layouts.xml
@@ -15,8 +15,7 @@
     limitations under the License.
 -->
 
-<resources xmlns:tools="http://schemas.android.com/tools"
-    tools:keep="@layout/*_two_pane">
+<resources xmlns:tools="http://schemas.android.com/tools">
     <item name="sud_glif_loading_template_two_pane" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_loading_template_compat</item>
     <item name="sud_glif_fullscreen_loading_template_two_pane" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_loading_template_compat</item>
 </resources>
diff --git a/lottie_loading_layout/res/values-w840dp-v34/layouts.xml b/lottie_loading_layout/res/values-w840dp-v34/layouts.xml
index fae9297..20b3be2 100644
--- a/lottie_loading_layout/res/values-w840dp-v34/layouts.xml
+++ b/lottie_loading_layout/res/values-w840dp-v34/layouts.xml
@@ -15,8 +15,7 @@
     limitations under the License.
 -->
 
-<resources xmlns:tools="http://schemas.android.com/tools"
-    tools:keep="@layout/*_two_pane">
+<resources xmlns:tools="http://schemas.android.com/tools">
     <item name="sud_glif_loading_template_two_pane" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_loading_template_card_two_pane</item>
     <item name="sud_glif_fullscreen_loading_template_two_pane" type="layout" tools:ignore="UnusedResources">@layout/sud_glif_fullscreen_loading_template_card_two_pane</item>
 </resources>
diff --git a/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java b/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java
index 46ece9a..5f4f9fb 100644
--- a/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java
+++ b/lottie_loading_layout/src/com/google/android/setupdesign/GlifLoadingLayout.java
@@ -66,6 +66,7 @@ import com.google.android.setupdesign.lottieloadinglayout.R;
 import com.google.android.setupdesign.util.LayoutStyler;
 import com.google.android.setupdesign.util.LottieAnimationHelper;
 import com.google.android.setupdesign.view.IllustrationVideoView;
+import java.io.IOException;
 import java.io.InputStream;
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
@@ -534,6 +535,12 @@ public class GlifLoadingLayout extends GlifLayout {
       if (resourceEntry != null) {
         InputStream inputRaw =
             resourceEntry.getResources().openRawResource(resourceEntry.getResourceId());
+        try {
+          Log.i(TAG, "setAnimation " + resourceEntry.getResourceName() + " length=" + inputRaw.available());
+        } catch (IOException e) {
+          Log.w(TAG, "IOException while length of " + resourceEntry.getResourceName());
+        }
+
         lottieView.setAnimation(inputRaw, null);
         lottieView.playAnimation();
         setLottieLayoutVisibility(View.VISIBLE);
@@ -704,7 +711,7 @@ public class GlifLoadingLayout extends GlifLayout {
         if (isEmbeddedActivityOnePaneEnabled(context)) {
           template = R.layout.sud_glif_fullscreen_loading_embedded_template;
         } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
-          template = ForceTwoPaneHelper.getForceTwoPaneStyleLayout(getContext(), template);
+          template = R.layout.sud_glif_fullscreen_loading_template_two_pane;
         }
       } else {
         template = R.layout.sud_glif_loading_template;
@@ -713,7 +720,7 @@ public class GlifLoadingLayout extends GlifLayout {
         if (isEmbeddedActivityOnePaneEnabled(context)) {
           template = R.layout.sud_glif_loading_embedded_template;
         } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
-          template = ForceTwoPaneHelper.getForceTwoPaneStyleLayout(getContext(), template);
+          template = R.layout.sud_glif_loading_template_two_pane;
         }
       }
     }
diff --git a/main/res/color-v34/sud_dynamic_switch_track_off_light.xml b/main/res/color-v34/sud_dynamic_switch_track_off_light.xml
index ffa9141..9d87da9 100644
--- a/main/res/color-v34/sud_dynamic_switch_track_off_light.xml
+++ b/main/res/color-v34/sud_dynamic_switch_track_off_light.xml
@@ -15,5 +15,5 @@
 -->
 
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
-  <item android:color="@android:color/system_neutral1_100" />
+  <item android:color="@android:color/system_surface_container_highest_light" />
 </selector>
\ No newline at end of file
diff --git a/main/res/values-v34/colors.xml b/main/res/values-v34/colors.xml
index 5e06218..5d454ee 100644
--- a/main/res/values-v34/colors.xml
+++ b/main/res/values-v34/colors.xml
@@ -18,16 +18,15 @@
 <resources>
   <!-- Accent color -->
   <color name="sud_dynamic_color_accent_glif_v3_dark">@color/sud_system_accent1_300</color>
-
-
-  <color name="sud_system_neutral2_600">@android:color/system_neutral2_600</color>
+  <!-- Surface container color -->
+  <color name="sud_system_sc_highest_dark">@android:color/system_surface_container_highest_dark</color>
 
 
   <color name="sud_dynamic_switch_thumb_off_light">@color/sud_system_neutral2_500</color>
 
   <color name="sud_dynamic_switch_thumb_off_outline_light">@color/sud_system_neutral2_500</color>
 
-  <color name="sud_dynamic_switch_track_off_dark">@color/sud_system_neutral2_600</color>
+  <color name="sud_dynamic_switch_track_off_dark">@color/sud_system_sc_highest_dark</color>
 
   <color name="sud_dynamic_switch_thumb_off_dark">@color/sud_system_neutral2_400</color>
 
diff --git a/main/res/values-v34/layouts.xml b/main/res/values-v34/layouts.xml
index f655865..5d5d158 100644
--- a/main/res/values-v34/layouts.xml
+++ b/main/res/values-v34/layouts.xml
@@ -15,10 +15,10 @@
     limitations under the License.
 -->
 
-<resources xmlns:tools="http://schemas.android.com/tools"
-    tools:keep="@layout/*_two_pane">
+<resources xmlns:tools="http://schemas.android.com/tools">
 
     <!-- Layout for supporting force two pane even if it is portrait mode. -->
     <item name="sud_glif_preference_template_two_pane" type="layout">@layout/sud_glif_preference_template_compact</item>
+    <item name="sud_glif_preference_recycler_view_compat_two_pane" type="layout">@layout/sud_glif_preference_recycler_view</item>
 
 </resources>
diff --git a/main/res/values-w840dp-v34/layouts.xml b/main/res/values-w840dp-v34/layouts.xml
index 2fe2e83..d5583fd 100644
--- a/main/res/values-w840dp-v34/layouts.xml
+++ b/main/res/values-w840dp-v34/layouts.xml
@@ -15,13 +15,13 @@
     limitations under the License.
 -->
 
-<resources xmlns:tools="http://schemas.android.com/tools"
-    tools:keep="@layout/*_two_pane">
+<resources xmlns:tools="http://schemas.android.com/tools">
 
     <!-- Layout for supporting force two pane even if it is portrait mode. -->
     <item name="sud_glif_template_two_pane" type="layout">@layout/sud_glif_template_card_two_pane</item>
     <item name="sud_glif_list_template_two_pane" type="layout">@layout/sud_glif_list_template_card_two_pane</item>
     <item name="sud_glif_recycler_template_two_pane" type="layout">@layout/sud_glif_recycler_template_card_two_pane</item>
     <item name="sud_glif_preference_template_two_pane" type="layout">@layout/sud_glif_preference_template_card_two_pane</item>
+    <item name="sud_glif_preference_recycler_view_compat_two_pane" type="layout">@layout/sud_glif_preference_recycler_view_two_pane</item>
 
 </resources>
diff --git a/main/res/values/layouts.xml b/main/res/values/layouts.xml
index 472edb1..7d3bd57 100644
--- a/main/res/values/layouts.xml
+++ b/main/res/values/layouts.xml
@@ -15,8 +15,7 @@
     limitations under the License.
 -->
 
-<resources xmlns:tools="http://schemas.android.com/tools"
-    tools:keep="@layout/*_two_pane">
+<resources xmlns:tools="http://schemas.android.com/tools">
 
     <item name="sud_template" type="layout">@layout/sud_template_header</item>
 
diff --git a/main/res/values/styles.xml b/main/res/values/styles.xml
index 1cddbd0..5957865 100644
--- a/main/res/values/styles.xml
+++ b/main/res/values/styles.xml
@@ -344,7 +344,7 @@
         <item name="sudEditTextBackgroundColor">@color/sud_glif_edit_text_bg_dark_color</item>
         <item name="android:editTextStyle">@style/SudEditText</item>
         <item name="alertDialogTheme">@style/SudAlertDialogThemeCompat</item>
-        <item name="android:alertDialogTheme" tools:targetApi="honeycomb">@style/SudAlertDialogTheme</item>
+        <item name="android:alertDialogTheme">@style/SudAlertDialogTheme</item>
         <item name="sucLightStatusBar" tools:targetApi="m">?android:attr/windowLightStatusBar</item>
     </style>
 
@@ -363,7 +363,7 @@
         <item name="sudEditTextBackgroundColor">@color/sud_glif_edit_text_bg_light_color</item>
         <item name="android:editTextStyle">@style/SudEditText</item>
         <item name="alertDialogTheme">@style/SudAlertDialogThemeCompat.Light</item>
-        <item name="android:alertDialogTheme" tools:targetApi="honeycomb">@style/SudAlertDialogTheme.Light</item>
+        <item name="android:alertDialogTheme">@style/SudAlertDialogTheme.Light</item>
         <item name="sucLightStatusBar" tools:targetApi="m">?android:attr/windowLightStatusBar</item>
     </style>
 
@@ -543,7 +543,8 @@
     <style name="SudDescription.Glif" parent="SudDescription" tools:ignore="UnusedResources">
         <item name="android:layout_marginTop">@dimen/sud_description_glif_margin_top</item>
         <item name="android:gravity">?attr/sudGlifHeaderGravity</item>
-        <item name="android:textAlignment" tools:targetApi="jelly_bean_mr1">gravity</item>
+        <item name="android:textAlignment">gravity</item>
+        <item name="android:textDirection">locale</item>
     </style>
 
     <!-- Ignore UnusedResources: Used by clients -->
@@ -551,7 +552,7 @@
         <item name="android:layout_marginTop">@dimen/sud_content_glif_margin_top</item>
         <item name="android:layout_marginBottom">@dimen/sud_content_glif_margin_bottom</item>
         <item name="android:gravity">start</item>
-        <item name="android:textAlignment" tools:targetApi="jelly_bean_mr1">gravity</item>
+        <item name="android:textAlignment">gravity</item>
     </style>
 
     <style name="TextAppearance.SudDescription" parent="TextAppearance.AppCompat.Medium">
@@ -646,10 +647,10 @@
     <style name="SudFourColorIndeterminateProgressBar" parent="SudBase.ProgressBarLarge">
         <item name="android:layout_gravity">center</item>
         <item name="android:indeterminate">true</item>
-        <item name="android:paddingEnd" tools:targetApi="17" >@dimen/sud_glif_progress_bar_padding</item>
+        <item name="android:paddingEnd">@dimen/sud_glif_progress_bar_padding</item>
         <item name="android:paddingLeft">@dimen/sud_glif_progress_bar_padding</item>
         <item name="android:paddingRight">@dimen/sud_glif_progress_bar_padding</item>
-        <item name="android:paddingStart" tools:targetApi="17" >@dimen/sud_glif_progress_bar_padding</item>
+        <item name="android:paddingStart">@dimen/sud_glif_progress_bar_padding</item>
     </style>
 
     <!-- Header layout (for phones) -->
@@ -687,20 +688,20 @@
         <item name="android:buttonStyle">@style/SudGlifButton.Tertiary</item>
         <item name="android:theme">@style/SudGlifButton.Tertiary</item>
 
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">sans-serif</item>
+        <item name="android:fontFamily">sans-serif</item>
         <item name="android:layout_gravity">?attr/sudButtonTertiaryGravity</item>
         <item name="android:layout_marginLeft">@dimen/sud_glif_negative_button_padding</item>
         <item name="android:layout_marginRight">@dimen/sud_glif_negative_button_padding</item>
         <!-- Always lowercase instead of reading attr/sudButtonAllCaps, since this is a tertiary
              button -->
-        <item name="android:textAllCaps" tools:targetApi="ice_cream_sandwich">false</item>
+        <item name="android:textAllCaps">false</item>
     </style>
 
     <!-- Ignore UnusedResources: used by clients -->
     <style name="SudGlifButton.Tertiary" parent="SudGlifButton.BaseTertiary"
         tools:ignore="UnusedResources">
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">?attr/sudButtonFontFamily</item>
-        <item name="textAllCaps" tools:targetApi="ice_cream_sandwich">false</item>
+        <item name="android:fontFamily">?attr/sudButtonFontFamily</item>
+        <item name="textAllCaps">false</item>
     </style>
 
     <style name="SudGlifButton.Primary" parent="Widget.AppCompat.Button.Colored">
@@ -712,10 +713,10 @@
         <item name="buttonStyle">@style/SudGlifButton.Primary</item>
 
         <!-- Values used in styles -->
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">?attr/sudButtonFontFamily</item>
+        <item name="android:fontFamily">?attr/sudButtonFontFamily</item>
         <item name="android:paddingLeft">@dimen/sud_glif_button_padding</item>
         <item name="android:paddingRight">@dimen/sud_glif_button_padding</item>
-        <item name="android:textAllCaps" tools:targetApi="ice_cream_sandwich">?attr/sudButtonAllCaps</item>
+        <item name="android:textAllCaps">?attr/sudButtonAllCaps</item>
         <item name="textAllCaps">?attr/sudButtonAllCaps</item>
         <item name="android:stateListAnimator">@null</item>
 
@@ -732,11 +733,11 @@
         <item name="buttonStyle">@style/SudGlifButton.Secondary</item>
 
         <!-- Values used in styles -->
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">?attr/sudButtonFontFamily</item>
+        <item name="android:fontFamily">?attr/sudButtonFontFamily</item>
         <item name="android:minWidth">0dp</item>
         <item name="android:paddingLeft">@dimen/sud_glif_button_padding</item>
         <item name="android:paddingRight">@dimen/sud_glif_button_padding</item>
-        <item name="android:textAllCaps" tools:targetApi="ice_cream_sandwich">?attr/sudButtonAllCaps</item>
+        <item name="android:textAllCaps">?attr/sudButtonAllCaps</item>
         <item name="textAllCaps">?attr/sudButtonAllCaps</item>
 
         <!-- Values used in themes -->
@@ -847,7 +848,7 @@
 
     <style name="SudItemTitle.GlifDescription" parent="SudItemTitle">
         <item name="android:gravity">?attr/sudGlifHeaderGravity</item>
-        <item name="android:textAlignment" tools:targetApi="jelly_bean_mr1">gravity</item>
+        <item name="android:textAlignment">gravity</item>
     </style>
 
     <style name="SudItemTitle.Verbose" parent="SudItemTitle">
@@ -860,7 +861,7 @@
 
     <style name="SudItemTitle.SectionHeader" parent="SudItemTitle">
         <item name="android:textSize">14sp</item>
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">@string/sudFontSecondaryMedium</item>
+        <item name="android:fontFamily">@string/sudFontSecondaryMedium</item>
     </style>
 
     <style name="SudSwitchStyle">
@@ -888,10 +889,10 @@
         <item name="android:layout_marginLeft">?attr/sudMarginStart</item>
         <item name="android:layout_marginRight">?attr/sudMarginEnd</item>
         <item name="android:layout_marginTop">?attr/sucGlifHeaderMarginTop</item>
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">@string/sudFontSecondary</item>
-        <item name="android:textAlignment" tools:targetApi="jelly_bean_mr1">gravity</item>
+        <item name="android:fontFamily">@string/sudFontSecondary</item>
+        <item name="android:textAlignment">gravity</item>
         <item name="android:textColor">?android:attr/textColorPrimary</item>
-        <item name="android:textDirection" tools:targetApi="jelly_bean_mr1">locale</item>
+        <item name="android:textDirection">locale</item>
         <item name="android:accessibilityHeading" tools:targetApi="p">true</item>
         <item name="android:hyphenationFrequency" tools:targetApi="23">full</item>
     </style>
@@ -900,16 +901,15 @@
         <!-- Before Honeycomb, layout_gravity is needed for FrameLayout to apply the margins -->
         <item name="android:layout_gravity">top</item>
         <item name="android:ellipsize">end</item>
-        <item name="android:maxLines">3</item>
         <item name="android:gravity">?attr/sudGlifHeaderGravity</item>
         <item name="android:layout_marginBottom">?attr/sucGlifHeaderMarginBottom</item>
         <item name="android:layout_marginLeft">?attr/sudMarginStart</item>
         <item name="android:layout_marginRight">?attr/sudMarginEnd</item>
         <item name="android:layout_marginTop">?attr/sucGlifHeaderMarginTop</item>
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">@string/sudFontSecondary</item>
-        <item name="android:textAlignment" tools:targetApi="jelly_bean_mr1">gravity</item>
+        <item name="android:fontFamily">@string/sudFontSecondary</item>
+        <item name="android:textAlignment">gravity</item>
         <item name="android:textColor">?android:attr/textColorPrimary</item>
-        <item name="android:textDirection" tools:targetApi="jelly_bean_mr1">locale</item>
+        <item name="android:textDirection">locale</item>
         <item name="android:accessibilityHeading" tools:targetApi="p">true</item>
         <item name="android:textSize">@dimen/sud_glif_header_title_size_material_you</item>
         <item name="android:hyphenationFrequency" tools:targetApi="23">full</item>
@@ -922,9 +922,8 @@
         <item name="android:layout_marginStart">?attr/sudMarginStart</item>
         <item name="android:layout_marginRight">?attr/sudMarginEnd</item>
         <item name="android:layout_marginEnd">?attr/sudMarginEnd</item>
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">@string/sudFontSecondary</item>
+        <item name="android:fontFamily">@string/sudFontSecondary</item>
         <item name="android:textColor">?android:attr/textColorPrimary</item>
-        <item name="android:textDirection" tools:targetApi="jelly_bean_mr1">locale</item>
     </style>
 
     <style name="SudGlifDescriptionMaterialYou">
@@ -932,7 +931,7 @@
         <item name="android:textAppearance">@android:style/TextAppearance.DeviceDefault</item>
         <item name="android:lineSpacingExtra">@dimen/sud_description_line_spacing_extra</item>
         <item name="android:gravity">?attr/sudGlifHeaderGravity</item>
-        <item name="android:textAlignment" tools:targetApi="jelly_bean_mr1">gravity</item>
+        <item name="android:textAlignment">gravity</item>
         <item name="android:layout_marginTop">?attr/sudGlifDescriptionMarginTop</item>
         <item name="android:layout_marginBottom">?attr/sudGlifDescriptionMarginBottom</item>
         <item name="android:layout_marginLeft">?attr/sudMarginStart</item>
@@ -940,7 +939,7 @@
         <item name="android:layout_marginRight">?attr/sudMarginEnd</item>
         <item name="android:layout_marginEnd">?attr/sudMarginEnd</item>
         <item name="android:textColor">?android:attr/textColorPrimary</item>
-        <item name="android:textDirection" tools:targetApi="jelly_bean_mr1">locale</item>
+        <item name="android:textDirection">locale</item>
         <item name="android:textSize">@dimen/sud_glif_description_text_size_material_you</item>
     </style>
 
@@ -963,7 +962,7 @@
     </style>
 
     <style name="SudGlifAccountName">
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">@string/sudFontSecondary</item>
+        <item name="android:fontFamily">@string/sudFontSecondary</item>
         <item name="android:textColor">?android:attr/textColorPrimary</item>
         <item name="android:textSize">@dimen/sud_account_name_text_size</item>
         <item name="android:layout_gravity">center_vertical</item>
@@ -1023,20 +1022,20 @@
 
     <style name="TextAppearance.SudMaterialYouItemTitle" parent="android:TextAppearance">
         <item name="android:textSize">@dimen/sud_items_title_text_size_material_you</item>
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">@string/sudFontSecondary</item>
+        <item name="android:fontFamily">@string/sudFontSecondary</item>
         <item name="android:textColor">?android:attr/textColorPrimary</item>
     </style>
 
     <style name="TextAppearance.SudMaterialYouItemSummary" parent="android:TextAppearance">
         <item name="android:textSize">@dimen/sud_items_summary_text_size_material_you</item>
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">@string/sudFontSecondaryText</item>
+        <item name="android:fontFamily">@string/sudFontSecondaryText</item>
         <item name="android:textColor">?android:attr/textColorSecondary</item>
     </style>
 
     <style name="TextAppearance.SudMaterialYouDescription" parent="TextAppearance.AppCompat.Medium">
         <item name="android:textColor">?android:attr/textColorPrimary</item>
         <item name="android:textSize">@dimen/sud_items_title_text_size_material_you</item>
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">@string/sudFontSecondary</item>
+        <item name="android:fontFamily">@string/sudFontSecondary</item>
     </style>
     <!-- Navigation bar styles -->
 
diff --git a/main/src/com/google/android/setupdesign/GlifLayout.java b/main/src/com/google/android/setupdesign/GlifLayout.java
index 4f565e1..cc06bf2 100644
--- a/main/src/com/google/android/setupdesign/GlifLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifLayout.java
@@ -43,6 +43,7 @@ import com.google.android.setupcompat.partnerconfig.PartnerConfig;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.template.StatusBarMixin;
 import com.google.android.setupcompat.util.ForceTwoPaneHelper;
+import com.google.android.setupcompat.util.Logger;
 import com.google.android.setupdesign.template.DescriptionMixin;
 import com.google.android.setupdesign.template.HeaderMixin;
 import com.google.android.setupdesign.template.IconMixin;
@@ -75,6 +76,8 @@ import com.google.android.setupdesign.util.LayoutStyler;
  */
 public class GlifLayout extends PartnerCustomizationLayout {
 
+  private static final Logger LOG = new Logger(GlifLayout.class);
+
   private ColorStateList primaryColor;
 
   private boolean backgroundPatterned = true;
@@ -291,7 +294,7 @@ public class GlifLayout extends PartnerCustomizationLayout {
       if (isEmbeddedActivityOnePaneEnabled(getContext())) {
         template = R.layout.sud_glif_embedded_template;
       } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
-        template = ForceTwoPaneHelper.getForceTwoPaneStyleLayout(getContext(), template);
+        template = R.layout.sud_glif_template_two_pane;
       }
     }
 
@@ -495,9 +498,17 @@ public class GlifLayout extends PartnerCustomizationLayout {
 
   /** Check if the one pane layout is enabled in embedded activity */
   protected boolean isEmbeddedActivityOnePaneEnabled(Context context) {
-    return PartnerConfigHelper.isEmbeddedActivityOnePaneEnabled(context)
-        && ActivityEmbeddingController.getInstance(context)
+    boolean embeddedActivityOnePaneEnabled =
+        PartnerConfigHelper.isEmbeddedActivityOnePaneEnabled(context);
+    boolean activityEmbedded =
+        ActivityEmbeddingController.getInstance(context)
             .isActivityEmbedded(PartnerCustomizationLayout.lookupActivityFromContext(context));
+    LOG.atVerbose(
+        "isEmbeddedActivityOnePaneEnabled = "
+            + embeddedActivityOnePaneEnabled
+            + "; isActivityEmbedded = "
+            + activityEmbedded);
+    return embeddedActivityOnePaneEnabled && activityEmbedded;
   }
 
   /** Updates the background color of this layout with the partner-customizable background color. */
diff --git a/main/src/com/google/android/setupdesign/GlifListLayout.java b/main/src/com/google/android/setupdesign/GlifListLayout.java
index 5afb334..ce69bd1 100644
--- a/main/src/com/google/android/setupdesign/GlifListLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifListLayout.java
@@ -96,7 +96,7 @@ public class GlifListLayout extends GlifLayout {
       if (isEmbeddedActivityOnePaneEnabled(getContext())) {
         template = R.layout.sud_glif_list_embedded_template;
       } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
-        template = ForceTwoPaneHelper.getForceTwoPaneStyleLayout(getContext(), template);
+        template = R.layout.sud_glif_list_template_two_pane;
       }
     }
     return super.onInflateTemplate(inflater, template);
diff --git a/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java b/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java
index b967719..433ca60 100644
--- a/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifPreferenceLayout.java
@@ -33,7 +33,7 @@ import com.google.android.setupdesign.template.RecyclerMixin;
  *
  * <p>Example:
  *
- * <pre>{@code
+ * <pre
  * &lt;style android:name="MyActivityTheme">
  *     &lt;item android:name="preferenceTheme">@style/MyPreferenceTheme&lt;/item>
  * &lt;/style>
@@ -45,20 +45,20 @@ import com.google.android.setupdesign.template.RecyclerMixin;
  * &lt;style android:name="MyPreferenceFragmentStyle">
  *     &lt;item android:name="android:layout">@layout/my_preference_layout&lt;/item>
  * &lt;/style>
- * }</pre>
+ * </pre>
  *
  * where {@code my_preference_layout} is a layout that contains {@link
  * com.google.android.setupdesign.GlifPreferenceLayout}.
  *
  * <p>Example:
  *
- * <pre>{@code
+ * <pre>
  * &lt;com.google.android.setupdesign.GlifPreferenceLayout
  *     xmlns:android="http://schemas.android.com/apk/res/android"
  *     android:id="@id/list_container"
  *     android:layout_width="match_parent"
  *     android:layout_height="match_parent" />
- * }</pre>
+ * </pre>
  *
  * <p>Fragments using this layout <em>must</em> delegate {@code onCreateRecyclerView} to the
  * implementation in this class: {@link #onCreateRecyclerView(android.view.LayoutInflater,
@@ -104,7 +104,7 @@ public class GlifPreferenceLayout extends GlifRecyclerLayout {
       if (isEmbeddedActivityOnePaneEnabled(getContext())) {
         template = R.layout.sud_glif_preference_embedded_template;
       } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
-        template = ForceTwoPaneHelper.getForceTwoPaneStyleLayout(getContext(), template);
+        template = R.layout.sud_glif_preference_template_two_pane;
       }
     }
     return super.onInflateTemplate(inflater, template);
@@ -117,8 +117,9 @@ public class GlifPreferenceLayout extends GlifRecyclerLayout {
     final LayoutInflater inflater = LayoutInflater.from(getContext());
     int recyclerViewLayoutId = R.layout.sud_glif_preference_recycler_view;
     if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
-      recyclerViewLayoutId =
-          ForceTwoPaneHelper.getForceTwoPaneStyleLayout(getContext(), recyclerViewLayoutId);
+      // Use the compat two pane layout for the recycler view if the two pane is enabled. Since the
+      // sud_glif_preference_recycler_view layout is not compatible with original layout.
+      recyclerViewLayoutId = R.layout.sud_glif_preference_recycler_view_compat_two_pane;
     }
     RecyclerView recyclerView = (RecyclerView) inflater.inflate(recyclerViewLayoutId, this, false);
     recyclerMixin = new RecyclerMixin(this, recyclerView);
diff --git a/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java b/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java
index 23d4dca..eed799c 100644
--- a/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java
+++ b/main/src/com/google/android/setupdesign/GlifRecyclerLayout.java
@@ -97,7 +97,7 @@ public class GlifRecyclerLayout extends GlifLayout {
       if (isEmbeddedActivityOnePaneEnabled(getContext())) {
         template = R.layout.sud_glif_recycler_embedded_template;
       } else if (ForceTwoPaneHelper.isForceTwoPaneEnable(getContext())) {
-        template = ForceTwoPaneHelper.getForceTwoPaneStyleLayout(getContext(), template);
+        template = R.layout.sud_glif_recycler_template_two_pane;
       }
     }
     return super.onInflateTemplate(inflater, template);
diff --git a/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java b/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java
index c934612..51d9e9f 100644
--- a/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java
+++ b/main/src/com/google/android/setupdesign/items/ExpandableSwitchItem.java
@@ -158,6 +158,11 @@ public class ExpandableSwitchItem extends SwitchItem
   public void onBindView(View view) {
     // TODO: If it is possible to detect, log a warning if this is being used with ListView.
     super.onBindView(view);
+
+    // Expandable switch item is using this view's child to listen clickable event, to avoid
+    // accessibility issue, remove clickable event in this view.
+    view.setClickable(false);
+
     View content = view.findViewById(R.id.sud_items_expandable_switch_content);
     content.setOnClickListener(this);
 
diff --git a/main/src/com/google/android/setupdesign/transition/TransitionHelper.java b/main/src/com/google/android/setupdesign/transition/TransitionHelper.java
index 25ab984..ad70a52 100644
--- a/main/src/com/google/android/setupdesign/transition/TransitionHelper.java
+++ b/main/src/com/google/android/setupdesign/transition/TransitionHelper.java
@@ -86,6 +86,7 @@ public class TransitionHelper {
     TRANSITION_FADE,
     TRANSITION_FRAMEWORK_DEFAULT_PRE_P,
     TRANSITION_CAPTIVE,
+    TRANSITION_FADE_THROUGH,
   })
   public @interface TransitionType {}
 
diff --git a/main/src/com/google/android/setupdesign/view/IntrinsicSizeFrameLayout.java b/main/src/com/google/android/setupdesign/view/IntrinsicSizeFrameLayout.java
index ffb3d70..5f37b22 100644
--- a/main/src/com/google/android/setupdesign/view/IntrinsicSizeFrameLayout.java
+++ b/main/src/com/google/android/setupdesign/view/IntrinsicSizeFrameLayout.java
@@ -112,6 +112,7 @@ public class IntrinsicSizeFrameLayout extends FrameLayout {
       if (intrinsicHeight == 0 && intrinsicWidth == 0) {
         params.width = ViewGroup.LayoutParams.MATCH_PARENT;
         params.height = ViewGroup.LayoutParams.MATCH_PARENT;
+        setElevation(0.0f);
       }
     }
     super.setLayoutParams(params);
```

