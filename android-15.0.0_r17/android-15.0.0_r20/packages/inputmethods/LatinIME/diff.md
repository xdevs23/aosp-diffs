```diff
diff --git a/java/src/com/android/inputmethod/keyboard/KeyboardSwitcher.java b/java/src/com/android/inputmethod/keyboard/KeyboardSwitcher.java
index 91295c772..d398ab8c5 100644
--- a/java/src/com/android/inputmethod/keyboard/KeyboardSwitcher.java
+++ b/java/src/com/android/inputmethod/keyboard/KeyboardSwitcher.java
@@ -116,7 +116,7 @@ public final class KeyboardSwitcher implements KeyboardState.SwitchActions {
         final KeyboardLayoutSet.Builder builder = new KeyboardLayoutSet.Builder(
                 mThemeContext, editorInfo);
         final Resources res = mThemeContext.getResources();
-        final int keyboardWidth = ResourceUtils.getDefaultKeyboardWidth(res);
+        final int keyboardWidth = ResourceUtils.getDefaultKeyboardWidth(mThemeContext);
         final int keyboardHeight = ResourceUtils.getKeyboardHeight(res, settingsValues);
         builder.setKeyboardGeometry(keyboardWidth, keyboardHeight);
         builder.setSubtype(mRichImm.getCurrentSubtype());
diff --git a/java/src/com/android/inputmethod/keyboard/KeyboardView.java b/java/src/com/android/inputmethod/keyboard/KeyboardView.java
index faa21070e..a42108477 100644
--- a/java/src/com/android/inputmethod/keyboard/KeyboardView.java
+++ b/java/src/com/android/inputmethod/keyboard/KeyboardView.java
@@ -46,36 +46,36 @@ import javax.annotation.Nullable;
 /**
  * A view that renders a virtual {@link Keyboard}.
  *
- * @attr ref R.styleable#KeyboardView_keyBackground
- * @attr ref R.styleable#KeyboardView_functionalKeyBackground
- * @attr ref R.styleable#KeyboardView_spacebarBackground
- * @attr ref R.styleable#KeyboardView_spacebarIconWidthRatio
- * @attr ref R.styleable#Keyboard_Key_keyLabelFlags
- * @attr ref R.styleable#KeyboardView_keyHintLetterPadding
- * @attr ref R.styleable#KeyboardView_keyPopupHintLetter
- * @attr ref R.styleable#KeyboardView_keyPopupHintLetterPadding
- * @attr ref R.styleable#KeyboardView_keyShiftedLetterHintPadding
- * @attr ref R.styleable#KeyboardView_keyTextShadowRadius
- * @attr ref R.styleable#KeyboardView_verticalCorrection
- * @attr ref R.styleable#Keyboard_Key_keyTypeface
- * @attr ref R.styleable#Keyboard_Key_keyLetterSize
- * @attr ref R.styleable#Keyboard_Key_keyLabelSize
- * @attr ref R.styleable#Keyboard_Key_keyLargeLetterRatio
- * @attr ref R.styleable#Keyboard_Key_keyLargeLabelRatio
- * @attr ref R.styleable#Keyboard_Key_keyHintLetterRatio
- * @attr ref R.styleable#Keyboard_Key_keyShiftedLetterHintRatio
- * @attr ref R.styleable#Keyboard_Key_keyHintLabelRatio
- * @attr ref R.styleable#Keyboard_Key_keyLabelOffCenterRatio
- * @attr ref R.styleable#Keyboard_Key_keyHintLabelOffCenterRatio
- * @attr ref R.styleable#Keyboard_Key_keyPreviewTextRatio
- * @attr ref R.styleable#Keyboard_Key_keyTextColor
- * @attr ref R.styleable#Keyboard_Key_keyTextColorDisabled
- * @attr ref R.styleable#Keyboard_Key_keyTextShadowColor
- * @attr ref R.styleable#Keyboard_Key_keyHintLetterColor
- * @attr ref R.styleable#Keyboard_Key_keyHintLabelColor
- * @attr ref R.styleable#Keyboard_Key_keyShiftedLetterHintInactivatedColor
- * @attr ref R.styleable#Keyboard_Key_keyShiftedLetterHintActivatedColor
- * @attr ref R.styleable#Keyboard_Key_keyPreviewTextColor
+ * @attr ref android.R.styleable#KeyboardView_keyBackground
+ * @attr ref android.R.styleable#KeyboardView_functionalKeyBackground
+ * @attr ref android.R.styleable#KeyboardView_spacebarBackground
+ * @attr ref android.R.styleable#KeyboardView_spacebarIconWidthRatio
+ * @attr ref android.R.styleable#Keyboard_Key_keyLabelFlags
+ * @attr ref android.R.styleable#KeyboardView_keyHintLetterPadding
+ * @attr ref android.R.styleable#KeyboardView_keyPopupHintLetter
+ * @attr ref android.R.styleable#KeyboardView_keyPopupHintLetterPadding
+ * @attr ref android.R.styleable#KeyboardView_keyShiftedLetterHintPadding
+ * @attr ref android.R.styleable#KeyboardView_keyTextShadowRadius
+ * @attr ref android.R.styleable#KeyboardView_verticalCorrection
+ * @attr ref android.R.styleable#Keyboard_Key_keyTypeface
+ * @attr ref android.R.styleable#Keyboard_Key_keyLetterSize
+ * @attr ref android.R.styleable#Keyboard_Key_keyLabelSize
+ * @attr ref android.R.styleable#Keyboard_Key_keyLargeLetterRatio
+ * @attr ref android.R.styleable#Keyboard_Key_keyLargeLabelRatio
+ * @attr ref android.R.styleable#Keyboard_Key_keyHintLetterRatio
+ * @attr ref android.R.styleable#Keyboard_Key_keyShiftedLetterHintRatio
+ * @attr ref android.R.styleable#Keyboard_Key_keyHintLabelRatio
+ * @attr ref android.R.styleable#Keyboard_Key_keyLabelOffCenterRatio
+ * @attr ref android.R.styleable#Keyboard_Key_keyHintLabelOffCenterRatio
+ * @attr ref android.R.styleable#Keyboard_Key_keyPreviewTextRatio
+ * @attr ref android.R.styleable#Keyboard_Key_keyTextColor
+ * @attr ref android.R.styleable#Keyboard_Key_keyTextColorDisabled
+ * @attr ref android.R.styleable#Keyboard_Key_keyTextShadowColor
+ * @attr ref android.R.styleable#Keyboard_Key_keyHintLetterColor
+ * @attr ref android.R.styleable#Keyboard_Key_keyHintLabelColor
+ * @attr ref android.R.styleable#Keyboard_Key_keyShiftedLetterHintInactivatedColor
+ * @attr ref android.R.styleable#Keyboard_Key_keyShiftedLetterHintActivatedColor
+ * @attr ref android.R.styleable#Keyboard_Key_keyPreviewTextColor
  */
 public class KeyboardView extends View {
     // XML attributes
diff --git a/java/src/com/android/inputmethod/keyboard/MainKeyboardView.java b/java/src/com/android/inputmethod/keyboard/MainKeyboardView.java
index 00d4fa236..fc8744ec6 100644
--- a/java/src/com/android/inputmethod/keyboard/MainKeyboardView.java
+++ b/java/src/com/android/inputmethod/keyboard/MainKeyboardView.java
@@ -69,45 +69,45 @@ import javax.annotation.Nullable;
 /**
  * A view that is responsible for detecting key presses and touch movements.
  *
- * @attr ref R.styleable#MainKeyboardView_languageOnSpacebarTextRatio
- * @attr ref R.styleable#MainKeyboardView_languageOnSpacebarTextColor
- * @attr ref R.styleable#MainKeyboardView_languageOnSpacebarTextShadowRadius
- * @attr ref R.styleable#MainKeyboardView_languageOnSpacebarTextShadowColor
- * @attr ref R.styleable#MainKeyboardView_languageOnSpacebarFinalAlpha
- * @attr ref R.styleable#MainKeyboardView_languageOnSpacebarFadeoutAnimator
- * @attr ref R.styleable#MainKeyboardView_altCodeKeyWhileTypingFadeoutAnimator
- * @attr ref R.styleable#MainKeyboardView_altCodeKeyWhileTypingFadeinAnimator
- * @attr ref R.styleable#MainKeyboardView_keyHysteresisDistance
- * @attr ref R.styleable#MainKeyboardView_touchNoiseThresholdTime
- * @attr ref R.styleable#MainKeyboardView_touchNoiseThresholdDistance
- * @attr ref R.styleable#MainKeyboardView_keySelectionByDraggingFinger
- * @attr ref R.styleable#MainKeyboardView_keyRepeatStartTimeout
- * @attr ref R.styleable#MainKeyboardView_keyRepeatInterval
- * @attr ref R.styleable#MainKeyboardView_longPressKeyTimeout
- * @attr ref R.styleable#MainKeyboardView_longPressShiftKeyTimeout
- * @attr ref R.styleable#MainKeyboardView_ignoreAltCodeKeyTimeout
- * @attr ref R.styleable#MainKeyboardView_keyPreviewLayout
- * @attr ref R.styleable#MainKeyboardView_keyPreviewOffset
- * @attr ref R.styleable#MainKeyboardView_keyPreviewHeight
- * @attr ref R.styleable#MainKeyboardView_keyPreviewLingerTimeout
- * @attr ref R.styleable#MainKeyboardView_keyPreviewShowUpAnimator
- * @attr ref R.styleable#MainKeyboardView_keyPreviewDismissAnimator
- * @attr ref R.styleable#MainKeyboardView_moreKeysKeyboardLayout
- * @attr ref R.styleable#MainKeyboardView_moreKeysKeyboardForActionLayout
- * @attr ref R.styleable#MainKeyboardView_backgroundDimAlpha
- * @attr ref R.styleable#MainKeyboardView_showMoreKeysKeyboardAtTouchPoint
- * @attr ref R.styleable#MainKeyboardView_gestureFloatingPreviewTextLingerTimeout
- * @attr ref R.styleable#MainKeyboardView_gestureStaticTimeThresholdAfterFastTyping
- * @attr ref R.styleable#MainKeyboardView_gestureDetectFastMoveSpeedThreshold
- * @attr ref R.styleable#MainKeyboardView_gestureDynamicThresholdDecayDuration
- * @attr ref R.styleable#MainKeyboardView_gestureDynamicTimeThresholdFrom
- * @attr ref R.styleable#MainKeyboardView_gestureDynamicTimeThresholdTo
- * @attr ref R.styleable#MainKeyboardView_gestureDynamicDistanceThresholdFrom
- * @attr ref R.styleable#MainKeyboardView_gestureDynamicDistanceThresholdTo
- * @attr ref R.styleable#MainKeyboardView_gestureSamplingMinimumDistance
- * @attr ref R.styleable#MainKeyboardView_gestureRecognitionMinimumTime
- * @attr ref R.styleable#MainKeyboardView_gestureRecognitionSpeedThreshold
- * @attr ref R.styleable#MainKeyboardView_suppressKeyPreviewAfterBatchInputDuration
+ * @attr ref android.R.styleable#MainKeyboardView_languageOnSpacebarTextRatio
+ * @attr ref android.R.styleable#MainKeyboardView_languageOnSpacebarTextColor
+ * @attr ref android.R.styleable#MainKeyboardView_languageOnSpacebarTextShadowRadius
+ * @attr ref android.R.styleable#MainKeyboardView_languageOnSpacebarTextShadowColor
+ * @attr ref android.R.styleable#MainKeyboardView_languageOnSpacebarFinalAlpha
+ * @attr ref android.R.styleable#MainKeyboardView_languageOnSpacebarFadeoutAnimator
+ * @attr ref android.R.styleable#MainKeyboardView_altCodeKeyWhileTypingFadeoutAnimator
+ * @attr ref android.R.styleable#MainKeyboardView_altCodeKeyWhileTypingFadeinAnimator
+ * @attr ref android.R.styleable#MainKeyboardView_keyHysteresisDistance
+ * @attr ref android.R.styleable#MainKeyboardView_touchNoiseThresholdTime
+ * @attr ref android.R.styleable#MainKeyboardView_touchNoiseThresholdDistance
+ * @attr ref android.R.styleable#MainKeyboardView_keySelectionByDraggingFinger
+ * @attr ref android.R.styleable#MainKeyboardView_keyRepeatStartTimeout
+ * @attr ref android.R.styleable#MainKeyboardView_keyRepeatInterval
+ * @attr ref android.R.styleable#MainKeyboardView_longPressKeyTimeout
+ * @attr ref android.R.styleable#MainKeyboardView_longPressShiftKeyTimeout
+ * @attr ref android.R.styleable#MainKeyboardView_ignoreAltCodeKeyTimeout
+ * @attr ref android.R.styleable#MainKeyboardView_keyPreviewLayout
+ * @attr ref android.R.styleable#MainKeyboardView_keyPreviewOffset
+ * @attr ref android.R.styleable#MainKeyboardView_keyPreviewHeight
+ * @attr ref android.R.styleable#MainKeyboardView_keyPreviewLingerTimeout
+ * @attr ref android.R.styleable#MainKeyboardView_keyPreviewShowUpAnimator
+ * @attr ref android.R.styleable#MainKeyboardView_keyPreviewDismissAnimator
+ * @attr ref android.R.styleable#MainKeyboardView_moreKeysKeyboardLayout
+ * @attr ref android.R.styleable#MainKeyboardView_moreKeysKeyboardForActionLayout
+ * @attr ref android.R.styleable#MainKeyboardView_backgroundDimAlpha
+ * @attr ref android.R.styleable#MainKeyboardView_showMoreKeysKeyboardAtTouchPoint
+ * @attr ref android.R.styleable#MainKeyboardView_gestureFloatingPreviewTextLingerTimeout
+ * @attr ref android.R.styleable#MainKeyboardView_gestureStaticTimeThresholdAfterFastTyping
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDetectFastMoveSpeedThreshold
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDynamicThresholdDecayDuration
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDynamicTimeThresholdFrom
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDynamicTimeThresholdTo
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDynamicDistanceThresholdFrom
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDynamicDistanceThresholdTo
+ * @attr ref android.R.styleable#MainKeyboardView_gestureSamplingMinimumDistance
+ * @attr ref android.R.styleable#MainKeyboardView_gestureRecognitionMinimumTime
+ * @attr ref android.R.styleable#MainKeyboardView_gestureRecognitionSpeedThreshold
+ * @attr ref android.R.styleable#MainKeyboardView_suppressKeyPreviewAfterBatchInputDuration
  */
 public final class MainKeyboardView extends KeyboardView implements DrawingProxy,
         MoreKeysPanel.Controller {
diff --git a/java/src/com/android/inputmethod/keyboard/emoji/EmojiLayoutParams.java b/java/src/com/android/inputmethod/keyboard/emoji/EmojiLayoutParams.java
index 797541a15..a85c3a97f 100644
--- a/java/src/com/android/inputmethod/keyboard/emoji/EmojiLayoutParams.java
+++ b/java/src/com/android/inputmethod/keyboard/emoji/EmojiLayoutParams.java
@@ -16,6 +16,7 @@
 
 package com.android.inputmethod.keyboard.emoji;
 
+import android.content.Context;
 import android.content.res.Resources;
 import androidx.viewpager.widget.ViewPager;
 import android.view.View;
@@ -37,9 +38,10 @@ final class EmojiLayoutParams {
     private final int mBottomPadding;
     private final int mTopPadding;
 
-    public EmojiLayoutParams(final Resources res) {
+    public EmojiLayoutParams(final Context context) {
+        final Resources res = context.getResources();
         final int defaultKeyboardHeight = ResourceUtils.getDefaultKeyboardHeight(res);
-        final int defaultKeyboardWidth = ResourceUtils.getDefaultKeyboardWidth(res);
+        final int defaultKeyboardWidth = ResourceUtils.getDefaultKeyboardWidth(context);
         mKeyVerticalGap = (int) res.getFraction(R.fraction.config_key_vertical_gap_holo,
                 defaultKeyboardHeight, defaultKeyboardHeight);
         mBottomPadding = (int) res.getFraction(R.fraction.config_keyboard_bottom_padding_holo,
diff --git a/java/src/com/android/inputmethod/keyboard/emoji/EmojiPalettesView.java b/java/src/com/android/inputmethod/keyboard/emoji/EmojiPalettesView.java
index 9ba8d2ba2..898605019 100644
--- a/java/src/com/android/inputmethod/keyboard/emoji/EmojiPalettesView.java
+++ b/java/src/com/android/inputmethod/keyboard/emoji/EmojiPalettesView.java
@@ -109,9 +109,9 @@ public final class EmojiPalettesView extends LinearLayout implements OnTabChange
         final KeyboardLayoutSet.Builder builder = new KeyboardLayoutSet.Builder(
                 context, null /* editorInfo */);
         final Resources res = context.getResources();
-        mEmojiLayoutParams = new EmojiLayoutParams(res);
+        mEmojiLayoutParams = new EmojiLayoutParams(context);
         builder.setSubtype(RichInputMethodSubtype.getEmojiSubtype());
-        builder.setKeyboardGeometry(ResourceUtils.getDefaultKeyboardWidth(res),
+        builder.setKeyboardGeometry(ResourceUtils.getDefaultKeyboardWidth(context),
                 mEmojiLayoutParams.mEmojiKeyboardHeight);
         final KeyboardLayoutSet layoutSet = builder.build();
         final TypedArray emojiPalettesViewAttr = context.obtainStyledAttributes(attrs,
@@ -137,7 +137,7 @@ public final class EmojiPalettesView extends LinearLayout implements OnTabChange
         super.onMeasure(widthMeasureSpec, heightMeasureSpec);
         final Resources res = getContext().getResources();
         // The main keyboard expands to the entire this {@link KeyboardView}.
-        final int width = ResourceUtils.getDefaultKeyboardWidth(res)
+        final int width = ResourceUtils.getDefaultKeyboardWidth(getContext())
                 + getPaddingLeft() + getPaddingRight();
         final int height = ResourceUtils.getDefaultKeyboardHeight(res)
                 + res.getDimensionPixelSize(R.dimen.config_suggestions_strip_height)
diff --git a/java/src/com/android/inputmethod/keyboard/internal/GestureFloatingTextDrawingPreview.java b/java/src/com/android/inputmethod/keyboard/internal/GestureFloatingTextDrawingPreview.java
index 5443c2a8c..cb50b76ae 100644
--- a/java/src/com/android/inputmethod/keyboard/internal/GestureFloatingTextDrawingPreview.java
+++ b/java/src/com/android/inputmethod/keyboard/internal/GestureFloatingTextDrawingPreview.java
@@ -35,13 +35,13 @@ import javax.annotation.Nonnull;
  * The class for single gesture preview text. The class for multiple gesture preview text will be
  * derived from it.
  *
- * @attr ref R.styleable#KeyboardView_gestureFloatingPreviewTextSize
- * @attr ref R.styleable#KeyboardView_gestureFloatingPreviewTextColor
- * @attr ref R.styleable#KeyboardView_gestureFloatingPreviewTextOffset
- * @attr ref R.styleable#KeyboardView_gestureFloatingPreviewColor
- * @attr ref R.styleable#KeyboardView_gestureFloatingPreviewHorizontalPadding
- * @attr ref R.styleable#KeyboardView_gestureFloatingPreviewVerticalPadding
- * @attr ref R.styleable#KeyboardView_gestureFloatingPreviewRoundRadius
+ * @attr ref android.R.styleable#KeyboardView_gestureFloatingPreviewTextSize
+ * @attr ref android.R.styleable#KeyboardView_gestureFloatingPreviewTextColor
+ * @attr ref android.R.styleable#KeyboardView_gestureFloatingPreviewTextOffset
+ * @attr ref android.R.styleable#KeyboardView_gestureFloatingPreviewColor
+ * @attr ref android.R.styleable#KeyboardView_gestureFloatingPreviewHorizontalPadding
+ * @attr ref android.R.styleable#KeyboardView_gestureFloatingPreviewVerticalPadding
+ * @attr ref android.R.styleable#KeyboardView_gestureFloatingPreviewRoundRadius
  */
 public class GestureFloatingTextDrawingPreview extends AbstractDrawingPreview {
     protected static final class GesturePreviewTextParams {
diff --git a/java/src/com/android/inputmethod/keyboard/internal/GestureStrokeDrawingParams.java b/java/src/com/android/inputmethod/keyboard/internal/GestureStrokeDrawingParams.java
index 478639d2d..eeba67892 100644
--- a/java/src/com/android/inputmethod/keyboard/internal/GestureStrokeDrawingParams.java
+++ b/java/src/com/android/inputmethod/keyboard/internal/GestureStrokeDrawingParams.java
@@ -23,10 +23,10 @@ import com.android.inputmethod.latin.R;
 /**
  * This class holds parameters to control how a gesture stroke is sampled and drawn on the screen.
  *
- * @attr ref R.styleable#MainKeyboardView_gestureTrailMinSamplingDistance
- * @attr ref R.styleable#MainKeyboardView_gestureTrailMaxInterpolationAngularThreshold
- * @attr ref R.styleable#MainKeyboardView_gestureTrailMaxInterpolationDistanceThreshold
- * @attr ref R.styleable#MainKeyboardView_gestureTrailMaxInterpolationSegments
+ * @attr ref android.R.styleable#MainKeyboardView_gestureTrailMinSamplingDistance
+ * @attr ref android.R.styleable#MainKeyboardView_gestureTrailMaxInterpolationAngularThreshold
+ * @attr ref android.R.styleable#MainKeyboardView_gestureTrailMaxInterpolationDistanceThreshold
+ * @attr ref android.R.styleable#MainKeyboardView_gestureTrailMaxInterpolationSegments
  */
 public final class GestureStrokeDrawingParams {
     public final double mMinSamplingDistance; // in pixel
diff --git a/java/src/com/android/inputmethod/keyboard/internal/GestureStrokeRecognitionParams.java b/java/src/com/android/inputmethod/keyboard/internal/GestureStrokeRecognitionParams.java
index 07b14514c..e98729d43 100644
--- a/java/src/com/android/inputmethod/keyboard/internal/GestureStrokeRecognitionParams.java
+++ b/java/src/com/android/inputmethod/keyboard/internal/GestureStrokeRecognitionParams.java
@@ -25,16 +25,16 @@ import com.android.inputmethod.latin.utils.ResourceUtils;
  * This class holds parameters to control how a gesture stroke is sampled and recognized.
  * This class also has parameters to distinguish gesture input events from fast typing events.
  *
- * @attr ref R.styleable#MainKeyboardView_gestureStaticTimeThresholdAfterFastTyping
- * @attr ref R.styleable#MainKeyboardView_gestureDetectFastMoveSpeedThreshold
- * @attr ref R.styleable#MainKeyboardView_gestureDynamicThresholdDecayDuration
- * @attr ref R.styleable#MainKeyboardView_gestureDynamicTimeThresholdFrom
- * @attr ref R.styleable#MainKeyboardView_gestureDynamicTimeThresholdTo
- * @attr ref R.styleable#MainKeyboardView_gestureDynamicDistanceThresholdFrom
- * @attr ref R.styleable#MainKeyboardView_gestureDynamicDistanceThresholdTo
- * @attr ref R.styleable#MainKeyboardView_gestureSamplingMinimumDistance
- * @attr ref R.styleable#MainKeyboardView_gestureRecognitionMinimumTime
- * @attr ref R.styleable#MainKeyboardView_gestureRecognitionSpeedThreshold
+ * @attr ref android.R.styleable#MainKeyboardView_gestureStaticTimeThresholdAfterFastTyping
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDetectFastMoveSpeedThreshold
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDynamicThresholdDecayDuration
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDynamicTimeThresholdFrom
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDynamicTimeThresholdTo
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDynamicDistanceThresholdFrom
+ * @attr ref android.R.styleable#MainKeyboardView_gestureDynamicDistanceThresholdTo
+ * @attr ref android.R.styleable#MainKeyboardView_gestureSamplingMinimumDistance
+ * @attr ref android.R.styleable#MainKeyboardView_gestureRecognitionMinimumTime
+ * @attr ref android.R.styleable#MainKeyboardView_gestureRecognitionSpeedThreshold
  */
 public final class GestureStrokeRecognitionParams {
     // Static threshold for gesture after fast typing
diff --git a/java/src/com/android/inputmethod/keyboard/internal/GestureTrailDrawingParams.java b/java/src/com/android/inputmethod/keyboard/internal/GestureTrailDrawingParams.java
index 088f03aa6..074862a70 100644
--- a/java/src/com/android/inputmethod/keyboard/internal/GestureTrailDrawingParams.java
+++ b/java/src/com/android/inputmethod/keyboard/internal/GestureTrailDrawingParams.java
@@ -27,11 +27,11 @@ import com.android.inputmethod.latin.R;
  * sampled and interpolated. This class controls how those gesture strokes are displayed as a
  * gesture trail and animated on the screen.
  *
- * @attr ref R.styleable#MainKeyboardView_gestureTrailFadeoutStartDelay
- * @attr ref R.styleable#MainKeyboardView_gestureTrailFadeoutDuration
- * @attr ref R.styleable#MainKeyboardView_gestureTrailUpdateInterval
- * @attr ref R.styleable#MainKeyboardView_gestureTrailColor
- * @attr ref R.styleable#MainKeyboardView_gestureTrailWidth
+ * @attr ref android.R.styleable#MainKeyboardView_gestureTrailFadeoutStartDelay
+ * @attr ref android.R.styleable#MainKeyboardView_gestureTrailFadeoutDuration
+ * @attr ref android.R.styleable#MainKeyboardView_gestureTrailUpdateInterval
+ * @attr ref android.R.styleable#MainKeyboardView_gestureTrailColor
+ * @attr ref android.R.styleable#MainKeyboardView_gestureTrailWidth
  */
 final class GestureTrailDrawingParams {
     private static final int FADEOUT_START_DELAY_FOR_DEBUG = 2000; // millisecond
diff --git a/java/src/com/android/inputmethod/keyboard/internal/SlidingKeyInputDrawingPreview.java b/java/src/com/android/inputmethod/keyboard/internal/SlidingKeyInputDrawingPreview.java
index 73a6f9516..6837f0fcb 100644
--- a/java/src/com/android/inputmethod/keyboard/internal/SlidingKeyInputDrawingPreview.java
+++ b/java/src/com/android/inputmethod/keyboard/internal/SlidingKeyInputDrawingPreview.java
@@ -28,10 +28,10 @@ import com.android.inputmethod.latin.common.CoordinateUtils;
 /**
  * Draw rubber band preview graphics during sliding key input.
  *
- * @attr ref R.styleable#MainKeyboardView_slidingKeyInputPreviewColor
- * @attr ref R.styleable#MainKeyboardView_slidingKeyInputPreviewWidth
- * @attr ref R.styleable#MainKeyboardView_slidingKeyInputPreviewBodyRatio
- * @attr ref R.styleable#MainKeyboardView_slidingKeyInputPreviewShadowRatio
+ * @attr ref android.R.styleable#MainKeyboardView_slidingKeyInputPreviewColor
+ * @attr ref android.R.styleable#MainKeyboardView_slidingKeyInputPreviewWidth
+ * @attr ref android.R.styleable#MainKeyboardView_slidingKeyInputPreviewBodyRatio
+ * @attr ref android.R.styleable#MainKeyboardView_slidingKeyInputPreviewShadowRatio
  */
 public final class SlidingKeyInputDrawingPreview extends AbstractDrawingPreview {
     private final float mPreviewBodyRadius;
diff --git a/java/src/com/android/inputmethod/latin/utils/ResourceUtils.java b/java/src/com/android/inputmethod/latin/utils/ResourceUtils.java
index cc0d470df..f799be750 100644
--- a/java/src/com/android/inputmethod/latin/utils/ResourceUtils.java
+++ b/java/src/com/android/inputmethod/latin/utils/ResourceUtils.java
@@ -16,13 +16,18 @@
 
 package com.android.inputmethod.latin.utils;
 
+import android.content.Context;
 import android.content.res.Resources;
 import android.content.res.TypedArray;
+import android.graphics.Insets;
 import android.os.Build;
 import android.text.TextUtils;
 import android.util.DisplayMetrics;
 import android.util.Log;
 import android.util.TypedValue;
+import android.view.WindowInsets;
+import android.view.WindowManager;
+import android.view.WindowMetrics;
 
 import com.android.inputmethod.annotations.UsedForTesting;
 import com.android.inputmethod.latin.R;
@@ -182,8 +187,20 @@ public final class ResourceUtils {
         return matchedAll;
     }
 
-    public static int getDefaultKeyboardWidth(final Resources res) {
-        final DisplayMetrics dm = res.getDisplayMetrics();
+    public static int getDefaultKeyboardWidth(final Context context) {
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+            // Since Android 15’s edge-to-edge enforcement, window insets should be considered.
+            final WindowManager wm = context.getSystemService(WindowManager.class);
+            final WindowMetrics windowMetrics = wm.getCurrentWindowMetrics();
+            final Insets insets =
+                    windowMetrics
+                            .getWindowInsets()
+                            .getInsetsIgnoringVisibility(
+                                    WindowInsets.Type.systemBars()
+                                            | WindowInsets.Type.displayCutout());
+            return windowMetrics.getBounds().width() - insets.left - insets.right;
+        }
+        final DisplayMetrics dm = context.getResources().getDisplayMetrics();
         return dm.widthPixels;
     }
 
diff --git a/tests/src/com/android/inputmethod/keyboard/KeyboardLayoutSetTestsBase.java b/tests/src/com/android/inputmethod/keyboard/KeyboardLayoutSetTestsBase.java
index 29787acc9..1f13b4106 100644
--- a/tests/src/com/android/inputmethod/keyboard/KeyboardLayoutSetTestsBase.java
+++ b/tests/src/com/android/inputmethod/keyboard/KeyboardLayoutSetTestsBase.java
@@ -155,7 +155,7 @@ public abstract class KeyboardLayoutSetTestsBase extends AndroidTestCase {
             final boolean languageSwitchKeyEnabled, final boolean splitLayoutEnabled) {
         final Context context = getContext();
         final Resources res = context.getResources();
-        final int keyboardWidth = ResourceUtils.getDefaultKeyboardWidth(res);
+        final int keyboardWidth = ResourceUtils.getDefaultKeyboardWidth(context);
         final int keyboardHeight = ResourceUtils.getDefaultKeyboardHeight(res);
         final Builder builder = new Builder(context, editorInfo);
         builder.setKeyboardGeometry(keyboardWidth, keyboardHeight)
diff --git a/tools/dicttool/Android.bp b/tools/dicttool/Android.bp
index 48f751e78..3a6c7dc09 100644
--- a/tools/dicttool/Android.bp
+++ b/tools/dicttool/Android.bp
@@ -36,6 +36,6 @@ java_binary_host {
         "jsr305",
         "latinime-common",
     ],
-    required: ["libjni_latinime"],
+    jni_libs: ["libjni_latinime"],
     main_class: "com.android.inputmethod.latin.dicttool.Dicttool",
 }
```

