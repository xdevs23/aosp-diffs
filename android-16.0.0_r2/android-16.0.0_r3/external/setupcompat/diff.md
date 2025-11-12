```diff
diff --git a/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java b/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java
index 6a4f732..d3bc18d 100644
--- a/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java
+++ b/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java
@@ -271,7 +271,7 @@ public class PartnerCustomizationLayout extends TemplateLayout {
   protected void onAttachedToWindow() {
     super.onAttachedToWindow();
     LifecycleFragment lifecycleFragment =
-        LifecycleFragment.attachNow(activity, this::logFooterButtonMetrics);
+        LifecycleFragment.attachNow(activity, this::logMetricsOnFragmentStop);
     if (lifecycleFragment == null) {
       LOG.atDebug(
           "Unable to attach lifecycle fragment to the host activity. Activity="
@@ -290,31 +290,51 @@ public class PartnerCustomizationLayout extends TemplateLayout {
     if (VERSION.SDK_INT >= Build.VERSION_CODES.Q
         && WizardManagerHelper.isAnySetupWizard(activity.getIntent())) {
       FooterBarMixin footerBarMixin = getMixin(FooterBarMixin.class);
-      footerBarMixin.onDetachedFromWindow();
-      FooterButton primaryButton = footerBarMixin.getPrimaryButton();
-      FooterButton secondaryButton = footerBarMixin.getSecondaryButton();
-      PersistableBundle primaryButtonMetrics =
-          primaryButton != null
-              ? primaryButton.getMetrics("PrimaryFooterButton")
-              : PersistableBundle.EMPTY;
-      PersistableBundle secondaryButtonMetrics =
-          secondaryButton != null
-              ? secondaryButton.getMetrics("SecondaryFooterButton")
-              : PersistableBundle.EMPTY;
-
-      PersistableBundle layoutTypeMetrics =
-          (layoutTypeBundle != null) ? layoutTypeBundle : PersistableBundle.EMPTY;
-
-      PersistableBundle persistableBundle =
-          PersistableBundles.mergeBundles(
-              footerBarMixin.getLoggingMetrics(),
-              primaryButtonMetrics,
-              secondaryButtonMetrics,
-              layoutTypeMetrics);
-
-      SetupMetricsLogger.logCustomEvent(
-          getContext(),
-          CustomEvent.create(MetricKey.get("SetupCompatMetrics", activity), persistableBundle));
+
+      if (footerBarMixin != null) {
+        footerBarMixin.onDetachedFromWindow();
+        FooterButton primaryButton = footerBarMixin.getPrimaryButton();
+        FooterButton secondaryButton = footerBarMixin.getSecondaryButton();
+        FooterButton tertiaryButton = footerBarMixin.getTertiaryButton();
+        PersistableBundle primaryButtonMetrics =
+            primaryButton != null
+                ? primaryButton.getMetrics("PrimaryFooterButton")
+                : PersistableBundle.EMPTY;
+        PersistableBundle secondaryButtonMetrics =
+            secondaryButton != null
+                ? secondaryButton.getMetrics("SecondaryFooterButton")
+                : PersistableBundle.EMPTY;
+        PersistableBundle tertiaryButtonMetrics =
+            tertiaryButton != null
+                ? tertiaryButton.getMetrics("TertiaryFooterButton")
+                : PersistableBundle.EMPTY;
+
+        PersistableBundle layoutTypeMetrics =
+            (layoutTypeBundle != null) ? layoutTypeBundle : PersistableBundle.EMPTY;
+
+        PersistableBundle onDetachedFromWindowMetrics = new PersistableBundle();
+        onDetachedFromWindowMetrics.putLong("onDetachedFromWindow", System.nanoTime());
+
+        PersistableBundle persistableBundle =
+            PersistableBundles.mergeBundles(
+                footerBarMixin.getLoggingMetrics(),
+                primaryButtonMetrics,
+                secondaryButtonMetrics,
+                tertiaryButtonMetrics,
+                layoutTypeMetrics,
+                onDetachedFromWindowMetrics);
+
+        SetupMetricsLogger.logCustomEvent(
+            getContext(),
+            CustomEvent.create(MetricKey.get("SetupCompatMetrics", activity), persistableBundle));
+      } else {
+        LOG.w("FooterBarMixin is null");
+        PersistableBundle presistableBundle = new PersistableBundle();
+        presistableBundle.putLong("onDetachedFromWindow", System.nanoTime());
+        SetupMetricsLogger.logCustomEvent(
+            getContext(),
+            CustomEvent.create(MetricKey.get("SetupCompatMetrics", activity), presistableBundle));
+      }
     }
     getViewTreeObserver().removeOnWindowFocusChangeListener(windowFocusChangeListener);
 
@@ -323,42 +343,48 @@ public class PartnerCustomizationLayout extends TemplateLayout {
     }
   }
 
-  private void logFooterButtonMetrics(PersistableBundle bundle) {
+  private void logMetricsOnFragmentStop(PersistableBundle bundle) {
     if (VERSION.SDK_INT >= Build.VERSION_CODES.Q
         && activity != null
         && WizardManagerHelper.isAnySetupWizard(activity.getIntent())
         && PartnerConfigHelper.isEnhancedSetupDesignMetricsEnabled(getContext())) {
       FooterBarMixin footerBarMixin = getMixin(FooterBarMixin.class);
 
-      if (footerBarMixin == null
-          || (footerBarMixin.getPrimaryButton() == null
-              && footerBarMixin.getSecondaryButton() == null)) {
-        LOG.atDebug("Skip footer button logging because no footer buttons.");
-        return;
+      if (footerBarMixin != null) {
+        footerBarMixin.onDetachedFromWindow();
+        FooterButton primaryButton = footerBarMixin.getPrimaryButton();
+        FooterButton secondaryButton = footerBarMixin.getSecondaryButton();
+        FooterButton tertiaryButton = footerBarMixin.getTertiaryButton();
+        PersistableBundle primaryButtonMetrics =
+            primaryButton != null
+                ? primaryButton.getMetrics("PrimaryFooterButton")
+                : PersistableBundle.EMPTY;
+        PersistableBundle secondaryButtonMetrics =
+            secondaryButton != null
+                ? secondaryButton.getMetrics("SecondaryFooterButton")
+                : PersistableBundle.EMPTY;
+        PersistableBundle tertiaryButtonMetrics =
+            tertiaryButton != null
+                ? tertiaryButton.getMetrics("TertiaryFooterButton")
+                : PersistableBundle.EMPTY;
+
+        PersistableBundle persistableBundle =
+            PersistableBundles.mergeBundles(
+                footerBarMixin.getLoggingMetrics(),
+                primaryButtonMetrics,
+                secondaryButtonMetrics,
+                tertiaryButtonMetrics,
+                bundle);
+
+        SetupMetricsLogger.logCustomEvent(
+            getContext(),
+            CustomEvent.create(MetricKey.get("FooterButtonMetrics", activity), persistableBundle));
+      } else {
+        LOG.w("FooterBarMixin is null");
+        SetupMetricsLogger.logCustomEvent(
+            getContext(),
+            CustomEvent.create(MetricKey.get("FooterButtonMetrics", activity), bundle));
       }
-
-      footerBarMixin.onDetachedFromWindow();
-      FooterButton primaryButton = footerBarMixin.getPrimaryButton();
-      FooterButton secondaryButton = footerBarMixin.getSecondaryButton();
-      PersistableBundle primaryButtonMetrics =
-          primaryButton != null
-              ? primaryButton.getMetrics("PrimaryFooterButton")
-              : PersistableBundle.EMPTY;
-      PersistableBundle secondaryButtonMetrics =
-          secondaryButton != null
-              ? secondaryButton.getMetrics("SecondaryFooterButton")
-              : PersistableBundle.EMPTY;
-
-      PersistableBundle persistableBundle =
-          PersistableBundles.mergeBundles(
-              footerBarMixin.getLoggingMetrics(),
-              primaryButtonMetrics,
-              secondaryButtonMetrics,
-              bundle);
-
-      SetupMetricsLogger.logCustomEvent(
-          getContext(),
-          CustomEvent.create(MetricKey.get("FooterButtonMetrics", activity), persistableBundle));
     }
   }
 
@@ -502,15 +528,18 @@ public class PartnerCustomizationLayout extends TemplateLayout {
         LOG.atDebug("NavigationBarHeight: " + insets.getSystemWindowInsetBottom());
         FooterBarMixin footerBarMixin = getMixin(FooterBarMixin.class);
         LinearLayout buttonContainer = footerBarMixin.getButtonContainer();
-        if (footerBarMixin != null && footerBarMixin.getButtonContainer() != null) {
-          if (PartnerConfigHelper.get(getContext())
-              .isPartnerConfigAvailable(PartnerConfig.CONFIG_FOOTER_BUTTON_PADDING_BOTTOM)) {
+        View view = findViewById(R.id.suc_layout_status);
+        if (PartnerConfigHelper.get(getContext())
+            .isPartnerConfigAvailable(PartnerConfig.CONFIG_FOOTER_BUTTON_PADDING_BOTTOM)) {
             footerBarPaddingBottom =
                 (int)
                     PartnerConfigHelper.get(getContext())
                         .getDimension(
                             getContext(), PartnerConfig.CONFIG_FOOTER_BUTTON_PADDING_BOTTOM);
           }
+        if (footerBarMixin != null
+            && footerBarMixin.getButtonContainer() != null
+            && footerBarMixin.getButtonContainer().getVisibility() != View.GONE) {
           // Adjust footer bar padding to account for the navigation bar, ensuring
           // it extends to the bottom of the screen and with proper bottom padding.
           buttonContainer.setPadding(
@@ -518,6 +547,13 @@ public class PartnerCustomizationLayout extends TemplateLayout {
               buttonContainer.getPaddingTop(),
               buttonContainer.getPaddingRight(),
               footerBarPaddingBottom + insets.getSystemWindowInsetBottom());
+          view.setPadding(view.getPaddingLeft(), view.getPaddingTop(), view.getPaddingRight(), 0);
+        } else {
+          view.setPadding(
+              view.getPaddingLeft(),
+              view.getPaddingTop(),
+              view.getPaddingRight(),
+              footerBarPaddingBottom + insets.getSystemWindowInsetBottom());
         }
       }
     }
diff --git a/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java b/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java
index 6027d29..1229faf 100644
--- a/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java
+++ b/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java
@@ -26,6 +26,7 @@ import android.os.Build.VERSION;
 import android.os.Build.VERSION_CODES;
 import android.os.PersistableBundle;
 import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
 import android.util.Log;
 import com.google.android.setupcompat.logging.CustomEvent;
 import com.google.android.setupcompat.logging.MetricKey;
@@ -38,6 +39,7 @@ public class LifecycleFragment extends Fragment {
   private static final String LOG_TAG = LifecycleFragment.class.getSimpleName();
   private static final Logger LOG = new Logger(LOG_TAG);
   private static final String FRAGMENT_ID = "lifecycle_monitor";
+  @VisibleForTesting static final String KEY_ON_SCREEN_START = "onScreenStart";
 
   private MetricKey metricKey;
   private long startInNanos;
@@ -134,16 +136,26 @@ public class LifecycleFragment extends Fragment {
     SetupMetricsLogger.logDuration(getActivity(), metricKey, NANOSECONDS.toMillis(durationInNanos));
   }
 
+  @Override
+  public void onStart() {
+    super.onStart();
+    startInNanos = ClockProvider.timeInNanos();
+    LOG.atDebug(
+        "onStart host="
+            + getActivity().getClass().getSimpleName()
+            + ", startInNanos="
+            + startInNanos);
+    logScreenTimestamp(KEY_ON_SCREEN_START);
+  }
+
   @Override
   public void onResume() {
     super.onResume();
-    startInNanos = ClockProvider.timeInNanos();
     LOG.atDebug(
         "onResume host="
             + getActivity().getClass().getSimpleName()
             + ", startInNanos="
-            + startInNanos);
-    logScreenResume();
+            + ClockProvider.timeInNanos());
   }
 
   @Override
@@ -169,10 +181,11 @@ public class LifecycleFragment extends Fragment {
     }
   }
 
-  private void logScreenResume() {
+  @VisibleForTesting
+  void logScreenTimestamp(String keyName) {
     if (VERSION.SDK_INT >= VERSION_CODES.Q) {
       PersistableBundle bundle = new PersistableBundle();
-      bundle.putLong("onScreenResume", System.nanoTime());
+      bundle.putLong(keyName, System.nanoTime());
       SetupMetricsLogger.logCustomEvent(
           getActivity(),
           CustomEvent.create(MetricKey.get("ScreenActivity", getActivity()), bundle));
diff --git a/main/java/com/google/android/setupcompat/internal/Validations.java b/main/java/com/google/android/setupcompat/internal/Validations.java
index 333c134..481af37 100644
--- a/main/java/com/google/android/setupcompat/internal/Validations.java
+++ b/main/java/com/google/android/setupcompat/internal/Validations.java
@@ -16,31 +16,28 @@
 
 package com.google.android.setupcompat.internal;
 
+import com.google.android.setupcompat.util.Logger;
+
 /** Commonly used validations and preconditions. */
 public final class Validations {
+  private static final Logger LOG = new Logger("Validations");
 
   /**
-   * Asserts that the {@code length} is in the expected range.
-   *
-   * @throws IllegalArgumentException if {@code input}'s length is than {@code minLength} or
-   *     greather than {@code maxLength}.
-   */
-  public static void assertLengthInRange(int length, String name, int minLength, int maxLength) {
-    Preconditions.checkArgument(
-        length <= maxLength && length >= minLength,
-        String.format("Length of %s should be in the range [%s-%s]", name, minLength, maxLength));
-  }
-
-  /**
-   * Asserts that the {@code input}'s length is in the expected range.
-   *
-   * @throws NullPointerException if {@code input} is null.
-   * @throws IllegalArgumentException if {@code input}'s length is than {@code minLength} or
-   *     greather than {@code maxLength}.
+   * Asserts that the {@code input}'s length is in the expected range. Print wtf if {@code input} is
+   * null or {@code input}'s length is shorter than {@code minLength} or greater than {@code
+   * maxLength}.
    */
   public static void assertLengthInRange(String input, String name, int minLength, int maxLength) {
-    Preconditions.checkNotNull(input, String.format("%s cannot be null.", name));
-    assertLengthInRange(input.length(), name, minLength, maxLength);
+    if (input == null) {
+      LOG.e(String.format("Input of %s cannot be null", name));
+      return;
+    }
+
+    if (input.length() > maxLength || input.length() < minLength) {
+      LOG.e(
+          String.format(
+              "Length of \"%s\" should be in the range [%s-%s]", input, minLength, maxLength));
+    }
   }
 
   private Validations() {
diff --git a/main/java/com/google/android/setupcompat/logging/CustomEvent.java b/main/java/com/google/android/setupcompat/logging/CustomEvent.java
index be8e52a..0c6dcc2 100644
--- a/main/java/com/google/android/setupcompat/logging/CustomEvent.java
+++ b/main/java/com/google/android/setupcompat/logging/CustomEvent.java
@@ -151,10 +151,9 @@ public final class CustomEvent implements Parcelable {
     if (this == o) {
       return true;
     }
-    if (!(o instanceof CustomEvent)) {
+    if (!(o instanceof CustomEvent that)) {
       return false;
     }
-    CustomEvent that = (CustomEvent) o;
     return timestampMillis == that.timestampMillis
         && ObjectUtils.equals(metricKey, that.metricKey)
         && PersistableBundles.equals(persistableBundle, that.persistableBundle)
@@ -176,7 +175,7 @@ public final class CustomEvent implements Parcelable {
     Preconditions.checkNotNull(bundle, "Bundle cannot be null.");
     Preconditions.checkArgument(!bundle.isEmpty(), "Bundle cannot be empty.");
     Preconditions.checkNotNull(piiValues, "piiValues cannot be null.");
-    assertPersistableBundleIsValid(bundle);
+    tryTrimStringOverMaxLengthInPersistableBundle(bundle);
     this.timestampMillis = timestampMillis;
     this.metricKey = metricKey;
     this.persistableBundle = new PersistableBundle(bundle);
@@ -188,33 +187,51 @@ public final class CustomEvent implements Parcelable {
   private final PersistableBundle persistableBundle;
   private final PersistableBundle piiValues;
 
-  private static void assertPersistableBundleIsValid(PersistableBundle bundle) {
+  @VisibleForTesting
+  static void tryTrimStringOverMaxLengthInPersistableBundle(PersistableBundle bundle) {
     for (String key : bundle.keySet()) {
       assertLengthInRange(key, "bundle key", MIN_BUNDLE_KEY_LENGTH, MAX_STR_LENGTH);
       Object value = bundle.get(key);
-      if (value instanceof String) {
-        Preconditions.checkArgument(
-            ((String) value).length() <= MAX_STR_LENGTH,
-            String.format(
-                "Maximum length of string value for key='%s' cannot exceed %s.",
-                key, MAX_STR_LENGTH));
+      if (value instanceof String stringValue) {
+        if (stringValue.length() > MAX_STR_LENGTH) {
+          stringValue = trimsStringOverMaxLength(stringValue);
+          bundle.putString(key, stringValue);
+        }
       }
     }
   }
 
   /**
-   * Trims the string longer than {@code MAX_STR_LENGTH} character, only keep the first {@code
-   * MAX_STR_LENGTH} - 1 characters and attached … in the end.
+   * Trims the string longer than {@code MAX_STR_LENGTH} character, only keep the last {@code
+   * MAX_STR_LENGTH} characters and add "truncated." prefix in the start.
+   *
+   * @param str the string to be trimmed
+   * @param maxLength the max length of the string. If it is less than {@code MAX_STR_LENGTH}, it
+   *     will be set to {@code MAX_STR_LENGTH}.
+   * @return the trimmed string
    */
   @NonNull
-  public static String trimsStringOverMaxLength(@NonNull String str) {
-    if (str.length() <= MAX_STR_LENGTH) {
+  public static String trimsStringOverMaxLength(@NonNull String str, int maxLength) {
+    if (maxLength < MAX_STR_LENGTH) {
+      maxLength = MAX_STR_LENGTH;
+    }
+
+    if (str.length() <= maxLength) {
       return str;
     } else {
-      return String.format("%s…", str.substring(0, MAX_STR_LENGTH - 1));
+      // Adding a prefix after trimming.
+      return PREFIX_AFTER_TRIM
+          + str.substring(str.length() - maxLength + PREFIX_AFTER_TRIM.length());
     }
   }
 
-  @VisibleForTesting public static final int MAX_STR_LENGTH = 50;
-  @VisibleForTesting static final int MIN_BUNDLE_KEY_LENGTH = 3;
+  @NonNull
+  public static String trimsStringOverMaxLength(@NonNull String str) {
+    return trimsStringOverMaxLength(str, MAX_STR_LENGTH);
+  }
+
+  public static final int MAX_STR_LENGTH = 50;
+  public static final int MIN_BUNDLE_KEY_LENGTH = 3;
+
+  public static final String PREFIX_AFTER_TRIM = "truncated.";
 }
diff --git a/main/java/com/google/android/setupcompat/logging/MetricKey.java b/main/java/com/google/android/setupcompat/logging/MetricKey.java
index cdfb7d7..20b6166 100644
--- a/main/java/com/google/android/setupcompat/logging/MetricKey.java
+++ b/main/java/com/google/android/setupcompat/logging/MetricKey.java
@@ -17,6 +17,7 @@
 package com.google.android.setupcompat.logging;
 
 import static com.google.android.setupcompat.internal.Validations.assertLengthInRange;
+import static com.google.android.setupcompat.logging.CustomEvent.trimsStringOverMaxLength;
 
 import android.app.Activity;
 import android.os.Bundle;
@@ -32,7 +33,6 @@ import java.util.regex.Pattern;
  * values reported by the API consumer.
  */
 public final class MetricKey implements Parcelable {
-
   private static final String METRIC_KEY_BUNDLE_NAME_KEY = "MetricKey_name";
   private static final String METRIC_KEY_BUNDLE_SCREEN_NAME_KEY = "MetricKey_screenName";
   private static final String METRIC_KEY_BUNDLE_VERSION = "MetricKey_version";
@@ -69,8 +69,7 @@ public final class MetricKey implements Parcelable {
     // We only checked the length of customized screen name, by the reason if the screenName match
     // to the class name skip check it
     if (!SCREEN_COMPONENTNAME_PATTERN.matcher(screenName).matches()) {
-      assertLengthInRange(
-          screenName, "MetricKey.screenName", MIN_SCREEN_NAME_LENGTH, MAX_SCREEN_NAME_LENGTH);
+      screenName = trimsStringOverMaxLength(screenName, MAX_SCREEN_NAME_LENGTH);
       Preconditions.checkArgument(
           SCREEN_NAME_PATTERN.matcher(screenName).matches(),
           "Invalid ScreenName, only alpha numeric characters are allowed.");
@@ -162,12 +161,11 @@ public final class MetricKey implements Parcelable {
   private final String name;
   private final String screenName;
 
-  private static final int MIN_SCREEN_NAME_LENGTH = 5;
   private static final int MIN_METRIC_KEY_LENGTH = 5;
-  private static final int MAX_SCREEN_NAME_LENGTH = 50;
+  private static final int MAX_SCREEN_NAME_LENGTH = 200;
   private static final int MAX_METRIC_KEY_LENGTH = 30;
   private static final Pattern METRIC_KEY_PATTERN = Pattern.compile("^[a-zA-Z][a-zA-Z0-9_]+");
   private static final Pattern SCREEN_COMPONENTNAME_PATTERN =
-      Pattern.compile("^([a-z]+[.])+[A-Z][a-zA-Z0-9]+");
-  private static final Pattern SCREEN_NAME_PATTERN = Pattern.compile("^[a-zA-Z][a-zA-Z0-9_]+");
+      Pattern.compile("^([a-z]+[.])+[A-Z][a-zA-Z0-9_$]+");
+  private static final Pattern SCREEN_NAME_PATTERN = Pattern.compile("^[a-zA-Z][a-zA-Z0-9_$]+");
 }
diff --git a/main/java/com/google/android/setupcompat/logging/internal/FooterBarMixinMetrics.java b/main/java/com/google/android/setupcompat/logging/internal/FooterBarMixinMetrics.java
index 62eab22..2fb1adf 100644
--- a/main/java/com/google/android/setupcompat/logging/internal/FooterBarMixinMetrics.java
+++ b/main/java/com/google/android/setupcompat/logging/internal/FooterBarMixinMetrics.java
@@ -36,6 +36,9 @@ public class FooterBarMixinMetrics {
   @VisibleForTesting
   public static final String EXTRA_SECONDARY_BUTTON_VISIBILITY = "SecondaryButtonVisibility";
 
+  @VisibleForTesting
+  public static final String EXTRA_TERTIARY_BUTTON_VISIBILITY = "TertiaryButtonVisibility";
+
   @Retention(SOURCE)
   @StringDef({
     FooterButtonVisibility.UNKNOWN,
@@ -62,6 +65,9 @@ public class FooterBarMixinMetrics {
 
   @FooterButtonVisibility String secondaryButtonVisibility = FooterButtonVisibility.UNKNOWN;
 
+  @VisibleForTesting @FooterButtonVisibility
+  public String tertiaryButtonVisibility = FooterButtonVisibility.UNKNOWN;
+
   /** Creates a metric object for metric logging */
   public FooterBarMixinMetrics() {}
 
@@ -96,13 +102,25 @@ public class FooterBarMixinMetrics {
             : secondaryButtonVisibility;
   }
 
+  /** Saves tertiary footer button visibility when initial state */
+  public void logTertiaryButtonInitialStateVisibility(boolean isVisible, boolean isUsingXml) {
+    tertiaryButtonVisibility =
+        tertiaryButtonVisibility.equals(FooterButtonVisibility.UNKNOWN)
+            ? getInitialStateVisibility(isVisible, isUsingXml)
+            : tertiaryButtonVisibility;
+  }
+
   /** Saves footer button visibility when finish state */
   public void updateButtonVisibility(
-      boolean isPrimaryButtonVisible, boolean isSecondaryButtonVisible) {
+      boolean isPrimaryButtonVisible,
+      boolean isSecondaryButtonVisible,
+      boolean isTertiaryButtonVisible) {
     primaryButtonVisibility =
         updateButtonVisibilityState(primaryButtonVisibility, isPrimaryButtonVisible);
     secondaryButtonVisibility =
         updateButtonVisibilityState(secondaryButtonVisibility, isSecondaryButtonVisible);
+    tertiaryButtonVisibility =
+        updateButtonVisibilityState(tertiaryButtonVisibility, isTertiaryButtonVisible);
   }
 
   @FooterButtonVisibility
@@ -132,6 +150,7 @@ public class FooterBarMixinMetrics {
     PersistableBundle persistableBundle = new PersistableBundle();
     persistableBundle.putString(EXTRA_PRIMARY_BUTTON_VISIBILITY, primaryButtonVisibility);
     persistableBundle.putString(EXTRA_SECONDARY_BUTTON_VISIBILITY, secondaryButtonVisibility);
+    persistableBundle.putString(EXTRA_TERTIARY_BUTTON_VISIBILITY, tertiaryButtonVisibility);
     return persistableBundle;
   }
 }
diff --git a/main/java/com/google/android/setupcompat/template/FooterBarMixin.java b/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
index 7aa9cd4..6322b06 100644
--- a/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
+++ b/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
@@ -51,6 +51,7 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.StyleRes;
 import androidx.annotation.VisibleForTesting;
+import androidx.core.view.ViewCompat;
 import com.google.android.material.button.MaterialButton;
 import com.google.android.setupcompat.PartnerCustomizationLayout;
 import com.google.android.setupcompat.R;
@@ -100,6 +101,8 @@ public class FooterBarMixin implements Mixin {
 
   private int footerBarPaddingTop;
   private int footerBarPaddingBottom;
+  private int windowInsetLeft = 0;
+  private int windowInsetRight = 0;
   @VisibleForTesting int footerBarPaddingStart;
   @VisibleForTesting int footerBarPaddingEnd;
   @VisibleForTesting int defaultPadding;
@@ -115,6 +118,8 @@ public class FooterBarMixin implements Mixin {
   private static final String KEY_HOST_FRAGMENT_TAG = "HostFragmentTag";
   private String hostFragmentName;
   private String hostFragmentTag;
+  private int containerVisibility;
+  private boolean downButtonEnable;
 
   @VisibleForTesting final int footerBarButtonMiddleSpacing;
 
@@ -302,6 +307,12 @@ public class FooterBarMixin implements Mixin {
     }
   }
 
+  public void setDownButtonEnabled(boolean enable) {
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      downButtonEnable = enable;
+    }
+  }
+
   public void setFragmentInfo(@Nullable Fragment fragment) {
     if (fragment != null) {
       hostFragmentName = fragment.getClass().getSimpleName();
@@ -381,9 +392,9 @@ public class FooterBarMixin implements Mixin {
     buttonContainer.setId(View.generateViewId());
     updateFooterBarPadding(
         buttonContainer,
-        footerBarPaddingStart,
+        footerBarPaddingStart + windowInsetLeft,
         footerBarPaddingTop,
-        footerBarPaddingEnd,
+        footerBarPaddingEnd + windowInsetRight,
         footerBarPaddingBottom);
     if (isFooterButtonAlignedEnd()) {
       buttonContainer.setGravity(Gravity.END | Gravity.CENTER_VERTICAL);
@@ -443,9 +454,9 @@ public class FooterBarMixin implements Mixin {
     }
     updateFooterBarPadding(
         buttonContainer,
-        footerBarPaddingStart,
+        footerBarPaddingStart + windowInsetLeft,
         footerBarPaddingTop,
-        footerBarPaddingEnd,
+        footerBarPaddingEnd + windowInsetRight,
         footerBarPaddingBottom);
 
     if (PartnerConfigHelper.get(context)
@@ -826,6 +837,11 @@ public class FooterBarMixin implements Mixin {
         });
   }
 
+  /** Returns the {@link FooterButton} of tertiary button. */
+  public FooterButton getTertiaryButton() {
+    return tertiaryButton;
+  }
+
   @Nullable
   public Button getTertiaryButtonView() {
     if (!PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
@@ -835,6 +851,12 @@ public class FooterBarMixin implements Mixin {
     return buttonContainer == null ? null : buttonContainer.findViewById(tertiaryButtonId);
   }
 
+  @VisibleForTesting
+  boolean isTertiaryButtonVisible() {
+    return getTertiaryButtonView() != null
+        && getTertiaryButtonView().getVisibility() == View.VISIBLE;
+  }
+
   /**
    * Corrects the order of footer buttons after the button has been inflated to the view hierarchy.
    * Subclasses can implement this method to modify the order of footer buttons as necessary.
@@ -857,6 +879,14 @@ public class FooterBarMixin implements Mixin {
       addSpace();
     }
 
+    // Save the button container visibility and set button container to invisible if it is visible.
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      containerVisibility = buttonContainer.getVisibility();
+      if (containerVisibility == View.VISIBLE) {
+        buttonContainer.setVisibility(View.INVISIBLE);
+      }
+    }
+
     if (tempSecondaryButton != null) {
       if (isSecondaryButtonInPrimaryStyle) {
         // Since the secondary button has the same style (with background) as the primary button,
@@ -931,7 +961,8 @@ public class FooterBarMixin implements Mixin {
   public void setButtonWidthForExpressiveStyle() {
     buttonContainer.post(
         () -> {
-          int containerWidth = buttonContainer.getMeasuredWidth();
+          int containerWidth =
+              buttonContainer.getMeasuredWidth() - windowInsetLeft - windowInsetRight;
           Button primaryButton = getPrimaryButtonView();
           Button secondaryButton = getSecondaryButtonView();
           Button tertiaryButton = getTertiaryButtonView();
@@ -954,11 +985,21 @@ public class FooterBarMixin implements Mixin {
           } else if (isBothButtons(primaryButton, secondaryButton)) {
             LayoutParams primaryLayoutParams = (LayoutParams) primaryButton.getLayoutParams();
             LayoutParams secondaryLayoutParams = (LayoutParams) secondaryButton.getLayoutParams();
+            maxButtonWidth = availableFooterBarWidth / 2;
+
             boolean isButtonStacked =
                 stackButtonIfTextOverFlow(
                     primaryButton, secondaryButton, maxButtonWidth, availableFooterBarWidth);
 
             if (!isButtonStacked) {
+              // When the button is not stacked, the buttons require to consider the margins for the
+              // footer bar available width. The button margins might be set by default in the
+              // Material button style.
+              maxButtonWidth =
+                  (availableFooterBarWidth
+                          - primaryLayoutParams.getMarginStart()
+                          - secondaryLayoutParams.getMarginEnd())
+                      / 2;
               if (primaryLayoutParams != null) {
                 primaryLayoutParams.width = maxButtonWidth;
                 primaryLayoutParams.setMarginStart(footerBarButtonMiddleSpacing / 2);
@@ -985,34 +1026,44 @@ public class FooterBarMixin implements Mixin {
           } else {
             LOG.atInfo("There are no button visible in the footer bar.");
           }
+          // Set back the button container visibility to its original state.
+          buttonContainer.setVisibility(containerVisibility);
         });
   }
 
   /** Sets down button for expressive style. */
   public void setDownButtonForExpressiveStyle() {
+    downButtonEnable = true;
     buttonContainer.post(
         () -> {
-          int containerWidth = buttonContainer.getMeasuredWidth();
-          // Only allow primary button been shown on the screen if in the down button style.
-          if (getSecondaryButtonView() != null) {
-            getSecondaryButtonView().setVisibility(View.GONE);
-          }
+          int containerWidth =
+              buttonContainer.getMeasuredWidth() - windowInsetLeft - windowInsetRight;
           setDownButtonStyle(getPrimaryButtonView());
           if (!isTwoPaneLayout()) {
             buttonContainer.setGravity(Gravity.CENTER_HORIZONTAL | Gravity.CENTER_VERTICAL);
           } else {
             buttonContainer.setGravity(Gravity.CENTER_VERTICAL);
 
-            Button downButtonView = getPrimaryButtonView();
-            LayoutParams primaryLayoutParams = (LayoutParams) downButtonView.getLayoutParams();
             int downButtonWidth =
                 context
                     .getResources()
                     .getDimensionPixelSize(R.dimen.suc_glif_expressive_down_button_width);
-            // Put down button to the center of the one side in two pane mode.
-            primaryLayoutParams.setMarginStart(
-                (containerWidth / 2) + (containerWidth / 4) - downButtonWidth);
-            downButtonView.setLayoutParams(primaryLayoutParams);
+            Button downButton = getPrimaryButtonView();
+            LinearLayout.LayoutParams layoutParams =
+                (LinearLayout.LayoutParams) downButton.getLayoutParams();
+            // Set padding for the button container to center the down button in two pane mode, it
+            // is required to consider the button's margin. Sets button container's padding instead
+            // of button margin because using button LayoutParameter to set the margin will call the
+            // request layout unexpectedly then make the down button style incorrect.
+            double paddingStart =
+                ((containerWidth * 0.75) - (downButtonWidth / 2.0))
+                    - (layoutParams.getMarginStart() + layoutParams.getMarginEnd());
+
+            buttonContainer.setPaddingRelative(
+                (int) (Math.round(paddingStart) + windowInsetLeft),
+                buttonContainer.getPaddingTop(),
+                buttonContainer.getPaddingEnd(),
+                buttonContainer.getPaddingBottom());
           }
         });
   }
@@ -1084,6 +1135,20 @@ public class FooterBarMixin implements Mixin {
         primaryButton.setLayoutParams(primaryLayoutParams);
         return true;
       }
+    } else {
+      // Button is not stacked, we need to set the button width and margin to be side by side.
+      if (buttonContainer instanceof ButtonBarLayout buttonBarLayout) {
+        buttonBarLayout.setStackedButtonForExpressiveStyle(false);
+        primaryLayoutParams.width = availableFooterBarWidth;
+        primaryLayoutParams.setMarginStart(footerBarButtonMiddleSpacing / 2);
+        primaryLayoutParams.bottomMargin = 0;
+        primaryButton.setLayoutParams(primaryLayoutParams);
+
+        secondaryLayoutParams.width = availableFooterBarWidth;
+        secondaryLayoutParams.setMarginEnd(footerBarButtonMiddleSpacing / 2);
+        secondaryLayoutParams.topMargin = 0;
+        secondaryButton.setLayoutParams(secondaryLayoutParams);
+      }
     }
     return false;
   }
@@ -1419,7 +1484,15 @@ public class FooterBarMixin implements Mixin {
       // Ignore action since buttonContainer is null
       return;
     }
-    buttonContainer.setPadding(left, top, right, bottom);
+    buttonContainer.setPaddingRelative(left, top, right, bottom);
+
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      // Adjust footer bar padding to account for the navigation bar, ensuring it extends to the
+      // bottom of the screen and with proper bottom padding.
+      if (VERSION.SDK_INT >= VERSION_CODES.KITKAT_WATCH) {
+        buttonContainer.requestApplyInsets();
+      }
+    }
   }
 
   /** Returns the paddingTop of footer bar. */
@@ -1442,11 +1515,14 @@ public class FooterBarMixin implements Mixin {
         /* isVisible= */ isPrimaryButtonVisible(), /* isUsingXml= */ false);
     metrics.logSecondaryButtonInitialStateVisibility(
         /* isVisible= */ isSecondaryButtonVisible(), /* isUsingXml= */ false);
+    metrics.logTertiaryButtonInitialStateVisibility(
+        /* isVisible= */ isTertiaryButtonVisible(), /* isUsingXml= */ false);
   }
 
   /** Uses for notify mixin the view already detached from window. */
   public void onDetachedFromWindow() {
-    metrics.updateButtonVisibility(isPrimaryButtonVisible(), isSecondaryButtonVisible());
+    metrics.updateButtonVisibility(
+        isPrimaryButtonVisible(), isSecondaryButtonVisible(), isTertiaryButtonVisible());
   }
 
   /**
@@ -1471,6 +1547,30 @@ public class FooterBarMixin implements Mixin {
     return persistableBundle;
   }
 
+  public void setWindowInsets(int left, int right) {
+    if (buttonContainer != null
+        && ViewCompat.getLayoutDirection(buttonContainer) == ViewCompat.LAYOUT_DIRECTION_RTL) {
+      int temp = left;
+      left = right;
+      right = temp;
+    }
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)
+        && (windowInsetLeft != left || windowInsetRight != right)) {
+      windowInsetLeft = left;
+      windowInsetRight = right;
+      if (downButtonEnable) {
+        setDownButtonForExpressiveStyle();
+      } else {
+        updateFooterBarPadding(
+            buttonContainer,
+            windowInsetLeft + footerBarPaddingStart,
+            footerBarPaddingTop,
+            windowInsetRight + footerBarPaddingEnd,
+            footerBarPaddingBottom);
+      }
+    }
+  }
+
   private void updateTextColorForButton(Button button, boolean enable, int color) {
     if (enable) {
       FooterButtonStyleUtils.updateButtonTextEnabledColor(button, color);
diff --git a/main/java/com/google/android/setupcompat/template/FooterButton.java b/main/java/com/google/android/setupcompat/template/FooterButton.java
index c204128..1c20bdd 100644
--- a/main/java/com/google/android/setupcompat/template/FooterButton.java
+++ b/main/java/com/google/android/setupcompat/template/FooterButton.java
@@ -235,11 +235,11 @@ public final class FooterButton implements OnClickListener {
   @Override
   public void onClick(View v) {
     if (onClickListener != null) {
-      clickCount++;
-      onClickListener.onClick(v);
       if (loggingObserver != null) {
         loggingObserver.log(new ButtonInteractionEvent(v, InteractionType.TAP));
       }
+      clickCount++;
+      onClickListener.onClick(v);
     }
   }
 
diff --git a/main/java/com/google/android/setupcompat/util/Logger.java b/main/java/com/google/android/setupcompat/util/Logger.java
index 3f8dfd1..d01514c 100644
--- a/main/java/com/google/android/setupcompat/util/Logger.java
+++ b/main/java/com/google/android/setupcompat/util/Logger.java
@@ -80,4 +80,8 @@ public final class Logger {
   public void e(String message, Throwable throwable) {
     Log.e(TAG, prefix.concat(message), throwable);
   }
+
+  public void wtf(String message) {
+    Log.wtf(TAG, prefix.concat(message));
+  }
 }
diff --git a/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java b/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java
index 9b7a40a..589ecc5 100644
--- a/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java
+++ b/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java
@@ -26,6 +26,7 @@ import android.os.Build.VERSION_CODES;
 import android.util.AttributeSet;
 import android.view.WindowInsets;
 import android.widget.FrameLayout;
+import com.google.android.setupcompat.R;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.util.Logger;
 
@@ -104,10 +105,10 @@ public class StatusBarBackgroundLayout extends FrameLayout {
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
     lastInsets = insets;
diff --git a/main/res/values-w840dp-h900dp-v35/config.xml b/main/res/values-w840dp-h900dp-v35/config.xml
new file mode 100644
index 0000000..8f7d0c8
--- /dev/null
+++ b/main/res/values-w840dp-h900dp-v35/config.xml
@@ -0,0 +1,23 @@
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
+<resources>
+
+    <!-- A boolean value that indicates whether the device should show two panes. -->
+    <bool name="sucTwoPaneLayoutStyle">true</bool>
+
+</resources>
diff --git a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java
index 9f41cf4..8ceb618 100644
--- a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java
+++ b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java
@@ -289,6 +289,14 @@ public enum PartnerConfig {
   // Size of account avatar
   CONFIG_ACCOUNT_AVATAR_SIZE(PartnerConfigKey.KEY_ACCOUNT_AVATAR_MAX_SIZE, ResourceType.DIMENSION),
 
+  // Margin top of the account container
+  CONFIG_ACCOUNT_CONTAINER_MARGIN_TOP(
+      PartnerConfigKey.KEY_ACCOUNT_CONTAINER_MARGIN_TOP, ResourceType.DIMENSION),
+
+  // Margin bottom of the account container
+  CONFIG_ACCOUNT_CONTAINER_MARGIN_BOTTOM(
+      PartnerConfigKey.KEY_ACCOUNT_CONTAINER_MARGIN_BOTTOM, ResourceType.DIMENSION),
+
   // Text size of the body content text
   CONFIG_CONTENT_TEXT_SIZE(PartnerConfigKey.KEY_CONTENT_TEXT_SIZE, ResourceType.DIMENSION),
 
@@ -353,6 +361,10 @@ public enum PartnerConfig {
   CONFIG_ITEMS_SUMMARY_FONT_FAMILY(
       PartnerConfigKey.KEY_ITEMS_SUMMARY_FONT_FAMILY, ResourceType.STRING),
 
+  // Font variation_settings of the list items title.
+  CONFIG_ITEMS_TITLE_FONT_VARIATION_SETTINGS(
+      PartnerConfigKey.KEY_ITEMS_TITLE_FONT_VARIATION_SETTINGS, ResourceType.STRING),
+
   // The padding top of list items.
   CONFIG_ITEMS_PADDING_TOP(PartnerConfigKey.KEY_ITEMS_PADDING_TOP, ResourceType.DIMENSION),
 
diff --git a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigHelper.java b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigHelper.java
index 8706418..e5058ce 100644
--- a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigHelper.java
+++ b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigHelper.java
@@ -41,6 +41,7 @@ import androidx.annotation.VisibleForTesting;
 import androidx.window.embedding.ActivityEmbeddingController;
 import com.google.android.setupcompat.partnerconfig.PartnerConfig.ResourceType;
 import com.google.android.setupcompat.util.BuildCompatUtils;
+import com.google.android.setupcompat.util.WizardManagerHelper;
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.EnumMap;
@@ -141,6 +142,8 @@ public class PartnerConfigHelper {
 
   private static boolean savedConfigEmbeddedActivityMode;
 
+  @VisibleForTesting static boolean isAnySetupWizard = true;
+
   @VisibleForTesting static Bundle applyTransitionBundle = null;
 
   @SuppressWarnings("NonFinalStaticField")
@@ -1173,8 +1176,29 @@ public class PartnerConfigHelper {
    * Returns true if the SetupWizard supports Glif Expressive style inside or outside setup flow.
    */
   public static boolean isGlifExpressiveEnabled(@NonNull Context context) {
+    boolean isRequery = false;
+    Activity activity = null;
+    try {
+      activity = lookupActivityFromContext(context);
+    } catch (IllegalArgumentException ex) {
+      Log.w(TAG, "Failed to lookup activity from context: " + ex);
+    }
+    // Save inside/outside setup wizard flag into bundle
+    Bundle extras = null;
+    if (activity != null) {
+      extras = new Bundle();
+      boolean currentIsAnySetupWizard = WizardManagerHelper.isAnySetupWizard(activity.getIntent());
+      // if the setup state is not cached or the setup staty is different from the current state, we
+      // need to requery the flag from the provider.
+      if (isAnySetupWizard != currentIsAnySetupWizard) {
+        isAnySetupWizard = currentIsAnySetupWizard;
+        isRequery = true;
+        Log.i(TAG, "Need to requery the flag isGlifExpressiveEnabled from provider");
+      }
+      extras.putBoolean(WizardManagerHelper.EXTRA_IS_SETUP_FLOW, currentIsAnySetupWizard);
+    }
 
-    if (applyGlifExpressiveBundle == null || applyGlifExpressiveBundle.isEmpty()) {
+    if (applyGlifExpressiveBundle == null || applyGlifExpressiveBundle.isEmpty() || isRequery) {
       try {
         applyGlifExpressiveBundle =
             context
@@ -1183,11 +1207,12 @@ public class PartnerConfigHelper {
                     getContentUri(),
                     IS_GLIF_EXPRESSIVE_ENABLED,
                     /* arg= */ null,
-                    /* extras= */ null);
+                    /* extras= */ extras);
       } catch (IllegalArgumentException | SecurityException exception) {
         Log.w(TAG, "isGlifExpressiveEnabled status is unknown; return as false.");
       }
     }
+
     if (applyGlifExpressiveBundle != null && !applyGlifExpressiveBundle.isEmpty()) {
       return applyGlifExpressiveBundle.getBoolean(IS_GLIF_EXPRESSIVE_ENABLED, false);
     }
diff --git a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java
index c5047b9..a8913f5 100644
--- a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java
+++ b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java
@@ -96,6 +96,8 @@ import java.lang.annotation.RetentionPolicy;
   PartnerConfigKey.KEY_ACCOUNT_NAME_FONT_FAMILY,
   PartnerConfigKey.KEY_ACCOUNT_AVATAR_MARGIN_END,
   PartnerConfigKey.KEY_ACCOUNT_AVATAR_MAX_SIZE,
+  PartnerConfigKey.KEY_ACCOUNT_CONTAINER_MARGIN_TOP,
+  PartnerConfigKey.KEY_ACCOUNT_CONTAINER_MARGIN_BOTTOM,
   PartnerConfigKey.KEY_CONTENT_TEXT_SIZE,
   PartnerConfigKey.KEY_CONTENT_TEXT_COLOR,
   PartnerConfigKey.KEY_CONTENT_LINK_TEXT_COLOR,
@@ -121,6 +123,7 @@ import java.lang.annotation.RetentionPolicy;
   PartnerConfigKey.KEY_ITEMS_GROUP_CORNER_RADIUS,
   PartnerConfigKey.KEY_ITEMS_MIN_HEIGHT,
   PartnerConfigKey.KEY_ITEMS_DIVIDER_SHOWN,
+  PartnerConfigKey.KEY_ITEMS_TITLE_FONT_VARIATION_SETTINGS,
   PartnerConfigKey.KEY_PROGRESS_ILLUSTRATION_DEFAULT,
   PartnerConfigKey.KEY_PROGRESS_ILLUSTRATION_ACCOUNT,
   PartnerConfigKey.KEY_PROGRESS_ILLUSTRATION_CONNECTION,
@@ -380,6 +383,12 @@ public @interface PartnerConfigKey {
   // Size of the account avatar
   String KEY_ACCOUNT_AVATAR_MAX_SIZE = "setup_design_account_avatar_size";
 
+  // Margin top of the account container
+  String KEY_ACCOUNT_CONTAINER_MARGIN_TOP = "setup_design_account_container_margin_top";
+
+  // Margin bottom of the account container
+  String KEY_ACCOUNT_CONTAINER_MARGIN_BOTTOM = "setup_design_account_container_margin_bottom";
+
   // Text size of the body content text
   String KEY_CONTENT_TEXT_SIZE = "setup_design_content_text_size";
 
@@ -449,6 +458,10 @@ public @interface PartnerConfigKey {
   // The divider of list items are showing.
   String KEY_ITEMS_DIVIDER_SHOWN = "setup_design_items_divider_shown";
 
+  // Font weight of the header
+  String KEY_ITEMS_TITLE_FONT_VARIATION_SETTINGS =
+      "setup_design_items_title_font_variation_settings";
+
   // The intrinsic width of the card view for foldable/tablet.
   String KEY_CARD_VIEW_INTRINSIC_WIDTH = "setup_design_card_view_intrinsic_width";
 
```

