```diff
diff --git a/OWNERS b/OWNERS
index 42973a3..2aa88eb 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/external/setupdesign:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/exempting_lint_checks.txt b/exempting_lint_checks.txt
index 3932c96..db494cb 100644
--- a/exempting_lint_checks.txt
+++ b/exempting_lint_checks.txt
@@ -58,3 +58,31 @@ third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setup
 third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/ForceTwoPaneHelper.java: NewApi: int widthInDp = (int) (windowMetrics.getBounds().width() / windowMetrics.getDensity());
 third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/SystemBarHelper.java: AnnotateVersionCheck: public static void setImeInsetView(final View view) {
 third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/AndroidManifest.xml: ExpiringTargetSdkVersion: <uses-sdk android:minSdkVersion="14" android:targetSdkVersion="31" />
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java: CustomViewStyleable: attrs, R.styleable.SucPartnerCustomizationLayout, defStyleAttr, 0);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/internal/PersistableBundles.java: UseRequiresApi: @TargetApi(VERSION_CODES.LOLLIPOP_MR1)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/internal/TemplateLayout.java: CustomViewStyleable: getContext().obtainStyledAttributes(attrs, R.styleable.SucTemplateLayout, defStyleAttr, 0);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/internal/TemplateLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/internal/TemplateLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/logging/CustomEvent.java: ObsoleteSdkInt: Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/logging/CustomEvent.java: UseRequiresApi: @TargetApi(VERSION_CODES.Q)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/logging/SetupMetric.java: UseRequiresApi: @TargetApi(VERSION_CODES.Q)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/logging/internal/FooterBarMixinMetrics.java: UseRequiresApi: @TargetApi(VERSION_CODES.Q)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/logging/internal/MetricBundleConverter.java: NewApi: bundle.putParcelable(MetricBundleKeys.CUSTOM_EVENT_BUNDLE, CustomEvent.toBundle(customEvent));
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterBarMixin.java: NewApi: onFooterButtonApplyPartnerResource(button, footerButtonPartnerConfig);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterBarMixin.java: UseRequiresApi: @TargetApi(VERSION_CODES.Q)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButton.java: UseRequiresApi: @TargetApi(VERSION_CODES.Q)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: NewApi: FooterButtonStyleUtils.updateButtonBackgroundWithPartnerConfig(
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: NewApi: FooterButtonStyleUtils.updateButtonRippleColorWithPartnerConfig(
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: ObsoleteSdkInt: Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: ObsoleteSdkInt: if (Build.VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP) {
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: UseRequiresApi: @TargetApi(VERSION_CODES.Q)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/ForceTwoPaneHelper.java: NewApi: WindowManager windowManager = context.getSystemService(WindowManager.class);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/ForceTwoPaneHelper.java: NewApi: WindowMetrics windowMetrics = windowManager.getCurrentWindowMetrics();
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/ForceTwoPaneHelper.java: NewApi: if (windowMetrics.getBounds().width() > windowMetrics.getBounds().height()) {
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/ForceTwoPaneHelper.java: NewApi: int widthInDp = (int) (windowMetrics.getBounds().width() / windowMetrics.getDensity());
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/SystemBarHelper.java: AnnotateVersionCheck: public static void setImeInsetView(final View view) {
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/SystemBarHelper.java: UseRequiresApi: @TargetApi(VERSION_CODES.LOLLIPOP)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java: UseRequiresApi: @TargetApi(VERSION_CODES.HONEYCOMB)
diff --git a/main/aidl/com/google/android/setupcompat/portal/ISetupNotificationService.aidl b/main/aidl/com/google/android/setupcompat/portal/ISetupNotificationService.aidl
index 9f9b1d8..6a060d9 100644
--- a/main/aidl/com/google/android/setupcompat/portal/ISetupNotificationService.aidl
+++ b/main/aidl/com/google/android/setupcompat/portal/ISetupNotificationService.aidl
@@ -37,4 +37,7 @@ interface ISetupNotificationService {
 
   /** Checks portal avaailable or not. */
   boolean isPortalAvailable() = 4;
+
+  /** Whether the portal is ready to register progress service or not. */
+  boolean isPortalReady() = 5;
 }
\ No newline at end of file
diff --git a/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java b/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java
index 055d07b..6a4f732 100644
--- a/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java
+++ b/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java
@@ -23,12 +23,18 @@ import android.os.Build;
 import android.os.Build.VERSION;
 import android.os.Build.VERSION_CODES;
 import android.os.PersistableBundle;
+import androidx.fragment.app.Fragment;
+import androidx.fragment.app.FragmentActivity;
+import androidx.fragment.app.FragmentManager;
+import androidx.fragment.app.FragmentManager.FragmentLifecycleCallbacks;
 import android.util.AttributeSet;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.ViewTreeObserver;
+import android.view.WindowInsets;
 import android.view.WindowManager;
+import android.widget.LinearLayout;
 import androidx.annotation.VisibleForTesting;
 import com.google.android.setupcompat.internal.FocusChangedMetricHelper;
 import com.google.android.setupcompat.internal.LifecycleFragment;
@@ -40,6 +46,7 @@ import com.google.android.setupcompat.logging.LoggingObserver;
 import com.google.android.setupcompat.logging.LoggingObserver.SetupCompatUiEvent.LayoutInflatedEvent;
 import com.google.android.setupcompat.logging.MetricKey;
 import com.google.android.setupcompat.logging.SetupMetricsLogger;
+import com.google.android.setupcompat.partnerconfig.PartnerConfig;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.template.FooterBarMixin;
 import com.google.android.setupcompat.template.FooterButton;
@@ -49,6 +56,7 @@ import com.google.android.setupcompat.util.BuildCompatUtils;
 import com.google.android.setupcompat.util.Logger;
 import com.google.android.setupcompat.util.WizardManagerHelper;
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
+import org.jspecify.annotations.NonNull;
 
 /** A templatization layout with consistent style used in Setup Wizard or app itself. */
 public class PartnerCustomizationLayout extends TemplateLayout {
@@ -74,10 +82,14 @@ public class PartnerCustomizationLayout extends TemplateLayout {
    */
   private boolean useDynamicColor;
 
-  private Activity activity;
+  protected Activity activity;
 
   private PersistableBundle layoutTypeBundle;
 
+  @VisibleForTesting FragmentLifecycleCallbacks fragmentLifecycleCallbacks;
+
+  private int footerBarPaddingBottom;
+
   @CanIgnoreReturnValue
   public PartnerCustomizationLayout(Context context) {
     this(context, 0, 0);
@@ -125,6 +137,18 @@ public class PartnerCustomizationLayout extends TemplateLayout {
 
     a.recycle();
 
+    // Get the footer bar default padding bottom value.
+    TypedArray footerBarMixinAttrs =
+        getContext().obtainStyledAttributes(attrs, R.styleable.SucFooterBarMixin, defStyleAttr, 0);
+    int defaultPadding =
+        footerBarMixinAttrs.getDimensionPixelSize(
+            R.styleable.SucFooterBarMixin_sucFooterBarPaddingVertical, 0);
+    footerBarPaddingBottom =
+        footerBarMixinAttrs.getDimensionPixelSize(
+            R.styleable.SucFooterBarMixin_sucFooterBarPaddingBottom, defaultPadding);
+
+    footerBarMixinAttrs.recycle();
+
     if (VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP && layoutFullscreen) {
       setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN);
     }
@@ -169,6 +193,13 @@ public class PartnerCustomizationLayout extends TemplateLayout {
 
     activity = lookupActivityFromContext(getContext());
 
+    LOG.atDebug(
+        "Flag of isEnhancedSetupDesignMetricsEnabled="
+            + PartnerConfigHelper.isEnhancedSetupDesignMetricsEnabled(getContext()));
+    if (PartnerConfigHelper.isEnhancedSetupDesignMetricsEnabled(getContext())) {
+      tryRegisterFragmentCallbacks(activity);
+    }
+
     boolean isSetupFlow = WizardManagerHelper.isAnySetupWizard(activity.getIntent());
 
     TypedArray a =
@@ -206,6 +237,28 @@ public class PartnerCustomizationLayout extends TemplateLayout {
             + useFullDynamicColorAttr);
   }
 
+  private void printFragmentInfoAtDebug(Fragment fragment, String tag) {
+    if (fragment == null) {
+      return;
+    }
+    int fragmentId = fragment.getId();
+    String fragmentName = tryGetResourceEntryName(fragmentId);
+    LOG.atDebug(
+        tag
+            + " fragment name="
+            + fragment.getClass().getSimpleName()
+            + ", tag="
+            + fragment.getTag()
+            + ", id="
+            + fragment.getId()
+            + ", name="
+            + fragmentName);
+  }
+
+  private String tryGetResourceEntryName(int fragmentId) {
+    return (fragmentId == 0) ? "" : getResources().getResourceEntryName(fragmentId);
+  }
+
   @Override
   protected ViewGroup findContainer(int containerId) {
     if (containerId == 0) {
@@ -217,7 +270,14 @@ public class PartnerCustomizationLayout extends TemplateLayout {
   @Override
   protected void onAttachedToWindow() {
     super.onAttachedToWindow();
-    LifecycleFragment.attachNow(activity);
+    LifecycleFragment lifecycleFragment =
+        LifecycleFragment.attachNow(activity, this::logFooterButtonMetrics);
+    if (lifecycleFragment == null) {
+      LOG.atDebug(
+          "Unable to attach lifecycle fragment to the host activity. Activity="
+              + ((activity != null) ? activity.getClass().getSimpleName() : "null"));
+    }
+
     if (WizardManagerHelper.isAnySetupWizard(activity.getIntent())) {
       getViewTreeObserver().addOnWindowFocusChangeListener(windowFocusChangeListener);
     }
@@ -257,6 +317,79 @@ public class PartnerCustomizationLayout extends TemplateLayout {
           CustomEvent.create(MetricKey.get("SetupCompatMetrics", activity), persistableBundle));
     }
     getViewTreeObserver().removeOnWindowFocusChangeListener(windowFocusChangeListener);
+
+    if (PartnerConfigHelper.isEnhancedSetupDesignMetricsEnabled(getContext())) {
+      tryUnregisterFragmentCallbacks(activity);
+    }
+  }
+
+  private void logFooterButtonMetrics(PersistableBundle bundle) {
+    if (VERSION.SDK_INT >= Build.VERSION_CODES.Q
+        && activity != null
+        && WizardManagerHelper.isAnySetupWizard(activity.getIntent())
+        && PartnerConfigHelper.isEnhancedSetupDesignMetricsEnabled(getContext())) {
+      FooterBarMixin footerBarMixin = getMixin(FooterBarMixin.class);
+
+      if (footerBarMixin == null
+          || (footerBarMixin.getPrimaryButton() == null
+              && footerBarMixin.getSecondaryButton() == null)) {
+        LOG.atDebug("Skip footer button logging because no footer buttons.");
+        return;
+      }
+
+      footerBarMixin.onDetachedFromWindow();
+      FooterButton primaryButton = footerBarMixin.getPrimaryButton();
+      FooterButton secondaryButton = footerBarMixin.getSecondaryButton();
+      PersistableBundle primaryButtonMetrics =
+          primaryButton != null
+              ? primaryButton.getMetrics("PrimaryFooterButton")
+              : PersistableBundle.EMPTY;
+      PersistableBundle secondaryButtonMetrics =
+          secondaryButton != null
+              ? secondaryButton.getMetrics("SecondaryFooterButton")
+              : PersistableBundle.EMPTY;
+
+      PersistableBundle persistableBundle =
+          PersistableBundles.mergeBundles(
+              footerBarMixin.getLoggingMetrics(),
+              primaryButtonMetrics,
+              secondaryButtonMetrics,
+              bundle);
+
+      SetupMetricsLogger.logCustomEvent(
+          getContext(),
+          CustomEvent.create(MetricKey.get("FooterButtonMetrics", activity), persistableBundle));
+    }
+  }
+
+  private void tryRegisterFragmentCallbacks(Activity activity) {
+    if ((activity instanceof FragmentActivity fragmentActivity)) {
+      fragmentLifecycleCallbacks =
+          new FragmentLifecycleCallbacks() {
+            @Override
+            public void onFragmentAttached(
+                @NonNull FragmentManager fm, @NonNull Fragment f, @NonNull Context context) {
+              printFragmentInfoAtDebug(f, "onFragmentAttached");
+              getMixin(FooterBarMixin.class).setFragmentInfo(f);
+              super.onFragmentAttached(fm, f, context);
+            }
+          };
+
+      fragmentActivity
+          .getSupportFragmentManager()
+          .registerFragmentLifecycleCallbacks(fragmentLifecycleCallbacks, true);
+      LOG.atDebug(
+          "Register the onFragmentAttached lifecycle callbacks to "
+              + activity.getClass().getSimpleName());
+    }
+  }
+
+  private void tryUnregisterFragmentCallbacks(Activity activity) {
+    if ((activity instanceof FragmentActivity fragmentActivity)) {
+      fragmentActivity
+          .getSupportFragmentManager()
+          .unregisterFragmentLifecycleCallbacks(fragmentLifecycleCallbacks);
+    }
   }
 
   /**
@@ -359,4 +492,35 @@ public class PartnerCustomizationLayout extends TemplateLayout {
             FocusChangedMetricHelper.getExtraBundle(
                 activity, PartnerCustomizationLayout.this, hasFocus));
   }
+
+  @Override
+  public WindowInsets onApplyWindowInsets(WindowInsets insets) {
+    // TODO: b/398407478 - Add test case for edge to edge to layout from library.
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
+      // Edge to edge extend the footer bar padding bottom to the navigation bar height.
+      if (VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP && insets.getSystemWindowInsetBottom() > 0) {
+        LOG.atDebug("NavigationBarHeight: " + insets.getSystemWindowInsetBottom());
+        FooterBarMixin footerBarMixin = getMixin(FooterBarMixin.class);
+        LinearLayout buttonContainer = footerBarMixin.getButtonContainer();
+        if (footerBarMixin != null && footerBarMixin.getButtonContainer() != null) {
+          if (PartnerConfigHelper.get(getContext())
+              .isPartnerConfigAvailable(PartnerConfig.CONFIG_FOOTER_BUTTON_PADDING_BOTTOM)) {
+            footerBarPaddingBottom =
+                (int)
+                    PartnerConfigHelper.get(getContext())
+                        .getDimension(
+                            getContext(), PartnerConfig.CONFIG_FOOTER_BUTTON_PADDING_BOTTOM);
+          }
+          // Adjust footer bar padding to account for the navigation bar, ensuring
+          // it extends to the bottom of the screen and with proper bottom padding.
+          buttonContainer.setPadding(
+              buttonContainer.getPaddingLeft(),
+              buttonContainer.getPaddingTop(),
+              buttonContainer.getPaddingRight(),
+              footerBarPaddingBottom + insets.getSystemWindowInsetBottom());
+        }
+      }
+    }
+    return super.onApplyWindowInsets(insets);
+  }
 }
diff --git a/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java b/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java
index 733ee52..6027d29 100644
--- a/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java
+++ b/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java
@@ -25,21 +25,43 @@ import android.content.Context;
 import android.os.Build.VERSION;
 import android.os.Build.VERSION_CODES;
 import android.os.PersistableBundle;
+import androidx.annotation.Nullable;
 import android.util.Log;
 import com.google.android.setupcompat.logging.CustomEvent;
 import com.google.android.setupcompat.logging.MetricKey;
 import com.google.android.setupcompat.logging.SetupMetricsLogger;
+import com.google.android.setupcompat.util.Logger;
 import com.google.android.setupcompat.util.WizardManagerHelper;
 
 /** Fragment used to detect lifecycle of an activity for metrics logging. */
 public class LifecycleFragment extends Fragment {
   private static final String LOG_TAG = LifecycleFragment.class.getSimpleName();
+  private static final Logger LOG = new Logger(LOG_TAG);
   private static final String FRAGMENT_ID = "lifecycle_monitor";
 
   private MetricKey metricKey;
   private long startInNanos;
   private long durationInNanos = 0;
 
+  private OnFragmentLifecycleChangeListener lifecycleChangeListener;
+
+  /** Interface for listening to lifecycle changes of the fragment. */
+  public interface OnFragmentLifecycleChangeListener {
+    void onStop(PersistableBundle bundle);
+  }
+
+  /**
+   * Registers a callback to be invoked when lifecycle of the fragment changed.
+   *
+   * @param listener The callback that will run
+   */
+  public void setOnFragmentLifecycleChangeListener(
+      @Nullable OnFragmentLifecycleChangeListener listener) {
+    if (listener != null) {
+      lifecycleChangeListener = listener;
+    }
+  }
+
   public LifecycleFragment() {
     setRetainInstance(true);
   }
@@ -48,9 +70,11 @@ public class LifecycleFragment extends Fragment {
    * Attaches the lifecycle fragment if it is not attached yet.
    *
    * @param activity the activity to detect lifecycle for.
+   * @param listener the callback method when lifecycle changed.
    * @return fragment to monitor life cycle.
    */
-  public static LifecycleFragment attachNow(Activity activity) {
+  public static LifecycleFragment attachNow(
+      Activity activity, OnFragmentLifecycleChangeListener listener) {
     if (WizardManagerHelper.isAnySetupWizard(activity.getIntent())) {
 
       if (VERSION.SDK_INT > VERSION_CODES.M) {
@@ -59,38 +83,54 @@ public class LifecycleFragment extends Fragment {
           Fragment fragment = fragmentManager.findFragmentByTag(FRAGMENT_ID);
           if (fragment == null) {
             LifecycleFragment lifeCycleFragment = new LifecycleFragment();
+            if (listener != null) {
+              lifeCycleFragment.setOnFragmentLifecycleChangeListener(listener);
+            }
             try {
               fragmentManager.beginTransaction().add(lifeCycleFragment, FRAGMENT_ID).commitNow();
               fragment = lifeCycleFragment;
             } catch (IllegalStateException e) {
-              Log.e(
-                  LOG_TAG,
-                  "Error occurred when attach to Activity:" + activity.getComponentName(),
-                  e);
+              LOG.e("Error occurred when attach to Activity:" + activity.getComponentName(), e);
             }
           } else if (!(fragment instanceof LifecycleFragment)) {
             Log.wtf(
                 LOG_TAG,
                 activity.getClass().getSimpleName() + " Incorrect instance on lifecycle fragment.");
             return null;
+          } else {
+            LOG.atDebug(
+                "Find an existing fragment that belongs to " + activity.getClass().getSimpleName());
           }
           return (LifecycleFragment) fragment;
         }
       }
     }
-
+    LOG.atDebug(
+        "Skip attach " + activity.getClass().getSimpleName() + " because it's not in SUW flow.");
     return null;
   }
 
+  /**
+   * Attaches the lifecycle fragment if it is not attached yet.
+   *
+   * @param activity the activity to detect lifecycle for.
+   * @return fragment to monitor life cycle.
+   */
+  public static LifecycleFragment attachNow(Activity activity) {
+    return attachNow(activity, null);
+  }
+
   @Override
   public void onAttach(Context context) {
     super.onAttach(context);
+    LOG.atDebug("onAttach host=" + getActivity().getClass().getSimpleName());
     metricKey = MetricKey.get("ScreenDuration", getActivity());
   }
 
   @Override
   public void onDetach() {
     super.onDetach();
+    LOG.atDebug("onDetach host=" + getActivity().getClass().getSimpleName());
     SetupMetricsLogger.logDuration(getActivity(), metricKey, NANOSECONDS.toMillis(durationInNanos));
   }
 
@@ -98,15 +138,37 @@ public class LifecycleFragment extends Fragment {
   public void onResume() {
     super.onResume();
     startInNanos = ClockProvider.timeInNanos();
+    LOG.atDebug(
+        "onResume host="
+            + getActivity().getClass().getSimpleName()
+            + ", startInNanos="
+            + startInNanos);
     logScreenResume();
   }
 
   @Override
   public void onPause() {
     super.onPause();
+    LOG.atDebug("onPause host=" + getActivity().getClass().getSimpleName());
     durationInNanos += (ClockProvider.timeInNanos() - startInNanos);
   }
 
+  @Override
+  public void onStop() {
+    super.onStop();
+    long onStopTimestamp = System.nanoTime();
+    LOG.atDebug(
+        "onStop host="
+            + getActivity().getClass().getSimpleName()
+            + ", onStopTimestamp="
+            + onStopTimestamp);
+    if (VERSION.SDK_INT >= VERSION_CODES.Q && lifecycleChangeListener != null) {
+      PersistableBundle bundle = new PersistableBundle();
+      bundle.putLong("onScreenStop", onStopTimestamp);
+      lifecycleChangeListener.onStop(bundle);
+    }
+  }
+
   private void logScreenResume() {
     if (VERSION.SDK_INT >= VERSION_CODES.Q) {
       PersistableBundle bundle = new PersistableBundle();
diff --git a/main/java/com/google/android/setupcompat/logging/CustomEvent.java b/main/java/com/google/android/setupcompat/logging/CustomEvent.java
index 38c32fa..be8e52a 100644
--- a/main/java/com/google/android/setupcompat/logging/CustomEvent.java
+++ b/main/java/com/google/android/setupcompat/logging/CustomEvent.java
@@ -215,6 +215,6 @@ public final class CustomEvent implements Parcelable {
     }
   }
 
-  @VisibleForTesting static final int MAX_STR_LENGTH = 50;
+  @VisibleForTesting public static final int MAX_STR_LENGTH = 50;
   @VisibleForTesting static final int MIN_BUNDLE_KEY_LENGTH = 3;
 }
diff --git a/main/java/com/google/android/setupcompat/logging/internal/FooterBarMixinMetrics.java b/main/java/com/google/android/setupcompat/logging/internal/FooterBarMixinMetrics.java
index 007aff9..62eab22 100644
--- a/main/java/com/google/android/setupcompat/logging/internal/FooterBarMixinMetrics.java
+++ b/main/java/com/google/android/setupcompat/logging/internal/FooterBarMixinMetrics.java
@@ -23,10 +23,13 @@ import android.os.Build.VERSION_CODES;
 import android.os.PersistableBundle;
 import androidx.annotation.StringDef;
 import androidx.annotation.VisibleForTesting;
+import com.google.android.setupcompat.util.Logger;
 import java.lang.annotation.Retention;
 
 /** Uses to log internal event footer button metric */
 public class FooterBarMixinMetrics {
+  private static final Logger LOG = new Logger("FooterBarMixinMetrics");
+
   @VisibleForTesting
   public static final String EXTRA_PRIMARY_BUTTON_VISIBILITY = "PrimaryButtonVisibility";
 
@@ -54,7 +57,8 @@ public class FooterBarMixinMetrics {
     String INVISIBLE = "Invisible";
   }
 
-  @FooterButtonVisibility String primaryButtonVisibility = FooterButtonVisibility.UNKNOWN;
+  @VisibleForTesting @FooterButtonVisibility
+  public String primaryButtonVisibility = FooterButtonVisibility.UNKNOWN;
 
   @FooterButtonVisibility String secondaryButtonVisibility = FooterButtonVisibility.UNKNOWN;
 
@@ -107,7 +111,7 @@ public class FooterBarMixinMetrics {
     if (!FooterButtonVisibility.VISIBLE_USING_XML.equals(originalVisibility)
         && !FooterButtonVisibility.VISIBLE.equals(originalVisibility)
         && !FooterButtonVisibility.INVISIBLE.equals(originalVisibility)) {
-      throw new IllegalStateException("Illegal visibility state: " + originalVisibility);
+      LOG.w("Illegal visibility state: " + originalVisibility);
     }
 
     if (isVisible && FooterButtonVisibility.INVISIBLE.equals(originalVisibility)) {
diff --git a/main/java/com/google/android/setupcompat/portal/PortalHelper.java b/main/java/com/google/android/setupcompat/portal/PortalHelper.java
index 4d1965a..8dd5625 100644
--- a/main/java/com/google/android/setupcompat/portal/PortalHelper.java
+++ b/main/java/com/google/android/setupcompat/portal/PortalHelper.java
@@ -141,6 +141,12 @@ public class PortalHelper {
     }
   }
 
+  /**
+   * Returns true when the SetupWizard Portal is enabled.
+   *
+   * @param context A context instance.
+   * @param listener Result listener.
+   */
   public static void isPortalAvailable(
       @NonNull Context context, @NonNull final PortalAvailableResultListener listener) {
     ServiceConnection connection =
@@ -173,6 +179,51 @@ public class PortalHelper {
     }
   }
 
+  /**
+   * Returns true when the portal is ready to register progress service.
+   *
+   * @param context A context instance.
+   * @param listener The listener for the result.
+   */
+  public static void isPortalReady(
+      @NonNull Context context, @NonNull final PortalReadyToRegisterResultListener listener) {
+    ServiceConnection connection =
+        new ServiceConnection() {
+          @Override
+          public void onServiceConnected(ComponentName name, IBinder binder) {
+            if (binder != null) {
+              ISetupNotificationService service =
+                  ISetupNotificationService.Stub.asInterface(binder);
+
+              try {
+                listener.onResult(service.isPortalReady());
+              } catch (RemoteException e) {
+                LOG.e("Failed to invoke SetupNotificationService#isPortalAvailable");
+                listener.onResult(false);
+              }
+            }
+            context.unbindService(this);
+          }
+
+          @Override
+          public void onServiceDisconnected(ComponentName name) {}
+        };
+
+    if (!bindSetupNotificationService(context, connection)) {
+      LOG.e(
+          "Failed to bind SetupNotificationService. Do you have permission"
+              + " \"com.google.android.setupwizard.SETUP_PROGRESS_SERVICE\"");
+      listener.onResult(false);
+    }
+  }
+
+  /**
+   * To query is the ProgressService already register in the portal or not.
+   *
+   * @param context A context instance.
+   * @param component The component of the progress service.
+   * @param listener The result listener.
+   */
   public static void isProgressServiceAlive(
       @NonNull final Context context,
       @NonNull final ProgressServiceComponent component,
@@ -260,20 +311,31 @@ public class PortalHelper {
     void onFailure(Throwable throwable);
   }
 
+  /** A callback for accepting the results of SetupNotificationService. */
   public interface RegisterNotificationCallback {
     void onSuccess();
 
     void onFailure(Throwable throwable);
   }
 
+  /** The listener interface that is used to notify the caller for the result of {@link PortalHelper#isPortalAvailable(Context, PortalAvailableResultListener)}.  */
+
   public interface ProgressServiceAliveResultListener {
     void onResult(boolean isAlive);
   }
 
+  /** The listener interface that is used to notify the caller for the result of {@link PortalHelper#isPortalAvailable(Context, PortalAvailableResultListener)}. */
+
   public interface PortalAvailableResultListener {
     void onResult(boolean isAvailable);
   }
 
+  /** The listener interface that is used to notify the caller for the result of {@link PortalHelper#isPortalReady(Context, PortalReadyToRegisterResultListener)}. */
+  public interface PortalReadyToRegisterResultListener {
+    void onResult(boolean isReady);
+  }
+
+  /** A data class that set the remaining size and convert to {@link android.os.Bundle}. */
   public static class RemainingValueBuilder {
     private final Bundle bundle = new Bundle();
 
diff --git a/main/java/com/google/android/setupcompat/template/FooterBarMixin.java b/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
index 7d72cf2..7aa9cd4 100644
--- a/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
+++ b/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
@@ -25,22 +25,19 @@ import android.content.Context;
 import android.content.res.Configuration;
 import android.content.res.TypedArray;
 import android.graphics.Color;
+import android.graphics.Paint;
 import android.graphics.drawable.GradientDrawable;
+import android.os.Build.VERSION;
 import android.os.Build.VERSION_CODES;
 import android.os.PersistableBundle;
-import android.text.Layout.Alignment;
-import android.text.StaticLayout;
-import android.text.TextPaint;
+import androidx.fragment.app.Fragment;
 import android.util.AttributeSet;
-import android.util.DisplayMetrics;
 import android.view.ContextThemeWrapper;
 import android.view.Gravity;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.ViewStub;
-import android.view.ViewTreeObserver;
-import android.view.ViewTreeObserver.OnGlobalLayoutListener;
 import android.widget.Button;
 import android.widget.LinearLayout;
 import android.widget.LinearLayout.LayoutParams;
@@ -59,6 +56,7 @@ import com.google.android.setupcompat.PartnerCustomizationLayout;
 import com.google.android.setupcompat.R;
 import com.google.android.setupcompat.internal.FooterButtonPartnerConfig;
 import com.google.android.setupcompat.internal.TemplateLayout;
+import com.google.android.setupcompat.logging.CustomEvent;
 import com.google.android.setupcompat.logging.LoggingObserver;
 import com.google.android.setupcompat.logging.LoggingObserver.SetupCompatUiEvent.ButtonInflatedEvent;
 import com.google.android.setupcompat.logging.internal.FooterBarMixinMetrics;
@@ -91,11 +89,14 @@ public class FooterBarMixin implements Mixin {
   @VisibleForTesting public LinearLayout buttonContainer;
   private FooterButton primaryButton;
   private FooterButton secondaryButton;
+  private FooterButton tertiaryButton;
   private LoggingObserver loggingObserver;
   @IdRes private int primaryButtonId;
   @IdRes private int secondaryButtonId;
+  @IdRes private int tertiaryButtonId;
   @VisibleForTesting public FooterButtonPartnerConfig primaryButtonPartnerConfigForTesting;
   @VisibleForTesting public FooterButtonPartnerConfig secondaryButtonPartnerConfigForTesting;
+  @VisibleForTesting public FooterButtonPartnerConfig tertiaryButtonPartnerConfigForTesting;
 
   private int footerBarPaddingTop;
   private int footerBarPaddingBottom;
@@ -110,6 +111,11 @@ public class FooterBarMixin implements Mixin {
   private final int footerBarSecondaryButtonEnabledTextColor;
   private final int footerBarPrimaryButtonDisabledTextColor;
   private final int footerBarSecondaryButtonDisabledTextColor;
+  private static final String KEY_HOST_FRAGMENT_NAME = "HostFragmentName";
+  private static final String KEY_HOST_FRAGMENT_TAG = "HostFragmentTag";
+  private String hostFragmentName;
+  private String hostFragmentTag;
+
   @VisibleForTesting final int footerBarButtonMiddleSpacing;
 
   @VisibleForTesting public final FooterBarMixinMetrics metrics = new FooterBarMixinMetrics();
@@ -127,7 +133,7 @@ public class FooterBarMixin implements Mixin {
 
             // TODO: b/364981299 - Use partner config to allow user to customize text color.
             if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
-              if (id == primaryButtonId) {
+              if (id == primaryButtonId || isSecondaryButtonInPrimaryStyle) {
                 updateTextColorForButton(
                     button,
                     enabled,
@@ -162,13 +168,24 @@ public class FooterBarMixin implements Mixin {
       public void onVisibilityChanged(int visibility) {
         if (buttonContainer != null) {
           Button button = buttonContainer.findViewById(id);
-          if (button != null) {
-            button.setVisibility(visibility);
-            autoSetButtonBarVisibility();
 
-            if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
-              setButtonWidthForExpressiveStyle(/* isDownButton= */ false);
-            }
+          if (button == null) {
+            LOG.atDebug("onVisibilityChanged: button is null, skiped.");
+            return;
+          }
+
+          if (button.getVisibility() == visibility) {
+            LOG.atDebug("onVisibilityChanged: button visibility is not changed, skiped.");
+            return;
+          }
+
+          button.setVisibility(visibility);
+          autoSetButtonBarVisibility();
+
+          if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+            // Re-layout the buttons when visibility changes, especially when tertiary button is
+            // enabled to avoid the button layout is not correct.
+            repopulateButtons();
           }
         }
       }
@@ -178,6 +195,9 @@ public class FooterBarMixin implements Mixin {
         if (buttonContainer != null) {
           Button button = buttonContainer.findViewById(id);
           if (button != null) {
+            if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+              setButtonWidthForExpressiveStyle();
+            }
             button.setText(text);
           }
         }
@@ -282,6 +302,13 @@ public class FooterBarMixin implements Mixin {
     }
   }
 
+  public void setFragmentInfo(@Nullable Fragment fragment) {
+    if (fragment != null) {
+      hostFragmentName = fragment.getClass().getSimpleName();
+      hostFragmentTag = fragment.getTag();
+    }
+  }
+
   public void setLoggingObserver(LoggingObserver observer) {
     loggingObserver = observer;
 
@@ -651,12 +678,21 @@ public class FooterBarMixin implements Mixin {
     // TODO: b/364981299 - Use partner config to allow user to customize text color.
     if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
       boolean enabled = secondaryButton.isEnabled();
-      updateTextColorForButton(
-          button,
-          enabled,
-          enabled
-              ? footerBarSecondaryButtonEnabledTextColor
-              : footerBarSecondaryButtonDisabledTextColor);
+      if (usePrimaryStyle) {
+        updateTextColorForButton(
+            button,
+            enabled,
+            enabled
+                ? footerBarPrimaryButtonEnabledTextColor
+                : footerBarPrimaryButtonDisabledTextColor);
+      } else {
+        updateTextColorForButton(
+            button,
+            enabled,
+            enabled
+                ? footerBarSecondaryButtonEnabledTextColor
+                : footerBarSecondaryButtonDisabledTextColor);
+      }
     }
     if (loggingObserver != null) {
       loggingObserver.log(new ButtonInflatedEvent(button, LoggingObserver.ButtonType.SECONDARY));
@@ -680,6 +716,125 @@ public class FooterBarMixin implements Mixin {
         });
   }
 
+  /**
+   * Sets tertiary button for footer. The button will use the primary button style by default.
+   *
+   * <p>NOTE: This method is only available when glif expressive is ENABLED and primary and
+   * secondary buttons are both VISIBLE.
+   *
+   * @param footerButton The {@link FooterButton} to set as the tertiary button.
+   */
+  @MainThread
+  public void setTertiaryButton(FooterButton footerButton) {
+    setTertiaryButton(footerButton, /* usePrimaryStyle= */ true);
+  }
+
+  /**
+   * Sets tertiary button for footer. Allow to use the primary or secondary button style.
+   *
+   * <p>NOTE: This method is only available when glif expressive is ENABLED and primary and
+   * secondary buttons are both VISIBLE.
+   *
+   * @param footerButton The {@link FooterButton} to set as the tertiary button.
+   * @param usePrimaryStyle Whether to use the primary or secondary button style.
+   */
+  @MainThread
+  public void setTertiaryButton(FooterButton footerButton, boolean usePrimaryStyle) {
+    if (!PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      LOG.atDebug("Cannot set tertiary button when glif expressive is not enabled.");
+      return;
+    }
+
+    ensureOnMainThread("setTertiaryButton");
+    ensureFooterInflated();
+
+    // Setup button partner config
+    FooterButtonPartnerConfig footerButtonPartnerConfig =
+        new FooterButtonPartnerConfig.Builder(footerButton)
+            .setPartnerTheme(
+                getPartnerTheme(
+                    footerButton,
+                    /* defaultPartnerTheme= */ R.style.SucGlifMaterialButton_Primary,
+                    /* buttonBackgroundColorConfig= */ usePrimaryStyle
+                        ? PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_BG_COLOR
+                        : PartnerConfig.CONFIG_FOOTER_SECONDARY_BUTTON_BG_COLOR))
+            .setButtonBackgroundConfig(
+                usePrimaryStyle
+                    ? PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_BG_COLOR
+                    : PartnerConfig.CONFIG_FOOTER_SECONDARY_BUTTON_BG_COLOR)
+            .setButtonDisableAlphaConfig(PartnerConfig.CONFIG_FOOTER_BUTTON_DISABLED_ALPHA)
+            .setButtonDisableBackgroundConfig(PartnerConfig.CONFIG_FOOTER_BUTTON_DISABLED_BG_COLOR)
+            .setButtonDisableTextColorConfig(
+                usePrimaryStyle
+                    ? PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_DISABLED_TEXT_COLOR
+                    : PartnerConfig.CONFIG_FOOTER_SECONDARY_BUTTON_DISABLED_TEXT_COLOR)
+            .setButtonIconConfig(getDrawablePartnerConfig(footerButton.getButtonType()))
+            .setButtonRadiusConfig(PartnerConfig.CONFIG_FOOTER_BUTTON_RADIUS)
+            .setButtonRippleColorAlphaConfig(PartnerConfig.CONFIG_FOOTER_BUTTON_RIPPLE_COLOR_ALPHA)
+            .setTextColorConfig(
+                usePrimaryStyle
+                    ? PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_TEXT_COLOR
+                    : PartnerConfig.CONFIG_FOOTER_SECONDARY_BUTTON_TEXT_COLOR)
+            .setMarginStartConfig(PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_MARGIN_START)
+            .setTextSizeConfig(PartnerConfig.CONFIG_FOOTER_BUTTON_TEXT_SIZE)
+            .setButtonMinHeight(PartnerConfig.CONFIG_FOOTER_BUTTON_MIN_HEIGHT)
+            .setTextTypeFaceConfig(PartnerConfig.CONFIG_FOOTER_BUTTON_FONT_FAMILY)
+            .setTextWeightConfig(PartnerConfig.CONFIG_FOOTER_BUTTON_FONT_WEIGHT)
+            .setTextStyleConfig(PartnerConfig.CONFIG_FOOTER_BUTTON_TEXT_STYLE)
+            .build();
+
+    IFooterActionButton buttonImpl = inflateButton(footerButton, footerButtonPartnerConfig);
+    // Update information for tertiary button. Need to update as long as the button inflated.
+    Button button = (Button) buttonImpl;
+    tertiaryButtonId = button.getId();
+    if (buttonImpl instanceof MaterialFooterActionButton materialFooterActionButton) {
+      materialFooterActionButton.setPrimaryButtonStyle(usePrimaryStyle);
+    }
+    tertiaryButton = footerButton;
+    tertiaryButtonPartnerConfigForTesting = footerButtonPartnerConfig;
+    onFooterButtonInflated(button, footerBarPrimaryBackgroundColor);
+    onFooterButtonApplyPartnerResource(button, footerButtonPartnerConfig);
+
+    boolean enabled = tertiaryButton.isEnabled();
+    if (usePrimaryStyle) {
+      updateTextColorForButton(
+          button,
+          enabled,
+          enabled
+              ? footerBarPrimaryButtonEnabledTextColor
+              : footerBarPrimaryButtonDisabledTextColor);
+    } else {
+      updateTextColorForButton(
+          button,
+          enabled,
+          enabled
+              ? footerBarSecondaryButtonEnabledTextColor
+              : footerBarSecondaryButtonDisabledTextColor);
+    }
+
+    // Make sure the position of buttons are correctly and prevent tertiary button create twice or
+    // more.
+    repopulateButtons();
+
+    // The requestFocus() is only working after activity onResume.
+    button.post(
+        () -> {
+          if (KeyboardHelper.isKeyboardFocusEnhancementEnabled(context)
+              && KeyboardHelper.hasHardwareKeyboard(context)) {
+            button.requestFocus();
+          }
+        });
+  }
+
+  @Nullable
+  public Button getTertiaryButtonView() {
+    if (!PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      LOG.atDebug("Cannot get tertiary button when glif expressive is not enabled.");
+      return null;
+    }
+    return buttonContainer == null ? null : buttonContainer.findViewById(tertiaryButtonId);
+  }
+
   /**
    * Corrects the order of footer buttons after the button has been inflated to the view hierarchy.
    * Subclasses can implement this method to modify the order of footer buttons as necessary.
@@ -688,6 +843,7 @@ public class FooterBarMixin implements Mixin {
     LinearLayout buttonContainer = ensureFooterInflated();
     Button tempPrimaryButton = getPrimaryButtonView();
     Button tempSecondaryButton = getSecondaryButtonView();
+    Button tempTertiaryButton = getTertiaryButtonView();
     buttonContainer.removeAllViews();
 
     boolean isEvenlyWeightedButtons = isFooterButtonsEvenlyWeighted();
@@ -717,14 +873,22 @@ public class FooterBarMixin implements Mixin {
     if (!isFooterButtonAlignedEnd() && !PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
       addSpace();
     }
+
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context) && tempTertiaryButton != null) {
+      if (isBothButtons(tempPrimaryButton, tempSecondaryButton)) {
+        buttonContainer.addView(tempTertiaryButton);
+      } else {
+        LOG.atDebug("Cannot add tertiary button when primary or secondary button is null.");
+      }
+    }
+
     if (tempPrimaryButton != null) {
       buttonContainer.addView(tempPrimaryButton);
     }
 
     setEvenlyWeightedButtons(tempPrimaryButton, tempSecondaryButton, isEvenlyWeightedButtons);
-
     if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
-      setButtonWidthForExpressiveStyle(/* isDownButton= */ false);
+      setButtonWidthForExpressiveStyle();
     }
   }
 
@@ -764,138 +928,207 @@ public class FooterBarMixin implements Mixin {
 
   // TODO: b/369285240 - Migrate setButtonWidthForExpressiveStyle of FooterBarMixin to
   /** Sets button width for expressive style. */
-  public void setButtonWidthForExpressiveStyle(boolean isDownButton) {
-    final ViewTreeObserver.OnGlobalLayoutListener onGlobalLayoutListener =
-        new OnGlobalLayoutListener() {
-          @Override
-          public void onGlobalLayout() {
-            int initialLeftMargin = 0;
-            if (!isDownButton) {
-              Button primaryButton = getPrimaryButtonView();
-              Button secondaryButton = getSecondaryButtonView();
-              DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
-              int screenWidth = displayMetrics.widthPixels;
-              if (isTwoPaneLayout()) {
-                screenWidth = screenWidth / 2;
-                if (primaryButton != null) {
-                  // Set back the margin once down button scrolling to the bottom.
-                  LinearLayout.LayoutParams primaryLayoutParams =
-                      ((LayoutParams) primaryButton.getLayoutParams());
-                  if (primaryLayoutParams.leftMargin != initialLeftMargin) {
-                    primaryLayoutParams.leftMargin = initialLeftMargin;
-                    primaryButton.setLayoutParams(primaryLayoutParams);
-                  }
-                }
-                buttonContainer.setGravity(Gravity.END);
-              }
+  public void setButtonWidthForExpressiveStyle() {
+    buttonContainer.post(
+        () -> {
+          int containerWidth = buttonContainer.getMeasuredWidth();
+          Button primaryButton = getPrimaryButtonView();
+          Button secondaryButton = getSecondaryButtonView();
+          Button tertiaryButton = getTertiaryButtonView();
+          if (isTwoPaneLayout()) {
+            containerWidth = containerWidth / 2;
+            buttonContainer.setGravity(Gravity.END);
+          }
 
-              // TODO: b/364981820 - Use partner config to allow user to customize button width.
-              int availableFooterBarWidth =
-                  screenWidth
-                      - footerBarPaddingStart
-                      - footerBarPaddingEnd
-                      - footerBarButtonMiddleSpacing;
-              int maxButtonWidth = availableFooterBarWidth / 2;
-              if (isBothButtons(primaryButton, secondaryButton)) {
-                LayoutParams primaryLayoutParams = (LayoutParams) primaryButton.getLayoutParams();
-                LayoutParams secondaryLayoutParams =
-                    (LayoutParams) secondaryButton.getLayoutParams();
-
-                boolean isPrimaryTextTooLong = isTextTooLong(primaryButton, maxButtonWidth);
-                boolean isSecondaryTextTooLong = isTextTooLong(secondaryButton, maxButtonWidth);
-
-                if (isPrimaryTextTooLong || isSecondaryTextTooLong) {
-                  if (buttonContainer instanceof ButtonBarLayout) {
-                    ((ButtonBarLayout) buttonContainer).setStackedButtonForExpressiveStyle(true);
-                  }
-                  int stackButtonMiddleSpacing = footerBarButtonMiddleSpacing / 2;
-                  primaryLayoutParams.width = availableFooterBarWidth;
-                  primaryLayoutParams.bottomMargin = stackButtonMiddleSpacing;
-                  primaryButton.setLayoutParams(primaryLayoutParams);
-
-                  secondaryLayoutParams.width = availableFooterBarWidth;
-                  secondaryLayoutParams.topMargin = stackButtonMiddleSpacing;
-                  secondaryButton.setLayoutParams(secondaryLayoutParams);
-                } else {
-                  if (primaryLayoutParams != null) {
-                    primaryLayoutParams.width = maxButtonWidth;
-                    primaryLayoutParams.setMarginStart(footerBarButtonMiddleSpacing / 2);
-                    primaryButton.setLayoutParams(primaryLayoutParams);
-                  }
-                  if (secondaryLayoutParams != null) {
-                    secondaryLayoutParams.width = maxButtonWidth;
-                    secondaryLayoutParams.setMarginEnd(footerBarButtonMiddleSpacing / 2);
-                    secondaryButton.setLayoutParams(secondaryLayoutParams);
-                  }
-                }
-              } else if (isPrimaryButtonOnly(primaryButton, secondaryButton)) {
-                LayoutParams primaryLayoutParams = (LayoutParams) primaryButton.getLayoutParams();
-                if (primaryLayoutParams != null) {
-                  primaryLayoutParams.width = availableFooterBarWidth;
-                  primaryButton.setLayoutParams(primaryLayoutParams);
-                }
-              } else if (isSecondaryOnly(primaryButton, secondaryButton)) {
-                LayoutParams secondaryLayoutParams =
-                    (LayoutParams) secondaryButton.getLayoutParams();
-                if (secondaryLayoutParams != null) {
-                  secondaryLayoutParams.width = availableFooterBarWidth;
-                  secondaryButton.setLayoutParams(secondaryLayoutParams);
-                }
-              } else {
-                LOG.atInfo("There are no button visible in the footer bar.");
-              }
-            } else {
-              // Only allow primary button been shown on the screen if in the down button style.
-              if (getSecondaryButtonView() != null) {
-                getSecondaryButtonView().setVisibility(View.GONE);
+          // TODO: b/364981820 - Use partner config to allow user to customize button width.
+          int availableFooterBarWidth =
+              containerWidth
+                  - footerBarPaddingStart
+                  - footerBarPaddingEnd
+                  - footerBarButtonMiddleSpacing;
+          int maxButtonWidth = availableFooterBarWidth / 2;
+
+          if (isThreeButtons(primaryButton, secondaryButton, tertiaryButton)) {
+            forceStackButtonInThreeButtonMode(
+                primaryButton, secondaryButton, tertiaryButton, availableFooterBarWidth);
+          } else if (isBothButtons(primaryButton, secondaryButton)) {
+            LayoutParams primaryLayoutParams = (LayoutParams) primaryButton.getLayoutParams();
+            LayoutParams secondaryLayoutParams = (LayoutParams) secondaryButton.getLayoutParams();
+            boolean isButtonStacked =
+                stackButtonIfTextOverFlow(
+                    primaryButton, secondaryButton, maxButtonWidth, availableFooterBarWidth);
+
+            if (!isButtonStacked) {
+              if (primaryLayoutParams != null) {
+                primaryLayoutParams.width = maxButtonWidth;
+                primaryLayoutParams.setMarginStart(footerBarButtonMiddleSpacing / 2);
+                primaryButton.setLayoutParams(primaryLayoutParams);
               }
-              setDownButtonStyle(getPrimaryButtonView());
-              if (!isTwoPaneLayout()) {
-                buttonContainer.setGravity(Gravity.CENTER_HORIZONTAL | Gravity.CENTER_VERTICAL);
-              } else {
-                buttonContainer.setGravity(Gravity.CENTER_VERTICAL);
-                int containerWidth = buttonContainer.getWidth();
-                Button downButtonView = getPrimaryButtonView();
-                LayoutParams primaryLayoutParams = (LayoutParams) downButtonView.getLayoutParams();
-                int halfContainerWidth = containerWidth / 2;
-                // Put down button to the center of the one side in two pane mode.
-                primaryLayoutParams.setMarginStart(
-                    (halfContainerWidth
-                        + (halfContainerWidth / 2 - downButtonView.getWidth() / 2)));
-                downButtonView.setLayoutParams(primaryLayoutParams);
+              if (secondaryLayoutParams != null) {
+                secondaryLayoutParams.width = maxButtonWidth;
+                secondaryLayoutParams.setMarginEnd(footerBarButtonMiddleSpacing / 2);
+                secondaryButton.setLayoutParams(secondaryLayoutParams);
               }
             }
-            buttonContainer.getViewTreeObserver().removeOnGlobalLayoutListener(this);
+          } else if (isPrimaryButtonOnly(primaryButton, secondaryButton)) {
+            LayoutParams primaryLayoutParams = (LayoutParams) primaryButton.getLayoutParams();
+            if (primaryLayoutParams != null) {
+              primaryLayoutParams.width = availableFooterBarWidth;
+              primaryButton.setLayoutParams(primaryLayoutParams);
+            }
+          } else if (isSecondaryOnly(primaryButton, secondaryButton)) {
+            LayoutParams secondaryLayoutParams = (LayoutParams) secondaryButton.getLayoutParams();
+            if (secondaryLayoutParams != null) {
+              secondaryLayoutParams.width = availableFooterBarWidth;
+              secondaryButton.setLayoutParams(secondaryLayoutParams);
+            }
+          } else {
+            LOG.atInfo("There are no button visible in the footer bar.");
+          }
+        });
+  }
+
+  /** Sets down button for expressive style. */
+  public void setDownButtonForExpressiveStyle() {
+    buttonContainer.post(
+        () -> {
+          int containerWidth = buttonContainer.getMeasuredWidth();
+          // Only allow primary button been shown on the screen if in the down button style.
+          if (getSecondaryButtonView() != null) {
+            getSecondaryButtonView().setVisibility(View.GONE);
+          }
+          setDownButtonStyle(getPrimaryButtonView());
+          if (!isTwoPaneLayout()) {
+            buttonContainer.setGravity(Gravity.CENTER_HORIZONTAL | Gravity.CENTER_VERTICAL);
+          } else {
+            buttonContainer.setGravity(Gravity.CENTER_VERTICAL);
+
+            Button downButtonView = getPrimaryButtonView();
+            LayoutParams primaryLayoutParams = (LayoutParams) downButtonView.getLayoutParams();
+            int downButtonWidth =
+                context
+                    .getResources()
+                    .getDimensionPixelSize(R.dimen.suc_glif_expressive_down_button_width);
+            // Put down button to the center of the one side in two pane mode.
+            primaryLayoutParams.setMarginStart(
+                (containerWidth / 2) + (containerWidth / 4) - downButtonWidth);
+            downButtonView.setLayoutParams(primaryLayoutParams);
           }
-        };
+        });
+  }
+
+  @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
+  boolean stackButtonIfTextOverFlow(
+      Button primaryButton,
+      Button secondaryButton,
+      float maxButtonWidth,
+      int availableFooterBarWidth) {
+    LayoutParams primaryLayoutParams = (LayoutParams) primaryButton.getLayoutParams();
+    LayoutParams secondaryLayoutParams = (LayoutParams) secondaryButton.getLayoutParams();
+
+    String primaryText = primaryButton.getText().toString();
+    Paint primaryTextPaint = new Paint();
+
+    primaryTextPaint.setTypeface(primaryButton.getTypeface());
+    primaryTextPaint.setTextSize(primaryButton.getTextSize());
+
+    float primaryButtonWidth =
+        primaryTextPaint.measureText(primaryText)
+            + primaryButton.getPaddingLeft()
+            + primaryButton.getPaddingRight()
+            + primaryButton.getPaddingStart()
+            + primaryButton.getPaddingEnd();
+
+    boolean isPrimaryButtonTextOverFlowing = primaryButtonWidth > maxButtonWidth;
+
+    LOG.atDebug(
+        "isPrimaryButtonTextOverFlowing= "
+            + isPrimaryButtonTextOverFlowing
+            + ", primaryButtonWidth= "
+            + primaryButtonWidth
+            + ", maxButtonWidth= "
+            + maxButtonWidth);
+
+    String secondaryText = secondaryButton.getText().toString();
+    Paint secondaryTextPaint = new Paint();
+
+    secondaryTextPaint.setTypeface(secondaryButton.getTypeface());
+    secondaryTextPaint.setTextSize(secondaryButton.getTextSize());
+    float secondaryButtonWidth =
+        secondaryTextPaint.measureText(secondaryText)
+            + secondaryButton.getPaddingLeft()
+            + secondaryButton.getPaddingRight()
+            + secondaryButton.getPaddingStart()
+            + secondaryButton.getPaddingEnd();
+
+    boolean isSecondaryButtonTextOverFlowing = secondaryButtonWidth > maxButtonWidth;
 
-    buttonContainer.getViewTreeObserver().addOnGlobalLayoutListener(onGlobalLayoutListener);
+    LOG.atDebug(
+        "isSecondaryButtonTextOverFlowing= "
+            + isSecondaryButtonTextOverFlowing
+            + ", secondaryButtonWidth= "
+            + secondaryButtonWidth
+            + ", maxButtonWidth= "
+            + maxButtonWidth);
+
+    if (isPrimaryButtonTextOverFlowing || isSecondaryButtonTextOverFlowing) {
+      if (buttonContainer instanceof ButtonBarLayout buttonBarLayout) {
+        buttonBarLayout.setStackedButtonForExpressiveStyle(true);
+        int stackButtonMiddleSpacing = footerBarButtonMiddleSpacing / 2;
+        secondaryLayoutParams.width = availableFooterBarWidth;
+        secondaryLayoutParams.topMargin = stackButtonMiddleSpacing;
+        secondaryButton.setLayoutParams(secondaryLayoutParams);
+
+        primaryLayoutParams.width = availableFooterBarWidth;
+        primaryLayoutParams.bottomMargin = stackButtonMiddleSpacing;
+        primaryButton.setLayoutParams(primaryLayoutParams);
+        return true;
+      }
+    }
+    return false;
   }
 
-  // TODO: b/376153500 - Add a test case for button stack mechanism.
-  private boolean isTextTooLong(Button button, float maxButtonWidth) {
-    String text = button.getText().toString();
-    TextPaint textPaint = button.getPaint();
-
-    int buttonWidth = (int) maxButtonWidth - button.getPaddingLeft() - button.getPaddingRight();
-
-    // Generate a static layout to see if text requires switching lines.
-    StaticLayout staticLayout =
-        new StaticLayout(
-            text,
-            textPaint,
-            buttonWidth,
-            Alignment.ALIGN_CENTER,
-            /* spacingMult= */ 1.0f,
-            /* spacingAdd= */ 0.0f,
-            /* includePad= */ false);
-    return staticLayout.getLineCount() > 1;
+  // TODO: b/400831621 -  Consider to combine this method to #stackButtonIfTextOverFlow
+  private void forceStackButtonInThreeButtonMode(
+      Button primaryButton,
+      Button secondaryButton,
+      Button tertiaryButton,
+      int availableFooterBarWidth) {
+
+    LayoutParams primaryLayoutParams = (LayoutParams) primaryButton.getLayoutParams();
+    LayoutParams secondaryLayoutParams = (LayoutParams) secondaryButton.getLayoutParams();
+    LayoutParams tertiaryLayoutParams = (LayoutParams) tertiaryButton.getLayoutParams();
+
+    if (buttonContainer instanceof ButtonBarLayout buttonBarLayout) {
+      buttonBarLayout.setStackedButtonForExpressiveStyle(true);
+      int stackButtonMiddleSpacing = footerBarButtonMiddleSpacing / 2;
+      secondaryLayoutParams.width = availableFooterBarWidth;
+      secondaryLayoutParams.topMargin = stackButtonMiddleSpacing;
+      secondaryButton.setLayoutParams(secondaryLayoutParams);
+
+      tertiaryLayoutParams.width = availableFooterBarWidth;
+      tertiaryLayoutParams.topMargin = stackButtonMiddleSpacing;
+      tertiaryLayoutParams.bottomMargin = stackButtonMiddleSpacing;
+      tertiaryButton.setLayoutParams(tertiaryLayoutParams);
+
+      primaryLayoutParams.width = availableFooterBarWidth;
+      primaryLayoutParams.bottomMargin = stackButtonMiddleSpacing;
+      primaryButton.setLayoutParams(primaryLayoutParams);
+    }
   }
 
   private boolean isTwoPaneLayout() {
     return context.getResources().getBoolean(R.bool.sucTwoPaneLayoutStyle);
   }
 
+  private boolean isThreeButtons(
+      Button primaryButton, Button secondaryButton, Button tertiaryButton) {
+    boolean isTertiaryButtonVisible =
+        tertiaryButton != null && tertiaryButton.getVisibility() == View.VISIBLE;
+    LOG.atDebug("isTertiaryButtonVisible=" + isTertiaryButtonVisible);
+    return isTertiaryButtonVisible && isBothButtons(primaryButton, secondaryButton);
+  }
+
   private boolean isBothButtons(Button primaryButton, Button secondaryButton) {
     boolean isPrimaryVisible =
         primaryButton != null && primaryButton.getVisibility() == View.VISIBLE;
@@ -1220,8 +1453,22 @@ public class FooterBarMixin implements Mixin {
    * Assigns logging metrics to bundle for PartnerCustomizationLayout to log metrics to SetupWizard.
    */
   @TargetApi(VERSION_CODES.Q)
+  @SuppressLint("ObsoleteSdkInt")
   public PersistableBundle getLoggingMetrics() {
-    return metrics.getMetrics();
+    LOG.atDebug("FooterBarMixin fragment name=" + hostFragmentName + ", Tag=" + hostFragmentTag);
+    PersistableBundle persistableBundle = metrics.getMetrics();
+    if (VERSION.SDK_INT >= VERSION_CODES.Q
+        && PartnerConfigHelper.isEnhancedSetupDesignMetricsEnabled(context)) {
+      if (hostFragmentName != null) {
+        persistableBundle.putString(
+            KEY_HOST_FRAGMENT_NAME, CustomEvent.trimsStringOverMaxLength(hostFragmentName));
+      }
+      if (hostFragmentTag != null) {
+        persistableBundle.putString(
+            KEY_HOST_FRAGMENT_TAG, CustomEvent.trimsStringOverMaxLength(hostFragmentTag));
+      }
+    }
+    return persistableBundle;
   }
 
   private void updateTextColorForButton(Button button, boolean enable, int color) {
diff --git a/main/java/com/google/android/setupcompat/template/FooterButton.java b/main/java/com/google/android/setupcompat/template/FooterButton.java
index 33bf265..c204128 100644
--- a/main/java/com/google/android/setupcompat/template/FooterButton.java
+++ b/main/java/com/google/android/setupcompat/template/FooterButton.java
@@ -31,6 +31,7 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.StringRes;
 import androidx.annotation.StyleRes;
+import androidx.annotation.VisibleForTesting;
 import com.google.android.setupcompat.R;
 import com.google.android.setupcompat.logging.CustomEvent;
 import com.google.android.setupcompat.logging.LoggingObserver;
@@ -38,15 +39,17 @@ import com.google.android.setupcompat.logging.LoggingObserver.InteractionType;
 import com.google.android.setupcompat.logging.LoggingObserver.SetupCompatUiEvent.ButtonInteractionEvent;
 import java.lang.annotation.Retention;
 import java.util.Locale;
+import java.util.Objects;
 
 /**
  * Definition of a footer button. Clients can use this class to customize attributes like text,
  * button type and click listener, and FooterBarMixin will inflate a corresponding Button view.
  */
 public final class FooterButton implements OnClickListener {
-  private static final String KEY_BUTTON_ON_CLICK_COUNT = "_onClickCount";
-  private static final String KEY_BUTTON_TEXT = "_text";
-  private static final String KEY_BUTTON_TYPE = "_type";
+  @VisibleForTesting static final String KEY_BUTTON_ON_CLICK_COUNT = "_onClickCount";
+  @VisibleForTesting static final String KEY_BUTTON_TEXT = "_text";
+  @VisibleForTesting static final String KEY_BUTTON_TEXT_RESOURCE_NAME = "_textResName";
+  @VisibleForTesting static final String KEY_BUTTON_TYPE = "_type";
 
   @ButtonType private final int buttonType;
   private CharSequence text;
@@ -60,6 +63,7 @@ public final class FooterButton implements OnClickListener {
   private int clickCount = 0;
   private Locale locale;
   private int direction;
+  private String textResourceName;
 
   public FooterButton(Context context, AttributeSet attrs) {
     TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SucFooterButton);
@@ -89,7 +93,8 @@ public final class FooterButton implements OnClickListener {
       @StyleRes int theme,
       Locale locale,
       int direction,
-      int visibility) {
+      int visibility,
+      String textResourceName) {
     this.text = text;
     onClickListener = listener;
     this.buttonType = buttonType;
@@ -97,6 +102,7 @@ public final class FooterButton implements OnClickListener {
     this.locale = locale;
     this.direction = direction;
     this.visibility = visibility;
+    this.textResourceName = textResourceName;
   }
 
   /** Returns the text that this footer button is displaying. */
@@ -185,6 +191,7 @@ public final class FooterButton implements OnClickListener {
 
   /** Sets the text to be displayed using a string resource identifier. */
   public void setText(Context context, @StringRes int resId) {
+    textResourceName = getTextResourceName(context, resId);
     setText(context.getText(resId));
   }
 
@@ -240,6 +247,14 @@ public final class FooterButton implements OnClickListener {
     this.loggingObserver = loggingObserver;
   }
 
+  @VisibleForTesting
+  static String getTextResourceName(Context context, int resId) {
+    if (context != null && context.getResources() != null && resId != 0) {
+      return context.getResources().getResourceEntryName(resId);
+    }
+    return "";
+  }
+
   /** Interface definition for a callback to be invoked when footer button API has set. */
   interface OnButtonEventListener {
 
@@ -349,6 +364,11 @@ public final class FooterButton implements OnClickListener {
         buttonName + KEY_BUTTON_TEXT, CustomEvent.trimsStringOverMaxLength(getText().toString()));
     bundle.putString(buttonName + KEY_BUTTON_TYPE, getButtonTypeName());
     bundle.putInt(buttonName + KEY_BUTTON_ON_CLICK_COUNT, clickCount);
+    if (textResourceName != null && !Objects.equals(textResourceName, "")) {
+      bundle.putString(
+          buttonName + KEY_BUTTON_TEXT_RESOURCE_NAME,
+          CustomEvent.trimsStringOverMaxLength(textResourceName));
+    }
     return bundle;
   }
 
@@ -383,6 +403,7 @@ public final class FooterButton implements OnClickListener {
     private int theme = 0;
 
     private int visibility = View.VISIBLE;
+    private String textResourceName = "";
 
     public Builder(@NonNull Context context) {
       this.context = context;
@@ -396,6 +417,7 @@ public final class FooterButton implements OnClickListener {
 
     /** Sets the {@code text} of FooterButton by resource. */
     public Builder setText(@StringRes int text) {
+      this.textResourceName = getTextResourceName(context, text);
       this.text = context.getString(text);
       return this;
     }
@@ -438,7 +460,14 @@ public final class FooterButton implements OnClickListener {
 
     public FooterButton build() {
       return new FooterButton(
-          text, onClickListener, buttonType, theme, locale, direction, visibility);
+          text,
+          onClickListener,
+          buttonType,
+          theme,
+          locale,
+          direction,
+          visibility,
+          textResourceName);
     }
   }
 }
diff --git a/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java b/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java
index 2b0aedf..9a7099d 100644
--- a/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java
+++ b/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java
@@ -70,6 +70,14 @@ public final class WizardManagerHelper {
   /** Extra for notifying an Activity that it is inside the "Portal Setup" flow. */
   public static final String EXTRA_IS_PORTAL_SETUP = "portalSetup";
 
+  /**
+   * Extra for including a persistable map of Onboarding Node Id to MetadataStore.
+   *
+   * <p>This will only be read and used by loading screens. Other screens should just pass this
+   * forwards.
+   */
+  public static final String EXTRA_PENDING_ACTIVITY_METADATA = "pendingActivityMetadata";
+
   /**
    * Extra for notifying an Activity that it is inside the any setup flow.
    *
@@ -133,6 +141,8 @@ public final class WizardManagerHelper {
    */
   public static void copyWizardManagerExtras(Intent srcIntent, Intent dstIntent) {
     dstIntent.putExtra(EXTRA_WIZARD_BUNDLE, srcIntent.getBundleExtra(EXTRA_WIZARD_BUNDLE));
+    dstIntent.putExtra(
+        EXTRA_PENDING_ACTIVITY_METADATA, srcIntent.getBundleExtra(EXTRA_PENDING_ACTIVITY_METADATA));
     for (String key :
         Arrays.asList(
             EXTRA_IS_FIRST_RUN,
diff --git a/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java b/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java
index 9cee894..9b7a40a 100644
--- a/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java
+++ b/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java
@@ -21,10 +21,13 @@ import android.content.Context;
 import android.graphics.Canvas;
 import android.graphics.drawable.Drawable;
 import android.os.Build;
+import android.os.Build.VERSION;
 import android.os.Build.VERSION_CODES;
 import android.util.AttributeSet;
 import android.view.WindowInsets;
 import android.widget.FrameLayout;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
+import com.google.android.setupcompat.util.Logger;
 
 /**
  * A FrameLayout subclass that will responds to onApplyWindowInsets to draw a drawable in the top
@@ -37,6 +40,8 @@ import android.widget.FrameLayout;
  */
 public class StatusBarBackgroundLayout extends FrameLayout {
 
+  private static final Logger LOG = new Logger("StatusBarBgLayout");
+
   private Drawable statusBarBackground;
   private Object lastInsets; // Use generic Object type for compatibility
 
@@ -70,7 +75,8 @@ public class StatusBarBackgroundLayout extends FrameLayout {
       if (lastInsets != null) {
         final int insetTop = ((WindowInsets) lastInsets).getSystemWindowInsetTop();
         if (insetTop > 0) {
-          statusBarBackground.setBounds(0, 0, getWidth(), insetTop);
+          statusBarBackground.setBounds(
+              /* left= */ 0, /* top= */ 0, /* right= */ getWidth(), /* bottom= */ insetTop);
           statusBarBackground.draw(canvas);
         }
       }
@@ -92,6 +98,18 @@ public class StatusBarBackgroundLayout extends FrameLayout {
 
   @Override
   public WindowInsets onApplyWindowInsets(WindowInsets insets) {
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
     lastInsets = insets;
     return super.onApplyWindowInsets(insets);
   }
diff --git a/main/res/values/attrs.xml b/main/res/values/attrs.xml
index deefea6..75d6482 100644
--- a/main/res/values/attrs.xml
+++ b/main/res/values/attrs.xml
@@ -107,6 +107,7 @@
         <attr name="sucFooterBarButtonFontWeight" format="integer" />
         <attr name="sucFooterBarButtonTextSize" format="dimension" />
         <attr name="sucFooterButtonTextLineSpacingExtra" format="dimension" />
+        <attr name="sucFooterBarButtonOutlinedColor" format="color" />
     </declare-styleable>
 
     <declare-styleable name="SucHeaderMixin">
@@ -122,4 +123,6 @@
 
     <attr name="sucMaterialButtonStyle" format="reference" />
 
+    <attr name="sucMaterialTonalButtonStyle" format="reference" />
+
 </resources>
diff --git a/main/res/values/styles.xml b/main/res/values/styles.xml
index 7b8e17d..c4a2ed4 100644
--- a/main/res/values/styles.xml
+++ b/main/res/values/styles.xml
@@ -129,6 +129,7 @@
         <item name="android:insetBottom">0dp</item>
         <item name="android:textSize">?attr/sucFooterBarButtonTextSize</item>
         <item name="android:lineSpacingExtra">?attr/sucFooterButtonTextLineSpacingExtra</item>
+        <item name="strokeColor">?attr/sucFooterBarButtonOutlinedColor</item>
 
         <!-- Values used in themes -->
         <item name="android:buttonCornerRadius" tools:ignore="NewApi">?attr/sucFooterBarButtonCornerRadius</item>
@@ -138,4 +139,12 @@
         <item name="viewInflaterClass">com.google.android.material.theme.MaterialComponentsViewInflater</item>
         <item name="sucMaterialOutlinedButtonStyle">@style/SucGlifMaterialButton.Secondary</item>
     </style>
+
+    <style name="SucGlifMaterialButton.Tonal" parent="Widget.Material3.Button.TonalButton.Icon">
+        <!-- This style can be applied to a button either as a "style" in XML, or as a theme in
+             ContextThemeWrapper. These self-referencing attributes make sure this is applied as
+             both to the button. -->
+        <item name="viewInflaterClass">com.google.android.material.theme.MaterialComponentsViewInflater</item>
+        <item name="sucMaterialTonalButtonStyle">@style/SucGlifMaterialButton.Tonal</item>
+     </style>
 </resources>
diff --git a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java
index 4b77e67..9f41cf4 100644
--- a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java
+++ b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java
@@ -189,6 +189,10 @@ public enum PartnerConfig {
   // Font weight of the header
   CONFIG_HEADER_FONT_WEIGHT(PartnerConfigKey.KEY_HEADER_FONT_WEIGHT, ResourceType.INTEGER),
 
+  // Font variation_settings of the header
+  CONFIG_HEADER_FONT_VARIATION_SETTINGS(
+      PartnerConfigKey.KEY_HEADER_FONT_VARIATION_SETTINGS, ResourceType.STRING),
+
   // Margin top of the header text
   CONFIG_HEADER_TEXT_MARGIN_TOP(
       PartnerConfigKey.KEY_HEADER_TEXT_MARGIN_TOP, ResourceType.DIMENSION),
diff --git a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigHelper.java b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigHelper.java
index de407e0..8706418 100644
--- a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigHelper.java
+++ b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigHelper.java
@@ -41,7 +41,6 @@ import androidx.annotation.VisibleForTesting;
 import androidx.window.embedding.ActivityEmbeddingController;
 import com.google.android.setupcompat.partnerconfig.PartnerConfig.ResourceType;
 import com.google.android.setupcompat.util.BuildCompatUtils;
-import com.google.android.setupcompat.util.WizardManagerHelper;
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.EnumMap;
@@ -91,6 +90,10 @@ public class PartnerConfigHelper {
   @VisibleForTesting
   public static final String IS_GLIF_EXPRESSIVE_ENABLED = "isGlifExpressiveEnabled";
 
+  @VisibleForTesting
+  public static final String IS_ENHANCED_SETUP_DESIGN_METRICS_ENABLED =
+      "isEnhancedSetupDesignMetricsEnabled";
+
   /** The method name to get the if the keyboard focus enhancement enabled */
   @VisibleForTesting
   public static final String IS_KEYBOARD_FOCUS_ENHANCEMENT_ENABLED_METHOD =
@@ -106,7 +109,7 @@ public class PartnerConfigHelper {
   @VisibleForTesting
   public static final String EMBEDDED_ACTIVITY_RESOURCE_SUFFIX = "_embedded_activity";
 
-  @VisibleForTesting static Bundle suwDayNightEnabledBundle = null;
+  @VisibleForTesting public static Bundle suwDayNightEnabledBundle = null;
 
   @VisibleForTesting public static Bundle applyExtendedPartnerConfigBundle = null;
 
@@ -146,6 +149,8 @@ public class PartnerConfigHelper {
 
   @VisibleForTesting public static Bundle applyGlifExpressiveBundle = null;
 
+  @VisibleForTesting public static Bundle enableMetricsLoggingBundle = null;
+
   @VisibleForTesting public static int savedOrientation = Configuration.ORIENTATION_PORTRAIT;
 
   /** The method name to get if transition settings is set from client. */
@@ -617,10 +622,10 @@ public class PartnerConfigHelper {
 
     if (BuildCompatUtils.isAtLeastU() && isActivityEmbedded(context)) {
       resourceEntry = adjustEmbeddedActivityResourceEntryDefaultValue(context, resourceEntry);
-    } else if (BuildCompatUtils.isAtLeastU() && isForceTwoPaneEnabled(context)) {
-      resourceEntry = adjustForceTwoPaneResourceEntryDefaultValue(context, resourceEntry);
     } else if (BuildCompatUtils.isAtLeastV() && isGlifExpressiveEnabled(context)) {
       resourceEntry = adjustGlifExpressiveResourceEntryDefaultValue(context, resourceEntry);
+    } else if (BuildCompatUtils.isAtLeastU() && isForceTwoPaneEnabled(context)) {
+      resourceEntry = adjustForceTwoPaneResourceEntryDefaultValue(context, resourceEntry);
     } else if (BuildCompatUtils.isAtLeastT() && shouldApplyMaterialYouStyle(context)) {
       resourceEntry = adjustMaterialYouResourceEntryDefaultValue(context, resourceEntry);
     }
@@ -853,6 +858,7 @@ public class PartnerConfigHelper {
     applyForceTwoPaneBundle = null;
     applyGlifExpressiveBundle = null;
     keyboardFocusEnhancementBundle = null;
+    enableMetricsLoggingBundle = null;
   }
 
   /**
@@ -1170,13 +1176,6 @@ public class PartnerConfigHelper {
 
     if (applyGlifExpressiveBundle == null || applyGlifExpressiveBundle.isEmpty()) {
       try {
-        Activity activity = lookupActivityFromContext(context);
-        // Save inside/outside setup wizard flag into bundle
-        Bundle extras = new Bundle();
-        extras.putBoolean(
-            WizardManagerHelper.EXTRA_IS_SETUP_FLOW,
-            WizardManagerHelper.isAnySetupWizard(activity.getIntent()));
-
         applyGlifExpressiveBundle =
             context
                 .getContentResolver()
@@ -1184,7 +1183,7 @@ public class PartnerConfigHelper {
                     getContentUri(),
                     IS_GLIF_EXPRESSIVE_ENABLED,
                     /* arg= */ null,
-                    /* extras= */ extras);
+                    /* extras= */ null);
       } catch (IllegalArgumentException | SecurityException exception) {
         Log.w(TAG, "isGlifExpressiveEnabled status is unknown; return as false.");
       }
@@ -1192,6 +1191,33 @@ public class PartnerConfigHelper {
     if (applyGlifExpressiveBundle != null && !applyGlifExpressiveBundle.isEmpty()) {
       return applyGlifExpressiveBundle.getBoolean(IS_GLIF_EXPRESSIVE_ENABLED, false);
     }
+
+    return false;
+  }
+
+  /** Returns true if the SetupWizard enable the UI component logging. */
+  public static boolean isEnhancedSetupDesignMetricsEnabled(@NonNull Context context) {
+    if (enableMetricsLoggingBundle == null || enableMetricsLoggingBundle.isEmpty()) {
+      try {
+        enableMetricsLoggingBundle =
+            context
+                .getContentResolver()
+                .call(
+                    getContentUri(),
+                    IS_ENHANCED_SETUP_DESIGN_METRICS_ENABLED,
+                    /* arg= */ null,
+                    /* extras= */ null);
+      } catch (IllegalArgumentException | SecurityException exception) {
+        Log.w(TAG, "Method " + IS_ENHANCED_SETUP_DESIGN_METRICS_ENABLED + " is unknown");
+        enableMetricsLoggingBundle = null;
+        return false;
+      }
+    }
+
+    if (enableMetricsLoggingBundle != null && !enableMetricsLoggingBundle.isEmpty()) {
+      return enableMetricsLoggingBundle.getBoolean(IS_ENHANCED_SETUP_DESIGN_METRICS_ENABLED, false);
+    }
+
     return false;
   }
 
diff --git a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java
index 7b20aed..c5047b9 100644
--- a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java
+++ b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java
@@ -69,6 +69,7 @@ import java.lang.annotation.RetentionPolicy;
   PartnerConfigKey.KEY_HEADER_TEXT_COLOR,
   PartnerConfigKey.KEY_HEADER_FONT_FAMILY,
   PartnerConfigKey.KEY_HEADER_FONT_WEIGHT,
+  PartnerConfigKey.KEY_HEADER_FONT_VARIATION_SETTINGS,
   PartnerConfigKey.KEY_HEADER_AREA_BACKGROUND_COLOR,
   PartnerConfigKey.KEY_HEADER_TEXT_MARGIN_TOP,
   PartnerConfigKey.KEY_HEADER_TEXT_MARGIN_BOTTOM,
@@ -296,6 +297,9 @@ public @interface PartnerConfigKey {
   // Font weight of the header
   String KEY_HEADER_FONT_WEIGHT = "setup_design_header_font_weight";
 
+  // Font weight of the header
+  String KEY_HEADER_FONT_VARIATION_SETTINGS = "setup_design_header_font_variation_settings";
+
   // Margin top of the header text
   String KEY_HEADER_TEXT_MARGIN_TOP = "setup_design_header_text_margin_top";
 
```

