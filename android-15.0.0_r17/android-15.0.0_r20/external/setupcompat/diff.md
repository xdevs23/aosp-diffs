```diff
diff --git a/Android.bp b/Android.bp
index 8a4196a..5d907d8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -98,6 +98,7 @@ android_library {
     static_libs: [
         "androidx.annotation_annotation",
         "androidx.window_window",
+        "com.google.android.material_material",
         "error_prone_annotations",
     ],
     min_sdk_version: "21",
@@ -108,6 +109,10 @@ android_library {
     lint: {
         baseline_filename: "lint-baseline.xml",
     },
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.healthfitness",
+    ],
 }
 
 android_library {
@@ -126,6 +131,7 @@ android_library {
     static_libs: [
         "androidx.annotation_annotation",
         "androidx.window_window",
+        "com.google.android.material_material",
         "error_prone_annotations",
     ],
     min_sdk_version: "21",
diff --git a/exempting_lint_checks.txt b/exempting_lint_checks.txt
index 08ba928..3932c96 100644
--- a/exempting_lint_checks.txt
+++ b/exempting_lint_checks.txt
@@ -26,3 +26,35 @@ third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setup
 third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: NewApi: FooterButtonStyleUtils.updateButtonRippleColorWithPartnerConfig(
 third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/SystemBarHelper.java: AnnotateVersionCheck: public static void setImeInsetView(final View view) {
 third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/AndroidManifest.xml: ExpiringTargetSdkVersion: <uses-sdk android:minSdkVersion="14" android:targetSdkVersion="31" />
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java: CustomViewStyleable: attrs, R.styleable.SucPartnerCustomizationLayout, defStyleAttr, 0);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/internal/TemplateLayout.java: CustomViewStyleable: getContext().obtainStyledAttributes(attrs, R.styleable.SucTemplateLayout, defStyleAttr, 0);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/internal/TemplateLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/logging/CustomEvent.java: ObsoleteSdkInt: Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/logging/internal/MetricBundleConverter.java: NewApi: bundle.putParcelable(MetricBundleKeys.CUSTOM_EVENT_BUNDLE, CustomEvent.toBundle(customEvent));
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterBarMixin.java: NewApi: onFooterButtonApplyPartnerResource(button, footerButtonPartnerConfig);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: NewApi: FooterButtonStyleUtils.updateButtonBackgroundWithPartnerConfig(
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: NewApi: FooterButtonStyleUtils.updateButtonRippleColorWithPartnerConfig(
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: ObsoleteSdkInt: Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: ObsoleteSdkInt: if (Build.VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP) {
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/SystemBarHelper.java: AnnotateVersionCheck: public static void setImeInsetView(final View view) {
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/AndroidManifest.xml: ExpiringTargetSdkVersion: <uses-sdk android:minSdkVersion="14" android:targetSdkVersion="31" />
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java: CustomViewStyleable: attrs, R.styleable.SucPartnerCustomizationLayout, defStyleAttr, 0);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/internal/TemplateLayout.java: CustomViewStyleable: getContext().obtainStyledAttributes(attrs, R.styleable.SucTemplateLayout, defStyleAttr, 0);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/internal/TemplateLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/logging/CustomEvent.java: ObsoleteSdkInt: Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/logging/internal/MetricBundleConverter.java: NewApi: bundle.putParcelable(MetricBundleKeys.CUSTOM_EVENT_BUNDLE, CustomEvent.toBundle(customEvent));
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterBarMixin.java: NewApi: onFooterButtonApplyPartnerResource(button, footerButtonPartnerConfig);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: NewApi: FooterButtonStyleUtils.updateButtonBackgroundWithPartnerConfig(
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: NewApi: FooterButtonStyleUtils.updateButtonRippleColorWithPartnerConfig(
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: ObsoleteSdkInt: Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java: ObsoleteSdkInt: if (Build.VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP) {
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/ForceTwoPaneHelper.java: NewApi: WindowManager windowManager = context.getSystemService(WindowManager.class);
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/ForceTwoPaneHelper.java: NewApi: WindowMetrics windowMetrics = windowManager.getCurrentWindowMetrics();
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/ForceTwoPaneHelper.java: NewApi: if (windowMetrics.getBounds().width() > windowMetrics.getBounds().height()) {
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/ForceTwoPaneHelper.java: NewApi: int widthInDp = (int) (windowMetrics.getBounds().width() / windowMetrics.getDensity());
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/util/SystemBarHelper.java: AnnotateVersionCheck: public static void setImeInsetView(final View view) {
+third_party/java_src/android_libs/setupcompat/main/java/com/google/android/setupcompat/view/StatusBarBackgroundLayout.java: ObsoleteSdkInt: @TargetApi(VERSION_CODES.HONEYCOMB)
diff --git a/main/aidl/com/google/android/setupcompat/ISetupCompatService.aidl b/main/aidl/com/google/android/setupcompat/ISetupCompatService.aidl
index e8cb7e5..8d09711 100644
--- a/main/aidl/com/google/android/setupcompat/ISetupCompatService.aidl
+++ b/main/aidl/com/google/android/setupcompat/ISetupCompatService.aidl
@@ -22,8 +22,6 @@ import android.os.Bundle;
  * Declares the interface for compat related service methods.
  */
 interface ISetupCompatService {
-  /** Notifies SetupWizard that the screen is using PartnerCustomizationLayout */
-  oneway void validateActivity(String screenName, in Bundle arguments) = 0;
 
   oneway void logMetric(int metricType, in Bundle arguments, in Bundle extras) = 1;
 
diff --git a/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java b/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java
index 26e7042..055d07b 100644
--- a/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java
+++ b/main/java/com/google/android/setupcompat/PartnerCustomizationLayout.java
@@ -309,37 +309,44 @@ public class PartnerCustomizationLayout extends TemplateLayout {
    * {@code false}.
    */
   public boolean shouldApplyDynamicColor() {
-    if (!useDynamicColor) {
-      return false;
-    }
     if (!BuildCompatUtils.isAtLeastS()) {
       return false;
     }
+
     if (!PartnerConfigHelper.get(getContext()).isAvailable()) {
       return false;
     }
+
+    // If the dynamic theme is applied, useDynamicColor would be true and shouldApplyDynamicColor
+    // would return true.
+    if (useDynamicColor) {
+      return true;
+    }
+    if (!PartnerConfigHelper.isSetupWizardDynamicColorEnabled(getContext())) {
+      return false;
+    }
     return true;
   }
 
   /**
    * Returns {@code true} if the current layout/activity applies full dynamic color. Otherwise,
-   * returns {@code false}. This method combines the result of {@link #shouldApplyDynamicColor()}
-   * and the value of the {@code app:sucFullDynamicColor}.
+   * returns {@code false}. This method combines the result of {@link #shouldApplyDynamicColor()},
+   * the value of the {@code app:sucFullDynamicColor}, and the result of {@link
+   * PartnerConfigHelper#isSetupWizardFullDynamicColorEnabled(Context)}.
    */
   public boolean useFullDynamicColor() {
-    return shouldApplyDynamicColor() && useFullDynamicColorAttr;
+    return shouldApplyDynamicColor()
+        && (useFullDynamicColorAttr
+            || PartnerConfigHelper.isSetupWizardFullDynamicColorEnabled(getContext()));
   }
 
   /**
-   * Sets a logging observer for {@link FooterBarMixin}. The logging observer is used to log
-   * impressions and clicks on the layout and footer bar buttons.
-   *
-   * @throws UnsupportedOperationException if the primary or secondary button has been set before
-   *     the logging observer is set
+   * Sets a logging observer for {@link FooterBarMixin}. The logging observer is used to log UI
+   * events (e.g. page impressions and button clicks) on the layout and footer bar buttons.
    */
   public void setLoggingObserver(LoggingObserver loggingObserver) {
-    getMixin(FooterBarMixin.class).setLoggingObserver(loggingObserver);
     loggingObserver.log(new LayoutInflatedEvent(this));
+    getMixin(FooterBarMixin.class).setLoggingObserver(loggingObserver);
   }
 
   /**
diff --git a/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java b/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java
index d882c9d..733ee52 100644
--- a/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java
+++ b/main/java/com/google/android/setupcompat/internal/LifecycleFragment.java
@@ -52,10 +52,6 @@ public class LifecycleFragment extends Fragment {
    */
   public static LifecycleFragment attachNow(Activity activity) {
     if (WizardManagerHelper.isAnySetupWizard(activity.getIntent())) {
-      SetupCompatServiceInvoker.get(activity.getApplicationContext())
-          .bindBack(
-              LayoutBindBackHelper.getScreenName(activity),
-              LayoutBindBackHelper.getExtraBundle(activity));
 
       if (VERSION.SDK_INT > VERSION_CODES.M) {
         FragmentManager fragmentManager = activity.getFragmentManager();
diff --git a/main/java/com/google/android/setupcompat/internal/SetupCompatServiceInvoker.java b/main/java/com/google/android/setupcompat/internal/SetupCompatServiceInvoker.java
index ed9c0e3..7208778 100644
--- a/main/java/com/google/android/setupcompat/internal/SetupCompatServiceInvoker.java
+++ b/main/java/com/google/android/setupcompat/internal/SetupCompatServiceInvoker.java
@@ -32,8 +32,7 @@ import java.util.concurrent.TimeoutException;
 /**
  * This class is responsible for safely executing methods on SetupCompatService. To avoid memory
  * issues due to backed up queues, an upper bound of {@link
- * ExecutorProvider#SETUP_METRICS_LOGGER_MAX_QUEUED} is set on the logging executor service's queue
- * and {@link ExecutorProvider#SETUP_COMPAT_BINDBACK_MAX_QUEUED} on the overall executor service.
+ * ExecutorProvider#SETUP_METRICS_LOGGER_MAX_QUEUED} is set on the logging executor service's queue.
  * Once the upper bound is reached, metrics published after this event are dropped silently.
  *
  * <p>NOTE: This class is not meant to be used directly. Please use {@link
@@ -52,14 +51,6 @@ public class SetupCompatServiceInvoker {
     }
   }
 
-  public void bindBack(String screenName, Bundle bundle) {
-    try {
-      loggingExecutor.execute(() -> invokeBindBack(screenName, bundle));
-    } catch (RejectedExecutionException e) {
-      LOG.e(String.format("Screen %s bind back fail.", screenName), e);
-    }
-  }
-
   /**
    * Help invoke the {@link ISetupCompatService#onFocusStatusChanged} using {@code loggingExecutor}.
    */
@@ -110,23 +101,6 @@ public class SetupCompatServiceInvoker {
     }
   }
 
-  private void invokeBindBack(String screenName, Bundle bundle) {
-    try {
-      ISetupCompatService setupCompatService =
-          SetupCompatServiceProvider.get(
-              context, waitTimeInMillisForServiceConnection, TimeUnit.MILLISECONDS);
-      if (setupCompatService != null) {
-        setupCompatService.validateActivity(screenName, bundle);
-      } else {
-        LOG.w("BindBack failed since service reference is null. Are the permissions valid?");
-      }
-    } catch (InterruptedException | TimeoutException | RemoteException e) {
-      LOG.e(
-          String.format("Exception occurred while %s trying bind back to SetupWizard.", screenName),
-          e);
-    }
-  }
-
   private SetupCompatServiceInvoker(Context context) {
     this.context = context;
     this.loggingExecutor = ExecutorProvider.setupCompatServiceInvoker.get();
diff --git a/main/java/com/google/android/setupcompat/template/FooterActionButton.java b/main/java/com/google/android/setupcompat/template/FooterActionButton.java
index d9726f9..212f86e 100644
--- a/main/java/com/google/android/setupcompat/template/FooterActionButton.java
+++ b/main/java/com/google/android/setupcompat/template/FooterActionButton.java
@@ -22,12 +22,13 @@ import android.util.AttributeSet;
 import android.view.MotionEvent;
 import android.view.View;
 import android.widget.Button;
-import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
 
 /** Button that can react to touch when disabled. */
-public class FooterActionButton extends Button {
+@SuppressWarnings("AppCompatCustomView")
+public class FooterActionButton extends Button implements IFooterActionButton {
 
-  @Nullable private FooterButton footerButton;
+  @VisibleForTesting FooterButton footerButton;
   private boolean isPrimaryButtonStyle = false;
 
   public FooterActionButton(Context context, AttributeSet attrs) {
@@ -38,8 +39,6 @@ public class FooterActionButton extends Button {
     this.footerButton = footerButton;
   }
 
-  // getOnClickListenerWhenDisabled is responsible for handling accessibility correctly, calling
-  // performClick if necessary.
   @SuppressLint("ClickableViewAccessibility")
   @Override
   public boolean onTouchEvent(MotionEvent event) {
@@ -47,6 +46,8 @@ public class FooterActionButton extends Button {
       if (footerButton != null
           && !footerButton.isEnabled()
           && footerButton.getVisibility() == View.VISIBLE) {
+        // getOnClickListenerWhenDisabled is responsible for handling accessibility correctly,
+        // calling performClick if necessary.
         OnClickListener listener = footerButton.getOnClickListenerWhenDisabled();
         if (listener != null) {
           listener.onClick(this);
@@ -65,7 +66,7 @@ public class FooterActionButton extends Button {
     this.isPrimaryButtonStyle = isPrimaryButtonStyle;
   }
 
-  /** Returns true when the footer button is primary button style. */
+  @Override
   public boolean isPrimaryButtonStyle() {
     return isPrimaryButtonStyle;
   }
diff --git a/main/java/com/google/android/setupcompat/template/FooterBarMixin.java b/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
index 5939a18..7d72cf2 100644
--- a/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
+++ b/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
@@ -25,15 +25,22 @@ import android.content.Context;
 import android.content.res.Configuration;
 import android.content.res.TypedArray;
 import android.graphics.Color;
+import android.graphics.drawable.GradientDrawable;
 import android.os.Build.VERSION_CODES;
 import android.os.PersistableBundle;
+import android.text.Layout.Alignment;
+import android.text.StaticLayout;
+import android.text.TextPaint;
 import android.util.AttributeSet;
+import android.util.DisplayMetrics;
 import android.view.ContextThemeWrapper;
 import android.view.Gravity;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.ViewStub;
+import android.view.ViewTreeObserver;
+import android.view.ViewTreeObserver.OnGlobalLayoutListener;
 import android.widget.Button;
 import android.widget.LinearLayout;
 import android.widget.LinearLayout.LayoutParams;
@@ -47,6 +54,7 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.StyleRes;
 import androidx.annotation.VisibleForTesting;
+import com.google.android.material.button.MaterialButton;
 import com.google.android.setupcompat.PartnerCustomizationLayout;
 import com.google.android.setupcompat.R;
 import com.google.android.setupcompat.internal.FooterButtonPartnerConfig;
@@ -57,6 +65,9 @@ import com.google.android.setupcompat.logging.internal.FooterBarMixinMetrics;
 import com.google.android.setupcompat.partnerconfig.PartnerConfig;
 import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
 import com.google.android.setupcompat.template.FooterButton.ButtonType;
+import com.google.android.setupcompat.util.KeyboardHelper;
+import com.google.android.setupcompat.util.Logger;
+import com.google.android.setupcompat.view.ButtonBarLayout;
 import java.util.Locale;
 
 /**
@@ -66,6 +77,8 @@ import java.util.Locale;
  */
 public class FooterBarMixin implements Mixin {
 
+  private static final Logger LOG = new Logger("FooterBarMixin");
+
   private final Context context;
 
   @Nullable private final ViewStub footerStub;
@@ -93,6 +106,11 @@ public class FooterBarMixin implements Mixin {
   @ColorInt private final int footerBarSecondaryBackgroundColor;
   private boolean removeFooterBarWhenEmpty = true;
   private boolean isSecondaryButtonInPrimaryStyle = false;
+  private final int footerBarPrimaryButtonEnabledTextColor;
+  private final int footerBarSecondaryButtonEnabledTextColor;
+  private final int footerBarPrimaryButtonDisabledTextColor;
+  private final int footerBarSecondaryButtonDisabledTextColor;
+  @VisibleForTesting final int footerBarButtonMiddleSpacing;
 
   @VisibleForTesting public final FooterBarMixinMetrics metrics = new FooterBarMixinMetrics();
 
@@ -106,16 +124,35 @@ public class FooterBarMixin implements Mixin {
           Button button = buttonContainer.findViewById(id);
           if (button != null) {
             button.setEnabled(enabled);
-            if (applyPartnerResources && !applyDynamicColor) {
-
-              updateButtonTextColorWithStates(
-                  button,
-                  (id == primaryButtonId || isSecondaryButtonInPrimaryStyle)
-                      ? PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_TEXT_COLOR
-                      : PartnerConfig.CONFIG_FOOTER_SECONDARY_BUTTON_TEXT_COLOR,
-                  (id == primaryButtonId || isSecondaryButtonInPrimaryStyle)
-                      ? PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_DISABLED_TEXT_COLOR
-                      : PartnerConfig.CONFIG_FOOTER_SECONDARY_BUTTON_DISABLED_TEXT_COLOR);
+
+            // TODO: b/364981299 - Use partner config to allow user to customize text color.
+            if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+              if (id == primaryButtonId) {
+                updateTextColorForButton(
+                    button,
+                    enabled,
+                    enabled
+                        ? footerBarPrimaryButtonEnabledTextColor
+                        : footerBarPrimaryButtonDisabledTextColor);
+              } else if (id == secondaryButtonId) {
+                updateTextColorForButton(
+                    button,
+                    enabled,
+                    enabled
+                        ? footerBarSecondaryButtonEnabledTextColor
+                        : footerBarSecondaryButtonDisabledTextColor);
+              }
+            } else {
+              if (applyPartnerResources && !applyDynamicColor) {
+                updateButtonTextColorWithStates(
+                    button,
+                    (id == primaryButtonId || isSecondaryButtonInPrimaryStyle)
+                        ? PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_TEXT_COLOR
+                        : PartnerConfig.CONFIG_FOOTER_SECONDARY_BUTTON_TEXT_COLOR,
+                    (id == primaryButtonId || isSecondaryButtonInPrimaryStyle)
+                        ? PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_DISABLED_TEXT_COLOR
+                        : PartnerConfig.CONFIG_FOOTER_SECONDARY_BUTTON_DISABLED_TEXT_COLOR);
+              }
             }
           }
         }
@@ -128,6 +165,10 @@ public class FooterBarMixin implements Mixin {
           if (button != null) {
             button.setVisibility(visibility);
             autoSetButtonBarVisibility();
+
+            if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+              setButtonWidthForExpressiveStyle(/* isDownButton= */ false);
+            }
           }
         }
       }
@@ -206,6 +247,20 @@ public class FooterBarMixin implements Mixin {
         a.getColor(R.styleable.SucFooterBarMixin_sucFooterBarSecondaryFooterBackground, 0);
     footerButtonAlignEnd =
         a.getBoolean(R.styleable.SucFooterBarMixin_sucFooterBarButtonAlignEnd, false);
+    footerBarPrimaryButtonEnabledTextColor =
+        a.getColor(
+            R.styleable.SucFooterBarMixin_sucFooterBarPrimaryFooterButtonEnabledTextColor, 0);
+    footerBarSecondaryButtonEnabledTextColor =
+        a.getColor(
+            R.styleable.SucFooterBarMixin_sucFooterBarSecondaryFooterButtonEnabledTextColor, 0);
+    footerBarPrimaryButtonDisabledTextColor =
+        a.getColor(
+            R.styleable.SucFooterBarMixin_sucFooterBarPrimaryFooterButtonDisabledTextColor, 0);
+    footerBarSecondaryButtonDisabledTextColor =
+        a.getColor(
+            R.styleable.SucFooterBarMixin_sucFooterBarSecondaryFooterButtonDisabledTextColor, 0);
+    footerBarButtonMiddleSpacing =
+        a.getDimensionPixelSize(R.styleable.SucFooterBarMixin_sucFooterBarButtonMiddleSpacing, 0);
 
     int primaryBtn =
         a.getResourceId(R.styleable.SucFooterBarMixin_sucFooterBarPrimaryFooterButton, 0);
@@ -379,15 +434,34 @@ public class FooterBarMixin implements Mixin {
   }
 
   /**
-   * Inflate FooterActionButton with layout "suc_button". Subclasses can implement this method to
+   * Inflate IFooterActionButton with layout "suc_button". Subclasses can implement this method to
    * modify the footer button layout as necessary.
    */
   @SuppressLint("InflateParams")
-  protected FooterActionButton createThemedButton(Context context, @StyleRes int theme) {
+  protected IFooterActionButton createThemedButton(Context context, @StyleRes int theme) {
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      try {
+        if (theme == R.style.SucGlifMaterialButton_Primary) {
+          return new MaterialFooterActionButton(
+              new ContextThemeWrapper(context, theme), null, R.attr.sucMaterialButtonStyle);
+        } else {
+          return new MaterialFooterActionButton(
+              new ContextThemeWrapper(context, theme), null, R.attr.sucMaterialOutlinedButtonStyle);
+        }
+      } catch (IllegalArgumentException e) {
+        LOG.e("Applyed invalid material theme: " + e);
+        // fallback theme style to glif theme
+        if (theme == R.style.SucGlifMaterialButton_Primary) {
+          theme = R.style.SucPartnerCustomizationButton_Primary;
+        } else {
+          theme = R.style.SucPartnerCustomizationButton_Secondary;
+        }
+      }
+    }
     // Inflate a single button from XML, which when using support lib, will take advantage of
     // the injected layout inflater and give us AppCompatButton instead.
     LayoutInflater inflater = LayoutInflater.from(new ContextThemeWrapper(context, theme));
-    return (FooterActionButton) inflater.inflate(R.layout.suc_button, null, false);
+    return (IFooterActionButton) inflater.inflate(R.layout.suc_button, null, false);
   }
 
   /** Sets primary button for footer. */
@@ -396,13 +470,21 @@ public class FooterBarMixin implements Mixin {
     ensureOnMainThread("setPrimaryButton");
     ensureFooterInflated();
 
+    int defaultPartnerTheme;
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      defaultPartnerTheme = R.style.SucGlifMaterialButton_Primary;
+    } else {
+      defaultPartnerTheme = R.style.SucPartnerCustomizationButton_Primary;
+    }
+
+    // TODO: b/364980746 - Use partner config to allow user to customize primary bg color.
     // Setup button partner config
     FooterButtonPartnerConfig footerButtonPartnerConfig =
         new FooterButtonPartnerConfig.Builder(footerButton)
             .setPartnerTheme(
                 getPartnerTheme(
                     footerButton,
-                    /* defaultPartnerTheme= */ R.style.SucPartnerCustomizationButton_Primary,
+                    /* defaultPartnerTheme= */ defaultPartnerTheme,
                     /* buttonBackgroundColorConfig= */ PartnerConfig
                         .CONFIG_FOOTER_PRIMARY_BUTTON_BG_COLOR))
             .setButtonBackgroundConfig(PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_BG_COLOR)
@@ -422,14 +504,32 @@ public class FooterBarMixin implements Mixin {
             .setTextStyleConfig(PartnerConfig.CONFIG_FOOTER_BUTTON_TEXT_STYLE)
             .build();
 
-    FooterActionButton button = inflateButton(footerButton, footerButtonPartnerConfig);
+    IFooterActionButton buttonImpl = inflateButton(footerButton, footerButtonPartnerConfig);
     // update information for primary button. Need to update as long as the button inflated.
+    Button button = (Button) buttonImpl;
     primaryButtonId = button.getId();
-    button.setPrimaryButtonStyle(/* isPrimaryButtonStyle= */ true);
+    if (buttonImpl instanceof MaterialFooterActionButton) {
+      ((MaterialFooterActionButton) buttonImpl)
+          .setPrimaryButtonStyle(/* isPrimaryButtonStyle= */ true);
+    } else if (button instanceof FooterActionButton) {
+      ((FooterActionButton) buttonImpl).setPrimaryButtonStyle(/* isPrimaryButtonStyle= */ true);
+    } else {
+      LOG.e("Set the primary button style error when setting primary button.");
+    }
     primaryButton = footerButton;
     primaryButtonPartnerConfigForTesting = footerButtonPartnerConfig;
     onFooterButtonInflated(button, footerBarPrimaryBackgroundColor);
     onFooterButtonApplyPartnerResource(button, footerButtonPartnerConfig);
+    // TODO: b/364981299 - Use partner config to allow user to customize text color.
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      boolean enabled = primaryButton.isEnabled();
+      updateTextColorForButton(
+          button,
+          enabled,
+          enabled
+              ? footerBarPrimaryButtonEnabledTextColor
+              : footerBarPrimaryButtonDisabledTextColor);
+    }
     if (loggingObserver != null) {
       loggingObserver.log(
           new ButtonInflatedEvent(getPrimaryButtonView(), LoggingObserver.ButtonType.PRIMARY));
@@ -439,6 +539,15 @@ public class FooterBarMixin implements Mixin {
     // Make sure the position of buttons are correctly and prevent primary button create twice or
     // more.
     repopulateButtons();
+
+    // The requestFocus() is only working after activity onResume.
+    button.post(
+        () -> {
+          if (KeyboardHelper.isKeyboardFocusEnhancementEnabled(context)
+              && KeyboardHelper.hasHardwareKeyboard(context)) {
+            button.requestFocus();
+          }
+        });
   }
 
   /** Returns the {@link FooterButton} of primary button. */
@@ -475,15 +584,26 @@ public class FooterBarMixin implements Mixin {
     isSecondaryButtonInPrimaryStyle = usePrimaryStyle;
     ensureFooterInflated();
 
+    int defaultPartnerTheme;
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      defaultPartnerTheme =
+          usePrimaryStyle
+              ? R.style.SucGlifMaterialButton_Primary
+              : R.style.SucGlifMaterialButton_Secondary;
+    } else {
+      defaultPartnerTheme =
+          usePrimaryStyle
+              ? R.style.SucPartnerCustomizationButton_Primary
+              : R.style.SucPartnerCustomizationButton_Secondary;
+    }
+
     // Setup button partner config
     FooterButtonPartnerConfig footerButtonPartnerConfig =
         new FooterButtonPartnerConfig.Builder(footerButton)
             .setPartnerTheme(
                 getPartnerTheme(
                     footerButton,
-                    /* defaultPartnerTheme= */ usePrimaryStyle
-                        ? R.style.SucPartnerCustomizationButton_Primary
-                        : R.style.SucPartnerCustomizationButton_Secondary,
+                    /* defaultPartnerTheme= */ defaultPartnerTheme,
                     /* buttonBackgroundColorConfig= */ usePrimaryStyle
                         ? PartnerConfig.CONFIG_FOOTER_PRIMARY_BUTTON_BG_COLOR
                         : PartnerConfig.CONFIG_FOOTER_SECONDARY_BUTTON_BG_COLOR))
@@ -512,15 +632,32 @@ public class FooterBarMixin implements Mixin {
             .setTextStyleConfig(PartnerConfig.CONFIG_FOOTER_BUTTON_TEXT_STYLE)
             .build();
 
-    FooterActionButton button = inflateButton(footerButton, footerButtonPartnerConfig);
+    IFooterActionButton buttonImpl = inflateButton(footerButton, footerButtonPartnerConfig);
     // update information for secondary button. Need to update as long as the button inflated.
+    Button button = (Button) buttonImpl;
     secondaryButtonId = button.getId();
-    button.setPrimaryButtonStyle(usePrimaryStyle);
+    if (buttonImpl instanceof MaterialFooterActionButton) {
+      ((MaterialFooterActionButton) buttonImpl).setPrimaryButtonStyle(usePrimaryStyle);
+    } else if (button instanceof FooterActionButton) {
+      ((FooterActionButton) buttonImpl).setPrimaryButtonStyle(usePrimaryStyle);
+    } else {
+      LOG.e("Set the primary button style error when setting secondary button.");
+    }
     secondaryButton = footerButton;
     secondaryButtonPartnerConfigForTesting = footerButtonPartnerConfig;
 
     onFooterButtonInflated(button, footerBarSecondaryBackgroundColor);
     onFooterButtonApplyPartnerResource(button, footerButtonPartnerConfig);
+    // TODO: b/364981299 - Use partner config to allow user to customize text color.
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      boolean enabled = secondaryButton.isEnabled();
+      updateTextColorForButton(
+          button,
+          enabled,
+          enabled
+              ? footerBarSecondaryButtonEnabledTextColor
+              : footerBarSecondaryButtonDisabledTextColor);
+    }
     if (loggingObserver != null) {
       loggingObserver.log(new ButtonInflatedEvent(button, LoggingObserver.ButtonType.SECONDARY));
       footerButton.setLoggingObserver(loggingObserver);
@@ -529,6 +666,18 @@ public class FooterBarMixin implements Mixin {
     // Make sure the position of buttons are correctly and prevent secondary button create twice or
     // more.
     repopulateButtons();
+
+    // The requestFocus() is only working after activity onResume.
+    button.post(
+        () -> {
+          if (KeyboardHelper.isKeyboardFocusEnhancementEnabled(context)
+              && KeyboardHelper.hasHardwareKeyboard(context)
+              && (primaryButtonId == 0
+                  // primary button may not be visible but it has been created
+                  || getPrimaryButtonView().getVisibility() != View.VISIBLE)) {
+            button.requestFocus();
+          }
+        });
   }
 
   /**
@@ -545,7 +694,10 @@ public class FooterBarMixin implements Mixin {
     boolean isLandscape =
         context.getResources().getConfiguration().orientation
             == Configuration.ORIENTATION_LANDSCAPE;
-    if (isLandscape && isEvenlyWeightedButtons && isFooterButtonAlignedEnd()) {
+    if (isLandscape
+        && isEvenlyWeightedButtons
+        && isFooterButtonAlignedEnd()
+        && !PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
       addSpace();
     }
 
@@ -562,7 +714,7 @@ public class FooterBarMixin implements Mixin {
       }
       buttonContainer.addView(tempSecondaryButton);
     }
-    if (!isFooterButtonAlignedEnd()) {
+    if (!isFooterButtonAlignedEnd() && !PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
       addSpace();
     }
     if (tempPrimaryButton != null) {
@@ -570,6 +722,10 @@ public class FooterBarMixin implements Mixin {
     }
 
     setEvenlyWeightedButtons(tempPrimaryButton, tempSecondaryButton, isEvenlyWeightedButtons);
+
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
+      setButtonWidthForExpressiveStyle(/* isDownButton= */ false);
+    }
   }
 
   private void setEvenlyWeightedButtons(
@@ -588,7 +744,7 @@ public class FooterBarMixin implements Mixin {
       if (primaryButton != null) {
         LinearLayout.LayoutParams primaryLayoutParams =
             (LinearLayout.LayoutParams) primaryButton.getLayoutParams();
-        if (null != primaryLayoutParams) {
+        if (primaryLayoutParams != null) {
           primaryLayoutParams.width = ViewGroup.LayoutParams.WRAP_CONTENT;
           primaryLayoutParams.weight = 0;
           primaryButton.setLayoutParams(primaryLayoutParams);
@@ -597,7 +753,7 @@ public class FooterBarMixin implements Mixin {
       if (secondaryButton != null) {
         LinearLayout.LayoutParams secondaryLayoutParams =
             (LinearLayout.LayoutParams) secondaryButton.getLayoutParams();
-        if (null != secondaryLayoutParams) {
+        if (secondaryLayoutParams != null) {
           secondaryLayoutParams.width = ViewGroup.LayoutParams.WRAP_CONTENT;
           secondaryLayoutParams.weight = 0;
           secondaryButton.setLayoutParams(secondaryLayoutParams);
@@ -606,6 +762,209 @@ public class FooterBarMixin implements Mixin {
     }
   }
 
+  // TODO: b/369285240 - Migrate setButtonWidthForExpressiveStyle of FooterBarMixin to
+  /** Sets button width for expressive style. */
+  public void setButtonWidthForExpressiveStyle(boolean isDownButton) {
+    final ViewTreeObserver.OnGlobalLayoutListener onGlobalLayoutListener =
+        new OnGlobalLayoutListener() {
+          @Override
+          public void onGlobalLayout() {
+            int initialLeftMargin = 0;
+            if (!isDownButton) {
+              Button primaryButton = getPrimaryButtonView();
+              Button secondaryButton = getSecondaryButtonView();
+              DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
+              int screenWidth = displayMetrics.widthPixels;
+              if (isTwoPaneLayout()) {
+                screenWidth = screenWidth / 2;
+                if (primaryButton != null) {
+                  // Set back the margin once down button scrolling to the bottom.
+                  LinearLayout.LayoutParams primaryLayoutParams =
+                      ((LayoutParams) primaryButton.getLayoutParams());
+                  if (primaryLayoutParams.leftMargin != initialLeftMargin) {
+                    primaryLayoutParams.leftMargin = initialLeftMargin;
+                    primaryButton.setLayoutParams(primaryLayoutParams);
+                  }
+                }
+                buttonContainer.setGravity(Gravity.END);
+              }
+
+              // TODO: b/364981820 - Use partner config to allow user to customize button width.
+              int availableFooterBarWidth =
+                  screenWidth
+                      - footerBarPaddingStart
+                      - footerBarPaddingEnd
+                      - footerBarButtonMiddleSpacing;
+              int maxButtonWidth = availableFooterBarWidth / 2;
+              if (isBothButtons(primaryButton, secondaryButton)) {
+                LayoutParams primaryLayoutParams = (LayoutParams) primaryButton.getLayoutParams();
+                LayoutParams secondaryLayoutParams =
+                    (LayoutParams) secondaryButton.getLayoutParams();
+
+                boolean isPrimaryTextTooLong = isTextTooLong(primaryButton, maxButtonWidth);
+                boolean isSecondaryTextTooLong = isTextTooLong(secondaryButton, maxButtonWidth);
+
+                if (isPrimaryTextTooLong || isSecondaryTextTooLong) {
+                  if (buttonContainer instanceof ButtonBarLayout) {
+                    ((ButtonBarLayout) buttonContainer).setStackedButtonForExpressiveStyle(true);
+                  }
+                  int stackButtonMiddleSpacing = footerBarButtonMiddleSpacing / 2;
+                  primaryLayoutParams.width = availableFooterBarWidth;
+                  primaryLayoutParams.bottomMargin = stackButtonMiddleSpacing;
+                  primaryButton.setLayoutParams(primaryLayoutParams);
+
+                  secondaryLayoutParams.width = availableFooterBarWidth;
+                  secondaryLayoutParams.topMargin = stackButtonMiddleSpacing;
+                  secondaryButton.setLayoutParams(secondaryLayoutParams);
+                } else {
+                  if (primaryLayoutParams != null) {
+                    primaryLayoutParams.width = maxButtonWidth;
+                    primaryLayoutParams.setMarginStart(footerBarButtonMiddleSpacing / 2);
+                    primaryButton.setLayoutParams(primaryLayoutParams);
+                  }
+                  if (secondaryLayoutParams != null) {
+                    secondaryLayoutParams.width = maxButtonWidth;
+                    secondaryLayoutParams.setMarginEnd(footerBarButtonMiddleSpacing / 2);
+                    secondaryButton.setLayoutParams(secondaryLayoutParams);
+                  }
+                }
+              } else if (isPrimaryButtonOnly(primaryButton, secondaryButton)) {
+                LayoutParams primaryLayoutParams = (LayoutParams) primaryButton.getLayoutParams();
+                if (primaryLayoutParams != null) {
+                  primaryLayoutParams.width = availableFooterBarWidth;
+                  primaryButton.setLayoutParams(primaryLayoutParams);
+                }
+              } else if (isSecondaryOnly(primaryButton, secondaryButton)) {
+                LayoutParams secondaryLayoutParams =
+                    (LayoutParams) secondaryButton.getLayoutParams();
+                if (secondaryLayoutParams != null) {
+                  secondaryLayoutParams.width = availableFooterBarWidth;
+                  secondaryButton.setLayoutParams(secondaryLayoutParams);
+                }
+              } else {
+                LOG.atInfo("There are no button visible in the footer bar.");
+              }
+            } else {
+              // Only allow primary button been shown on the screen if in the down button style.
+              if (getSecondaryButtonView() != null) {
+                getSecondaryButtonView().setVisibility(View.GONE);
+              }
+              setDownButtonStyle(getPrimaryButtonView());
+              if (!isTwoPaneLayout()) {
+                buttonContainer.setGravity(Gravity.CENTER_HORIZONTAL | Gravity.CENTER_VERTICAL);
+              } else {
+                buttonContainer.setGravity(Gravity.CENTER_VERTICAL);
+                int containerWidth = buttonContainer.getWidth();
+                Button downButtonView = getPrimaryButtonView();
+                LayoutParams primaryLayoutParams = (LayoutParams) downButtonView.getLayoutParams();
+                int halfContainerWidth = containerWidth / 2;
+                // Put down button to the center of the one side in two pane mode.
+                primaryLayoutParams.setMarginStart(
+                    (halfContainerWidth
+                        + (halfContainerWidth / 2 - downButtonView.getWidth() / 2)));
+                downButtonView.setLayoutParams(primaryLayoutParams);
+              }
+            }
+            buttonContainer.getViewTreeObserver().removeOnGlobalLayoutListener(this);
+          }
+        };
+
+    buttonContainer.getViewTreeObserver().addOnGlobalLayoutListener(onGlobalLayoutListener);
+  }
+
+  // TODO: b/376153500 - Add a test case for button stack mechanism.
+  private boolean isTextTooLong(Button button, float maxButtonWidth) {
+    String text = button.getText().toString();
+    TextPaint textPaint = button.getPaint();
+
+    int buttonWidth = (int) maxButtonWidth - button.getPaddingLeft() - button.getPaddingRight();
+
+    // Generate a static layout to see if text requires switching lines.
+    StaticLayout staticLayout =
+        new StaticLayout(
+            text,
+            textPaint,
+            buttonWidth,
+            Alignment.ALIGN_CENTER,
+            /* spacingMult= */ 1.0f,
+            /* spacingAdd= */ 0.0f,
+            /* includePad= */ false);
+    return staticLayout.getLineCount() > 1;
+  }
+
+  private boolean isTwoPaneLayout() {
+    return context.getResources().getBoolean(R.bool.sucTwoPaneLayoutStyle);
+  }
+
+  private boolean isBothButtons(Button primaryButton, Button secondaryButton) {
+    boolean isPrimaryVisible =
+        primaryButton != null && primaryButton.getVisibility() == View.VISIBLE;
+    boolean isSecondaryVisible =
+        secondaryButton != null && secondaryButton.getVisibility() == View.VISIBLE;
+    LOG.atDebug(
+        "isPrimaryVisible=" + isPrimaryVisible + ", isSecondaryVisible=" + isSecondaryVisible);
+    return isPrimaryVisible && isSecondaryVisible;
+  }
+
+  private boolean isPrimaryButtonOnly(Button primaryButton, Button secondaryButton) {
+    boolean isPrimaryOnly = primaryButton != null && secondaryButton == null;
+    boolean isPrimaryOnlyButSecondaryInvisible =
+        (primaryButton != null)
+            && (secondaryButton != null && secondaryButton.getVisibility() != View.VISIBLE);
+    LOG.atDebug(
+        "isPrimaryOnly="
+            + isPrimaryOnly
+            + ", isPrimaryOnlyButSecondaryInvisible="
+            + isPrimaryOnlyButSecondaryInvisible);
+    return isPrimaryOnly || isPrimaryOnlyButSecondaryInvisible;
+  }
+
+  private boolean isSecondaryOnly(Button primaryButton, Button secondaryButton) {
+    boolean isSecondaryOnly = secondaryButton != null && primaryButton == null;
+    boolean isSecondaryOnlyButPrimaryInvisible =
+        (secondaryButton != null)
+            && (primaryButton != null && primaryButton.getVisibility() != View.VISIBLE);
+    LOG.atDebug(
+        "isSecondaryOnly="
+            + isSecondaryOnly
+            + ", isSecondaryOnlyButPrimaryInvisible="
+            + isSecondaryOnlyButPrimaryInvisible);
+    return isSecondaryOnly || isSecondaryOnlyButPrimaryInvisible;
+  }
+
+  private void setDownButtonStyle(Button button) {
+    // TODO: b/364121308 - Extract values as attributes.
+    int width =
+        context.getResources().getDimensionPixelSize(R.dimen.suc_glif_expressive_down_button_width);
+    int height =
+        context
+            .getResources()
+            .getDimensionPixelSize(R.dimen.suc_glif_expressive_down_button_height);
+
+    if (button != null) {
+      LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) button.getLayoutParams();
+      layoutParams.width = width;
+      layoutParams.height = height;
+      button.setLayoutParams(layoutParams);
+    }
+    setDownButtonRadius(button);
+  }
+
+  private void setDownButtonRadius(Button button) {
+    float radius =
+        context.getResources().getDimension(R.dimen.suc_glif_expressive_down_button_radius);
+    if (button != null) {
+      if (button instanceof MaterialButton) {
+        ((MaterialButton) button).setCornerRadius((int) radius);
+      } else {
+        GradientDrawable gradientDrawable = FooterButtonStyleUtils.getGradientDrawable(button);
+        if (gradientDrawable != null) {
+          gradientDrawable.setCornerRadius(radius);
+        }
+      }
+    }
+  }
+
   /**
    * Notifies that the footer button has been inInflated and add to the view hierarchy. Calling
    * super is necessary while subclass implement it.
@@ -631,7 +990,9 @@ public class FooterBarMixin implements Mixin {
     int overrideTheme = footerButton.getTheme();
 
     // Set the default theme if theme is not set, or when running in setup flow.
-    if (footerButton.getTheme() == 0 || applyPartnerResources) {
+    if (footerButton.getTheme() == 0
+        || applyPartnerResources
+        || PartnerConfigHelper.isGlifExpressiveEnabled(context)) {
       overrideTheme = defaultPartnerTheme;
     }
     // TODO: Make sure customize attributes in theme can be applied during setup flow.
@@ -640,9 +1001,15 @@ public class FooterBarMixin implements Mixin {
     if (applyPartnerResources) {
       int color = PartnerConfigHelper.get(context).getColor(context, buttonBackgroundColorConfig);
       if (color == Color.TRANSPARENT) {
-        overrideTheme = R.style.SucPartnerCustomizationButton_Secondary;
+        overrideTheme =
+            PartnerConfigHelper.isGlifExpressiveEnabled(context)
+                ? R.style.SucGlifMaterialButton_Secondary
+                : R.style.SucPartnerCustomizationButton_Secondary;
       } else {
-        overrideTheme = R.style.SucPartnerCustomizationButton_Primary;
+        overrideTheme =
+            PartnerConfigHelper.isGlifExpressiveEnabled(context)
+                ? R.style.SucGlifMaterialButton_Primary
+                : R.style.SucPartnerCustomizationButton_Primary;
       }
     }
     return overrideTheme;
@@ -710,10 +1077,11 @@ public class FooterBarMixin implements Mixin {
         && getSecondaryButtonView().getVisibility() == View.VISIBLE;
   }
 
-  private FooterActionButton inflateButton(
+  private IFooterActionButton inflateButton(
       FooterButton footerButton, FooterButtonPartnerConfig footerButtonPartnerConfig) {
-    FooterActionButton button =
+    IFooterActionButton buttonImpl =
         createThemedButton(context, footerButtonPartnerConfig.getPartnerTheme());
+    Button button = (Button) buttonImpl;
     button.setId(View.generateViewId());
 
     // apply initial configuration into button view.
@@ -721,10 +1089,15 @@ public class FooterBarMixin implements Mixin {
     button.setOnClickListener(footerButton);
     button.setVisibility(footerButton.getVisibility());
     button.setEnabled(footerButton.isEnabled());
-    button.setFooterButton(footerButton);
-
+    if (buttonImpl instanceof MaterialFooterActionButton) {
+      ((MaterialFooterActionButton) buttonImpl).setFooterButton(footerButton);
+    } else if (button instanceof FooterActionButton) {
+      ((FooterActionButton) buttonImpl).setFooterButton(footerButton);
+    } else {
+      LOG.e("Set the footer button error!");
+    }
     footerButton.setOnButtonEventListener(createButtonEventListener(button.getId()));
-    return button;
+    return buttonImpl;
   }
 
   // TODO: Make sure customize attributes in theme can be applied during setup flow.
@@ -850,4 +1223,12 @@ public class FooterBarMixin implements Mixin {
   public PersistableBundle getLoggingMetrics() {
     return metrics.getMetrics();
   }
+
+  private void updateTextColorForButton(Button button, boolean enable, int color) {
+    if (enable) {
+      FooterButtonStyleUtils.updateButtonTextEnabledColor(button, color);
+    } else {
+      FooterButtonStyleUtils.updateButtonTextDisabledColor(button, color);
+    }
+  }
 }
diff --git a/main/java/com/google/android/setupcompat/template/FooterButton.java b/main/java/com/google/android/setupcompat/template/FooterButton.java
index 38b81c2..33bf265 100644
--- a/main/java/com/google/android/setupcompat/template/FooterButton.java
+++ b/main/java/com/google/android/setupcompat/template/FooterButton.java
@@ -80,6 +80,7 @@ public final class FooterButton implements OnClickListener {
    * @param listener The listener for button.
    * @param buttonType The type of button.
    * @param theme The theme for button.
+   * @param visibility the visibility for button.
    */
   private FooterButton(
       CharSequence text,
@@ -87,13 +88,15 @@ public final class FooterButton implements OnClickListener {
       @ButtonType int buttonType,
       @StyleRes int theme,
       Locale locale,
-      int direction) {
+      int direction,
+      int visibility) {
     this.text = text;
     onClickListener = listener;
     this.buttonType = buttonType;
     this.theme = theme;
     this.locale = locale;
     this.direction = direction;
+    this.visibility = visibility;
   }
 
   /** Returns the text that this footer button is displaying. */
@@ -366,6 +369,7 @@ public final class FooterButton implements OnClickListener {
    *         .setTheme(R.style.SuwGlifButton_Primary)
    *         .setTextLocale(Locale.CANADA)
    *         .setLayoutDirection(View.LAYOUT_DIRECTION_LTR)
+   *         .setVisibility(View.VISIBLE)
    *         .build();
    * </pre>
    */
@@ -378,6 +382,8 @@ public final class FooterButton implements OnClickListener {
     @ButtonType private int buttonType = ButtonType.OTHER;
     private int theme = 0;
 
+    private int visibility = View.VISIBLE;
+
     public Builder(@NonNull Context context) {
       this.context = context;
     }
@@ -424,8 +430,15 @@ public final class FooterButton implements OnClickListener {
       return this;
     }
 
+    /** Sets the {@code visibility} of FooterButton. */
+    public Builder setVisibility(int visibility) {
+      this.visibility = visibility;
+      return this;
+    }
+
     public FooterButton build() {
-      return new FooterButton(text, onClickListener, buttonType, theme, locale, direction);
+      return new FooterButton(
+          text, onClickListener, buttonType, theme, locale, direction, visibility);
     }
   }
 }
diff --git a/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java b/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java
index fc56aad..3045002 100644
--- a/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java
+++ b/main/java/com/google/android/setupcompat/template/FooterButtonStyleUtils.java
@@ -291,12 +291,12 @@ public class FooterButtonStyleUtils {
       }
       float alpha =
           PartnerConfigHelper.get(context).getFraction(context, buttonRippleColorAlphaConfig);
-      updateButtonRippleColor(button, textDefaultColor, alpha);
+      updateButtonRippleColor(context, button, textDefaultColor, alpha);
     }
   }
 
   private static void updateButtonRippleColor(
-      Button button, @ColorInt int textColor, float rippleAlpha) {
+      Context context, Button button, @ColorInt int textColor, float rippleAlpha) {
     // RippleDrawable is available after sdk 21. And because on lower sdk the RippleDrawable is
     // unavailable. Since Stencil customization provider only works on Q+, there is no need to
     // perform any customization for versions 21.
@@ -315,7 +315,13 @@ public class FooterButtonStyleUtils {
           new ColorStateList(
               new int[][] {pressedState, focusState, StateSet.NOTHING},
               new int[] {argbColor, argbColor, Color.TRANSPARENT});
-      rippleDrawable.setColor(colorStateList);
+      if (PartnerConfigHelper.isGlifExpressiveEnabled(context)
+          && button instanceof MaterialFooterActionButton) {
+        MaterialFooterActionButton materialButton = (MaterialFooterActionButton) button;
+        materialButton.setRippleColor(colorStateList);
+      } else {
+        rippleDrawable.setColor(colorStateList);
+      }
     }
   }
 
@@ -388,9 +394,15 @@ public class FooterButtonStyleUtils {
       Context context, Button button, PartnerConfig buttonRadiusConfig) {
     if (Build.VERSION.SDK_INT >= VERSION_CODES.N) {
       float radius = PartnerConfigHelper.get(context).getDimension(context, buttonRadiusConfig);
-      GradientDrawable gradientDrawable = getGradientDrawable(button);
-      if (gradientDrawable != null) {
-        gradientDrawable.setCornerRadius(radius);
+      if (PartnerConfigHelper.isGlifExpressiveEnabled(context)
+          && button instanceof MaterialFooterActionButton) {
+        MaterialFooterActionButton materialButton = (MaterialFooterActionButton) button;
+        materialButton.setCornerRadius((int) radius);
+      } else {
+        GradientDrawable gradientDrawable = getGradientDrawable(button);
+        if (gradientDrawable != null) {
+          gradientDrawable.setCornerRadius(radius);
+        }
       }
     }
   }
diff --git a/main/java/com/google/android/setupcompat/template/IFooterActionButton.java b/main/java/com/google/android/setupcompat/template/IFooterActionButton.java
new file mode 100644
index 0000000..59f7bed
--- /dev/null
+++ b/main/java/com/google/android/setupcompat/template/IFooterActionButton.java
@@ -0,0 +1,42 @@
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
+package com.google.android.setupcompat.template;
+
+import android.view.MotionEvent;
+
+/**
+ * Interface for footer action buttons in Setup library to indicate Android Button or Material
+ * button classes.
+ *
+ * <p>This interface defines common methods for footer action buttons, regardless of their specific
+ * implementation. It provides a way to interact with footer buttons and determine their style
+ * attributes.
+ */
+public interface IFooterActionButton {
+
+  /**
+   * Handles touch events for the footer action button, ensuring accessibility and proper behavior
+   * even when the button is disabled.
+   *
+   * @param event The MotionEvent object representing the touch event.
+   * @return true if the event was consumed by the button, false otherwise.
+   */
+  boolean onTouchEvent(MotionEvent event);
+
+  /** Returns true when the footer button is primary button style. */
+  boolean isPrimaryButtonStyle();
+}
diff --git a/main/java/com/google/android/setupcompat/template/MaterialFooterActionButton.java b/main/java/com/google/android/setupcompat/template/MaterialFooterActionButton.java
new file mode 100644
index 0000000..da86746
--- /dev/null
+++ b/main/java/com/google/android/setupcompat/template/MaterialFooterActionButton.java
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
+package com.google.android.setupcompat.template;
+
+import android.annotation.SuppressLint;
+import android.content.Context;
+import android.util.AttributeSet;
+import android.view.MotionEvent;
+import android.view.View;
+import androidx.annotation.VisibleForTesting;
+import com.google.android.material.button.MaterialButton;
+
+/** Material Button that can react to touch when disabled. */
+public class MaterialFooterActionButton extends MaterialButton implements IFooterActionButton {
+  @VisibleForTesting FooterButton footerButton;
+  private boolean isPrimaryButtonStyle = false;
+
+  public MaterialFooterActionButton(Context context, AttributeSet attrs) {
+    super(context, attrs);
+  }
+
+  public MaterialFooterActionButton(Context context, AttributeSet attrs, int value) {
+    super(context, attrs, value);
+  }
+
+  void setFooterButton(FooterButton footerButton) {
+    this.footerButton = footerButton;
+  }
+
+  @SuppressLint("ClickableViewAccessibility")
+  @Override
+  public boolean onTouchEvent(MotionEvent event) {
+    if (event.getAction() == MotionEvent.ACTION_DOWN) {
+      if (footerButton != null
+          && !footerButton.isEnabled()
+          && footerButton.getVisibility() == View.VISIBLE) {
+        // getOnClickListenerWhenDisabled is responsible for handling accessibility correctly,
+        // calling performClick if necessary.
+        OnClickListener listener = footerButton.getOnClickListenerWhenDisabled();
+        if (listener != null) {
+          listener.onClick(this);
+        }
+      }
+    }
+    return super.onTouchEvent(event);
+  }
+
+  /**
+   * Sets this footer button is primary button style.
+   *
+   * @param isPrimaryButtonStyle True if this button is primary button style.
+   */
+  void setPrimaryButtonStyle(boolean isPrimaryButtonStyle) {
+    this.isPrimaryButtonStyle = isPrimaryButtonStyle;
+  }
+
+  @Override
+  public boolean isPrimaryButtonStyle() {
+    return isPrimaryButtonStyle;
+  }
+}
diff --git a/main/java/com/google/android/setupcompat/util/BuildCompatUtils.java b/main/java/com/google/android/setupcompat/util/BuildCompatUtils.java
index ef14d04..5049006 100644
--- a/main/java/com/google/android/setupcompat/util/BuildCompatUtils.java
+++ b/main/java/com/google/android/setupcompat/util/BuildCompatUtils.java
@@ -56,35 +56,13 @@ public final class BuildCompatUtils {
   }
 
   /**
-   * Implementation of BuildCompat.isAtLeast*() suitable for use in Setup
-   *
-   * <p>BuildCompat.isAtLeast*() can be changed by Android Release team, and once that is changed it
-   * may take weeks for that to propagate to stable/prerelease/experimental SDKs in Google3. Also it
-   * can be different in all these channels. This can cause random issues, especially with sidecars
-   * (i.e., the code running on R may not know that it runs on R).
-   *
-   * <p>This still should try using BuildCompat.isAtLeastR() as source of truth, but also checking
-   * for VERSION_SDK_INT and VERSION.CODENAME in case when BuildCompat implementation returned
-   * false. Note that both checks should be >= and not = to make sure that when Android version
-   * increases (i.e., from R to S), this does not stop working.
-   *
-   * <p>Supported configurations:
-   *
-   * <ul>
-   *   <li>For current Android release: while new API is not finalized yet (CODENAME =
-   *       "UpsideDownCake", SDK_INT = 33)
-   *   <li>For current Android release: when new API is finalized (CODENAME = "REL", SDK_INT = 34)
-   *   <li>For next Android release (CODENAME = "VanillaIceCream", SDK_INT = 35+)
-   * </ul>
-   *
-   * <p>Note that Build.VERSION_CODES.T cannot be used here until final SDK is available in all
-   * channels, because it is equal to Build.VERSION_CODES.CUR_DEVELOPMENT before API finalization.
+   * Implementation of BuildCompat.isAtLeastU() suitable for use in Setup
    *
    * @return Whether the current OS version is higher or equal to U.
    */
+  @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
   public static boolean isAtLeastU() {
-    return (Build.VERSION.CODENAME.equals("REL") && Build.VERSION.SDK_INT >= 34)
-        || isAtLeastPreReleaseCodename("UpsideDownCake");
+    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE;
   }
 
   /**
@@ -97,16 +75,5 @@ public final class BuildCompatUtils {
     return Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM;
   }
 
-  private static boolean isAtLeastPreReleaseCodename(String codename) {
-    // Special case "REL", which means the build is not a pre-release build.
-    if (Build.VERSION.CODENAME.equals("REL")) {
-      return false;
-    }
-
-    // Otherwise lexically compare them. Return true if the build codename is equal to or
-    // greater than the requested codename.
-    return Build.VERSION.CODENAME.compareTo(codename) >= 0;
-  }
-
   private BuildCompatUtils() {}
 }
\ No newline at end of file
diff --git a/main/java/com/google/android/setupcompat/util/KeyboardHelper.java b/main/java/com/google/android/setupcompat/util/KeyboardHelper.java
new file mode 100644
index 0000000..2f5f490
--- /dev/null
+++ b/main/java/com/google/android/setupcompat/util/KeyboardHelper.java
@@ -0,0 +1,39 @@
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
+package com.google.android.setupcompat.util;
+
+import android.content.Context;
+import android.content.res.Configuration;
+import androidx.annotation.NonNull;
+import com.google.android.setupcompat.partnerconfig.PartnerConfigHelper;
+
+/** Helper class to handle keyboard related operations. */
+public final class KeyboardHelper {
+
+  /** Returns whether the keyboard focus changed is enabled. */
+  public static boolean isKeyboardFocusEnhancementEnabled(@NonNull Context context) {
+    return PartnerConfigHelper.isKeyboardFocusEnhancementEnabled(context);
+  }
+
+  /** Returns whether a physical keyboard is available. */
+  public static boolean hasHardwareKeyboard(Context context) {
+    Configuration configuration = context.getResources().getConfiguration();
+    return configuration.keyboard != Configuration.KEYBOARD_NOKEYS
+        && configuration.hardKeyboardHidden != Configuration.HARDKEYBOARDHIDDEN_YES;
+  }
+
+  private KeyboardHelper() {}
+}
diff --git a/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java b/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java
index 9c73ea9..2b0aedf 100644
--- a/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java
+++ b/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java
@@ -22,7 +22,6 @@ import android.content.Intent;
 import android.os.Build;
 import android.provider.Settings;
 import androidx.annotation.Nullable;
-import androidx.annotation.VisibleForTesting;
 import com.google.errorprone.annotations.InlineMe;
 import java.util.Arrays;
 
@@ -52,10 +51,12 @@ public final class WizardManagerHelper {
   /** Extra for notifying an Activity that what SetupWizard flow is. */
   public static final String EXTRA_SUW_LIFECYCLE = "suw_lifecycle";
 
-  @VisibleForTesting public static final String ACTION_NEXT = "com.android.wizard.NEXT";
+  public static final String ACTION_NEXT = "com.android.wizard.NEXT";
 
   public static final String EXTRA_WIZARD_BUNDLE = "wizardBundle";
-  private static final String EXTRA_RESULT_CODE = "com.android.setupwizard.ResultCode";
+
+  /** Extra used for including the resultcode of a wizardmanager action. */
+  public static final String EXTRA_RESULT_CODE = "com.android.setupwizard.ResultCode";
 
   /** Extra for notifying an Activity that it is inside the first SetupWizard flow or not. */
   public static final String EXTRA_IS_FIRST_RUN = "firstRun";
diff --git a/main/java/com/google/android/setupcompat/view/ButtonBarLayout.java b/main/java/com/google/android/setupcompat/view/ButtonBarLayout.java
index 7500f26..4b37bf8 100644
--- a/main/java/com/google/android/setupcompat/view/ButtonBarLayout.java
+++ b/main/java/com/google/android/setupcompat/view/ButtonBarLayout.java
@@ -42,6 +42,8 @@ public class ButtonBarLayout extends LinearLayout {
   private int originalPaddingLeft;
   private int originalPaddingRight;
 
+  private boolean stackedButtonForExpressiveStyle;
+
   public ButtonBarLayout(Context context) {
     super(context);
   }
@@ -70,7 +72,8 @@ public class ButtonBarLayout extends LinearLayout {
 
     super.onMeasure(initialWidthMeasureSpec, heightMeasureSpec);
 
-    final boolean childrenLargerThanContainer = (widthSize > 0) && (getMeasuredWidth() > widthSize);
+    final boolean childrenLargerThanContainer =
+        ((widthSize > 0) && (getMeasuredWidth() > widthSize)) || stackedButtonForExpressiveStyle;
     if (!isFooterButtonsEvenlyWeighted(getContext()) && childrenLargerThanContainer) {
       setStacked(true);
 
@@ -133,8 +136,15 @@ public class ButtonBarLayout extends LinearLayout {
     }
 
     if (stacked) {
-      // When stacked, the buttons need to be kept in the center of the button bar.
-      setHorizontalGravity(Gravity.CENTER);
+      if (getContext().getResources().getBoolean(R.bool.sucTwoPaneLayoutStyle)
+          && PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
+        // When device in the two pane mode and glif expressive flag enabled, the button should
+        // aligned to the end.
+        setHorizontalGravity(Gravity.END);
+      } else {
+        // When stacked, the buttons need to be kept in the center of the button bar.
+        setHorizontalGravity(Gravity.CENTER);
+      }
       // HACK: In the default button bar style, the left and right paddings are not
       // balanced to compensate for different alignment for borderless (left) button and
       // the raised (right) button. When it's stacked, we want the buttons to be centered,
@@ -217,4 +227,12 @@ public class ButtonBarLayout extends LinearLayout {
       return false;
     }
   }
+
+  public void setStackedButtonForExpressiveStyle(boolean isStacked) {
+    if (PartnerConfigHelper.isGlifExpressiveEnabled(getContext())) {
+      stackedButtonForExpressiveStyle = isStacked;
+    } else {
+      stackedButtonForExpressiveStyle = false;
+    }
+  }
 }
diff --git a/main/res/values-w600dp-h900dp-v35/config.xml b/main/res/values-w600dp-h900dp-v35/config.xml
new file mode 100644
index 0000000..01b6054
--- /dev/null
+++ b/main/res/values-w600dp-h900dp-v35/config.xml
@@ -0,0 +1,23 @@
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
+    <!-- A boolean value that indicates whether the device should show two panes. -->
+    <bool name="sucTwoPaneLayoutStyle">false</bool>
+
+</resources>
diff --git a/main/res/values-w600dp-v35/config.xml b/main/res/values-w600dp-v35/config.xml
new file mode 100644
index 0000000..a1950b0
--- /dev/null
+++ b/main/res/values-w600dp-v35/config.xml
@@ -0,0 +1,23 @@
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
+    <!-- A boolean value that indicates whether the device should show two panes. -->
+    <bool name="sucTwoPaneLayoutStyle">true</bool>
+
+</resources>
diff --git a/main/res/values/attrs.xml b/main/res/values/attrs.xml
index 0aaea8b..deefea6 100644
--- a/main/res/values/attrs.xml
+++ b/main/res/values/attrs.xml
@@ -85,12 +85,17 @@
         <attr name="sucFooterBarButtonAlignEnd" format="boolean" />
         <attr name="sucFooterBarButtonCornerRadius" format="dimension" />
         <attr name="sucFooterBarButtonFontFamily" format="string|reference" />
+        <attr name="sucFooterBarButtonMinHeight" format="dimension" />
         <attr name="sucFooterBarPaddingTop" format="dimension" />
         <attr name="sucFooterBarPaddingBottom" format="dimension" />
         <attr name="sucFooterBarPrimaryFooterBackground" format="color" />
         <attr name="sucFooterBarPrimaryFooterButton" format="reference" />
+        <attr name="sucFooterBarPrimaryFooterButtonEnabledTextColor" format="color" />
+        <attr name="sucFooterBarPrimaryFooterButtonDisabledTextColor" format="color" />
         <attr name="sucFooterBarSecondaryFooterBackground" format="color" />
         <attr name="sucFooterBarSecondaryFooterButton" format="reference" />
+        <attr name="sucFooterBarSecondaryFooterButtonEnabledTextColor" format="color" />
+        <attr name="sucFooterBarSecondaryFooterButtonDisabledTextColor" format="color" />
         <attr name="sucFooterBarButtonHighlightAlpha" format="float" />
         <attr name="sucFooterBarButtonColorControlHighlight" format="color" />
         <attr name="sucFooterBarButtonColorControlHighlightRipple" format="color" />
@@ -98,6 +103,10 @@
         <attr name="sucFooterBarPaddingStart" format="dimension" />
         <attr name="sucFooterBarPaddingEnd" format="dimension" />
         <attr name="sucFooterBarMinHeight" format="dimension" />
+        <attr name="sucFooterBarButtonMiddleSpacing" format="dimension" />
+        <attr name="sucFooterBarButtonFontWeight" format="integer" />
+        <attr name="sucFooterBarButtonTextSize" format="dimension" />
+        <attr name="sucFooterButtonTextLineSpacingExtra" format="dimension" />
     </declare-styleable>
 
     <declare-styleable name="SucHeaderMixin">
@@ -109,4 +118,8 @@
         <attr name="sucHeaderContainerMarginBottom" format="dimension" />
     </declare-styleable>
 
+    <attr name="sucMaterialOutlinedButtonStyle" format="reference" />
+
+    <attr name="sucMaterialButtonStyle" format="reference" />
+
 </resources>
diff --git a/main/res/values/config.xml b/main/res/values/config.xml
index 99bad1c..80a31d7 100644
--- a/main/res/values/config.xml
+++ b/main/res/values/config.xml
@@ -20,4 +20,7 @@
     <!-- ID used with View#setTag to store the original weight on a ButtonBar -->
     <item name="suc_customization_original_weight" type="id" />
 
+    <!-- A boolean value that indicates whether the device should show two panes. -->
+    <bool name="sucTwoPaneLayoutStyle">false</bool>
+
 </resources>
diff --git a/main/res/values/dimens.xml b/main/res/values/dimens.xml
new file mode 100644
index 0000000..8809bf3
--- /dev/null
+++ b/main/res/values/dimens.xml
@@ -0,0 +1,10 @@
+<?xml version="1.0" encoding="utf-8"?>
+<resources>
+
+  <!-- TODO: b/370872815 - Migrate down button values to design lib. -->
+  <!-- Glif expressive down button -->
+  <dimen name="suc_glif_expressive_down_button_width">72dp</dimen>
+  <dimen name="suc_glif_expressive_down_button_height">56dp</dimen>
+  <dimen name="suc_glif_expressive_down_button_radius">28dp</dimen>
+
+</resources>
\ No newline at end of file
diff --git a/main/res/values/styles.xml b/main/res/values/styles.xml
index 6625e83..7b8e17d 100644
--- a/main/res/values/styles.xml
+++ b/main/res/values/styles.xml
@@ -45,7 +45,7 @@
         <item name="android:theme">@style/SucPartnerCustomizationButton.Primary</item>
 
         <!-- Values used in styles -->
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">?attr/sucFooterBarButtonFontFamily</item>
+        <item name="android:fontFamily">?attr/sucFooterBarButtonFontFamily</item>
         <item name="android:paddingLeft">?attr/sucFooterButtonPaddingStart</item>
         <item name="android:paddingStart" tools:ignore="NewApi">?attr/sucFooterButtonPaddingStart</item>
         <item name="android:paddingRight">?attr/sucFooterButtonPaddingEnd</item>
@@ -65,7 +65,7 @@
         <item name="android:theme">@style/SucPartnerCustomizationButton.Secondary</item>
 
         <!-- Values used in styles -->
-        <item name="android:fontFamily" tools:targetApi="jelly_bean">?attr/sucFooterBarButtonFontFamily</item>
+        <item name="android:fontFamily">?attr/sucFooterBarButtonFontFamily</item>
         <item name="android:minWidth">0dp</item>
         <item name="android:paddingLeft">?attr/sucFooterButtonPaddingStart</item>
         <item name="android:paddingStart" tools:ignore="NewApi">?attr/sucFooterButtonPaddingStart</item>
@@ -79,4 +79,63 @@
         <item name="sucFooterBarButtonColorControlHighlight">@color/suc_customization_button_highlight_ripple</item>
     </style>
 
+    <style name="SucGlifMaterialButton.Primary" parent="Widget.Material3.Button">
+        <!-- This style can be applied to a button either as a "style" in XML, or as a theme in
+             ContextThemeWrapper. These self-referencing attributes make sure this is applied as
+             both to the button. -->
+        <item name="android:buttonStyle">@style/SucGlifMaterialButton.Primary</item>
+        <item name="android:theme">@style/SucGlifMaterialButton.Primary</item>
+
+        <!-- Values used in styles -->
+        <item name="android:fontFamily">?attr/sucFooterBarButtonFontFamily</item>
+        <item name="android:paddingLeft">?attr/sucFooterButtonPaddingStart</item>
+        <item name="android:paddingStart" tools:ignore="NewApi">?attr/sucFooterButtonPaddingStart</item>
+        <item name="android:paddingRight">?attr/sucFooterButtonPaddingEnd</item>
+        <item name="android:paddingEnd" tools:ignore="NewApi">?attr/sucFooterButtonPaddingEnd</item>
+        <item name="android:textAllCaps">?attr/sucFooterBarButtonAllCaps</item>
+        <item name="android:stateListAnimator" tools:ignore="NewApi">@null</item>
+        <item name="android:minHeight">?attr/sucFooterBarButtonMinHeight</item>
+        <item name="android:textFontWeight" tools:targetApi="p">?attr/sucFooterBarButtonFontWeight</item>
+        <item name="android:insetTop">0dp</item>
+        <item name="android:insetBottom">0dp</item>
+        <item name="android:textSize">?attr/sucFooterBarButtonTextSize</item>
+        <item name="android:lineSpacingExtra">?attr/sucFooterButtonTextLineSpacingExtra</item>
+
+        <!-- Values used in themes -->
+        <item name="android:buttonCornerRadius" tools:ignore="NewApi">?attr/sucFooterBarButtonCornerRadius</item>
+
+        <item name="viewInflaterClass">com.google.android.material.theme.MaterialComponentsViewInflater</item>
+        <item name="sucMaterialButtonStyle">@style/SucGlifMaterialButton.Primary</item>
+    </style>
+
+    <style name="SucGlifMaterialButton.Secondary" parent="Widget.Material3.Button.OutlinedButton">
+        <!-- This style can be applied to a button either as a "style" in XML, or as a theme in
+             ContextThemeWrapper. These self-referencing attributes make sure this is applied as
+             both to the button. -->
+        <item name="android:buttonStyle">@style/SucGlifMaterialButton.Secondary</item>
+        <item name="android:theme">@style/SucGlifMaterialButton.Secondary</item>
+
+        <!-- Values used in styles -->
+        <item name="android:fontFamily">?attr/sucFooterBarButtonFontFamily</item>
+        <item name="android:minWidth">0dp</item>
+        <item name="android:paddingLeft">?attr/sucFooterButtonPaddingStart</item>
+        <item name="android:paddingStart" tools:ignore="NewApi">?attr/sucFooterButtonPaddingStart</item>
+        <item name="android:paddingRight">?attr/sucFooterButtonPaddingEnd</item>
+        <item name="android:paddingEnd" tools:ignore="NewApi">?attr/sucFooterButtonPaddingEnd</item>
+        <item name="android:textAllCaps">?attr/sucFooterBarButtonAllCaps</item>
+        <item name="android:minHeight">?attr/sucFooterBarButtonMinHeight</item>
+        <item name="android:textFontWeight" tools:targetApi="p">?attr/sucFooterBarButtonFontWeight</item>
+        <item name="android:insetTop">0dp</item>
+        <item name="android:insetBottom">0dp</item>
+        <item name="android:textSize">?attr/sucFooterBarButtonTextSize</item>
+        <item name="android:lineSpacingExtra">?attr/sucFooterButtonTextLineSpacingExtra</item>
+
+        <!-- Values used in themes -->
+        <item name="android:buttonCornerRadius" tools:ignore="NewApi">?attr/sucFooterBarButtonCornerRadius</item>
+        <item name="android:colorControlHighlight" tools:targetApi="lollipop">@color/suc_customization_button_highlight_ripple</item>
+        <item name="sucFooterBarButtonColorControlHighlight">@color/suc_customization_button_highlight_ripple</item>
+
+        <item name="viewInflaterClass">com.google.android.material.theme.MaterialComponentsViewInflater</item>
+        <item name="sucMaterialOutlinedButtonStyle">@style/SucGlifMaterialButton.Secondary</item>
+    </style>
 </resources>
diff --git a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java
index 7ab946d..4b77e67 100644
--- a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java
+++ b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfig.java
@@ -355,6 +355,10 @@ public enum PartnerConfig {
   // The padding bottom of list items.
   CONFIG_ITEMS_PADDING_BOTTOM(PartnerConfigKey.KEY_ITEMS_PADDING_BOTTOM, ResourceType.DIMENSION),
 
+  // The corner radius of list items group.
+  CONFIG_ITEMS_GROUP_CORNER_RADIUS(
+      PartnerConfigKey.KEY_ITEMS_GROUP_CORNER_RADIUS, ResourceType.DIMENSION),
+
   // The minimum height of list items.
   CONFIG_ITEMS_MIN_HEIGHT(PartnerConfigKey.KEY_ITEMS_MIN_HEIGHT, ResourceType.DIMENSION),
 
diff --git a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigHelper.java b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigHelper.java
index f027011..de407e0 100644
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
@@ -87,11 +88,20 @@ public class PartnerConfigHelper {
   @VisibleForTesting
   public static final String IS_FORCE_TWO_PANE_ENABLED_METHOD = "isForceTwoPaneEnabled";
 
+  @VisibleForTesting
+  public static final String IS_GLIF_EXPRESSIVE_ENABLED = "isGlifExpressiveEnabled";
+
+  /** The method name to get the if the keyboard focus enhancement enabled */
+  @VisibleForTesting
+  public static final String IS_KEYBOARD_FOCUS_ENHANCEMENT_ENABLED_METHOD =
+      "isKeyboardFocusEnhancementEnabled";
+
   @VisibleForTesting
   public static final String GET_SUW_DEFAULT_THEME_STRING_METHOD = "suwDefaultThemeString";
 
   @VisibleForTesting public static final String SUW_PACKAGE_NAME = "com.google.android.setupwizard";
   @VisibleForTesting public static final String MATERIAL_YOU_RESOURCE_SUFFIX = "_material_you";
+  @VisibleForTesting public static final String GLIF_EXPRESSIVE_RESOURCE_SUFFIX = "_expressive";
 
   @VisibleForTesting
   public static final String EMBEDDED_ACTIVITY_RESOURCE_SUFFIX = "_embedded_activity";
@@ -113,6 +123,8 @@ public class PartnerConfigHelper {
 
   @VisibleForTesting public static Bundle suwDefaultThemeBundle = null;
 
+  @VisibleForTesting public static Bundle keyboardFocusEnhancementBundle = null;
+
   private static PartnerConfigHelper instance = null;
 
   @VisibleForTesting Bundle resultBundle = null;
@@ -132,6 +144,8 @@ public class PartnerConfigHelper {
   @VisibleForTesting
   public static Bundle applyForceTwoPaneBundle = null;
 
+  @VisibleForTesting public static Bundle applyGlifExpressiveBundle = null;
+
   @VisibleForTesting public static int savedOrientation = Configuration.ORIENTATION_PORTRAIT;
 
   /** The method name to get if transition settings is set from client. */
@@ -605,6 +619,8 @@ public class PartnerConfigHelper {
       resourceEntry = adjustEmbeddedActivityResourceEntryDefaultValue(context, resourceEntry);
     } else if (BuildCompatUtils.isAtLeastU() && isForceTwoPaneEnabled(context)) {
       resourceEntry = adjustForceTwoPaneResourceEntryDefaultValue(context, resourceEntry);
+    } else if (BuildCompatUtils.isAtLeastV() && isGlifExpressiveEnabled(context)) {
+      resourceEntry = adjustGlifExpressiveResourceEntryDefaultValue(context, resourceEntry);
     } else if (BuildCompatUtils.isAtLeastT() && shouldApplyMaterialYouStyle(context)) {
       resourceEntry = adjustMaterialYouResourceEntryDefaultValue(context, resourceEntry);
     }
@@ -785,6 +801,43 @@ public class PartnerConfigHelper {
     return resourceEntry;
   }
 
+  // Check the GlifExpressive flag and replace the inputResourceEntry.resourceName &
+  // inputResourceEntry.resourceId after V, that means if using GlifExpressive theme before V, will
+  // always use glifv4 resources.
+  ResourceEntry adjustGlifExpressiveResourceEntryDefaultValue(
+      Context context, ResourceEntry inputResourceEntry) {
+    // If not overlay resource
+    try {
+      if (Objects.equals(inputResourceEntry.getPackageName(), SUW_PACKAGE_NAME)) {
+        String resourceTypeName =
+            inputResourceEntry
+                .getResources()
+                .getResourceTypeName(inputResourceEntry.getResourceId());
+        // try to update resourceName & resourceId
+        String glifExpressiveResourceName =
+            inputResourceEntry.getResourceName().concat(GLIF_EXPRESSIVE_RESOURCE_SUFFIX);
+        int glifExpressiveResourceId =
+            inputResourceEntry
+                .getResources()
+                .getIdentifier(
+                    glifExpressiveResourceName,
+                    resourceTypeName,
+                    inputResourceEntry.getPackageName());
+        if (glifExpressiveResourceId != 0) {
+          Log.i(TAG, "use expressive resource:" + glifExpressiveResourceName);
+          return new ResourceEntry(
+              inputResourceEntry.getPackageName(),
+              glifExpressiveResourceName,
+              glifExpressiveResourceId,
+              inputResourceEntry.getResources());
+        }
+      }
+    } catch (NotFoundException ex) {
+      // fall through
+    }
+    return inputResourceEntry;
+  }
+
   @VisibleForTesting
   public static synchronized void resetInstance() {
     instance = null;
@@ -798,6 +851,8 @@ public class PartnerConfigHelper {
     suwDefaultThemeBundle = null;
     applyTransitionBundle = null;
     applyForceTwoPaneBundle = null;
+    applyGlifExpressiveBundle = null;
+    keyboardFocusEnhancementBundle = null;
   }
 
   /**
@@ -883,8 +938,9 @@ public class PartnerConfigHelper {
       }
     }
 
-    return (applyMaterialYouConfigBundle != null
-        && applyMaterialYouConfigBundle.getBoolean(IS_MATERIAL_YOU_STYLE_ENABLED_METHOD, false));
+    return ((applyMaterialYouConfigBundle != null
+            && applyMaterialYouConfigBundle.getBoolean(IS_MATERIAL_YOU_STYLE_ENABLED_METHOD, false))
+        || isGlifExpressiveEnabled(context));
   }
 
   /**
@@ -1083,6 +1139,62 @@ public class PartnerConfigHelper {
     return false;
   }
 
+  /** Returns whether the keyboard focus enhancement is enabled. */
+  public static boolean isKeyboardFocusEnhancementEnabled(@NonNull Context context) {
+    if (keyboardFocusEnhancementBundle == null || keyboardFocusEnhancementBundle.isEmpty()) {
+      try {
+        keyboardFocusEnhancementBundle =
+            context
+                .getContentResolver()
+                .call(
+                    getContentUri(),
+                    IS_KEYBOARD_FOCUS_ENHANCEMENT_ENABLED_METHOD,
+                    /* arg= */ null,
+                    /* extras= */ null);
+      } catch (IllegalArgumentException | SecurityException exception) {
+        Log.w(TAG, "SetupWizard keyboard focus enhancement status unknown; return as false.");
+        keyboardFocusEnhancementBundle = null;
+        return false;
+      }
+    }
+    if (keyboardFocusEnhancementBundle == null || keyboardFocusEnhancementBundle.isEmpty()) {
+      return false;
+    }
+    return keyboardFocusEnhancementBundle.getBoolean(IS_KEYBOARD_FOCUS_ENHANCEMENT_ENABLED_METHOD);
+  }
+
+  /**
+   * Returns true if the SetupWizard supports Glif Expressive style inside or outside setup flow.
+   */
+  public static boolean isGlifExpressiveEnabled(@NonNull Context context) {
+
+    if (applyGlifExpressiveBundle == null || applyGlifExpressiveBundle.isEmpty()) {
+      try {
+        Activity activity = lookupActivityFromContext(context);
+        // Save inside/outside setup wizard flag into bundle
+        Bundle extras = new Bundle();
+        extras.putBoolean(
+            WizardManagerHelper.EXTRA_IS_SETUP_FLOW,
+            WizardManagerHelper.isAnySetupWizard(activity.getIntent()));
+
+        applyGlifExpressiveBundle =
+            context
+                .getContentResolver()
+                .call(
+                    getContentUri(),
+                    IS_GLIF_EXPRESSIVE_ENABLED,
+                    /* arg= */ null,
+                    /* extras= */ extras);
+      } catch (IllegalArgumentException | SecurityException exception) {
+        Log.w(TAG, "isGlifExpressiveEnabled status is unknown; return as false.");
+      }
+    }
+    if (applyGlifExpressiveBundle != null && !applyGlifExpressiveBundle.isEmpty()) {
+      return applyGlifExpressiveBundle.getBoolean(IS_GLIF_EXPRESSIVE_ENABLED, false);
+    }
+    return false;
+  }
+
   @VisibleForTesting
   static Uri getContentUri() {
     return new Uri.Builder()
diff --git a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java
index 220054c..7b20aed 100644
--- a/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java
+++ b/partnerconfig/java/com/google/android/setupcompat/partnerconfig/PartnerConfigKey.java
@@ -117,6 +117,7 @@ import java.lang.annotation.RetentionPolicy;
   PartnerConfigKey.KEY_ITEMS_SUMMARY_FONT_FAMILY,
   PartnerConfigKey.KEY_ITEMS_PADDING_TOP,
   PartnerConfigKey.KEY_ITEMS_PADDING_BOTTOM,
+  PartnerConfigKey.KEY_ITEMS_GROUP_CORNER_RADIUS,
   PartnerConfigKey.KEY_ITEMS_MIN_HEIGHT,
   PartnerConfigKey.KEY_ITEMS_DIVIDER_SHOWN,
   PartnerConfigKey.KEY_PROGRESS_ILLUSTRATION_DEFAULT,
@@ -435,6 +436,9 @@ public @interface PartnerConfigKey {
   // The padding bottom of list items.
   String KEY_ITEMS_PADDING_BOTTOM = "setup_design_items_padding_bottom";
 
+  // The corner radius of list items group.
+  String KEY_ITEMS_GROUP_CORNER_RADIUS = "setup_design_items_group_corner_radius";
+
   // The minimum height of list items.
   String KEY_ITEMS_MIN_HEIGHT = "setup_design_items_min_height";
 
```

