```diff
diff --git a/Android.bp b/Android.bp
index da1c676..799f302 100644
--- a/Android.bp
+++ b/Android.bp
@@ -23,7 +23,7 @@ java_defaults {
     name: "CaptivePortalLoginDefaults",
     sdk_version: "module_current",
     min_sdk_version: "30",
-    target_sdk_version: "35", // Keep in sync with CaptivePortalLoginTests
+    target_sdk_version: "36", // Keep in sync with CaptivePortalLoginTests
     lint: {
         strict_updatability_linting: true,
     },
@@ -42,9 +42,11 @@ android_library {
         "androidx.legacy_legacy-support-core-ui",
         "captiveportal-lib",
         "metrics-constants-protos",
+        "modules-utils-build",
         "net-utils-connectivity-apks",
     ],
     libs: [
+        "framework-configinfrastructure.stubs.module_lib",
         "framework-connectivity.stubs.module_lib",
         "framework-mediaprovider.stubs.module_lib",
         "framework-wifi.stubs.module_lib",
@@ -92,16 +94,3 @@ android_library {
         strict_updatability_linting: true,
     },
 }
-
-// Alternative CaptivePortalLogin signed with the platform cert, to use
-// with InProcessNetworkStack.
-android_app {
-    name: "PlatformCaptivePortalLogin",
-    defaults: ["CaptivePortalLoginDefaults"],
-    static_libs: ["CaptivePortalLoginLib"],
-    certificate: "platform",
-    overrides: ["CaptivePortalLogin"],
-    lint: {
-        strict_updatability_linting: true,
-    },
-}
diff --git a/res/layout/activity_captive_portal_login.xml b/res/layout/activity_captive_portal_login.xml
index 9d9ccb9..d61cca5 100644
--- a/res/layout/activity_captive_portal_login.xml
+++ b/res/layout/activity_captive_portal_login.xml
@@ -3,7 +3,6 @@
     android:id="@+id/container"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
-    android:fitsSystemWindows="true"
     tools:context="com.android.captiveportallogin.CaptivePortalLoginActivity"
     tools:ignore="MergeRootFrame" >
 
diff --git a/res/layout/activity_custom_tab_header.xml b/res/layout/activity_custom_tab_header.xml
new file mode 100644
index 0000000..c5368e2
--- /dev/null
+++ b/res/layout/activity_custom_tab_header.xml
@@ -0,0 +1,45 @@
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:fitsSystemWindows="true"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:orientation="vertical">
+    <LinearLayout
+        android:id="@+id/custom_tab_header_top_bar"
+        style="@android:style/Widget.Material.ActionBar.Solid"
+        android:layout_width="match_parent"
+        android:layout_height="@dimen/custom_tab_header_title_height"
+        android:elevation="0px"
+        android:orientation="horizontal">
+        <TextView
+            android:id="@+id/custom_tab_header_title"
+            style="@android:style/TextAppearance.Material.Widget.ActionBar.Title"
+            android:layout_height="wrap_content"
+            android:layout_width="wrap_content"
+            android:layout_marginStart="@dimen/custom_tab_header_horizontal_margin"
+            android:layout_marginEnd="@dimen/custom_tab_header_horizontal_margin"
+            android:contentDescription="@string/action_bar_label" />
+    </LinearLayout>
+    <FrameLayout
+        android:id="@+id/custom_tab_header_remaining_space"
+        android:layout_height="0dp"
+        android:layout_width="match_parent"
+        android:layout_weight="1" />
+</LinearLayout>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 2a94abd..4ce571e 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -7,7 +7,7 @@
     <string name="action_bar_label" msgid="2023171629563754892">"નેટવર્ક પર સાઇન ઇન કરો"</string>
     <string name="action_bar_title" msgid="2566334512545554724">"%1$sમાં સઇન ઇન કરો"</string>
     <string name="ssl_error_warning" msgid="494203210316238046">"તમે જોડાવાનો પ્રયાસ કરી રહ્યાં છો તે નેટવર્કમાં સુરક્ષા સમસ્યાઓ છે."</string>
-    <string name="ssl_error_example" msgid="4574594291839092653">"ઉદાહરણ તરીકે, લોગિન પૃષ્ઠ દર્શાવેલ સંસ્થાનું હોઈ શકતું નથી."</string>
+    <string name="ssl_error_example" msgid="4574594291839092653">"ઉદાહરણ તરીકે, હોઈ શકે કે, લૉગ ઇન પેજ દર્શાવેલી સંસ્થાને સંબંધિત ન હોય."</string>
     <string name="no_bypass_error_vpnwarning" msgid="5263739853101734851">"વૈકલ્પિક રીતે, આ ભૂલને બાયપાસ કરવાનું શક્ય નથી કારણ કે ડિવાઇસમાં હાલમાં VPN ચાલી રહ્યું છે."</string>
     <string name="error_continue_via_browser" msgid="7091550471744444659">"તો પણ બ્રાઉઝર મારફતે ચાલુ રાખો"</string>
     <string name="ssl_error_untrusted" msgid="5183246242332501768">"આ પ્રમાણપત્ર વિશ્વસનીય સત્તાધિકારી તરફથી મળ્યું નથી."</string>
diff --git a/res/values-land/dimens.xml b/res/values-land/dimens.xml
new file mode 100644
index 0000000..b4834d1
--- /dev/null
+++ b/res/values-land/dimens.xml
@@ -0,0 +1,4 @@
+<resources>
+    <!-- As per Material Design guidelines -->
+    <dimen name="custom_tab_header_title_height">64dp</dimen>
+</resources>
diff --git a/res/values-sw600dp/dimens.xml b/res/values-sw600dp/dimens.xml
new file mode 100644
index 0000000..ed9796d
--- /dev/null
+++ b/res/values-sw600dp/dimens.xml
@@ -0,0 +1,4 @@
+<resources>
+    <!-- As per Material Design guidelines -->
+    <dimen name="custom_tab_header_title_height">48dp</dimen>
+</resources>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index 55c1e59..04a6a8a 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -4,4 +4,7 @@
     <dimen name="activity_horizontal_margin">16dp</dimen>
     <dimen name="activity_vertical_margin">16dp</dimen>
 
+    <dimen name="custom_tab_header_horizontal_margin">8dp</dimen>
+    <dimen name="custom_tab_header_title_height">56dp</dimen>
+
 </resources>
diff --git a/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java b/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java
index 2a771c3..96c0b27 100755
--- a/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java
+++ b/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java
@@ -19,9 +19,8 @@ package com.android.captiveportallogin;
 import static android.net.ConnectivityManager.EXTRA_CAPTIVE_PORTAL_PROBE_SPEC;
 import static android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED;
 
-import static androidx.browser.customtabs.CustomTabsCallback.NAVIGATION_STARTED;
-
 import static com.android.captiveportallogin.CaptivePortalLoginFlags.CAPTIVE_PORTAL_CUSTOM_TABS;
+import static com.android.captiveportallogin.CaptivePortalLoginFlags.USE_ANY_CUSTOM_TAB_PROVIDER;
 import static com.android.captiveportallogin.DownloadService.isDirectlyOpenType;
 
 import android.app.Activity;
@@ -34,7 +33,12 @@ import android.content.Context;
 import android.content.DialogInterface;
 import android.content.Intent;
 import android.content.ServiceConnection;
+import android.content.pm.PackageManager;
+import android.content.pm.PackageManager.NameNotFoundException;
+import android.content.pm.ResolveInfo;
 import android.graphics.Bitmap;
+import android.graphics.Insets;
+import android.graphics.Rect;
 import android.net.CaptivePortal;
 import android.net.CaptivePortalData;
 import android.net.ConnectivityManager;
@@ -54,9 +58,13 @@ import android.os.Build;
 import android.os.Bundle;
 import android.os.IBinder;
 import android.os.Looper;
+import android.os.OutcomeReceiver;
+import android.os.ServiceSpecificException;
 import android.os.SystemProperties;
+import android.provider.DeviceConfig;
 import android.provider.DocumentsContract;
 import android.provider.MediaStore;
+import android.system.OsConstants;
 import android.text.TextUtils;
 import android.util.ArrayMap;
 import android.util.ArraySet;
@@ -68,6 +76,7 @@ import android.view.Menu;
 import android.view.MenuItem;
 import android.view.View;
 import android.view.ViewGroup;
+import android.view.WindowInsets;
 import android.webkit.CookieManager;
 import android.webkit.DownloadListener;
 import android.webkit.SslErrorHandler;
@@ -87,6 +96,7 @@ import android.widget.Toast;
 import androidx.annotation.GuardedBy;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
+import androidx.annotation.RequiresApi;
 import androidx.annotation.StringRes;
 import androidx.annotation.VisibleForTesting;
 import androidx.browser.customtabs.CustomTabsCallback;
@@ -98,6 +108,7 @@ import androidx.core.content.FileProvider;
 import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
 
 import com.android.internal.logging.nano.MetricsProto.MetricsEvent;
+import com.android.modules.utils.build.SdkLevel;
 import com.android.net.module.util.DeviceConfigUtils;
 
 import java.io.File;
@@ -111,8 +122,12 @@ import java.net.URLConnection;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.Paths;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
 import java.util.Objects;
 import java.util.Random;
+import java.util.concurrent.Executor;
 import java.util.concurrent.atomic.AtomicBoolean;
 
 public class CaptivePortalLoginActivity extends Activity {
@@ -159,49 +174,136 @@ public class CaptivePortalLoginActivity extends Activity {
     private boolean mCaptivePortalCustomTabsEnabled;
     // Ensures that done() happens once exactly, handling concurrent callers with atomic operations.
     private final AtomicBoolean isDone = new AtomicBoolean(false);
+    // Must only be touched on the UI thread. This must be initialized to false for thread
+    // visibility reasons (if initialized to true, the UI thread may still see false).
+    private boolean mIsResumed = false;
+
+    // Persistence across configuration changes, e.g. when the device is rotated, the
+    // window is resized in multi-window mode, or a hardware keyboard is attached.
+    // When this happens the app needs to know not to create a new custom tab, or it will
+    // have multiple tabs open on top of each other.
+    // This must only be touched on the main thread of the app.
+    private static final class PersistentState {
+        CaptivePortalCustomTabsServiceConnection mServiceConnection = null;
+        CaptivePortalCustomTabsCallback mCallback = null;
+        public void copyFrom(@NonNull PersistentState other) {
+            mServiceConnection = other.mServiceConnection;
+            mCallback = other.mCallback;
+        }
+    }
+    // Must only be touched on the UI thread
+    private final PersistentState mPersistentState = new PersistentState();
+
+    private static final class CaptivePortalCustomTabsCallback extends CustomTabsCallback {
+        @NonNull private CaptivePortalLoginActivity mParent;
+
+        CaptivePortalCustomTabsCallback(@NonNull final CaptivePortalLoginActivity parent) {
+            mParent = parent;
+        }
+
+        public void reparent(@NonNull final CaptivePortalLoginActivity newParent) {
+            mParent = newParent;
+        }
 
-    private final CustomTabsCallback mCustomTabsCallback = new CustomTabsCallback() {
         @Override
         public void onNavigationEvent(int navigationEvent, @Nullable Bundle extras) {
             if (navigationEvent == NAVIGATION_STARTED) {
-                mCaptivePortal.reevaluateNetwork();
+                mParent.mCaptivePortal.reevaluateNetwork();
+            }
+            if (navigationEvent == TAB_HIDDEN) {
+                // Run on UI thread to make sure mIsResumed is correctly visible.
+                mParent.runOnUiThread(() -> {
+                    // The tab is hidden when the browser's activity is hidden : screen off,
+                    // home button, or press the close button on the tab. In the last case,
+                    // close the app. The activity behind the tab is only resumed in that case.
+                    if (mParent.mIsResumed) mParent.done(Result.DISMISSED);
+                });
             }
         }
-    };
+    }
 
-    private final CustomTabsServiceConnection mCustomTabsServiceConnection =
-            new CustomTabsServiceConnection() {
-                    @Override
-                    public void onCustomTabsServiceConnected(@NonNull ComponentName name,
-                            @NonNull CustomTabsClient client) {
-                        Log.d(TAG, "CustomTabs service connected");
-                        final CustomTabsSession session = client.newSession(mCustomTabsCallback);
-                        // The application package name that will resolve to the CustomTabs intent
-                        // has been set in {@Link CustomTabsIntent.Builder} constructor, unnecessary
-                        // to call {@Link Intent#setPackage} to explicitly specify the package name
-                        // again.
-                        final CustomTabsIntent customTabsIntent =
-                                new CustomTabsIntent.Builder(session)
-                                        .setNetwork(mNetwork)
-                                        .setShareState(CustomTabsIntent.SHARE_STATE_OFF)
-                                        .setShowTitle(true /* showTitle */)
-                                        .build();
-
-                        // Remove Referrer Header from HTTP probe packet by setting an empty Uri
-                        // instance in EXTRA_REFERRER, make sure users using custom tabs have the
-                        // same experience as the custom tabs browser.
-                        final String emptyReferrer = "";
-                        customTabsIntent.intent.putExtra(Intent.EXTRA_REFERRER,
-                                Uri.parse(emptyReferrer));
-                        customTabsIntent.launchUrl(CaptivePortalLoginActivity.this,
-                                Uri.parse(mUrl.toString()));
-                    }
+    private static final class CaptivePortalCustomTabsServiceConnection extends
+            CustomTabsServiceConnection {
+        @NonNull private CaptivePortalLoginActivity mParent;
 
-                    @Override
-                    public void onServiceDisconnected(ComponentName componentName) {
-                        Log.d(TAG, "CustomTabs service disconnected");
-                    }
-            };
+        CaptivePortalCustomTabsServiceConnection(
+                @NonNull final CaptivePortalLoginActivity parent) {
+            mParent = parent;
+        }
+
+        public void reparent(@NonNull final CaptivePortalLoginActivity newParent) {
+            mParent = newParent;
+        }
+
+        @Override
+        public void onCustomTabsServiceConnected(@NonNull ComponentName name,
+                @NonNull CustomTabsClient client) {
+            Log.d(TAG, "CustomTabs service connected");
+            final CustomTabsSession session = client.newSession(mParent.mPersistentState.mCallback);
+            // TODO : recompute available space when the app changes sizes
+            final View remainingSpaceView = mParent.findViewById(
+                    R.id.custom_tab_header_remaining_space);
+            int availableSpace = remainingSpaceView.getHeight();
+            if (availableSpace < 100) {
+                // In some situations the layout pass is not done ? Not sure why yet but
+                // as a stopgap use a fixed value
+                final Rect windowSize =
+                        mParent.getWindowManager().getCurrentWindowMetrics().getBounds();
+                final int top = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP,
+                        96 /* dp */, mParent.getResources().getDisplayMetrics());
+                availableSpace = (windowSize.bottom - windowSize.top) - top;
+            }
+            final int size = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP,
+                    24 /* dp */, mParent.getResources().getDisplayMetrics());
+            final Bitmap emptyIcon = Bitmap.createBitmap(size /* width */, size /* height */,
+                    Bitmap.Config.ARGB_8888);
+            emptyIcon.setPixel(0, 0, 0);
+            // The application package name that will resolve to the CustomTabs intent
+            // has been set in {@Link CustomTabsIntent.Builder} constructor, unnecessary
+            // to call {@Link Intent#setPackage} to explicitly specify the package name
+            // again.
+            final CustomTabsIntent customTabsIntent = new CustomTabsIntent.Builder(session)
+                    .setNetwork(mParent.mNetwork)
+                    .setShareState(CustomTabsIntent.SHARE_STATE_OFF)
+                    // Do not show a title to avoid pages pretend they are part of the Android
+                    // system.
+                    .setShowTitle(false /* showTitle */)
+                    // Have the tab take up the available space under the header.
+                    .setInitialActivityHeightPx(availableSpace,
+                            CustomTabsIntent.ACTIVITY_HEIGHT_FIXED)
+                    // Don't show animations, because there is no content to animate from or to in
+                    // this activity. As such, set the res IDs to zero, which code for no animation.
+                    .setStartAnimations(mParent, 0, 0)
+                    .setExitAnimations(mParent, 0, 0)
+                    // Temporary workaround : use an empty icon for the close button. It doesn't
+                    // prevent interaction, but it least it doesn't LOOK like you can press it.
+                    .setCloseButtonIcon(emptyIcon)
+                    // External handlers will not work since they won't know on what network to
+                    // operate.
+                    .setSendToExternalDefaultHandlerEnabled(false)
+                    // No rounding on the corners so as to have the UI of the tab blend more
+                    // closely with the header contents.
+                    .setToolbarCornerRadiusDp(0)
+                    // Use the identity of the captive portal login app
+                    .setShareIdentityEnabled(true)
+                    // Don't hide the URL bar when scrolling down, to make sure the user is always
+                    // aware they are on the page from a captive portal.
+                    .setUrlBarHidingEnabled(false)
+                    .build();
+
+            // Remove Referrer Header from HTTP probe packet by setting an empty Uri
+            // instance in EXTRA_REFERRER, make sure users using custom tabs have the
+            // same experience as the custom tabs browser.
+            final String emptyReferrer = "";
+            customTabsIntent.intent.putExtra(Intent.EXTRA_REFERRER, Uri.parse(emptyReferrer));
+            customTabsIntent.launchUrl(mParent, Uri.parse(mParent.mUrl.toString()));
+        }
+
+        @Override
+        public void onServiceDisconnected(ComponentName componentName) {
+            Log.d(TAG, "CustomTabs service disconnected");
+        }
+    }
 
     // When starting downloads a file is created via startActivityForResult(ACTION_CREATE_DOCUMENT).
     // This array keeps the download request until the activity result is received. It is keyed by
@@ -235,6 +337,18 @@ public class CaptivePortalLoginActivity extends Activity {
         }
     };
 
+    @Override
+    protected void onPause() {
+        mIsResumed = false;
+        super.onPause();
+    }
+
+    @Override
+    protected void onResume() {
+        mIsResumed = true;
+        super.onResume();
+    }
+
     @VisibleForTesting
     final DownloadService.ProgressCallback mProgressCallback =
             new DownloadService.ProgressCallback() {
@@ -285,6 +399,12 @@ public class CaptivePortalLoginActivity extends Activity {
         return DeviceConfigUtils.isCaptivePortalLoginFeatureEnabled(getApplicationContext(), name);
     }
 
+    @VisibleForTesting
+    boolean getDeviceConfigPropertyBoolean(final String name, boolean defaultValue) {
+        return DeviceConfigUtils.getDeviceConfigPropertyBoolean(
+                DeviceConfig.NAMESPACE_CAPTIVEPORTALLOGIN, name, defaultValue);
+    }
+
     private void maybeStartPendingDownloads() {
         ensureRunningOnMainThread();
 
@@ -341,17 +461,90 @@ public class CaptivePortalLoginActivity extends Activity {
         }
     }
 
+    // Ideally there should be a setting to let the user decide whether they want to
+    // use custom tabs from a non-default browser for captive portals. Most users are
+    // expected not to want custom tabs from a non-default browser : there
+    // is a good chance they don't trust the company making a non-default browser that
+    // is installed by default on their phone, or even if they trust it they may just
+    // dislike it. Users tend to be passionate about their browser preference.
+    // Still there is a use case for this, like playing DRM-protected content. Absent
+    // trust and like issues, a non-default browser is still probably a more competent
+    // implementation than the webview, and while it probably doesn't have the user's
+    // credentials or personal info, it is likely better at handling SSL errors, non-
+    // default schemes, login status and the like.
+    // Until there is such a setting, the captive portal login app should default to
+    // only use the default browser, and use the webview if the default browser does
+    // not support custom tabs with multi-networking.
+    // However, temporarily to help with tests, using any browser with the available
+    // capabilities is useful. As such, only do this if the hidden device config
+    // USE_ANY_CUSTOM_TAB_PROVIDER is true.
+    @Nullable
+    String getAnyCustomTabsProviderPackage() {
+        // Get all apps that can handle VIEW intents and Custom Tab service connections.
+        final Intent activityIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://"));
+        final List<String> packages = new ArrayList<>();
+        for (final ResolveInfo resolveInfo : getPackageManager()
+                .queryIntentActivities(activityIntent, PackageManager.MATCH_ALL)) {
+            if (null == resolveInfo || null == resolveInfo.activityInfo) continue;
+            if (isMultiNetworkingSupportedByProvider(resolveInfo.activityInfo.packageName)) {
+                packages.add(resolveInfo.activityInfo.packageName);
+            }
+        }
+        if (packages.isEmpty()) return null;
+        final List<String> priorities = Arrays.asList(".dev", ".canary", ".beta");
+        for (String priority : priorities) {
+            for (String packageName : packages) {
+                if (packageName.endsWith(priority)) {
+                    return packageName;
+                }
+            }
+        }
+        return packages.get(0);
+    }
+
     @VisibleForTesting
     @Nullable
     String getDefaultCustomTabsProviderPackage() {
         return CustomTabsClient.getPackageName(getApplicationContext(), null /* packages */);
     }
 
+    @VisibleForTesting
+    int getPackageUid(@NonNull final String customTabsProviderPackageName)
+            throws NameNotFoundException {
+        return getPackageManager().getPackageUid(customTabsProviderPackageName, 0);
+    }
+
     @VisibleForTesting
     boolean isMultiNetworkingSupportedByProvider(@NonNull final String defaultPackageName) {
         return CustomTabsClient.isSetNetworkSupported(getApplicationContext(), defaultPackageName);
     }
 
+    @VisibleForTesting
+    Context getContextForCustomTabsBinding() {
+        return getApplicationContext();
+    }
+
+    private void applyWindowInsets(final int resourceId) {
+        if (!SdkLevel.isAtLeastV()) return;
+        final View view = findViewById(resourceId);
+        view.setOnApplyWindowInsetsListener((v, windowInsets) -> {
+            final Insets insets = windowInsets.getInsets(WindowInsets.Type.systemBars());
+            v.setPadding(0 /* left */, insets.top /* top */, 0 /* right */,
+                    0 /* bottom */);
+            return windowInsets.inset(0, insets.top, 0, 0);
+        });
+    }
+
+    private void initializeCustomTabHeader() {
+        setContentView(R.layout.activity_custom_tab_header);
+        // No action bar as this activity implements its own UI instead, so it can display more
+        // useful information, e.g. about VPN or private DNS handling.
+        getActionBar().hide();
+        final TextView headerTitle = findViewById(R.id.custom_tab_header_title);
+        headerTitle.setText(getHeaderTitle());
+        applyWindowInsets(R.id.custom_tab_header_top_bar);
+    }
+
     private void initializeWebView() {
         // Also initializes proxy system properties.
         mCm.bindProcessToNetwork(mNetwork);
@@ -366,6 +559,8 @@ public class CaptivePortalLoginActivity extends Activity {
         getActionBar().setTitle(getHeaderTitle());
         getActionBar().setSubtitle("");
 
+        applyWindowInsets(R.id.container);
+
         final WebView webview = getWebview();
         webview.clearCache(true);
         CookieManager.getInstance().setAcceptThirdPartyCookies(webview, true);
@@ -393,41 +588,78 @@ public class CaptivePortalLoginActivity extends Activity {
         });
     }
 
-    @Nullable
-    private String getCustomTabsProviderPackageIfEnabled() {
-        if (!mCaptivePortalCustomTabsEnabled) return null;
+    private void bindCustomTabsService(@NonNull final String customTabsProviderPackageName) {
+        CustomTabsClient.bindCustomTabsService(getContextForCustomTabsBinding(),
+                customTabsProviderPackageName, mPersistentState.mServiceConnection);
+    }
 
-        final String defaultPackageName = getDefaultCustomTabsProviderPackage();
-        if (defaultPackageName == null) {
-            Log.i(TAG, "Default browser doesn't support custom tabs");
-            return null;
+    @RequiresApi(Build.VERSION_CODES.S)
+    private boolean bypassVpnForCustomTabsProvider(
+            @NonNull final String customTabsProviderPackageName,
+            @NonNull final OutcomeReceiver<Void, ServiceSpecificException> receiver) {
+        final Class captivePortalClass = mCaptivePortal.getClass();
+        try {
+            final Method setDelegateUidMethod =
+                    captivePortalClass.getMethod("setDelegateUid", int.class, Executor.class,
+                            OutcomeReceiver.class);
+            setDelegateUidMethod.invoke(mCaptivePortal,
+                    getPackageUid(customTabsProviderPackageName),
+                    getMainExecutor(),
+                    receiver);
+            return true;
+        } catch (ReflectiveOperationException | IllegalArgumentException e) {
+            Log.e(TAG, "Reflection exception while setting delegate uid", e);
+            return false;
+        } catch (NameNotFoundException e) {
+            Log.e(TAG, "Could not find the UID for " + customTabsProviderPackageName, e);
+            return false;
         }
+    }
 
-        final boolean support = isMultiNetworkingSupportedByProvider(defaultPackageName);
-        if (!support) {
-            Log.i(TAG, "Default browser doesn't support multi-network");
-            return null;
-        }
+    @Nullable
+    private String getCustomTabsProviderPackageIfEnabled() {
+        if (!mCaptivePortalCustomTabsEnabled) return null;
 
+        // TODO: b/330670424 - check if privacy settings such as private DNS is bypassable,
+        // otherwise, fallback to WebView.
         final LinkProperties lp = mCm.getLinkProperties(mNetwork);
         if (lp == null || lp.getPrivateDnsServerName() != null) {
             Log.i(TAG, "Do not use custom tabs if private DNS (strict mode) is enabled");
             return null;
         }
 
-        // TODO: b/330670424
-        // - check if privacy settings such as VPN/private DNS is bypassable, otherwise, fallback
-        //   to WebView.
-        return defaultPackageName;
+        final String defaultPackage = getDefaultCustomTabsProviderPackage();
+        if (null != defaultPackage && isMultiNetworkingSupportedByProvider(defaultPackage)) {
+            return defaultPackage;
+        }
+
+        Log.i(TAG, "Default browser doesn't support custom tabs");
+
+        // Intentionally no UX way to set this. It is useful for verifying the test-only feature
+        // with the early development version of browser.
+        final boolean useAnyCustomTabProvider =
+                getDeviceConfigPropertyBoolean(USE_ANY_CUSTOM_TAB_PROVIDER,
+                        false /* defaultValue */);
+        if (!useAnyCustomTabProvider) return null;
+        return getAnyCustomTabsProviderPackage();
     }
 
     @Override
-    protected void onCreate(Bundle savedInstanceState) {
+    public Object onRetainNonConfigurationInstance() {
+        return mPersistentState;
+    }
+
+    @Override
+    protected void onCreate(@Nullable Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
         // Initialize the feature flag after CaptivePortalLoginActivity is created, otherwise, the
         // context is still null and throw NPE when fetching the package manager from context.
         mCaptivePortalCustomTabsEnabled = isFeatureEnabled(CAPTIVE_PORTAL_CUSTOM_TABS);
         mCaptivePortal = getIntent().getParcelableExtra(ConnectivityManager.EXTRA_CAPTIVE_PORTAL);
+        final PersistentState lastState = (PersistentState) getLastNonConfigurationInstance();
+        if (null != lastState) {
+            mPersistentState.copyFrom(lastState);
+        }
         // Null CaptivePortal is unexpected. The following flow will need to access mCaptivePortal
         // to communicate with system. Thus, finish the activity.
         if (mCaptivePortal == null) {
@@ -483,15 +715,53 @@ public class CaptivePortalLoginActivity extends Activity {
             return;
         }
 
-        final String customTabsProviderPackage = getCustomTabsProviderPackageIfEnabled();
-        if (customTabsProviderPackage == null) {
+        maybeDeleteDirectlyOpenFile();
+
+        final String customTabsProviderPackageName = getCustomTabsProviderPackageIfEnabled();
+        if (customTabsProviderPackageName == null || !SdkLevel.isAtLeastS()) {
             initializeWebView();
         } else {
-            CustomTabsClient.bindCustomTabsService(this, customTabsProviderPackage,
-                    mCustomTabsServiceConnection);
-        }
+            initializeCustomTabHeader();
+            if (mPersistentState.mCallback != null) {
+                mPersistentState.mCallback.reparent(this);
+            } else {
+                mPersistentState.mCallback = new CaptivePortalCustomTabsCallback(this);
+            }
 
-        maybeDeleteDirectlyOpenFile();
+            if (mPersistentState.mServiceConnection != null) {
+                mPersistentState.mServiceConnection.reparent(this);
+            } else {
+                mPersistentState.mServiceConnection =
+                        new CaptivePortalCustomTabsServiceConnection(this);
+                // TODO: Fall back to WebView iff VPN is enabled and the custom tabs provider is not
+                // allowed to bypass VPN, e.g. an error or exception happens when calling the
+                // {@link CaptivePortal#setDelegateUid} API. Otherwise, force launch the custom tabs
+                // even if VPN cannot be bypassed.
+                final boolean success = bypassVpnForCustomTabsProvider(
+                        customTabsProviderPackageName,
+                        new OutcomeReceiver<Void, ServiceSpecificException>() {
+                            // TODO: log the callback result metrics.
+                            @Override
+                            public void onResult(Void r) {
+                                Log.d(TAG, "Set delegate uid for "
+                                        + customTabsProviderPackageName
+                                        + " to bypass VPN successfully");
+                                bindCustomTabsService(customTabsProviderPackageName);
+                            }
+
+                            @Override
+                            public void onError(ServiceSpecificException e) {
+                                Log.e(TAG, "Fail to set delegate uid for "
+                                        + customTabsProviderPackageName + " to bypass VPN"
+                                        + ", error: " + OsConstants.errnoName(e.errorCode), e);
+                                bindCustomTabsService(customTabsProviderPackageName);
+                            }
+                        });
+                if (!success) { // caught an exception
+                    bindCustomTabsService(customTabsProviderPackageName);
+                }
+            }
+        }
     }
 
     private void maybeDeleteDirectlyOpenFile() {
@@ -589,8 +859,9 @@ public class CaptivePortalLoginActivity extends Activity {
 
     @Override
     public void onBackPressed() {
-        WebView myWebView = findViewById(R.id.webview);
-        if (myWebView.canGoBack() && mWebViewClient.allowBack()) {
+        final WebView myWebView = findViewById(R.id.webview);
+        // The web view is null if the app is using custom tabs
+        if (null != myWebView && myWebView.canGoBack() && mWebViewClient.allowBack()) {
             myWebView.goBack();
         } else {
             super.onBackPressed();
@@ -631,6 +902,8 @@ public class CaptivePortalLoginActivity extends Activity {
     private void setProgressSpinnerVisibility(int visibility) {
         ensureRunningOnMainThread();
 
+        // getProgressLayout should never return null here, because this method is only ever called
+        // when running in webview mode.
         getProgressLayout().setVisibility(visibility);
         if (visibility != View.VISIBLE) {
             mDirectlyOpenId = NO_DIRECTLY_OPEN_TASK_ID;
@@ -662,8 +935,12 @@ public class CaptivePortalLoginActivity extends Activity {
             unbindService(mDownloadServiceConn);
         }
 
-        if (mCaptivePortalCustomTabsEnabled) {
-            unbindService(mCustomTabsServiceConnection);
+        // When changing configurations, the activity will be restarted immediately by the
+        // system. It will retain persistent state with onRetainNonConfigurationInstance,
+        // and therefore the connection must not be severed just yet.
+        if (null != mPersistentState.mServiceConnection && !isChangingConfigurations()) {
+            getContextForCustomTabsBinding().unbindService(mPersistentState.mServiceConnection);
+            mPersistentState.mServiceConnection = null;
         }
 
         final WebView webview = (WebView) findViewById(R.id.webview);
@@ -834,6 +1111,8 @@ public class CaptivePortalLoginActivity extends Activity {
                 String subtitle = (url != null) ? getHeaderSubtitle(url) : urlString;
                 getActionBar().setSubtitle(subtitle);
             }
+            // getProgressBar() can't return null here because this method can only be
+            // called in webview mode, not in custom tabs mode.
             getProgressBar().setVisibility(View.VISIBLE);
             mCaptivePortal.reevaluateNetwork();
         }
@@ -841,6 +1120,8 @@ public class CaptivePortalLoginActivity extends Activity {
         @Override
         public void onPageFinished(WebView view, String url) {
             mPagesLoaded++;
+            // getProgressBar() can't return null here because this method can only be
+            // called in webview mode, not in custom tabs mode.
             getProgressBar().setVisibility(View.INVISIBLE);
             mSwipeRefreshLayout.setRefreshing(false);
             if (mPagesLoaded == 1) {
@@ -1087,6 +1368,8 @@ public class CaptivePortalLoginActivity extends Activity {
     private class MyWebChromeClient extends WebChromeClient {
         @Override
         public void onProgressChanged(WebView view, int newProgress) {
+            // getProgressBar() can't return null here because this method can only be
+            // called in webview mode, not in custom tabs mode.
             getProgressBar().setProgress(newProgress);
         }
     }
@@ -1204,14 +1487,17 @@ public class CaptivePortalLoginActivity extends Activity {
         return FILE_PROVIDER_AUTHORITY;
     }
 
+    @Nullable
     private ProgressBar getProgressBar() {
         return findViewById(R.id.progress_bar);
     }
 
+    @Nullable
     private WebView getWebview() {
         return findViewById(R.id.webview);
     }
 
+    @Nullable
     private FrameLayout getProgressLayout() {
         return findViewById(R.id.downloading_panel);
     }
diff --git a/src/com/android/captiveportallogin/CaptivePortalLoginFlags.java b/src/com/android/captiveportallogin/CaptivePortalLoginFlags.java
index 6b955cf..261998f 100755
--- a/src/com/android/captiveportallogin/CaptivePortalLoginFlags.java
+++ b/src/com/android/captiveportallogin/CaptivePortalLoginFlags.java
@@ -25,4 +25,11 @@ public class CaptivePortalLoginFlags {
      * captive portal when connecting to a network that presents a captive portal.
      */
     public static final String CAPTIVE_PORTAL_CUSTOM_TABS = "captive_portal_custom_tabs";
+
+    /**
+     * Experiment flag to use any browser in the system to launch custom tabs temporarily if
+     * the default browser doesn't support custom tabs and multi-networking, which is useful
+     * for testing.
+     */
+    public static final String USE_ANY_CUSTOM_TAB_PROVIDER = "use_any_custom_tab_provider";
 }
diff --git a/tests/Android.bp b/tests/Android.bp
index 3b405c1..ad35bfa 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -31,7 +31,7 @@ android_test {
     platform_apis: true,
     compile_multilib: "both",
     min_sdk_version: "30",
-    target_sdk_version: "35", // Keep in sync with CaptivePortalLogin
+    target_sdk_version: "36", // Keep in sync with CaptivePortalLogin
     test_suites: [
         "general-tests",
         "mts-networking",
diff --git a/tests/AndroidTest.xml b/tests/AndroidTest.xml
index 57ead69..1230df5 100644
--- a/tests/AndroidTest.xml
+++ b/tests/AndroidTest.xml
@@ -30,10 +30,12 @@
         <option name="package" value="com.android.captiveportallogin.tests" />
         <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
         <option name="device-listeners" value="android.device.collectors.ScreenshotOnFailureCollector" />
+        <option name="device-listeners" value="com.android.testutils.ConnectivityDiagnosticsCollector" />
     </test>
 
     <metrics_collector class="com.android.tradefed.device.metric.FilePullerLogCollector">
         <option name="pull-pattern-keys" value="android.device.collectors.ScreenshotOnFailureCollector.*\.png"/>
+        <option name="pull-pattern-keys" value="com.android.testutils.ConnectivityDiagnosticsCollector.*"/>
         <option name="directory-keys" value="/data/user/0/com.android.captiveportallogin.tests/files" />
         <option name="collect-on-run-ended-only" value="false" />
     </metrics_collector>
diff --git a/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java b/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
index 70dd4ee..7688bfa 100644
--- a/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
+++ b/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
@@ -77,6 +77,7 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.ServiceConnection;
+import android.content.pm.PackageManager.NameNotFoundException;
 import android.net.CaptivePortal;
 import android.net.CaptivePortalData;
 import android.net.ConnectivityManager;
@@ -90,12 +91,16 @@ import android.net.wifi.WifiInfo;
 import android.os.Build;
 import android.os.Bundle;
 import android.os.ConditionVariable;
+import android.os.OutcomeReceiver;
 import android.os.Parcel;
 import android.os.Parcelable;
+import android.os.ServiceSpecificException;
+import android.system.OsConstants;
 import android.util.ArrayMap;
 import android.view.accessibility.AccessibilityEvent;
 import android.widget.Toast;
 
+import androidx.annotation.NonNull;
 import androidx.browser.customtabs.CustomTabsCallback;
 import androidx.browser.customtabs.CustomTabsClient;
 import androidx.browser.customtabs.CustomTabsIntent;
@@ -110,6 +115,9 @@ import androidx.test.uiautomator.UiDevice;
 import androidx.test.uiautomator.UiObject;
 import androidx.test.uiautomator.UiSelector;
 
+import com.android.testutils.DevSdkIgnoreRule;
+import com.android.testutils.DevSdkIgnoreRule.IgnoreAfter;
+import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo;
 import com.android.testutils.SkipPresubmit;
 import com.android.testutils.TestNetworkTracker;
 import com.android.testutils.com.android.testutils.SetFeatureFlagsRule;
@@ -132,6 +140,7 @@ import java.util.Collections;
 import java.util.HashMap;
 import java.util.Map;
 import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.Executor;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.TimeoutException;
 import java.util.concurrent.atomic.AtomicReference;
@@ -145,6 +154,7 @@ import fi.iki.elonen.NanoHTTPD;
 public class CaptivePortalLoginActivityTest {
     private static final String TEST_URL = "http://android.test.com";
     private static final int TEST_NETID = 1234;
+    private static final int TEST_CUSTOM_TABS_PROVIDER_UID = 12345;
     private static final String TEST_NC_SSID = "Test NetworkCapabilities SSID";
     private static final String TEST_WIFIINFO_SSID = "Test Other SSID";
     private static final String TEST_URL_QUERY = "testquery";
@@ -169,13 +179,15 @@ public class CaptivePortalLoginActivityTest {
     private static DownloadService.DownloadServiceBinder sDownloadServiceBinder;
     private static CustomTabsClient sMockCustomTabsClient;
     private static ArrayMap<String, Boolean> sFeatureFlags = new ArrayMap<>();
-    private static boolean sIsMultiNetworkingSupported;
+    private static boolean sIsMultiNetworkingSupportedByProvider;
     @Rule
     public final SetFeatureFlagsRule mSetFeatureFlagsRule =
             new SetFeatureFlagsRule((name, enabled) -> {
                 sFeatureFlags.put(name, enabled);
                 return null;
             }, (name) -> sFeatureFlags.getOrDefault(name, false));
+    @Rule
+    public final DevSdkIgnoreRule mIgnoreRule = new DevSdkIgnoreRule();
 
     public static class InstrumentedCaptivePortalLoginActivity extends CaptivePortalLoginActivity {
         private final ConditionVariable mDestroyedCv = new ConditionVariable(false);
@@ -253,6 +265,11 @@ public class CaptivePortalLoginActivityTest {
             mDlServiceunbindCv.open();
         }
 
+        @Override
+        Context getContextForCustomTabsBinding() {
+            return this;
+        }
+
         @Override
         public void startActivity(Intent intent) {
             if (Intent.ACTION_VIEW.equals(intent.getAction())
@@ -275,9 +292,15 @@ public class CaptivePortalLoginActivityTest {
             return TEST_CUSTOM_TABS_PACKAGE_NAME;
         }
 
+        @Override
+        int getPackageUid(@NonNull final String customTabsProviderPackageName)
+                throws NameNotFoundException {
+            return TEST_CUSTOM_TABS_PROVIDER_UID;
+        }
+
         @Override
         boolean isMultiNetworkingSupportedByProvider(final String defaultPackageName) {
-            return sIsMultiNetworkingSupported;
+            return sIsMultiNetworkingSupportedByProvider;
         }
 
         @Override
@@ -285,26 +308,36 @@ public class CaptivePortalLoginActivityTest {
             if (sFeatureFlags.get(name) == null) return false;
             return sFeatureFlags.get(name);
         }
+
+        @Override
+        boolean getDeviceConfigPropertyBoolean(final String name, boolean defaultValue) {
+            return defaultValue;
+        }
     }
 
     /** Class to replace CaptivePortal to prevent mock object is updated and replaced by parcel. */
     public static class MockCaptivePortal extends CaptivePortal {
+        public OutcomeReceiver<Void, ServiceSpecificException> mDelegateUidReceiver;
+
         int mDismissTimes;
         int mIgnoreTimes;
         int mUseTimes;
         int mReevaluateTimes;
+        int mSetDelegateUidTimes;
 
         private MockCaptivePortal() {
-            this(0, 0, 0, 0);
+            this(0, 0, 0, 0, 0);
         }
         private MockCaptivePortal(int dismissTimes, int ignoreTimes, int useTimes,
-                int reevaluateTimes) {
+                int reevaluateTimes, int setDelegateUidTimes) {
             super(null);
             mDismissTimes = dismissTimes;
             mIgnoreTimes = ignoreTimes;
             mUseTimes = useTimes;
             mReevaluateTimes = reevaluateTimes;
+            mSetDelegateUidTimes = setDelegateUidTimes;
         }
+
         @Override
         public void reportCaptivePortalDismissed() {
             mDismissTimes++;
@@ -325,6 +358,12 @@ public class CaptivePortalLoginActivityTest {
             mReevaluateTimes++;
         }
 
+        @Override
+        public void setDelegateUid(int uid, Executor executor, OutcomeReceiver receiver) {
+            mDelegateUidReceiver = receiver;
+            mSetDelegateUidTimes++;
+        }
+
         @Override
         public void writeToParcel(Parcel out, int flags) {
             out.writeInt(mDismissTimes);
@@ -338,7 +377,7 @@ public class CaptivePortalLoginActivityTest {
                 @Override
                 public MockCaptivePortal createFromParcel(Parcel in) {
                     return new MockCaptivePortal(in.readInt(), in.readInt(), in.readInt(),
-                            in.readInt());
+                            in.readInt(), in.readInt());
                 }
 
                 @Override
@@ -405,6 +444,8 @@ public class CaptivePortalLoginActivityTest {
         if (mTestNetworkTracker != null) {
             runAsShell(MANAGE_TEST_NETWORKS, mTestNetworkTracker::teardown);
         }
+        // Clean up the feature flags to not mess up the next test case.
+        sFeatureFlags.clear();
     }
 
     private void initActivity(String url) {
@@ -1121,10 +1162,8 @@ public class CaptivePortalLoginActivityTest {
         server.stop();
     }
 
-    @Test
-    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
-    public void testCaptivePortalUsingCustomTabs() throws Exception {
-        sIsMultiNetworkingSupported = true;
+    private void runCaptivePortalUsingCustomTabsTest(boolean isVpnBypassable) {
+        sIsMultiNetworkingSupportedByProvider = true;
         final LinkProperties linkProperties = new LinkProperties();
         doReturn(linkProperties).when(sConnectivityManager).getLinkProperties(mNetwork);
 
@@ -1135,10 +1174,19 @@ public class CaptivePortalLoginActivityTest {
         intending(hasPackage(TEST_CUSTOM_TABS_PACKAGE_NAME))
                 .respondWith(new ActivityResult(RESULT_OK, null));
         initActivity(TEST_URL);
+        final MockCaptivePortal cp = getCaptivePortal();
+        if (isVpnBypassable) {
+            mActivityScenario.onActivity(a -> cp.mDelegateUidReceiver.onResult(null));
+        } else {
+            mActivityScenario.onActivity(a -> cp.mDelegateUidReceiver.onError(
+                    new ServiceSpecificException(OsConstants.EBUSY)));
+        }
 
+        // TODO: check the WebView should be initialized if VPN is not allowed to bypass. So far
+        // we force launch the custom tab even if VPN cannot be bypassed in production code.
         final ArgumentCaptor<CustomTabsCallback> captor =
                 ArgumentCaptor.forClass(CustomTabsCallback.class);
-        verify(sMockCustomTabsClient).newSession(captor.capture());
+        verify(sMockCustomTabsClient, timeout(TEST_TIMEOUT_MS)).newSession(captor.capture());
         final CustomTabsCallback callback = captor.getValue();
         assertNotNull(callback);
         intended(allOf(
@@ -1148,61 +1196,68 @@ public class CaptivePortalLoginActivityTest {
 
         // Send navigation start event, verify if the network will be reevaluated.
         callback.onNavigationEvent(NAVIGATION_STARTED, null /* extras */);
-        final MockCaptivePortal cp = getCaptivePortal();
         assertEquals(1, cp.mReevaluateTimes);
+        assertEquals(1, cp.mSetDelegateUidTimes);
     }
 
     @Test
-    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = false)
-    public void testCaptivePortalUsingCustomTabs_flagOff() throws Exception {
-        sIsMultiNetworkingSupported = true;
-        // Set up result stubbing for the CustomTabsIntent#launchUrl, however, the
-        // feature flag is off, therefore, WebView should be used.
-        Intents.init();
-        intending(hasPackage(TEST_CUSTOM_TABS_PACKAGE_NAME))
-                .respondWith(new ActivityResult(RESULT_OK, null));
-        initActivity(TEST_URL);
+    @IgnoreUpTo(Build.VERSION_CODES.R)
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs() throws Exception {
+        runCaptivePortalUsingCustomTabsTest(true /* isVpnBypassable */);
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.R)
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs_bypassVpnFailure() throws Exception {
+        runCaptivePortalUsingCustomTabsTest(false /* isVpnBypassable */);
+    }
+
+    private void verifyWebViewInitialization() {
         verify(sConnectivityManager).bindProcessToNetwork(any());
         verify(sMockCustomTabsClient, never()).newSession(any());
         mActivityScenario.onActivity(activity ->
                 assertNotNull(activity.findViewById(R.id.webview)));
     }
 
-    @Test
-    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
-    public void testCaptivePortalUsingCustomTabs_nullLinkProperties() throws Exception {
-        sIsMultiNetworkingSupported = true;
-        doReturn(null).when(sConnectivityManager).getLinkProperties(mNetwork);
-
-        // Set up result stubbing for the CustomTabsIntent#launchUrl, however, due to the
-        // LinkProperties is null, WebView should be used.
+    private void verifyUsingWebViewRatherThanCustomTabs() {
         Intents.init();
         intending(hasPackage(TEST_CUSTOM_TABS_PACKAGE_NAME))
                 .respondWith(new ActivityResult(RESULT_OK, null));
         initActivity(TEST_URL);
-        verify(sConnectivityManager).bindProcessToNetwork(any());
-        verify(sMockCustomTabsClient, never()).newSession(any());
-        mActivityScenario.onActivity(activity ->
-                assertNotNull(activity.findViewById(R.id.webview)));
+        verifyWebViewInitialization();
+    }
+
+    @Test
+    @IgnoreAfter(Build.VERSION_CODES.R)
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs_setDelegateUidNotSupported_R() throws Exception {
+        sIsMultiNetworkingSupportedByProvider = true;
+        verifyUsingWebViewRatherThanCustomTabs();
+    }
+
+    @Test
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = false)
+    public void testCaptivePortalUsingCustomTabs_flagOff() throws Exception {
+        sIsMultiNetworkingSupportedByProvider = true;
+        verifyUsingWebViewRatherThanCustomTabs();
     }
 
     @Test
     @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
-    public void testCaptivePortalUsingCustomTabs_setNetworkIsnotEnabled() throws Exception {
-        sIsMultiNetworkingSupported = false;
+    public void testCaptivePortalUsingCustomTabs_nullLinkProperties() throws Exception {
+        sIsMultiNetworkingSupportedByProvider = true;
+        doReturn(null).when(sConnectivityManager).getLinkProperties(mNetwork);
+        verifyUsingWebViewRatherThanCustomTabs();
+    }
+
+    @Test
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs_multiNetworkNotSupported() throws Exception {
+        sIsMultiNetworkingSupportedByProvider = false;
         final LinkProperties linkProperties = new LinkProperties();
         doReturn(linkProperties).when(sConnectivityManager).getLinkProperties(mNetwork);
-
-        // Set up result stubbing for the CustomTabsIntent#launchUrl, however, due to the
-        // default browser doesn't support multi-network feature (i.e. isSetNetworkSupport returns
-        // false), WebView should be used.
-        Intents.init();
-        intending(hasPackage(TEST_CUSTOM_TABS_PACKAGE_NAME))
-                .respondWith(new ActivityResult(RESULT_OK, null));
-        initActivity(TEST_URL);
-        verify(sConnectivityManager).bindProcessToNetwork(any());
-        verify(sMockCustomTabsClient, never()).newSession(any());
-        mActivityScenario.onActivity(activity ->
-                assertNotNull(activity.findViewById(R.id.webview)));
+        verifyUsingWebViewRatherThanCustomTabs();
     }
 }
diff --git a/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt b/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt
index 232679e..f17944b 100644
--- a/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt
+++ b/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt
@@ -24,6 +24,7 @@ import android.content.ServiceConnection
 import android.content.res.Configuration
 import android.net.Network
 import android.net.Uri
+import android.os.Build
 import android.os.Bundle
 import android.os.IBinder
 import android.os.Parcel
@@ -31,6 +32,7 @@ import android.os.Parcelable
 import android.os.SystemClock
 import android.util.Log
 import android.widget.TextView
+import androidx.annotation.ChecksSdkIntAtLeast
 import androidx.core.content.FileProvider
 import androidx.test.core.app.ActivityScenario
 import androidx.test.ext.junit.runners.AndroidJUnit4
@@ -46,6 +48,11 @@ import androidx.test.uiautomator.Until
 import com.android.captiveportallogin.DownloadService.DOWNLOAD_ABORTED_REASON_FILE_TOO_LARGE
 import com.android.captiveportallogin.DownloadService.DownloadServiceBinder
 import com.android.captiveportallogin.DownloadService.ProgressCallback
+import com.android.modules.utils.build.SdkLevel.isAtLeastS
+import com.android.testutils.ConnectivityDiagnosticsCollector
+import com.android.testutils.DeviceInfoUtils
+import com.android.testutils.runCommandInRootShell
+import com.android.testutils.runCommandInShell
 import java.io.ByteArrayInputStream
 import java.io.File
 import java.io.FileInputStream
@@ -65,11 +72,15 @@ import kotlin.test.assertFalse
 import kotlin.test.assertNotEquals
 import kotlin.test.assertTrue
 import kotlin.test.fail
+import org.junit.AfterClass
 import org.junit.Assert.assertNotNull
 import org.junit.Assume.assumeFalse
 import org.junit.Before
+import org.junit.BeforeClass
 import org.junit.Rule
 import org.junit.Test
+import org.junit.rules.TestWatcher
+import org.junit.runner.Description
 import org.junit.runner.RunWith
 import org.mockito.Mockito.doReturn
 import org.mockito.Mockito.mock
@@ -115,6 +126,65 @@ val mServiceRule = ServiceTestRule()
 @RunWith(AndroidJUnit4::class)
 @SmallTest
 class DownloadServiceTest {
+    companion object {
+        private var originalTraceBufferSizeKb = 0
+
+        // To identify which process is deleting test files during the run (b/317602748), enable
+        // tracing for file deletion in f2fs (the filesystem used for /data on test devices) and
+        // process creation/exit
+        private const val tracePath = "/sys/kernel/tracing"
+        private val traceEnablePaths = listOf(
+            "$tracePath/events/f2fs/f2fs_unlink_enter",
+            "$tracePath/events/sched/sched_process_exec",
+            "$tracePath/events/sched/sched_process_fork",
+            "$tracePath/events/sched/sched_process_exit",
+            "$tracePath/tracing_on"
+        )
+
+        @JvmStatic
+        @BeforeClass
+        fun setUpClass() {
+            if (!enableTracing()) return
+            val originalSize = runCommandInShell("cat $tracePath/buffer_size_kb").trim()
+            // Buffer size may be small on boot when tracing is disabled, and automatically expanded
+            // when enabled (buffer_size_kb will report  something like: "7 (expanded: 1408)"). As
+            // only fixed values can be used when resetting, reset to the expanded size in that
+            // case.
+            val match = Regex("([0-9]+)|[0-9]+ \\(expanded: ([0-9]+)\\)")
+                .matchEntire(originalSize)
+                ?: fail("Could not parse original buffer size: $originalSize")
+            originalTraceBufferSizeKb = (match.groups[2]?.value ?: match.groups[1]?.value)?.toInt()
+                ?: fail("Buffer size not found in $originalSize")
+            traceEnablePaths.forEach {
+                runCommandInRootShell("echo 1 > $it")
+            }
+            runCommandInRootShell("echo 96000 > $tracePath/buffer_size_kb")
+        }
+
+        @JvmStatic
+        @AfterClass
+        fun tearDownClass() {
+            if (!enableTracing()) return
+            traceEnablePaths.asReversed().forEach {
+                runCommandInRootShell("echo 0 > $it")
+            }
+            runCommandInRootShell("echo $originalTraceBufferSizeKb > $tracePath/buffer_size_kb")
+        }
+
+        @ChecksSdkIntAtLeast(Build.VERSION_CODES.S)
+        fun enableTracing() = DeviceInfoUtils.isDebuggable() && isAtLeastS()
+    }
+
+    @get:Rule
+    val collectTraceOnFailureRule = object : TestWatcher() {
+        override fun failed(e: Throwable, description: Description) {
+            if (!enableTracing()) return
+            ConnectivityDiagnosticsCollector.instance?.let {
+                it.collectCommandOutput("su 0 cat $tracePath/trace")
+            }
+        }
+    }
+
     private val connection = mock(HttpURLConnection::class.java)
 
     private val context by lazy { getInstrumentation().context }
```

