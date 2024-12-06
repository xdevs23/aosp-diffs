```diff
diff --git a/Android.bp b/Android.bp
index 8b66e37..da1c676 100644
--- a/Android.bp
+++ b/Android.bp
@@ -21,34 +21,62 @@ package {
 
 java_defaults {
     name: "CaptivePortalLoginDefaults",
-    srcs: ["src/**/*.java"],
     sdk_version: "module_current",
     min_sdk_version: "30",
     target_sdk_version: "35", // Keep in sync with CaptivePortalLoginTests
+    lint: {
+        strict_updatability_linting: true,
+    },
+    optimize: {
+        ignore_warnings: false,
+    },
+}
+
+android_library {
+    name: "CaptivePortalLoginLib",
+    defaults: ["CaptivePortalLoginDefaults"],
+    srcs: ["src/**/*.java"],
     static_libs: [
         "androidx.annotation_annotation",
+        "androidx.browser_browser",
         "androidx.legacy_legacy-support-core-ui",
         "captiveportal-lib",
         "metrics-constants-protos",
-        "net-utils-device-common",
+        "net-utils-connectivity-apks",
     ],
     libs: [
-        "framework-connectivity",
-        "framework-mediaprovider",
-        "framework-wifi",
+        "framework-connectivity.stubs.module_lib",
+        "framework-mediaprovider.stubs.module_lib",
+        "framework-wifi.stubs.module_lib",
     ],
     manifest: "AndroidManifest.xml",
-    lint: {
-        strict_updatability_linting: true,
-    },
-    optimize: {
-        ignore_warnings: false,
-    },
+}
+
+java_genrule {
+    name: "CaptivePortalLoginJarJarRules",
+    tool_files: [
+        ":CaptivePortalLoginLib{.jar}",
+        "jarjar-excludes.txt",
+    ],
+    tools: [
+        "jarjar-rules-generator",
+    ],
+    out: ["CaptivePortalLoginJarJarRules.txt"],
+    cmd: "$(location jarjar-rules-generator) " +
+        "$(location :CaptivePortalLoginLib{.jar}) " +
+        "--excludes $(location jarjar-excludes.txt) " +
+        "--prefix com.android.captiveportallogin " +
+        "--output $(out)",
+    visibility: [
+        "//packages/modules/CaptivePortalLogin:__subpackages__",
+    ],
 }
 
 android_app {
     name: "CaptivePortalLogin",
     defaults: ["CaptivePortalLoginDefaults"],
+    static_libs: ["CaptivePortalLoginLib"],
+    jarjar_rules: ":CaptivePortalLoginJarJarRules",
     certificate: "networkstack",
     updatable: true,
 }
@@ -56,7 +84,10 @@ android_app {
 android_library {
     name: "CaptivePortalLoginTestLib",
     defaults: ["CaptivePortalLoginDefaults"],
-    static_libs: ["net-tests-utils"],
+    static_libs: [
+        "CaptivePortalLoginLib",
+        "net-tests-utils",
+    ],
     lint: {
         strict_updatability_linting: true,
     },
@@ -67,6 +98,7 @@ android_library {
 android_app {
     name: "PlatformCaptivePortalLogin",
     defaults: ["CaptivePortalLoginDefaults"],
+    static_libs: ["CaptivePortalLoginLib"],
     certificate: "platform",
     overrides: ["CaptivePortalLogin"],
     lint: {
diff --git a/jarjar-excludes.txt b/jarjar-excludes.txt
new file mode 100644
index 0000000..d9f681c
--- /dev/null
+++ b/jarjar-excludes.txt
@@ -0,0 +1,5 @@
+# Exclude "androidx" package prefix, otherwise, some classes within this package
+# such as "androidx.startup.InitializationProvider" cannot be found when launching
+# the CaptivePortalActivity, also androidx is typically used by apps as-is so it
+# should not conflict with classes in the bootclasspath.
+androidx\..+
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 33ea7e9..490441a 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -8,7 +8,7 @@
     <string name="action_bar_title" msgid="2566334512545554724">"‏سجّل الدخول إلى %1$s"</string>
     <string name="ssl_error_warning" msgid="494203210316238046">"الشبكة التي تحاول الانضمام إليها بها مشاكل أمنية."</string>
     <string name="ssl_error_example" msgid="4574594291839092653">"على سبيل المثال، قد لا تنتمي صفحة تسجيل الدخول إلى المنظمة المعروضة."</string>
-    <string name="no_bypass_error_vpnwarning" msgid="5263739853101734851">"‏بالإضافة إلى ذلك، لا يمكن تجاوز هذا الخطأ لأن الجهاز يعمل الآن من خلال شبكة افتراضية خاصة (VPN)."</string>
+    <string name="no_bypass_error_vpnwarning" msgid="5263739853101734851">"‏بالإضافة إلى ذلك، لا يمكن تجاوز هذا الخطأ لأن الجهاز يعمل الآن من خلال شبكة VPN."</string>
     <string name="error_continue_via_browser" msgid="7091550471744444659">"المتابعة على أي حال باستخدام المتصفح"</string>
     <string name="ssl_error_untrusted" msgid="5183246242332501768">"هذه الشهادة ليست من جهة موثوق بها."</string>
     <string name="ssl_error_mismatch" msgid="5260665486390938291">"لا يتطابق اسم الموقع مع الاسم على الشهادة."</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 647a582..8f1b806 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -8,7 +8,7 @@
     <string name="action_bar_title" msgid="2566334512545554724">"%1$s मा साइन इन गर्नुहोस्"</string>
     <string name="ssl_error_warning" msgid="494203210316238046">"तपाईँले सामेल हुन प्रयास गरिरहनु भएको नेटवर्कमा सुरक्षा मुद्दाहरू छन्।"</string>
     <string name="ssl_error_example" msgid="4574594291839092653">"उदाहरणका लागि, लग इन पृष्ठ देखाइएको संस्थाको नहुन सक्छ।"</string>
-    <string name="no_bypass_error_vpnwarning" msgid="5263739853101734851">"यसका अतिरिक्त, यो यन्त्रले हाल VPN प्रयोग गरिरहेको हुनाले यो त्रुटि बेवास्ता गरेर अगाडि बढ्न सम्भव छैन।"</string>
+    <string name="no_bypass_error_vpnwarning" msgid="5263739853101734851">"यसका अतिरिक्त, यो डिभाइसले हाल VPN प्रयोग गरिरहेको हुनाले यो त्रुटि बेवास्ता गरेर अगाडि बढ्न सम्भव छैन।"</string>
     <string name="error_continue_via_browser" msgid="7091550471744444659">"तैपनि ब्राउजरमार्फत जारी राख्नुहोस्"</string>
     <string name="ssl_error_untrusted" msgid="5183246242332501768">"यो विश्वसनीय प्राधिकरणबाट उपलब्ध गराइएको प्रमाणपत्र होइन।"</string>
     <string name="ssl_error_mismatch" msgid="5260665486390938291">"प्रमाणपत्रमा भएको नाम साइटमा भएको नामसँग मेल खाँदैन।"</string>
diff --git a/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java b/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java
index 7245a18..2a771c3 100755
--- a/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java
+++ b/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java
@@ -19,6 +19,9 @@ package com.android.captiveportallogin;
 import static android.net.ConnectivityManager.EXTRA_CAPTIVE_PORTAL_PROBE_SPEC;
 import static android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED;
 
+import static androidx.browser.customtabs.CustomTabsCallback.NAVIGATION_STARTED;
+
+import static com.android.captiveportallogin.CaptivePortalLoginFlags.CAPTIVE_PORTAL_CUSTOM_TABS;
 import static com.android.captiveportallogin.DownloadService.isDirectlyOpenType;
 
 import android.app.Activity;
@@ -86,17 +89,22 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.StringRes;
 import androidx.annotation.VisibleForTesting;
+import androidx.browser.customtabs.CustomTabsCallback;
+import androidx.browser.customtabs.CustomTabsClient;
+import androidx.browser.customtabs.CustomTabsIntent;
+import androidx.browser.customtabs.CustomTabsServiceConnection;
+import androidx.browser.customtabs.CustomTabsSession;
 import androidx.core.content.FileProvider;
 import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
 
 import com.android.internal.logging.nano.MetricsProto.MetricsEvent;
+import com.android.net.module.util.DeviceConfigUtils;
 
 import java.io.File;
 import java.io.FileNotFoundException;
 import java.io.IOException;
 import java.lang.reflect.Field;
 import java.lang.reflect.Method;
-import java.net.HttpURLConnection;
 import java.net.MalformedURLException;
 import java.net.URL;
 import java.net.URLConnection;
@@ -146,9 +154,55 @@ public class CaptivePortalLoginActivity extends Activity {
     private boolean mLaunchBrowser = false;
     private MyWebViewClient mWebViewClient;
     private SwipeRefreshLayout mSwipeRefreshLayout;
+    // This member is just used in the UI thread model(e.g. onCreate and onDestroy), so non-final
+    // should be fine.
+    private boolean mCaptivePortalCustomTabsEnabled;
     // Ensures that done() happens once exactly, handling concurrent callers with atomic operations.
     private final AtomicBoolean isDone = new AtomicBoolean(false);
 
+    private final CustomTabsCallback mCustomTabsCallback = new CustomTabsCallback() {
+        @Override
+        public void onNavigationEvent(int navigationEvent, @Nullable Bundle extras) {
+            if (navigationEvent == NAVIGATION_STARTED) {
+                mCaptivePortal.reevaluateNetwork();
+            }
+        }
+    };
+
+    private final CustomTabsServiceConnection mCustomTabsServiceConnection =
+            new CustomTabsServiceConnection() {
+                    @Override
+                    public void onCustomTabsServiceConnected(@NonNull ComponentName name,
+                            @NonNull CustomTabsClient client) {
+                        Log.d(TAG, "CustomTabs service connected");
+                        final CustomTabsSession session = client.newSession(mCustomTabsCallback);
+                        // The application package name that will resolve to the CustomTabs intent
+                        // has been set in {@Link CustomTabsIntent.Builder} constructor, unnecessary
+                        // to call {@Link Intent#setPackage} to explicitly specify the package name
+                        // again.
+                        final CustomTabsIntent customTabsIntent =
+                                new CustomTabsIntent.Builder(session)
+                                        .setNetwork(mNetwork)
+                                        .setShareState(CustomTabsIntent.SHARE_STATE_OFF)
+                                        .setShowTitle(true /* showTitle */)
+                                        .build();
+
+                        // Remove Referrer Header from HTTP probe packet by setting an empty Uri
+                        // instance in EXTRA_REFERRER, make sure users using custom tabs have the
+                        // same experience as the custom tabs browser.
+                        final String emptyReferrer = "";
+                        customTabsIntent.intent.putExtra(Intent.EXTRA_REFERRER,
+                                Uri.parse(emptyReferrer));
+                        customTabsIntent.launchUrl(CaptivePortalLoginActivity.this,
+                                Uri.parse(mUrl.toString()));
+                    }
+
+                    @Override
+                    public void onServiceDisconnected(ComponentName componentName) {
+                        Log.d(TAG, "CustomTabs service disconnected");
+                    }
+            };
+
     // When starting downloads a file is created via startActivityForResult(ACTION_CREATE_DOCUMENT).
     // This array keeps the download request until the activity result is received. It is keyed by
     // requestCode sent in startActivityForResult.
@@ -226,6 +280,11 @@ public class CaptivePortalLoginActivity extends Activity {
         }
     };
 
+    @VisibleForTesting
+    boolean isFeatureEnabled(final String name) {
+        return DeviceConfigUtils.isCaptivePortalLoginFeatureEnabled(getApplicationContext(), name);
+    }
+
     private void maybeStartPendingDownloads() {
         ensureRunningOnMainThread();
 
@@ -282,9 +341,92 @@ public class CaptivePortalLoginActivity extends Activity {
         }
     }
 
+    @VisibleForTesting
+    @Nullable
+    String getDefaultCustomTabsProviderPackage() {
+        return CustomTabsClient.getPackageName(getApplicationContext(), null /* packages */);
+    }
+
+    @VisibleForTesting
+    boolean isMultiNetworkingSupportedByProvider(@NonNull final String defaultPackageName) {
+        return CustomTabsClient.isSetNetworkSupported(getApplicationContext(), defaultPackageName);
+    }
+
+    private void initializeWebView() {
+        // Also initializes proxy system properties.
+        mCm.bindProcessToNetwork(mNetwork);
+
+        // Proxy system properties must be initialized before setContentView is called
+        // because setContentView initializes the WebView logic which in turn reads the
+        // system properties.
+        setContentView(R.layout.activity_captive_portal_login);
+
+        getActionBar().setDisplayShowHomeEnabled(false);
+        getActionBar().setElevation(0); // remove shadow
+        getActionBar().setTitle(getHeaderTitle());
+        getActionBar().setSubtitle("");
+
+        final WebView webview = getWebview();
+        webview.clearCache(true);
+        CookieManager.getInstance().setAcceptThirdPartyCookies(webview, true);
+        WebSettings webSettings = webview.getSettings();
+        webSettings.setJavaScriptEnabled(true);
+        webSettings.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);
+        webSettings.setUseWideViewPort(true);
+        webSettings.setLoadWithOverviewMode(true);
+        webSettings.setSupportZoom(true);
+        webSettings.setBuiltInZoomControls(true);
+        webSettings.setDisplayZoomControls(false);
+        webSettings.setDomStorageEnabled(true);
+        mWebViewClient = new MyWebViewClient();
+        webview.setWebViewClient(mWebViewClient);
+        webview.setWebChromeClient(new MyWebChromeClient());
+        webview.setDownloadListener(new PortalDownloadListener());
+        // Start initial page load so WebView finishes loading proxy settings.
+        // Actual load of mUrl is initiated by MyWebViewClient.
+        webview.loadData("", "text/html", null);
+
+        mSwipeRefreshLayout = findViewById(R.id.swipe_refresh);
+        mSwipeRefreshLayout.setOnRefreshListener(() -> {
+            webview.reload();
+            mSwipeRefreshLayout.setRefreshing(true);
+        });
+    }
+
+    @Nullable
+    private String getCustomTabsProviderPackageIfEnabled() {
+        if (!mCaptivePortalCustomTabsEnabled) return null;
+
+        final String defaultPackageName = getDefaultCustomTabsProviderPackage();
+        if (defaultPackageName == null) {
+            Log.i(TAG, "Default browser doesn't support custom tabs");
+            return null;
+        }
+
+        final boolean support = isMultiNetworkingSupportedByProvider(defaultPackageName);
+        if (!support) {
+            Log.i(TAG, "Default browser doesn't support multi-network");
+            return null;
+        }
+
+        final LinkProperties lp = mCm.getLinkProperties(mNetwork);
+        if (lp == null || lp.getPrivateDnsServerName() != null) {
+            Log.i(TAG, "Do not use custom tabs if private DNS (strict mode) is enabled");
+            return null;
+        }
+
+        // TODO: b/330670424
+        // - check if privacy settings such as VPN/private DNS is bypassable, otherwise, fallback
+        //   to WebView.
+        return defaultPackageName;
+    }
+
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
+        // Initialize the feature flag after CaptivePortalLoginActivity is created, otherwise, the
+        // context is still null and throw NPE when fetching the package manager from context.
+        mCaptivePortalCustomTabsEnabled = isFeatureEnabled(CAPTIVE_PORTAL_CUSTOM_TABS);
         mCaptivePortal = getIntent().getParcelableExtra(ConnectivityManager.EXTRA_CAPTIVE_PORTAL);
         // Null CaptivePortal is unexpected. The following flow will need to access mCaptivePortal
         // to communicate with system. Thus, finish the activity.
@@ -297,6 +439,7 @@ public class CaptivePortalLoginActivity extends Activity {
         mDpm = getSystemService(DevicePolicyManager.class);
         mWifiManager = getSystemService(WifiManager.class);
         mNetwork = getIntent().getParcelableExtra(ConnectivityManager.EXTRA_NETWORK);
+        mNetwork = mNetwork.getPrivateDnsBypassingCopy();
         mVenueFriendlyName = getVenueFriendlyName();
         mUserAgent =
                 getIntent().getStringExtra(ConnectivityManager.EXTRA_CAPTIVE_PORTAL_USER_AGENT);
@@ -340,44 +483,13 @@ public class CaptivePortalLoginActivity extends Activity {
             return;
         }
 
-        // Also initializes proxy system properties.
-        mNetwork = mNetwork.getPrivateDnsBypassingCopy();
-        mCm.bindProcessToNetwork(mNetwork);
-
-        // Proxy system properties must be initialized before setContentView is called because
-        // setContentView initializes the WebView logic which in turn reads the system properties.
-        setContentView(R.layout.activity_captive_portal_login);
-
-        getActionBar().setDisplayShowHomeEnabled(false);
-        getActionBar().setElevation(0); // remove shadow
-        getActionBar().setTitle(getHeaderTitle());
-        getActionBar().setSubtitle("");
-
-        final WebView webview = getWebview();
-        webview.clearCache(true);
-        CookieManager.getInstance().setAcceptThirdPartyCookies(webview, true);
-        WebSettings webSettings = webview.getSettings();
-        webSettings.setJavaScriptEnabled(true);
-        webSettings.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);
-        webSettings.setUseWideViewPort(true);
-        webSettings.setLoadWithOverviewMode(true);
-        webSettings.setSupportZoom(true);
-        webSettings.setBuiltInZoomControls(true);
-        webSettings.setDisplayZoomControls(false);
-        webSettings.setDomStorageEnabled(true);
-        mWebViewClient = new MyWebViewClient();
-        webview.setWebViewClient(mWebViewClient);
-        webview.setWebChromeClient(new MyWebChromeClient());
-        webview.setDownloadListener(new PortalDownloadListener());
-        // Start initial page load so WebView finishes loading proxy settings.
-        // Actual load of mUrl is initiated by MyWebViewClient.
-        webview.loadData("", "text/html", null);
-
-        mSwipeRefreshLayout = findViewById(R.id.swipe_refresh);
-        mSwipeRefreshLayout.setOnRefreshListener(() -> {
-                webview.reload();
-                mSwipeRefreshLayout.setRefreshing(true);
-            });
+        final String customTabsProviderPackage = getCustomTabsProviderPackageIfEnabled();
+        if (customTabsProviderPackage == null) {
+            initializeWebView();
+        } else {
+            CustomTabsClient.bindCustomTabsService(this, customTabsProviderPackage,
+                    mCustomTabsServiceConnection);
+        }
 
         maybeDeleteDirectlyOpenFile();
     }
@@ -414,29 +526,12 @@ public class CaptivePortalLoginActivity extends Activity {
     @VisibleForTesting
     void handleCapabilitiesChanged(@NonNull final Network network,
             @NonNull final NetworkCapabilities nc) {
-        if (!isNetworkValidationDismissEnabled()) {
-            return;
-        }
-
         if (network.equals(mNetwork) && nc.hasCapability(NET_CAPABILITY_VALIDATED)) {
             // Dismiss when login is no longer needed since network has validated, exit.
             done(Result.DISMISSED);
         }
     }
 
-    /**
-     * Indicates whether network validation (NET_CAPABILITY_VALIDATED) should be used to determine
-     * when the portal should be dismissed, instead of having the CaptivePortalLoginActivity use
-     * its own probe.
-     */
-    private boolean isNetworkValidationDismissEnabled() {
-        return isAtLeastR();
-    }
-
-    private boolean isAtLeastR() {
-        return Build.VERSION.SDK_INT > Build.VERSION_CODES.Q;
-    }
-
     // Find WebView's proxy BroadcastReceiver and prompt it to read proxy system properties.
     private void setWebViewProxy() {
         // TODO: migrate to androidx WebView proxy setting API as soon as it is finalized
@@ -567,6 +662,10 @@ public class CaptivePortalLoginActivity extends Activity {
             unbindService(mDownloadServiceConn);
         }
 
+        if (mCaptivePortalCustomTabsEnabled) {
+            unbindService(mCustomTabsServiceConnection);
+        }
+
         final WebView webview = (WebView) findViewById(R.id.webview);
         if (webview != null) {
             webview.stopLoading();
@@ -665,70 +764,6 @@ public class CaptivePortalLoginActivity extends Activity {
         return SystemProperties.getInt("ro.debuggable", 0) == 1;
     }
 
-    private void reevaluateNetwork() {
-        if (isNetworkValidationDismissEnabled()) {
-            // TODO : replace this with an actual call to the method when the network stack
-            // is built against a recent enough SDK.
-            if (callVoidMethodIfExists(mCaptivePortal, "reevaluateNetwork")) return;
-        }
-        testForCaptivePortal();
-    }
-
-    private boolean callVoidMethodIfExists(@NonNull final Object target,
-            @NonNull final String methodName) {
-        try {
-            final Method method = target.getClass().getDeclaredMethod(methodName);
-            method.invoke(target);
-            return true;
-        } catch (ReflectiveOperationException e) {
-            return false;
-        }
-    }
-
-    private void testForCaptivePortal() {
-        // TODO: NetworkMonitor validation is used on R+ instead; remove when dropping Q support.
-        new Thread(new Runnable() {
-            public void run() {
-                // Give time for captive portal to open.
-                try {
-                    Thread.sleep(1000);
-                } catch (InterruptedException e) {
-                }
-                HttpURLConnection urlConnection = null;
-                int httpResponseCode = 500;
-                String locationHeader = null;
-                try {
-                    urlConnection = (HttpURLConnection) mNetwork.openConnection(mUrl);
-                    urlConnection.setInstanceFollowRedirects(false);
-                    urlConnection.setConnectTimeout(SOCKET_TIMEOUT_MS);
-                    urlConnection.setReadTimeout(SOCKET_TIMEOUT_MS);
-                    urlConnection.setUseCaches(false);
-                    if (mUserAgent != null) {
-                       urlConnection.setRequestProperty("User-Agent", mUserAgent);
-                    }
-                    // cannot read request header after connection
-                    String requestHeader = urlConnection.getRequestProperties().toString();
-
-                    urlConnection.getInputStream();
-                    httpResponseCode = urlConnection.getResponseCode();
-                    locationHeader = urlConnection.getHeaderField(HTTP_LOCATION_HEADER_NAME);
-                    if (DBG) {
-                        Log.d(TAG, "probe at " + mUrl +
-                                " ret=" + httpResponseCode +
-                                " request=" + requestHeader +
-                                " headers=" + urlConnection.getHeaderFields());
-                    }
-                } catch (IOException e) {
-                } finally {
-                    if (urlConnection != null) urlConnection.disconnect();
-                }
-                if (isDismissed(httpResponseCode, locationHeader, mProbeSpec)) {
-                    done(Result.DISMISSED);
-                }
-            }
-        }).start();
-    }
-
     private static boolean isDismissed(
             int httpResponseCode, String locationHeader, CaptivePortalProbeSpec probeSpec) {
         return (probeSpec != null)
@@ -800,7 +835,7 @@ public class CaptivePortalLoginActivity extends Activity {
                 getActionBar().setSubtitle(subtitle);
             }
             getProgressBar().setVisibility(View.VISIBLE);
-            reevaluateNetwork();
+            mCaptivePortal.reevaluateNetwork();
         }
 
         @Override
@@ -822,7 +857,7 @@ public class CaptivePortalLoginActivity extends Activity {
                 view.requestFocus();
                 view.clearHistory();
             }
-            reevaluateNetwork();
+            mCaptivePortal.reevaluateNetwork();
         }
 
         // Convert Android scaled-pixels (sp) to HTML size.
@@ -896,7 +931,7 @@ public class CaptivePortalLoginActivity extends Activity {
             // Before Android R, CaptivePortalLogin cannot call the isAlwaysOnVpnLockdownEnabled()
             // to get the status of VPN always-on due to permission denied. So adding a version
             // check here to prevent CaptivePortalLogin crashes.
-            if (hasVpnNetwork() || (isAtLeastR() && isAlwaysOnVpnEnabled())) {
+            if (hasVpnNetwork() || isAlwaysOnVpnEnabled()) {
                 final String vpnWarning = getString(R.string.no_bypass_error_vpnwarning);
                 return "  <div class=vpnwarning>" + vpnWarning + "</div><br>";
             }
@@ -1264,9 +1299,6 @@ public class CaptivePortalLoginActivity extends Activity {
     }
 
     private CharSequence getVenueFriendlyName() {
-        if (!isAtLeastR()) {
-            return null;
-        }
         final LinkProperties linkProperties = mCm.getLinkProperties(mNetwork);
         if (linkProperties == null) {
             return null;
diff --git a/src/com/android/captiveportallogin/DownloadService.java b/src/com/android/captiveportallogin/DownloadService.java
index 62b2365..68ea0c5 100644
--- a/src/com/android/captiveportallogin/DownloadService.java
+++ b/src/com/android/captiveportallogin/DownloadService.java
@@ -326,7 +326,7 @@ public class DownloadService extends Service {
                     final InputStream is = connection.getInputStream();
 
                     if (!downloadToFile(is, fop, contentLength, task, nm)) {
-                        // Download cancelled
+                        Log.d(TAG, "Download cancelled, deleting " + task.mOutFile);
                         tryDeleteFile(task.mOutFile);
                         // Don't clear the notification: this will be done when the service stops
                         // (foreground service notifications cannot be cleared).
@@ -338,7 +338,7 @@ public class DownloadService extends Service {
                 updateNotification(nm, NOTE_DOWNLOAD_DONE, task.mMimeType,
                         makeDoneNotification(task));
             } catch (IOException e) {
-                Log.e(DownloadService.class.getSimpleName(), "Download error", e);
+                Log.e(TAG, "Download error, deleting " + task.mOutFile, e);
                 updateNotification(nm, NOTE_DOWNLOAD_DONE, task.mMimeType,
                         makeErrorNotification(task.mDisplayName));
                 tryDeleteFile(task.mOutFile);
diff --git a/tests/Android.bp b/tests/Android.bp
index f8195a1..3b405c1 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -54,9 +54,9 @@ android_test {
         "net-tests-utils",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs",
+        "android.test.base.stubs",
+        "android.test.mock.stubs",
     ],
     // If CaptivePortalLoginActivityTest wants to run on Q device, it needs to set sdk_version for
     // using the portable JNI libraries.
diff --git a/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java b/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
index 0bb48c4..b3cd4b6 100644
--- a/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
+++ b/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
@@ -27,15 +27,22 @@ import static android.net.ConnectivityManager.EXTRA_NETWORK;
 import static android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED;
 import static android.view.accessibility.AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED;
 
+import static androidx.browser.customtabs.CustomTabsCallback.NAVIGATION_STARTED;
+import static androidx.browser.customtabs.CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION;
 import static androidx.lifecycle.Lifecycle.State.DESTROYED;
+import static androidx.test.espresso.intent.Intents.intended;
 import static androidx.test.espresso.intent.Intents.intending;
 import static androidx.test.espresso.intent.matcher.IntentMatchers.hasAction;
+import static androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra;
+import static androidx.test.espresso.intent.matcher.IntentMatchers.hasData;
+import static androidx.test.espresso.intent.matcher.IntentMatchers.hasPackage;
 import static androidx.test.espresso.intent.matcher.IntentMatchers.isInternal;
 import static androidx.test.espresso.web.sugar.Web.onWebView;
 import static androidx.test.espresso.web.webdriver.DriverAtoms.findElement;
 import static androidx.test.espresso.web.webdriver.DriverAtoms.webClick;
 import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;
 
+import static com.android.captiveportallogin.CaptivePortalLoginFlags.CAPTIVE_PORTAL_CUSTOM_TABS;
 import static com.android.captiveportallogin.DownloadService.DOWNLOAD_ABORTED_REASON_FILE_TOO_LARGE;
 import static com.android.testutils.TestNetworkTrackerKt.initTestNetwork;
 import static com.android.testutils.TestPermissionUtil.runAsShell;
@@ -45,6 +52,7 @@ import static junit.framework.Assert.assertNotNull;
 import static junit.framework.Assert.assertNull;
 
 import static org.hamcrest.CoreMatchers.not;
+import static org.hamcrest.core.AllOf.allOf;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
@@ -54,7 +62,9 @@ import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.anyInt;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
+import static org.mockito.Mockito.timeout;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
@@ -82,9 +92,14 @@ import android.os.Bundle;
 import android.os.ConditionVariable;
 import android.os.Parcel;
 import android.os.Parcelable;
+import android.util.ArrayMap;
 import android.view.accessibility.AccessibilityEvent;
 import android.widget.Toast;
 
+import androidx.browser.customtabs.CustomTabsCallback;
+import androidx.browser.customtabs.CustomTabsClient;
+import androidx.browser.customtabs.CustomTabsIntent;
+import androidx.browser.customtabs.CustomTabsServiceConnection;
 import androidx.test.core.app.ActivityScenario;
 import androidx.test.espresso.intent.Intents;
 import androidx.test.espresso.web.webdriver.Locator;
@@ -97,9 +112,12 @@ import androidx.test.uiautomator.UiSelector;
 
 import com.android.testutils.SkipPresubmit;
 import com.android.testutils.TestNetworkTracker;
+import com.android.testutils.com.android.testutils.SetFeatureFlagsRule;
+import com.android.testutils.com.android.testutils.SetFeatureFlagsRule.FeatureFlag;
 
 import org.junit.After;
 import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
@@ -136,7 +154,10 @@ public class CaptivePortalLoginActivityTest {
     private static final String TEST_USERAGENT = "Test/42.0 Unit-test";
     private static final String TEST_FRIENDLY_NAME = "Network friendly name";
     private static final String TEST_PORTAL_HOSTNAME = "localhost";
+    private static final String TEST_CUSTOM_TABS_PACKAGE_NAME = "com.android.customtabs";
     private static final String TEST_WIFI_CONFIG_TYPE = "application/x-wifi-config";
+    private static final String TEST_DOWNLOAD_SERVICE_COMPONENT_CLASS_NAME =
+            DownloadService.class.getName();
     private ActivityScenario<InstrumentedCaptivePortalLoginActivity> mActivityScenario;
     private Network mNetwork = new Network(TEST_NETID);
     private TestNetworkTracker mTestNetworkTracker;
@@ -146,6 +167,15 @@ public class CaptivePortalLoginActivityTest {
     private static ConnectivityManager sConnectivityManager;
     private static DevicePolicyManager sMockDevicePolicyManager;
     private static DownloadService.DownloadServiceBinder sDownloadServiceBinder;
+    private static CustomTabsClient sMockCustomTabsClient;
+    private static ArrayMap<String, Boolean> sFeatureFlags = new ArrayMap<>();
+    private static boolean sIsMultiNetworkingSupported;
+    @Rule
+    public final SetFeatureFlagsRule mSetFeatureFlagsRule =
+            new SetFeatureFlagsRule((name, enabled) -> {
+                sFeatureFlags.put(name, enabled);
+                return null;
+            }, (name) -> sFeatureFlags.getOrDefault(name, false));
 
     public static class InstrumentedCaptivePortalLoginActivity extends CaptivePortalLoginActivity {
         private final ConditionVariable mDestroyedCv = new ConditionVariable(false);
@@ -154,7 +184,9 @@ public class CaptivePortalLoginActivityTest {
         private final CompletableFuture<Intent> mOpenInBrowserIntent =
                 new CompletableFuture<>();
         private Intent mServiceIntent = new Intent();
-        private final CompletableFuture<ServiceConnection> mServiceBound =
+        private final CompletableFuture<ServiceConnection> mDownloadServiceBound =
+                new CompletableFuture<>();
+        private final CompletableFuture<CustomTabsServiceConnection> mCustomTabsServiceBound =
                 new CompletableFuture<>();
         private final ConditionVariable mDlServiceunbindCv = new ConditionVariable(false);
 
@@ -198,11 +230,21 @@ public class CaptivePortalLoginActivityTest {
 
         @Override
         public boolean bindService(Intent service, ServiceConnection conn, int flags) {
-            assertTrue("Multiple foreground services were bound during the test",
-                    mServiceBound.complete(conn));
-            getMainThreadHandler().post(() -> conn.onServiceConnected(
-                    getInstrumentation().getComponentName(), sDownloadServiceBinder));
-
+            if (service.getAction() == null
+                    && service.getComponent().getClassName().equals(
+                            TEST_DOWNLOAD_SERVICE_COMPONENT_CLASS_NAME)) {
+                assertTrue("Download foreground service was bound multiple times during the test",
+                        mDownloadServiceBound.complete(conn));
+                getMainThreadHandler().post(() -> conn.onServiceConnected(
+                        getInstrumentation().getComponentName(), sDownloadServiceBinder));
+            } else if (service.getAction().equals(ACTION_CUSTOM_TABS_CONNECTION)) {
+                assertTrue("CustomTabs foreground service was bound multiple times during the test",
+                        mCustomTabsServiceBound.complete((CustomTabsServiceConnection) conn));
+                getMainThreadHandler().post(() -> {
+                    ((CustomTabsServiceConnection) conn).onCustomTabsServiceConnected(
+                            getInstrumentation().getComponentName(), sMockCustomTabsClient);
+                });
+            }
             return true;
         }
 
@@ -227,6 +269,22 @@ public class CaptivePortalLoginActivityTest {
             // Matches the test provider in the test app manifest
             return "com.android.captiveportallogin.tests.fileprovider";
         }
+
+        @Override
+        String getDefaultCustomTabsProviderPackage() {
+            return TEST_CUSTOM_TABS_PACKAGE_NAME;
+        }
+
+        @Override
+        boolean isMultiNetworkingSupportedByProvider(final String defaultPackageName) {
+            return sIsMultiNetworkingSupported;
+        }
+
+        @Override
+        boolean isFeatureEnabled(final String name) {
+            if (sFeatureFlags.get(name) == null) return false;
+            return sFeatureFlags.get(name);
+        }
     }
 
     /** Class to replace CaptivePortal to prevent mock object is updated and replaced by parcel. */
@@ -234,15 +292,18 @@ public class CaptivePortalLoginActivityTest {
         int mDismissTimes;
         int mIgnoreTimes;
         int mUseTimes;
+        int mReevaluateTimes;
 
         private MockCaptivePortal() {
-            this(0, 0, 0);
+            this(0, 0, 0, 0);
         }
-        private MockCaptivePortal(int dismissTimes, int ignoreTimes, int useTimes) {
+        private MockCaptivePortal(int dismissTimes, int ignoreTimes, int useTimes,
+                int reevaluateTimes) {
             super(null);
             mDismissTimes = dismissTimes;
             mIgnoreTimes = ignoreTimes;
             mUseTimes = useTimes;
+            mReevaluateTimes = reevaluateTimes;
         }
         @Override
         public void reportCaptivePortalDismissed() {
@@ -259,18 +320,25 @@ public class CaptivePortalLoginActivityTest {
             mUseTimes++;
         }
 
+        @Override
+        public void reevaluateNetwork() {
+            mReevaluateTimes++;
+        }
+
         @Override
         public void writeToParcel(Parcel out, int flags) {
             out.writeInt(mDismissTimes);
             out.writeInt(mIgnoreTimes);
             out.writeInt(mUseTimes);
+            out.writeInt(mReevaluateTimes);
         }
 
         public static final Parcelable.Creator<MockCaptivePortal> CREATOR =
                 new Parcelable.Creator<MockCaptivePortal>() {
                 @Override
                 public MockCaptivePortal createFromParcel(Parcel in) {
-                    return new MockCaptivePortal(in.readInt(), in.readInt(), in.readInt());
+                    return new MockCaptivePortal(in.readInt(), in.readInt(), in.readInt(),
+                            in.readInt());
                 }
 
                 @Override
@@ -286,6 +354,7 @@ public class CaptivePortalLoginActivityTest {
         sConnectivityManager = spy(context.getSystemService(ConnectivityManager.class));
         sMockDevicePolicyManager = mock(DevicePolicyManager.class);
         sDownloadServiceBinder = mock(DownloadService.DownloadServiceBinder.class);
+        sMockCustomTabsClient = mock(CustomTabsClient.class);
 
         MockitoAnnotations.initMocks(this);
         // Use a real (but test) network for the application. The application will pass this
@@ -355,9 +424,6 @@ public class CaptivePortalLoginActivityTest {
             activity.sendBroadcast(new Intent(Intent.ACTION_CLOSE_SYSTEM_DIALOGS));
         });
         getInstrumentation().waitForIdleSync();
-
-        // Initialize intent capturing after launching the activity to avoid capturing extra intents
-        Intents.init();
     }
 
     @Test
@@ -424,6 +490,10 @@ public class CaptivePortalLoginActivityTest {
     @Test
     public void testHasVpnNetwork() throws Exception {
         initActivity(TEST_URL);
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
+
         // Test non-vpn case.
         configNonVpnNetwork();
         mActivityScenario.onActivity(activity -> assertFalse(activity.hasVpnNetwork()));
@@ -436,6 +506,10 @@ public class CaptivePortalLoginActivityTest {
     @Test
     public void testIsAlwaysOnVpnEnabled() throws Exception {
         initActivity(TEST_URL);
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
+
         doReturn(false).when(sMockDevicePolicyManager).isAlwaysOnVpnLockdownEnabled(any());
         mActivityScenario.onActivity(activity -> assertFalse(activity.isAlwaysOnVpnEnabled()));
 
@@ -445,6 +519,10 @@ public class CaptivePortalLoginActivityTest {
 
     private void runVpnMsgOrLinkToBrowser(boolean useVpnMatcher) {
         initActivity(TEST_URL);
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
+
         // Test non-vpn case.
         configNonVpnNetwork();
         doReturn(false).when(sMockDevicePolicyManager).isAlwaysOnVpnLockdownEnabled(any());
@@ -523,6 +601,10 @@ public class CaptivePortalLoginActivityTest {
     @Test @SdkSuppress(minSdkVersion = Build.VERSION_CODES.R)
     public void testNetworkCapabilitiesUpdate_RAndLater() throws Exception {
         initActivity(TEST_URL);
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
+
         // NetworkCapabilities updates w/o NET_CAPABILITY_VALIDATED.
         final NetworkCapabilities nc = new NetworkCapabilities();
         notifyValidatedChangedNotDone(nc);
@@ -540,6 +622,10 @@ public class CaptivePortalLoginActivityTest {
     @Test @SdkSuppress(maxSdkVersion = Build.VERSION_CODES.Q)
     public void testNetworkCapabilitiesUpdate_Q() throws Exception {
         initActivity(TEST_URL);
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
+
         final NetworkCapabilities nc = new NetworkCapabilities();
         nc.setCapability(NET_CAPABILITY_VALIDATED, true);
         // Auto-dismiss should not happen.
@@ -554,6 +640,9 @@ public class CaptivePortalLoginActivityTest {
         server.start();
         ActivityScenario.launch(RequestDismissKeyguardActivity.class);
         initActivity(server.makeUrl(TEST_URL_QUERY));
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
         // Mock all external intents
         intending(not(isInternal())).respondWith(new ActivityResult(RESULT_OK, null));
 
@@ -632,6 +721,9 @@ public class CaptivePortalLoginActivityTest {
 
         ActivityScenario.launch(RequestDismissKeyguardActivity.class);
         initActivity(server.makeUrl(TEST_URL_QUERY));
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
 
         // Create a mock file to be returned when mocking the file chooser
         final Intent mockFileResponse = new Intent();
@@ -690,6 +782,9 @@ public class CaptivePortalLoginActivityTest {
         when(sConnectivityManager.getLinkProperties(mNetwork)).thenReturn(linkProperties);
         configNonVpnNetwork();
         initActivity("https://tc.example.com/");
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
 
         // Verify that the correct venue friendly name is used
         mActivityScenario.onActivity(activity ->
@@ -701,6 +796,9 @@ public class CaptivePortalLoginActivityTest {
     public void testWifiSsid_Q() throws Exception {
         configNonVpnNetwork();
         initActivity("https://portal.example.com/");
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
         mActivityScenario.onActivity(activity ->
                 assertEquals(activity.getActionBar().getTitle(),
                         getInstrumentation().getContext().getString(R.string.action_bar_title,
@@ -712,6 +810,9 @@ public class CaptivePortalLoginActivityTest {
     public void testWifiSsid() throws Exception {
         configNonVpnNetwork();
         initActivity("https://portal.example.com/");
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
         mActivityScenario.onActivity(activity ->
                 assertEquals(activity.getActionBar().getTitle(),
                         getInstrumentation().getContext().getString(R.string.action_bar_title,
@@ -836,6 +937,9 @@ public class CaptivePortalLoginActivityTest {
 
         ActivityScenario.launch(RequestDismissKeyguardActivity.class);
         initActivity(server.makeUrl(TEST_URL_QUERY));
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
         return server;
     }
 
@@ -898,6 +1002,9 @@ public class CaptivePortalLoginActivityTest {
     @Test
     public void testDirectlyOpen_onDownloadAborted() throws Exception {
         initActivity(TEST_URL);
+        // Initialize intent capturing after launching the activity to avoid capturing extra
+        // intents.
+        Intents.init();
         final Uri mockFile = Uri.parse("content://mockdata");
         final String expectMsg = getInstrumentation().getContext().getString(
                 R.string.file_too_large_cancel_download);
@@ -1007,4 +1114,89 @@ public class CaptivePortalLoginActivityTest {
 
         server.stop();
     }
+
+    @Test
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs() throws Exception {
+        sIsMultiNetworkingSupported = true;
+        final LinkProperties linkProperties = new LinkProperties();
+        doReturn(linkProperties).when(sConnectivityManager).getLinkProperties(mNetwork);
+
+        // Set up result stubbing for the CustomTabsIntent#launchUrl, this stub should be
+        // initialized before starting CaptivePortalLoginActivity, otherwise, no activity
+        // found to handle the CustomTabsIntent.
+        Intents.init();
+        intending(hasPackage(TEST_CUSTOM_TABS_PACKAGE_NAME))
+                .respondWith(new ActivityResult(RESULT_OK, null));
+        initActivity(TEST_URL);
+
+        final ArgumentCaptor<CustomTabsCallback> captor =
+                ArgumentCaptor.forClass(CustomTabsCallback.class);
+        verify(sMockCustomTabsClient).newSession(captor.capture());
+        final CustomTabsCallback callback = captor.getValue();
+        assertNotNull(callback);
+        intended(allOf(
+                hasExtra(Intent.EXTRA_REFERRER, Uri.parse("")),
+                hasExtra(CustomTabsIntent.EXTRA_NETWORK, mNetwork),
+                hasData(Uri.parse(TEST_URL))));
+
+        // Send navigation start event, verify if the network will be reevaluated.
+        callback.onNavigationEvent(NAVIGATION_STARTED, null /* extras */);
+        final MockCaptivePortal cp = getCaptivePortal();
+        assertEquals(1, cp.mReevaluateTimes);
+    }
+
+    @Test
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = false)
+    public void testCaptivePortalUsingCustomTabs_flagOff() throws Exception {
+        sIsMultiNetworkingSupported = true;
+        // Set up result stubbing for the CustomTabsIntent#launchUrl, however, the
+        // feature flag is off, therefore, WebView should be used.
+        Intents.init();
+        intending(hasPackage(TEST_CUSTOM_TABS_PACKAGE_NAME))
+                .respondWith(new ActivityResult(RESULT_OK, null));
+        initActivity(TEST_URL);
+        verify(sConnectivityManager).bindProcessToNetwork(any());
+        verify(sMockCustomTabsClient, never()).newSession(any());
+        mActivityScenario.onActivity(activity ->
+                assertNotNull(activity.findViewById(R.id.webview)));
+    }
+
+    @Test
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs_nullLinkProperties() throws Exception {
+        sIsMultiNetworkingSupported = true;
+        doReturn(null).when(sConnectivityManager).getLinkProperties(mNetwork);
+
+        // Set up result stubbing for the CustomTabsIntent#launchUrl, however, due to the
+        // LinkProperties is null, WebView should be used.
+        Intents.init();
+        intending(hasPackage(TEST_CUSTOM_TABS_PACKAGE_NAME))
+                .respondWith(new ActivityResult(RESULT_OK, null));
+        initActivity(TEST_URL);
+        verify(sConnectivityManager).bindProcessToNetwork(any());
+        verify(sMockCustomTabsClient, never()).newSession(any());
+        mActivityScenario.onActivity(activity ->
+                assertNotNull(activity.findViewById(R.id.webview)));
+    }
+
+    @Test
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs_setNetworkIsnotEnabled() throws Exception {
+        sIsMultiNetworkingSupported = false;
+        final LinkProperties linkProperties = new LinkProperties();
+        doReturn(linkProperties).when(sConnectivityManager).getLinkProperties(mNetwork);
+
+        // Set up result stubbing for the CustomTabsIntent#launchUrl, however, due to the
+        // default browser doesn't support multi-network feature (i.e. isSetNetworkSupport returns
+        // false), WebView should be used.
+        Intents.init();
+        intending(hasPackage(TEST_CUSTOM_TABS_PACKAGE_NAME))
+                .respondWith(new ActivityResult(RESULT_OK, null));
+        initActivity(TEST_URL);
+        verify(sConnectivityManager).bindProcessToNetwork(any());
+        verify(sMockCustomTabsClient, never()).newSession(any());
+        mActivityScenario.onActivity(activity ->
+                assertNotNull(activity.findViewById(R.id.webview)));
+    }
 }
diff --git a/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt b/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt
index 077e27e..232679e 100644
--- a/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt
+++ b/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt
@@ -28,6 +28,7 @@ import android.os.Bundle
 import android.os.IBinder
 import android.os.Parcel
 import android.os.Parcelable
+import android.os.SystemClock
 import android.util.Log
 import android.widget.TextView
 import androidx.core.content.FileProvider
@@ -58,6 +59,7 @@ import java.util.concurrent.CompletableFuture
 import java.util.concurrent.SynchronousQueue
 import java.util.concurrent.TimeUnit.MILLISECONDS
 import kotlin.math.min
+import kotlin.random.Random
 import kotlin.test.assertEquals
 import kotlin.test.assertFalse
 import kotlin.test.assertNotEquals
@@ -105,6 +107,8 @@ private val TEST_WIFI_CONFIG_TYPE = "application/x-wifi-config"
 
 private val TAG = DownloadServiceTest::class.simpleName
 
+private val random = Random(SystemClock.elapsedRealtimeNanos())
+
 @Rule
 val mServiceRule = ServiceTestRule()
 
@@ -250,9 +254,9 @@ class DownloadServiceTest {
         testFilePath.mkdir()
         // Do not use File.createTempFile, as it generates very long filenames that may not
         // fit in notifications, making it difficult to find the right notification.
-        // currentTimeMillis would generally be 13 digits. Use the bottom 8 to fit the filename and
-        // a bit more text, even on very small screens (320 dp, minimum CDD size).
-        var index = System.currentTimeMillis().rem(100_000_000)
+        // Use 8 digits to fit the filename and a bit more text, even on very small screens (320 dp,
+        // minimum CDD size).
+        var index = random.nextInt(100_000_000)
         while (true) {
             val file = File(testFilePath, "tmp$index$extension")
             if (!file.exists()) {
```

