```diff
diff --git a/Android.bp b/Android.bp
index cb33ffc..7ec9c80 100644
--- a/Android.bp
+++ b/Android.bp
@@ -57,6 +57,7 @@ android_library {
     ],
 
     libs: [
+        "framework-platformcrashrecovery.stubs.module_lib",
         "framework-configinfrastructure.stubs.module_lib",
         "framework-connectivity.stubs.module_lib",
     ],
@@ -98,6 +99,7 @@ android_app {
         "com.android.extservices",
         "test_com.android.extservices",
     ],
+    updatable: true,
 }
 
 android_app {
@@ -131,4 +133,5 @@ android_app {
         "com.android.extservices",
         "test_com.android.extservices",
     ],
+    updatable: true,
 }
diff --git a/java/res/values-b+sr+Latn/strings.xml b/java/res/values-b+sr+Latn/strings.xml
index 82c7d40..d01f976 100644
--- a/java/res/values-b+sr+Latn/strings.xml
+++ b/java/res/values-b+sr+Latn/strings.xml
@@ -34,7 +34,7 @@
     <item msgid="2052362882225775298">"verifikacija"</item>
     <item msgid="4759495520595696444">"potvrdi"</item>
     <item msgid="4360404417991731370">"potvrda"</item>
-    <item msgid="5135302120938115660">"jednokratno"</item>
+    <item msgid="5135302120938115660">"jednom"</item>
     <item msgid="405482768547359066">"pristup"</item>
     <item msgid="7962233525908588330">"validacija"</item>
     <item msgid="9095545913763732113">"proveri"</item>
diff --git a/java/res/values-mk/strings.xml b/java/res/values-mk/strings.xml
index b2e627c..731b996 100644
--- a/java/res/values-mk/strings.xml
+++ b/java/res/values-mk/strings.xml
@@ -25,7 +25,7 @@
     <item msgid="826248726164877615">"два чекора"</item>
     <item msgid="2156400793251117724">"најавување"</item>
     <item msgid="3621495493711216796">"најавување"</item>
-    <item msgid="4652629344958695406">"најави се"</item>
+    <item msgid="4652629344958695406">"најава"</item>
     <item msgid="6021138326345874403">"автентицирај"</item>
     <item msgid="301989899519648952">"автентикација"</item>
     <item msgid="2409846400635400651">"код"</item>
diff --git a/java/res/values-sr/strings.xml b/java/res/values-sr/strings.xml
index 1519f32..f30c888 100644
--- a/java/res/values-sr/strings.xml
+++ b/java/res/values-sr/strings.xml
@@ -34,7 +34,7 @@
     <item msgid="2052362882225775298">"верификација"</item>
     <item msgid="4759495520595696444">"потврди"</item>
     <item msgid="4360404417991731370">"потврда"</item>
-    <item msgid="5135302120938115660">"једнократно"</item>
+    <item msgid="5135302120938115660">"једном"</item>
     <item msgid="405482768547359066">"приступ"</item>
     <item msgid="7962233525908588330">"валидација"</item>
     <item msgid="9095545913763732113">"провери"</item>
diff --git a/java/src/android/ext/services/notification/Assistant.java b/java/src/android/ext/services/notification/Assistant.java
index 335bfd6..e6dc8bf 100644
--- a/java/src/android/ext/services/notification/Assistant.java
+++ b/java/src/android/ext/services/notification/Assistant.java
@@ -22,6 +22,7 @@ import android.annotation.SuppressLint;
 import android.app.ActivityManager;
 import android.app.Notification;
 import android.app.NotificationChannel;
+import android.content.Context;
 import android.content.pm.PackageManager;
 import android.os.Bundle;
 import android.os.Trace;
@@ -45,6 +46,7 @@ import com.android.textclassifier.notification.SmartSuggestionsHelper;
 
 import java.util.ArrayList;
 import java.util.List;
+import java.util.Objects;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
@@ -65,6 +67,9 @@ public class Assistant extends NotificationAssistantService {
     @VisibleForTesting
     protected boolean mUseTextClassifier = true;
 
+    @VisibleForTesting
+    protected Context mContext;
+
     @VisibleForTesting
     protected PackageManager mPm;
 
@@ -80,7 +85,8 @@ public class Assistant extends NotificationAssistantService {
     protected AssistantSettings.Factory mSettingsFactory = AssistantSettings.FACTORY;
     @VisibleForTesting
     protected AssistantSettings mSettings;
-    private SmsHelper mSmsHelper;
+    @VisibleForTesting
+    protected SmsHelper mSmsHelper;
     @VisibleForTesting
     protected SmartSuggestionsHelper mSmartSuggestionsHelper;
 
@@ -95,6 +101,7 @@ public class Assistant extends NotificationAssistantService {
         super.onCreate();
         // Contexts are correctly hooked up by the creation step, which is required for the observer
         // to be hooked up/initialized.
+        mContext = this;
         mPm = getPackageManager();
         mAm = getSystemService(ActivityManager.class);
         mTcm = getSystemService(TextClassificationManager.class);
@@ -136,6 +143,7 @@ public class Assistant extends NotificationAssistantService {
 
         final boolean shouldCheckForOtp = SdkLevel.isAtLeastV()
                 && Flags.redactSensitiveNotificationsFromUntrustedListeners()
+                && Objects.equals(sbn.getPackageName(), mSmsHelper.getDefaultSmsPackage())
                 && NotificationOtpDetectionHelper.shouldCheckForOtp(sbn.getNotification());
         boolean foundOtpWithRegex = shouldCheckForOtp
                 && NotificationOtpDetectionHelper
diff --git a/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java b/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java
index d7006c3..f2f081d 100644
--- a/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java
+++ b/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java
@@ -28,9 +28,6 @@ import static android.app.Notification.EXTRA_TEXT_LINES;
 import static android.app.Notification.EXTRA_TITLE;
 import static android.app.Notification.EXTRA_TITLE_BIG;
 import static android.os.Build.VERSION.SDK_INT;
-import static android.view.textclassifier.TextClassifier.TYPE_ADDRESS;
-import static android.view.textclassifier.TextClassifier.TYPE_FLIGHT_NUMBER;
-import static android.view.textclassifier.TextClassifier.TYPE_PHONE;
 
 import static java.lang.String.format;
 
@@ -45,9 +42,9 @@ import android.os.Parcelable;
 import android.util.ArrayMap;
 import android.view.textclassifier.TextClassifier;
 import android.view.textclassifier.TextLanguage;
-import android.view.textclassifier.TextLinks;
 
 import androidx.annotation.Nullable;
+import androidx.annotation.RequiresApi;
 import androidx.annotation.VisibleForTesting;
 
 import java.util.ArrayList;
@@ -62,24 +59,26 @@ import java.util.regex.Pattern;
  * This file needs to only use public android API methods, see b/361149088
  */
 @SuppressLint("ObsoleteSdkInt")
+@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
 public class NotificationOtpDetectionHelper {
 
     // Use an ArrayList because a List.of list will throw NPE when calling "contains(null)"
-    private static final List<String> SENSITIVE_NOTIFICATION_CATEGORIES = new ArrayList<>(
-            Arrays.asList(CATEGORY_MESSAGE, CATEGORY_EMAIL, CATEGORY_SOCIAL));
-
-    private static final List<Class<? extends Notification.Style>> SENSITIVE_STYLES =
-            new ArrayList<>(Arrays.asList(Notification.MessagingStyle.class,
-                    Notification.InboxStyle.class, Notification.BigTextStyle.class));
-
-    private static final List<Class<? extends Notification.Style>> EXCLUDED_STYLES =
-            new ArrayList<>(Arrays.asList(Notification.MediaStyle.class,
-                    Notification.BigPictureStyle.class));
-    static {
-        if (SDK_INT >= Build.VERSION_CODES.S) {
-            EXCLUDED_STYLES.add(Notification.CallStyle.class);
-        }
-    }
+    private static final List<String> SENSITIVE_NOTIFICATION_CATEGORIES =
+            Arrays.asList(CATEGORY_MESSAGE, CATEGORY_EMAIL, CATEGORY_SOCIAL);
+
+    private static final List<String> SENSITIVE_STYLES =
+            Arrays.asList(
+                    Notification.MessagingStyle.class.getName(),
+                    Notification.InboxStyle.class.getName(),
+                    Notification.BigTextStyle.class.getName()
+            );
+
+    private static final List<String> EXCLUDED_STYLES =
+            Arrays.asList(
+                    Notification.MediaStyle.class.getName(),
+                    Notification.BigPictureStyle.class.getName(),
+                    Notification.CallStyle.class.getName()
+            );
 
     private static final int PATTERN_FLAGS =
             Pattern.DOTALL | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;
@@ -356,10 +355,8 @@ public class NotificationOtpDetectionHelper {
                 // Only use the language-specific regex for false positives
                 return languageSpecificMatcher.find();
             }
-            // Else, use TC to check for false positives
-            if (hasFalsePositivesTcCheck(sensitiveText, tc)) {
-                return false;
-            }
+            // Only check for OTPs when there is a language specific matcher
+            return false;
         }
 
         return !allOtpMatchesAreFalsePositives(sensitiveText, FALSE_POSITIVE_SHORTER_REGEX.get(),
@@ -445,29 +442,6 @@ public class NotificationOtpDetectionHelper {
         return highestConfidenceLocale;
     }
 
-    private static boolean hasFalsePositivesTcCheck(String text, @Nullable TextClassifier tc) {
-        if (tc == null) {
-            return false;
-        }
-        // Use TC to eliminate false positives from a regex match, namely: flight codes, and
-        // addresses
-        List<String> included = new ArrayList<>(Arrays.asList(TYPE_FLIGHT_NUMBER, TYPE_ADDRESS));
-        List<String> excluded = new ArrayList<>(Arrays.asList(TYPE_PHONE));
-        TextClassifier.EntityConfig config =
-                new TextClassifier.EntityConfig.Builder().setIncludedTypes(
-                        included).setExcludedTypes(excluded).build();
-        TextLinks.Request request =
-                new TextLinks.Request.Builder(text).setEntityConfig(config).build();
-        TextLinks links = tc.generateLinks(request);
-        for (TextLinks.TextLink link : links.getLinks()) {
-            if (link.getConfidenceScore(TYPE_FLIGHT_NUMBER) > TC_THRESHOLD
-                    || link.getConfidenceScore(TYPE_ADDRESS) > TC_THRESHOLD) {
-                return true;
-            }
-        }
-        return false;
-    }
-
     /**
      * Gets the sections of text in a notification that should be checked for sensitive content.
      * This includes the text, title, subtext, messages, and extra text lines.
@@ -531,13 +505,12 @@ public class NotificationOtpDetectionHelper {
                 || shouldCheckForOtp(notification.publicVersion);
     }
 
-    private static boolean isStyle(Notification notification,
-            Class<? extends Notification.Style> styleClass) {
+    private static boolean isStyle(Notification notification, String styleClassName) {
         if (notification.extras == null) {
             return false;
         }
         String templateClass = notification.extras.getString(Notification.EXTRA_TEMPLATE);
-        return Objects.equals(templateClass, styleClass.getName());
+        return Objects.equals(templateClass, styleClassName);
     }
 
     private NotificationOtpDetectionHelper() { }
diff --git a/java/tests/AndroidManifest.xml b/java/tests/AndroidManifest.xml
index 318788c..7e5b8b2 100644
--- a/java/tests/AndroidManifest.xml
+++ b/java/tests/AndroidManifest.xml
@@ -18,6 +18,7 @@
           package="android.ext.services.tests.unit">
 
     <uses-sdk android:minSdkVersion="30" android:targetSdkVersion="30"/>
+    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
 
     <application>
         <uses-library android:name="android.test.runner" />
diff --git a/java/tests/hosttests/AndroidTest-sminus.xml b/java/tests/hosttests/AndroidTest-sminus.xml
index 9b511ba..60387ac 100644
--- a/java/tests/hosttests/AndroidTest-sminus.xml
+++ b/java/tests/hosttests/AndroidTest-sminus.xml
@@ -44,4 +44,7 @@
             class="com.android.tradefed.testtype.suite.module.MainlineTestModuleController">
         <option name="mainline-module-package-name" value="com.google.android.extservices"/>
     </object>
+
+   <!-- Needed to set TestDeviceHelper for class rules -->
+   <target_preparer class="com.android.adservices.common.AdServicesHostTestsTargetPreparer"/>
 </configuration>
diff --git a/java/tests/hosttests/AndroidTest-tplus.xml b/java/tests/hosttests/AndroidTest-tplus.xml
index 7114d68..c76f56e 100644
--- a/java/tests/hosttests/AndroidTest-tplus.xml
+++ b/java/tests/hosttests/AndroidTest-tplus.xml
@@ -38,4 +38,7 @@
             class="com.android.tradefed.testtype.suite.module.MainlineTestModuleController">
         <option name="mainline-module-package-name" value="com.google.android.extservices"/>
     </object>
-</configuration>
+
+   <!-- Needed to set TestDeviceHelper for class rules -->
+   <target_preparer class="com.android.adservices.common.AdServicesHostTestsTargetPreparer"/>
+ </configuration>
diff --git a/java/tests/src/android/ext/services/notification/AssistantSettingsTest.java b/java/tests/src/android/ext/services/notification/AssistantSettingsTest.java
index 4e5721a..3f7016c 100644
--- a/java/tests/src/android/ext/services/notification/AssistantSettingsTest.java
+++ b/java/tests/src/android/ext/services/notification/AssistantSettingsTest.java
@@ -48,6 +48,8 @@ public class AssistantSettingsTest {
             "device_config delete " + DeviceConfig.NAMESPACE_SYSTEMUI;
     private static final String WRITE_DEVICE_CONFIG_PERMISSION =
             "android.permission.WRITE_DEVICE_CONFIG";
+    private static final String WRITE_ALLOWLISTED_DEVICE_CONFIG_PERMISSION =
+            "android.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG";
 
     private static final String READ_DEVICE_CONFIG_PERMISSION =
             "android.permission.READ_DEVICE_CONFIG";
@@ -67,6 +69,7 @@ public class AssistantSettingsTest {
         InstrumentationRegistry.getInstrumentation().getUiAutomation()
                 .adoptShellPermissionIdentity(
                         WRITE_DEVICE_CONFIG_PERMISSION,
+                        WRITE_ALLOWLISTED_DEVICE_CONFIG_PERMISSION,
                         READ_DEVICE_CONFIG_PERMISSION);
         mAssistantSettings = new AssistantSettings();
     }
diff --git a/java/tests/src/android/ext/services/notification/AssistantTest.kt b/java/tests/src/android/ext/services/notification/AssistantTest.kt
index fb3f62c..e5b6444 100644
--- a/java/tests/src/android/ext/services/notification/AssistantTest.kt
+++ b/java/tests/src/android/ext/services/notification/AssistantTest.kt
@@ -22,12 +22,14 @@ import android.app.Notification.CATEGORY_MESSAGE
 import android.app.NotificationChannel
 import android.app.NotificationManager.IMPORTANCE_DEFAULT
 import android.app.PendingIntent
+import android.content.Context
 import android.content.Intent
 import android.content.pm.PackageManager
 import android.content.pm.PackageManager.FEATURE_WATCH
 import android.icu.util.ULocale
 import android.os.Process
 import android.platform.test.flag.junit.SetFlagsRule
+import android.provider.Telephony
 import android.service.notification.Adjustment.KEY_SENSITIVE_CONTENT
 import android.service.notification.Adjustment.KEY_TEXT_REPLIES
 import android.service.notification.Flags
@@ -36,7 +38,7 @@ import android.view.textclassifier.TextClassificationManager
 import android.view.textclassifier.TextClassifier
 import android.view.textclassifier.TextLanguage
 import android.view.textclassifier.TextLinks
-import androidx.test.platform.app.InstrumentationRegistry
+import androidx.test.core.app.ApplicationProvider
 import com.android.modules.utils.build.SdkLevel
 import com.android.textclassifier.notification.SmartSuggestions
 import com.android.textclassifier.notification.SmartSuggestionsHelper
@@ -66,7 +68,7 @@ import org.mockito.stubbing.Stubber
 
 @RunWith(JUnit4::class)
 class AssistantTest {
-    val context = InstrumentationRegistry.getInstrumentation().targetContext!!
+    private val context = ApplicationProvider.getApplicationContext<Context>()
     lateinit var mockSuggestions: SmartSuggestionsHelper
     lateinit var mockTc: TextClassifier
     lateinit var assistant: Assistant
@@ -92,6 +94,9 @@ class AssistantTest {
         mockTc = mock(TextClassifier::class.java)
         mockAm = mock(ActivityManager::class.java)
         mockPm = mock(PackageManager::class.java)
+        assistant.mContext = context
+        assistant.mSmsHelper = SmsHelper(context)
+        assistant.mSmsHelper.initialize()
         assistant.mAm = mockAm
         assistant.mPm = mockPm
         assistant.mSmartSuggestionsHelper = mockSuggestions
@@ -118,10 +123,21 @@ class AssistantTest {
         assertThat(directReturn).isNull()
     }
 
+    @Test
+    fun onNotificationEnqueued_doesntCheckForOtpIfNotSMS() {
+        val sbn = createSbn(TEXT_WITH_OTP, packageName = "invalid_package_name")
+        doReturn(TextLanguage.Builder().putLocale(ULocale.ENGLISH, 0.9f).build())
+            .whenKt(mockTc).detectLanguage(any())
+        assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
+        Thread.sleep(EXECUTOR_AWAIT_TIME)
+        verify(assistant, never())
+            .createNotificationAdjustment(any(), any(), any(), eq(true))
+    }
+
     @Test
     fun onNotificationEnqueued_callsTextClassifierForOtpAndSuggestions() {
         val sbn = createSbn(TEXT_WITH_OTP)
-        doReturn(TextLanguage.Builder().putLocale(ULocale.ROOT, 0.9f).build())
+        doReturn(TextLanguage.Builder().putLocale(ULocale.ENGLISH, 0.9f).build())
             .whenKt(mockTc).detectLanguage(any())
         assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
         Thread.sleep(EXECUTOR_AWAIT_TIME)
@@ -137,7 +153,7 @@ class AssistantTest {
     @Test
     fun onNotificationEnqueued_usesBothRegexAndTc() {
         val sbn = createSbn(TEXT_WITH_OTP)
-        doReturn(TextLanguage.Builder().putLocale(ULocale.ROOT, 0.9f).build())
+        doReturn(TextLanguage.Builder().putLocale(ULocale.ENGLISH, 0.9f).build())
             .whenKt(mockTc).detectLanguage(any())
         val directReturn =
             assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
@@ -258,7 +274,8 @@ class AssistantTest {
         title: String = "",
         subtext: String = "",
         category: String = CATEGORY_MESSAGE,
-        style: Notification.Style? = null
+        style: Notification.Style? = null,
+        packageName: String? = Telephony.Sms.getDefaultSmsPackage(context)
     ): StatusBarNotification {
         val intent = Intent(Intent.ACTION_MAIN)
         intent.setFlags(
@@ -277,8 +294,8 @@ class AssistantTest {
         if (style != null) {
             nb.setStyle(style)
         }
-        return StatusBarNotification(context.packageName, context.packageName, 0, "",
-            Process.myUid(), 0, 0, nb.build(), Process.myUserHandle(), System.currentTimeMillis())
+        return StatusBarNotification(packageName, packageName, 0, "", Process.myUid(), 0, 0,
+            nb.build(), Process.myUserHandle(), System.currentTimeMillis())
     }
 
     private fun createTestPendingIntent(): PendingIntent {
diff --git a/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt b/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt
index 8dc7a38..d5bcd02 100644
--- a/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt
+++ b/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt
@@ -28,7 +28,6 @@ import android.content.Intent
 import android.icu.util.ULocale
 import android.os.Build
 import android.os.Build.VERSION.SDK_INT
-import android.view.textclassifier.TextClassificationManager
 import android.view.textclassifier.TextClassifier
 import android.view.textclassifier.TextLanguage
 import android.view.textclassifier.TextLinks
@@ -418,26 +417,6 @@ class NotificationOtpDetectionHelperTest {
         addMatcherTestResult(expected = false, threeLowercase, textClassifier = tc)
     }
 
-    @Test
-    fun testContainsOtp_commonYearsDontMatch_withoutLanguageSpecificRegex() {
-        val tc = getTestTextClassifier(invalidLocale)
-        val twentyXX = "2009"
-        val twentyOneXX = "2109"
-        val thirtyXX = "3035"
-        val nineteenXX = "1945"
-        val eighteenXX = "1899"
-        val yearSubstring = "20051"
-        addMatcherTestResult(expected = false, twentyXX, textClassifier = tc)
-        // Behavior should be the same for an invalid language, and null TextClassifier
-        addMatcherTestResult(expected = false, twentyXX, textClassifier = null)
-        addMatcherTestResult(expected = true, twentyOneXX, textClassifier = tc)
-        addMatcherTestResult(expected = true, thirtyXX, textClassifier = tc)
-        addMatcherTestResult(expected = false, nineteenXX, textClassifier = tc)
-        addMatcherTestResult(expected = true, eighteenXX, textClassifier = tc)
-        // A substring of a year should not trigger a false positive
-        addMatcherTestResult(expected = true, yearSubstring, textClassifier = tc)
-    }
-
     @Test
     fun testContainsOtp_englishSpecificRegex() {
         val tc = getTestTextClassifier(ULocale.ENGLISH)
@@ -512,13 +491,10 @@ class NotificationOtpDetectionHelperTest {
     }
 
     @Test
-    fun testContainsOtpCode_usesTcForFalsePositivesIfNoLanguageSpecificRegex() {
-        var tc = getTestTextClassifier(invalidLocale, listOf(TextClassifier.TYPE_ADDRESS))
-        val address = "this text doesn't actually matter, but meet me at 6353 Juan Tabo, Apt. 6"
-        addMatcherTestResult(expected = false, address, textClassifier = tc)
-        tc = getTestTextClassifier(invalidLocale, listOf(TextClassifier.TYPE_FLIGHT_NUMBER))
-        val flight = "your flight number is UA1234"
-        addMatcherTestResult(expected = false, flight, textClassifier = tc)
+    fun testContainsOtpCode_falseIfNoLanguageSpecificRegex() {
+        val tc = getTestTextClassifier(invalidLocale)
+        val text = "your one time code is 34343"
+        addMatcherTestResult(expected = false, text, textClassifier = tc)
     }
 
     @Test
```

