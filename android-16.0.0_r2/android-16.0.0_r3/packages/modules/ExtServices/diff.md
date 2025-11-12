```diff
diff --git a/Android.bp b/Android.bp
index dfbd14c..81002d8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -30,10 +30,18 @@ license {
     ],
 }
 
+genrule {
+    name: "statslog-extservices-java-gen",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --java $(out) --module extservices --javaPackage android.ext.services --javaClass ExtServicesStatsLog",
+    out: ["android/ext/services/ExtServicesStatsLog.java"],
+}
+
 android_library {
     name: "ExtServices-core",
     srcs: [
         "java/src/**/*.java",
+        ":statslog-extservices-java-gen",
     ],
 
     sdk_version: "module_current",
@@ -61,6 +69,7 @@ android_library {
         "framework-platformcrashrecovery.stubs.module_lib",
         "framework-configinfrastructure.stubs.module_lib",
         "framework-connectivity.stubs.module_lib",
+        "framework-statsd.stubs.module_lib",
     ],
 
     lint: {
@@ -102,6 +111,10 @@ android_app {
         "test_com.android.extservices",
     ],
     updatable: true,
+    licenses: [
+        "packages_modules_ExtServices_license",
+        "opensourcerequest",
+    ],
 }
 
 android_app {
@@ -137,4 +150,8 @@ android_app {
         "test_com.android.extservices",
     ],
     updatable: true,
+    licenses: [
+        "packages_modules_ExtServices_license",
+        "opensourcerequest",
+    ],
 }
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 6453ad9..437c09d 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -38,6 +38,7 @@
     <uses-permission android:name="android.permission.FOREGROUND_SERVICE" tools:node="remove" />
     <!-- Need this permission to receive the Boot-Completed broadcast -->
     <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
+    <uses-permission android:name="android.permission.ACCESS_TEXT_CLASSIFIER_BY_TYPE" />
 
     <application
         android:name=".ExtServicesApplication"
diff --git a/OWNERS b/OWNERS
index 71a31d5..fb9a763 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,8 @@
 # Bug component: 1101073
-adarshsridhar@google.com
+bhagavatular@google.com
+akhilga@google.com
+gehuang@google.com
+sawkar@google.com
 # Autofill
 include platform/frameworks/base:/core/java/android/service/autofill/OWNERS
 # PackageWatchdog
diff --git a/apex/Android.bp b/apex/Android.bp
index 1c5b7bc..fe051d6 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -30,6 +30,10 @@ apex {
     manifest: "tplus_apex_manifest.json",
     variant_version: "3",
     min_sdk_version: "33",
+    licenses: [
+        "packages_modules_ExtServices_license",
+        "opensourcerequest",
+    ],
 }
 
 apex {
@@ -38,6 +42,10 @@ apex {
     apps: ["ExtServices-sminus"],
     java_libs: ["android.ext.adservices"],
     jni_libs: ["libtflite_support_classifiers_native"],
+    licenses: [
+        "packages_modules_ExtServices_license",
+        "opensourcerequest",
+    ],
 }
 
 apex_defaults {
diff --git a/apex/permissions/android.ext_sminus.services.xml b/apex/permissions/android.ext_sminus.services.xml
index 4fb465d..b70a154 100644
--- a/apex/permissions/android.ext_sminus.services.xml
+++ b/apex/permissions/android.ext_sminus.services.xml
@@ -20,6 +20,7 @@
         <permission name="android.permission.MONITOR_DEFAULT_SMS_PACKAGE" />
         <permission name="android.permission.REQUEST_NOTIFICATION_ASSISTANT_SERVICE" />
         <permission name="android.permission.INTERACT_ACROSS_USERS" />
+        <permission name="android.permission.ACCESS_TEXT_CLASSIFIER_BY_TYPE" />
     </privapp-permissions>
     <library
         name="android.ext.adservices"
diff --git a/apex/permissions/android.ext_tplus.services.xml b/apex/permissions/android.ext_tplus.services.xml
index 1c75bb1..5fe01ae 100644
--- a/apex/permissions/android.ext_tplus.services.xml
+++ b/apex/permissions/android.ext_tplus.services.xml
@@ -20,5 +20,6 @@
         <permission name="android.permission.MONITOR_DEFAULT_SMS_PACKAGE" />
         <permission name="android.permission.REQUEST_NOTIFICATION_ASSISTANT_SERVICE" />
         <permission name="android.permission.INTERACT_ACROSS_USERS" />
+        <permission name="android.permission.ACCESS_TEXT_CLASSIFIER_BY_TYPE" />
     </privapp-permissions>
 </permissions>
diff --git a/java/src/android/ext/services/notification/Assistant.java b/java/src/android/ext/services/notification/Assistant.java
index 6cec868..ed8eec4 100644
--- a/java/src/android/ext/services/notification/Assistant.java
+++ b/java/src/android/ext/services/notification/Assistant.java
@@ -17,6 +17,11 @@
 package android.ext.services.notification;
 
 import static android.content.pm.PackageManager.FEATURE_WATCH;
+import static android.ext.services.ExtServicesStatsLog.NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__NOTIFICATION_ENQUEUED;
+import static android.ext.services.ExtServicesStatsLog.NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__OTP_CHECKED;
+import static android.ext.services.ExtServicesStatsLog.NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__OTP_CHECK_SKIPPED_DUE_TO_LOAD;
+import static android.ext.services.ExtServicesStatsLog.NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__OTP_DETECTED;
+import static android.ext.services.ExtServicesStatsLog.NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__TC_FOR_OTP_DETECTION_ENABLED;
 
 import android.annotation.SuppressLint;
 import android.app.ActivityManager;
@@ -24,6 +29,8 @@ import android.app.Notification;
 import android.app.NotificationChannel;
 import android.content.Context;
 import android.content.pm.PackageManager;
+import android.ext.services.ExtServicesStatsLog;
+import android.os.Build;
 import android.os.Bundle;
 import android.os.Trace;
 import android.os.UserHandle;
@@ -34,11 +41,14 @@ import android.service.notification.StatusBarNotification;
 import android.util.ArrayMap;
 import android.util.Log;
 import android.view.textclassifier.TextClassificationManager;
+import android.view.textclassifier.TextClassifier;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
+import androidx.annotation.RequiresApi;
 import androidx.annotation.VisibleForTesting;
 
+import com.android.ext.services.flags.Flags;
 import com.android.modules.utils.build.SdkLevel;
 import com.android.textclassifier.notification.SmartSuggestions;
 import com.android.textclassifier.notification.SmartSuggestionsHelper;
@@ -64,7 +74,9 @@ public class Assistant extends NotificationAssistantService {
     protected ArrayMap<String, NotificationEntry> mLiveNotifications = new ArrayMap<>();
 
     @VisibleForTesting
-    protected boolean mUseTextClassifier = true;
+    protected boolean mIsWatch;
+    @VisibleForTesting
+    protected boolean mIsLowRamDevice;
 
     @VisibleForTesting
     protected Context mContext;
@@ -72,9 +84,6 @@ public class Assistant extends NotificationAssistantService {
     @VisibleForTesting
     protected PackageManager mPm;
 
-    @VisibleForTesting
-    protected ActivityManager mAm;
-
     protected final ExecutorService mSingleThreadExecutor = Executors.newSingleThreadExecutor();
     // Using newFixedThreadPool because that returns a ThreadPoolExecutor, allowing us to access
     // the queue of jobs
@@ -90,7 +99,20 @@ public class Assistant extends NotificationAssistantService {
     protected SmartSuggestionsHelper mSmartSuggestionsHelper;
 
     @VisibleForTesting
-    protected TextClassificationManager mTcm;
+    protected TextClassifier mTc;
+
+    protected static boolean sUseTcForOtpDetection;
+
+    private static final int EVENT_NOTIFICATION_ENQUEUED =
+            NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__NOTIFICATION_ENQUEUED;
+    private static final int EVENT_TC_FOR_OTP_DETECTION_ENABLED =
+            NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__TC_FOR_OTP_DETECTION_ENABLED;
+    private static final int EVENT_OTP_CHECK_SKIPPED_DUE_TO_LOAD =
+            NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__OTP_CHECK_SKIPPED_DUE_TO_LOAD;
+    private static final int EVENT_OTP_CHECKED =
+            NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__OTP_CHECKED;
+    private static final int EVENT_OTP_DETECTED =
+            NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__OTP_DETECTED;
 
     public Assistant() {
     }
@@ -102,18 +124,20 @@ public class Assistant extends NotificationAssistantService {
         // to be hooked up/initialized.
         mContext = this;
         mPm = getPackageManager();
-        mAm = getSystemService(ActivityManager.class);
-        mTcm = getSystemService(TextClassificationManager.class);
         mSettings = mSettingsFactory.createAndRegister();
         mSmartSuggestionsHelper = new SmartSuggestionsHelper(this, mSettings);
         mSmsHelper = new SmsHelper(this);
         mSmsHelper.initialize();
-        setUseTextClassifier();
-    }
-
-    @VisibleForTesting
-    protected void setUseTextClassifier() {
-        mUseTextClassifier = !(mAm.isLowRamDevice() || mPm.hasSystemFeature(FEATURE_WATCH));
+        sUseTcForOtpDetection = useTcForOtpDetection();
+        mIsLowRamDevice = getSystemService(ActivityManager.class).isLowRamDevice();
+        mIsWatch = mPm.hasSystemFeature(FEATURE_WATCH);
+
+        TextClassificationManager tcm = getSystemService(TextClassificationManager.class);
+        if (sUseTcForOtpDetection) {
+            mTc = tcm.getClassifier(TextClassifier.CLASSIFIER_TYPE_ANDROID_DEFAULT);
+        } else {
+            mTc = tcm.getTextClassifier();
+        }
     }
 
     @Override
@@ -140,6 +164,49 @@ public class Assistant extends NotificationAssistantService {
             return null;
         }
 
+        if (SdkLevel.isAtLeastV()) {
+            reportEvent(EVENT_NOTIFICATION_ENQUEUED);
+        }
+
+        if (!sUseTcForOtpDetection) {
+            return onNotificationEnqueuedLegacy(sbn);
+        }
+        reportEvent(EVENT_TC_FOR_OTP_DETECTION_ENABLED);
+
+        // Ignoring the result of the future
+        Future<?> ignored = mMachineLearningExecutor.submit(() -> {
+            final boolean checkForOtp = SdkLevel.isAtLeastB()
+                    && Objects.equals(sbn.getPackageName(), mSmsHelper.getDefaultSmsPackage())
+                    && NotificationOtpDetectionHelper.shouldCheckForOtp(sbn.getNotification());
+
+            if (checkForOtp) {
+                if (mMachineLearningExecutor.getQueue().size() >= MAX_QUEUED_ML_JOBS) {
+                    reportEvent(EVENT_OTP_CHECK_SKIPPED_DUE_TO_LOAD);
+                } else {
+                    reportEvent(EVENT_OTP_CHECKED);
+                    if (containsOtp(sbn)) {
+                        adjustNotificationIfNotNull(
+                                createNotificationAdjustment(sbn, null, null, true));
+                        reportEvent(EVENT_OTP_DETECTED);
+                    }
+                }
+            }
+
+            SmartSuggestions suggestions = getSmartSuggestion(sbn);
+            adjustNotificationIfNotNull(createNotificationAdjustment(
+                    sbn,
+                    new ArrayList<>(suggestions.getActions()),
+                    new ArrayList<>(suggestions.getReplies()),
+                    null));
+        });
+
+        return null;
+    }
+
+    // This is a legacy implementation intended to be run on V and below.
+    // If below V, only smart suggestions are adjusted.
+    // If V then OTP detection is performed using the local detection implementation.
+    private Adjustment onNotificationEnqueuedLegacy(@NonNull StatusBarNotification sbn) {
         final boolean shouldCheckForOtp = SdkLevel.isAtLeastV()
                 && Objects.equals(sbn.getPackageName(), mSmsHelper.getDefaultSmsPackage())
                 && NotificationOtpDetectionHelper.shouldCheckForOtp(sbn.getNotification());
@@ -158,17 +225,10 @@ public class Assistant extends NotificationAssistantService {
         // Ignoring the result of the future
         Future<?> ignored = mMachineLearningExecutor.submit(() -> {
             Boolean containsOtp = null;
-            if (shouldCheckForOtp && mUseTextClassifier) {
+            if (shouldCheckForOtp && !mIsLowRamDevice && !mIsWatch) {
                 // If we can use the text classifier, do a second pass, using the TC to detect
                 // languages, and potentially using the TC to remove false positives
-                Trace.beginSection(TAG + "_RegexWithTc");
-                try {
-                    containsOtp = NotificationOtpDetectionHelper.containsOtp(
-                            sbn.getNotification(), true, mTcm.getTextClassifier());
-
-                } finally {
-                    Trace.endSection();
-                }
+                containsOtp = containsOtp(sbn);
             }
 
             // If we found an otp (and didn't already send an adjustment), send an adjustment early
@@ -177,21 +237,7 @@ public class Assistant extends NotificationAssistantService {
                         createNotificationAdjustment(sbn, null, null, true));
             }
 
-            SmartSuggestions suggestions;
-            Trace.beginSection(TAG + "_SmartSuggestions");
-            try {
-                suggestions = mSmartSuggestionsHelper.onNotificationEnqueued(sbn);
-            } finally {
-                Trace.endSection();
-            }
-
-            if (DEBUG) {
-                Log.d(TAG, String.format(
-                        "Creating Adjustment for %s, with %d actions, and %d replies.",
-                        sbn.getKey(),
-                        suggestions.getActions().size(),
-                        suggestions.getReplies().size()));
-            }
+            SmartSuggestions suggestions = getSmartSuggestion(sbn);
 
             adjustNotificationIfNotNull(createNotificationAdjustment(
                     sbn,
@@ -203,6 +249,37 @@ public class Assistant extends NotificationAssistantService {
         return earlyOtpReturn;
     }
 
+    private SmartSuggestions getSmartSuggestion(@NonNull StatusBarNotification sbn) {
+        SmartSuggestions suggestions;
+        Trace.beginSection(TAG + "_SmartSuggestions");
+        try {
+            suggestions = mSmartSuggestionsHelper.onNotificationEnqueued(sbn);
+        } finally {
+            Trace.endSection();
+        }
+        if (DEBUG) {
+            Log.d(TAG, String.format(
+                    "Creating Adjustment for %s, with %d actions, and %d replies.",
+                    sbn.getKey(),
+                    suggestions.getActions().size(),
+                    suggestions.getReplies().size()));
+        }
+        return suggestions;
+    }
+
+    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
+    private boolean containsOtp(@NonNull StatusBarNotification sbn) {
+        String suffix = mTc != null && sUseTcForOtpDetection ? "_TcForOtp" : "_RegexWithTc";
+        Trace.beginSection(TAG + suffix);
+        try {
+            return NotificationOtpDetectionHelper.containsOtp(
+                    sbn.getNotification(), true, mTc);
+
+        } finally {
+            Trace.endSection();
+        }
+    }
+
     // Due to Mockito setup, some methods marked @NonNull can sometimes be called with a
     // null parameter. This method accounts for that.
     private void adjustNotificationIfNotNull(@Nullable Adjustment adjustment) {
@@ -342,4 +419,17 @@ public class Assistant extends NotificationAssistantService {
     private boolean isForCurrentUser(StatusBarNotification sbn) {
         return sbn != null && sbn.getUserId() == UserHandle.myUserId();
     }
+
+    @VisibleForTesting
+    protected static boolean useTcForOtpDetection() {
+        return SdkLevel.isAtLeastB()
+                && android.permission.flags.Flags.textClassifierChoiceApiEnabled()
+                && android.permission.flags.Flags.enableOtpInTextClassifiers()
+                && Flags.textClassifierForOtpDetectionEnabled();
+    }
+
+    @VisibleForTesting
+    protected void reportEvent(int event) {
+        ExtServicesStatsLog.write(ExtServicesStatsLog.NOTIFICATION_ASSISTANT_EVENT_REPORTED, event);
+    }
 }
diff --git a/java/src/android/ext/services/notification/LegacyOtpDetector.java b/java/src/android/ext/services/notification/LegacyOtpDetector.java
new file mode 100644
index 0000000..a6d52f9
--- /dev/null
+++ b/java/src/android/ext/services/notification/LegacyOtpDetector.java
@@ -0,0 +1,375 @@
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
+package android.ext.services.notification;
+
+import static java.lang.String.format;
+
+import android.annotation.SuppressLint;
+import android.icu.util.ULocale;
+import android.os.Build;
+import android.util.ArrayMap;
+import android.view.textclassifier.TextClassifier;
+import android.view.textclassifier.TextLanguage;
+
+import androidx.annotation.Nullable;
+import androidx.annotation.RequiresApi;
+
+import com.android.modules.utils.build.SdkLevel;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
+
+/**
+ * Class with helper methods related to detecting OTP codes in a text for V only.
+ *
+ * @deprecated in B+. The OTP detection functionality has been integrated into TextClassifier. This
+ * class is intended for use only on V.
+ */
+@SuppressLint("ObsoleteSdkInt")
+@Deprecated
+@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
+public class LegacyOtpDetector {
+    private static final int PATTERN_FLAGS =
+            Pattern.DOTALL | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;
+
+    private static ThreadLocal<Matcher> compileToRegex(String pattern) {
+        return ThreadLocal.withInitial(() -> Pattern.compile(pattern, PATTERN_FLAGS).matcher(""));
+    }
+
+    private static final float TC_THRESHOLD = 0.6f;
+
+    private static final ArrayMap<String, ThreadLocal<Matcher>> EXTRA_LANG_OTP_REGEX =
+            new ArrayMap<>();
+
+    /**
+     * A regex matching a line start, open paren, arrow, colon (not proceeded by a digit), open
+     * square
+     * bracket, equals sign, double or single quote, ideographic char, or a space that is not
+     * preceded
+     * by a number. It will not consume the start char (meaning START won't be included in the
+     * matched
+     * string)
+     */
+    private static final String START =
+            "(^|(?<=((^|[^0-9])\\s)|[>(\"'=\\[\\p{IsIdeographic}]|[^0-9]:))";
+
+    /** One single OTP char. A number or alphabetical char (that isn't also ideographic) */
+    private static final String OTP_CHAR = "([0-9\\p{IsAlphabetic}&&[^\\p{IsIdeographic}]])";
+
+    /** One OTP char, followed by an optional dash */
+    private static final String OTP_CHAR_WITH_DASH = format("(%s-?)", OTP_CHAR);
+
+    /**
+     * Performs a lookahead to find a digit after 0 to 7 OTP_CHARs. This ensures that our potential
+     * OTP code contains at least one number
+     */
+    private static final String FIND_DIGIT = format("(?=%s{0,7}\\d)", OTP_CHAR_WITH_DASH);
+
+    /**
+     * Matches between 5 and 8 otp chars, with dashes in between. Here, we are assuming an OTP code
+     * is
+     * 5-8 characters long. The last char must not be followed by a dash
+     */
+    private static final String OTP_CHARS = format("(%s{4,7}%s)", OTP_CHAR_WITH_DASH, OTP_CHAR);
+
+    /**
+     * A regex matching a line end, a space that is not followed by a number, an ideographic char,
+     * or
+     * a period, close paren, close square bracket, single or double quote, exclamation point,
+     * question mark, or comma. It will not consume the end char
+     */
+    private static final String END = "(?=\\s[^0-9]|$|\\p{IsIdeographic}|[.?!,)'\\]\"])";
+
+    /** A regex matching four digit numerical codes */
+    private static final String FOUR_DIGITS = "(\\d{4})";
+
+    private static final String FIVE_TO_EIGHT_ALPHANUM_AT_LEAST_ONE_NUM =
+            format("(%s%s)", FIND_DIGIT, OTP_CHARS);
+
+    /** A regex matching two pairs of 3 digits (ex "123 456") */
+    private static final String SIX_DIGITS_WITH_SPACE = "(\\d{3}\\s\\d{3})";
+
+    /**
+     * Combining the regular expressions above, we get an OTP regex: 1. search for START, THEN 2.
+     * match ONE of a. alphanumeric sequence, at least one number, length 5-8, with optional dashes
+     * b.
+     * 4 numbers in a row c. pair of 3 digit codes separated by a space THEN 3. search for END Ex:
+     * "6454", " 345 678.", "[YDT-456]"
+     */
+    private static final String ALL_OTP =
+            format(
+                    "%s(%s|%s|%s)%s",
+                    START, FIVE_TO_EIGHT_ALPHANUM_AT_LEAST_ONE_NUM, FOUR_DIGITS,
+                    SIX_DIGITS_WITH_SPACE, END);
+
+    private static final ThreadLocal<Matcher> OTP_REGEX = compileToRegex(ALL_OTP);
+
+    /**
+     * A Date regular expression. Looks for dates with the month, day, and year separated by
+     * dashes.
+     * Handles one and two digit months and days, and four or two-digit years. It makes the
+     * following
+     * assumptions: Dates and months will never be higher than 39 If a four digit year is used, the
+     * leading digit will be 1 or 2
+     */
+    private static final String DATE_WITH_DASHES = "([0-3]?\\d-[0-3]?\\d-([12]\\d)?\\d\\d)";
+
+    /**
+     * matches a ten digit phone number, when the area code is separated by a space or dash.
+     * Supports
+     * optional parentheses around the area code, and an optional dash or space in between the rest
+     * of
+     * the numbers. This format registers as an otp match due to the space between the area code
+     * and
+     * the rest, but shouldn't.
+     */
+    private static final String PHONE_WITH_SPACE = "(\\(?\\d{3}\\)?(-|\\s)?\\d{3}(-|\\s)?\\d{4})";
+
+    /**
+     * A combination of common false positives. These matches are expected to be longer than (or
+     * equal
+     * in length to) otp matches, and are always run, even if we have a language specific regex
+     */
+    private static final ThreadLocal<Matcher> FALSE_POSITIVE_LONGER_REGEX =
+            compileToRegex(format("%s(%s|%s)%s", START, DATE_WITH_DASHES, PHONE_WITH_SPACE, END));
+
+    /** A regex matching the common years of 19xx and 20xx. Used for false positive reduction */
+    private static final String COMMON_YEARS = format("%s((19|20)\\d\\d)%s", START, END);
+
+    /**
+     * A regex matching three lower case letters. Used for false positive reduction, as no known
+     * OTPs
+     * have 3 lowercase letters in sequence.
+     */
+    private static final String THREE_LOWERCASE = "(\\p{Ll}{3})";
+
+    /**
+     * A combination of common false positives. Run in cases where we don't have a language specific
+     * regular expression. These matches are expect to be shorter than (or equal in length to) otp
+     * matches
+     */
+    private static final ThreadLocal<Matcher> FALSE_POSITIVE_SHORTER_REGEX =
+            compileToRegex(format("%s|%s", COMMON_YEARS, THREE_LOWERCASE));
+
+    /**
+     * A list of regular expressions representing words found in an OTP context (non case sensitive)
+     * Note: TAN is short for Transaction Authentication Number
+     */
+    private static final String[] ENGLISH_CONTEXT_WORDS =
+            new String[]{
+                    "pin",
+                    "pass[-\\s]?(code|word)",
+                    "TAN",
+                    "otp",
+                    "2fa",
+                    "(two|2)[-\\s]?factor",
+                    "log[-\\s]?in",
+                    "auth(enticat(e|ion))?",
+                    "code",
+                    "secret",
+                    "verif(y|ication)",
+                    "one(\\s|-)?time",
+                    "access",
+                    "validat(e|ion)"
+            };
+
+    /**
+     * Creates a regular expression to match any of a series of individual words, case insensitive.
+     * It
+     * also verifies the position of the word, relative to the OTP match
+     */
+    private static ThreadLocal<Matcher> createDictionaryRegex(String[] words) {
+        StringBuilder regex = new StringBuilder("(");
+        for (int i = 0; i < words.length; i++) {
+            String boundedWord = "\\b" + words[i] + "\\b";
+            regex.append(boundedWord);
+            if (i != words.length - 1) {
+                regex.append("|");
+            }
+        }
+        regex.append(")");
+        return compileToRegex(regex.toString());
+    }
+
+    static {
+        EXTRA_LANG_OTP_REGEX.put(
+                ULocale.ENGLISH.toLanguageTag(), createDictionaryRegex(ENGLISH_CONTEXT_WORDS));
+    }
+
+    /**
+     * Checks if a string of text might contain an OTP, based on several regular expressions, and
+     * potentially using a textClassifier to eliminate false positives
+     *
+     * @param sensitiveText          The text whose content should be checked
+     * @param checkForFalsePositives If true, will ensure the content does not match the date
+     *                               regex.
+     *                               If a TextClassifier is provided, it will then try to find a
+     *                               language specific regex. If it
+     *                               is successful, it will use that regex to check for false
+     *                               positives. If it is not, it will
+     *                               use the TextClassifier (if provided), plus the year and three
+     *                               lowercase regexes to remove
+     *                               possible false positives.
+     * @param tc                     If non null, the provided TextClassifier will be used to find
+     *                               the language of the
+     *                               text, and look for a language-specific regex for it. If
+     *                               checkForFalsePositives is true will
+     *                               also use the classifier to find flight codes and addresses.
+     * @param language               If non null, then the TextClassifier (if provided), will not
+     *                               perform language
+     *                               id, and the system will assume the text is in the specified
+     *                               language
+     * @return True if we believe an OTP is in the message, false otherwise.
+     */
+    public static boolean containsOtp(
+            String sensitiveText,
+            boolean checkForFalsePositives,
+            @Nullable TextClassifier tc,
+            @Nullable ULocale language) {
+        if (sensitiveText == null || !SdkLevel.isAtLeastV()) {
+            return false;
+        }
+        Matcher otpMatcher = OTP_REGEX.get();
+        otpMatcher.reset(sensitiveText);
+        boolean otpMatch = otpMatcher.find();
+        if (!checkForFalsePositives || !otpMatch) {
+            return otpMatch;
+        }
+
+        if (allOtpMatchesAreFalsePositives(sensitiveText, FALSE_POSITIVE_LONGER_REGEX.get(),
+                true)) {
+            return false;
+        }
+
+        if (tc != null || language != null) {
+            if (language == null) {
+                language = getLanguageWithRegex(sensitiveText, tc);
+            }
+            Matcher languageSpecificMatcher =
+                    language != null ? EXTRA_LANG_OTP_REGEX.get(language.toLanguageTag()).get()
+                            : null;
+            if (languageSpecificMatcher != null) {
+                languageSpecificMatcher.reset(sensitiveText);
+                // Only use the language-specific regex for false positives
+                return languageSpecificMatcher.find();
+            }
+            // Only check for OTPs when there is a language specific matcher
+            return false;
+        }
+
+        return !allOtpMatchesAreFalsePositives(
+                sensitiveText, FALSE_POSITIVE_SHORTER_REGEX.get(), false);
+    }
+
+    /**
+     * Checks that a given text has at least one match for one regex, that doesn't match another
+     *
+     * @param text                      The full text to check
+     * @param falsePositiveRegex        A regex that should not match the OTP regex (for at least
+     *                                  one match
+     *                                  found by the OTP regex). The false positive regex matches
+     *                                  may be longer or shorter than the
+     *                                  OTP matches.
+     * @param fpMatchesAreLongerThanOtp Whether the false positives are longer than the otp
+     *                                  matches.
+     *                                  If true, this method will search the whole text for false
+     *                                  positives, and verify at least
+     *                                  one OTP match is not contained by any of the false
+     *                                  positives. If false, then this method
+     *                                  will search individual OTP matches for false positives, and
+     *                                  will verify at least one OTP
+     *                                  match doesn't contain a false positive.
+     * @return true, if all matches found by OTP_REGEX are contained in, or themselves contain a
+     * match
+     * to falsePositiveRegex, or there are no OTP matches, false otherwise.
+     */
+    private static boolean allOtpMatchesAreFalsePositives(
+            String text, Matcher falsePositiveRegex, boolean fpMatchesAreLongerThanOtp) {
+        List<String> falsePositives = new ArrayList<>();
+        if (fpMatchesAreLongerThanOtp) {
+            // if the false positives are longer than the otp, search for them in the whole text
+            falsePositives = getAllMatches(text, falsePositiveRegex);
+        }
+        List<String> otpMatches = getAllMatches(text, OTP_REGEX.get());
+        for (String otpMatch : otpMatches) {
+            boolean otpMatchContainsNoFp = true;
+            boolean noFpContainsOtpMatch = true;
+            if (!fpMatchesAreLongerThanOtp) {
+                // if the false positives are shorter than the otp, search for them in the otp match
+                falsePositives = getAllMatches(otpMatch, falsePositiveRegex);
+            }
+            for (String falsePositive : falsePositives) {
+                otpMatchContainsNoFp =
+                        fpMatchesAreLongerThanOtp
+                                || (otpMatchContainsNoFp && !otpMatch.contains(falsePositive));
+                noFpContainsOtpMatch =
+                        !fpMatchesAreLongerThanOtp
+                                || (noFpContainsOtpMatch && !falsePositive.contains(otpMatch));
+            }
+            if (otpMatchContainsNoFp && noFpContainsOtpMatch) {
+                return false;
+            }
+        }
+        return true;
+    }
+
+    private static List<String> getAllMatches(String text, Matcher regex) {
+        ArrayList<String> matches = new ArrayList<>();
+        regex.reset(text);
+        while (regex.find()) {
+            matches.add(regex.group());
+        }
+        return matches;
+    }
+
+  /**
+   * Tries to determine the language of the given text. Will return the language with the highest
+   * confidence score that meets the minimum threshold, and has a language-specific regex, null
+   * otherwise.
+   *
+   * @param text The text to analyze for language detection
+   * @param tc   The {@link TextClassifier} to use for language detection. Can be null
+   * @return The {@link ULocale} of the detected language, or null if no language meets the criteria
+   */
+    @Nullable
+    public static ULocale getLanguageWithRegex(String text, @Nullable TextClassifier tc) {
+        if (tc == null) {
+            return null;
+        }
+
+        float highestConfidence = 0;
+        ULocale highestConfidenceLocale = null;
+        TextLanguage.Request langRequest = new TextLanguage.Request.Builder(text).build();
+        TextLanguage lang = tc.detectLanguage(langRequest);
+        for (int i = 0; i < lang.getLocaleHypothesisCount(); i++) {
+            ULocale locale = lang.getLocale(i);
+            float confidence = lang.getConfidenceScore(locale);
+            if (confidence >= TC_THRESHOLD
+                    && confidence >= highestConfidence
+                    && EXTRA_LANG_OTP_REGEX.containsKey(locale.toLanguageTag())) {
+                highestConfidence = confidence;
+                highestConfidenceLocale = locale;
+            }
+        }
+        return highestConfidenceLocale;
+    }
+
+    private LegacyOtpDetector() {
+    }
+}
diff --git a/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java b/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java
index f2f081d..c22e37f 100644
--- a/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java
+++ b/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java
@@ -25,34 +25,36 @@ import static android.app.Notification.EXTRA_SUB_TEXT;
 import static android.app.Notification.EXTRA_SUMMARY_TEXT;
 import static android.app.Notification.EXTRA_TEXT;
 import static android.app.Notification.EXTRA_TEXT_LINES;
-import static android.app.Notification.EXTRA_TITLE;
 import static android.app.Notification.EXTRA_TITLE_BIG;
-import static android.os.Build.VERSION.SDK_INT;
-
-import static java.lang.String.format;
 
 import android.annotation.SuppressLint;
 import android.app.Notification;
 import android.app.Notification.MessagingStyle;
 import android.app.Notification.MessagingStyle.Message;
+import android.ext.services.ExtServicesStatsLog;
 import android.icu.util.ULocale;
 import android.os.Build;
 import android.os.Bundle;
 import android.os.Parcelable;
-import android.util.ArrayMap;
+import android.permission.flags.Flags;
 import android.view.textclassifier.TextClassifier;
-import android.view.textclassifier.TextLanguage;
+import android.view.textclassifier.TextLinks;
 
+import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.RequiresApi;
 import androidx.annotation.VisibleForTesting;
 
+import com.android.modules.utils.build.SdkLevel;
+
+import com.google.common.collect.ImmutableList;
+
 import java.util.ArrayList;
 import java.util.Arrays;
+import java.util.HashSet;
 import java.util.List;
 import java.util.Objects;
-import java.util.regex.Matcher;
-import java.util.regex.Pattern;
+import java.util.Set;
 
 /**
  * Class with helper methods related to detecting OTP codes in notifications.
@@ -80,195 +82,17 @@ public class NotificationOtpDetectionHelper {
                     Notification.CallStyle.class.getName()
             );
 
-    private static final int PATTERN_FLAGS =
-            Pattern.DOTALL | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;
-
-    private static ThreadLocal<Matcher> compileToRegex(String pattern) {
-        return ThreadLocal.withInitial(() -> Pattern.compile(pattern, PATTERN_FLAGS).matcher(""));
-    }
-
-    private static final float TC_THRESHOLD = 0.6f;
-
-    private static final ArrayMap<String, ThreadLocal<Matcher>> EXTRA_LANG_OTP_REGEX =
-            new ArrayMap<>();
-
     private static final int MAX_SENSITIVE_TEXT_LEN = 600;
 
-    /**
-     * A regex matching a line start, open paren, arrow, colon (not proceeded by a digit),
-     * open square bracket, equals sign, double or single quote, ideographic char, or a space that
-     * is not preceded by a number. It will not consume the start char (meaning START won't be
-     * included in the matched string)
-     */
-    private static final String START =
-            "(^|(?<=((^|[^0-9])\\s)|[>(\"'=\\[\\p{IsIdeographic}]|[^0-9]:))";
-
-
-    /**
-     * One single OTP char. A number or alphabetical char (that isn't also ideographic)
-     */
-    private static final String OTP_CHAR = "([0-9\\p{IsAlphabetic}&&[^\\p{IsIdeographic}]])";
-
-    /**
-     * One OTP char, followed by an optional dash
-     */
-    private static final String OTP_CHAR_WITH_DASH = format("(%s-?)", OTP_CHAR);
-
-    /**
-     * Performs a lookahead to find a digit after 0 to 7 OTP_CHARs. This ensures that our potential
-     * OTP code contains at least one number
-     */
-    private static final String FIND_DIGIT = format("(?=%s{0,7}\\d)", OTP_CHAR_WITH_DASH);
+    private static final String TYPE_OTP =
+            SdkLevel.isAtLeastB() && Flags.textClassifierChoiceApiEnabled()
+                    ? TextClassifier.TYPE_OTP : "otp";
 
-    /**
-     * Matches between 5 and 8 otp chars, with dashes in between. Here, we are assuming an OTP code
-     * is 5-8 characters long. The last char must not be followed by a dash
-     */
-    private static final String OTP_CHARS = format("(%s{4,7}%s)", OTP_CHAR_WITH_DASH, OTP_CHAR);
-
-    /**
-     * A regex matching a line end, a space that is not followed by a number, an ideographic char,
-     * or a period, close paren, close square bracket, single or double quote, exclamation point,
-     * question mark, or comma. It will not consume the end char
-     */
-    private static final String END = "(?=\\s[^0-9]|$|\\p{IsIdeographic}|[.?!,)'\\]\"])";
-
-    /**
-     * A regex matching four digit numerical codes
-     */
-    private static final String FOUR_DIGITS = "(\\d{4})";
-
-    private static final String FIVE_TO_EIGHT_ALPHANUM_AT_LEAST_ONE_NUM =
-            format("(%s%s)", FIND_DIGIT, OTP_CHARS);
-
-    /**
-     * A regex matching two pairs of 3 digits (ex "123 456")
-     */
-    private static final String SIX_DIGITS_WITH_SPACE = "(\\d{3}\\s\\d{3})";
-
-    /**
-     * Combining the regular expressions above, we get an OTP regex:
-     * 1. search for START, THEN
-     * 2. match ONE of
-     *   a. alphanumeric sequence, at least one number, length 5-8, with optional dashes
-     *   b. 4 numbers in a row
-     *   c. pair of 3 digit codes separated by a space
-     * THEN
-     * 3. search for END Ex:
-     * "6454", " 345 678.", "[YDT-456]"
-     */
-    private static final String ALL_OTP =
-            format("%s(%s|%s|%s)%s",
-                    START, FIVE_TO_EIGHT_ALPHANUM_AT_LEAST_ONE_NUM, FOUR_DIGITS,
-                    SIX_DIGITS_WITH_SPACE, END);
-
-
-
-    private static final ThreadLocal<Matcher> OTP_REGEX = compileToRegex(ALL_OTP);
-    /**
-     * A Date regular expression. Looks for dates with the month, day, and year separated by dashes.
-     * Handles one and two digit months and days, and four or two-digit years. It makes the
-     * following assumptions:
-     * Dates and months will never be higher than 39
-     * If a four digit year is used, the leading digit will be 1 or 2
-     */
-    private static final String DATE_WITH_DASHES = "([0-3]?\\d-[0-3]?\\d-([12]\\d)?\\d\\d)";
-
-    /**
-     * matches a ten digit phone number, when the area code is separated by a space or dash.
-     * Supports optional parentheses around the area code, and an optional dash or space in between
-     * the rest of the numbers.
-     * This format registers as an otp match due to the space between the area code and the rest,
-     * but shouldn't.
-     */
-    private static final String PHONE_WITH_SPACE = "(\\(?\\d{3}\\)?(-|\\s)?\\d{3}(-|\\s)?\\d{4})";
-
-    /**
-     * A combination of common false positives. These matches are expected to be longer than (or
-     * equal in length to) otp matches, and are always run, even if we have a language specific
-     * regex
-     */
-    private static final ThreadLocal<Matcher> FALSE_POSITIVE_LONGER_REGEX =
-            compileToRegex(format("%s(%s|%s)%s", START, DATE_WITH_DASHES, PHONE_WITH_SPACE, END));
-
-    /**
-     * A regex matching the common years of 19xx and 20xx. Used for false positive reduction
-     */
-    private static final String COMMON_YEARS = format("%s((19|20)\\d\\d)%s", START, END);
-
-    /**
-     * A regex matching three lower case letters. Used for false positive reduction, as no known
-     *  OTPs have 3 lowercase letters in sequence.
-     */
-    private static final String THREE_LOWERCASE = "(\\p{Ll}{3})";
-
-    /**
-     * A combination of common false positives. Run in cases where we don't have a language specific
-     * regular expression. These matches are expect to be shorter than (or equal in length to) otp
-     * matches
-     */
-    private static final ThreadLocal<Matcher> FALSE_POSITIVE_SHORTER_REGEX =
-                    compileToRegex(format("%s|%s", COMMON_YEARS, THREE_LOWERCASE));
-
-    /**
-     * A list of regular expressions representing words found in an OTP context (non case sensitive)
-     * Note: TAN is short for Transaction Authentication Number
-     */
-    private static final String[] ENGLISH_CONTEXT_WORDS = new String[] {
-            "pin", "pass[-\\s]?(code|word)", "TAN", "otp", "2fa", "(two|2)[-\\s]?factor",
-            "log[-\\s]?in", "auth(enticat(e|ion))?", "code", "secret", "verif(y|ication)",
-            "one(\\s|-)?time", "access", "validat(e|ion)"
-    };
-
-    /**
-     * Creates a regular expression to match any of a series of individual words, case insensitive.
-     * It also verifies the position of the word, relative to the OTP match
-     */
-    private static ThreadLocal<Matcher> createDictionaryRegex(String[] words) {
-        StringBuilder regex = new StringBuilder("(");
-        for (int i = 0; i < words.length; i++) {
-            regex.append(findContextWordWithCode(words[i]));
-            if (i != words.length - 1) {
-                regex.append("|");
-            }
-        }
-        regex.append(")");
-        return compileToRegex(regex.toString());
-    }
-
-    /**
-     * Creates a regular expression that will find a context word, if that word occurs in the
-     * sentence preceding an OTP, or in the same sentence as an OTP (before or after). In both
-     * cases, the context word must occur within 50 characters of the suspected OTP
-     * @param contextWord The context word we expect to find around the OTP match
-     * @return A string representing a regular expression that will determine if we found a context
-     * word occurring before an otp match, or after it, but in the same sentence.
-     */
-    private static String findContextWordWithCode(String contextWord) {
-        String boundedContext = "\\b" + contextWord + "\\b";
-        // Asserts that we find the OTP code within 50 characters after the context word, with at
-        // most one sentence punctuation between the OTP code and the context word (i.e. they are
-        // in the same sentence, or the context word is in the previous sentence)
-        String contextWordBeforeOtpInSameOrPreviousSentence =
-                String.format("(%s(?=.{1,50}%s)[^.?!]*[.?!]?[^.?!]*%s)",
-                        boundedContext, ALL_OTP, ALL_OTP);
-        // Asserts that we find the context word within 50 characters after the OTP code, with no
-        // sentence punctuation between the OTP code and the context word (i.e. they are in the same
-        // sentence)
-        String contextWordAfterOtpSameSentence =
-                String.format("(%s)[^.!?]{1,50}%s", ALL_OTP, boundedContext);
-        return String.format("(%s|%s)", contextWordBeforeOtpInSameOrPreviousSentence,
-                contextWordAfterOtpSameSentence);
-    }
-
-    static {
-        EXTRA_LANG_OTP_REGEX.put(ULocale.ENGLISH.toLanguageTag(),
-                createDictionaryRegex(ENGLISH_CONTEXT_WORDS));
-    }
-
-    private static boolean isPreV() {
-        return SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM;
-    }
+    private static final TextClassifier.EntityConfig TC_REQUEST_CONFIG =
+            new TextClassifier.EntityConfig.Builder()
+                    .setIncludedTypes(ImmutableList.of(TYPE_OTP))
+                    .includeTypesFromTextClassifier(false)
+                    .build();
 
     /**
      * Checks if any text fields in a notification might contain an OTP, based on several
@@ -282,164 +106,66 @@ public class NotificationOtpDetectionHelper {
      *                               regex to check for false positives. If it is not, it will use
      *                               the TextClassifier (if provided), plus the year and three
      *                               lowercase regexes to remove possible false positives.
-     * @param tc If non null, the provided TextClassifier will be used to find the language of the
-     *           text, and look for a language-specific regex for it. If checkForFalsePositives is
-     *           true will also use the classifier to find flight codes and addresses.
+     * @param tc If use of TC for otp detection is enabled then the TC instance will be handling
+     *           OTP detection. If not and non null, the provided TextClassifier will be used to
+     *           find the language of the text, and look for a language-specific regex for it. If
+     *           checkForFalsePositives is true will also use the classifier to find flight codes
+     *           and addresses.
      * @return True if we believe an OTP is in the message, false otherwise.
      */
     public static boolean containsOtp(Notification notification,
             boolean checkForFalsePositives, @Nullable TextClassifier tc) {
-        if (notification == null || notification.extras == null || isPreV()) {
+        if (notification == null || notification.extras == null || !SdkLevel.isAtLeastV()) {
             return false;
         }
 
-        // Get the language of the text once
-        ULocale textLocale = getLanguageWithRegex(getTextForDetection(notification), tc);
         // Get all the individual fields
-        List<CharSequence> fields = getNotificationTextFields(notification);
-        for (CharSequence field : fields) {
-            if (field != null
-                    && containsOtp(field.toString(), checkForFalsePositives, tc, textLocale)) {
-                return true;
-            }
-        }
-
-        return false;
-    }
-
-    /**
-     * Checks if a string of text might contain an OTP, based on several
-     * regular expressions, and potentially using a textClassifier to eliminate false positives
-     *
-     * @param sensitiveText The text whose content should be checked
-     * @param checkForFalsePositives If true, will ensure the content does not match the date regex.
-     *                               If a TextClassifier is provided, it will then try to find a
-     *                               language specific regex. If it is successful, it will use that
-     *                               regex to check for false positives. If it is not, it will use
-     *                               the TextClassifier (if provided), plus the year and three
-     *                               lowercase regexes to remove possible false positives.
-     * @param tc If non null, the provided TextClassifier will be used to find the language of the
-     *           text, and look for a language-specific regex for it. If checkForFalsePositives is
-     *           true will also use the classifier to find flight codes and addresses.
-     * @param language If non null, then the TextClassifier (if provided), will not perform language
-     *                 id, and the system will assume the text is in the specified language
-     * @return True if we believe an OTP is in the message, false otherwise.
-     */
-    public static boolean containsOtp(String sensitiveText,
-            boolean checkForFalsePositives, @Nullable TextClassifier tc,
-            @Nullable ULocale language) {
-        if (sensitiveText == null || isPreV()) {
-            return false;
-        }
-
-        Matcher otpMatcher = OTP_REGEX.get();
-        otpMatcher.reset(sensitiveText);
-        boolean otpMatch = otpMatcher.find();
-        if (!checkForFalsePositives || !otpMatch) {
-            return otpMatch;
-        }
-
-        if (allOtpMatchesAreFalsePositives(
-                sensitiveText, FALSE_POSITIVE_LONGER_REGEX.get(), true)) {
-            return false;
-        }
+        Set<String> fields = getNotificationTextFields(notification);
 
-        if (tc != null || language != null) {
-            if (language == null) {
-                language = getLanguageWithRegex(sensitiveText, tc);
+        if (tc != null && Assistant.sUseTcForOtpDetection) {
+            for (String field : fields) {
+                if (containsOtpByTextClassifier(field, tc)) {
+                    return true;
+                }
             }
-            Matcher languageSpecificMatcher = language != null
-                    ? EXTRA_LANG_OTP_REGEX.get(language.toLanguageTag()).get() : null;
-            if (languageSpecificMatcher != null) {
-                languageSpecificMatcher.reset(sensitiveText);
-                // Only use the language-specific regex for false positives
-                return languageSpecificMatcher.find();
+        } else {
+            // Get the language of the text once
+            ULocale textLocale = LegacyOtpDetector.getLanguageWithRegex(
+                    getTextForDetection(notification), tc);
+            for (String field : fields) {
+                // Makes use of legacy local logic for OTP detection in V.
+                if (LegacyOtpDetector.containsOtp(field.toString(), checkForFalsePositives,
+                        tc, textLocale)) {
+                    return true;
+                }
             }
-            // Only check for OTPs when there is a language specific matcher
-            return false;
         }
-
-        return !allOtpMatchesAreFalsePositives(sensitiveText, FALSE_POSITIVE_SHORTER_REGEX.get(),
-                false);
+        return false;
     }
 
-    /**
-     * Checks that a given text has at least one match for one regex, that doesn't match another
-     * @param text The full text to check
-     * @param falsePositiveRegex A regex that should not match the OTP regex (for at least one match
-     *                           found by the OTP regex). The false positive regex matches may be
-     *                           longer or shorter than the OTP matches.
-     * @param fpMatchesAreLongerThanOtp Whether the false positives are longer than the otp matches.
-     *                                  If true, this method will search the whole text for false
-     *                                  positives, and verify at least one OTP match is not
-     *                                  contained by any of the false positives. If false, then this
-     *                                  method will search individual OTP matches for false
-     *                                  positives, and will verify at least one OTP match doesn't
-     *                                  contain a false positive.
-     * @return true, if all matches found by OTP_REGEX are contained in, or themselves contain a
-     *         match to falsePositiveRegex, or there are no OTP matches, false otherwise.
-     */
-    private static boolean allOtpMatchesAreFalsePositives(String text, Matcher falsePositiveRegex,
-            boolean fpMatchesAreLongerThanOtp) {
-        List<String> falsePositives = new ArrayList<>();
-        if (fpMatchesAreLongerThanOtp) {
-            // if the false positives are longer than the otp, search for them in the whole text
-            falsePositives = getAllMatches(text, falsePositiveRegex);
-        }
-        List<String> otpMatches = getAllMatches(text, OTP_REGEX.get());
-        for (String otpMatch: otpMatches) {
-            boolean otpMatchContainsNoFp = true;
-            boolean noFpContainsOtpMatch = true;
-            if (!fpMatchesAreLongerThanOtp) {
-                // if the false positives are shorter than the otp, search for them in the otp match
-                falsePositives = getAllMatches(otpMatch, falsePositiveRegex);
-            }
-            for (String falsePositive : falsePositives) {
-                otpMatchContainsNoFp = fpMatchesAreLongerThanOtp
-                        || (otpMatchContainsNoFp && !otpMatch.contains(falsePositive));
-                noFpContainsOtpMatch = !fpMatchesAreLongerThanOtp
-                        || (noFpContainsOtpMatch && !falsePositive.contains(otpMatch));
+    @SuppressLint("WrongConstant")
+    private static boolean containsOtpByTextClassifier(@NonNull String text,
+            @NonNull TextClassifier tc) {
+        TextLinks.Request request =
+                new TextLinks.Request.Builder(text).setEntityConfig(TC_REQUEST_CONFIG).build();
+
+        long startTime = System.currentTimeMillis();
+        TextLinks links = tc.generateLinks(request);
+        reportOtpDetectionDurationMs(System.currentTimeMillis() - startTime);
+
+        for (TextLinks.TextLink link : links.getLinks()) {
+            for (int i = 0; i < link.getEntityCount(); i++) {
+                if (link.getEntity(i).equals(TYPE_OTP)) {
+                    return true;
+                }
             }
-            if (otpMatchContainsNoFp && noFpContainsOtpMatch) {
-                return false;
-            }
-        }
-        return true;
-    }
-
-    private static List<String> getAllMatches(String text, Matcher regex) {
-        ArrayList<String> matches = new ArrayList<>();
-        regex.reset(text);
-        while (regex.find()) {
-            matches.add(regex.group());
         }
-        return matches;
+        return false;
     }
 
-    // Tries to determine the language of the given text. Will return the language with the highest
-    // confidence score that meets the minimum threshold, and has a language-specific regex, null
-    // otherwise
-    @Nullable
-    private static ULocale getLanguageWithRegex(String text,
-            @Nullable TextClassifier tc) {
-        if (tc == null) {
-            return null;
-        }
-
-        float highestConfidence = 0;
-        ULocale highestConfidenceLocale = null;
-        TextLanguage.Request langRequest = new TextLanguage.Request.Builder(text).build();
-        TextLanguage lang = tc.detectLanguage(langRequest);
-        for (int i = 0; i < lang.getLocaleHypothesisCount(); i++) {
-            ULocale locale = lang.getLocale(i);
-            float confidence = lang.getConfidenceScore(locale);
-            if (confidence >= TC_THRESHOLD && confidence >= highestConfidence
-                    && EXTRA_LANG_OTP_REGEX.containsKey(locale.toLanguageTag())) {
-                highestConfidence = confidence;
-                highestConfidenceLocale = locale;
-            }
-        }
-        return highestConfidenceLocale;
+    private static void reportOtpDetectionDurationMs(long duration) {
+        ExtServicesStatsLog.write(ExtServicesStatsLog.NOTIFICATION_ASSISTANT_DURATION_RECEIVED,
+                duration);
     }
 
     /**
@@ -450,24 +176,22 @@ public class NotificationOtpDetectionHelper {
      */
     @VisibleForTesting
     protected static String getTextForDetection(Notification notification) {
-        if (notification == null || notification.extras == null || isPreV()) {
+        if (notification == null || notification.extras == null || !SdkLevel.isAtLeastV()) {
             return "";
         }
-        StringBuilder builder = new StringBuilder();
-        for (CharSequence line : getNotificationTextFields(notification)) {
-            builder.append(line != null ? line : "").append(" ");
-        }
-        return builder.length() <= MAX_SENSITIVE_TEXT_LEN ? builder.toString()
-                : builder.substring(0, MAX_SENSITIVE_TEXT_LEN);
+        String joinedString = String.join(" ", getNotificationTextFields(notification));
+        return joinedString.length() <= MAX_SENSITIVE_TEXT_LEN
+                ? joinedString
+                : joinedString.substring(0, MAX_SENSITIVE_TEXT_LEN);
     }
 
-    protected static List<CharSequence> getNotificationTextFields(Notification notification) {
-        if (notification == null || notification.extras == null || isPreV()) {
-            return new ArrayList<>();
+    protected static Set<String> getNotificationTextFields(Notification notification) {
+        if (notification == null || notification.extras == null || !SdkLevel.isAtLeastV()) {
+            return new HashSet<>() {
+            };
         }
         ArrayList<CharSequence> fields = new ArrayList<>();
         Bundle extras = notification.extras;
-        fields.add(extras.getCharSequence(EXTRA_TITLE));
         fields.add(extras.getCharSequence(EXTRA_TEXT));
         fields.add(extras.getCharSequence(EXTRA_SUB_TEXT));
         fields.add(extras.getCharSequence(EXTRA_BIG_TEXT));
@@ -479,13 +203,16 @@ public class NotificationOtpDetectionHelper {
         }
         List<Message> messages = Message.getMessagesFromBundleArray(
                 extras.getParcelableArray(EXTRA_MESSAGES, Parcelable.class));
-        // Sort the newest messages (largest timestamp) first
-        messages.sort((MessagingStyle.Message lhs, MessagingStyle.Message rhs) ->
-                Long.compare(rhs.getTimestamp(), lhs.getTimestamp()));
         for (MessagingStyle.Message message : messages) {
             fields.add(message.getText());
         }
-        return fields;
+        Set<String> uniqueFields = new HashSet<>();
+        for (CharSequence field : fields) {
+            if (field != null && !field.isEmpty()) {
+                uniqueFields.add((field.toString()));
+            }
+        }
+        return uniqueFields;
     }
 
     /**
@@ -495,14 +222,21 @@ public class NotificationOtpDetectionHelper {
      * @return true, if further checks for OTP codes should be performed, false otherwise
      */
     public static boolean shouldCheckForOtp(Notification notification) {
-        if (notification == null || isPreV()
+        if (notification == null || !SdkLevel.isAtLeastV()
                 || EXCLUDED_STYLES.stream().anyMatch(s -> isStyle(notification, s))) {
             return false;
         }
-        return SENSITIVE_NOTIFICATION_CATEGORIES.contains(notification.category)
-                || SENSITIVE_STYLES.stream().anyMatch(s -> isStyle(notification, s))
-                || containsOtp(notification, false, null)
-                || shouldCheckForOtp(notification.publicVersion);
+        // We do not pre-check while using TC for otp detection
+        if (Assistant.sUseTcForOtpDetection) {
+            return SENSITIVE_NOTIFICATION_CATEGORIES.contains(notification.category)
+                    || SENSITIVE_STYLES.stream().anyMatch(s -> isStyle(notification, s))
+                    || shouldCheckForOtp(notification.publicVersion);
+        } else {
+            return SENSITIVE_NOTIFICATION_CATEGORIES.contains(notification.category)
+                    || SENSITIVE_STYLES.stream().anyMatch(s -> isStyle(notification, s))
+                    || containsOtp(notification, false, null)
+                    || shouldCheckForOtp(notification.publicVersion);
+        }
     }
 
     private static boolean isStyle(Notification notification, String styleClassName) {
diff --git a/java/tests/src/android/ext/services/notification/AssistantTest.kt b/java/tests/src/android/ext/services/notification/AssistantTest.kt
index c991ce8..e50c844 100644
--- a/java/tests/src/android/ext/services/notification/AssistantTest.kt
+++ b/java/tests/src/android/ext/services/notification/AssistantTest.kt
@@ -16,7 +16,6 @@
 
 package android.ext.services.notification
 
-import android.app.ActivityManager
 import android.app.Notification
 import android.app.Notification.CATEGORY_MESSAGE
 import android.app.NotificationChannel
@@ -25,14 +24,13 @@ import android.app.PendingIntent
 import android.content.Context
 import android.content.Intent
 import android.content.pm.PackageManager
-import android.content.pm.PackageManager.FEATURE_WATCH
+import android.ext.services.ExtServicesStatsLog
 import android.icu.util.ULocale
 import android.os.Process
 import android.provider.Telephony
 import android.service.notification.Adjustment.KEY_SENSITIVE_CONTENT
 import android.service.notification.Adjustment.KEY_TEXT_REPLIES
 import android.service.notification.StatusBarNotification
-import android.view.textclassifier.TextClassificationManager
 import android.view.textclassifier.TextClassifier
 import android.view.textclassifier.TextLanguage
 import android.view.textclassifier.TextLinks
@@ -40,13 +38,13 @@ import androidx.test.core.app.ApplicationProvider
 import com.android.modules.utils.build.SdkLevel
 import com.android.textclassifier.notification.SmartSuggestions
 import com.android.textclassifier.notification.SmartSuggestionsHelper
+import com.google.common.collect.ImmutableMap
 import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.Truth.assertWithMessage
+import org.junit.After
 import org.junit.Assume.assumeTrue
 import org.junit.Before
-import org.junit.Rule
 import org.junit.Test
-import org.junit.rules.TestRule
 import org.junit.runner.RunWith
 import org.junit.runners.JUnit4
 import org.mockito.ArgumentMatchers.any
@@ -65,6 +63,7 @@ import org.mockito.Mockito.verify
 import org.mockito.invocation.InvocationOnMock
 import org.mockito.stubbing.Stubber
 
+
 @RunWith(JUnit4::class)
 class AssistantTest {
     private val context = ApplicationProvider.getApplicationContext<Context>()
@@ -72,7 +71,6 @@ class AssistantTest {
     lateinit var mockTc: TextClassifier
     lateinit var assistant: Assistant
     lateinit var mockPm: PackageManager
-    lateinit var mockAm: ActivityManager
     val EXECUTOR_AWAIT_TIME = 200L
     val MOKITO_VERIFY_TIMEOUT = 500L
 
@@ -85,21 +83,23 @@ class AssistantTest {
         assistant = spy(Assistant())
         mockSuggestions = mock(SmartSuggestionsHelper::class.java)
         mockTc = mock(TextClassifier::class.java)
-        mockAm = mock(ActivityManager::class.java)
         mockPm = mock(PackageManager::class.java)
         assistant.mContext = context
         assistant.mSmsHelper = SmsHelper(context)
         assistant.mSmsHelper.initialize()
-        assistant.mAm = mockAm
         assistant.mPm = mockPm
         assistant.mSmartSuggestionsHelper = mockSuggestions
         doReturn(SmartSuggestions(emptyList(), emptyList()))
-                .whenKt(mockSuggestions).onNotificationEnqueued(any())
-        assistant.mTcm = context.getSystemService(TextClassificationManager::class.java)!!
-        assistant.mTcm.setTextClassifier(mockTc)
-        doReturn(TextLinks.Builder("").build()).whenKt(mockTc).generateLinks(any())
-        doReturn(false).whenKt(mockAm).isLowRamDevice
-        assistant.setUseTextClassifier()
+            .whenKt(mockSuggestions).onNotificationEnqueued(any())
+        assistant.mTc = mockTc
+        assistant.mIsWatch = false
+        assistant.mIsLowRamDevice = false
+        Assistant.sUseTcForOtpDetection = false
+    }
+
+    @After
+    fun reset() {
+        Assistant.sUseTcForOtpDetection = Assistant.useTcForOtpDetection()
     }
 
     @Test
@@ -161,8 +161,7 @@ class AssistantTest {
     @Test
     fun onNotificationEnqueued_doesntUseTcIfWatch() {
         val sbn = createSbn(TEXT_WITH_OTP)
-        doReturn(true).whenKt(mockPm).hasSystemFeature(eq(FEATURE_WATCH))
-        assistant.setUseTextClassifier()
+        assistant.mIsWatch = true
         // Empty list of detected languages means that the notification language didn't match
         doReturn(TextLanguage.Builder().build())
             .whenKt(mockTc).detectLanguage(any())
@@ -178,8 +177,7 @@ class AssistantTest {
     @Test
     fun onNotificationEnqueued_doesntUseTcIfLowRamDevice() {
         val sbn = createSbn(TEXT_WITH_OTP)
-        doReturn(true).whenKt(mockAm).isLowRamDevice
-        assistant.setUseTextClassifier()
+        assistant.mIsLowRamDevice = true;
         // Empty list of detected languages means that the notification language didn't match
         doReturn(TextLanguage.Builder().build())
             .whenKt(mockTc).detectLanguage(any())
@@ -248,6 +246,78 @@ class AssistantTest {
         assertThat(adjustment3.signals.containsKey(KEY_SENSITIVE_CONTENT)).isFalse()
     }
 
+    @Test
+    fun onNotificationEnqueued_callsTcForOtpDetection() {
+        assumeTrue(SdkLevel.isAtLeastB())
+        Assistant.sUseTcForOtpDetection = true
+        val sbn = createSbn(TEXT_WITH_OTP)
+        doReturn(TextLinks.Builder("")
+            .addLink(0, 0, ImmutableMap.of("otp", 1f))
+            .build()).whenKt(mockTc).generateLinks(any())
+        assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
+
+        Thread.sleep(EXECUTOR_AWAIT_TIME)
+
+        verify(assistant.mSmartSuggestionsHelper, timeout(MOKITO_VERIFY_TIMEOUT).times(1)).onNotificationEnqueued(eq(sbn))
+        verify(mockTc, atLeastOnce()).generateLinks(any())
+        verify(assistant, times(1)).reportEvent(ExtServicesStatsLog.NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__TC_FOR_OTP_DETECTION_ENABLED)
+        verify(assistant, times(1)).reportEvent(ExtServicesStatsLog.NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__NOTIFICATION_ENQUEUED)
+
+        // Adjustment upon OTP detection
+        verify(assistant, times(1)).createNotificationAdjustment(any(), isNull(), isNull(), eq(true))
+        verify(assistant, times(1)).reportEvent(ExtServicesStatsLog.NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__OTP_CHECKED)
+        verify(assistant, times(1)).reportEvent(ExtServicesStatsLog.NOTIFICATION_ASSISTANT_EVENT_REPORTED__EVENT_TYPE__OTP_DETECTED)
+
+        // Adjustment for smart suggestion
+        verify(assistant).createNotificationAdjustment(any(),
+            eq(ArrayList<Notification.Action>()), eq(ArrayList<CharSequence>()), eq(null))
+    }
+
+    @Test
+    fun onNotificationEnqueued_noAdjustmentForNonOtp() {
+        assumeTrue(SdkLevel.isAtLeastB())
+        Assistant.sUseTcForOtpDetection = true
+        val sbn = createSbn(TEXT_WITH_NO_OTP)
+        doReturn(TextLinks.Builder("").build()).whenKt(mockTc).generateLinks(any())
+        assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
+        Thread.sleep(EXECUTOR_AWAIT_TIME)
+        verify(mockTc, atLeastOnce()).generateLinks(any())
+        verify(assistant.mSmartSuggestionsHelper, timeout(MOKITO_VERIFY_TIMEOUT).times(1)).onNotificationEnqueued(eq(sbn))
+        // Adjustment upon OTP detection
+        verify(assistant, never()).createNotificationAdjustment(any(), isNull(), isNull(), eq(true))
+        // Adjustment for smart suggestion
+        verify(assistant).createNotificationAdjustment(any(),
+            eq(ArrayList<Notification.Action>()), eq(ArrayList<CharSequence>()), eq(null))
+    }
+
+    @Test
+    fun onNotificationEnqueued_usesTcForOtpDetectionInWatch() {
+        assumeTrue(SdkLevel.isAtLeastB())
+        Assistant.sUseTcForOtpDetection = true
+        val sbn = createSbn(TEXT_WITH_OTP)
+        assistant.mIsWatch = true
+        doReturn(TextLinks.Builder("")
+            .addLink(0, 0, ImmutableMap.of("otp", 1f))
+            .build()).whenKt(mockTc).generateLinks(any())
+        assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
+        Thread.sleep(EXECUTOR_AWAIT_TIME)
+        verify(mockTc, atLeastOnce()).generateLinks(any())
+    }
+
+    @Test
+    fun onNotificationEnqueued_usesTcForOtpDetectionInLowRamDevice() {
+        assumeTrue(SdkLevel.isAtLeastB())
+        Assistant.sUseTcForOtpDetection = true
+        val sbn = createSbn(TEXT_WITH_OTP)
+        assistant.mIsLowRamDevice = true;
+        doReturn(TextLinks.Builder("")
+            .addLink(0, 0, ImmutableMap.of("otp", 1f))
+            .build()).whenKt(mockTc).generateLinks(any())
+        assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
+        Thread.sleep(EXECUTOR_AWAIT_TIME)
+        verify(mockTc, atLeastOnce()).generateLinks(any())
+    }
+
     private fun createSbn(
         text: String = "",
         title: String = "",
@@ -291,6 +361,6 @@ class AssistantTest {
 
     companion object {
         const val TEXT_WITH_OTP = "Your login code is 345454"
+        const val TEXT_WITH_NO_OTP = "Your login code is unavailable"
     }
-
 }
diff --git a/java/tests/src/android/ext/services/notification/LegacyOtpDetectionHelperTest.kt b/java/tests/src/android/ext/services/notification/LegacyOtpDetectionHelperTest.kt
new file mode 100644
index 0000000..2ce4b1f
--- /dev/null
+++ b/java/tests/src/android/ext/services/notification/LegacyOtpDetectionHelperTest.kt
@@ -0,0 +1,353 @@
+/**
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
+ * in compliance with the License. You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software distributed under the License
+ * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
+ * or implied. See the License for the specific language governing permissions and limitations under
+ * the License.
+ */
+package android.ext.services.notification
+
+import android.icu.util.ULocale
+import android.os.Build
+import android.os.Build.VERSION.SDK_INT
+import android.view.textclassifier.TextClassifier
+import android.view.textclassifier.TextLanguage
+import android.view.textclassifier.TextLinks
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.google.common.truth.Truth.assertWithMessage
+import org.junit.After
+import org.junit.Assume.assumeTrue
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.ArgumentMatchers.any
+import org.mockito.Mockito
+
+@RunWith(AndroidJUnit4::class)
+class LegacyOtpDetectionHelperTest {
+  private val localeWithRegex = ULocale.ENGLISH
+  private val invalidLocale = ULocale.ROOT
+
+  private data class TestResult(
+    val expected: Boolean,
+    val actual: Boolean,
+    val failureMessage: String,
+  )
+
+  private val results = mutableListOf<TestResult>()
+
+  @Before
+  fun enableFlag() {
+    assumeTrue(SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM)
+    results.clear()
+  }
+
+  @After
+  fun verifyResults() {
+    val allFailuresMessage = StringBuilder("")
+    var numFailures = 0
+    for ((expected, actual, failureMessage) in results) {
+      if (expected != actual) {
+        numFailures += 1
+        allFailuresMessage.append("$failureMessage\n")
+      }
+    }
+    assertWithMessage("Found $numFailures failures:\n$allFailuresMessage")
+      .that(numFailures)
+      .isEqualTo(0)
+  }
+
+  private fun addResult(expected: Boolean, actual: Boolean, failureMessage: String) {
+    results.add(TestResult(expected, actual, failureMessage))
+  }
+
+  @Test
+  fun testContainsOtp_length() {
+    val tooShortAlphaNum = "123G"
+    val tooShortNumOnly = "123"
+    val minLenAlphaNum = "123G5"
+    val minLenNumOnly = "1235"
+    val twoTriplets = "123 456"
+    val tooShortTriplets = "12 345"
+    val maxLen = "123456F8"
+    val tooLong = "123T56789"
+
+    addMatcherTestResult(expected = true, minLenAlphaNum)
+    addMatcherTestResult(expected = true, minLenNumOnly)
+    addMatcherTestResult(expected = true, maxLen)
+    addMatcherTestResult(expected = false, tooShortAlphaNum, customFailureMessage = "is too short")
+    addMatcherTestResult(expected = false, tooShortNumOnly, customFailureMessage = "is too short")
+    addMatcherTestResult(expected = false, tooLong, customFailureMessage = "is too long")
+    addMatcherTestResult(expected = true, twoTriplets)
+    addMatcherTestResult(expected = false, tooShortTriplets, customFailureMessage = "is too short")
+  }
+
+  @Test
+  fun testContainsOtp_acceptsNonRomanAlphabeticalChars() {
+    val lowercase = "123ķ4"
+    val uppercase = "123Ŀ4"
+    val ideographicInMiddle = "123码456"
+    addMatcherTestResult(expected = true, lowercase)
+    addMatcherTestResult(expected = true, uppercase)
+    addMatcherTestResult(expected = false, ideographicInMiddle)
+  }
+
+  @Test
+  fun testContainsOtp_mustHaveNumber() {
+    val noNums = "TEFHXES"
+    addMatcherTestResult(expected = false, noNums)
+  }
+
+  @Test
+  fun testContainsOtp_dateExclusion() {
+    val date = "01-01-2001"
+    val singleDigitDate = "1-1-2001"
+    val twoDigitYear = "1-1-01"
+    val dateWithOtpAfter = "1-1-01 is the date of your code T3425"
+    val dateWithOtpBefore = "your code 54-234-3 was sent on 1-1-01"
+    val otpWithDashesButInvalidDate = "34-58-30"
+    val otpWithDashesButInvalidYear = "12-1-3089"
+
+    addMatcherTestResult(
+      expected = true,
+      date,
+      checkForFalsePositives = false,
+      customFailureMessage = "should match if checkForFalsePositives is false",
+    )
+    addMatcherTestResult(
+      expected = false,
+      date,
+      customFailureMessage = "should not match if checkForFalsePositives is true",
+    )
+    addMatcherTestResult(expected = false, singleDigitDate)
+    addMatcherTestResult(expected = false, twoDigitYear)
+    addMatcherTestResult(expected = true, dateWithOtpAfter)
+    addMatcherTestResult(expected = true, dateWithOtpBefore)
+    addMatcherTestResult(expected = true, otpWithDashesButInvalidDate)
+    addMatcherTestResult(expected = true, otpWithDashesButInvalidYear)
+  }
+
+  @Test
+  fun testContainsOtp_phoneExclusion() {
+    val parens = "(888) 8888888"
+    val allSpaces = "888 888 8888"
+    val withDash = "(888) 888-8888"
+    val allDashes = "888-888-8888"
+    val allDashesWithParen = "(888)-888-8888"
+    addMatcherTestResult(
+      expected = true,
+      parens,
+      checkForFalsePositives = false,
+      customFailureMessage = "should match if checkForFalsePositives is false",
+    )
+    addMatcherTestResult(expected = false, parens)
+    addMatcherTestResult(expected = false, allSpaces)
+    addMatcherTestResult(expected = false, withDash)
+    addMatcherTestResult(expected = false, allDashes)
+    addMatcherTestResult(expected = false, allDashesWithParen)
+  }
+
+  @Test
+  fun testContainsOtp_dashes() {
+    val oneDash = "G-3d523"
+    val manyDashes = "G-FD-745"
+    val tooManyDashes = "6--7893"
+    val oopsAllDashes = "------"
+    addMatcherTestResult(expected = true, oneDash)
+    addMatcherTestResult(expected = true, manyDashes)
+    addMatcherTestResult(expected = false, tooManyDashes)
+    addMatcherTestResult(expected = false, oopsAllDashes)
+  }
+
+  @Test
+  fun testContainsOtp_startAndEnd() {
+    val noSpaceStart = "your code isG-345821"
+    val noSpaceEnd = "your code is G-345821for real"
+    val numberSpaceStart = "your code is 4 G-345821"
+    val numberSpaceEnd = "your code is G-345821 3"
+    val colonStart = "your code is:G-345821"
+    val newLineStart = "your code is \nG-345821"
+    val quote = "your code is 'G-345821'"
+    val doubleQuote = "your code is \"G-345821\""
+    val bracketStart = "your code is [G-345821"
+    val ideographicStart = "your code is码G-345821"
+    val colonStartNumberPreceding = "your code is4:G-345821"
+    val periodEnd = "you code is G-345821."
+    val parens = "you code is (G-345821)"
+    val squareBrkt = "you code is [G-345821]"
+    val dashEnd = "you code is 'G-345821-'"
+    val randomSymbolEnd = "your code is G-345821$"
+    val underscoreEnd = "you code is 'G-345821_'"
+    val ideographicEnd = "your code is码G-345821码"
+    addMatcherTestResult(expected = false, noSpaceStart)
+    addMatcherTestResult(expected = false, noSpaceEnd)
+    addMatcherTestResult(expected = false, numberSpaceStart)
+    addMatcherTestResult(expected = false, numberSpaceEnd)
+    addMatcherTestResult(expected = false, colonStartNumberPreceding)
+    addMatcherTestResult(expected = false, dashEnd)
+    addMatcherTestResult(expected = false, underscoreEnd)
+    addMatcherTestResult(expected = false, randomSymbolEnd)
+    addMatcherTestResult(expected = true, colonStart)
+    addMatcherTestResult(expected = true, newLineStart)
+    addMatcherTestResult(expected = true, quote)
+    addMatcherTestResult(expected = true, doubleQuote)
+    addMatcherTestResult(expected = true, bracketStart)
+    addMatcherTestResult(expected = true, ideographicStart)
+    addMatcherTestResult(expected = true, periodEnd)
+    addMatcherTestResult(expected = true, parens)
+    addMatcherTestResult(expected = true, squareBrkt)
+    addMatcherTestResult(expected = true, ideographicEnd)
+  }
+
+  @Test
+  fun testContainsOtp_lookaheadMustBeOtpChar() {
+    val validLookahead = "g4zy75"
+    val spaceLookahead = "GVRXY 2"
+    addMatcherTestResult(expected = true, validLookahead)
+    addMatcherTestResult(expected = false, spaceLookahead)
+  }
+
+  @Test
+  fun testContainsOtp_threeDontMatch_withoutLanguageSpecificRegex() {
+    val tc = getTestTextClassifier(invalidLocale)
+    val threeLowercase = "34agb"
+    addMatcherTestResult(expected = false, threeLowercase, textClassifier = tc)
+  }
+
+  @Test
+  fun testContainsOtpCode_falseIfNoLanguageSpecificRegex() {
+    val tc = getTestTextClassifier(invalidLocale)
+    val text = "your one time code is 34343"
+    addMatcherTestResult(expected = false, text, textClassifier = tc)
+  }
+
+  @Test
+  fun testContainsOtp_englishSpecificRegex() {
+    val tc = getTestTextClassifier(ULocale.ENGLISH)
+    val englishFalsePositive = "This is a false positive 4543"
+    val englishContextWords =
+      listOf(
+        "login",
+        "log in",
+        "2fa",
+        "authenticate",
+        "auth",
+        "authentication",
+        "tan",
+        "password",
+        "passcode",
+        "two factor",
+        "two-factor",
+        "2factor",
+        "2 factor",
+        "pin",
+        "one time",
+      )
+    val englishContextWordsCase = listOf("LOGIN", "logIn", "LoGiN")
+    // Strings with a context word somewhere in the substring
+    val englishContextSubstrings = listOf("pins", "gaping", "backspin")
+    val codeInSentenceAfterNewline = "your code is \n 34343"
+
+    addMatcherTestResult(expected = false, englishFalsePositive, textClassifier = tc)
+    for (context in englishContextWords) {
+      val englishTruePositive = "$context $englishFalsePositive"
+      addMatcherTestResult(expected = true, englishTruePositive, textClassifier = tc)
+    }
+    for (context in englishContextWordsCase) {
+      val englishTruePositive = "$context $englishFalsePositive"
+      addMatcherTestResult(expected = true, englishTruePositive, textClassifier = tc)
+    }
+    for (falseContext in englishContextSubstrings) {
+      val anotherFalsePositive = "$falseContext $englishFalsePositive"
+      addMatcherTestResult(expected = false, anotherFalsePositive, textClassifier = tc)
+    }
+    addMatcherTestResult(expected = true, codeInSentenceAfterNewline, textClassifier = tc)
+  }
+
+  @Test
+  fun testContainsOtp_multipleFalsePositives() {
+    val otp = "code 1543 code"
+    val longFp = "888-777-6666"
+    val shortFp = "34ess"
+    val multipleLongFp = "$longFp something something $longFp"
+    val multipleLongFpWithOtpBefore = "$otp $multipleLongFp"
+    val multipleLongFpWithOtpAfter = "$multipleLongFp $otp"
+    val multipleLongFpWithOtpBetween = "$longFp $otp $longFp"
+    val multipleShortFp = "$shortFp something something $shortFp"
+    val multipleShortFpWithOtpBefore = "$otp $multipleShortFp"
+    val multipleShortFpWithOtpAfter = "$otp $multipleShortFp"
+    val multipleShortFpWithOtpBetween = "$shortFp $otp $shortFp"
+    addMatcherTestResult(expected = false, multipleLongFp)
+    addMatcherTestResult(expected = false, multipleShortFp)
+    addMatcherTestResult(expected = true, multipleLongFpWithOtpBefore)
+    addMatcherTestResult(expected = true, multipleLongFpWithOtpAfter)
+    addMatcherTestResult(expected = true, multipleLongFpWithOtpBetween)
+    addMatcherTestResult(expected = true, multipleShortFpWithOtpBefore)
+    addMatcherTestResult(expected = true, multipleShortFpWithOtpAfter)
+    addMatcherTestResult(expected = true, multipleShortFpWithOtpBetween)
+  }
+
+  @Test
+  fun testContainsOtpCode_languageSpecificOverridesFalsePositivesExceptDate() {
+    // TC will detect an address, but the language-specific regex will be preferred
+    val tc = getTestTextClassifier(localeWithRegex, listOf(TextClassifier.TYPE_ADDRESS))
+    val date = "1-1-01"
+    // Dates should still be checked
+    addMatcherTestResult(expected = false, date, textClassifier = tc)
+    // A string with a code with three lowercase letters, and an excluded year
+    val withOtherFalsePositives = "your login code is abd4f 1985"
+    // Other false positive regular expressions should not be checked
+    addMatcherTestResult(expected = true, withOtherFalsePositives, textClassifier = tc)
+  }
+
+  private fun addMatcherTestResult(
+    expected: Boolean,
+    text: String,
+    checkForFalsePositives: Boolean = true,
+    textClassifier: TextClassifier? = null,
+    customFailureMessage: String? = null,
+  ) {
+    val failureMessage =
+      if (customFailureMessage != null) {
+        "$text $customFailureMessage"
+      } else if (expected) {
+        "$text should match"
+      } else {
+        "$text should not match"
+      }
+    @Suppress("DEPRECATION") // This is mean to test the older class
+    val actual = LegacyOtpDetector.containsOtp(text, checkForFalsePositives, textClassifier, null)
+    addResult(expected = expected, actual, failureMessage)
+  }
+
+  // Creates a mock TextClassifier that will report back that text provided to it matches the
+  // given language codes (for language requests) and textClassifier entities (for links request)
+  private fun getTestTextClassifier(
+    locale: ULocale?,
+    tcEntities: List<String>? = null,
+  ): TextClassifier {
+    val tc = Mockito.mock(TextClassifier::class.java)
+    if (locale != null) {
+      Mockito.doReturn(TextLanguage.Builder().putLocale(locale, 0.9f).build())
+        .`when`(tc)
+        .detectLanguage(any(TextLanguage.Request::class.java))
+    }
+
+    val entityMap = mutableMapOf<String, Float>()
+    // to build the TextLinks, the entity map must have at least one item
+    entityMap[TextClassifier.TYPE_URL] = 0.01f
+    for (entity in tcEntities ?: emptyList()) {
+      entityMap[entity] = 0.9f
+    }
+    Mockito.doReturn(TextLinks.Builder("").addLink(0, 1, entityMap).build())
+      .`when`(tc)
+      .generateLinks(any(TextLinks.Request::class.java))
+    return tc
+  }
+}
\ No newline at end of file
diff --git a/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt b/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt
index d5bcd02..750bfc4 100644
--- a/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt
+++ b/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt
@@ -33,6 +33,8 @@ import android.view.textclassifier.TextLanguage
 import android.view.textclassifier.TextLinks
 import androidx.test.core.app.ApplicationProvider
 import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.modules.utils.build.SdkLevel
+import com.google.common.collect.ImmutableMap
 import com.google.common.truth.Truth.assertWithMessage
 import org.junit.After
 import org.junit.Assume.assumeTrue
@@ -41,12 +43,18 @@ import org.junit.Test
 import org.junit.runner.RunWith
 import org.mockito.ArgumentMatchers.any
 import org.mockito.Mockito
+import org.mockito.Mockito.doReturn
+import org.mockito.Mockito.mock
+import org.mockito.Mockito.never
+import org.mockito.Mockito.times
+import org.mockito.Mockito.verify
+import org.mockito.stubbing.Stubber
+import org.testng.Assert
 
 @RunWith(AndroidJUnit4::class)
 class NotificationOtpDetectionHelperTest {
     private val context = ApplicationProvider.getApplicationContext<Context>()
-    private val localeWithRegex = ULocale.ENGLISH
-    private val invalidLocale = ULocale.ROOT
+    private fun <T> Stubber.whenKt(mock: T): T = `when`(mock)
 
     private data class TestResult(
         val expected: Boolean,
@@ -59,6 +67,7 @@ class NotificationOtpDetectionHelperTest {
     @Before
     fun enableFlag() {
         assumeTrue(SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM)
+        Assistant.sUseTcForOtpDetection = false
         results.clear()
     }
 
@@ -76,10 +85,44 @@ class NotificationOtpDetectionHelperTest {
             .that(numFailures).isEqualTo(0)
     }
 
+    @After
+    fun reset() {
+        Assistant.sUseTcForOtpDetection = Assistant.useTcForOtpDetection()
+    }
+
     private fun addResult(expected: Boolean, actual: Boolean, failureMessage: String) {
         results.add(TestResult(expected, actual, failureMessage))
     }
 
+    @Test
+    fun testContainsOtp_otpDetectedUsingTc() {
+        assumeTrue(SdkLevel.isAtLeastB())
+        Assistant.sUseTcForOtpDetection = true
+        val notification = createNotification("Your otp code is 123456")
+        val mockTc: TextClassifier = mock(TextClassifier::class.java)
+        doReturn(TextLinks.Builder("")
+            .addLink(0, 0, ImmutableMap.of("otp", 1f))
+            .build()).whenKt(mockTc).generateLinks(any())
+        val actual = NotificationOtpDetectionHelper.containsOtp(notification, true, mockTc)
+        verify(mockTc, times(1)).generateLinks(any())
+        Assert.assertEquals(actual, true);
+    }
+
+    @Test
+    fun testContainsOtp_otpDetectedUsingLocalImpl() {
+        Assistant.sUseTcForOtpDetection = false
+        val notification = createNotification("Your otp code is 123456")
+        val mockTc: TextClassifier = mock(TextClassifier::class.java)
+        doReturn(TextLinks.Builder("")
+            .addLink(0, 0, ImmutableMap.of("otp", 1f))
+            .build()).whenKt(mockTc).generateLinks(any())
+        doReturn(TextLanguage.Builder().putLocale(ULocale.ENGLISH, 0.9f).build())
+            .whenKt(mockTc).detectLanguage(any())
+        val actual = NotificationOtpDetectionHelper.containsOtp(notification, true, mockTc)
+        verify(mockTc, never()).generateLinks(any())
+        Assert.assertEquals(actual, true);
+    }
+
     @Test
     fun testGetTextForDetection_textFieldsIncluded() {
         val text = "text"
@@ -88,7 +131,7 @@ class NotificationOtpDetectionHelperTest {
         val sensitive = NotificationOtpDetectionHelper.getTextForDetection(
             createNotification(text = text, title = title, subtext = subtext))
         addResult(expected = true, sensitive.contains(text),"expected sensitive text to contain $text")
-        addResult(expected = true, sensitive.contains(title), "expected sensitive text to contain $title")
+        addResult(expected = false, sensitive.contains(title), "expected sensitive text to contain $title")
         addResult(expected = true, sensitive.contains(subtext), "expected sensitive text to contain $subtext")
     }
 
@@ -112,52 +155,6 @@ class NotificationOtpDetectionHelperTest {
         addResult(expected = true, sensitive != null, "expected to get a nonnull string")
     }
 
-    @Test
-    fun testGetTextForDetection_messagesIncludedSorted() {
-        val empty = Person.Builder().setName("test name").build()
-        val messageText1 = "message text 1"
-        val messageText2 = "message text 2"
-        val messageText3 = "message text 3"
-        val timestamp1 = 0L
-        val timestamp2 = 1000L
-        val timestamp3 = 50L
-        val message1 =
-            Notification.MessagingStyle.Message(messageText1,
-                timestamp1,
-                empty)
-        val message2 =
-            Notification.MessagingStyle.Message(messageText2,
-                timestamp2,
-                empty)
-        val message3 =
-            Notification.MessagingStyle.Message(messageText3,
-                timestamp3,
-                empty)
-        val style = Notification.MessagingStyle(empty).apply {
-            addMessage(message1)
-            addMessage(message2)
-            addMessage(message3)
-        }
-        val notif = createNotification(style = style)
-        val sensitive = NotificationOtpDetectionHelper.getTextForDetection(notif)
-        addResult(expected = true, sensitive.contains(messageText1), "expected sensitive text to contain $messageText1")
-        addResult(expected = true, sensitive.contains(messageText2), "expected sensitive text to contain $messageText2")
-        addResult(expected = true, sensitive.contains(messageText3), "expected sensitive text to contain $messageText3")
-
-        // MessagingStyle notifications get their main text set automatically to their first
-        // message, so we should skip to the end of that to find the message text
-        val notifText = notif.extras.getCharSequence(EXTRA_TEXT)?.toString() ?: ""
-        val messagesSensitiveStartIdx = sensitive.indexOf(notifText) + notifText.length
-        val sensitiveSub = sensitive.substring(messagesSensitiveStartIdx)
-        val text1Position = sensitiveSub.indexOf(messageText1)
-        val text2Position = sensitiveSub.indexOf(messageText2)
-        val text3Position = sensitiveSub.indexOf(messageText3)
-        // The messages should be sorted by timestamp, newest first, so 2 -> 3 -> 1
-        addResult(expected = true, text2Position < text1Position, "expected the newest message (2) to be first in \"$sensitiveSub\"")
-        addResult(expected = true, text2Position < text3Position, "expected the newest message (2) to be first in \"$sensitiveSub\"")
-        addResult(expected = true, text3Position < text1Position, "expected the middle message (3) to be center in \"$sensitiveSub\"")
-    }
-
     @Test
     fun testGetTextForDetection_textLinesIncluded() {
         val style = Notification.InboxStyle()
@@ -263,253 +260,6 @@ class NotificationOtpDetectionHelperTest {
                 "be checked")
     }
 
-
-    @Test
-    fun testContainsOtp_length() {
-        val tooShortAlphaNum = "123G"
-        val tooShortNumOnly = "123"
-        val minLenAlphaNum = "123G5"
-        val minLenNumOnly = "1235"
-        val twoTriplets = "123 456"
-        val tooShortTriplets = "12 345"
-        val maxLen = "123456F8"
-        val tooLong = "123T56789"
-
-        addMatcherTestResult(expected = true, minLenAlphaNum)
-        addMatcherTestResult(expected = true, minLenNumOnly)
-        addMatcherTestResult(expected = true, maxLen)
-        addMatcherTestResult(expected = false, tooShortAlphaNum, customFailureMessage = "is too short")
-        addMatcherTestResult(expected = false, tooShortNumOnly, customFailureMessage = "is too short")
-        addMatcherTestResult(expected = false, tooLong, customFailureMessage = "is too long")
-        addMatcherTestResult(expected = true, twoTriplets)
-        addMatcherTestResult(expected = false, tooShortTriplets, customFailureMessage = "is too short")
-    }
-
-    @Test
-    fun testContainsOtp_acceptsNonRomanAlphabeticalChars() {
-        val lowercase = "123ķ4"
-        val uppercase = "123Ŀ4"
-        val ideographicInMiddle = "123码456"
-        addMatcherTestResult(expected = true, lowercase)
-        addMatcherTestResult(expected = true, uppercase)
-        addMatcherTestResult(expected = false, ideographicInMiddle)
-    }
-
-    @Test
-    fun testContainsOtp_mustHaveNumber() {
-        val noNums = "TEFHXES"
-        addMatcherTestResult(expected = false, noNums)
-    }
-
-    @Test
-    fun testContainsOtp_dateExclusion() {
-        val date = "01-01-2001"
-        val singleDigitDate = "1-1-2001"
-        val twoDigitYear = "1-1-01"
-        val dateWithOtpAfter = "1-1-01 is the date of your code T3425"
-        val dateWithOtpBefore = "your code 54-234-3 was sent on 1-1-01"
-        val otpWithDashesButInvalidDate = "34-58-30"
-        val otpWithDashesButInvalidYear = "12-1-3089"
-
-        addMatcherTestResult(
-            expected = true,
-            date,
-            checkForFalsePositives = false,
-            customFailureMessage = "should match if checkForFalsePositives is false"
-        )
-        addMatcherTestResult(
-            expected = false,
-            date,
-            customFailureMessage = "should not match if checkForFalsePositives is true"
-        )
-        addMatcherTestResult(expected = false, singleDigitDate)
-        addMatcherTestResult(expected = false, twoDigitYear)
-        addMatcherTestResult(expected = true, dateWithOtpAfter)
-        addMatcherTestResult(expected = true, dateWithOtpBefore)
-        addMatcherTestResult(expected = true, otpWithDashesButInvalidDate)
-        addMatcherTestResult(expected = true, otpWithDashesButInvalidYear)
-    }
-
-    @Test
-    fun testContainsOtp_phoneExclusion() {
-        val parens = "(888) 8888888"
-        val allSpaces = "888 888 8888"
-        val withDash = "(888) 888-8888"
-        val allDashes = "888-888-8888"
-        val allDashesWithParen = "(888)-888-8888"
-        addMatcherTestResult(
-            expected = true,
-            parens,
-            checkForFalsePositives = false,
-            customFailureMessage = "should match if checkForFalsePositives is false"
-        )
-        addMatcherTestResult(expected = false, parens)
-        addMatcherTestResult(expected = false, allSpaces)
-        addMatcherTestResult(expected = false, withDash)
-        addMatcherTestResult(expected = false, allDashes)
-        addMatcherTestResult(expected = false, allDashesWithParen)
-    }
-
-    @Test
-    fun testContainsOtp_dashes() {
-        val oneDash = "G-3d523"
-        val manyDashes = "G-FD-745"
-        val tooManyDashes = "6--7893"
-        val oopsAllDashes = "------"
-        addMatcherTestResult(expected = true, oneDash)
-        addMatcherTestResult(expected = true, manyDashes)
-        addMatcherTestResult(expected = false, tooManyDashes)
-        addMatcherTestResult(expected = false, oopsAllDashes)
-    }
-
-    @Test
-    fun testContainsOtp_startAndEnd() {
-        val noSpaceStart = "your code isG-345821"
-        val noSpaceEnd = "your code is G-345821for real"
-        val numberSpaceStart = "your code is 4 G-345821"
-        val numberSpaceEnd = "your code is G-345821 3"
-        val colonStart = "your code is:G-345821"
-        val newLineStart = "your code is \nG-345821"
-        val quote = "your code is 'G-345821'"
-        val doubleQuote = "your code is \"G-345821\""
-        val bracketStart = "your code is [G-345821"
-        val ideographicStart = "your code is码G-345821"
-        val colonStartNumberPreceding = "your code is4:G-345821"
-        val periodEnd = "you code is G-345821."
-        val parens = "you code is (G-345821)"
-        val squareBrkt = "you code is [G-345821]"
-        val dashEnd = "you code is 'G-345821-'"
-        val randomSymbolEnd = "your code is G-345821$"
-        val underscoreEnd = "you code is 'G-345821_'"
-        val ideographicEnd = "your code is码G-345821码"
-        addMatcherTestResult(expected = false, noSpaceStart)
-        addMatcherTestResult(expected = false, noSpaceEnd)
-        addMatcherTestResult(expected = false, numberSpaceStart)
-        addMatcherTestResult(expected = false, numberSpaceEnd)
-        addMatcherTestResult(expected = false, colonStartNumberPreceding)
-        addMatcherTestResult(expected = false, dashEnd)
-        addMatcherTestResult(expected = false, underscoreEnd)
-        addMatcherTestResult(expected = false, randomSymbolEnd)
-        addMatcherTestResult(expected = true, colonStart)
-        addMatcherTestResult(expected = true, newLineStart)
-        addMatcherTestResult(expected = true, quote)
-        addMatcherTestResult(expected = true, doubleQuote)
-        addMatcherTestResult(expected = true, bracketStart)
-        addMatcherTestResult(expected = true, ideographicStart)
-        addMatcherTestResult(expected = true, periodEnd)
-        addMatcherTestResult(expected = true, parens)
-        addMatcherTestResult(expected = true, squareBrkt)
-        addMatcherTestResult(expected = true, ideographicEnd)
-    }
-
-    @Test
-    fun testContainsOtp_lookaheadMustBeOtpChar() {
-        val validLookahead = "g4zy75"
-        val spaceLookahead = "GVRXY 2"
-        addMatcherTestResult(expected = true, validLookahead)
-        addMatcherTestResult(expected = false, spaceLookahead)
-    }
-
-    @Test
-    fun testContainsOtp_threeDontMatch_withoutLanguageSpecificRegex() {
-        val tc = getTestTextClassifier(invalidLocale)
-        val threeLowercase = "34agb"
-        addMatcherTestResult(expected = false, threeLowercase, textClassifier = tc)
-    }
-
-    @Test
-    fun testContainsOtp_englishSpecificRegex() {
-        val tc = getTestTextClassifier(ULocale.ENGLISH)
-        val englishFalsePositive = "This is a false positive 4543"
-        val englishContextWords = listOf("login", "log in", "2fa", "authenticate", "auth",
-            "authentication", "tan", "password", "passcode", "two factor", "two-factor", "2factor",
-            "2 factor", "pin", "one time")
-        val englishContextWordsCase = listOf("LOGIN", "logIn", "LoGiN")
-        // Strings with a context word somewhere in the substring
-        val englishContextSubstrings = listOf("pins", "gaping", "backspin")
-        val codeInNextSentence = "context word: code. This sentence has the actual value of 434343"
-        val codeInNextSentenceTooFar =
-            "context word: code. ${"f".repeat(60)} This sentence has the actual value of 434343"
-        val codeTwoSentencesAfterContext = "context word: code. One sentence. actual value 34343"
-        val codeInSentenceBeforeContext = "34343 is a number. This number is a code"
-        val codeInSentenceAfterNewline = "your code is \n 34343"
-        val codeTooFarBeforeContext = "34343 ${"f".repeat(60)} code"
-
-        addMatcherTestResult(expected = false, englishFalsePositive, textClassifier = tc)
-        for (context in englishContextWords) {
-            val englishTruePositive = "$context $englishFalsePositive"
-            addMatcherTestResult(expected = true, englishTruePositive, textClassifier = tc)
-        }
-        for (context in englishContextWordsCase) {
-            val englishTruePositive = "$context $englishFalsePositive"
-            addMatcherTestResult(expected = true, englishTruePositive, textClassifier = tc)
-        }
-        for (falseContext in englishContextSubstrings) {
-            val anotherFalsePositive = "$falseContext $englishFalsePositive"
-            addMatcherTestResult(expected = false, anotherFalsePositive, textClassifier = tc)
-        }
-        addMatcherTestResult(expected = true, codeInNextSentence, textClassifier = tc)
-        addMatcherTestResult(expected = true, codeInSentenceAfterNewline, textClassifier = tc)
-        addMatcherTestResult(expected = false, codeTwoSentencesAfterContext, textClassifier = tc)
-        addMatcherTestResult(expected = false, codeInSentenceBeforeContext, textClassifier = tc)
-        addMatcherTestResult(expected = false, codeInNextSentenceTooFar, textClassifier = tc)
-        addMatcherTestResult(expected = false, codeTooFarBeforeContext, textClassifier = tc)
-    }
-
-    @Test
-    fun testContainsOtp_notificationFieldsCheckedIndividually() {
-        val tc = getTestTextClassifier(ULocale.ENGLISH)
-        // Together, the title and text will match the language-specific regex and the main regex,
-        // but apart, neither are enough
-        val notification = createNotification(text = "code", title = "434343")
-        addMatcherTestResult(expected = true, "code 434343")
-        addResult(expected = false, NotificationOtpDetectionHelper.containsOtp(notification, true,
-            tc), "Expected text of 'code' and title of '434343' not to match")
-    }
-
-    @Test
-    fun testContainsOtp_multipleFalsePositives() {
-        val otp = "code 1543 code"
-        val longFp = "888-777-6666"
-        val shortFp = "34ess"
-        val multipleLongFp = "$longFp something something $longFp"
-        val multipleLongFpWithOtpBefore = "$otp $multipleLongFp"
-        val multipleLongFpWithOtpAfter = "$multipleLongFp $otp"
-        val multipleLongFpWithOtpBetween = "$longFp $otp $longFp"
-        val multipleShortFp = "$shortFp something something $shortFp"
-        val multipleShortFpWithOtpBefore = "$otp $multipleShortFp"
-        val multipleShortFpWithOtpAfter = "$otp $multipleShortFp"
-        val multipleShortFpWithOtpBetween = "$shortFp $otp $shortFp"
-        addMatcherTestResult(expected = false, multipleLongFp)
-        addMatcherTestResult(expected = false, multipleShortFp)
-        addMatcherTestResult(expected = true, multipleLongFpWithOtpBefore)
-        addMatcherTestResult(expected = true, multipleLongFpWithOtpAfter)
-        addMatcherTestResult(expected = true, multipleLongFpWithOtpBetween)
-        addMatcherTestResult(expected = true, multipleShortFpWithOtpBefore)
-        addMatcherTestResult(expected = true, multipleShortFpWithOtpAfter)
-        addMatcherTestResult(expected = true, multipleShortFpWithOtpBetween)
-    }
-
-    @Test
-    fun testContainsOtpCode_falseIfNoLanguageSpecificRegex() {
-        val tc = getTestTextClassifier(invalidLocale)
-        val text = "your one time code is 34343"
-        addMatcherTestResult(expected = false, text, textClassifier = tc)
-    }
-
-    @Test
-    fun testContainsOtpCode_languageSpecificOverridesFalsePositivesExceptDate() {
-        // TC will detect an address, but the language-specific regex will be preferred
-        val tc = getTestTextClassifier(localeWithRegex, listOf(TextClassifier.TYPE_ADDRESS))
-        val date = "1-1-01"
-        // Dates should still be checked
-        addMatcherTestResult(expected = false, date, textClassifier = tc)
-        // A string with a code with three lowercase letters, and an excluded year
-        val withOtherFalsePositives = "your login code is abd4f 1985"
-        // Other false positive regular expressions should not be checked
-        addMatcherTestResult(expected = true, withOtherFalsePositives, textClassifier = tc)
-    }
-
     private fun createNotification(
         text: String? = "",
         title: String? = "",
diff --git a/jni/android_ext_services_displayhash_ImageHashManager.cpp b/jni/android_ext_services_displayhash_ImageHashManager.cpp
index 23d2d32..7a15362 100644
--- a/jni/android_ext_services_displayhash_ImageHashManager.cpp
+++ b/jni/android_ext_services_displayhash_ImageHashManager.cpp
@@ -21,6 +21,7 @@
 #include <log/log_main.h>
 #include <nativehelper/JNIHelp.h>
 #include <nativehelper/scoped_utf_chars.h>
+#include <algorithm>
 #include <array>
 #include <string>
 
```

