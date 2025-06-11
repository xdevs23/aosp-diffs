```diff
diff --git a/Android.bp b/Android.bp
index 7ec9c80..dfbd14c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -54,6 +54,7 @@ android_library {
         "androidx.appsearch_appsearch",
         "androidx.appsearch_appsearch-platform-storage",
         "android.service.notification.flags-aconfig-export-java",
+        "extservices-mainline-aconfig-java-lib",
     ],
 
     libs: [
@@ -82,6 +83,7 @@ android_app {
         shrink_resources: true,
         proguard_compatibility: false,
         proguard_flags_files: ["proguard.proguard"],
+        keep_runtime_invisible_annotations: true,
     },
     privileged: true,
     privapp_allowlist: ":privapp_allowlist_android.ext_tplus.services.xml",
@@ -112,6 +114,7 @@ android_app {
         shrink_resources: true,
         proguard_compatibility: false,
         proguard_flags_files: ["proguard.proguard"],
+        keep_runtime_invisible_annotations: true,
     },
     privileged: true,
     privapp_allowlist: ":privapp_allowlist_android.ext_sminus.services.xml",
diff --git a/OWNERS b/OWNERS
index 2ce48f7..71a31d5 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,6 +1,5 @@
 # Bug component: 1101073
 adarshsridhar@google.com
-npattan@google.com
 # Autofill
 include platform/frameworks/base:/core/java/android/service/autofill/OWNERS
 # PackageWatchdog
@@ -9,8 +8,6 @@ gavincorkery@google.com
 dsandler@google.com
 juliacr@google.com
 # TextClassifier
-toki@google.com
 tonymak@google.com
-licha@google.com
 
-include platform/packages/modules/common:/MODULES_OWNERS  # see go/mainline-owners-policy
\ No newline at end of file
+include platform/packages/modules/common:/MODULES_OWNERS  # see go/mainline-owners-policy
diff --git a/flags/Android.bp b/flags/Android.bp
new file mode 100644
index 0000000..8d4b21f
--- /dev/null
+++ b/flags/Android.bp
@@ -0,0 +1,40 @@
+//
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aconfig_declarations {
+    name: "extservices-mainline-aconfig-flags",
+    package: "com.android.ext.services.flags",
+    srcs: ["flags.aconfig"],
+    container: "com.android.ext.services",
+}
+
+java_aconfig_library {
+    name: "extservices-mainline-aconfig-java-lib",
+    aconfig_declarations: "extservices-mainline-aconfig-flags",
+    min_sdk_version: "30",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.extservices",
+    ],
+    installable: false,
+    visibility: [
+        "//packages/modules/ExtServices:__subpackages__",
+    ],
+}
diff --git a/flags/flags.aconfig b/flags/flags.aconfig
new file mode 100644
index 0000000..07d8e33
--- /dev/null
+++ b/flags/flags.aconfig
@@ -0,0 +1,9 @@
+package: "com.android.ext.services.flags"
+container: "com.android.ext.services"
+
+flag {
+    name: "text_classifier_for_otp_detection_enabled"
+    namespace: "permissions"
+    description: "Enables text classifier for OTP detection in ExtServices"
+    bug: "388899782"
+}
diff --git a/java/res/values-nl/strings.xml b/java/res/values-nl/strings.xml
index f23092c..c90d457 100644
--- a/java/res/values-nl/strings.xml
+++ b/java/res/values-nl/strings.xml
@@ -21,8 +21,8 @@
     <item msgid="7615778208475066419">"pincode"</item>
     <item msgid="7174505163902448507">"wachtwoord"</item>
     <item msgid="3917837442156595568">"toegangscode"</item>
-    <item msgid="6971032950332150936">"verificatie in 2 stappen"</item>
-    <item msgid="826248726164877615">"verificatie in 2 stappen"</item>
+    <item msgid="6971032950332150936">"tweefactorauthenticatie"</item>
+    <item msgid="826248726164877615">"tweefactorauthenticatie"</item>
     <item msgid="2156400793251117724">"inloggen"</item>
     <item msgid="3621495493711216796">"login"</item>
     <item msgid="4652629344958695406">"inloggen"</item>
diff --git a/java/src/android/ext/services/notification/Assistant.java b/java/src/android/ext/services/notification/Assistant.java
index e6dc8bf..6cec868 100644
--- a/java/src/android/ext/services/notification/Assistant.java
+++ b/java/src/android/ext/services/notification/Assistant.java
@@ -28,7 +28,6 @@ import android.os.Bundle;
 import android.os.Trace;
 import android.os.UserHandle;
 import android.service.notification.Adjustment;
-import android.service.notification.Flags;
 import android.service.notification.NotificationAssistantService;
 import android.service.notification.NotificationStats;
 import android.service.notification.StatusBarNotification;
@@ -142,7 +141,6 @@ public class Assistant extends NotificationAssistantService {
         }
 
         final boolean shouldCheckForOtp = SdkLevel.isAtLeastV()
-                && Flags.redactSensitiveNotificationsFromUntrustedListeners()
                 && Objects.equals(sbn.getPackageName(), mSmsHelper.getDefaultSmsPackage())
                 && NotificationOtpDetectionHelper.shouldCheckForOtp(sbn.getNotification());
         boolean foundOtpWithRegex = shouldCheckForOtp
diff --git a/java/tests/src/android/ext/services/notification/AssistantTest.kt b/java/tests/src/android/ext/services/notification/AssistantTest.kt
index e5b6444..c991ce8 100644
--- a/java/tests/src/android/ext/services/notification/AssistantTest.kt
+++ b/java/tests/src/android/ext/services/notification/AssistantTest.kt
@@ -28,11 +28,9 @@ import android.content.pm.PackageManager
 import android.content.pm.PackageManager.FEATURE_WATCH
 import android.icu.util.ULocale
 import android.os.Process
-import android.platform.test.flag.junit.SetFlagsRule
 import android.provider.Telephony
 import android.service.notification.Adjustment.KEY_SENSITIVE_CONTENT
 import android.service.notification.Adjustment.KEY_TEXT_REPLIES
-import android.service.notification.Flags
 import android.service.notification.StatusBarNotification
 import android.view.textclassifier.TextClassificationManager
 import android.view.textclassifier.TextClassifier
@@ -61,6 +59,7 @@ import org.mockito.Mockito.doReturn
 import org.mockito.Mockito.mock
 import org.mockito.Mockito.never
 import org.mockito.Mockito.spy
+import org.mockito.Mockito.timeout
 import org.mockito.Mockito.times
 import org.mockito.Mockito.verify
 import org.mockito.invocation.InvocationOnMock
@@ -75,20 +74,14 @@ class AssistantTest {
     lateinit var mockPm: PackageManager
     lateinit var mockAm: ActivityManager
     val EXECUTOR_AWAIT_TIME = 200L
+    val MOKITO_VERIFY_TIMEOUT = 500L
 
     private fun <T> Stubber.whenKt(mock: T): T = `when`(mock)
 
-    @get:Rule
-    val setFlagsRule = if (SdkLevel.isAtLeastV()) {
-        SetFlagsRule()
-    } else {
-        // On < V, have a test rule that does nothing
-        TestRule { statement, _ -> statement}
-    }
-
     @Before
     fun setUpMocks() {
         assumeTrue(SdkLevel.isAtLeastV())
+        assumeTrue(Telephony.Sms.getDefaultSmsPackage(context) != null)
         assistant = spy(Assistant())
         mockSuggestions = mock(SmartSuggestionsHelper::class.java)
         mockTc = mock(TextClassifier::class.java)
@@ -105,22 +98,8 @@ class AssistantTest {
         assistant.mTcm = context.getSystemService(TextClassificationManager::class.java)!!
         assistant.mTcm.setTextClassifier(mockTc)
         doReturn(TextLinks.Builder("").build()).whenKt(mockTc).generateLinks(any())
-        if (SdkLevel.isAtLeastV()) {
-            (setFlagsRule as SetFlagsRule).enableFlags(
-                Flags.FLAG_REDACT_SENSITIVE_NOTIFICATIONS_FROM_UNTRUSTED_LISTENERS
-            )
-        }
-    }
-
-    @Test
-    fun onNotificationEnqueued_doesntCheckForOtpIfFlagDisabled() {
-        (setFlagsRule as SetFlagsRule)
-            .disableFlags(Flags.FLAG_REDACT_SENSITIVE_NOTIFICATIONS_FROM_UNTRUSTED_LISTENERS)
-        val sbn = createSbn(TEXT_WITH_OTP)
-        val directReturn =
-            assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
-        // Expect no adjustment returned, despite the regex
-        assertThat(directReturn).isNull()
+        doReturn(false).whenKt(mockAm).isLowRamDevice
+        assistant.setUseTextClassifier()
     }
 
     @Test
@@ -142,7 +121,7 @@ class AssistantTest {
         assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
         Thread.sleep(EXECUTOR_AWAIT_TIME)
         verify(mockTc, atLeastOnce()).detectLanguage(any())
-        verify(assistant.mSmartSuggestionsHelper, times(1)).onNotificationEnqueued(eq(sbn))
+        verify(assistant.mSmartSuggestionsHelper, timeout(MOKITO_VERIFY_TIMEOUT).times(1)).onNotificationEnqueued(eq(sbn))
         // A false result shouldn't result in an adjustment call for the otp
         verify(assistant).createNotificationAdjustment(any(), isNull(), isNull(), eq(true))
         // One adjustment for the suggestions and OTP together
@@ -164,9 +143,9 @@ class AssistantTest {
         Thread.sleep(EXECUTOR_AWAIT_TIME)
         // Expect a call to the TC, and a call to adjust the notification
         verify(mockTc, atLeastOnce()).detectLanguage(any())
-        verify(assistant).createNotificationAdjustment(any(), isNull(), isNull(), eq(true))
+        verify(assistant, timeout(MOKITO_VERIFY_TIMEOUT)).createNotificationAdjustment(any(), isNull(), isNull(), eq(true))
         // Expect adjustment for the suggestions and OTP together, with a true value
-        verify(assistant).createNotificationAdjustment(any(),
+        verify(assistant, timeout(MOKITO_VERIFY_TIMEOUT)).createNotificationAdjustment(any(),
             eq(ArrayList<Notification.Action>()), eq(ArrayList<CharSequence>()), eq(true))
     }
 
diff --git a/jni/OWNERS b/jni/OWNERS
index 52c0a12..54899bf 100644
--- a/jni/OWNERS
+++ b/jni/OWNERS
@@ -1,2 +1 @@
-chaviw@google.com
 wanggang@google.com
diff --git a/native/OWNERS b/native/OWNERS
index 52c0a12..54899bf 100644
--- a/native/OWNERS
+++ b/native/OWNERS
@@ -1,2 +1 @@
-chaviw@google.com
 wanggang@google.com
diff --git a/proguard.proguard b/proguard.proguard
index e873931..0cd5be9 100644
--- a/proguard.proguard
+++ b/proguard.proguard
@@ -1,6 +1,8 @@
 -keepparameternames
 -keepattributes Exceptions,InnerClasses,Signature,Deprecated,
-                SourceFile,LineNumberTable,*Annotation*,EnclosingMethod
+                SourceFile,LineNumberTable,EnclosingMethod,
+                RuntimeVisibleAnnotations,RuntimeVisibleParameterAnnotations,
+                RuntimeVisibleTypeAnnotations,AnnotationDefault
 
 # Rules required by TextClassifierServiceLibNoManifest
 # Jni classes
```

