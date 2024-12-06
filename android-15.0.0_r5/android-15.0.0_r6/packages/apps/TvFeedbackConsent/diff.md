```diff
diff --git a/OWNERS b/OWNERS
index 1a7a0aa..d91a2b2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,8 +1,9 @@
 # Android TV
 agazal@google.com
-havrikov@google.com
-thomasleu@google.com
+
+# LauncherX
 souravbasu@google.com
 bval@google.com
-aabdagic@google.com #{LAST_RESORT_SUGGESTION}
-robhor@google.com #{LAST_RESORT_SUGGESTION}
+
+gubailey@google.com #{LAST_RESORT_SUGGESTION}
+timurc@google.com #{LAST_RESORT_SUGGESTION}
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 96f5757..b38a543 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -20,9 +20,7 @@
     <string name="feedback_system_logs_title_text" msgid="8162964763101361628">"Сва евиденција (систем и апликација)"</string>
     <string name="feedback_system_logs_legal_text" msgid="4770068793128503597">"Дељење свих евиденција уређаја које се односе на систем и апликацију може да шаље Google-у детаље као што су корисничка имена, локација, ИД уређаја и информације о мрежи. Google користи ове информације за решавање техничких проблема и унапређење услуга. Сазнајте више на g.co/android/devicelogs."</string>
     <string name="feedback_bugreport_title_text" msgid="8863884817986711122">"Уврсти извештај о грешци"</string>
-    <!-- String.format failed for translation -->
-    <!-- no translation found for feedback_bugreport_legal_display_text (4486929548753044585) -->
-    <skip />
+    <string name="feedback_bugreport_legal_display_text" msgid="4486929548753044585">"Извештај о грешци (од %1$s) садржи податке као што су корисничка имена, локација, ИД уређаја и информације о мрежи који помажу Google-у да разуме и реши проблем."</string>
     <string name="submit_feedback" msgid="217532499393989328">"Пошаљи"</string>
     <string name="cancel_feedback" msgid="6474868153025535650">"Откажи"</string>
     <string name="feedback_view_system_logs_button_text" msgid="1889709679017124924">"Прикажи евиденције система"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index d1c35df..2ccf33c 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -20,9 +20,7 @@
     <string name="feedback_system_logs_title_text" msgid="8162964763101361628">"تمام آلہ لاگز شامل کریں (سسٹم اور ایپ)"</string>
     <string name="feedback_system_logs_legal_text" msgid="4770068793128503597">"تمام سسٹم اور ایپ آلات لاگز کا اشتراک کرنے سے Google کو صارف نام، مقام، آلہ IDs اور نیٹ ورک کی معلومات جیسی تفصیلات بھیجی جا سکتی ہیں۔ Google تکنیکی مسائل حل کرنے اور سروسز کو بہتر بنانے کیلئے اس معلومات کا استعمال کرتا ہے۔ g.co/android/devicelogs پر مزید جانیں۔"</string>
     <string name="feedback_bugreport_title_text" msgid="8863884817986711122">"بگ رپورٹ شامل کریں"</string>
-    <!-- String.format failed for translation -->
-    <!-- no translation found for feedback_bugreport_legal_display_text (4486929548753044585) -->
-    <skip />
+    <string name="feedback_bugreport_legal_display_text" msgid="4486929548753044585">"بگ رپورٹ (%1$s سے) میں صارف کے نام، مقام، آلہ کی IDs اور نیٹ ورک کی معلومات جیسا ڈیٹا شامل ہے تاکہ Google کو مسئلہ سمجھنے اور اسے درست کرنے میں مدد ملے۔"</string>
     <string name="submit_feedback" msgid="217532499393989328">"جمع کرائیں"</string>
     <string name="cancel_feedback" msgid="6474868153025535650">"منسوخ کریں"</string>
     <string name="feedback_view_system_logs_button_text" msgid="1889709679017124924">"سسٹم لاگز دیکھیں"</string>
diff --git a/src/com/android/tv/feedbackconsent/TvFeedbackConsentActivity.java b/src/com/android/tv/feedbackconsent/TvFeedbackConsentActivity.java
index 07d874d..da0f239 100644
--- a/src/com/android/tv/feedbackconsent/TvFeedbackConsentActivity.java
+++ b/src/com/android/tv/feedbackconsent/TvFeedbackConsentActivity.java
@@ -18,6 +18,7 @@ package com.android.tv.feedbackconsent;
 
 import static com.android.tv.feedbackconsent.TvFeedbackConstants.BUGREPORT_CONSENT;
 import static com.android.tv.feedbackconsent.TvFeedbackConstants.BUGREPORT_REQUESTED;
+import static com.android.tv.feedbackconsent.TvFeedbackConstants.BUGREPORT_TOGGLE_ON_BY_DEFAULT;
 import static com.android.tv.feedbackconsent.TvFeedbackConstants.CANCEL_REQUEST;
 import static com.android.tv.feedbackconsent.TvFeedbackConstants.CONSENT_RECEIVER;
 import static com.android.tv.feedbackconsent.TvFeedbackConstants.RESULT_CODE_OK;
@@ -52,6 +53,7 @@ public class TvFeedbackConsentActivity extends Activity implements
     private static ResultReceiver resultReceiver;
     private boolean systemLogRequested;
     private boolean bugreportRequested;
+    private boolean setBugreportSwitchOnByDefault;
     private boolean sendLogs;
     private boolean sendBugreport;
     private boolean cancelRequest;
@@ -67,6 +69,8 @@ public class TvFeedbackConsentActivity extends Activity implements
         Intent intent = getIntent();
         systemLogRequested = intent.getBooleanExtra(SYSTEM_LOGS_REQUESTED, false);
         bugreportRequested = intent.getBooleanExtra(BUGREPORT_REQUESTED, false);
+        setBugreportSwitchOnByDefault =
+            intent.getBooleanExtra(BUGREPORT_TOGGLE_ON_BY_DEFAULT, false);
 
         if (!systemLogRequested && !bugreportRequested) {
             Log.e(TAG, "Consent screen requested without requesting any data.");
@@ -114,7 +118,11 @@ public class TvFeedbackConsentActivity extends Activity implements
             TextView bugreportLegalTextView = requireViewById(R.id.bugreport_legal_text);
             bugreportLegalTextView.setText(formattedBugreportLegalText);
 
-            View bugreportSwitch = requireViewById(R.id.bugreport_switch);
+            Switch bugreportSwitch = requireViewById(R.id.bugreport_switch);
+            bugreportSwitch = requireViewById(R.id.bugreport_switch);
+            if (setBugreportSwitchOnByDefault) {
+                bugreportSwitch.setChecked(true);
+            }
             bugreportSwitch.setOnFocusChangeListener(
                 (v, focused) -> bugreportRow.setSelected(focused));
         }
diff --git a/src/com/android/tv/feedbackconsent/TvFeedbackConsentService.java b/src/com/android/tv/feedbackconsent/TvFeedbackConsentService.java
index 9314e95..d0a5dc7 100644
--- a/src/com/android/tv/feedbackconsent/TvFeedbackConsentService.java
+++ b/src/com/android/tv/feedbackconsent/TvFeedbackConsentService.java
@@ -18,6 +18,7 @@ package com.android.tv.feedbackconsent;
 
 import static com.android.tv.feedbackconsent.TvFeedbackConstants.BUGREPORT_CONSENT;
 import static com.android.tv.feedbackconsent.TvFeedbackConstants.BUGREPORT_REQUESTED;
+import static com.android.tv.feedbackconsent.TvFeedbackConstants.BUGREPORT_TOGGLE_ON_BY_DEFAULT;
 import static com.android.tv.feedbackconsent.TvFeedbackConstants.CANCEL_REQUEST;
 import static com.android.tv.feedbackconsent.TvFeedbackConstants.CONSENT_RECEIVER;
 import static com.android.tv.feedbackconsent.TvFeedbackConstants.RESULT_CODE_OK;
@@ -57,9 +58,12 @@ public final class TvFeedbackConsentService extends Service {
 
     final TvDiagnosticInformationManagerBinder tvDiagnosticInformationBinder =
         new TvDiagnosticInformationManagerBinder();
+    private boolean setBugreportSwitchOnByDefault;
 
     @Override
     public IBinder onBind(Intent intent) {
+        setBugreportSwitchOnByDefault =
+            intent.getBooleanExtra(BUGREPORT_TOGGLE_ON_BY_DEFAULT, false);
         return tvDiagnosticInformationBinder;
     }
 
@@ -191,6 +195,7 @@ public final class TvFeedbackConsentService extends Service {
             consentIntent.putExtra(CONSENT_RECEIVER, resultReceiver);
             consentIntent.putExtra(BUGREPORT_REQUESTED, mBugreportRequested);
             consentIntent.putExtra(SYSTEM_LOGS_REQUESTED, mSystemLogsRequested);
+            consentIntent.putExtra(BUGREPORT_TOGGLE_ON_BY_DEFAULT, setBugreportSwitchOnByDefault);
             consentIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
 
             try {
diff --git a/src/com/android/tv/feedbackconsent/TvFeedbackConstants.java b/src/com/android/tv/feedbackconsent/TvFeedbackConstants.java
index ec4b07e..5c5def0 100644
--- a/src/com/android/tv/feedbackconsent/TvFeedbackConstants.java
+++ b/src/com/android/tv/feedbackconsent/TvFeedbackConstants.java
@@ -23,11 +23,11 @@ public final class TvFeedbackConstants {
 
     public static final String BUGREPORT_CONSENT = "BUGREPORT_CONSENT";
     public static final String BUGREPORT_REQUESTED = "BUGREPORT_REQUESTED";
+    public static final String BUGREPORT_TOGGLE_ON_BY_DEFAULT = "BUGREPORT_TOGGLE_ON_BY_DEFAULT";
     public static final String CONSENT_RECEIVER = "CONSENT_RECEIVER";
     public static final String CANCEL_REQUEST = "CANCEL_REQUEST";
     public static final int RESULT_CODE_OK = 0;
     public static final String SYSTEM_LOGS_CONSENT = "SYSTEM_LOGS_CONSENT";
     public static final String SYSTEM_LOGS_KEY = "SYSTEM_LOGS_KEY";
     public static final String SYSTEM_LOGS_REQUESTED = "SYSTEM_LOGS_REQUESTED";
-
 }
\ No newline at end of file
```

