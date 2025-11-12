```diff
diff --git a/OWNERS b/OWNERS
index d91a2b2..6f6fde4 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,9 +1,3 @@
-# Android TV
-agazal@google.com
-
 # LauncherX
 souravbasu@google.com
 bval@google.com
-
-gubailey@google.com #{LAST_RESORT_SUGGESTION}
-timurc@google.com #{LAST_RESORT_SUGGESTION}
diff --git a/src/com/android/tv/feedbackconsent/TvFeedbackConsentActivity.java b/src/com/android/tv/feedbackconsent/TvFeedbackConsentActivity.java
index da0f239..f752266 100644
--- a/src/com/android/tv/feedbackconsent/TvFeedbackConsentActivity.java
+++ b/src/com/android/tv/feedbackconsent/TvFeedbackConsentActivity.java
@@ -151,6 +151,12 @@ public class TvFeedbackConsentActivity extends Activity implements
         viewLogsDialog.updateRecyclerView(systemLogs);
     }
 
+    @Override
+    public void onDumpsysReady() {
+    //   TODO: Add dumpsys to the dialog
+        Log.i(TAG, "onDumpsysReady");
+    }
+
     private void onSendFeedbackButtonClicked(View view) {
         sendLogs = ((Switch) requireViewById(R.id.system_logs_switch)).isChecked();
         sendBugreport = ((Switch) requireViewById(R.id.bugreport_switch)).isChecked();
diff --git a/src/com/android/tv/feedbackconsent/TvFeedbackConsentDataCollector.java b/src/com/android/tv/feedbackconsent/TvFeedbackConsentDataCollector.java
index bfe2c93..6da0d36 100644
--- a/src/com/android/tv/feedbackconsent/TvFeedbackConsentDataCollector.java
+++ b/src/com/android/tv/feedbackconsent/TvFeedbackConsentDataCollector.java
@@ -12,14 +12,15 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 
-/**
- * Generates and returns diagnostic data (such as logs, dumpsys, etc) from a device.
- */
+/** Generates and returns diagnostic data (such as logs, dumpsys, etc) from a device. */
 final class TvFeedbackConsentDataCollector {
 
     private static final String TAG = TvFeedbackConsentDataCollector.class.getSimpleName();
 
     private List<String> mSystemLogs = new ArrayList<>(0);
+    private List<String> mDumpsys = new ArrayList<>(0);
+    private List<String> dumpsysServices =
+            Arrays.asList("wifi", "bluetooth_manager", "meminfo", "procstats", "activity");
     private final TvFeedbackConsentDataCollectorCallback mDataCollectorCallback;
 
     TvFeedbackConsentDataCollector(TvFeedbackConsentDataCollectorCallback callback) {
@@ -34,9 +35,15 @@ final class TvFeedbackConsentDataCollector {
         this.mSystemLogs = systemLogs;
     }
 
-    /**
-     * Collects system logs through logcat (usually around 1-2 MB for the default 10,000 lines).
-     */
+    public List<String> getDumpsys() {
+        return mDumpsys;
+    }
+
+    private void setDumpsys(List<String> dumpsys) {
+        this.mDumpsys = dumpsys;
+    }
+
+    /** Collects system logs through logcat (usually around 1-2 MB for the default 10,000 lines). */
     public void collectSystemLogs(long numLines) {
         List<String> systemLogsCommand =
                 Arrays.asList("logcat", "-d", "-v", "time", "-t", String.valueOf(numLines));
@@ -44,6 +51,17 @@ final class TvFeedbackConsentDataCollector {
         mDataCollectorCallback.onSystemLogsReady();
     }
 
+    /** Collects dumpsys of approved services */
+    public void collectPartialDumpsys() {
+        List<String> dumpsys = new ArrayList<>(0);
+        dumpsysServices.forEach(
+                service -> {
+                    List<String> dumpsysCommand = Arrays.asList("dumpsys ", service);
+                    dumpsys.addAll(runCommand(dumpsysCommand));
+                });
+        setDumpsys(dumpsys);
+    }
+
     @NonNull
     private List<String> runCommand(List<String> command) {
         List<String> output = new ArrayList<>(0);
@@ -70,9 +88,10 @@ final class TvFeedbackConsentDataCollector {
      * @hide
      */
     interface TvFeedbackConsentDataCollectorCallback {
-        /**
-         * Callback invoked when system Logs are ready
-         */
+        /** Callback invoked when system Logs are ready */
         void onSystemLogsReady();
+
+        /** Callback invoked when dumpsys is ready */
+        void onDumpsysReady();
     }
 }
diff --git a/src/com/android/tv/feedbackconsent/TvFeedbackConsentService.java b/src/com/android/tv/feedbackconsent/TvFeedbackConsentService.java
index d0a5dc7..7e9d8dc 100644
--- a/src/com/android/tv/feedbackconsent/TvFeedbackConsentService.java
+++ b/src/com/android/tv/feedbackconsent/TvFeedbackConsentService.java
@@ -199,6 +199,7 @@ public final class TvFeedbackConsentService extends Service {
             consentIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
 
             try {
+                Log.d(TAG, "Displaying UI to request user consent.");
                 TvFeedbackConsentService.this.startActivity(consentIntent);
             } catch (ActivityNotFoundException e) {
                 Log.e(TAG, "Error starting activity", e);
```

