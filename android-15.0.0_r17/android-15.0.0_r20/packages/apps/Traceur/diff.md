```diff
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 5080b4b2..0c0658d5 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -40,16 +40,16 @@
     <string name="stack_samples_saved" msgid="8863295751647724616">"מקבץ של דגימות שנשמרו"</string>
     <string name="saving_heap_dump" msgid="6118616780825771824">"שמירת תמונת מצב של הזיכרון"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"תמונת מצב של הזיכרון נשמרה"</string>
-    <string name="tap_to_share" msgid="4440713575852187545">"ניתן להקיש כדי לשתף את ההקלטה"</string>
+    <string name="tap_to_share" msgid="4440713575852187545">"ניתן ללחוץ כדי לשתף את ההקלטה"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"הפסקת המעקב"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"‏הפסקת פרופיילינג של המעבד (CPU)"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"חלק מקטגוריות המעקב אינן זמינות:"</string>
     <string name="trace_is_being_recorded" msgid="5947378146009337469">"המעקב מתועד"</string>
-    <string name="tap_to_stop_tracing" msgid="6533282719573871806">"יש להקיש כדי להפסיק את המעקב"</string>
+    <string name="tap_to_stop_tracing" msgid="6533282719573871806">"יש ללחוץ כדי להפסיק את המעקב"</string>
     <string name="stack_samples_are_being_recorded" msgid="8669254939248349583">"מקבץ של דגימות בתהליך הקלטה"</string>
-    <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"אפשר להקיש כדי להפסיק לקבץ דגימות"</string>
+    <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"אפשר ללחוץ כדי להפסיק לקבץ דגימות"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"מתבצעת הקלטה של תמונת מצב של הזיכרון"</string>
-    <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"אפשר להקיש כדי לעצור את ההקלטה של תמונת המצב של הזיכרון"</string>
+    <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"אפשר ללחוץ כדי לעצור את ההקלטה של תמונת המצב של הזיכרון"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"ניקוי הקבצים שנשמרו"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ההקלטות נמחקות כעבור חודש"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"לנקות את הקבצים שנשמרו?"</string>
diff --git a/src/com/android/traceur/TraceController.java b/src/com/android/traceur/TraceController.java
index 75ab6afc..f9962747 100644
--- a/src/com/android/traceur/TraceController.java
+++ b/src/com/android/traceur/TraceController.java
@@ -48,6 +48,10 @@ public class TraceController extends Handler {
     private static final String TAG = "TraceController";
     private static final String PERFETTO_SUFFIX = ".perfetto-trace";
     private static final String WINSCOPE_SUFFIX = "_winscope_traces.zip";
+    private static final int GRANT_ACCESS_FLAGS =
+        Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION |
+            Intent.FLAG_GRANT_READ_URI_PERMISSION |
+            Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
 
     private final Context mContext;
 
@@ -57,6 +61,7 @@ public class TraceController extends Handler {
 
     @Override
     public void handleMessage(Message msg) {
+        Log.d(TAG, "handling message " + msg.what + " in TraceController");
         switch (msg.what) {
             case MessageConstants.START_WHAT:
                 startTracingSafely(mContext, msg.getData());
@@ -109,33 +114,27 @@ public class TraceController extends Handler {
     // Files are kept on private storage, so turn into Uris that we can
     // grant temporary permissions for. We then share them, usually with BetterBug, via Intents
     private static void shareFiles(Context context, Messenger replyTo) {
+        Bundle data = new Bundle();
         String perfettoFileName = TraceUtils.getOutputFilename(TraceUtils.RecordingType.TRACE);
         TraceUtils.traceDump(context, perfettoFileName).ifPresent(files -> {
-            int grantAccessFlags =
-                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION |
-                    Intent.FLAG_GRANT_READ_URI_PERMISSION |
-                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
-            Bundle data = new Bundle();
-
             // Perfetto traces have their own viewer so it makes sense to move them out of the zip.
             files.stream().filter(it ->
                 it.getName().endsWith(PERFETTO_SUFFIX)
             ).findFirst().ifPresent(it -> {
                 Uri perfettoUri = FileProvider.getUriForFile(context, AUTHORITY, it);
                 files.remove(it);
-                context.grantUriPermission(SYSTEM_UI_PACKAGE_NAME, perfettoUri, grantAccessFlags);
+                context.grantUriPermission(SYSTEM_UI_PACKAGE_NAME, perfettoUri, GRANT_ACCESS_FLAGS);
                 data.putParcelable(MessageConstants.EXTRA_PERFETTO, perfettoUri);
             });
 
             String winscopeFileName = perfettoFileName.replace(PERFETTO_SUFFIX, WINSCOPE_SUFFIX);
             Uri winscopeUri = zipFileListIntoOneUri(context, files, winscopeFileName);
             if (winscopeUri != null) {
-                context.grantUriPermission(SYSTEM_UI_PACKAGE_NAME, winscopeUri, grantAccessFlags);
+                context.grantUriPermission(SYSTEM_UI_PACKAGE_NAME, winscopeUri, GRANT_ACCESS_FLAGS);
                 data.putParcelable(MessageConstants.EXTRA_WINSCOPE, winscopeUri);
             }
-
-            replyToClient(replyTo, MessageConstants.SHARE_WHAT, data);
         });
+        replyToClient(replyTo, MessageConstants.SHARE_WHAT, data);
     }
 
     @Nullable
diff --git a/src/com/android/traceur/TraceService.java b/src/com/android/traceur/TraceService.java
index ddb89e98..7e5d49e4 100644
--- a/src/com/android/traceur/TraceService.java
+++ b/src/com/android/traceur/TraceService.java
@@ -343,6 +343,7 @@ public class TraceService extends IntentService {
             postFileSharingNotification(getApplicationContext(), files.get());
         }
 
+        notificationManager.cancel(SAVING_TRACE_NOTIFICATION);
         stopForeground(Service.STOP_FOREGROUND_REMOVE);
 
         TraceUtils.cleanupOlderFiles();
diff --git a/src_common/com/android/traceur/FileSender.java b/src_common/com/android/traceur/FileSender.java
index 8753b16a..69ab49b1 100644
--- a/src_common/com/android/traceur/FileSender.java
+++ b/src_common/com/android/traceur/FileSender.java
@@ -25,6 +25,7 @@ import android.content.Intent;
 import android.net.Uri;
 import android.os.Build;
 import android.os.SystemProperties;
+import android.util.Log;
 import android.util.Patterns;
 
 import androidx.core.content.FileProvider;
@@ -37,7 +38,7 @@ import java.util.List;
  * Sends bugreport-y files, adapted from fw/base/packages/Shell's BugreportReceiver.
  */
 public class FileSender {
-
+    private static final String TAG = "Traceur";
     private static final String MIME_TYPE = "application/vnd.android.systrace";
 
     public static List<Uri> getUriForFiles(Context context, List<File> files, String authority) {
@@ -59,12 +60,17 @@ public class FileSender {
         intent.addCategory(Intent.CATEGORY_DEFAULT);
         intent.setType(MIME_TYPE);
 
-        intent.putExtra(Intent.EXTRA_SUBJECT, traceUris.get(0).getLastPathSegment());
-        intent.putExtra(Intent.EXTRA_TEXT, description);
-        intent.putExtra(Intent.EXTRA_STREAM, new ArrayList(traceUris));
+        if (!traceUris.isEmpty()) {
+            intent.putExtra(Intent.EXTRA_SUBJECT, traceUris.get(0).getLastPathSegment());
+            intent.putExtra(Intent.EXTRA_STREAM, new ArrayList(traceUris));
 
-        // Explicitly set the clip data; see b/119399115
-        intent.setClipData(buildClipData(traceUris));
+            // Explicitly set the clip data; see b/119399115
+            intent.setClipData(buildClipData(traceUris));
+        } else {
+            Log.e(TAG, "There are no URIs to attach to this send intent. " +
+                    "An error may have occurred while tracing or retrieving trace files.");
+        }
+        intent.putExtra(Intent.EXTRA_TEXT, description);
 
         final Account sendToAccount = findSendToAccount(context);
         if (sendToAccount != null) {
diff --git a/src_common/com/android/traceur/PerfettoUtils.java b/src_common/com/android/traceur/PerfettoUtils.java
index 4124c772..02962c98 100644
--- a/src_common/com/android/traceur/PerfettoUtils.java
+++ b/src_common/com/android/traceur/PerfettoUtils.java
@@ -22,6 +22,7 @@ import android.util.Log;
 import java.io.File;
 import java.nio.file.Files;
 import java.nio.file.Paths;
+import java.util.ArrayList;
 import java.util.Collection;
 import java.util.List;
 import java.util.TreeMap;
@@ -62,7 +63,9 @@ public class PerfettoUtils {
 
     // The total amount of memory allocated to the two target buffers will be divided according to a
     // ratio of (BUFFER_SIZE_RATIO - 1) to 1.
-    private static final int BUFFER_SIZE_RATIO = 32;
+    private static final int BUFFER_SIZE_RATIO = 8;
+
+    private static final int SYSTEM_INFO_BUFFER_SIZE_KB = 512;
 
     // atrace trace categories that will result in added data sources in the Perfetto config.
     private static final String CAMERA_TAG = "camera";
@@ -72,12 +75,17 @@ public class PerfettoUtils {
     private static final String POWER_TAG = "power";
     private static final String SCHED_TAG = "sched";
     private static final String WEBVIEW_TAG = "webview";
+    private static final String WINDOW_MANAGER_TAG = "wm";
 
     // Custom trace categories.
     private static final String SYS_STATS_TAG = "sys_stats";
     private static final String LOG_TAG = "logs";
     private static final String CPU_TAG = "cpu";
-    public static final String WINDOW_MANAGER_TAG = "wm";
+
+    // Statsd atoms. Values should be aligned with frameworks/proto_logging/stats/atoms.proto.
+    private static final int DESKTOP_MODE_UI_CHANGED = 818;
+    private static final int DESKTOP_MODE_SESSION_TASK_UPDATE = 819;
+    private static final int DESKTOP_MODE_TASK_SIZE_UPDATED = 935;
 
     public String getName() {
         return NAME;
@@ -118,8 +126,9 @@ public class PerfettoUtils {
         // So we use this to ensure that we reserve the correctly-sized buffer.
         int numCpus = Runtime.getRuntime().availableProcessors();
 
-        // Allots 1 / BUFFER_SIZE_RATIO to the small buffer and the remainder to the large buffer.
-        int totalBufferSizeKb = numCpus * bufferSizeKb;
+        // Allots 1 / BUFFER_SIZE_RATIO to the small buffer and the remainder to the large buffer,
+        // (less the size of the buffer reserved for unchanging system information).
+        int totalBufferSizeKb = numCpus * bufferSizeKb - SYSTEM_INFO_BUFFER_SIZE_KB;
         int targetBuffer1Kb = totalBufferSizeKb / BUFFER_SIZE_RATIO;
         int targetBuffer0Kb = totalBufferSizeKb - targetBuffer1Kb;
 
@@ -130,15 +139,30 @@ public class PerfettoUtils {
         // This is target_buffer: 1, which is used for additional data sources.
         appendTraceBuffer(config, targetBuffer1Kb);
 
+        // This is target_buffer: 2, used for unchanging system information like the packages
+        // list.
+        appendTraceBuffer(config, SYSTEM_INFO_BUFFER_SIZE_KB);
+
         appendFtraceConfig(config, tags, apps);
 
         appendSystemPropertyConfig(config, tags);
+        appendPackagesListConfig(config);
+        appendStatsdConfig(config, tags);
         appendProcStatsConfig(config, tags, /* targetBuffer = */ 1);
         appendAdditionalDataSources(config, tags, winscope, longTrace, /* targetBuffer = */ 1);
 
         return startPerfettoWithTextConfig(config.toString());
     }
 
+    private void appendPackagesListConfig(StringBuilder config) {
+            config.append("data_sources: {\n")
+                .append("  config { \n")
+                .append("    name: \"android.packages_list\"\n")
+                .append("    target_buffer: 2\n")
+                .append("  }\n")
+                .append("}\n");
+    }
+
     private void appendSystemPropertyConfig(StringBuilder config, Collection<String> tags) {
         if (tags.contains(WINDOW_MANAGER_TAG)) {
             config.append("data_sources: {\n")
@@ -153,6 +177,32 @@ public class PerfettoUtils {
         }
     }
 
+    private void appendStatsdConfig(StringBuilder config, Collection<String> tags) {
+        List<Integer> rawPushAtomIds = new ArrayList<>();
+        if (tags.contains(WINDOW_MANAGER_TAG)) {
+            rawPushAtomIds.add(DESKTOP_MODE_UI_CHANGED);
+            rawPushAtomIds.add(DESKTOP_MODE_SESSION_TASK_UPDATE);
+            rawPushAtomIds.add(DESKTOP_MODE_TASK_SIZE_UPDATED);
+        }
+
+        if (rawPushAtomIds.size() > 0) {
+            config.append("data_sources: {\n")
+                    .append("  config { \n")
+                    .append("    name: \"android.statsd\"\n")
+                    .append("    target_buffer: 1\n")
+                    .append("    statsd_tracing_config {\n");
+
+            for (int id : rawPushAtomIds) {
+                config.append("      raw_push_atom_id: " + id + "\n");
+            }
+
+            config.append("    }\n")
+                    .append("  }\n")
+                    .append("}\n");
+        }
+    }
+
+
     public boolean stackSampleStart(boolean attachToBugreport) {
         if (isTracingOn()) {
             Log.e(TAG, "Attemping to start stack sampling but perfetto is already active");
@@ -620,15 +670,7 @@ public class PerfettoUtils {
                 .append("    }\n")
                 .append("  }\n")
                 .append("}\n");
-            // Include the packages_list data source so that we can map UIDs
-            // from Network Tracing to the corresponding package name.
-            config.append("data_sources: {\n")
-                .append("  config { \n")
-                .append("    name: \"android.packages_list\"\n")
-                .append("    target_buffer: " + targetBuffer + "\n")
-                .append("  }\n")
-                .append("}\n");
-        }
+       }
 
         // Also enable Chrome events when the WebView tag is enabled.
         if (tags.contains(WEBVIEW_TAG)) {
diff --git a/src_common/com/android/traceur/TraceConfig.java b/src_common/com/android/traceur/TraceConfig.java
index c7534866..d00d6247 100644
--- a/src_common/com/android/traceur/TraceConfig.java
+++ b/src_common/com/android/traceur/TraceConfig.java
@@ -119,7 +119,7 @@ public class TraceConfig implements Parcelable {
         parcel.writeStringArray(tags.toArray(String[]::new));
     }
 
-    public static Parcelable.Creator<TraceConfig> CREATOR = new Creator<>() {
+    public static final Parcelable.Creator<TraceConfig> CREATOR = new Creator<>() {
         @Override
         public TraceConfig createFromParcel(Parcel parcel) {
             return new TraceConfig(
```

