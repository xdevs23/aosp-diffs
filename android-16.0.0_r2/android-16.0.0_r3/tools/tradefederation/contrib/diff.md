```diff
diff --git a/src/com/android/tradefed/targetprep/ExampleTargetPreparer.java b/src/com/android/tradefed/targetprep/ExampleTargetPreparer.java
index cd6785a..70e02f0 100644
--- a/src/com/android/tradefed/targetprep/ExampleTargetPreparer.java
+++ b/src/com/android/tradefed/targetprep/ExampleTargetPreparer.java
@@ -15,8 +15,8 @@
  */
 package com.android.tradefed.targetprep;
 
-import com.android.ddmlib.Log;
 import com.android.tradefed.invoker.TestInformation;
+import com.android.tradefed.log.Log;
 
 /**
  * Placeholder empty implementation of a {@link com.android.tradefed.targetprep.ITargetPreparer}.
diff --git a/src/com/android/tradefed/targetprep/PerfettoHeapConfigTargetPreparer.java b/src/com/android/tradefed/targetprep/PerfettoHeapConfigTargetPreparer.java
index bef6b33..87d6bc1 100644
--- a/src/com/android/tradefed/targetprep/PerfettoHeapConfigTargetPreparer.java
+++ b/src/com/android/tradefed/targetprep/PerfettoHeapConfigTargetPreparer.java
@@ -33,7 +33,6 @@ import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.RunUtil;
 
 import java.io.File;
-import java.io.FileWriter;
 import java.io.IOException;
 import java.io.OutputStream;
 import java.util.ArrayList;
@@ -108,8 +107,8 @@ public class PerfettoHeapConfigTargetPreparer extends BaseTargetPreparer {
             for (String pushFile : mPushFiles.keySet()) {
                 // Get trace config file from artifacts
                 File srcFile = getFileFromTestArtifacts(testInfo.getBuildInfo(), pushFile);
-                updateTraceConfig(srcFile);
-                pushFile(testInfo.getDevice(), srcFile, mPushFiles.get(pushFile));
+                final String patchedFileContents = updateTraceConfig(srcFile);
+                pushString(testInfo.getDevice(), patchedFileContents, mPushFiles.get(pushFile));
             }
         } else {
             CLog.i(
@@ -122,7 +121,7 @@ public class PerfettoHeapConfigTargetPreparer extends BaseTargetPreparer {
      * Using heap_profile tool to update perfetto trace config. heap_profile cmdline doc:
      * https://perfetto.dev/docs/reference/heap_profile-cli
      */
-    private void updateTraceConfig(File srcFile) {
+    private String updateTraceConfig(File srcFile) {
         List<String> commandArgsList = new ArrayList<String>();
         commandArgsList.add(mTraceToolFile.getAbsolutePath());
         commandArgsList.add("--print-config");
@@ -159,26 +158,35 @@ public class PerfettoHeapConfigTargetPreparer extends BaseTargetPreparer {
         CLog.i(String.format("Command result status = %s", result.getStatus()));
         if (CommandStatus.SUCCESS.equals(result.getStatus())) {
             CLog.i(String.format("Command result = %s", result.getStdout()));
-            String modifiedResult = extractDataSources(result.getStdout());
-            CLog.i(String.format("Modified result = %s", modifiedResult));
+            String dataSourcesToAppend = extractDataSources(result.getStdout());
+            CLog.i(String.format("Data sources to append = %s", dataSourcesToAppend));
+
+            String originalContent;
             try {
-                FileWriter fileWriter = new FileWriter(srcFile, true);
-                storeToFile(srcFile.getName(), modifiedResult, fileWriter);
-                fileWriter.close();
+                originalContent = FileUtil.readStringFromFile(srcFile);
             } catch (IOException e) {
-                CLog.e(String.format("Unable to update file %s ", srcFile.getName()), e);
+                CLog.e(
+                        String.format(
+                                "Unable to read original config file %s",
+                                srcFile.getAbsolutePath()),
+                        e);
+                return null;
             }
+
+            return originalContent + "\n" + dataSourcesToAppend;
         } else {
             CLog.e("Fail to run heap_profile command");
         }
+
+        return null;
     }
 
-    private void pushFile(ITestDevice device, File src, String remotePath)
+    private void pushString(ITestDevice device, String src, String remotePath)
             throws DeviceNotAvailableException {
-        if (!device.pushFile(src, remotePath)) {
+        if (!device.pushString(src, remotePath)) {
             CLog.e(
                     String.format(
-                            "Failed to push local '%s' to remote '%s'", src.getPath(), remotePath));
+                            "Failed to push a string to remote '%s'", remotePath));
         }
     }
 
@@ -217,18 +225,6 @@ public class PerfettoHeapConfigTargetPreparer extends BaseTargetPreparer {
         return result.toString();
     }
 
-    private void storeToFile(String targetFileName, String content, FileWriter target)
-            throws RuntimeException {
-        try {
-            target.write('\n');
-            target.write(content);
-            target.write('\n');
-        } catch (IOException e) {
-            throw new RuntimeException(
-                    String.format("Unable to write file %s ", targetFileName), e);
-        }
-    }
-
     /**
      * Retrieve the file from the test artifacts or module artifacts and cache it in a map for the
      * subsequent calls.
```

