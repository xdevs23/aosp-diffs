```diff
diff --git a/Android.bp b/Android.bp
index 6d70de8..a829a56 100644
--- a/Android.bp
+++ b/Android.bp
@@ -25,11 +25,11 @@ java_library_host {
         "//external/robolectric",
     ],
     libs: [
-        "Robolectric_nativeruntime_upstream",
-        "Robolectric_robolectric_upstream",
-        "Robolectric_sandbox_upstream",
-        "Robolectric_shadows_versioning_upstream",
-        "Robolectric_utils_reflector_upstream",
+        "Robolectric_nativeruntime",
+        "Robolectric_robolectric",
+        "Robolectric_sandbox",
+        "Robolectric_shadows_versioning",
+        "Robolectric_utils_reflector",
         "robolectric-host-android_all",
     ],
     plugins: ["auto_service_plugin"],
@@ -44,8 +44,8 @@ java_test_host {
     srcs: ["src/test/java/**/*.java"],
     static_libs: [
         "Robolectric-aosp-plugins",
-        "Robolectric_robolectric_upstream",
-        "Robolectric_shadows_versioning_upstream",
+        "Robolectric_robolectric",
+        "Robolectric_shadows_versioning",
         "hamcrest",
         "guava",
         "junit",
diff --git a/clearcut-junit-listener/Android.bp b/clearcut-junit-listener/Android.bp
index fe44e66..9619e5c 100644
--- a/clearcut-junit-listener/Android.bp
+++ b/clearcut-junit-listener/Android.bp
@@ -1,5 +1,8 @@
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_visibility: [
+        "//external/robolectric:__subpackages__",
+    ],
 }
 
 team {
@@ -11,8 +14,8 @@ java_library_host {
     name: "ClearcutJunitListener",
     srcs: ["src/main/java/**/*.java"],
     static_libs: [
-        "asuite_proto_java",
-        "libprotobuf-java-util-full",
+        "asuite_proto_java_lite",
+        "libprotobuf-java-lite",
         "auto_service_annotations",
         "junit",
     ],
@@ -32,6 +35,7 @@ java_test_host {
     static_libs: [
         "ClearcutJunitListener",
         "truth-1.4.0-prebuilt",
+        "guava",
         "jsr305",
     ],
     //test_options: {
diff --git a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutEventHelper.java b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutEventHelper.java
index 1b5881b..20e4361 100644
--- a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutEventHelper.java
+++ b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutEventHelper.java
@@ -43,14 +43,15 @@ public class ClearcutEventHelper {
      * @param userKey The unique id representing the user
      * @param runId The current id for the session.
      * @param userType The type of the user: internal or external.
+     * @param toolName The name of test tool.
      * @param subToolName The name of test suite tool.
      * @return a ByteString representation of the even proto.
      */
     public static ByteString createStartEvent(
-            String userKey, String runId, UserType userType, String subToolName) {
+            String userKey, String runId, UserType userType, String toolName, String subToolName) {
         if (UserType.GOOGLE.equals(userType)) {
             AtestLogEventInternal.Builder builder =
-                    createBaseInternalEventBuilder(userKey, runId, userType, subToolName);
+                    createBaseInternalEventBuilder(userKey, runId, userType, toolName, subToolName);
             AtestLogEventInternal.AtestStartEvent.Builder startEventBuilder =
                     AtestLogEventInternal.AtestStartEvent.newBuilder();
             builder.setAtestStartEvent(startEventBuilder.build());
@@ -58,7 +59,7 @@ public class ClearcutEventHelper {
         }
 
         AtestLogEventExternal.Builder builder =
-                createBaseExternalEventBuilder(userKey, runId, userType, subToolName);
+                createBaseExternalEventBuilder(userKey, runId, userType, toolName, subToolName);
         AtestStartEvent.Builder startBuilder = AtestStartEvent.newBuilder();
         builder.setAtestStartEvent(startBuilder.build());
         return builder.build().toByteString();
@@ -70,6 +71,7 @@ public class ClearcutEventHelper {
      * @param userKey The unique id representing the user
      * @param runId The current id for the session.
      * @param userType The type of the user: internal or external.
+     * @param toolName The name of tool.
      * @param subToolName The name of test suite tool.
      * @param sessionDuration The duration of the complete session.
      * @return a ByteString representation of the even proto.
@@ -78,11 +80,12 @@ public class ClearcutEventHelper {
             String userKey,
             String runId,
             UserType userType,
+            String toolName,
             String subToolName,
             Duration sessionDuration) {
         if (UserType.GOOGLE.equals(userType)) {
             AtestLogEventInternal.Builder builder =
-                    createBaseInternalEventBuilder(userKey, runId, userType, subToolName);
+                    createBaseInternalEventBuilder(userKey, runId, userType, toolName, subToolName);
             AtestLogEventInternal.AtestExitEvent.Builder exitEventBuilder =
                     AtestLogEventInternal.AtestExitEvent.newBuilder();
             Common.Duration duration =
@@ -96,7 +99,7 @@ public class ClearcutEventHelper {
         }
 
         AtestLogEventExternal.Builder builder =
-                createBaseExternalEventBuilder(userKey, runId, userType, subToolName);
+                createBaseExternalEventBuilder(userKey, runId, userType, toolName, subToolName);
         AtestLogEventExternal.AtestExitEvent.Builder startBuilder = AtestExitEvent.newBuilder();
         builder.setAtestExitEvent(startBuilder.build());
         return builder.build().toByteString();
@@ -108,15 +111,16 @@ public class ClearcutEventHelper {
      * @param userKey The unique id representing the user
      * @param runId The current id for the session.
      * @param userType The type of the user: internal or external.
+     * @param toolName The name of the tool.
      * @param subToolName The name of test suite tool.
      * @return a ByteString representation of the even proto.
      */
     public static ByteString createRunStartEvent(
-            String userKey, String runId, UserType userType, String subToolName) {
+            String userKey, String runId, UserType userType, String toolName, String subToolName) {
         if (UserType.GOOGLE.equals(userType)) {
             //This is where individual test results belong.   Weird.
             AtestLogEventInternal.Builder builder =
-                    createBaseInternalEventBuilder(userKey, runId, userType, subToolName);
+                    createBaseInternalEventBuilder(userKey, runId, userType, toolName, subToolName);
             AtestLogEventInternal.RunnerFinishEvent.Builder startRunEventBuilder =
                     AtestLogEventInternal.RunnerFinishEvent.newBuilder();
             //Why aren't we calling? startRunEventBuilder.addTest();
@@ -125,7 +129,7 @@ public class ClearcutEventHelper {
         }
 
         AtestLogEventExternal.Builder builder =
-                createBaseExternalEventBuilder(userKey, runId, userType, subToolName);
+                createBaseExternalEventBuilder(userKey, runId, userType, toolName, subToolName);
         RunnerFinishEvent.Builder startBuilder = RunnerFinishEvent.newBuilder();
         builder.setRunnerFinishEvent(startBuilder.build());
         return builder.build().toByteString();
@@ -148,6 +152,7 @@ public class ClearcutEventHelper {
      * @param userKey The unique id representing the user
      * @param runId The current id for the session.
      * @param userType The type of the user: internal or external.
+     * @param toolName The name of test suite tool.
      * @param subToolName The name of test suite tool.
      * @param testDuration the duration of the test session.
      * @return a ByteString representation of the even proto.
@@ -156,11 +161,12 @@ public class ClearcutEventHelper {
             String userKey,
             String runId,
             UserType userType,
+            String toolName,
             String subToolName,
             Duration testDuration) {
         if (UserType.GOOGLE.equals(userType)) {
             AtestLogEventInternal.Builder builder =
-                    createBaseInternalEventBuilder(userKey, runId, userType, subToolName);
+                    createBaseInternalEventBuilder(userKey, runId, userType, toolName, subToolName);
             AtestLogEventInternal.RunTestsFinishEvent.Builder runTestsFinished =
                     AtestLogEventInternal.RunTestsFinishEvent.newBuilder();
             Common.Duration duration =
@@ -174,28 +180,29 @@ public class ClearcutEventHelper {
         }
 
         AtestLogEventExternal.Builder builder =
-                createBaseExternalEventBuilder(userKey, runId, userType, subToolName);
+                createBaseExternalEventBuilder(userKey, runId, userType, toolName, subToolName);
         RunTestsFinishEvent.Builder startBuilder = RunTestsFinishEvent.newBuilder();
         builder.setRunTestsFinishEvent(startBuilder.build());
         return builder.build().toByteString();
     }
 
     /**
-     * Create the basic event builder with all the common informations.
+     * Create the basic event builder with all the common information.
      *
      * @param userKey The unique id representing the user
      * @param runId The current id for the session.
      * @param userType The type of the user: internal or external.
+     * @param toolName The name of test suite tool.
      * @param subToolName The name of test suite tool.
      * @return a builder for the event.
      */
     private static AtestLogEventExternal.Builder createBaseExternalEventBuilder(
-            String userKey, String runId, UserType userType, String subToolName) {
+            String userKey, String runId, UserType userType, String toolName, String subToolName) {
         AtestLogEventExternal.Builder builder = AtestLogEventExternal.newBuilder();
         builder.setUserKey(userKey);
         builder.setRunId(runId);
         builder.setUserType(userType);
-        builder.setToolName(TOOL_NAME);
+        builder.setToolName(toolName);
         builder.setSubToolName(subToolName);
         return builder;
     }
@@ -210,12 +217,12 @@ public class ClearcutEventHelper {
      * @return a builder for the event.
      */
     private static AtestLogEventInternal.Builder createBaseInternalEventBuilder(
-            String userKey, String runId, UserType userType, String subToolName) {
+            String userKey, String runId, UserType userType, String toolName, String subToolName) {
         AtestLogEventInternal.Builder builder = AtestLogEventInternal.newBuilder();
         builder.setUserKey(userKey);
         builder.setRunId(runId);
         builder.setUserType(userType);
-        builder.setToolName(TOOL_NAME);
+        builder.setToolName(toolName);
         builder.setSubToolName(subToolName);
         return builder;
     }
diff --git a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutJunitListener.java b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutJunitListener.java
index 963c9ce..81d5347 100644
--- a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutJunitListener.java
+++ b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutJunitListener.java
@@ -15,50 +15,48 @@
  */
 
 package com.google.asuite.clearcut.junit.listener;
-
 import com.google.auto.service.AutoService;
-
-import org.junit.runner.Description;
-import org.junit.runner.Result;
 import org.junit.runner.notification.RunListener;
 
 @AutoService(RunListener.class)
 public class ClearcutJunitListener extends RunListener {
 
-    private Client client;
-    private long startTime = System.nanoTime();
-
-    public ClearcutJunitListener() {
-        System.out.println("In clearcut listener");
-        String context = "junit";
-        if (EnvironmentInformation.isSysUIRoboTest()) { //sysui
-            context = "junit_sysui";
-        } else if (EnvironmentInformation.isGradleTest()) { //intellij
-            context = "junit_gradle";
-        } else if (EnvironmentInformation.isRoboTest()) { //robolectric
-            context += "_robolectric";
+    /**
+     * Static since the listener gets rebuilt once per class.
+     */
+    private static final Client client;
+
+    static {
+        String tool = "junit";
+        String subtool = "junit";
+        boolean disable = true;
+        try {
+
+            if (EnvironmentInformation.isSysUIRoboTest()) { //sysui
+                subtool += "_sysui";
+            } else if (EnvironmentInformation.isGradleTest()) { //intellij
+                subtool += "_gradle";
+            }
+            if (EnvironmentInformation.isDebugging()) { //robolectric
+                subtool += "_debug";
+            }
+            if (EnvironmentInformation.isRoboTest()) { //robolectric
+                subtool += "_robo";
+            }
+            if ((EnvironmentInformation.isGoogleDomain() ||
+                    EnvironmentInformation
+                            .getGitUserIfGoogleEmail(EnvironmentInformation.getGitEmail())
+                            .isPresent())) {
+                disable = false;
+            }
+        } catch (Throwable t) {
+            System.out.println("Error configuring clearcut listener:");
+            t.printStackTrace();
+        }
+        client = new Client(tool, subtool);
+        if (disable) {
+            client.disable();
         }
-        client = new Client(context);
-    }
-
-
-    @Override
-    public void testRunStarted(Description description) throws Exception {
         client.notifyTradefedStartEvent();
     }
-
-    @Override
-    public void testRunFinished(Result result) throws Exception {
-        client.notifyTradefedFinishedEvent();
-    }
-
-    @Override
-    public void testStarted(Description description) throws Exception {
-        client.notifyTradefedInvocationStartEvent();
-    }
-
-    public void testFinished(Description description) throws Exception {
-        client.notifyTestRunFinished(startTime);
-        client.stop();
-    }
 }
diff --git a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/Client.java b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/Client.java
index b4e1b8a..21bddb9 100644
--- a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/Client.java
+++ b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/Client.java
@@ -21,40 +21,29 @@ import com.android.asuite.clearcut.Clientanalytics.LogRequest;
 import com.android.asuite.clearcut.Clientanalytics.LogResponse;
 import com.android.asuite.clearcut.Common.UserType;
 
-import com.google.common.base.Strings;
-import com.google.protobuf.util.JsonFormat;
-
 import java.io.BufferedReader;
+import java.io.ByteArrayOutputStream;
 import java.io.Closeable;
 import java.io.File;
 import java.io.IOException;
 import java.io.InputStream;
 import java.io.InputStreamReader;
 import java.io.OutputStream;
-import java.io.OutputStreamWriter;
 import java.net.HttpURLConnection;
-import java.net.InetAddress;
 import java.net.URI;
 import java.net.URISyntaxException;
 import java.net.URL;
-import java.net.UnknownHostException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
-import java.nio.file.OpenOption;
 import java.nio.file.StandardOpenOption;
 import java.time.Duration;
-import java.util.ArrayList;
-import java.util.Arrays;
-import java.util.List;
+import java.util.Objects;
 import java.util.Optional;
 import java.util.UUID;
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.ExecutionException;
-import java.util.concurrent.Executors;
-import java.util.concurrent.ScheduledThreadPoolExecutor;
-import java.util.concurrent.ThreadFactory;
-import java.util.concurrent.TimeUnit;
 import java.util.stream.Collectors;
+import java.util.zip.GZIPOutputStream;
 
 /** Client that allows reporting usage metrics to clearcut. */
 public class Client {
@@ -66,56 +55,50 @@ public class Client {
     private static final int CLIENT_TYPE = 1;
     private static final int INTERNAL_LOG_SOURCE = 971;
     private static final int EXTERNAL_LOG_SOURCE = 934;
-
-    private static final long SCHEDULER_INITIAL_DELAY_MILLISECONDS = 1000;
-    private static final long SCHEDULER_PERDIOC_MILLISECONDS = 250;
-
-    private static final String GOOGLE_EMAIL = "@google.com";
-    private static final String GOOGLE_HOSTNAME = ".google.com";
-
     private File mCachedUuidFile = new File(System.getProperty("user.home"), ".clearcut_listener");
     private String mRunId;
     private long mSessionStartTime = 0L;
-
     private final int mLogSource;
     private final String mUrl;
     private final UserType mUserType;
+    private final String mToolName;
     private final String mSubToolName;
+    private final String mUser;
+    private final boolean mIsGoogle;
 
-    // Consider synchronized list
-    private final List<LogRequest> mExternalEventQueue;
-    // The pool executor to actually post the metrics
-    private ScheduledThreadPoolExecutor mExecutor;
     // Whether the clearcut client should be a noop
     private boolean mDisabled = false;
 
-    public Client(String subToolName) {
-        this(null, subToolName);
+    public Client(String toolName, String subToolName) {
+        this(null, toolName, subToolName);
         Runtime.getRuntime().addShutdownHook(new Thread(Client.this::stop));
     }
 
     /**
      * Create Client with customized posting URL and forcing whether it's internal or external user.
      */
-    protected Client(String url, String subToolName) {
+    protected Client(String url, String toolName, String subToolName) {
         mDisabled = isClearcutDisabled();
+        Optional<String> email = EnvironmentInformation.getGitEmail();
+        Optional<String> googleUser = EnvironmentInformation.getGitUserIfGoogleEmail(email);
+        mIsGoogle = EnvironmentInformation.isGoogleDomain() ||
+                googleUser.isPresent();
+        Optional<String> username = EnvironmentInformation.executeCommand("whoami");
 
         // We still have to set the 'final' variable so go through the assignments before returning
         if (!mDisabled && isGoogleUser()) {
             mLogSource = INTERNAL_LOG_SOURCE;
             mUserType = UserType.GOOGLE;
+            mUser = googleUser.orElse(username.orElse(""));
         } else {
             mLogSource = EXTERNAL_LOG_SOURCE;
             mUserType = UserType.EXTERNAL;
+            mUser = UUID5.uuidOf(UUID5.NAMESPACE_DNS, email.orElse(username.orElse(""))).toString();
         }
-        if (url == null) {
-            mUrl = CLEARCUT_PROD_URL;
-        } else {
-            mUrl = url;
-        }
+        mUrl = Objects.requireNonNullElse(url, CLEARCUT_PROD_URL);
+        mToolName = toolName;
         mRunId = UUID.randomUUID().toString();
-        mExternalEventQueue = new ArrayList<>();
-        if (Strings.isNullOrEmpty(subToolName) && System.getenv(CLEARCUT_SUB_TOOL_NAME) != null) {
+        if (subToolName != null && subToolName.isEmpty() && System.getenv(CLEARCUT_SUB_TOOL_NAME) != null) {
             mSubToolName = System.getenv(CLEARCUT_SUB_TOOL_NAME);
         } else {
             mSubToolName = subToolName;
@@ -127,32 +110,14 @@ public class Client {
 
         // Print the notice
         System.out.println(NoticeMessageUtil.getNoticeMessage(mUserType));
+    }
+
+    protected void disable(){
+        mDisabled = true;
+    }
 
-        // Executor to actually send the events.
-        mExecutor =
-                new ScheduledThreadPoolExecutor(
-                        1,
-                        new ThreadFactory() {
-                            @Override
-                            public Thread newThread(Runnable r) {
-                                Thread t = Executors.defaultThreadFactory().newThread(r);
-                                t.setDaemon(true);
-                                t.setName("clearcut-client-thread");
-                                return t;
-                            }
-                        });
-        Runnable command =
-                new Runnable() {
-                    @Override
-                    public void run() {
-                        flushEvents();
-                    }
-                };
-        mExecutor.scheduleAtFixedRate(
-                command,
-                SCHEDULER_INITIAL_DELAY_MILLISECONDS,
-                SCHEDULER_PERDIOC_MILLISECONDS,
-                TimeUnit.MILLISECONDS);
+    boolean isGoogleUser() {
+        return mIsGoogle;
     }
 
     /** Send the first event to notify that Tradefed was started. */
@@ -162,117 +127,45 @@ public class Client {
         }
         mSessionStartTime = System.nanoTime();
         long eventTimeMs = System.currentTimeMillis();
-        CompletableFuture.supplyAsync(() -> createStartEvent(eventTimeMs));
+        CompletableFuture.supplyAsync(() -> createAndSendStartEvent(eventTimeMs));
     }
 
-    private boolean createStartEvent(long eventTimeMs) {
-        LogRequest.Builder request = createBaseLogRequest();
+    private boolean createAndSendStartEvent(long eventTimeMs) {
         LogEvent.Builder logEvent = LogEvent.newBuilder();
         logEvent.setEventTimeMs(eventTimeMs);
         logEvent.setSourceExtension(
                 ClearcutEventHelper.createStartEvent(
-                        getGroupingKey(), mRunId, mUserType, mSubToolName));
+                        mUser, mRunId, mUserType, mToolName, mSubToolName));
+        LogRequest.Builder request = createBaseLogRequest();
         request.addLogEvent(logEvent);
-        queueEvent(request.build());
+        sendEvent(request.build());
         return true;
     }
 
-    /** Send the last event to notify that Tradefed is done. */
     public void notifyTradefedFinishedEvent() {
         if (mDisabled) {
             return;
         }
-        Duration duration = java.time.Duration.ofNanos(System.nanoTime() - mSessionStartTime);
-        LogRequest.Builder request = createBaseLogRequest();
-        LogEvent.Builder logEvent = LogEvent.newBuilder();
-        logEvent.setEventTimeMs(System.currentTimeMillis());
-        logEvent.setSourceExtension(
-                ClearcutEventHelper.createFinishedEvent(
-                        getGroupingKey(), mRunId, mUserType, mSubToolName, duration));
-        request.addLogEvent(logEvent);
-        queueEvent(request.build());
+        CompletableFuture.supplyAsync(() -> createAndSendFinishedEvent());
     }
 
-    /** Send the event to notify that a Tradefed invocation was started. */
-    public void notifyTradefedInvocationStartEvent() {
-        if (mDisabled) {
-            return;
-        }
-        LogRequest.Builder request = createBaseLogRequest();
+    /** Send the last event to notify that Tradefed is done. */
+    public boolean createAndSendFinishedEvent() {
+        Duration duration = java.time.Duration.ofNanos(System.nanoTime() - mSessionStartTime);
         LogEvent.Builder logEvent = LogEvent.newBuilder();
         logEvent.setEventTimeMs(System.currentTimeMillis());
         logEvent.setSourceExtension(
-                ClearcutEventHelper.createRunStartEvent(
-                        getGroupingKey(), mRunId, mUserType, mSubToolName));
-        request.addLogEvent(logEvent);
-        queueEvent(request.build());
-    }
-
-    /** Send the event to notify that a test run finished. */
-    public void notifyTestRunFinished(long startTimeNano) {
-        if (mDisabled) {
-            return;
-        }
-        Duration duration = java.time.Duration.ofNanos(System.nanoTime() - startTimeNano);
+                ClearcutEventHelper.createFinishedEvent(
+                        mUser, mRunId, mUserType, mToolName, mSubToolName, duration));
         LogRequest.Builder request = createBaseLogRequest();
-        LogEvent.Builder logEvent = LogEvent.newBuilder();
-        logEvent.setEventTimeMs(System.currentTimeMillis());
-        logEvent.setSourceExtension(
-                ClearcutEventHelper.creatRunTestFinished(
-                        getGroupingKey(), mRunId, mUserType, mSubToolName, duration));
         request.addLogEvent(logEvent);
-        queueEvent(request.build());
+        sendEvent(request.build());
+        return true;
     }
 
     /** Stop the periodic sending of clearcut events */
     public void stop() {
-        if (mExecutor != null) {
-            mExecutor.setRemoveOnCancelPolicy(true);
-            mExecutor.shutdown();
-            mExecutor = null;
-        }
-        // Send all remaining events
-        flushEvents();
-    }
-
-    /** Add an event to the queue of events that needs to be send. */
-    public void queueEvent(LogRequest event) {
-        synchronized (mExternalEventQueue) {
-            mExternalEventQueue.add(event);
-        }
-    }
-
-    /** Returns the current queue size. */
-    public final int getQueueSize() {
-        synchronized (mExternalEventQueue) {
-            return mExternalEventQueue.size();
-        }
-    }
-
-    /** Allows to override the default cached uuid file. */
-    public void setCachedUuidFile(File uuidFile) {
-        mCachedUuidFile = uuidFile;
-    }
-
-    /** Get a new or the cached uuid for the user. */
-    String getGroupingKey() {
-        String uuid = null;
-        if (mCachedUuidFile.exists()) {
-            try {
-                uuid = readFromFile(mCachedUuidFile);
-            } catch (IOException e) {
-                logError(e);
-            }
-        }
-        if (uuid == null || uuid.isEmpty()) {
-            uuid = UUID.randomUUID().toString();
-            try {
-                writeToFile(uuid, mCachedUuidFile);
-            } catch (IOException e) {
-                logError(e);
-            }
-        }
-        return uuid;
+        notifyTradefedFinishedEvent();
     }
 
     /** Returns True if clearcut is disabled, False otherwise. */
@@ -280,26 +173,6 @@ public class Client {
         return "1".equals(System.getenv(DISABLE_CLEARCUT_KEY));
     }
 
-    /** Returns True if the user is a Googler, False otherwise. */
-    boolean isGoogleUser() {
-        try {
-            String hostname = InetAddress.getLocalHost().getHostName();
-            if (hostname.contains(GOOGLE_HOSTNAME)) {
-                return true;
-            }
-        } catch (UnknownHostException e) {
-            // Ignore
-        }
-        Optional<String> result = executCommand("git", "config", "--get", "user.email");
-        if (result.isPresent()) {
-            String stdout = result.get();
-            if (stdout != null && stdout.trim().endsWith(GOOGLE_EMAIL)) {
-                return true;
-            }
-        }
-        return false;
-    }
-
     private LogRequest.Builder createBaseLogRequest() {
         LogRequest.Builder request = LogRequest.newBuilder();
         request.setLogSource(mLogSource);
@@ -307,24 +180,12 @@ public class Client {
         return request;
     }
 
-    private void flushEvents() {
-        List<LogRequest> copy = new ArrayList<>();
-        synchronized (mExternalEventQueue) {
-            copy.addAll(mExternalEventQueue);
-            mExternalEventQueue.clear();
-        }
-        List<CompletableFuture<Boolean>> futures = new ArrayList<>();
-        while (!copy.isEmpty()) {
-            LogRequest event = copy.remove(0);
-            futures.add(CompletableFuture.supplyAsync(() -> sendToClearcut(event)));
-        }
-
-        for (CompletableFuture<Boolean> future : futures) {
-            try {
-                future.get();
-            } catch (InterruptedException | ExecutionException e) {
-                logError(e);
-            }
+    private void sendEvent(LogRequest request) {
+        CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> sendToClearcut(request));
+        try {
+            future.get();
+        } catch (InterruptedException | ExecutionException e) {
+            logError(e);
         }
     }
 
@@ -333,15 +194,13 @@ public class Client {
         InputStream inputStream = null;
         InputStream errorStream = null;
         OutputStream outputStream = null;
-        OutputStreamWriter outputStreamWriter = null;
         try {
-            HttpURLConnection connection = createConnection(new URI(mUrl).toURL(), "POST", "text");
+            HttpURLConnection connection = createConnection(new URI(mUrl).toURL(), "POST", null);
+            connection.setRequestProperty("Content-Encoding", "gzip");
+            connection.setRequestProperty("Content-Type", "application/x-gzip");
             outputStream = connection.getOutputStream();
-            outputStreamWriter = new OutputStreamWriter(outputStream);
-
-            String jsonObject = JsonFormat.printer().preservingProtoFieldNames().print(event);
-            outputStreamWriter.write(jsonObject.toString());
-            outputStreamWriter.flush();
+            outputStream.write(gzipCompress(event.toByteArray()));
+            outputStream.flush();
 
             inputStream = connection.getInputStream();
             LogResponse response = LogResponse.parseFrom(inputStream);
@@ -355,13 +214,13 @@ public class Client {
             logError(e);
         } catch (NoSuchMethodError e) {
             if (e.getMessage().contains("com.google.protobuf.Descriptors$Descriptor com.google.protobuf.Any.getDescriptor()")) {
-                StringBuilder message = new StringBuilder();
-                message.append("In order for the ClearcutListener to operate it must use protobuf-full to be able to convert messages to json.\n");
-                message.append("Android typically uses protobuf-lite.");
-                message.append("If you're seeing this in a gradle build, adding `testImplementation(project(\":RobolectricLib\"))` to the start of ");
-                message.append("your dependency section should be sufficient, if not (due to how gradle calculates deps), add this dep: ");
-                message.append("`testImplementation(libs.protobuf.java)` to the top of your dependencies");
-                throw new RuntimeException(message.toString(), e);
+                String message =
+                        "In order for the ClearcutListener to operate it must use protobuf-full to be able to convert messages to json.\n"
+                                + "Android typically uses protobuf-lite."
+                                + "If you're seeing this in a gradle build, adding `testImplementation(project(\":RobolectricLib\"))` to the start of "
+                                + "your dependency section should be sufficient, if not (due to how gradle calculates deps), add this dep: "
+                                + "`testImplementation(libs.protobuf.java)` to the top of your dependencies";
+                throw new RuntimeException(message, e);
             } else {
                 logError(e);
                 throw e;
@@ -372,7 +231,6 @@ public class Client {
         } finally {
             closeQuietly(outputStream);
             closeQuietly(inputStream);
-            closeQuietly(outputStreamWriter);
             closeQuietly(errorStream);
         }
         return true;
@@ -407,30 +265,6 @@ public class Client {
         }
     }
 
-    protected static Optional<String> executCommand(String... command) {
-        try {
-            ProcessBuilder pb = new ProcessBuilder(command);
-            Process process = pb.start();
-            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
-            String line;
-            StringBuilder output = new StringBuilder();
-            while ((line = reader.readLine()) != null) {
-                output.append(line).append("\n");
-            }
-            if (process.waitFor(60, TimeUnit.SECONDS)) {
-                int exitCode = process.exitValue();
-                if (exitCode == 0) {
-                    return Optional.of(output.toString());
-                }
-            }
-        } catch (IOException | InterruptedException e) {
-            System.out.println(Client.class.getName() + " could not execute command:" +
-                    Arrays.stream(command).collect(Collectors.joining(" ")));
-            e.printStackTrace();
-        }
-        return Optional.empty();
-    }
-
     private static HttpURLConnection createConnection(URL url, String method, String contentType)
             throws IOException {
         HttpURLConnection connection = (HttpURLConnection) url.openConnection();
@@ -447,4 +281,12 @@ public class Client {
 
         return connection;
     }
+
+    private static byte[] gzipCompress(byte[] data) throws IOException {
+        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
+        try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(outputStream)) {
+            gzipOutputStream.write(data);
+        }
+        return outputStream.toByteArray();
+    }
 }
diff --git a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformation.java b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformation.java
index a99b403..f89df95 100644
--- a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformation.java
+++ b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformation.java
@@ -16,11 +16,31 @@
 
 package com.google.asuite.clearcut.junit.listener;
 
+import java.io.BufferedReader;
+import java.io.IOException;
+import java.io.InputStreamReader;
+import java.net.InetAddress;
+import java.net.UnknownHostException;
+import java.util.Arrays;
+import java.util.List;
+import java.util.Optional;
+import java.util.UUID;
+import java.util.concurrent.TimeUnit;
+
 public class EnvironmentInformation {
 
+    // LINT.IfChange
+    private static final List<String> GOOGLE_HOSTNAMES = Arrays.asList(".google.com", "c.googlers.com");
+    // LINT.ThenChange(/tools/asuite/atest/constants_default.py)
     private static String ROBOLECTRIC_SYSUI_EXTENSION_CLASS = "com.google.android.sysui.ToTSdkProvider";
     private static String GRADLE = "worker.org.gradle.process.internal.worker.GradleWorkerMain";
     private static String ROBOLECTRIC_CLASS = "org.robolectric.Robolectric";
+    private static final String GOOGLE_EMAIL = "@google.com";
+
+    static {
+        System.out.println("ENVIRONMENT:");
+        System.getenv().forEach( (k,v) -> System.out.println(k + " : "+v));
+    }
 
     private static boolean hasClassInLoader(String className) {
         try {
@@ -45,8 +65,65 @@ public class EnvironmentInformation {
     }
 
     public static boolean isDebugging() {
-        return java.lang.management.ManagementFactory.getRuntimeMXBean().
-                getInputArguments().toString().contains("-agentlib:jdwp");
+        try {
+            return java.lang.management.ManagementFactory.getRuntimeMXBean().
+                    getInputArguments().toString().contains("-agentlib:jdwp");
+        } catch (Throwable t) {
+            return false;
+        }
     }
 
+
+    public static Optional<String> getGitEmail() {
+        return executeCommand("git", "config", "--get", "user.email");
+    }
+
+    /**
+     * @return Optional of git username, if email and ends in @google.com
+     */
+    public static Optional<String> getGitUserIfGoogleEmail(Optional<String> email) {
+        if (email.isPresent()) {
+            String emailStr = email.get();
+            if (emailStr.trim().endsWith(GOOGLE_EMAIL)) {
+                return Optional.of(emailStr.trim().replace(GOOGLE_EMAIL, ""));
+            }
+        }
+        return Optional.empty();
+    }
+
+    static Optional<String> executeCommand(String... command) {
+        try {
+            ProcessBuilder pb = new ProcessBuilder(command);
+            Process process = pb.start();
+            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
+            String line;
+            StringBuilder output = new StringBuilder();
+            while ((line = reader.readLine()) != null) {
+                output.append(line).append("\n");
+            }
+            if (process.waitFor(60, TimeUnit.SECONDS)) {
+                int exitCode = process.exitValue();
+                if (exitCode == 0) {
+                    return Optional.of(output.toString());
+                }
+            }
+        } catch (IOException | InterruptedException e) {
+            System.out.println(Client.class.getName() + " could not execute command:" +
+                    String.join(" ", command));
+            e.printStackTrace();
+        }
+        return Optional.empty();
+    }
+
+    public static boolean isGoogleDomain() {
+        try {
+            String hostname = InetAddress.getLocalHost().getHostName();
+            if (GOOGLE_HOSTNAMES.stream().anyMatch(hostname::endsWith)) {
+                return true;
+            }
+        } catch (UnknownHostException e) {
+            System.err.println("Could not determine if google host: " + e.getMessage());
+        }
+        return false;
+    }
 }
diff --git a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/UUID5.java b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/UUID5.java
new file mode 100644
index 0000000..e8dc5ec
--- /dev/null
+++ b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/UUID5.java
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
+package com.google.asuite.clearcut.junit.listener;
+import java.nio.charset.Charset;
+import java.security.MessageDigest;
+import java.security.NoSuchAlgorithmException;
+import java.util.Objects;
+import java.util.UUID;
+
+public class UUID5 {
+    private static final Charset UTF8 = Charset.forName("UTF-8");
+    public static final UUID NAMESPACE_DNS = UUID.fromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8");
+    public static final UUID NAMESPACE_URL = UUID.fromString("6ba7b811-9dad-11d1-80b4-00c04fd430c8");
+    public static final UUID NAMESPACE_OID = UUID.fromString("6ba7b812-9dad-11d1-80b4-00c04fd430c8");
+    public static final UUID NAMESPACE_X500 = UUID.fromString("6ba7b814-9dad-11d1-80b4-00c04fd430c8");
+
+    public static UUID uuidOf(UUID namespace, String name) {
+        return uuidOf(namespace, Objects.requireNonNull(name, "name == null").getBytes(UTF8));
+    }
+
+    public static UUID uuidOf(UUID namespace, byte[] name) {
+        MessageDigest md;
+        try {
+            md = MessageDigest.getInstance("SHA-1");
+        } catch (NoSuchAlgorithmException nsae) {
+            throw new InternalError("SHA-1 not supported");
+        }
+        md.update(toBytes(Objects.requireNonNull(namespace, "namespace is null")));
+        md.update(Objects.requireNonNull(name, "name is null"));
+        byte[] sha1Bytes = md.digest();
+        sha1Bytes[6] &= 0x0f;  /* clear version        */
+        sha1Bytes[6] |= 0x50;  /* set to version 5     */
+        sha1Bytes[8] &= 0x3f;  /* clear variant        */
+        sha1Bytes[8] |= 0x80;  /* set to IETF variant  */
+        return fromBytes(sha1Bytes);
+    }
+
+    private static UUID fromBytes(byte[] data) {
+        // Based on the private UUID(bytes[]) constructor
+        long msb = 0;
+        long lsb = 0;
+        assert data.length >= 16;
+        for (int i = 0; i < 8; i++)
+            msb = (msb << 8) | (data[i] & 0xff);
+        for (int i = 8; i < 16; i++)
+            lsb = (lsb << 8) | (data[i] & 0xff);
+        return new UUID(msb, lsb);
+    }
+
+    private static byte[] toBytes(UUID uuid) {
+        // inverted logic of fromBytes()
+        byte[] out = new byte[16];
+        long msb = uuid.getMostSignificantBits();
+        long lsb = uuid.getLeastSignificantBits();
+        for (int i = 0; i < 8; i++)
+            out[i] = (byte) ((msb >> ((7 - i) * 8)) & 0xff);
+        for (int i = 8; i < 16; i++)
+            out[i] = (byte) ((lsb >> ((15 - i) * 8)) & 0xff);
+        return out;
+    }
+}
\ No newline at end of file
diff --git a/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/ClientTest.java b/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/ClientTest.java
index 99143a6..14f0314 100644
--- a/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/ClientTest.java
+++ b/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/ClientTest.java
@@ -47,32 +47,6 @@ public class ClientTest {
         mClient.stop();
     }
 
-    @Test
-    public void testGetGroupingKey() throws Exception {
-        File testFile = File.createTempFile("uuid-test", "");
-        try {
-            mClient.setCachedUuidFile(testFile);
-            String grouping = mClient.getGroupingKey();
-            // Key was created and written to cached file.
-            assertEquals(grouping, Client.readFromFile(testFile));
-        } finally {
-            testFile.delete();
-        }
-    }
-
-    @Test
-    public void testGetGroupingKey_exists() throws Exception {
-        File testFile = File.createTempFile("uuid-test", "");
-        try {
-            Client.writeToFile("test", testFile);
-            mClient.setCachedUuidFile(testFile);
-            String grouping = mClient.getGroupingKey();
-            assertEquals("test", grouping);
-        } finally {
-            testFile.delete();
-        }
-    }
-
     @Test
     public void testDisableClient() {
         Client c =
@@ -91,7 +65,6 @@ public class ClientTest {
             c.notifyTradefedStartEvent();
             c.notifyTradefedStartEvent();
             c.notifyTradefedStartEvent();
-            assertEquals(0, c.getQueueSize());
         } finally {
             c.stop();
         }
diff --git a/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/UUID5Test.java b/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/UUID5Test.java
new file mode 100644
index 0000000..86f0545
--- /dev/null
+++ b/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/UUID5Test.java
@@ -0,0 +1,32 @@
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
+package com.google.asuite.clearcut.junit.listener;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import org.junit.Test;
+
+public class UUID5Test {
+
+    @Test
+    public void testUUID5() {
+        String rexhoffman_google_com_uuid5 = "f543c3fc-651a-57a4-8d4f-f7f0961d2179";
+        assertThat(UUID5
+                .uuidOf(UUID5.NAMESPACE_DNS, "rexhoffman@google.com").toString())
+                .isEqualTo(rexhoffman_google_com_uuid5);
+    }
+}
diff --git a/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java b/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java
index d075d1d..2e8a668 100644
--- a/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java
+++ b/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java
@@ -16,42 +16,20 @@
 
 package org.robolectric.android.plugins;
 
-import static android.os.Build.VERSION_CODES.O;
-
-import static com.google.common.base.StandardSystemProperty.OS_ARCH;
-import static com.google.common.base.StandardSystemProperty.OS_NAME;
-
-import static org.robolectric.util.reflector.Reflector.reflector;
-
-import android.graphics.Typeface;
-import android.os.Build;
-
 import com.google.auto.service.AutoService;
-import com.google.common.collect.ImmutableList;
 import com.google.common.io.Files;
 import com.google.common.io.Resources;
 
-import org.robolectric.internal.bytecode.ShadowConstants;
 import org.robolectric.nativeruntime.DefaultNativeRuntimeLoader;
 import org.robolectric.pluginapi.NativeRuntimeLoader;
-import org.robolectric.shadow.api.Shadow;
-import org.robolectric.util.PerfStatsCollector;
-import org.robolectric.util.ReflectionHelpers;
 import org.robolectric.util.TempDirectory;
 import org.robolectric.util.inject.Supersedes;
-import org.robolectric.util.reflector.Accessor;
-import org.robolectric.util.reflector.ForType;
-import org.robolectric.versioning.AndroidVersions;
-import org.robolectric.versioning.AndroidVersions.U;
-import org.robolectric.versioning.AndroidVersions.V;
 
-import java.io.File;
 import java.io.IOException;
 import java.net.URL;
 import java.nio.file.Path;
-import java.nio.file.Paths;
-import java.util.Locale;
-import java.util.Objects;
+import java.util.ArrayList;
+import java.util.List;
 
 import javax.annotation.Priority;
 
@@ -60,187 +38,34 @@ import javax.annotation.Priority;
 @Supersedes(DefaultNativeRuntimeLoader.class)
 @Priority(Integer.MIN_VALUE)
 public class AndroidNativeRuntimeLoader extends DefaultNativeRuntimeLoader {
-  private static final String METHOD_BINDING_FORMAT = "$$robo$$${method}$nativeBinding";
-
-  // Core classes for which native methods are to be registered.
-  private static final ImmutableList<String> CORE_CLASS_NATIVES =
-      ImmutableList.copyOf(
-          new String[] {
-            "android.animation.PropertyValuesHolder",
-            "android.database.CursorWindow",
-            "android.database.sqlite.SQLiteConnection",
-            "android.media.ImageReader",
-            "android.view.Surface",
-            "com.android.internal.util.VirtualRefBasePtr",
-            "libcore.util.NativeAllocationRegistry",
-          });
-
-  // Graphics classes for which native methods are to be registered.
-  private static final ImmutableList<String> GRAPHICS_CLASS_NATIVES =
-      ImmutableList.copyOf(
-          new String[] {
-            "android.graphics.Bitmap",
-            "android.graphics.BitmapFactory",
-            "android.graphics.ByteBufferStreamAdaptor",
-            "android.graphics.Camera",
-            "android.graphics.Canvas",
-            "android.graphics.CanvasProperty",
-            "android.graphics.Color",
-            "android.graphics.ColorFilter",
-            "android.graphics.ColorSpace",
-            "android.graphics.CreateJavaOutputStreamAdaptor",
-            "android.graphics.DrawFilter",
-            "android.graphics.FontFamily",
-            "android.graphics.Gainmap",
-            "android.graphics.Graphics",
-            "android.graphics.HardwareRenderer",
-            "android.graphics.HardwareRendererObserver",
-            "android.graphics.ImageDecoder",
-            "android.graphics.Interpolator",
-            "android.graphics.MaskFilter",
-            "android.graphics.Matrix",
-            "android.graphics.NinePatch",
-            "android.graphics.Paint",
-            "android.graphics.Path",
-            "android.graphics.PathEffect",
-            "android.graphics.PathMeasure",
-            "android.graphics.Picture",
-            "android.graphics.RecordingCanvas",
-            "android.graphics.Region",
-            "android.graphics.RenderEffect",
-            "android.graphics.RenderNode",
-            "android.graphics.Shader",
-            "android.graphics.Typeface",
-            "android.graphics.YuvImage",
-            "android.graphics.animation.NativeInterpolatorFactory",
-            "android.graphics.animation.RenderNodeAnimator",
-            "android.graphics.drawable.AnimatedVectorDrawable",
-            "android.graphics.drawable.AnimatedImageDrawable",
-            "android.graphics.drawable.VectorDrawable",
-            "android.graphics.fonts.Font",
-            "android.graphics.fonts.FontFamily",
-            "android.graphics.text.LineBreaker",
-            "android.graphics.text.MeasuredText",
-            "android.graphics.text.TextRunShaper",
-            "android.util.PathParser",
-          });
-
-  /**
-   * {@link #DEFERRED_STATIC_INITIALIZERS} that invoke their own native methods in static
-   * initializers. Unlike libcore, registering JNI on the JVM causes static initialization to be
-   * performed on the class. Because of this, static initializers cannot invoke the native methods
-   * of the class under registration. Executing these static initializers must be deferred until
-   * after JNI has been registered.
-   */
-  private static final ImmutableList<String> DEFERRED_STATIC_INITIALIZERS =
-      ImmutableList.copyOf(
-          new String[] {
-            "android.graphics.FontFamily",
-            "android.graphics.Path",
-            "android.graphics.Typeface",
-            "android.graphics.text.MeasuredText$Builder",
-            "android.media.ImageReader",
-          });
-
-  @Override
-  public synchronized void ensureLoaded() {
-    DefaultNativeRuntimeLoaderReflector accessor = reflector(DefaultNativeRuntimeLoaderReflector.class, this);
-    if (loaded.get()) {
-      return;
-    }
 
-    if (!accessor.isSupported()) {
-      String errorMessage =
-          String.format(
-              "The Robolectric native runtime is not supported on %s (%s)",
-              OS_NAME.value(), OS_ARCH.value());
-      throw new AssertionError(errorMessage);
-    }
-    loaded.set(true);
-
-    try {
-      PerfStatsCollector.getInstance()
-          .measure(
-              "loadNativeRuntime",
-              () -> {
-                TempDirectory extractDirectory = new TempDirectory("nativeruntime");
-                accessor.setExtractDirectory(extractDirectory);
-                System.setProperty("icu.locale.default", Locale.getDefault().toLanguageTag());
-                if (Build.VERSION.SDK_INT >= O) {
-                  accessor.maybeCopyFonts(extractDirectory);
-                }
-                maybeCopyIcuData(extractDirectory);
-                maybeCopyArscFile(extractDirectory);
-                if (isAndroidVOrAbove()) {
-                  // Load per-sdk Robolectric Native Runtime (RNR)
-                  System.setProperty("core_native_classes", String.join(",", CORE_CLASS_NATIVES));
-                  System.setProperty(
-                      "graphics_native_classes", String.join(",", GRAPHICS_CLASS_NATIVES));
-                  System.setProperty("method_binding_format", METHOD_BINDING_FORMAT);
-                  if (Boolean.parseBoolean(System.getProperty(
-                          "android.robolectric.loadLibraryFromPath", "false"))) {
-                    loadLibraryFromPath();
-                  } else {
-                    loadLibrary(extractDirectory);
-                  }
-                  invokeDeferredStaticInitializers();
-                  Typeface.loadPreinstalledSystemFontMap();
-                } else {
-                  loadLibrary(extractDirectory);
-                }
-
-              });
-    } catch (IOException e) {
-      throw new AssertionError("Unable to load Robolectric native runtime library", e);
-    }
+  protected  List<String> getDeferredStaticInitializers() {
+    List<String> initializers = new ArrayList<>(super.getDeferredStaticInitializers());
+    //initializers.remove("android.graphics.PathIterator");
+    return initializers;
   }
 
-  private void loadLibraryFromPath() {
-    // find the libandroid_runtime.so file in java.library.path, and create a copy of it so
-    // it can be loaded across different sandboxes
-    var path = System.getProperty("java.library.path");
-    var filename = "libandroid_runtime.so";
-
-
-    try {
-      if (path == null) {
-          throw new UnsatisfiedLinkError("Cannot load library " + filename + "."
-                + " Property java.library.path not set!");
-      }
-      for (var dir : path.split(":")) {
-          var libraryPath = Paths.get(dir, filename);
-          if (java.nio.file.Files.exists(libraryPath)) {
-              // create a copy of the file
-              File tmpLibraryFile = java.nio.file.Files.createTempFile("", "android_runtime").toFile();
-              tmpLibraryFile.deleteOnExit();
-              Files.copy(libraryPath.toFile().getAbsoluteFile(), tmpLibraryFile);
-              System.load(tmpLibraryFile.getAbsolutePath());
-              return;
-         }
-      }
-      throw new UnsatisfiedLinkError("Library " + filename + " not found in "
-              + "java.library.path: " + path);
-    } catch (IOException e) {
-      throw new AssertionError("Failed to copy " + filename, e);
-    }
+  protected  List<String> getGraphicsNatives() {
+    List<String> initializers = new ArrayList<>(super.getGraphicsNatives());
+    //initializers.remove("android.graphics.PathIterator");
+    return initializers;
   }
 
-  /** Attempts to load the ICU dat file. This is only relevant for native graphics. */
-  private void maybeCopyIcuData(TempDirectory tempDirectory) throws IOException {
-    String icuDatFile = isAndroidVOrAbove() ? "icudt.dat" : "icudt68l.dat";
+  protected  List<String> getCoreClassNatives() {
+    List<String> initializers = new ArrayList<>(super.getCoreClassNatives());
+    //initializers.add("android.database.sqlite.SQLiteRawStatement");
+    return initializers;
+  }
 
-    URL icuDatUrl;
+  protected void maybeCopyExtraResources(TempDirectory dir) {
     try {
-      icuDatUrl = Resources.getResource("icu/" + icuDatFile);
-    } catch (IllegalArgumentException e) {
-      return;
+      maybeCopyArscFile(dir);
+    } catch (IOException ioe) {
+      throw new RuntimeException(ioe);
     }
-    Path icuPath = tempDirectory.create("icu");
-    Path icuDatPath = icuPath.resolve(icuDatFile);
-    Resources.asByteSource(icuDatUrl).copyTo(Files.asByteSink(icuDatPath.toFile()));
-    System.setProperty("icu.data.path", icuDatPath.toAbsolutePath().toString());
   }
 
+
   /** Attempts to load the ARSC file. This is only relevant for native graphics. */
   private void maybeCopyArscFile(TempDirectory tempDirectory) throws IOException {
     URL arscUrl;
@@ -256,61 +81,4 @@ public class AndroidNativeRuntimeLoader extends DefaultNativeRuntimeLoader {
     System.setProperty("arsc.file.path", arscFilePath.toAbsolutePath().toString());
   }
 
-  protected void invokeDeferredStaticInitializers() {
-    for (String className : DEFERRED_STATIC_INITIALIZERS) {
-      ReflectionHelpers.callStaticMethod(
-              Shadow.class.getClassLoader(), className, ShadowConstants.STATIC_INITIALIZER_METHOD_NAME);
-    }
-  }
-
-  private void loadLibrary(TempDirectory tempDirectory) throws IOException {
-    String libraryName = System.mapLibraryName("robolectric-nativeruntime");
-    Path libraryPath = tempDirectory.getBasePath().resolve(libraryName);
-    URL libraryResource = Resources.getResource(nativeLibraryPath());
-    Resources.asByteSource(libraryResource).copyTo(Files.asByteSink(libraryPath.toFile()));
-    System.load(libraryPath.toAbsolutePath().toString());
-  }
-
-  /** For V and above, insert "V" folder for V and above lib path. */
-  private String nativeLibraryPath() {
-    String defaultPath = defaultNativeLibraryPath();
-    if (isAndroidVOrAbove()) {
-      int index = defaultPath.lastIndexOf(System.mapLibraryName("robolectric-nativeruntime"));
-      if (index < 0) {
-        return defaultPath;
-      }
-      String result = defaultPath.substring(0,index) + "V/" + defaultPath.substring(index);
-      return result;
-    }
-    return defaultPath;
-  }
-
-  private String defaultNativeLibraryPath() {
-    DefaultNativeRuntimeLoaderReflector accessor =
-            reflector(DefaultNativeRuntimeLoaderReflector.class, this);
-    String os = accessor.osName();
-    String arch = accessor.arch();
-    return String.format(
-            "native/%s/%s/%s",
-            os,
-            arch,
-            System.mapLibraryName("robolectric-nativeruntime"));
-  }
-
-  private boolean isAndroidVOrAbove() {
-    return (Objects.equals(AndroidVersions.CURRENT.getShortCode(), V.SHORT_CODE) &&
-            AndroidVersions.CURRENT.getSdkInt() >= U.SDK_INT) ||
-        AndroidVersions.CURRENT.getSdkInt() >= V.SDK_INT;
-  }
-
-  @ForType(DefaultNativeRuntimeLoader.class)
-  private interface DefaultNativeRuntimeLoaderReflector {
-    @Accessor("extractDirectory")
-    void setExtractDirectory(TempDirectory dir);
-
-    boolean isSupported();
-    void maybeCopyFonts(TempDirectory tempDirectory);
-    String osName();
-    String arch();
-  }
 }
```

