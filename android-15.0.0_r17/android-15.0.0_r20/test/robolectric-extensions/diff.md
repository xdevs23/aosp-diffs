```diff
diff --git a/clearcut-junit-listener/Android.bp b/clearcut-junit-listener/Android.bp
new file mode 100644
index 0000000..fe44e66
--- /dev/null
+++ b/clearcut-junit-listener/Android.bp
@@ -0,0 +1,40 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+team {
+    name: "Android_Platform_Developer_Experience",
+    trendy_team_id: "5677977168281600",
+}
+
+java_library_host {
+    name: "ClearcutJunitListener",
+    srcs: ["src/main/java/**/*.java"],
+    static_libs: [
+        "asuite_proto_java",
+        "libprotobuf-java-util-full",
+        "auto_service_annotations",
+        "junit",
+    ],
+    plugins: ["auto_service_plugin"],
+    //limit to jdk 11 in case we ever make tradefed use this instead.
+    java_version: "11",
+}
+
+//#############################################
+// Compile Robolectric robolectric tests
+//#############################################
+java_test_host {
+    name: "TestClearcutJunitListener",
+    team: "Android_Platform_Developer_Experience",
+    srcs: ["src/test/java/**/*.java"],
+    java_resource_dirs: ["src/test/resources"],
+    static_libs: [
+        "ClearcutJunitListener",
+        "truth-1.4.0-prebuilt",
+        "jsr305",
+    ],
+    //test_options: {
+    //    unit_test: false,
+    //},
+}
diff --git a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutEventHelper.java b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutEventHelper.java
new file mode 100644
index 0000000..1b5881b
--- /dev/null
+++ b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutEventHelper.java
@@ -0,0 +1,222 @@
+/*
+* Copyright (C) 2019 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+*      http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+package com.google.asuite.clearcut.junit.listener;
+
+import com.android.asuite.clearcut.Common;
+import com.android.asuite.clearcut.Common.UserType;
+import com.android.asuite.clearcut.ExternalUserLog.AtestLogEventExternal;
+import com.android.asuite.clearcut.ExternalUserLog.AtestLogEventExternal.AtestExitEvent;
+import com.android.asuite.clearcut.ExternalUserLog.AtestLogEventExternal.AtestStartEvent;
+import com.android.asuite.clearcut.ExternalUserLog.AtestLogEventExternal.RunTestsFinishEvent;
+import com.android.asuite.clearcut.ExternalUserLog.AtestLogEventExternal.RunnerFinishEvent;
+import com.android.asuite.clearcut.InternalUserLog.AtestLogEventInternal;
+
+import com.google.protobuf.ByteString;
+
+import java.time.Duration;
+
+/**
+ * Utility to help populate the event protos
+ * Cloned from tradefed and decoupled.
+ * Needs a_lot of work.
+ */
+public class ClearcutEventHelper {
+
+    private static final String TOOL_NAME = "Tradefed";
+
+    /**
+     * Create the start event for Tradefed.
+     *
+     * @param userKey The unique id representing the user
+     * @param runId The current id for the session.
+     * @param userType The type of the user: internal or external.
+     * @param subToolName The name of test suite tool.
+     * @return a ByteString representation of the even proto.
+     */
+    public static ByteString createStartEvent(
+            String userKey, String runId, UserType userType, String subToolName) {
+        if (UserType.GOOGLE.equals(userType)) {
+            AtestLogEventInternal.Builder builder =
+                    createBaseInternalEventBuilder(userKey, runId, userType, subToolName);
+            AtestLogEventInternal.AtestStartEvent.Builder startEventBuilder =
+                    AtestLogEventInternal.AtestStartEvent.newBuilder();
+            builder.setAtestStartEvent(startEventBuilder.build());
+            return builder.build().toByteString();
+        }
+
+        AtestLogEventExternal.Builder builder =
+                createBaseExternalEventBuilder(userKey, runId, userType, subToolName);
+        AtestStartEvent.Builder startBuilder = AtestStartEvent.newBuilder();
+        builder.setAtestStartEvent(startBuilder.build());
+        return builder.build().toByteString();
+    }
+
+    /**
+     * Create the end event for Tradefed.
+     *
+     * @param userKey The unique id representing the user
+     * @param runId The current id for the session.
+     * @param userType The type of the user: internal or external.
+     * @param subToolName The name of test suite tool.
+     * @param sessionDuration The duration of the complete session.
+     * @return a ByteString representation of the even proto.
+     */
+    public static ByteString createFinishedEvent(
+            String userKey,
+            String runId,
+            UserType userType,
+            String subToolName,
+            Duration sessionDuration) {
+        if (UserType.GOOGLE.equals(userType)) {
+            AtestLogEventInternal.Builder builder =
+                    createBaseInternalEventBuilder(userKey, runId, userType, subToolName);
+            AtestLogEventInternal.AtestExitEvent.Builder exitEventBuilder =
+                    AtestLogEventInternal.AtestExitEvent.newBuilder();
+            Common.Duration duration =
+                    Common.Duration.newBuilder()
+                            .setSeconds(sessionDuration.getSeconds())
+                            .setNanos(sessionDuration.getNano())
+                            .build();
+            exitEventBuilder.setDuration(duration);
+            builder.setAtestExitEvent(exitEventBuilder.build());
+            return builder.build().toByteString();
+        }
+
+        AtestLogEventExternal.Builder builder =
+                createBaseExternalEventBuilder(userKey, runId, userType, subToolName);
+        AtestLogEventExternal.AtestExitEvent.Builder startBuilder = AtestExitEvent.newBuilder();
+        builder.setAtestExitEvent(startBuilder.build());
+        return builder.build().toByteString();
+    }
+
+    /**
+     * Create the start invocation event for Tradefed.
+     *
+     * @param userKey The unique id representing the user
+     * @param runId The current id for the session.
+     * @param userType The type of the user: internal or external.
+     * @param subToolName The name of test suite tool.
+     * @return a ByteString representation of the even proto.
+     */
+    public static ByteString createRunStartEvent(
+            String userKey, String runId, UserType userType, String subToolName) {
+        if (UserType.GOOGLE.equals(userType)) {
+            //This is where individual test results belong.   Weird.
+            AtestLogEventInternal.Builder builder =
+                    createBaseInternalEventBuilder(userKey, runId, userType, subToolName);
+            AtestLogEventInternal.RunnerFinishEvent.Builder startRunEventBuilder =
+                    AtestLogEventInternal.RunnerFinishEvent.newBuilder();
+            //Why aren't we calling? startRunEventBuilder.addTest();
+            builder.setRunnerFinishEvent(startRunEventBuilder.build());
+            return builder.build().toByteString();
+        }
+
+        AtestLogEventExternal.Builder builder =
+                createBaseExternalEventBuilder(userKey, runId, userType, subToolName);
+        RunnerFinishEvent.Builder startBuilder = RunnerFinishEvent.newBuilder();
+        builder.setRunnerFinishEvent(startBuilder.build());
+        return builder.build().toByteString();
+    }
+
+    /**
+     * Not needed yet.
+     */
+    private AtestLogEventInternal.RunnerFinishEvent.Test buildTest(String name, int result, String stacktrace) {
+        AtestLogEventInternal.RunnerFinishEvent.Test.Builder testBuilder = AtestLogEventInternal.RunnerFinishEvent.Test.newBuilder();
+        testBuilder.setName(name);
+        testBuilder.setResult(result);
+        testBuilder.setStacktrace(stacktrace);
+        return testBuilder.build();
+    }
+
+    /**
+     * Create the run test finished event for Tradefed.
+     *
+     * @param userKey The unique id representing the user
+     * @param runId The current id for the session.
+     * @param userType The type of the user: internal or external.
+     * @param subToolName The name of test suite tool.
+     * @param testDuration the duration of the test session.
+     * @return a ByteString representation of the even proto.
+     */
+    public static ByteString creatRunTestFinished(
+            String userKey,
+            String runId,
+            UserType userType,
+            String subToolName,
+            Duration testDuration) {
+        if (UserType.GOOGLE.equals(userType)) {
+            AtestLogEventInternal.Builder builder =
+                    createBaseInternalEventBuilder(userKey, runId, userType, subToolName);
+            AtestLogEventInternal.RunTestsFinishEvent.Builder runTestsFinished =
+                    AtestLogEventInternal.RunTestsFinishEvent.newBuilder();
+            Common.Duration duration =
+                    Common.Duration.newBuilder()
+                            .setSeconds(testDuration.getSeconds())
+                            .setNanos(testDuration.getNano())
+                            .build();
+            runTestsFinished.setDuration(duration);
+            builder.setRunTestsFinishEvent(runTestsFinished.build());
+            return builder.build().toByteString();
+        }
+
+        AtestLogEventExternal.Builder builder =
+                createBaseExternalEventBuilder(userKey, runId, userType, subToolName);
+        RunTestsFinishEvent.Builder startBuilder = RunTestsFinishEvent.newBuilder();
+        builder.setRunTestsFinishEvent(startBuilder.build());
+        return builder.build().toByteString();
+    }
+
+    /**
+     * Create the basic event builder with all the common informations.
+     *
+     * @param userKey The unique id representing the user
+     * @param runId The current id for the session.
+     * @param userType The type of the user: internal or external.
+     * @param subToolName The name of test suite tool.
+     * @return a builder for the event.
+     */
+    private static AtestLogEventExternal.Builder createBaseExternalEventBuilder(
+            String userKey, String runId, UserType userType, String subToolName) {
+        AtestLogEventExternal.Builder builder = AtestLogEventExternal.newBuilder();
+        builder.setUserKey(userKey);
+        builder.setRunId(runId);
+        builder.setUserType(userType);
+        builder.setToolName(TOOL_NAME);
+        builder.setSubToolName(subToolName);
+        return builder;
+    }
+
+    /**
+     * Create the basic event builder with all the common informations.
+     *
+     * @param userKey The unique id representing the user
+     * @param runId The current id for the session.
+     * @param userType The type of the user: internal or external.
+     * @param subToolName The name of test suite tool.
+     * @return a builder for the event.
+     */
+    private static AtestLogEventInternal.Builder createBaseInternalEventBuilder(
+            String userKey, String runId, UserType userType, String subToolName) {
+        AtestLogEventInternal.Builder builder = AtestLogEventInternal.newBuilder();
+        builder.setUserKey(userKey);
+        builder.setRunId(runId);
+        builder.setUserType(userType);
+        builder.setToolName(TOOL_NAME);
+        builder.setSubToolName(subToolName);
+        return builder;
+    }
+}
\ No newline at end of file
diff --git a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutJunitListener.java b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutJunitListener.java
new file mode 100644
index 0000000..963c9ce
--- /dev/null
+++ b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/ClearcutJunitListener.java
@@ -0,0 +1,64 @@
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
+import com.google.auto.service.AutoService;
+
+import org.junit.runner.Description;
+import org.junit.runner.Result;
+import org.junit.runner.notification.RunListener;
+
+@AutoService(RunListener.class)
+public class ClearcutJunitListener extends RunListener {
+
+    private Client client;
+    private long startTime = System.nanoTime();
+
+    public ClearcutJunitListener() {
+        System.out.println("In clearcut listener");
+        String context = "junit";
+        if (EnvironmentInformation.isSysUIRoboTest()) { //sysui
+            context = "junit_sysui";
+        } else if (EnvironmentInformation.isGradleTest()) { //intellij
+            context = "junit_gradle";
+        } else if (EnvironmentInformation.isRoboTest()) { //robolectric
+            context += "_robolectric";
+        }
+        client = new Client(context);
+    }
+
+
+    @Override
+    public void testRunStarted(Description description) throws Exception {
+        client.notifyTradefedStartEvent();
+    }
+
+    @Override
+    public void testRunFinished(Result result) throws Exception {
+        client.notifyTradefedFinishedEvent();
+    }
+
+    @Override
+    public void testStarted(Description description) throws Exception {
+        client.notifyTradefedInvocationStartEvent();
+    }
+
+    public void testFinished(Description description) throws Exception {
+        client.notifyTestRunFinished(startTime);
+        client.stop();
+    }
+}
diff --git a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/Client.java b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/Client.java
new file mode 100644
index 0000000..b4e1b8a
--- /dev/null
+++ b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/Client.java
@@ -0,0 +1,450 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+package com.google.asuite.clearcut.junit.listener;
+
+import com.android.asuite.clearcut.Clientanalytics.ClientInfo;
+import com.android.asuite.clearcut.Clientanalytics.LogEvent;
+import com.android.asuite.clearcut.Clientanalytics.LogRequest;
+import com.android.asuite.clearcut.Clientanalytics.LogResponse;
+import com.android.asuite.clearcut.Common.UserType;
+
+import com.google.common.base.Strings;
+import com.google.protobuf.util.JsonFormat;
+
+import java.io.BufferedReader;
+import java.io.Closeable;
+import java.io.File;
+import java.io.IOException;
+import java.io.InputStream;
+import java.io.InputStreamReader;
+import java.io.OutputStream;
+import java.io.OutputStreamWriter;
+import java.net.HttpURLConnection;
+import java.net.InetAddress;
+import java.net.URI;
+import java.net.URISyntaxException;
+import java.net.URL;
+import java.net.UnknownHostException;
+import java.nio.charset.StandardCharsets;
+import java.nio.file.Files;
+import java.nio.file.OpenOption;
+import java.nio.file.StandardOpenOption;
+import java.time.Duration;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
+import java.util.Optional;
+import java.util.UUID;
+import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.Executors;
+import java.util.concurrent.ScheduledThreadPoolExecutor;
+import java.util.concurrent.ThreadFactory;
+import java.util.concurrent.TimeUnit;
+import java.util.stream.Collectors;
+
+/** Client that allows reporting usage metrics to clearcut. */
+public class Client {
+
+    public static final String DISABLE_CLEARCUT_KEY = "DISABLE_CLEARCUT";
+    private static final String CLEARCUT_SUB_TOOL_NAME = "CLEARCUT_SUB_TOOL_NAME";
+
+    private static final String CLEARCUT_PROD_URL = "https://play.googleapis.com/log";
+    private static final int CLIENT_TYPE = 1;
+    private static final int INTERNAL_LOG_SOURCE = 971;
+    private static final int EXTERNAL_LOG_SOURCE = 934;
+
+    private static final long SCHEDULER_INITIAL_DELAY_MILLISECONDS = 1000;
+    private static final long SCHEDULER_PERDIOC_MILLISECONDS = 250;
+
+    private static final String GOOGLE_EMAIL = "@google.com";
+    private static final String GOOGLE_HOSTNAME = ".google.com";
+
+    private File mCachedUuidFile = new File(System.getProperty("user.home"), ".clearcut_listener");
+    private String mRunId;
+    private long mSessionStartTime = 0L;
+
+    private final int mLogSource;
+    private final String mUrl;
+    private final UserType mUserType;
+    private final String mSubToolName;
+
+    // Consider synchronized list
+    private final List<LogRequest> mExternalEventQueue;
+    // The pool executor to actually post the metrics
+    private ScheduledThreadPoolExecutor mExecutor;
+    // Whether the clearcut client should be a noop
+    private boolean mDisabled = false;
+
+    public Client(String subToolName) {
+        this(null, subToolName);
+        Runtime.getRuntime().addShutdownHook(new Thread(Client.this::stop));
+    }
+
+    /**
+     * Create Client with customized posting URL and forcing whether it's internal or external user.
+     */
+    protected Client(String url, String subToolName) {
+        mDisabled = isClearcutDisabled();
+
+        // We still have to set the 'final' variable so go through the assignments before returning
+        if (!mDisabled && isGoogleUser()) {
+            mLogSource = INTERNAL_LOG_SOURCE;
+            mUserType = UserType.GOOGLE;
+        } else {
+            mLogSource = EXTERNAL_LOG_SOURCE;
+            mUserType = UserType.EXTERNAL;
+        }
+        if (url == null) {
+            mUrl = CLEARCUT_PROD_URL;
+        } else {
+            mUrl = url;
+        }
+        mRunId = UUID.randomUUID().toString();
+        mExternalEventQueue = new ArrayList<>();
+        if (Strings.isNullOrEmpty(subToolName) && System.getenv(CLEARCUT_SUB_TOOL_NAME) != null) {
+            mSubToolName = System.getenv(CLEARCUT_SUB_TOOL_NAME);
+        } else {
+            mSubToolName = subToolName;
+        }
+
+        if (mDisabled) {
+            return;
+        }
+
+        // Print the notice
+        System.out.println(NoticeMessageUtil.getNoticeMessage(mUserType));
+
+        // Executor to actually send the events.
+        mExecutor =
+                new ScheduledThreadPoolExecutor(
+                        1,
+                        new ThreadFactory() {
+                            @Override
+                            public Thread newThread(Runnable r) {
+                                Thread t = Executors.defaultThreadFactory().newThread(r);
+                                t.setDaemon(true);
+                                t.setName("clearcut-client-thread");
+                                return t;
+                            }
+                        });
+        Runnable command =
+                new Runnable() {
+                    @Override
+                    public void run() {
+                        flushEvents();
+                    }
+                };
+        mExecutor.scheduleAtFixedRate(
+                command,
+                SCHEDULER_INITIAL_DELAY_MILLISECONDS,
+                SCHEDULER_PERDIOC_MILLISECONDS,
+                TimeUnit.MILLISECONDS);
+    }
+
+    /** Send the first event to notify that Tradefed was started. */
+    public void notifyTradefedStartEvent() {
+        if (mDisabled) {
+            return;
+        }
+        mSessionStartTime = System.nanoTime();
+        long eventTimeMs = System.currentTimeMillis();
+        CompletableFuture.supplyAsync(() -> createStartEvent(eventTimeMs));
+    }
+
+    private boolean createStartEvent(long eventTimeMs) {
+        LogRequest.Builder request = createBaseLogRequest();
+        LogEvent.Builder logEvent = LogEvent.newBuilder();
+        logEvent.setEventTimeMs(eventTimeMs);
+        logEvent.setSourceExtension(
+                ClearcutEventHelper.createStartEvent(
+                        getGroupingKey(), mRunId, mUserType, mSubToolName));
+        request.addLogEvent(logEvent);
+        queueEvent(request.build());
+        return true;
+    }
+
+    /** Send the last event to notify that Tradefed is done. */
+    public void notifyTradefedFinishedEvent() {
+        if (mDisabled) {
+            return;
+        }
+        Duration duration = java.time.Duration.ofNanos(System.nanoTime() - mSessionStartTime);
+        LogRequest.Builder request = createBaseLogRequest();
+        LogEvent.Builder logEvent = LogEvent.newBuilder();
+        logEvent.setEventTimeMs(System.currentTimeMillis());
+        logEvent.setSourceExtension(
+                ClearcutEventHelper.createFinishedEvent(
+                        getGroupingKey(), mRunId, mUserType, mSubToolName, duration));
+        request.addLogEvent(logEvent);
+        queueEvent(request.build());
+    }
+
+    /** Send the event to notify that a Tradefed invocation was started. */
+    public void notifyTradefedInvocationStartEvent() {
+        if (mDisabled) {
+            return;
+        }
+        LogRequest.Builder request = createBaseLogRequest();
+        LogEvent.Builder logEvent = LogEvent.newBuilder();
+        logEvent.setEventTimeMs(System.currentTimeMillis());
+        logEvent.setSourceExtension(
+                ClearcutEventHelper.createRunStartEvent(
+                        getGroupingKey(), mRunId, mUserType, mSubToolName));
+        request.addLogEvent(logEvent);
+        queueEvent(request.build());
+    }
+
+    /** Send the event to notify that a test run finished. */
+    public void notifyTestRunFinished(long startTimeNano) {
+        if (mDisabled) {
+            return;
+        }
+        Duration duration = java.time.Duration.ofNanos(System.nanoTime() - startTimeNano);
+        LogRequest.Builder request = createBaseLogRequest();
+        LogEvent.Builder logEvent = LogEvent.newBuilder();
+        logEvent.setEventTimeMs(System.currentTimeMillis());
+        logEvent.setSourceExtension(
+                ClearcutEventHelper.creatRunTestFinished(
+                        getGroupingKey(), mRunId, mUserType, mSubToolName, duration));
+        request.addLogEvent(logEvent);
+        queueEvent(request.build());
+    }
+
+    /** Stop the periodic sending of clearcut events */
+    public void stop() {
+        if (mExecutor != null) {
+            mExecutor.setRemoveOnCancelPolicy(true);
+            mExecutor.shutdown();
+            mExecutor = null;
+        }
+        // Send all remaining events
+        flushEvents();
+    }
+
+    /** Add an event to the queue of events that needs to be send. */
+    public void queueEvent(LogRequest event) {
+        synchronized (mExternalEventQueue) {
+            mExternalEventQueue.add(event);
+        }
+    }
+
+    /** Returns the current queue size. */
+    public final int getQueueSize() {
+        synchronized (mExternalEventQueue) {
+            return mExternalEventQueue.size();
+        }
+    }
+
+    /** Allows to override the default cached uuid file. */
+    public void setCachedUuidFile(File uuidFile) {
+        mCachedUuidFile = uuidFile;
+    }
+
+    /** Get a new or the cached uuid for the user. */
+    String getGroupingKey() {
+        String uuid = null;
+        if (mCachedUuidFile.exists()) {
+            try {
+                uuid = readFromFile(mCachedUuidFile);
+            } catch (IOException e) {
+                logError(e);
+            }
+        }
+        if (uuid == null || uuid.isEmpty()) {
+            uuid = UUID.randomUUID().toString();
+            try {
+                writeToFile(uuid, mCachedUuidFile);
+            } catch (IOException e) {
+                logError(e);
+            }
+        }
+        return uuid;
+    }
+
+    /** Returns True if clearcut is disabled, False otherwise. */
+    public boolean isClearcutDisabled() {
+        return "1".equals(System.getenv(DISABLE_CLEARCUT_KEY));
+    }
+
+    /** Returns True if the user is a Googler, False otherwise. */
+    boolean isGoogleUser() {
+        try {
+            String hostname = InetAddress.getLocalHost().getHostName();
+            if (hostname.contains(GOOGLE_HOSTNAME)) {
+                return true;
+            }
+        } catch (UnknownHostException e) {
+            // Ignore
+        }
+        Optional<String> result = executCommand("git", "config", "--get", "user.email");
+        if (result.isPresent()) {
+            String stdout = result.get();
+            if (stdout != null && stdout.trim().endsWith(GOOGLE_EMAIL)) {
+                return true;
+            }
+        }
+        return false;
+    }
+
+    private LogRequest.Builder createBaseLogRequest() {
+        LogRequest.Builder request = LogRequest.newBuilder();
+        request.setLogSource(mLogSource);
+        request.setClientInfo(ClientInfo.newBuilder().setClientType(CLIENT_TYPE));
+        return request;
+    }
+
+    private void flushEvents() {
+        List<LogRequest> copy = new ArrayList<>();
+        synchronized (mExternalEventQueue) {
+            copy.addAll(mExternalEventQueue);
+            mExternalEventQueue.clear();
+        }
+        List<CompletableFuture<Boolean>> futures = new ArrayList<>();
+        while (!copy.isEmpty()) {
+            LogRequest event = copy.remove(0);
+            futures.add(CompletableFuture.supplyAsync(() -> sendToClearcut(event)));
+        }
+
+        for (CompletableFuture<Boolean> future : futures) {
+            try {
+                future.get();
+            } catch (InterruptedException | ExecutionException e) {
+                logError(e);
+            }
+        }
+    }
+
+    /** Send one event to the configured server. */
+    private boolean sendToClearcut(LogRequest event) {
+        InputStream inputStream = null;
+        InputStream errorStream = null;
+        OutputStream outputStream = null;
+        OutputStreamWriter outputStreamWriter = null;
+        try {
+            HttpURLConnection connection = createConnection(new URI(mUrl).toURL(), "POST", "text");
+            outputStream = connection.getOutputStream();
+            outputStreamWriter = new OutputStreamWriter(outputStream);
+
+            String jsonObject = JsonFormat.printer().preservingProtoFieldNames().print(event);
+            outputStreamWriter.write(jsonObject.toString());
+            outputStreamWriter.flush();
+
+            inputStream = connection.getInputStream();
+            LogResponse response = LogResponse.parseFrom(inputStream);
+
+            errorStream = connection.getErrorStream();
+            if (errorStream != null) {
+                String message =  readStream(errorStream);
+                System.out.println("Error posting clearcut event: " + message + " LogResponse: " + response);
+            }
+        } catch (IOException | URISyntaxException e) {
+            logError(e);
+        } catch (NoSuchMethodError e) {
+            if (e.getMessage().contains("com.google.protobuf.Descriptors$Descriptor com.google.protobuf.Any.getDescriptor()")) {
+                StringBuilder message = new StringBuilder();
+                message.append("In order for the ClearcutListener to operate it must use protobuf-full to be able to convert messages to json.\n");
+                message.append("Android typically uses protobuf-lite.");
+                message.append("If you're seeing this in a gradle build, adding `testImplementation(project(\":RobolectricLib\"))` to the start of ");
+                message.append("your dependency section should be sufficient, if not (due to how gradle calculates deps), add this dep: ");
+                message.append("`testImplementation(libs.protobuf.java)` to the top of your dependencies");
+                throw new RuntimeException(message.toString(), e);
+            } else {
+                logError(e);
+                throw e;
+            }
+        } catch (Throwable t) {
+            logError(t);
+            throw t;
+        } finally {
+            closeQuietly(outputStream);
+            closeQuietly(inputStream);
+            closeQuietly(outputStreamWriter);
+            closeQuietly(errorStream);
+        }
+        return true;
+    }
+
+    private void closeQuietly(Closeable c) {
+        try {
+            if (c != null) {
+                c.close();
+            }
+        } catch (IOException ex) {
+            // Intentional No-Op
+        }
+    }
+
+    private void logError(Throwable t) {
+        System.out.println(t);
+        t.printStackTrace(System.out);
+    }
+
+    protected static String readFromFile(File file) throws IOException {
+        return Files.readString(file.toPath());
+    }
+
+    protected static void writeToFile(String content, File file) throws IOException {
+        Files.writeString(file.toPath(), content, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
+    }
+
+    protected static String readStream(InputStream is) throws IOException {
+        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
+            return reader.lines().collect(Collectors.joining(System.lineSeparator()));
+        }
+    }
+
+    protected static Optional<String> executCommand(String... command) {
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
+                    Arrays.stream(command).collect(Collectors.joining(" ")));
+            e.printStackTrace();
+        }
+        return Optional.empty();
+    }
+
+    private static HttpURLConnection createConnection(URL url, String method, String contentType)
+            throws IOException {
+        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
+        connection.setRequestMethod(method);
+        if (contentType != null) {
+            connection.setRequestProperty("Content-Type", contentType);
+        }
+        connection.setDoInput(true);
+        connection.setDoOutput(true);
+        connection.setConnectTimeout(60 * 1000);  // timeout for establishing the connection
+        connection.setReadTimeout(60 * 1000);  // timeout for receiving a read() response
+        connection.setRequestProperty("User-Agent",
+                String.format("%s/%s", "TradeFederation_like_ClearcutJunitListener", "1.0"));
+
+        return connection;
+    }
+}
diff --git a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformation.java b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformation.java
new file mode 100644
index 0000000..a99b403
--- /dev/null
+++ b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformation.java
@@ -0,0 +1,52 @@
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
+public class EnvironmentInformation {
+
+    private static String ROBOLECTRIC_SYSUI_EXTENSION_CLASS = "com.google.android.sysui.ToTSdkProvider";
+    private static String GRADLE = "worker.org.gradle.process.internal.worker.GradleWorkerMain";
+    private static String ROBOLECTRIC_CLASS = "org.robolectric.Robolectric";
+
+    private static boolean hasClassInLoader(String className) {
+        try {
+            Thread.currentThread().getContextClassLoader().loadClass(
+                    className);
+            return true;
+        } catch (ClassNotFoundException ex) {
+            return false;
+        }
+    }
+
+    public static boolean isSysUIRoboTest() {
+        return hasClassInLoader(ROBOLECTRIC_SYSUI_EXTENSION_CLASS);
+    }
+
+    public static boolean isGradleTest() {
+        return hasClassInLoader(GRADLE);
+    }
+
+    public static boolean isRoboTest() {
+        return hasClassInLoader(ROBOLECTRIC_CLASS);
+    }
+
+    public static boolean isDebugging() {
+        return java.lang.management.ManagementFactory.getRuntimeMXBean().
+                getInputArguments().toString().contains("-agentlib:jdwp");
+    }
+
+}
diff --git a/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/NoticeMessageUtil.java b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/NoticeMessageUtil.java
new file mode 100644
index 0000000..a9adecd
--- /dev/null
+++ b/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/NoticeMessageUtil.java
@@ -0,0 +1,46 @@
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
+import com.android.asuite.clearcut.Common;
+
+public class NoticeMessageUtil {
+
+    private static final String INTERNAL_AGREEMENT = "https://cla.developers.google.com/";
+    private static final String EXTERNAL_AGREEMENT = "https://opensource.google.com/docs/cla/";
+    private static final String ANONYMOUS = "anonymous ";
+
+    private static final String NOTICE_MESSAGE =
+            "==================\nNotice:\n"
+                    + "We collect %susage statistics in accordance with our Content Licenses "
+                    + "(https://source.android.com/setup/start/licenses), Contributor License "
+                    + "Agreement (%s), Privacy Policy "
+                    + "(https://policies.google.com/privacy) and Terms of Service "
+                    + "(https://policies.google.com/terms)."
+                    + "\n==================";
+
+    private NoticeMessageUtil() {}
+
+    /** Returns the notice message based on the user type (internal vs external). */
+    public static String getNoticeMessage(Common.UserType type) {
+        if (Common.UserType.EXTERNAL.equals(type)) {
+            return String.format(NOTICE_MESSAGE, ANONYMOUS, EXTERNAL_AGREEMENT);
+        } else {
+            return String.format(NOTICE_MESSAGE, "", INTERNAL_AGREEMENT);
+        }
+    }
+}
diff --git a/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/ClientTest.java b/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/ClientTest.java
new file mode 100644
index 0000000..99143a6
--- /dev/null
+++ b/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/ClientTest.java
@@ -0,0 +1,99 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+package com.google.asuite.clearcut.junit.listener;
+
+import static org.junit.Assert.assertEquals;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.io.File;
+
+/** Unit tests for {@link Client}. */
+@RunWith(JUnit4.class)
+public class ClientTest {
+
+    private Client mClient;
+
+    @Before
+    public void setUp() {
+        mClient =
+                new Client("url", "test") {
+                    @Override
+                    boolean isGoogleUser() {
+                        return false;
+                    }
+                };
+    }
+
+    @After
+    public void tearDown() {
+        mClient.stop();
+    }
+
+    @Test
+    public void testGetGroupingKey() throws Exception {
+        File testFile = File.createTempFile("uuid-test", "");
+        try {
+            mClient.setCachedUuidFile(testFile);
+            String grouping = mClient.getGroupingKey();
+            // Key was created and written to cached file.
+            assertEquals(grouping, Client.readFromFile(testFile));
+        } finally {
+            testFile.delete();
+        }
+    }
+
+    @Test
+    public void testGetGroupingKey_exists() throws Exception {
+        File testFile = File.createTempFile("uuid-test", "");
+        try {
+            Client.writeToFile("test", testFile);
+            mClient.setCachedUuidFile(testFile);
+            String grouping = mClient.getGroupingKey();
+            assertEquals("test", grouping);
+        } finally {
+            testFile.delete();
+        }
+    }
+
+    @Test
+    public void testDisableClient() {
+        Client c =
+                new Client("url", "test") {
+                    @Override
+                    public boolean isClearcutDisabled() {
+                        return true;
+                    }
+
+                    @Override
+                    boolean isGoogleUser() {
+                        throw new RuntimeException("Should not be called if disabled");
+                    }
+                };
+        try {
+            c.notifyTradefedStartEvent();
+            c.notifyTradefedStartEvent();
+            c.notifyTradefedStartEvent();
+            assertEquals(0, c.getQueueSize());
+        } finally {
+            c.stop();
+        }
+    }
+}
diff --git a/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformationTest.java b/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformationTest.java
new file mode 100644
index 0000000..8551eda
--- /dev/null
+++ b/clearcut-junit-listener/src/test/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformationTest.java
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
+
+public class EnvironmentInformationTest {
+    @Test
+    public void testEnvironmentInformation() {
+        assertThat(EnvironmentInformation.isGradleTest()).isEqualTo(false);
+        assertThat(EnvironmentInformation.isDebugging()).isEqualTo(false);
+        assertThat(EnvironmentInformation.isRoboTest()).isEqualTo(false);
+        assertThat(EnvironmentInformation.isSysUIRoboTest()).isEqualTo(false);
+    }
+}
diff --git a/plugins/src/main/java/org/robolectric/android/plugins/AndroidConfigConfigurer.java b/plugins/src/main/java/org/robolectric/android/plugins/AndroidConfigConfigurer.java
index aa296c7..899efee 100644
--- a/plugins/src/main/java/org/robolectric/android/plugins/AndroidConfigConfigurer.java
+++ b/plugins/src/main/java/org/robolectric/android/plugins/AndroidConfigConfigurer.java
@@ -7,14 +7,18 @@ import org.robolectric.pluginapi.config.GlobalConfigProvider;
 import org.robolectric.plugins.ConfigConfigurer;
 import org.robolectric.plugins.PackagePropertiesLoader;
 import org.robolectric.util.Logger;
-import org.robolectric.util.inject.Supercedes;
+import org.robolectric.util.inject.Supersedes;
 
 @AutoService(Configurer.class)
-@Supercedes(ConfigConfigurer.class)
+@Supersedes(ConfigConfigurer.class)
 public class AndroidConfigConfigurer extends ConfigConfigurer {
 
   static {
+    // Enables utils/src/main/java/org/robolectric/util/Logger.java
     System.setProperty("robolectric.logging.enabled", "true");
+    // Set to enable logging to stdout in
+    // shadows/framework/src/main/java/org/robolectric/shadows/ShadowLog.java
+    System.setProperty("robolectric.logging", "stdout");
     Logger.info("Logging turned on by AndroidConfigConfigurer.class");
   }
 
@@ -27,4 +31,4 @@ public class AndroidConfigConfigurer extends ConfigConfigurer {
           GlobalConfigProvider defaultConfigProvider) {
     super(packagePropertiesLoader, defaultConfigProvider);
   }
-}
\ No newline at end of file
+}
diff --git a/plugins/src/main/java/org/robolectric/android/plugins/AndroidConscryptModeConfigurer.java b/plugins/src/main/java/org/robolectric/android/plugins/AndroidConscryptModeConfigurer.java
new file mode 100644
index 0000000..9361b9c
--- /dev/null
+++ b/plugins/src/main/java/org/robolectric/android/plugins/AndroidConscryptModeConfigurer.java
@@ -0,0 +1,51 @@
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
+package org.robolectric.plugins;
+
+import static com.google.common.base.StandardSystemProperty.OS_ARCH;
+
+import com.google.auto.service.AutoService;
+import java.util.Locale;
+import java.util.Properties;
+import javax.annotation.Priority;
+import org.robolectric.annotation.ConscryptMode;
+import org.robolectric.annotation.ConscryptMode.Mode;
+import org.robolectric.pluginapi.config.Configurer;
+import org.robolectric.plugins.config.SingleValueConfigurer;
+import org.robolectric.util.OsUtil;
+import org.robolectric.util.inject.Supersedes;
+
+/** 
+ * Provides configuration to Robolectric for its @{@link ConscryptMode} annotation. 
+ * Due to instability in the librobolectric-runtime.so default to mode OFF in android
+ * until we can build the .so in branch.
+ */
+@AutoService(Configurer.class)
+@Supersedes(ConscryptModeConfigurer.class)
+@Priority(Integer.MAX_VALUE)
+public class AndroidConscryptModeConfigurer extends SingleValueConfigurer<ConscryptMode, ConscryptMode.Mode> {
+
+  public AndroidConscryptModeConfigurer(
+      Properties systemProperties, PackagePropertiesLoader propertyFileLoader) {
+    super(
+        ConscryptMode.class,
+        ConscryptMode.Mode.class,
+        Mode.OFF,
+        propertyFileLoader,
+        systemProperties);
+  }
+}
diff --git a/plugins/src/main/java/org/robolectric/android/plugins/AndroidLocalSdkProvider.java b/plugins/src/main/java/org/robolectric/android/plugins/AndroidLocalSdkProvider.java
index c68c1d1..b74d0b6 100644
--- a/plugins/src/main/java/org/robolectric/android/plugins/AndroidLocalSdkProvider.java
+++ b/plugins/src/main/java/org/robolectric/android/plugins/AndroidLocalSdkProvider.java
@@ -19,10 +19,20 @@ import java.util.stream.Collectors;
 
 import javax.annotation.Priority;
 
+import org.robolectric.util.Logger;
+
 @AutoService(SdkProvider.class)
 @Priority(2)
 public class AndroidLocalSdkProvider extends DefaultSdkProvider {
 
+    static {
+      System.setProperty("robolectric.offline", "true");
+      Logger.info("Offline mode set by AndroidLocalSdkProvider.class");
+      System.setProperty("robolectric.usePreinstrumentedJars", "false");
+      Logger.info("Disable preinstrumented jars in AndroidLocalSdkProvider.class");
+    }
+
+
     public AndroidLocalSdkProvider(DependencyResolver dependencyResolver) {
         super(dependencyResolver);
     }
diff --git a/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java b/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java
index 45943b7..d075d1d 100644
--- a/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java
+++ b/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java
@@ -38,7 +38,7 @@ import org.robolectric.shadow.api.Shadow;
 import org.robolectric.util.PerfStatsCollector;
 import org.robolectric.util.ReflectionHelpers;
 import org.robolectric.util.TempDirectory;
-import org.robolectric.util.inject.Supercedes;
+import org.robolectric.util.inject.Supersedes;
 import org.robolectric.util.reflector.Accessor;
 import org.robolectric.util.reflector.ForType;
 import org.robolectric.versioning.AndroidVersions;
@@ -57,7 +57,7 @@ import javax.annotation.Priority;
 
 /** Loads the Robolectric native runtime. */
 @AutoService(NativeRuntimeLoader.class)
-@Supercedes(DefaultNativeRuntimeLoader.class)
+@Supersedes(DefaultNativeRuntimeLoader.class)
 @Priority(Integer.MIN_VALUE)
 public class AndroidNativeRuntimeLoader extends DefaultNativeRuntimeLoader {
   private static final String METHOD_BINDING_FORMAT = "$$robo$$${method}$nativeBinding";
@@ -256,7 +256,7 @@ public class AndroidNativeRuntimeLoader extends DefaultNativeRuntimeLoader {
     System.setProperty("arsc.file.path", arscFilePath.toAbsolutePath().toString());
   }
 
-  private void invokeDeferredStaticInitializers() {
+  protected void invokeDeferredStaticInitializers() {
     for (String className : DEFERRED_STATIC_INITIALIZERS) {
       ReflectionHelpers.callStaticMethod(
               Shadow.class.getClassLoader(), className, ShadowConstants.STATIC_INITIALIZER_METHOD_NAME);
@@ -273,9 +273,7 @@ public class AndroidNativeRuntimeLoader extends DefaultNativeRuntimeLoader {
 
   /** For V and above, insert "V" folder for V and above lib path. */
   private String nativeLibraryPath() {
-    DefaultNativeRuntimeLoaderReflector accessor =
-            reflector(DefaultNativeRuntimeLoaderReflector.class, this);
-    String defaultPath = accessor.nativeLibraryPath();
+    String defaultPath = defaultNativeLibraryPath();
     if (isAndroidVOrAbove()) {
       int index = defaultPath.lastIndexOf(System.mapLibraryName("robolectric-nativeruntime"));
       if (index < 0) {
@@ -287,9 +285,22 @@ public class AndroidNativeRuntimeLoader extends DefaultNativeRuntimeLoader {
     return defaultPath;
   }
 
+  private String defaultNativeLibraryPath() {
+    DefaultNativeRuntimeLoaderReflector accessor =
+            reflector(DefaultNativeRuntimeLoaderReflector.class, this);
+    String os = accessor.osName();
+    String arch = accessor.arch();
+    return String.format(
+            "native/%s/%s/%s",
+            os,
+            arch,
+            System.mapLibraryName("robolectric-nativeruntime"));
+  }
+
   private boolean isAndroidVOrAbove() {
-    return Objects.equals(AndroidVersions.CURRENT.getShortCode(), V.SHORT_CODE) &&
-            AndroidVersions.CURRENT.getSdkInt() >= U.SDK_INT;
+    return (Objects.equals(AndroidVersions.CURRENT.getShortCode(), V.SHORT_CODE) &&
+            AndroidVersions.CURRENT.getSdkInt() >= U.SDK_INT) ||
+        AndroidVersions.CURRENT.getSdkInt() >= V.SDK_INT;
   }
 
   @ForType(DefaultNativeRuntimeLoader.class)
@@ -299,6 +310,7 @@ public class AndroidNativeRuntimeLoader extends DefaultNativeRuntimeLoader {
 
     boolean isSupported();
     void maybeCopyFonts(TempDirectory tempDirectory);
-    String nativeLibraryPath();
+    String osName();
+    String arch();
   }
 }
diff --git a/plugins/src/main/java/org/robolectric/android/plugins/AndroidSQLiteModeConfigurer.java b/plugins/src/main/java/org/robolectric/android/plugins/AndroidSQLiteModeConfigurer.java
index b66fd80..2ca64c1 100644
--- a/plugins/src/main/java/org/robolectric/android/plugins/AndroidSQLiteModeConfigurer.java
+++ b/plugins/src/main/java/org/robolectric/android/plugins/AndroidSQLiteModeConfigurer.java
@@ -24,7 +24,7 @@ import org.robolectric.pluginapi.config.Configurer;
 import org.robolectric.plugins.SQLiteModeConfigurer;
 import org.robolectric.plugins.PackagePropertiesLoader;
 import org.robolectric.plugins.config.SingleValueConfigurer;
-import org.robolectric.util.inject.Supercedes;
+import org.robolectric.util.inject.Supersedes;
 
 /**
  * A {@link org.robolectric.pluginapi.config.Configurer} plugin for sqlite mode for Android. This
@@ -32,7 +32,7 @@ import org.robolectric.util.inject.Supercedes;
  * for Robolectric in AOSP.
  */
 @AutoService(Configurer.class)
-@Supercedes(SQLiteModeConfigurer.class)
+@Supersedes(SQLiteModeConfigurer.class)
 @Priority(Integer.MAX_VALUE)
 public class AndroidSQLiteModeConfigurer
     extends SingleValueConfigurer<SQLiteMode, SQLiteMode.Mode> {
diff --git a/scripts/run-android-test.sh b/scripts/run-android-test.sh
index d8f8180..5c0955a 100755
--- a/scripts/run-android-test.sh
+++ b/scripts/run-android-test.sh
@@ -57,12 +57,14 @@ java -cp $ANDROID_HOST_OUT_TESTCASES/$MODULE_NAME/$MODULE_NAME.jar:$ANDROID_HOST
     -Drobolectric.logging.enabled=true \
     -Drobolectric.offline=true \
     -Drobolectric.resourcesMode=BINARY \
+    -Drobolectric.graphicsMode=NATIVE \
     -Drobolectric.usePreinstrumentedJars=false \
-    -Drobolectric.enabledSdks=35 \
+    -Drobolectric.enabledSdks=36 \
     -Drobolectric.alwaysIncludeVariantMarkersInTestName=true \
     -Dandroid.robolectric.loadLibraryFromPath=true \
     -Djava.library.path=$ANDROID_HOST_OUT/lib64:/usr/java/packages/lib:/usr/lib64:/lib64:/lib:/usr/lib \
     -Drobolectric.sqliteMode=NATIVE \
+    --add-opens=java.base/java.io=ALL-UNNAMED \
     $DEBUGGER \
     org.junit.runner.JUnitCore \
-    $CLASS_NAME
\ No newline at end of file
+    $CLASS_NAME
```

