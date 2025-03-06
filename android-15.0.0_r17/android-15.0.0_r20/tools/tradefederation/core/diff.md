```diff
diff --git a/.classpath b/.classpath
index 5a5fe22a1..a7c1ebc54 100644
--- a/.classpath
+++ b/.classpath
@@ -1,6 +1,7 @@
 <?xml version="1.0" encoding="UTF-8"?>
 <classpath>
 	<classpathentry kind="src" path="src"/>
+	<classpathentry excluding="Android.bp|javatests/**" kind="src" path="avd_util"/>
 	<classpathentry excluding="Android.bp" kind="src" path="test_observatory"/>
 	<classpathentry excluding="Android.bp" kind="src" path="external_dependencies"/>
 	<classpathentry excluding="Android.bp" kind="src" path="isolation"/>
diff --git a/Android.bp b/Android.bp
index 7cab1f7e5..d141c952a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -27,7 +27,10 @@ java_library_host {
         "//tools/tradefederation/core/test_result_interfaces",
     ],
     srcs: ["proto/**/*.proto"],
-    exclude_srcs: ["proto/virtual_device_manager.proto"],
+    exclude_srcs: [
+        "proto/virtual_device_manager.proto",
+        "proto/resultdb/*",
+    ],
     libs: [
         "libprotobuf-java-full",
     ],
@@ -82,6 +85,23 @@ java_library_host {
     java_version: "11",
 }
 
+java_library_host {
+    name: "resultdb-protos",
+    srcs: ["proto/resultdb/*.proto"],
+    libs: [
+        "libprotobuf-java-full",
+        "googleapis-field-behavior-java-proto",
+    ],
+    proto: {
+        include_dirs: [
+            "external/protobuf/src",
+            "external/googleapis",
+        ],
+        type: "full",
+    },
+    java_version: "11",
+}
+
 java_library_host {
     name: "tradefed-invocation-grpc",
     srcs: [
@@ -169,7 +189,7 @@ java_library_host {
 }
 
 // Avoid version number in apk file name
-genrule {
+java_genrule {
     name: "test-services-normalized.apk",
     srcs: [":test-services.apk"],
     out: ["test-services-normalized.apk"],
@@ -177,7 +197,7 @@ genrule {
 }
 
 // Avoid version number in apk file name
-genrule {
+java_genrule {
     name: "test-orchestrator-normalized.apk",
     srcs: [":androidx.test.orchestrator"],
     out: ["test-orchestrator-normalized.apk"],
@@ -191,7 +211,7 @@ tradefed_java_library_host {
     java_resource_dirs: [
         "res",
     ],
-    java_resources: [
+    device_common_java_resources: [
         ":TradefedContentProvider",
         ":TelephonyUtility",
         ":WifiUtil",
@@ -201,6 +221,7 @@ tradefed_java_library_host {
     static_libs: [
         "tradefed-lib-core",
         "tradefed-test-framework",
+        "resultdb-protos",
     ],
     required: [
         "loganalysis",
@@ -386,8 +407,6 @@ java_genrule_host {
         "soong_zip",
     ],
     srcs: [
-        ":TradeFedTestApp",
-        ":TradeFedUiTestApp",
         ":compatibility-host-util",
         ":compatibility-tradefed",
         ":loganalysis",
@@ -399,6 +418,10 @@ java_genrule_host {
         "tools/content_uploader.py",
         "tradefed.sh",
     ],
+    device_common_srcs: [
+        ":TradeFedTestApp",
+        ":TradeFedUiTestApp",
+    ],
     uses_order_only_build_number_file: true,
     out: ["tradefed.zip"],
     dist: {
diff --git a/avd_util/Android.bp b/avd_util/Android.bp
index 65b962110..4729bd007 100644
--- a/avd_util/Android.bp
+++ b/avd_util/Android.bp
@@ -30,6 +30,7 @@ java_library_host {
     static_libs: [
         "tradefed-common-util",
         "virtual-device-manager-proto",
+        "gson",
     ],
     libs: [
         "ddmlib-prebuilt",
@@ -58,6 +59,7 @@ tradefed_java_library_host {
         "virtual-device-manager-proto",
         "junit-host",
         "mockito",
+        "objenesis",
     ],
     libs: [
         "guava",
diff --git a/avd_util/com/android/tradefed/util/avd/HostOrchestratorClient.java b/avd_util/com/android/tradefed/util/avd/HostOrchestratorClient.java
new file mode 100644
index 000000000..236d40854
--- /dev/null
+++ b/avd_util/com/android/tradefed/util/avd/HostOrchestratorClient.java
@@ -0,0 +1,100 @@
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
+package com.android.tradefed.util.avd;
+
+import com.google.gson.Gson;
+
+import java.io.IOException;
+import java.net.URI;
+import java.net.http.HttpClient;
+import java.net.http.HttpRequest;
+import java.net.http.HttpResponse;
+import java.net.http.HttpResponse.BodyHandlers;
+
+/**
+ * Java implementation of Cuttlefish Host Orchestator API.
+ *
+ * <p>- Endpoints:
+ * https://github.com/google/android-cuttlefish/blob/main/frontend/src/host_orchestrator/orchestrator/controller.go#L56-L102
+ * - Objects:
+ * https://github.com/google/android-cuttlefish/blob/main/frontend/src/host_orchestrator/api/v1/messages.go
+ */
+public class HostOrchestratorClient {
+
+    // https://github.com/google/android-cuttlefish/blob/main/frontend/src/host_orchestrator/api/v1/messages.go#L104
+    public static final class Operation {
+        public String name;
+        public boolean done;
+    }
+
+    // https://github.com/google/android-cuttlefish/blob/fff7e3487c924435e6f6120345edf1dddb49d50b/frontend/src/host_orchestrator/orchestrator/controller.go#L78
+    public static HttpRequest buildGetOperationRequest(String baseURL, String name) {
+        return HttpRequest.newBuilder()
+                .uri(URI.create(String.format("%s/operations/%s", baseURL, name)))
+                .build();
+    }
+
+    public static interface IHoHttpClient {
+        HttpResponse<String> send(HttpRequest request)
+                throws IOException, InterruptedException, ErrorResponseException;
+    }
+
+    public static final class HoHttpClient implements IHoHttpClient {
+        private final HttpClient mClient;
+
+        public HoHttpClient() {
+            mClient = HttpClient.newBuilder().build();
+        }
+
+        @Override
+        public HttpResponse<String> send(HttpRequest request)
+                throws IOException, InterruptedException, ErrorResponseException {
+            return mClient.send(request, BodyHandlers.ofString());
+        }
+    }
+
+    public static final class ErrorResponseException extends Exception {
+        private final int mStatusCode;
+        private final String mBody;
+
+        public ErrorResponseException(int statusCode, String body) {
+            super(
+                    String.format(
+                            "error response with status code: %d, response body: %s",
+                            statusCode, body));
+            mStatusCode = statusCode;
+            mBody = body;
+        }
+
+        public int getStatusCode() {
+            return mStatusCode;
+        }
+
+        public String getBody() {
+            return mBody;
+        }
+    }
+
+    public static <T> T sendRequest(
+        IHoHttpClient client, HttpRequest request, Class<T> responseClass)
+            throws IOException, InterruptedException, ErrorResponseException {
+        HttpResponse<String> res = client.send(request);
+        if (res.statusCode() != 200) {
+            throw new ErrorResponseException(res.statusCode(), res.body());
+        }
+        return new Gson().fromJson(res.body(), responseClass);
+    }
+}
diff --git a/avd_util/com/android/tradefed/util/avd/HostOrchestratorUtil.java b/avd_util/com/android/tradefed/util/avd/HostOrchestratorUtil.java
index d2c3c8ef9..5b68dea9e 100644
--- a/avd_util/com/android/tradefed/util/avd/HostOrchestratorUtil.java
+++ b/avd_util/com/android/tradefed/util/avd/HostOrchestratorUtil.java
@@ -15,6 +15,13 @@
  */
 package com.android.tradefed.util.avd;
 
+import static com.android.tradefed.util.avd.HostOrchestratorClient.ErrorResponseException;
+import static com.android.tradefed.util.avd.HostOrchestratorClient.HoHttpClient;
+import static com.android.tradefed.util.avd.HostOrchestratorClient.IHoHttpClient;
+import static com.android.tradefed.util.avd.HostOrchestratorClient.Operation;
+import static com.android.tradefed.util.avd.HostOrchestratorClient.buildGetOperationRequest;
+import static com.android.tradefed.util.avd.HostOrchestratorClient.sendRequest;
+
 import com.android.ddmlib.Log.LogLevel;
 import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.util.CommandResult;
@@ -35,6 +42,7 @@ import org.json.JSONTokener;
 import java.io.File;
 import java.io.FileOutputStream;
 import java.io.IOException;
+import java.net.http.HttpRequest;
 import java.nio.file.Files;
 import java.util.ArrayList;
 import java.util.List;
@@ -47,15 +55,13 @@ public class HostOrchestratorUtil {
             "_journal/entries?_SYSTEMD_UNIT=cuttlefish-host_orchestrator.service";
     public static final String URL_OXYGEN_CONTAINER_LOG = "_journal/entries?CONTAINER_NAME=oxygen";
     private static final long CMD_TIMEOUT_MS = 5 * 6 * 1000 * 10; // 5 min
-    private static final long WAIT_FOR_OPERATION_MS = 5 * 6 * 1000; // 30 sec
+    private static final long WAIT_FOR_OPERATION_MS = 5 * 1000; // 5 sec
     private static final long WAIT_FOR_OPERATION_TIMEOUT_MS = 5 * 6 * 1000 * 10; // 5 min
     private static final String CVD_HOST_LOGZ = "cvd_hostlog_zip";
     private static final String URL_CVD_DEVICE_LOG = "cvds/%s/:bugreport";
     private static final String URL_CVD_BUGREPORTS = "cvdbugreports/%s";
-    private static final String URL_HO_BASE = "http://%s:%s/%s";
     private static final String URL_HO_POWERWASH = "cvds/%s/%s/:powerwash";
     private static final String URL_HO_STOP = "cvds/%s/%s";
-    private static final String URL_QUERY_OPERATION = "operations/%s";
     private static final String URL_QUERY_OPERATION_RESULT = "operations/%s/result";
     private static final String UNSUPPORTED_API_RESPONSE = "404 page not found";
 
@@ -77,6 +83,7 @@ public class HostOrchestratorUtil {
     private String mAccountingUser;
     private Map<String, String> mExtraOxygenArgs;
     private OxygenClient mOxygenClient;
+    private IHoHttpClient mHttpClient;
 
     public HostOrchestratorUtil(
             boolean useOxygenation,
@@ -95,6 +102,28 @@ public class HostOrchestratorUtil {
         mTargetRegion = targetRegion;
         mAccountingUser = accountingUser;
         mOxygenClient = oxygenClient;
+        mHttpClient = new HoHttpClient();
+    }
+
+    public HostOrchestratorUtil(
+            boolean useOxygenation,
+            Map<String, String> extraOxygenArgs,
+            String instanceName,
+            String host,
+            String oxygenationDeviceId,
+            String targetRegion,
+            String accountingUser,
+            OxygenClient oxygenClient,
+            IHoHttpClient httpClient) {
+        mUseOxygenation = useOxygenation;
+        mExtraOxygenArgs = extraOxygenArgs;
+        mInstanceName = instanceName;
+        mHost = host;
+        mOxygenationDeviceId = oxygenationDeviceId;
+        mTargetRegion = targetRegion;
+        mAccountingUser = accountingUser;
+        mOxygenClient = oxygenClient;
+        mHttpClient = httpClient;
     }
 
     /**
@@ -175,6 +204,7 @@ public class HostOrchestratorUtil {
             String cvdGroup = parseListCvdOutput(curlRes.getStdout(), "group");
             curlRes =
                     cvdOperationExecution(
+                            mHttpClient,
                             portNumber,
                             "POST",
                             String.format(URL_CVD_DEVICE_LOG, cvdGroup),
@@ -201,7 +231,7 @@ public class HostOrchestratorUtil {
                 return null;
             }
             cvdLogsDir = ZipUtil2.extractZipToTemp(cvdLogsZip, "cvd_logs");
-        } catch (IOException e) {
+        } catch (IOException | InterruptedException | ErrorResponseException e) {
             CLog.e("Failed pulling cvd host logs via Host Orchestrator: %s", e);
         } finally {
             if (mUseOxygenation) {
@@ -288,6 +318,7 @@ public class HostOrchestratorUtil {
             }
             curlRes =
                     cvdOperationExecution(
+                            mHttpClient,
                             portNumber,
                             "POST",
                             String.format(URL_HO_POWERWASH, cvdGroup, cvdName),
@@ -295,7 +326,7 @@ public class HostOrchestratorUtil {
             if (!CommandStatus.SUCCESS.equals(curlRes.getStatus())) {
                 CLog.e("Failed powerwashing cvd via Host Orchestrator: %s", curlRes.getStdout());
             }
-        } catch (IOException e) {
+        } catch (IOException | InterruptedException | ErrorResponseException e) {
             CLog.e("Failed powerwashing gce via Host Orchestrator: %s", e);
         } finally {
             if (mUseOxygenation) {
@@ -339,6 +370,7 @@ public class HostOrchestratorUtil {
             }
             curlRes =
                     cvdOperationExecution(
+                            mHttpClient,
                             portNumber,
                             "DELETE",
                             String.format(URL_HO_STOP, cvdGroup, cvdName),
@@ -346,7 +378,7 @@ public class HostOrchestratorUtil {
             if (!CommandStatus.SUCCESS.equals(curlRes.getStatus())) {
                 CLog.e("Failed stopping gce via Host Orchestrator: %s", curlRes.getStdout());
             }
-        } catch (IOException e) {
+        } catch (IOException | InterruptedException | ErrorResponseException e) {
             CLog.e("Failed stopping gce via Host Orchestrator: %s", e);
         } finally {
             if (mUseOxygenation) {
@@ -368,6 +400,12 @@ public class HostOrchestratorUtil {
         return new CommandResult(CommandStatus.EXCEPTION);
     }
 
+    /** Attempt to delete snapshot of a Cuttlefish instance via Host Orchestrator. */
+    public CommandResult deleteSnapshotGce(String snapshotId) {
+        // TODO(b/339304559): Flesh out this section when the host orchestrator is supported.
+        return new CommandResult(CommandStatus.EXCEPTION);
+    }
+
     /**
      * Create Host Orchestrator Tunnel with a given port number.
      *
@@ -420,11 +458,7 @@ public class HostOrchestratorUtil {
         cmd.add("-v");
         cmd.add("-X");
         cmd.add(method);
-        if (mUseOxygenation) {
-            cmd.add(String.format(URL_HO_BASE, "127.0.0.1", portNumber, api));
-        } else {
-            cmd.add(String.format(URL_HO_BASE, mHost, portNumber, api));
-        }
+        cmd.add(getHOBaseUrl(portNumber) + "/"  + api);
         for (String cmdOption : commands) {
             cmd.add(cmdOption);
         }
@@ -497,24 +531,24 @@ public class HostOrchestratorUtil {
      */
     @VisibleForTesting
     CommandResult cvdOperationExecution(
-            String portNumber, String method, String request, long maxWaitTime) {
+            IHoHttpClient client,
+            String portNumber,
+            String method,
+            String request,
+            long maxWaitTime)
+            throws IOException, InterruptedException, ErrorResponseException {
         CommandResult commandRes = curlCommandExecution(portNumber, method, request, true);
         if (!CommandStatus.SUCCESS.equals(commandRes.getStatus())) {
             CLog.e("Failed running %s, error: %s", request, commandRes.getStdout());
             return commandRes;
         }
-
         String operationId = parseCvdContent(commandRes.getStdout(), "name");
         long maxEndTime = System.currentTimeMillis() + maxWaitTime;
         while (System.currentTimeMillis() < maxEndTime) {
-            commandRes =
-                    curlCommandExecution(
-                            portNumber,
-                            "GET",
-                            String.format(URL_QUERY_OPERATION, operationId),
-                            true);
-            if (CommandStatus.SUCCESS.equals(commandRes.getStatus())
-                    && parseCvdContent(commandRes.getStdout(), "done").equals("true")) {
+            HttpRequest httpRequest =
+                buildGetOperationRequest(getHOBaseUrl(portNumber), operationId);
+            Operation op = sendRequest(client, httpRequest, Operation.class);
+            if (op.done) {
                 request = String.format(URL_QUERY_OPERATION_RESULT, operationId);
                 return curlCommandExecution(portNumber, "GET", request, true);
             }
@@ -543,4 +577,9 @@ public class HostOrchestratorUtil {
     public File getTunnelLog() {
         return mTunnelLog;
     }
+
+    String getHOBaseUrl(String port) {
+        String host = mUseOxygenation ? "127.0.0.1" : mHost;
+        return String.format("http://%s:%s", host, port);
+    }
 }
diff --git a/avd_util/com/android/tradefed/util/avd/LogCollector.java b/avd_util/com/android/tradefed/util/avd/LogCollector.java
index b81b72bdb..08067271f 100644
--- a/avd_util/com/android/tradefed/util/avd/LogCollector.java
+++ b/avd_util/com/android/tradefed/util/avd/LogCollector.java
@@ -72,6 +72,11 @@ public class LogCollector {
                                             new AbstractMap.SimpleEntry<>(
                                                     "E cvd     : fetch_cvd",
                                                     "fetch_cvd_failure_general")),
+                                    new AbstractMap.SimpleEntry<>(
+                                            Pattern.compile(".*vdl_stdout.*"),
+                                            new AbstractMap.SimpleEntry<>(
+                                                    "Could not resolve host: ",
+                                                    "fetch_cvd_failure_resolve_host")),
                                     new AbstractMap.SimpleEntry<>(
                                             Pattern.compile(".*launcher.*"),
                                             new AbstractMap.SimpleEntry<>(
@@ -108,7 +113,20 @@ public class LogCollector {
                                             new AbstractMap.SimpleEntry<>(
                                                     "mkdir failed: errno 117 (Structure needs"
                                                             + " cleaning)",
-                                                    "filesystem_corrupt")))
+                                                    "filesystem_corrupt")),
+                                    new AbstractMap.SimpleEntry<>(
+                                            Pattern.compile(".*kernel.*"),
+                                            new AbstractMap.SimpleEntry<>(
+                                                    "Kernel panic - not syncing: VFS: Unable to"
+                                                            + " mount root fs on unknown-block",
+                                                    "cf_ramdisk_mount_failure")),
+                                    new AbstractMap.SimpleEntry<>(
+                                            Pattern.compile(".*launcher.*"),
+                                            new AbstractMap.SimpleEntry<>(
+                                                    "BluetoothShellCommand:"
+                                                        + " wait-for-state:STATE_OFF: Failed with"
+                                                        + " status=-1",
+                                                    "bluetooth_failed_to_stop")))
                             .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
 
     /**
diff --git a/avd_util/com/android/tradefed/util/avd/OxygenClient.java b/avd_util/com/android/tradefed/util/avd/OxygenClient.java
index d6f31f40c..7d435c395 100644
--- a/avd_util/com/android/tradefed/util/avd/OxygenClient.java
+++ b/avd_util/com/android/tradefed/util/avd/OxygenClient.java
@@ -30,6 +30,8 @@ import com.google.common.collect.Lists;
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.net.ServerSocket;
+import java.text.DateFormat;
+import java.text.SimpleDateFormat;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
@@ -429,16 +431,20 @@ public class OxygenClient {
         oxygenClientArgs.add("-device_id");
         oxygenClientArgs.add(oxygenationDeviceId);
         try {
+            DateFormat dateFormat = new SimpleDateFormat("MM/dd/yy HH:mm:SS");
             CLog.i(
                     "Building %s tunnel from oxygen client with command %s...",
                     mode, oxygenClientArgs.toString());
-            tunnelLog.write(String.format("\n=== Beginning ===\n").getBytes());
             tunnelLog.write(
-                    String.format("\n=== Session id: %s, Server URL: %s===\n", sessionId, serverUrl)
+                    String.format(
+                                    "\n===[%s]Session id: %s, Server URL: %s===\n",
+                                    dateFormat.format(System.currentTimeMillis()),
+                                    sessionId,
+                                    serverUrl)
                             .getBytes());
             lhpTunnel = getRunUtil().runCmdInBackground(oxygenClientArgs, tunnelLog);
             // TODO(b/363861223): reduce the waiting time when LHP is stable.
-            getRunUtil().sleep(15 * 1000);
+            getRunUtil().sleep(30 * 1000);
         } catch (IOException e) {
             CLog.d("Failed connecting to remote GCE using %s over LHP, %s", mode, e.getMessage());
         }
diff --git a/avd_util/javatests/com/android/tradefed/util/avd/HostOrchestratorClientTest.java b/avd_util/javatests/com/android/tradefed/util/avd/HostOrchestratorClientTest.java
new file mode 100644
index 000000000..8d68f57d7
--- /dev/null
+++ b/avd_util/javatests/com/android/tradefed/util/avd/HostOrchestratorClientTest.java
@@ -0,0 +1,139 @@
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
+package com.android.tradefed.util.avd;
+
+import static com.android.tradefed.util.avd.HostOrchestratorClient.ErrorResponseException;
+import static com.android.tradefed.util.avd.HostOrchestratorClient.Operation;
+import static com.android.tradefed.util.avd.HostOrchestratorClient.buildGetOperationRequest;
+import static com.android.tradefed.util.avd.HostOrchestratorClient.sendRequest;
+
+import org.junit.After;
+import org.junit.Assert;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Mock;
+import org.mockito.Mockito;
+import org.mockito.MockitoAnnotations;
+
+import java.net.URI;
+import java.net.http.HttpClient;
+import java.net.http.HttpHeaders;
+import java.net.http.HttpRequest;
+import java.net.http.HttpResponse;
+import java.util.Map;
+import java.util.Optional;
+
+import javax.net.ssl.SSLSession;
+
+/** Unit tests for {@link HostOrchestratorClient} */
+@RunWith(JUnit4.class)
+public class HostOrchestratorClientTest {
+
+    @Mock private HostOrchestratorClient.IHoHttpClient mFakeHttpClient;
+
+    @Before
+    public void setUp() throws Exception {
+        MockitoAnnotations.initMocks(this);
+    }
+
+    @After
+    public void tearDown() {}
+
+    @Test
+    public void testBuildGetOperationRequest() throws Exception {
+        HttpRequest r = buildGetOperationRequest("https://ho.test", "opfoo");
+
+        Assert.assertEquals("https://ho.test/operations/opfoo", r.uri().toString());
+    }
+
+    @Test
+    public void testSendRequestSucceeds() throws Exception {
+        String body = "{ \"name\":\"foo\", \"done\": \"true\" }";
+        HttpRequest request = buildGetOperationRequest("https://ho.test", "opfoo");
+        HttpResponse<String> response = buildFakeResponse(200, body);
+        Mockito.when(mFakeHttpClient.send(Mockito.any())).thenReturn(response);
+
+        Operation result = sendRequest(mFakeHttpClient, request, Operation.class);
+
+        Assert.assertEquals("foo", result.name);
+        Assert.assertTrue(result.done);
+    }
+
+    @Test
+    public void testSendRequestErrorResponse() throws Exception {
+        String body = "500 Internal Server Error";
+        HttpRequest request = buildGetOperationRequest("https://ho.test", "opfoo");
+        HttpResponse<String> response = buildFakeResponse(500, body);
+        Mockito.when(mFakeHttpClient.send(Mockito.any())).thenReturn(response);
+
+        ErrorResponseException mE = new ErrorResponseException(0, "");
+        try {
+            Operation result = sendRequest(mFakeHttpClient, request, Operation.class);
+        } catch (ErrorResponseException e) {
+            mE = e;
+        }
+
+        Assert.assertEquals(mE.getStatusCode(), 500);
+        Assert.assertEquals(mE.getBody(), body);
+    }
+
+    private static HttpResponse<String> buildFakeResponse(int statusCode, String body) {
+        return new HttpResponse<>() {
+            @Override
+            public int statusCode() {
+                return statusCode;
+            }
+
+            @Override
+            public HttpHeaders headers() {
+                return HttpHeaders.of(Map.of(), (a, b) -> true);
+            }
+
+            @Override
+            public String body() {
+                return body;
+            }
+
+            @Override
+            public Optional<HttpResponse<String>> previousResponse() {
+                return Optional.empty();
+            }
+
+            @Override
+            public HttpRequest request() {
+                return null;
+            }
+
+            @Override
+            public Optional<SSLSession> sslSession() {
+                return Optional.empty();
+            }
+
+            @Override
+            public URI uri() {
+                return null;
+            }
+
+            @Override
+            public HttpClient.Version version() {
+                return null;
+            }
+        };
+    }
+}
diff --git a/avd_util/javatests/com/android/tradefed/util/avd/HostOrchestratorUtilTest.java b/avd_util/javatests/com/android/tradefed/util/avd/HostOrchestratorUtilTest.java
index 07eaa4c66..c70b1f179 100644
--- a/avd_util/javatests/com/android/tradefed/util/avd/HostOrchestratorUtilTest.java
+++ b/avd_util/javatests/com/android/tradefed/util/avd/HostOrchestratorUtilTest.java
@@ -16,6 +16,8 @@
 
 package com.android.tradefed.util.avd;
 
+import static com.android.tradefed.util.avd.HostOrchestratorClient.IHoHttpClient;
+
 import static org.mockito.Mockito.times;
 
 import com.android.tradefed.util.CommandResult;
@@ -30,11 +32,22 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+import org.mockito.Mock;
 import org.mockito.Mockito;
+import org.mockito.MockitoAnnotations;
 
 import java.io.File;
 import java.io.OutputStream;
+import java.net.URI;
+import java.net.http.HttpClient;
+import java.net.http.HttpHeaders;
+import java.net.http.HttpRequest;
+import java.net.http.HttpResponse;
 import java.util.HashMap;
+import java.util.Map;
+import java.util.Optional;
+
+import javax.net.ssl.SSLSession;
 
 /** Unit tests for {@link HostOrchestratorUtil} */
 @RunWith(JUnit4.class)
@@ -49,6 +62,10 @@ public class HostOrchestratorUtilTest {
     private OxygenClient mMockClient;
     private IRunUtil mMockRunUtil;
     private Process mMockProcess;
+    private File mMockFile;
+
+    @Mock private HostOrchestratorClient.IHoHttpClient mMockHttpClient;
+
     private static final String LIST_CVD_RES =
             "{\"cvds\":[{\"group\":\"cvd_1\",\"name\":\"ins-1\",\"build_source\":{},"
                     + "\"status\":\"Running\",\"displays\":[\"720 x 1280 ( 320 )\"],"
@@ -68,6 +85,7 @@ public class HostOrchestratorUtilTest {
 
     @Before
     public void setUp() throws Exception {
+        MockitoAnnotations.initMocks(this);
         mExtraOxygenArgs = new HashMap<>();
         mExtraOxygenArgs.put("arg1", "value1");
         mMockClient = Mockito.mock(OxygenClient.class);
@@ -80,7 +98,6 @@ public class HostOrchestratorUtilTest {
         FileUtil.deleteFile(mHOUtil.getTunnelLog());
     }
 
-
     @Test
     public void testCreateHostOrchestratorTunnel_Oxygenation() throws Exception {
         mHOUtil =
@@ -92,7 +109,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient);
+                        mMockClient,
+                        mMockHttpClient);
         mHOUtil.createHostOrchestratorTunnel("1111");
         Mockito.verify(mMockClient, times(1))
                 .createTunnelViaLHP(
@@ -121,7 +139,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -179,7 +198,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -236,7 +256,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -249,7 +270,11 @@ public class HostOrchestratorUtilTest {
 
                     @Override
                     public CommandResult cvdOperationExecution(
-                            String portNumber, String method, String request, long maxWaitTime) {
+                            IHoHttpClient client,
+                            String portNumber,
+                            String method,
+                            String request,
+                            long maxWaitTime) {
                         CommandResult res = new CommandResult(CommandStatus.SUCCESS);
                         res.setStdout("operation_id");
                         return res;
@@ -326,7 +351,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -388,7 +414,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return null;
@@ -440,7 +467,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -453,7 +481,11 @@ public class HostOrchestratorUtilTest {
 
                     @Override
                     public CommandResult cvdOperationExecution(
-                            String portNumber, String method, String request, long maxWaitTime) {
+                            IHoHttpClient client,
+                            String portNumber,
+                            String method,
+                            String request,
+                            long maxWaitTime) {
                         CommandResult res = new CommandResult(CommandStatus.SUCCESS);
                         res.setStdout("operation_id");
                         return res;
@@ -507,7 +539,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -569,7 +602,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -608,20 +642,8 @@ public class HostOrchestratorUtilTest {
                         Mockito.eq("-X"),
                         Mockito.eq("POST"),
                         Mockito.eq("http://127.0.0.1:1111/cvds/cvd_1/ins-1/:powerwash"));
-        CommandResult operationRes = new CommandResult(CommandStatus.SUCCESS);
-        operationRes.setStdout(OPERATION_DONE_RES);
-        Mockito.doReturn(operationRes)
-                .when(mMockRunUtil)
-                .runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq((OutputStream) null),
-                        Mockito.eq((OutputStream) null),
-                        Mockito.eq("curl"),
-                        Mockito.eq("-0"),
-                        Mockito.eq("-v"),
-                        Mockito.eq("-X"),
-                        Mockito.eq("GET"),
-                        Mockito.eq("http://127.0.0.1:1111/operations/some_id"));
+        Mockito.when(mMockHttpClient.send(Mockito.any()))
+                .thenReturn(mockHttpResponse(200, OPERATION_DONE_RES));
         CommandResult successRes = new CommandResult(CommandStatus.SUCCESS);
         successRes.setStdout("operation_id");
         Mockito.doReturn(successRes)
@@ -674,7 +696,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return null;
@@ -723,7 +746,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -775,7 +799,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -827,7 +852,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -879,7 +905,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -918,20 +945,8 @@ public class HostOrchestratorUtilTest {
                         Mockito.eq("-X"),
                         Mockito.eq("DELETE"),
                         Mockito.eq("http://127.0.0.1:1111/cvds/cvd_1/ins-1"));
-        CommandResult operationRes = new CommandResult(CommandStatus.SUCCESS);
-        operationRes.setStdout(OPERATION_DONE_RES);
-        Mockito.doReturn(operationRes)
-                .when(mMockRunUtil)
-                .runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq((OutputStream) null),
-                        Mockito.eq((OutputStream) null),
-                        Mockito.eq("curl"),
-                        Mockito.eq("-0"),
-                        Mockito.eq("-v"),
-                        Mockito.eq("-X"),
-                        Mockito.eq("GET"),
-                        Mockito.eq("http://127.0.0.1:1111/operations/some_id"));
+        Mockito.when(mMockHttpClient.send(Mockito.any()))
+                .thenReturn(mockHttpResponse(200, OPERATION_DONE_RES));
         CommandResult successRes = new CommandResult(CommandStatus.SUCCESS);
         successRes.setStdout("operation_id");
         Mockito.doReturn(successRes)
@@ -984,7 +999,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return null;
@@ -1033,7 +1049,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -1085,7 +1102,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -1137,7 +1155,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -1187,7 +1206,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     protected IRunUtil getRunUtil() {
                         return mMockRunUtil;
@@ -1210,7 +1230,7 @@ public class HostOrchestratorUtilTest {
                         Mockito.eq("http://127.0.0.1:1111/request"));
         Assert.assertEquals(
                 CommandStatus.FAILED,
-                mHOUtil.cvdOperationExecution("1111", "POST", "request", 5).getStatus());
+                mHOUtil.cvdOperationExecution(null, "1111", "POST", "request", 5).getStatus());
     }
 
     @Test
@@ -1224,7 +1244,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     protected IRunUtil getRunUtil() {
                         return mMockRunUtil;
@@ -1244,20 +1265,8 @@ public class HostOrchestratorUtilTest {
                         Mockito.eq("-X"),
                         Mockito.eq("POST"),
                         Mockito.eq("http://127.0.0.1:1111/request"));
-        CommandResult operationRes = new CommandResult(CommandStatus.SUCCESS);
-        operationRes.setStdout(OPERATION_DONE_RES);
-        Mockito.doReturn(operationRes)
-                .when(mMockRunUtil)
-                .runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq((OutputStream) null),
-                        Mockito.eq((OutputStream) null),
-                        Mockito.eq("curl"),
-                        Mockito.eq("-0"),
-                        Mockito.eq("-v"),
-                        Mockito.eq("-X"),
-                        Mockito.eq("GET"),
-                        Mockito.eq("http://127.0.0.1:1111/operations/some_id"));
+        Mockito.when(mMockHttpClient.send(Mockito.any()))
+                .thenReturn(mockHttpResponse(200, OPERATION_DONE_RES));
         CommandResult failedRes = new CommandResult(CommandStatus.FAILED);
         failedRes.setStdout("some output");
         Mockito.doReturn(failedRes)
@@ -1274,7 +1283,8 @@ public class HostOrchestratorUtilTest {
                         Mockito.eq("http://127.0.0.1:1111/operations/some_id/result"));
         Assert.assertEquals(
                 CommandStatus.FAILED,
-                mHOUtil.cvdOperationExecution("1111", "POST", "request", 5).getStatus());
+                mHOUtil.cvdOperationExecution(mMockHttpClient, "1111", "POST", "request", 5)
+                        .getStatus());
     }
 
     @Test
@@ -1288,7 +1298,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     protected IRunUtil getRunUtil() {
                         return mMockRunUtil;
@@ -1308,20 +1319,8 @@ public class HostOrchestratorUtilTest {
                         Mockito.eq("-X"),
                         Mockito.eq("POST"),
                         Mockito.eq("http://127.0.0.1:1111/request"));
-        CommandResult operationRes = new CommandResult(CommandStatus.SUCCESS);
-        operationRes.setStdout(OPERATION_DONE_RES);
-        Mockito.doReturn(operationRes)
-                .when(mMockRunUtil)
-                .runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq((OutputStream) null),
-                        Mockito.eq((OutputStream) null),
-                        Mockito.eq("curl"),
-                        Mockito.eq("-0"),
-                        Mockito.eq("-v"),
-                        Mockito.eq("-X"),
-                        Mockito.eq("GET"),
-                        Mockito.eq("http://127.0.0.1:1111/operations/some_id"));
+        Mockito.when(mMockHttpClient.send(Mockito.any()))
+                .thenReturn(mockHttpResponse(200, OPERATION_DONE_RES));
         CommandResult successRes = new CommandResult(CommandStatus.SUCCESS);
         successRes.setStdout("operation_id");
         Mockito.doReturn(successRes)
@@ -1338,7 +1337,8 @@ public class HostOrchestratorUtilTest {
                         Mockito.eq("http://127.0.0.1:1111/operations/some_id/result"));
         Assert.assertEquals(
                 "operation_id",
-                mHOUtil.cvdOperationExecution("1111", "POST", "request", 5).getStdout());
+                mHOUtil.cvdOperationExecution(mMockHttpClient, "1111", "POST", "request", 5)
+                        .getStdout());
     }
 
     @Test
@@ -1352,7 +1352,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     protected IRunUtil getRunUtil() {
                         return mMockRunUtil;
@@ -1372,23 +1373,12 @@ public class HostOrchestratorUtilTest {
                         Mockito.eq("-X"),
                         Mockito.eq("POST"),
                         Mockito.eq("http://127.0.0.1:1111/request"));
-        CommandResult operationRes = new CommandResult(CommandStatus.SUCCESS);
-        commandRes.setStdout(OPERATION_TIMEOUT_RES);
-        Mockito.doReturn(commandRes)
-                .when(mMockRunUtil)
-                .runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq((OutputStream) null),
-                        Mockito.eq((OutputStream) null),
-                        Mockito.eq("curl"),
-                        Mockito.eq("-0"),
-                        Mockito.eq("-v"),
-                        Mockito.eq("-X"),
-                        Mockito.eq("GET"),
-                        Mockito.eq("http://127.0.0.1:1111/operations/some_id"));
+        Mockito.when(mMockHttpClient.send(Mockito.any()))
+                .thenReturn(mockHttpResponse(200, OPERATION_TIMEOUT_RES));
         Assert.assertEquals(
                 CommandStatus.TIMED_OUT,
-                mHOUtil.cvdOperationExecution("1111", "POST", "request", 5).getStatus());
+                mHOUtil.cvdOperationExecution(mMockHttpClient, "1111", "POST", "request", 5)
+                        .getStatus());
     }
 
     @Test
@@ -1402,7 +1392,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient);
+                        mMockClient,
+                        mMockHttpClient);
         Assert.assertEquals("cvd_1", mHOUtil.parseListCvdOutput(LIST_CVD_RES, "group"));
     }
 
@@ -1417,7 +1408,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient);
+                        mMockClient,
+                        null);
         Assert.assertEquals("", mHOUtil.parseListCvdOutput(LIST_CVD_BADRES, "group"));
     }
 
@@ -1434,7 +1426,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -1476,7 +1469,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return mMockProcess;
@@ -1519,7 +1513,8 @@ public class HostOrchestratorUtilTest {
                         OXYGENATION_DEVICE_ID,
                         TARGET_REGION,
                         ACCOUNTING_USER,
-                        mMockClient) {
+                        mMockClient,
+                        mMockHttpClient) {
                     @Override
                     public Process createHostOrchestratorTunnel(String portNumber) {
                         return null;
@@ -1533,4 +1528,48 @@ public class HostOrchestratorUtilTest {
         Assert.assertFalse(mHOUtil.deviceBootCompleted(10));
         Mockito.verify(mMockClient, times(1)).closeLHPConnection(null);
     }
+
+    private static HttpResponse<String> mockHttpResponse(int statusCode, String body) {
+        return new HttpResponse<>() {
+            @Override
+            public int statusCode() {
+                return statusCode;
+            }
+
+            @Override
+            public HttpHeaders headers() {
+                return HttpHeaders.of(Map.of(), (a, b) -> true);
+            }
+
+            @Override
+            public String body() {
+                return body;
+            }
+
+            @Override
+            public Optional<HttpResponse<String>> previousResponse() {
+                return Optional.empty();
+            }
+
+            @Override
+            public HttpRequest request() {
+                return null;
+            }
+
+            @Override
+            public Optional<SSLSession> sslSession() {
+                return Optional.empty();
+            }
+
+            @Override
+            public URI uri() {
+                return null;
+            }
+
+            @Override
+            public HttpClient.Version version() {
+                return null;
+            }
+        };
+    }
 }
diff --git a/common_util/com/android/tradefed/cache/ExecutableAction.java b/common_util/com/android/tradefed/cache/ExecutableAction.java
index 1569debdc..240298d72 100644
--- a/common_util/com/android/tradefed/cache/ExecutableAction.java
+++ b/common_util/com/android/tradefed/cache/ExecutableAction.java
@@ -16,6 +16,8 @@
 
 package com.android.tradefed.cache;
 
+import com.android.tradefed.invoker.tracing.CloseableTraceScope;
+
 import build.bazel.remote.execution.v2.Action;
 import build.bazel.remote.execution.v2.Command;
 import build.bazel.remote.execution.v2.Command.EnvironmentVariable;
@@ -46,55 +48,46 @@ public abstract class ExecutableAction {
     public static ExecutableAction create(
             File input, Iterable<String> args, Map<String, String> envVariables, long timeout)
             throws IOException {
+        try (CloseableTraceScope ignored = new CloseableTraceScope("create_executable_action")) {
+            Command command =
+                    Command.newBuilder()
+                            .addAllArguments(args)
+                            .setPlatform(
+                                    Platform.newBuilder()
+                                            .addProperties(
+                                                    Property.newBuilder()
+                                                            .setName("cache-silo-key")
+                                                            .setValue(SILO_CACHE_KEY)
+                                                            .build())
+                                            .build())
+                            .addAllEnvironmentVariables(
+                                    envVariables.entrySet().stream()
+                                            .map(
+                                                    entry ->
+                                                            EnvironmentVariable.newBuilder()
+                                                                    .setName(entry.getKey())
+                                                                    .setValue(entry.getValue())
+                                                                    .build())
+                                            .collect(Collectors.toList()))
+                            .build();
 
-        Command command =
-                Command.newBuilder()
-                        .addAllArguments(args)
-                        .setPlatform(
-                                Platform.newBuilder()
-                                        .addProperties(
-                                                Property.newBuilder()
-                                                        .setName(
-                                                                String.format(
-                                                                        "%s(%s)",
-                                                                        System.getProperty(
-                                                                                "os.name"),
-                                                                        System.getProperty(
-                                                                                "os.version")))
-                                                        .build())
-                                        .addProperties(
-                                                Property.newBuilder()
-                                                        .setName("cache-silo-key")
-                                                        .setValue(SILO_CACHE_KEY)
-                                                        .build())
-                                        .build())
-                        .addAllEnvironmentVariables(
-                                envVariables.entrySet().stream()
-                                        .map(
-                                                entry ->
-                                                        EnvironmentVariable.newBuilder()
-                                                                .setName(entry.getKey())
-                                                                .setValue(entry.getValue())
-                                                                .build())
-                                        .collect(Collectors.toList()))
-                        .build();
+            MerkleTree inputMerkleTree = MerkleTree.buildFromDir(input);
+            Action.Builder actionBuilder =
+                    Action.newBuilder()
+                            .setInputRootDigest(inputMerkleTree.rootDigest())
+                            .setCommandDigest(DigestCalculator.compute(command));
+            if (timeout > 0L) {
+                actionBuilder.setTimeout(Duration.newBuilder().setSeconds(timeout).build());
+            }
 
-        MerkleTree inputMerkleTree = MerkleTree.buildFromDir(input);
-        Action.Builder actionBuilder =
-                Action.newBuilder()
-                        .setInputRootDigest(inputMerkleTree.rootDigest())
-                        .setCommandDigest(DigestCalculator.compute(command));
-        if (timeout > 0L) {
-            actionBuilder.setTimeout(Duration.newBuilder().setSeconds(timeout).build());
+            Action action = actionBuilder.build();
+            return new AutoValue_ExecutableAction(
+                    action,
+                    DigestCalculator.compute(action),
+                    command,
+                    DigestCalculator.compute(command),
+                    inputMerkleTree);
         }
-
-        Action action = actionBuilder.build();
-        return new AutoValue_ExecutableAction(
-                action,
-                DigestCalculator.compute(action),
-                command,
-                DigestCalculator.compute(command),
-                inputMerkleTree);
     }
 
     public abstract Action action();
diff --git a/common_util/com/android/tradefed/cache/remote/Chunker.java b/common_util/com/android/tradefed/cache/remote/Chunker.java
index 7dfb228f3..0ce7f88aa 100644
--- a/common_util/com/android/tradefed/cache/remote/Chunker.java
+++ b/common_util/com/android/tradefed/cache/remote/Chunker.java
@@ -19,6 +19,7 @@ package com.android.tradefed.cache.remote;
 import static java.lang.Math.min;
 
 import com.google.protobuf.ByteString;
+
 import java.io.IOException;
 import java.io.InputStream;
 import java.util.NoSuchElementException;
@@ -53,14 +54,12 @@ public final class Chunker {
 
     private InputStream mBlob;
     private long mSize;
-    private int mChunkSize;
     private long mOffset;
     private byte[] mChunkBuffer;
 
     public Chunker(InputStream blob, long size, int chunkSize) {
         mBlob = blob;
         mSize = size;
-        mChunkSize = chunkSize;
         mOffset = 0;
         mChunkBuffer = new byte[(int) min(size, chunkSize)];
     }
diff --git a/common_util/com/android/tradefed/error/HarnessRuntimeException.java b/common_util/com/android/tradefed/error/HarnessRuntimeException.java
index 164b528c2..e1ae012ff 100644
--- a/common_util/com/android/tradefed/error/HarnessRuntimeException.java
+++ b/common_util/com/android/tradefed/error/HarnessRuntimeException.java
@@ -48,8 +48,23 @@ public class HarnessRuntimeException extends RuntimeException implements IHarnes
      * @param cause The {@link IHarnessException} that caused the exception.
      */
     public HarnessRuntimeException(String message, IHarnessException cause) {
+        this(message, null, cause);
+    }
+
+    /**
+     * Constructor for the exception.
+     *
+     * @param message The message associated with the exception.
+     * @param defaultError the {@link ErrorIdentifier} to apply if not set in the exception.
+     * @param cause The {@link IHarnessException} that caused the exception.
+     */
+    public HarnessRuntimeException(
+            String message, ErrorIdentifier defaultError, IHarnessException cause) {
         super(message, (cause instanceof Throwable) ? (Throwable) cause : null);
         mErrorId = cause.getErrorId();
+        if (mErrorId == null) {
+            mErrorId = defaultError;
+        }
         mOrigin = cause.getOrigin();
     }
 
diff --git a/common_util/com/android/tradefed/invoker/logger/InvocationMetricLogger.java b/common_util/com/android/tradefed/invoker/logger/InvocationMetricLogger.java
index 493d98593..dae741783 100644
--- a/common_util/com/android/tradefed/invoker/logger/InvocationMetricLogger.java
+++ b/common_util/com/android/tradefed/invoker/logger/InvocationMetricLogger.java
@@ -256,6 +256,8 @@ public class InvocationMetricLogger {
         // CAS downloader metrics
         CAS_VERSION("cas_version", false),
         CAS_DOWNLOAD_ERRORS("cas_download_errors", true),
+        CAS_DOWNLOAD_ERROR_FILES("cas_download_error_files", true),
+        CAS_DOWNLOAD_ERROR_BUILD_ID("cas_download_error_build_id", true),
         // Name of files downloaded by CAS downloader.
         CAS_DOWNLOAD_FILES("cas_download_files", true),
         CAS_DOWNLOAD_FILE_SUCCESS_COUNT("cas_download_file_success_count", true),
@@ -362,6 +364,7 @@ public class InvocationMetricLogger {
                 "incremental_snapuserd_write_blocking_time", true),
         INCREMENTAL_FALLBACK_REASON("incremental_fallback_reason", true),
         INCREMENTAL_RECOVERY_FALLBACK("incremental_recovery_fallback", true),
+        INCREMENTAL_FIRST_BOOTLOADER_REBOOT_FAIL("incremental_first_bootloader_reboot_fail", true),
         INCREMENTAL_NEW_FLOW("incremental_new_flow", true),
         DEVICE_IMAGE_CACHE_MISMATCH("device_image_cache_mismatch", true),
         DEVICE_IMAGE_CACHE_ORIGIN("device_image_cache_origin", true),
@@ -402,10 +405,17 @@ public class InvocationMetricLogger {
 
         // Test caching metrics
         CACHED_MODULE_RESULTS_COUNT("cached_module_results_count", true),
+        DEVICE_IMAGE_HASH("device_image_hash", false),
 
         // Module level caching
+        MODULE_CACHE_UPLOAD_ERROR("module_cache_upload_error", true),
+        MODULE_CACHE_UPLOAD_TIME("module_cache_upload_time", true),
+        MODULE_CACHE_DOWNLOAD_ERROR("module_cache_download_error", true),
+        MODULE_CACHE_DOWNLOAD_TIME("module_cache_download_time", true),
         MODULE_RESULTS_CHECKING_CACHE("module_results_checking_cache", true),
         MODULE_RESULTS_CACHE_HIT("module_results_cache_hit", true),
+        MODULE_CACHE_HIT_ID("module_cache_hit_id", true),
+        MODULE_CACHE_MISS_ID("module_cache_miss_id", true),
         MODULE_CACHE_NO_DIR("module_cache_no_dir", true),
         MODULE_RESULTS_CACHE_DEVICE_MISMATCH("module_results_cache_device_mismatch", true),
         ;
diff --git a/common_util/com/android/tradefed/result/LogDataType.java b/common_util/com/android/tradefed/result/LogDataType.java
index 98d73c3b3..2ea41bc04 100644
--- a/common_util/com/android/tradefed/result/LogDataType.java
+++ b/common_util/com/android/tradefed/result/LogDataType.java
@@ -92,6 +92,7 @@ public enum LogDataType {
     ADB_HOST_LOG("txt", "text/plain", true, true),
     PASSED_TESTS("txt", "text/plain", true, true),
     RECOVERY_MODE_LOG("txt", "text/plain", false, true),
+    CONNDIAG("txt", "text/plain", false, true), // Connectivity diagnostics
     GOLDEN_RESULT_PROTO(
             "textproto",
             "text/plain",
diff --git a/common_util/com/android/tradefed/result/error/DeviceErrorIdentifier.java b/common_util/com/android/tradefed/result/error/DeviceErrorIdentifier.java
index 774899fe9..9eb7ee08b 100644
--- a/common_util/com/android/tradefed/result/error/DeviceErrorIdentifier.java
+++ b/common_util/com/android/tradefed/result/error/DeviceErrorIdentifier.java
@@ -45,6 +45,8 @@ public enum DeviceErrorIdentifier implements ErrorIdentifier {
     DEVICE_FAILED_TO_SUSPEND(520_109, FailureStatus.DEPENDENCY_ISSUE),
     DEVICE_FAILED_TO_RESUME(520_110, FailureStatus.DEPENDENCY_ISSUE),
     DEVICE_FAILED_TO_STOP(520_111, FailureStatus.DEPENDENCY_ISSUE),
+    DEVICE_FAILED_TO_RESTORE_SNAPSHOT_NOT_ENOUGH_SPACE(520_112, FailureStatus.DEPENDENCY_ISSUE),
+    DEVICE_FAILED_TO_DELETE_SNAPSHOT(520_113, FailureStatus.DEPENDENCY_ISSUE),
 
     INSTRUMENTATION_CRASH(520_200, FailureStatus.SYSTEM_UNDER_TEST_CRASHED),
     ADB_DISCONNECT(520_201, FailureStatus.DEPENDENCY_ISSUE),
diff --git a/common_util/com/android/tradefed/result/error/TestErrorIdentifier.java b/common_util/com/android/tradefed/result/error/TestErrorIdentifier.java
index 0a9d417d3..c16e0de27 100644
--- a/common_util/com/android/tradefed/result/error/TestErrorIdentifier.java
+++ b/common_util/com/android/tradefed/result/error/TestErrorIdentifier.java
@@ -35,7 +35,8 @@ public enum TestErrorIdentifier implements ErrorIdentifier {
     HOST_COMMAND_FAILED(530_012, FailureStatus.CUSTOMER_ISSUE),
     TEST_PHASE_TIMED_OUT(530_013, FailureStatus.TIMED_OUT),
     TEST_FILTER_NEEDS_UPDATE(530_014, FailureStatus.SYSTEM_UNDER_TEST_CRASHED),
-    TEST_TIMEOUT(530_015, FailureStatus.TIMED_OUT);
+    TEST_TIMEOUT(530_015, FailureStatus.TIMED_OUT),
+    SUBPROCESS_UNCATEGORIZED_EXCEPTION(530_016, FailureStatus.CUSTOMER_ISSUE);
 
     private final long code;
     private final @Nonnull FailureStatus status;
diff --git a/common_util/com/android/tradefed/util/FileUtil.java b/common_util/com/android/tradefed/util/FileUtil.java
index fc8d1e596..47843a661 100644
--- a/common_util/com/android/tradefed/util/FileUtil.java
+++ b/common_util/com/android/tradefed/util/FileUtil.java
@@ -725,14 +725,13 @@ public class FileUtil {
         // Based on empirical testing File.getUsableSpace is a low cost operation (~ 100 us for
         // local disk, ~ 100 ms for network disk). Therefore call it every time tmp file is
         // created
-        long usableSpace = 0L;
         File toCheck = file;
         if (!file.isDirectory() && file.getParentFile() != null) {
             // If the given file is not a directory it might not work properly so using the parent
             // in that case.
             toCheck = file.getParentFile();
         }
-        usableSpace = toCheck.getUsableSpace();
+        long usableSpace = toCheck.getUsableSpace();
 
         long minDiskSpace = mMinDiskSpaceMb * 1024 * 1024;
         if (usableSpace < minDiskSpace) {
@@ -969,11 +968,11 @@ public class FileUtil {
      *
      * @param rootDir the root directory to search in
      * @param relativeParent An optional parent for all {@link File}s returned. If not specified,
-     *            all {@link File}s will be relative to {@code rootDir}.
+     *     all {@link File}s will be relative to {@code rootDir}.
      * @return An set of {@link File}s, representing all directories under {@code rootDir},
-     *         including {@code rootDir} itself. If {@code rootDir} is null, an empty set is
-     *         returned.
+     *     including {@code rootDir} itself. If {@code rootDir} is null, an empty set is returned.
      */
+    @Deprecated
     public static Set<File> findDirsUnder(File rootDir, File relativeParent) {
         Set<File> dirs = new HashSet<File>();
         if (rootDir != null) {
diff --git a/common_util/com/android/tradefed/util/IRunUtil.java b/common_util/com/android/tradefed/util/IRunUtil.java
index 1a64e4d4b..93deb0ac9 100644
--- a/common_util/com/android/tradefed/util/IRunUtil.java
+++ b/common_util/com/android/tradefed/util/IRunUtil.java
@@ -17,8 +17,6 @@
 package com.android.tradefed.util;
 
 import com.android.annotations.Nullable;
-import com.android.tradefed.cache.ExecutableActionResult;
-import com.android.tradefed.cache.ICacheClient;
 import com.android.tradefed.result.error.ErrorIdentifier;
 
 import java.io.File;
@@ -154,30 +152,6 @@ public interface IRunUtil {
             OutputStream stderr,
             final String... command);
 
-    /**
-     * Helper method to execute a system command with caching.
-     *
-     * <p>If {@code cacheClient} is specified, the caching will be enabled. If the cache is
-     * available, the cached result will be returned. Otherwise, {@link
-     * IRunUtil#runTimedCmdWithOutputMonitor( long, long, OutputStream, OutputStream, String...)}
-     * will be used to execute the command and the result will be uploaded for caching.
-     *
-     * @param timeout timeout maximum time to wait in ms. 0 means no timeout.
-     * @param idleOutputTimeout maximum time to wait in ms for output on the output streams.
-     * @param stdout {@link OutputStream} where the std output will be redirected. Can be null.
-     * @param stderr {@link OutputStream} where the error output will be redirected. Can be null.
-     * @param cacheClient an instance of {@link ICacheClient} used to handle caching.
-     * @param command the specified system command and optionally arguments to exec.
-     * @return a {@link CommandResult} containing result from command run.
-     */
-    public CommandResult runTimedCmdWithOutputMonitor(
-            final long timeout,
-            final long idleOutputTimeout,
-            OutputStream stdout,
-            OutputStream stderr,
-            ICacheClient cacheClient,
-            final String... command);
-
     /**
      * Helper method to execute a system command, abort if it takes longer than a specified time,
      * and redirect output to files if specified. When {@link OutputStream} are provided this way,
@@ -538,12 +512,4 @@ public interface IRunUtil {
         SET,
         UNSET
     }
-
-    /**
-     * Uploads the last {@link ExecutableActionResult} ran with a cacheClient.
-     *
-     * @param cacheClient The {@link ICacheClient} used to upload the result.
-     * @param actionResult The {@link ExecutableActionResult} to upload.
-     */
-    public void uploadCache(ICacheClient cacheClient, ExecutableActionResult actionResult);
 }
diff --git a/common_util/com/android/tradefed/util/RunUtil.java b/common_util/com/android/tradefed/util/RunUtil.java
index 11601fba8..180f2cda4 100644
--- a/common_util/com/android/tradefed/util/RunUtil.java
+++ b/common_util/com/android/tradefed/util/RunUtil.java
@@ -18,27 +18,21 @@ package com.android.tradefed.util;
 
 
 import com.android.annotations.Nullable;
-import com.android.tradefed.cache.ExecutableAction;
-import com.android.tradefed.cache.ExecutableActionResult;
-import com.android.tradefed.cache.ICacheClient;
 import com.android.tradefed.command.CommandInterrupter;
 import com.android.tradefed.invoker.logger.InvocationMetricLogger.InvocationMetricKey;
 import com.android.tradefed.invoker.tracing.CloseableTraceScope;
 import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.result.error.ErrorIdentifier;
-import com.android.tradefed.result.error.InfraErrorIdentifier;
 
 import com.google.common.annotations.VisibleForTesting;
 import com.google.common.base.Strings;
 
 import java.io.BufferedOutputStream;
 import java.io.File;
-import java.io.FileInputStream;
 import java.io.IOException;
 import java.io.InputStream;
 import java.io.OutputStream;
 import java.lang.ProcessBuilder.Redirect;
-import java.nio.file.Paths;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashMap;
@@ -71,12 +65,9 @@ public class RunUtil implements IRunUtil {
     private EnvPriority mEnvVariablePriority = EnvPriority.UNSET;
     private boolean mRedirectStderr = false;
     private boolean mLinuxInterruptProcess = false;
-    private static final String PROGRESS_MONITOR_ENV = "RUN_PROGRESS_MONITOR";
-    private static final String PROGRESS_MONITOR_TIMEOUT_ENV = "RUN_PROGRESS_MONITOR_TIMEOUT";
 
     private final CommandInterrupter mInterrupter;
     private final boolean mInheritEnvVars;
-    private ExecutableAction mAction = null;
 
     /**
      * Create a new {@link RunUtil} object to use.
@@ -211,65 +202,8 @@ public class RunUtil implements IRunUtil {
             final OutputStream stdout,
             OutputStream stderr,
             final String... command) {
-        return runTimedCmdWithOutputMonitor(
-                timeout, idleOutputTimeout, stdout, stderr, null, command);
-    }
-
-    /** {@inheritDoc} */
-    @Override
-    public CommandResult runTimedCmdWithOutputMonitor(
-            final long timeout,
-            final long idleOutputTimeout,
-            OutputStream stdout,
-            OutputStream stderr,
-            ICacheClient cacheClient,
-            final String... command) {
-        ProcessBuilder processBuilder = createProcessBuilder(cacheClient != null, command);
-        if (cacheClient != null) {
-            try {
-                mAction =
-                        ExecutableAction.create(
-                                processBuilder.directory(),
-                                processBuilder.command(),
-                                processBuilder.environment(),
-                                timeout);
-                CLog.d(
-                        "Caching command [%s] running in [%s] with environment variables:\n%s",
-                        processBuilder.command(),
-                        processBuilder.directory(),
-                        processBuilder.environment());
-            } catch (IOException e) {
-                CLog.e("Exception occurred when building executable action! Disabling cache...");
-                CLog.e(e);
-                // Disable caching.
-                cacheClient = null;
-            }
-        }
-
-        ExecutableActionResult cachedResult = null;
-        try {
-            cachedResult =
-                    mAction != null && cacheClient != null
-                            ? cacheClient.lookupCache(mAction)
-                            : null;
-        } catch (IOException e) {
-            CLog.e("Failed to lookup cache!");
-            CLog.e(e);
-        } catch (InterruptedException e) {
-            throw new RunInterruptedException(e.getMessage(), e, InfraErrorIdentifier.UNDETERMINED);
-        }
-        if (cachedResult != null) {
-            try {
-                CLog.d("Cache is hit with action: %s", mAction.action());
-                return handleCachedResult(cachedResult, stdout, stderr);
-            } catch (IOException e) {
-                CLog.e("Exception occurred when handling cached result!");
-                CLog.e(e);
-            }
-        }
-
+        ProcessBuilder processBuilder = createProcessBuilder(command);
         RunnableResult osRunnable = createRunnableResult(stdout, stderr, processBuilder);
-
         CommandStatus status =
                 runTimedWithOutputMonitor(timeout, idleOutputTimeout, osRunnable, true);
         CommandResult result = osRunnable.getResult();
@@ -325,11 +259,6 @@ public class RunUtil implements IRunUtil {
         return createProcessBuilder(Arrays.asList(command));
     }
 
-    private synchronized ProcessBuilder createProcessBuilder(
-            boolean enableCache, String... command) {
-        return createProcessBuilder(null, Arrays.asList(command), enableCache);
-    }
-
     private synchronized ProcessBuilder createProcessBuilder(Redirect redirect, String... command) {
         return createProcessBuilder(redirect, Arrays.asList(command), false);
     }
@@ -1203,58 +1132,12 @@ public class RunUtil implements IRunUtil {
         return commandResult;
     }
 
-    private static CommandResult handleCachedResult(
-            ExecutableActionResult result, OutputStream stdout, OutputStream stderr)
-            throws IOException {
-
-        CommandResult commandResult = newCommandResult();
-        commandResult.setExitCode(result.exitCode());
-        // Only success run will be cached.
-        commandResult.setStatus(CommandStatus.SUCCESS);
-        commandResult.setCached(true);
-        if (result.stdOut() != null) {
-            if (stdout != null) {
-                FileInputStream stdoutStream = new FileInputStream(result.stdOut());
-                try {
-                    StreamUtil.copyStreams(stdoutStream, stdout);
-                } finally {
-                    stdoutStream.close();
-                    FileUtil.deleteFile(result.stdOut());
-                }
-            } else {
-                try {
-                    commandResult.setStdout(FileUtil.readStringFromFile(result.stdOut()));
-                } finally {
-                    FileUtil.deleteFile(result.stdOut());
-                }
-            }
-        }
-        if (result.stdErr() != null) {
-            if (stderr != null) {
-                FileInputStream stderrStream = new FileInputStream(result.stdErr());
-                try {
-                    StreamUtil.copyStreams(stderrStream, stderr);
-                } finally {
-                    stderrStream.close();
-                    FileUtil.deleteFile(result.stdErr());
-                }
-            } else {
-                try {
-                    commandResult.setStderr(FileUtil.readStringFromFile(result.stdErr()));
-                } finally {
-                    FileUtil.deleteFile(result.stdErr());
-                }
-            }
-        }
-        return commandResult;
-    }
-
-    public static String toRelative(File start, String target) {
+    private static String toRelative(File start, String target) {
         File targetFile = new File(target);
         return targetFile.exists() ? toRelative(start, targetFile) : target;
     }
 
-    public static String toRelative(File start, File target) {
+    private static String toRelative(File start, File target) {
         String relPath = start.toPath().relativize(target.toPath()).toString();
         return relPath.length() != 0 ? relPath : ".";
     }
@@ -1262,47 +1145,4 @@ public class RunUtil implements IRunUtil {
     private static String pathSeparator() {
         return System.getProperty("path.separator");
     }
-
-    /**
-     * Links the {@code target} to a place under {@code destRoot}.
-     *
-     * <p>If the target file or the symlink is already existed under the {@code destRoot}, the file
-     * won't be linked.
-     *
-     * @param destRoot The root of the destination.
-     * @param relToRoot The relative path from the destination dir to root.
-     * @param target The target file to be linked.
-     * @return the symlink
-     * @throws IOException if the target file fails to be linked.
-     */
-    public static File linkFile(File destRoot, String relToRoot, File target) throws IOException {
-        if (target.getAbsolutePath().startsWith(destRoot.getAbsolutePath())) {
-            return target;
-        }
-        String relPath = Paths.get(relToRoot, target.getName()).toString();
-        File symlink = new File(destRoot, relPath);
-        if (symlink.exists()) {
-            FileUtil.deleteFile(symlink);
-        }
-        symlink.getParentFile().mkdirs();
-        FileUtil.symlinkFile(target, symlink);
-        return symlink;
-    }
-
-    /** {@inheritDoc} */
-    @Override
-    public void uploadCache(ICacheClient cacheClient, ExecutableActionResult actionResult) {
-        if (actionResult.exitCode() != 0 || cacheClient == null || mAction == null) {
-            return;
-        }
-        CLog.d("Uploading cache for action: %s", mAction.action());
-        try {
-            cacheClient.uploadCache(mAction, actionResult);
-        } catch (IOException e) {
-            CLog.e("Failed to upload cache!");
-            CLog.e(e);
-        } catch (InterruptedException e) {
-            throw new RunInterruptedException(e.getMessage(), e, InfraErrorIdentifier.UNDETERMINED);
-        }
-    }
 }
diff --git a/common_util/com/android/tradefed/util/VersionParser.java b/common_util/com/android/tradefed/util/VersionParser.java
index 43c93d87f..a5c2c46b6 100644
--- a/common_util/com/android/tradefed/util/VersionParser.java
+++ b/common_util/com/android/tradefed/util/VersionParser.java
@@ -25,7 +25,6 @@ public class VersionParser {
 
     public static final String DEFAULT_IMPLEMENTATION_VERSION = "default";
     private static final String VERSION_FILE = "version.txt";
-    private static final String TF_MAIN_JAR = "/tradefed.jar";
 
     public static String fetchVersion() {
         return getPackageVersion();
diff --git a/common_util/com/android/tradefed/util/gcs/GCSFileDownloaderBase.java b/common_util/com/android/tradefed/util/gcs/GCSFileDownloaderBase.java
index fe95ed203..3c7424a7d 100644
--- a/common_util/com/android/tradefed/util/gcs/GCSFileDownloaderBase.java
+++ b/common_util/com/android/tradefed/util/gcs/GCSFileDownloaderBase.java
@@ -148,14 +148,20 @@ public class GCSFileDownloaderBase extends GCSCommon {
                     remoteFilename = sanitizeDirectoryName(remoteFilename);
                     recursiveDownloadFolder(bucketName, remoteFilename, localFile);
                     return;
-                } catch (SocketException se) {
+                } catch (IOException e) {
                     // Allow one retry in case of flaky connection.
                     if (i >= 2) {
-                        throw se;
+                        throw e;
+                    }
+                    // Allow `Read timed out` exception to be retried.
+                    if (!(e instanceof SocketException)
+                            && !"Read timed out".equals(e.getMessage())) {
+                        throw e;
                     }
                     CLog.e(
                             "Error '%s' while downloading gs://%s/%s. retrying.",
-                            se.getMessage(), bucketName, remoteFilename);
+                            e.getMessage(), bucketName, remoteFilename);
+                    CLog.e(e);
                 }
             } while (true);
         } catch (IOException e) {
@@ -164,6 +170,7 @@ public class GCSFileDownloaderBase extends GCSCommon {
                             "Failed to download gs://%s/%s due to: %s",
                             bucketName, remoteFilename, e.getMessage());
             CLog.e(message);
+            CLog.e(e);
             throw new IOException(message, e);
         }
     }
diff --git a/device_build_interfaces/com/android/tradefed/device/TestDeviceOptions.java b/device_build_interfaces/com/android/tradefed/device/TestDeviceOptions.java
index c5e0cc155..ffc185e51 100644
--- a/device_build_interfaces/com/android/tradefed/device/TestDeviceOptions.java
+++ b/device_build_interfaces/com/android/tradefed/device/TestDeviceOptions.java
@@ -227,6 +227,11 @@ public class TestDeviceOptions {
             description = "Use the new Connection descriptor for devices.")
     private boolean mEnableConnectionFeature = true;
 
+    @Option(
+            name = "adb-connect-wait-time",
+            description = "maximum time in ms to wait for a ADB connection.",
+            isTimeVal = true)
+    protected long mAdbConnectWaitTime = 2 * 60 * 1000;
     // ====================== Options Related to Virtual Devices ======================
     @Option(
             name = INSTANCE_TYPE_OPTION,
@@ -402,7 +407,7 @@ public class TestDeviceOptions {
     @Option(
             name = "use-cmd-wifi",
             description = "Feature flag to switch the wifi connection to using cmd commands.")
-    private boolean mUseCmdWifi = false;
+    private boolean mUseCmdWifi = true;
 
     @Option(name = "cmd-wifi-virtual", description = "Whether to use cmd wifi for virtual devices.")
     private boolean mCmdWifiVirtual = true;
@@ -1014,6 +1019,11 @@ public class TestDeviceOptions {
         return mEnableConnectionFeature;
     }
 
+    /** Return the timeout value in ms to be applied to ADB connection. */
+    public long getAdbConnectWaitTime() {
+        return mAdbConnectWaitTime;
+    }
+
     public void setUseConnection(boolean useConnection) {
         mEnableConnectionFeature = useConnection;
     }
diff --git a/invocation_interfaces/com/android/tradefed/config/ConfigurationDescriptor.java b/invocation_interfaces/com/android/tradefed/config/ConfigurationDescriptor.java
index 122d7ea6f..295300a01 100644
--- a/invocation_interfaces/com/android/tradefed/config/ConfigurationDescriptor.java
+++ b/invocation_interfaces/com/android/tradefed/config/ConfigurationDescriptor.java
@@ -50,6 +50,12 @@ public class ConfigurationDescriptor implements Serializable, Cloneable {
     /** Metadata key for a config parameterization, optional. */
     public static final String ACTIVE_PARAMETER_KEY = "active-parameter";
 
+    /** Metadata key for a config to specify if it is prioritizing host config. */
+    public static final String PRIORITIZE_HOST_CONFIG_KEY = "prioritize-host-config";
+
+    /** Metadata key for a config to specify the module dir path when it's a module config. */
+    public static final String MODULE_DIR_PATH_KEY = "module-dir-path";
+
     @Option(name = "test-suite-tag", description = "A membership tag to suite. Can be repeated.")
     private List<String> mSuiteTags = new ArrayList<>();
 
@@ -95,6 +101,8 @@ public class ConfigurationDescriptor implements Serializable, Cloneable {
     /** Optional: track the shard index of the invocation */
     private Integer mShardIndex = null;
 
+    private MultiMap<String, String> mInternalMetaData = new MultiMap<>();
+
     /** a list of options applicable to rerun the test */
     private final List<OptionDef> mRerunOptions = new ArrayList<>();
 
@@ -112,12 +120,16 @@ public class ConfigurationDescriptor implements Serializable, Cloneable {
     public MultiMap<String, String> getAllMetaData() {
         MultiMap<String, String> copy = new MultiMap<>();
         copy.putAll(mMetaData);
+        copy.putAll(mInternalMetaData);
         return copy;
     }
 
     /** Get the named metadata entries */
     public List<String> getMetaData(String name) {
-        List<String> entry = mMetaData.get(name);
+        MultiMap<String, String> copy = new MultiMap<>();
+        copy.putAll(mMetaData);
+        copy.putAll(mInternalMetaData);
+        List<String> entry = copy.get(name);
         if (entry == null) {
             return null;
         }
@@ -136,7 +148,7 @@ public class ConfigurationDescriptor implements Serializable, Cloneable {
      * @param value A{@link String} of the additional value.
      */
     public void addMetadata(String key, String value) {
-        mMetaData.put(key, value);
+        mInternalMetaData.put(key, value);
     }
 
     /**
@@ -147,7 +159,7 @@ public class ConfigurationDescriptor implements Serializable, Cloneable {
      */
     public void addMetadata(String key, List<String> values) {
         for (String source : values) {
-            mMetaData.put(key, source);
+            mInternalMetaData.put(key, source);
         }
     }
 
@@ -155,7 +167,7 @@ public class ConfigurationDescriptor implements Serializable, Cloneable {
      * Remove the tracking of the specified metadata key.
      */
     public List<String> removeMetadata(String key) {
-        return mMetaData.remove(key);
+        return mInternalMetaData.remove(key);
     }
 
     /** Returns if the configuration is shardable or not as part of a suite */
@@ -238,9 +250,9 @@ public class ConfigurationDescriptor implements Serializable, Cloneable {
         descriptorBuilder.addAllTestSuiteTag(mSuiteTags);
         // Metadata
         List<Metadata> metadatas = new ArrayList<>();
-        for (String key : mMetaData.keySet()) {
-            Metadata value =
-                    Metadata.newBuilder().setKey(key).addAllValue(mMetaData.get(key)).build();
+        MultiMap<String, String> local = getAllMetaData();
+        for (String key : local.keySet()) {
+            Metadata value = Metadata.newBuilder().setKey(key).addAllValue(local.get(key)).build();
             metadatas.add(value);
         }
         descriptorBuilder.addAllMetadata(metadatas);
diff --git a/invocation_interfaces/com/android/tradefed/util/SearchArtifactUtil.java b/invocation_interfaces/com/android/tradefed/util/SearchArtifactUtil.java
index 7c7e8f5cf..a4510ea2a 100644
--- a/invocation_interfaces/com/android/tradefed/util/SearchArtifactUtil.java
+++ b/invocation_interfaces/com/android/tradefed/util/SearchArtifactUtil.java
@@ -19,6 +19,7 @@ package com.android.tradefed.util;
 import com.android.tradefed.build.BuildInfoKey.BuildInfoFileKey;
 import com.android.tradefed.build.IBuildInfo;
 import com.android.tradefed.build.IDeviceBuildInfo;
+import com.android.tradefed.config.ConfigurationDescriptor;
 import com.android.tradefed.invoker.ExecutionFiles;
 import com.android.tradefed.invoker.ExecutionFiles.FilesKey;
 import com.android.tradefed.invoker.IInvocationContext;
@@ -153,7 +154,10 @@ public class SearchArtifactUtil {
                 return file;
             } else {
                 // fallback to staging from remote zip files.
-                File stagingDir = getWorkFolder(testInfo);
+                File stagingDir = getModuleDirFromConfig();
+                if (stagingDir == null) {
+                    stagingDir = getWorkFolder(testInfo);
+                }
                 if (fileExists(stagingDir)) {
                     buildInfo.stageRemoteFile(fileName, stagingDir);
                     // multiple matching files can be staged. So do a search with module name and
@@ -179,6 +183,13 @@ public class SearchArtifactUtil {
             AltDirBehavior altDirBehavior,
             TestInformation testInfo) {
         List<File> dirs = new LinkedList<>();
+        // Prioritize the module directory retrieved from the config obj, as this is the ideal place
+        // for all test artifacts.
+        File moduleDir = getModuleDirFromConfig();
+        if (moduleDir != null) {
+            dirs.add(moduleDir);
+        }
+
         ExecutionFiles executionFiles = singleton.getExecutionFiles(testInfo);
         if (executionFiles != null) {
             // Add host/testcases or target/testcases directory first
@@ -324,6 +335,28 @@ public class SearchArtifactUtil {
         return null;
     }
 
+    public static File getModuleDirFromConfig(IInvocationContext moduleContext) {
+        if (moduleContext != null) {
+            List<String> moduleDirPath =
+                    moduleContext
+                            .getConfigurationDescriptor()
+                            .getMetaData(ConfigurationDescriptor.MODULE_DIR_PATH_KEY);
+            if (moduleDirPath != null && !moduleDirPath.isEmpty()) {
+                File moduleDir = new File(moduleDirPath.get(0));
+                if (moduleDir.exists()) {
+                    return moduleDir;
+                }
+            }
+        }
+        return null;
+    }
+
+    /** Returns the module directory if present, when called inside a module scope. */
+    public static File getModuleDirFromConfig() {
+        IInvocationContext moduleContext = CurrentInvocation.getModuleContext();
+        return getModuleDirFromConfig(moduleContext);
+    }
+
     /**
      * Finds the module directory that matches the given module name
      *
diff --git a/isolation/com/android/tradefed/isolation/IsolationRunner.java b/isolation/com/android/tradefed/isolation/IsolationRunner.java
index ebd27cf8f..99e5043cd 100644
--- a/isolation/com/android/tradefed/isolation/IsolationRunner.java
+++ b/isolation/com/android/tradefed/isolation/IsolationRunner.java
@@ -51,6 +51,7 @@ public final class IsolationRunner {
     private static final String EXCLUDE_NO_TEST_FAILURE = "org.junit.runner.manipulation.Filter";
     private Socket mSocket = null;
     private ServerSocket mServer = null;
+    private boolean mDoNotSwallowRunnerErrors = false;
 
     public static void main(String[] args)
             throws ParseException, NumberFormatException, IOException {
@@ -67,6 +68,8 @@ public final class IsolationRunner {
         // Set a timeout for hearing something from the host when we start a read.
         mSocket.setSoTimeout(config.getTimeout());
 
+        mDoNotSwallowRunnerErrors = config.doNotSwallowRunnerErrors();
+
         OutputStream output = mSocket.getOutputStream();
 
         // Process messages by receiving and looping
@@ -128,7 +131,6 @@ public final class IsolationRunner {
 
         try {
             for (Class<?> klass : klasses) {
-                System.out.println("INFO: IsolationRunner: Starting class: " + klass);
                 IsolationResultForwarder list = new IsolationResultForwarder(output);
                 JUnitCore runnerCore = new JUnitCore();
                 runnerCore.addListener(list);
@@ -143,24 +145,42 @@ public final class IsolationRunner {
                     boolean isFilterError =
                             EXCLUDE_NO_TEST_FAILURE.equals(
                                     req.getRunner().getDescription().getClassName());
-                    if (!params.hasFilter() && isFilterError) {
-                        System.err.println(
-                                String.format(
-                                        "ERROR: IsolationRunner: Found ErrorRunner when trying to"
-                                                + " run class: %s",
-                                        klass));
-                        runnerCore.run(req.getRunner());
+                    if (mDoNotSwallowRunnerErrors) {
+                        if (params.hasFilter() && isFilterError) {
+                            // In this case, do not report it as an error.
+                            System.out.println(
+                                    String.format(
+                                            "Skipping this class since all methods were filtered"
+                                                + " out: %s",
+                                            klass));
+                        } else {
+                            System.out.println(
+                                    String.format(
+                                            "Found ErrorRunner when trying to run class: %s",
+                                            klass));
+                            runnerCore.run(req.getRunner());
+                        }
                     } else {
-                        System.err.println(
-                                String.format(
-                                        "ERROR: IsolationRunner: Encountered ErrorReportingRunner"
-                                                + " when trying to run: %s",
-                                        klass));
+                        // TODO(b/312517322): Remove this entire else block once the flag is rolled
+                        // out completely.
+                        if (!params.hasFilter() && isFilterError) {
+                            System.err.println(
+                                    String.format(
+                                            "ERROR: IsolationRunner: Found ErrorRunner when trying"
+                                                + " to run class: %s",
+                                            klass));
+                            runnerCore.run(req.getRunner());
+                        } else {
+                            System.err.println(
+                                    String.format(
+                                            "ERROR: IsolationRunner: Encountered"
+                                                + " ErrorReportingRunner when trying to run: %s",
+                                            klass));
+                        }
                     }
                 } else if (req.getRunner() instanceof IgnoredClassRunner) {
                     // Do nothing since class was ignored
                 } else {
-                    System.out.println("INFO: IsolationRunner: Executing class: " + klass);
                     Runner checkRunner = req.getRunner();
 
                     if (params.getDryRun()) {
@@ -192,8 +212,6 @@ public final class IsolationRunner {
     }
 
     private List<Class<?>> getClasses(TestParameters params) {
-        System.out.println("INFO: IsolationRunner: Excluded paths:");
-        params.getExcludePathsList().stream().forEach(path -> System.out.println(path));
         return HostUtils.getJUnitClasses(
                 new HashSet<>(params.getTestClassesList()),
                 new HashSet<>(params.getTestJarAbsPathsList()),
@@ -209,8 +227,10 @@ public final class IsolationRunner {
         private final int mPort;
         private final String mAddress;
         private final int mTimeout;
+        private final boolean mDoNotSwallowRunnerErrors;
 
-        public RunnerConfig(int port, String address, int timeout) {
+        public RunnerConfig(
+                int port, String address, int timeout, boolean doNotSwallowRunnerErrors) {
             if (port > 0) {
                 mPort = port;
             } else {
@@ -228,6 +248,8 @@ public final class IsolationRunner {
             } else {
                 mTimeout = RunnerConfig.DEFAULT_TIMEOUT;
             }
+
+            mDoNotSwallowRunnerErrors = doNotSwallowRunnerErrors;
         }
 
         public int getPort() {
@@ -241,6 +263,10 @@ public final class IsolationRunner {
         public int getTimeout() {
             return mTimeout;
         }
+
+        public boolean doNotSwallowRunnerErrors() {
+            return mDoNotSwallowRunnerErrors;
+        }
     }
 
     private static RunnerConfig parseFlags(String[] args)
@@ -259,6 +285,12 @@ public final class IsolationRunner {
         timeoutOption.setRequired(false);
         options.addOption(timeoutOption);
 
+        Option doNotSwallowRunnerErrorsOption =
+                new Option(
+                        "e", "do-not-swallow-runner-errors", false, "Do not swallow runner errors");
+        doNotSwallowRunnerErrorsOption.setRequired(false);
+        options.addOption(doNotSwallowRunnerErrorsOption);
+
         CommandLineParser parser = new PosixParser();
         CommandLine cmd;
 
@@ -267,6 +299,7 @@ public final class IsolationRunner {
         String portStr = cmd.getOptionValue("p");
         String addressStr = cmd.getOptionValue("a");
         String timeoutStr = cmd.getOptionValue("t");
+        boolean doNotSwallowRunnerErrors = cmd.hasOption("e");
 
         int port = -1;
         String address = null;
@@ -282,6 +315,6 @@ public final class IsolationRunner {
             timeout = Integer.parseInt(timeoutStr);
         }
 
-        return new RunnerConfig(port, address, timeout);
+        return new RunnerConfig(port, address, timeout, doNotSwallowRunnerErrors);
     }
 }
diff --git a/javatests/com/android/tradefed/UnitTests.java b/javatests/com/android/tradefed/UnitTests.java
index f9ca11d83..51b89eafb 100644
--- a/javatests/com/android/tradefed/UnitTests.java
+++ b/javatests/com/android/tradefed/UnitTests.java
@@ -276,6 +276,7 @@ import com.android.tradefed.targetprep.DeviceStorageFillerTest;
 import com.android.tradefed.targetprep.DeviceStringPusherTest;
 import com.android.tradefed.targetprep.DisableSELinuxTargetPreparerTest;
 import com.android.tradefed.targetprep.DynamicSystemPreparerTest;
+import com.android.tradefed.targetprep.FastbootCommandPreparerTest;
 import com.android.tradefed.targetprep.FastbootDeviceFlasherTest;
 import com.android.tradefed.targetprep.FeatureFlagTargetPreparerTest;
 import com.android.tradefed.targetprep.FlashingResourcesParserTest;
@@ -317,6 +318,7 @@ import com.android.tradefed.targetprep.UserCleanerTest;
 import com.android.tradefed.targetprep.VisibleBackgroundUserPreparerTest;
 import com.android.tradefed.targetprep.adb.AdbStopServerPreparerTest;
 import com.android.tradefed.targetprep.app.NoApkTestSkipperTest;
+import com.android.tradefed.targetprep.incremental.ApkChangeDetectorTest;
 import com.android.tradefed.targetprep.multi.MergeMultiBuildTargetPreparerTest;
 import com.android.tradefed.targetprep.multi.MixImageZipPreparerTest;
 import com.android.tradefed.targetprep.multi.PairingMultiTargetPreparerTest;
@@ -836,6 +838,7 @@ import org.junit.runners.Suite.SuiteClasses;
     DeviceStringPusherTest.class,
     DisableSELinuxTargetPreparerTest.class,
     DynamicSystemPreparerTest.class,
+    FastbootCommandPreparerTest.class,
     FastbootDeviceFlasherTest.class,
     FeatureFlagTargetPreparerTest.class,
     FlashingResourcesParserTest.class,
@@ -882,6 +885,9 @@ import org.junit.runners.Suite.SuiteClasses;
     // targetprep.app
     NoApkTestSkipperTest.class,
 
+    // targetprep.incremental
+    ApkChangeDetectorTest.class,
+
     // targetprep.multi
     MergeMultiBuildTargetPreparerTest.class,
     MixImageZipPreparerTest.class,
diff --git a/javatests/com/android/tradefed/build/content/DeviceMerkleTreeTest.java b/javatests/com/android/tradefed/build/content/DeviceMerkleTreeTest.java
index a0a33d13e..06b3ed05b 100644
--- a/javatests/com/android/tradefed/build/content/DeviceMerkleTreeTest.java
+++ b/javatests/com/android/tradefed/build/content/DeviceMerkleTreeTest.java
@@ -16,6 +16,7 @@
 package com.android.tradefed.build.content;
 
 import com.android.tradefed.build.content.ContentAnalysisContext.AnalysisMethod;
+import com.android.tradefed.result.skipped.AnalysisHeuristic;
 import com.android.tradefed.util.FileUtil;
 
 import build.bazel.remote.execution.v2.Digest;
@@ -43,14 +44,18 @@ public class DeviceMerkleTreeTest {
             ContentAnalysisContext contextBase =
                     new ContentAnalysisContext(
                             "mysuite.zip", infoBase, AnalysisMethod.DEVICE_IMAGE);
-            Digest baseDigest = DeviceMerkleTree.buildFromContext(contextBase);
+            Digest baseDigest =
+                    DeviceMerkleTree.buildFromContext(
+                            contextBase, AnalysisHeuristic.REMOVE_EXEMPTION);
 
             ContentInformation currentBase =
                     new ContentInformation(null, null, currentJson, "8888");
             ContentAnalysisContext contextCurrent =
                     new ContentAnalysisContext(
                             "mysuite.zip", currentBase, AnalysisMethod.DEVICE_IMAGE);
-            Digest currentDigest = DeviceMerkleTree.buildFromContext(contextCurrent);
+            Digest currentDigest =
+                    DeviceMerkleTree.buildFromContext(
+                            contextCurrent, AnalysisHeuristic.REMOVE_EXEMPTION);
 
             Truth.assertThat(baseDigest.getHash()).isNotEqualTo(currentDigest.getHash());
             Truth.assertThat(baseDigest.getHash())
diff --git a/javatests/com/android/tradefed/cluster/ClusterCommandSchedulerTest.java b/javatests/com/android/tradefed/cluster/ClusterCommandSchedulerTest.java
index 17c6dd5a9..fdd30cb9a 100644
--- a/javatests/com/android/tradefed/cluster/ClusterCommandSchedulerTest.java
+++ b/javatests/com/android/tradefed/cluster/ClusterCommandSchedulerTest.java
@@ -1625,7 +1625,6 @@ public class ClusterCommandSchedulerTest {
         verify(mMockHostUploader).flush();
         ClusterHostEvent hostEvent = capture.getValue();
         assertNotNull(hostEvent.getHostName());
-        assertNotNull(hostEvent.getTimestamp());
         assertEquals(CommandScheduler.HostState.RUNNING, hostEvent.getHostState());
         scheduler.shutdown();
         scheduler.join();
diff --git a/javatests/com/android/tradefed/cluster/ClusterDeviceMonitorTest.java b/javatests/com/android/tradefed/cluster/ClusterDeviceMonitorTest.java
index d392779f0..c27531fcb 100644
--- a/javatests/com/android/tradefed/cluster/ClusterDeviceMonitorTest.java
+++ b/javatests/com/android/tradefed/cluster/ClusterDeviceMonitorTest.java
@@ -148,7 +148,6 @@ public class ClusterDeviceMonitorTest {
         ClusterHostEvent hostEvent = capture.getValue();
         Assert.assertNotNull(hostEvent.getHostName());
         Assert.assertNotNull(hostEvent.getData().get(ClusterHostEvent.TEST_HARNESS_START_TIME_KEY));
-        Assert.assertNotNull(hostEvent.getTimestamp());
         Assert.assertEquals("cluster1", hostEvent.getClusterId());
         Assert.assertEquals(Arrays.asList("cluster2", "cluster3"), hostEvent.getNextClusterIds());
         Assert.assertEquals("lab1", hostEvent.getLabName());
@@ -171,7 +170,6 @@ public class ClusterDeviceMonitorTest {
         verify(mHostEventUploader).flush();
         ClusterHostEvent hostEvent = capture.getValue();
         Assert.assertNotNull(hostEvent.getHostName());
-        Assert.assertNotNull(hostEvent.getTimestamp());
         Assert.assertEquals("cluster1", hostEvent.getClusterId());
         Assert.assertEquals(Arrays.asList("cluster2", "cluster3"), hostEvent.getNextClusterIds());
         Assert.assertEquals("lab1", hostEvent.getLabName());
@@ -261,7 +259,6 @@ public class ClusterDeviceMonitorTest {
         verify(mHostEventUploader).flush();
         ClusterHostEvent hostEvent = capture.getValue();
         Assert.assertNotNull(hostEvent.getHostName());
-        Assert.assertNotNull(hostEvent.getTimestamp());
         Assert.assertEquals("cluster1", hostEvent.getClusterId());
         Assert.assertEquals(Arrays.asList("cluster2", "cluster3"), hostEvent.getNextClusterIds());
         Assert.assertEquals(1, hostEvent.getDeviceInfos().size());
diff --git a/javatests/com/android/tradefed/config/ConfigurationFactoryTest.java b/javatests/com/android/tradefed/config/ConfigurationFactoryTest.java
index ba6c27927..ff9268b7e 100644
--- a/javatests/com/android/tradefed/config/ConfigurationFactoryTest.java
+++ b/javatests/com/android/tradefed/config/ConfigurationFactoryTest.java
@@ -42,6 +42,8 @@ import com.android.tradefed.targetprep.multi.StubMultiTargetPreparer;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.StreamUtil;
 
+import com.google.common.collect.ImmutableSet;
+
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -1377,6 +1379,19 @@ public class ConfigurationFactoryTest {
         assertEquals("faketestdir", provider.getTestDir().getName());
     }
 
+    @Test
+    public void testPartialCreateMultiDevices() throws Exception {
+        IConfiguration config =
+                mFactory.createPartialConfigurationFromArgs(
+                        new String[] {"test-config-multi-include", "--test-dir", "faketestdir"},
+                        null,
+                        ImmutableSet.of(Configuration.BUILD_PROVIDER_TYPE_NAME),
+                        null);
+        assertEquals(2, config.getDeviceConfig().size());
+        IDeviceConfiguration device2 = config.getDeviceConfigByName("device2");
+        assertTrue(device2.getBuildProvider() instanceof LocalDeviceBuildProvider);
+    }
+
     /**
      * Test when an <include> tag tries to load a <device> tag inside another <device> tag. This
      * should throw an exception.
diff --git a/javatests/com/android/tradefed/device/DumpsysPackageReceiverTest.java b/javatests/com/android/tradefed/device/DumpsysPackageReceiverTest.java
index ddb177aed..0bc61b7d0 100644
--- a/javatests/com/android/tradefed/device/DumpsysPackageReceiverTest.java
+++ b/javatests/com/android/tradefed/device/DumpsysPackageReceiverTest.java
@@ -33,7 +33,7 @@ public class DumpsysPackageReceiverTest {
     public void testParse_classic() throws Exception {
         final String[] froyoPkgTxt = new String[] {"Packages:",
                 "Package [com.android.soundrecorder] (462f6b38):",
-                "targetSdk=8",
+                "targetSdk=8 codePath=/data/app/~~XXmm==/com.app.android==",
                 "versionName=3.1.36 (88)",
                 "pkgFlags=0x1 installStatus=1 enabled=0"};
 
@@ -45,6 +45,7 @@ public class DumpsysPackageReceiverTest {
         assertTrue(pkg.isSystemApp());
         assertFalse(pkg.isUpdatedSystemApp());
         assertEquals("3.1.36 (88)", pkg.getVersionName());
+        assertEquals("/data/app/~~XXmm==/com.app.android==", pkg.getCodePath());
     }
 
     /**
diff --git a/javatests/com/android/tradefed/device/NativeDeviceTest.java b/javatests/com/android/tradefed/device/NativeDeviceTest.java
index 923ead2c1..bd8dc436f 100644
--- a/javatests/com/android/tradefed/device/NativeDeviceTest.java
+++ b/javatests/com/android/tradefed/device/NativeDeviceTest.java
@@ -469,6 +469,12 @@ public class NativeDeviceTest {
                         return "drwxr-xr-x root     root    somedirectory";
                     }
 
+                    @Override
+                    public boolean doesFileExist(String deviceFilePath, int userId)
+                            throws DeviceNotAvailableException {
+                        return true;
+                    }
+
                     @Override
                     public int getCurrentUser() throws DeviceNotAvailableException {
                         return 0;
@@ -517,6 +523,12 @@ public class NativeDeviceTest {
                         return "drwxr-xr-x root     root    somedirectory";
                     }
 
+                    @Override
+                    public boolean doesFileExist(String deviceFilePath, int userId)
+                            throws DeviceNotAvailableException {
+                        return true;
+                    }
+
                     @Override
                     protected boolean pullFileInternal(String remoteFilePath, File localFile)
                             throws DeviceNotAvailableException {
@@ -589,6 +601,12 @@ public class NativeDeviceTest {
                         return "drwxr-xr-x root     root    somedirectory";
                     }
 
+                    @Override
+                    public boolean doesFileExist(String deviceFilePath, int userId)
+                            throws DeviceNotAvailableException {
+                        return true;
+                    }
+
                     @Override
                     protected boolean pullFileInternal(String remoteFilePath, File localFile)
                             throws DeviceNotAvailableException {
@@ -663,6 +681,12 @@ public class NativeDeviceTest {
                         return "-rwxr-xr-x root     root    somefile";
                     }
 
+                    @Override
+                    public boolean doesFileExist(String deviceFilePath, int userId)
+                            throws DeviceNotAvailableException {
+                        return true;
+                    }
+
                     @Override
                     public int getCurrentUser() throws DeviceNotAvailableException {
                         return 0;
@@ -878,6 +902,23 @@ public class NativeDeviceTest {
     /** Unit test for {@link NativeDevice#connectToWifiNetwork(String, String)}. */
     @Test
     public void testConnectToWifiNetwork_success() throws DeviceNotAvailableException {
+        mTestDevice =
+                new TestableAndroidNativeDevice() {
+                    @Override
+                    public boolean enableAdbRoot() throws DeviceNotAvailableException {
+                        return false;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper() throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper(boolean useV2) throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+                };
         when(mMockWifi.connectToNetwork(
                         FAKE_NETWORK_SSID,
                         FAKE_NETWORK_PASSWORD,
@@ -895,6 +936,23 @@ public class NativeDeviceTest {
     /** Unit test for {@link NativeDevice#connectToWifiNetwork(Map<String, String>)}. */
     @Test
     public void testConnectToWifiNetworkGivenMap_success() throws DeviceNotAvailableException {
+        mTestDevice =
+                new TestableAndroidNativeDevice() {
+                    @Override
+                    public boolean enableAdbRoot() throws DeviceNotAvailableException {
+                        return false;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper() throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper(boolean useV2) throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+                };
         when(mMockWifi.connectToNetwork(
                         FAKE_NETWORK_SSID,
                         FAKE_NETWORK_PASSWORD,
@@ -917,6 +975,23 @@ public class NativeDeviceTest {
      */
     @Test
     public void testConnectToWifiNetwork_failure() throws DeviceNotAvailableException {
+        mTestDevice =
+                new TestableAndroidNativeDevice() {
+                    @Override
+                    public boolean enableAdbRoot() throws DeviceNotAvailableException {
+                        return false;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper() throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper(boolean useV2) throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+                };
         when(mMockWifi.connectToNetwork(
                         FAKE_NETWORK_SSID,
                         FAKE_NETWORK_PASSWORD,
@@ -947,6 +1022,23 @@ public class NativeDeviceTest {
      */
     @Test
     public void testConnectToWifiNetworkGivenMap_failure() throws DeviceNotAvailableException {
+        mTestDevice =
+                new TestableAndroidNativeDevice() {
+                    @Override
+                    public boolean enableAdbRoot() throws DeviceNotAvailableException {
+                        return false;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper() throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper(boolean useV2) throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+                };
         when(mMockWifi.connectToNetwork(
                         FAKE_NETWORK_SSID,
                         FAKE_NETWORK_PASSWORD,
@@ -980,6 +1072,23 @@ public class NativeDeviceTest {
     @Test
     public void testConnectToWifiNetwork_maxConnectTime()
             throws DeviceNotAvailableException, ConfigurationException {
+        mTestDevice =
+                new TestableAndroidNativeDevice() {
+                    @Override
+                    public boolean enableAdbRoot() throws DeviceNotAvailableException {
+                        return false;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper() throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper(boolean useV2) throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+                };
         OptionSetter deviceOptionSetter = new OptionSetter(mTestDevice.getOptions());
         deviceOptionSetter.setOptionValue("max-wifi-connect-time", "10000");
         Clock mockClock = Mockito.mock(Clock.class);
@@ -1016,6 +1125,23 @@ public class NativeDeviceTest {
     @Test
     public void testConnectToWifiNetworkGivenMap_maxConnectTime()
             throws DeviceNotAvailableException, ConfigurationException {
+        mTestDevice =
+                new TestableAndroidNativeDevice() {
+                    @Override
+                    public boolean enableAdbRoot() throws DeviceNotAvailableException {
+                        return false;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper() throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper(boolean useV2) throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+                };
         OptionSetter deviceOptionSetter = new OptionSetter(mTestDevice.getOptions());
         deviceOptionSetter.setOptionValue("max-wifi-connect-time", "10000");
         Clock mockClock = Mockito.mock(Clock.class);
@@ -1050,6 +1176,23 @@ public class NativeDeviceTest {
     /** Unit test for {@link NativeDevice#connectToWifiNetwork(String, String, boolean)}. */
     @Test
     public void testConnectToWifiNetwork_scanSsid() throws DeviceNotAvailableException {
+        mTestDevice =
+                new TestableAndroidNativeDevice() {
+                    @Override
+                    public boolean enableAdbRoot() throws DeviceNotAvailableException {
+                        return false;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper() throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper(boolean useV2) throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+                };
         when(mMockWifi.connectToNetwork(
                         FAKE_NETWORK_SSID,
                         FAKE_NETWORK_PASSWORD,
@@ -1068,6 +1211,23 @@ public class NativeDeviceTest {
     /** Unit test for {@link NativeDevice#connectToWifiNetwork(Map<String, String>, boolean)}. */
     @Test
     public void testConnectToWifiNetworkGivenMap_scanSsid() throws DeviceNotAvailableException {
+        mTestDevice =
+                new TestableAndroidNativeDevice() {
+                    @Override
+                    public boolean enableAdbRoot() throws DeviceNotAvailableException {
+                        return false;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper() throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper(boolean useV2) throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+                };
         when(mMockWifi.connectToNetwork(
                         FAKE_NETWORK_SSID,
                         FAKE_NETWORK_PASSWORD,
@@ -1125,6 +1285,23 @@ public class NativeDeviceTest {
     /** Unit test for {@link NativeDevice#disconnectFromWifi()}. */
     @Test
     public void testDisconnectFromWifi() throws DeviceNotAvailableException {
+        mTestDevice =
+                new TestableAndroidNativeDevice() {
+                    @Override
+                    public boolean enableAdbRoot() throws DeviceNotAvailableException {
+                        return false;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper() throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+
+                    @Override
+                    IWifiHelper createWifiHelper(boolean useV2) throws DeviceNotAvailableException {
+                        return mMockWifi;
+                    }
+                };
         when(mMockWifi.disconnectFromNetwork()).thenReturn(true);
 
         assertTrue(mTestDevice.disconnectFromWifi());
diff --git a/javatests/com/android/tradefed/device/TestDeviceTest.java b/javatests/com/android/tradefed/device/TestDeviceTest.java
index f550834c8..9b3efd8fe 100644
--- a/javatests/com/android/tradefed/device/TestDeviceTest.java
+++ b/javatests/com/android/tradefed/device/TestDeviceTest.java
@@ -5717,17 +5717,21 @@ public class TestDeviceTest {
                     public File pullFile(String remoteFilePath) throws DeviceNotAvailableException {
                         return new File("test");
                     }
+
+                    @Override
+                    public boolean doesFileExist(String deviceFilePath, int userId)
+                            throws DeviceNotAvailableException {
+                        return true;
+                    }
                 };
         injectShellResponse("pidof system_server", "929");
         injectShellResponse("am dumpheap 929 /data/dump.hprof", "");
-        injectShellResponse("ls \"/data/dump.hprof\"", "/data/dump.hprof");
         injectShellResponse("rm -rf /data/dump.hprof", "");
 
         File res = mTestDevice.dumpHeap("system_server", "/data/dump.hprof");
         assertNotNull(res);
         verifyShellResponse("pidof system_server");
         verifyShellResponse("am dumpheap 929 /data/dump.hprof");
-        verifyShellResponse("ls \"/data/dump.hprof\"");
         verifyShellResponse("rm -rf /data/dump.hprof");
     }
 
@@ -6039,21 +6043,22 @@ public class TestDeviceTest {
     /** Test {@link TestDevice#doesFileExist(String)}. */
     @Test
     public void testDoesFileExists() throws Exception {
-        injectShellResponse("ls \"/data/local/tmp/file\"", "file");
+        TestDevice testDevice =
+                new TestableTestDeviceV2()
+                        .injectShellV2Command("ls '/data/local/tmp/file\'", "file");
 
-        assertTrue(mTestDevice.doesFileExist("/data/local/tmp/file"));
-        verifyShellResponse("ls \"/data/local/tmp/file\"");
+        assertTrue(testDevice.doesFileExist("/data/local/tmp/file"));
     }
 
     /** Test {@link TestDevice#doesFileExist(String)} when the file does not exists. */
     @Test
     public void testDoesFileExists_notExists() throws Exception {
-        injectShellResponse(
-                "ls \"/data/local/tmp/file\"",
-                "ls: cannot access 'file': No such file or directory\n");
-
-        assertFalse(mTestDevice.doesFileExist("/data/local/tmp/file"));
-        verifyShellResponse("ls \"/data/local/tmp/file\"");
+        TestDevice testDevice =
+                new TestableTestDeviceV2()
+                        .injectShellV2Command(
+                                "ls '/data/local/tmp/file'",
+                                "ls: cannot access 'file': No such file or directory\n");
+        assertFalse(testDevice.doesFileExist("/data/local/tmp/file"));
     }
 
     /**
diff --git a/javatests/com/android/tradefed/device/WifiCommandUtilTest.java b/javatests/com/android/tradefed/device/WifiCommandUtilTest.java
index 4623eb7fa..ee32ab689 100644
--- a/javatests/com/android/tradefed/device/WifiCommandUtilTest.java
+++ b/javatests/com/android/tradefed/device/WifiCommandUtilTest.java
@@ -73,6 +73,7 @@ public class WifiCommandUtilTest {
         assertEquals("573", wifiInfo.get("linkSpeed"));
         assertEquals("-60", wifiInfo.get("rssi"));
         assertEquals("82:f2:40:f1:51:be", wifiInfo.get("macAddress"));
+        assertEquals("14", wifiInfo.get("netId"));
     }
 
     private String readTestFile(String filename) {
diff --git a/javatests/com/android/tradefed/device/internal/DeviceSnapshotFeatureTest.java b/javatests/com/android/tradefed/device/internal/DeviceSnapshotFeatureTest.java
index 65131b663..7e31e69bd 100644
--- a/javatests/com/android/tradefed/device/internal/DeviceSnapshotFeatureTest.java
+++ b/javatests/com/android/tradefed/device/internal/DeviceSnapshotFeatureTest.java
@@ -96,4 +96,20 @@ public class DeviceSnapshotFeatureTest {
                         .getErrorTrace()
                         .contains("with connection type [null] doesn't support snapshotting"));
     }
+
+    @Test
+    public void testFeature_deleteSnapshot() throws Exception {
+        FeatureRequest.Builder request =
+                FeatureRequest.newBuilder()
+                        .putArgs("serial", "device-serial")
+                        .putArgs("device_name", ConfigurationDef.DEFAULT_DEVICE_NAME)
+                        .putArgs("snapshot_id", "random_id")
+                        .putArgs("delete_flag", "true");
+
+        FeatureResponse response = mFeature.execute(request.build());
+        assertTrue(
+                response.getErrorInfo()
+                        .getErrorTrace()
+                        .contains("with connection type [null] doesn't support snapshotting"));
+    }
 }
diff --git a/javatests/com/android/tradefed/device/internal/DeviceSnapshotHandlerTest.java b/javatests/com/android/tradefed/device/internal/DeviceSnapshotHandlerTest.java
index 820ff9d08..e2745ab87 100644
--- a/javatests/com/android/tradefed/device/internal/DeviceSnapshotHandlerTest.java
+++ b/javatests/com/android/tradefed/device/internal/DeviceSnapshotHandlerTest.java
@@ -215,4 +215,60 @@ public class DeviceSnapshotHandlerTest {
                                 "0");
         assertEquals("2", count);
     }
+
+    @Test
+    public void testDeleteSnapshot() throws Exception {
+        FeatureResponse.Builder responseBuilder = FeatureResponse.newBuilder();
+        when(mMockClient.triggerFeature(any(), any())).thenReturn(responseBuilder.build());
+
+        mHandler.snapshotDevice(mMockDevice, "random_id");
+    }
+
+    @Test
+    public void testDeleteSnapshot_error() throws Exception {
+        FeatureResponse.Builder responseBuilder = FeatureResponse.newBuilder();
+        responseBuilder.setErrorInfo(ErrorInfo.newBuilder().setErrorTrace("random error"));
+        when(mMockClient.triggerFeature(any(), any())).thenReturn(responseBuilder.build());
+
+        try {
+            mHandler.deleteSnapshot(mMockDevice, "random_id");
+            fail("Should have thrown an exception");
+        } catch (HarnessRuntimeException expected) {
+            // Expected
+            assertTrue(expected.getMessage().contains("random error"));
+        }
+    }
+
+    @Test
+    public void testDeleteSnapshot_dnae() throws Exception {
+        DeviceNotAvailableException e = new DeviceNotAvailableException("dnae", "serial");
+        FeatureResponse.Builder responseBuilder = FeatureResponse.newBuilder();
+        responseBuilder.setErrorInfo(
+                ErrorInfo.newBuilder().setErrorTrace(SerializationUtil.serializeToString(e)));
+        when(mMockClient.triggerFeature(any(), any())).thenReturn(responseBuilder.build());
+
+        try {
+            mHandler.deleteSnapshot(mMockDevice, "random_id");
+            fail("Should have thrown an exception");
+        } catch (DeviceNotAvailableException expected) {
+            // Expected
+        }
+    }
+
+    @Test
+    public void testDeleteSnapshot_runtime() throws Exception {
+        Exception e = new RuntimeException("runtime");
+        FeatureResponse.Builder responseBuilder = FeatureResponse.newBuilder();
+        responseBuilder.setErrorInfo(
+                ErrorInfo.newBuilder().setErrorTrace(SerializationUtil.serializeToString(e)));
+        when(mMockClient.triggerFeature(any(), any())).thenReturn(responseBuilder.build());
+
+        try {
+            mHandler.deleteSnapshot(mMockDevice, "random_id");
+            fail("Should have thrown an exception");
+        } catch (HarnessRuntimeException expected) {
+            // Expected
+            assertTrue(expected.getCause() instanceof RuntimeException);
+        }
+    }
 }
diff --git a/javatests/com/android/tradefed/device/metric/FilePullerLogCollectorTest.java b/javatests/com/android/tradefed/device/metric/FilePullerLogCollectorTest.java
index 27ed81697..bbda8c137 100644
--- a/javatests/com/android/tradefed/device/metric/FilePullerLogCollectorTest.java
+++ b/javatests/com/android/tradefed/device/metric/FilePullerLogCollectorTest.java
@@ -250,6 +250,32 @@ public class FilePullerLogCollectorTest {
         assertTrue(collector.isPostProcessed());
     }
 
+    /** Test that files are collected with a data type matching the log-data-type option. */
+    @Test
+    public void testLogDataTypeOption() throws Exception {
+        OptionSetter setter = new OptionSetter(mCollector);
+        setter.setOptionValue("log-data-type", "CONNDIAG");
+        when(mMockDevice.getDeviceState()).thenReturn(TestDeviceState.ONLINE);
+        ITestInvocationListener listener = mCollector.init(mContext, mMockListener);
+        TestDescription test = new TestDescription("class", "test");
+        Map<String, String> metrics = new HashMap<>();
+        metrics.put("log1", "/data/local/tmp/log1.txt");
+
+        ArgumentCaptor<HashMap<String, Metric>> capture = ArgumentCaptor.forClass(HashMap.class);
+
+        when(mMockDevice.getIDevice()).thenReturn(mMockIDevice);
+        when(mMockDevice.pullFile(Mockito.eq("/data/local/tmp/log1.txt"), Mockito.eq(0)))
+                .thenReturn(new File("file"));
+
+        listener.testRunStarted("runName", 1);
+        listener.testStarted(test, 0L);
+        listener.testEnded(test, 50L, TfMetricProtoUtil.upgradeConvert(metrics));
+        listener.testRunEnded(100L, new HashMap<String, Metric>());
+
+        verify(mMockListener)
+                .testLog(Mockito.eq("file"), Mockito.eq(LogDataType.CONNDIAG), Mockito.any());
+    }
+
     private static class PostProcessingFilePullerLogCollector extends FilePullerLogCollector {
         private boolean mIsPostProcessed = false;
 
diff --git a/javatests/com/android/tradefed/observatory/TestDiscoveryExecutorTest.java b/javatests/com/android/tradefed/observatory/TestDiscoveryExecutorTest.java
index 1f9dbee16..66c5ac8c5 100644
--- a/javatests/com/android/tradefed/observatory/TestDiscoveryExecutorTest.java
+++ b/javatests/com/android/tradefed/observatory/TestDiscoveryExecutorTest.java
@@ -65,14 +65,16 @@ public class TestDiscoveryExecutorTest {
     private Configuration mMockedConfiguration;
     private TestDiscoveryExecutor mTestDiscoveryExecutor;
 
+    private TestDiscoveryUtil mTestDiscoveryUtil;
+
     @Before
     public void setUp() throws Exception {
         mMockConfigFactory = Mockito.spy((ConfigurationFactory) ConfigurationFactory.getInstance());
         mMockedConfiguration = Mockito.mock(Configuration.class);
-        mTestDiscoveryExecutor =
-                new TestDiscoveryExecutor() {
+        mTestDiscoveryUtil =
+                new TestDiscoveryUtil() {
                     @Override
-                    IConfigurationFactory getConfigurationFactory() {
+                    public IConfigurationFactory getConfigurationFactory() {
                         return mMockConfigFactory;
                     }
 
@@ -81,6 +83,7 @@ public class TestDiscoveryExecutorTest {
                         return "not-null";
                     }
                 };
+        mTestDiscoveryExecutor = new TestDiscoveryExecutor(mTestDiscoveryUtil);
         doReturn(mMockedConfiguration)
                 .when(mMockConfigFactory)
                 .createPartialConfigurationFromArgs(
@@ -259,10 +262,10 @@ public class TestDiscoveryExecutorTest {
                     mediaConfig);
             File secondNotRunConfig = new File(rootDir, "another.config");
             FileUtil.writeToFile("<configuration></configuration>", secondNotRunConfig);
-            mTestDiscoveryExecutor =
-                    new TestDiscoveryExecutor() {
+            mTestDiscoveryUtil =
+                    new TestDiscoveryUtil() {
                         @Override
-                        IConfigurationFactory getConfigurationFactory() {
+                        public IConfigurationFactory getConfigurationFactory() {
                             return mMockConfigFactory;
                         }
 
@@ -271,6 +274,7 @@ public class TestDiscoveryExecutorTest {
                             return rootDir.getAbsolutePath();
                         }
                     };
+            mTestDiscoveryExecutor = new TestDiscoveryExecutor(mTestDiscoveryUtil);
 
             // Mock to return some include filters
             BaseTestSuite test1 = new BaseTestSuite();
@@ -316,10 +320,10 @@ public class TestDiscoveryExecutorTest {
                     multiConfig);
             File secondNotRunConfig = new File(rootDir, "another.config");
             FileUtil.writeToFile("<configuration></configuration>", secondNotRunConfig);
-            mTestDiscoveryExecutor =
-                    new TestDiscoveryExecutor() {
+            mTestDiscoveryUtil =
+                    new TestDiscoveryUtil() {
                         @Override
-                        IConfigurationFactory getConfigurationFactory() {
+                        public IConfigurationFactory getConfigurationFactory() {
                             return mMockConfigFactory;
                         }
 
@@ -328,6 +332,7 @@ public class TestDiscoveryExecutorTest {
                             return rootDir.getAbsolutePath();
                         }
                     };
+            mTestDiscoveryExecutor = new TestDiscoveryExecutor(mTestDiscoveryUtil);
 
             // Mock to return some include filters
             BaseTestSuite test1 = new BaseTestSuite();
diff --git a/javatests/com/android/tradefed/presubmit/GeneralTestsConfigValidation.java b/javatests/com/android/tradefed/presubmit/GeneralTestsConfigValidation.java
index 6f377641f..6ad3000ac 100644
--- a/javatests/com/android/tradefed/presubmit/GeneralTestsConfigValidation.java
+++ b/javatests/com/android/tradefed/presubmit/GeneralTestsConfigValidation.java
@@ -148,6 +148,7 @@ public class GeneralTestsConfigValidation implements IBuildReceiver {
                             "hidl_test.config",
                             "hidl_test_java.config",
                             "fmq_test.config"));
+
     /** List of configs to exclude until b/277261121 is fixed. */
     private static final Set<String> EXEMPTED_KERNEL_MODULES =
             new HashSet<>(
@@ -467,7 +468,7 @@ public class GeneralTestsConfigValidation implements IBuildReceiver {
                         // See if binary files exists
                         File file32 = FileUtil.findFile(config.getParentFile(), path + "32");
                         File file64 = FileUtil.findFile(config.getParentFile(), path + "64");
-                        if (file32 == null || file64 == null) {
+                        if (file32 == null && file64 == null) {
                             throw new ConfigurationException(
                                     String.format(
                                             "File %s wasn't found in module dependencies while it's"
@@ -477,6 +478,27 @@ public class GeneralTestsConfigValidation implements IBuildReceiver {
                                                     + " field if it's a binary file or under 'data'"
                                                     + " field for all other files.",
                                             path, config.getName()));
+                        } else if (file32 == null || file64 == null) {
+                            // if either binary is missing, make sure the config
+                            // specifies it in the metadata
+                            List<String> parameters =
+                                    c.getConfigurationDescription()
+                                            .getMetaData(ITestSuite.PARAMETER_KEY);
+                            if (parameters == null
+                                    || !parameters.contains(
+                                            ModuleParameters.NOT_MULTI_ABI.toString())) {
+                                String missingVersion = file32 == null ? "32" : "64";
+                                throw new ConfigurationException(
+                                        String.format(
+                                                "File %s is missing a binary version in module"
+                                                    + " dependencies while it's expected to be"
+                                                    + " pushed as part of %s. Make  sure that it's"
+                                                    + " added in the Android.bp file of the module"
+                                                    + " under 'data_device_bins_both' field or that"
+                                                    + " the module specifies the parameter"
+                                                    + " 'not_multi_abi'. Missing version: %s",
+                                                path, config.getName(), missingVersion));
+                            }
                         }
                     }
                 }
diff --git a/javatests/com/android/tradefed/presubmit/TestMappingsValidation.java b/javatests/com/android/tradefed/presubmit/TestMappingsValidation.java
index f7cc9f15a..fff96b47d 100644
--- a/javatests/com/android/tradefed/presubmit/TestMappingsValidation.java
+++ b/javatests/com/android/tradefed/presubmit/TestMappingsValidation.java
@@ -181,8 +181,10 @@ public class TestMappingsValidation implements IBuildReceiver {
                     "CtsContentTestCases",
                     "CtsHostsideNetworkTests",
                     "CtsHostsideNetworkPolicyTests",
+                    "CtsHostsideNetworkPolicyTests_NoRequiresDevice",
                     "vm-tests-tf",
                     "CtsStatsdAtomHostTestCases",
+                    "CtsStatsdAtomHostTestCases_statsdatom_voiceinteraction",
                     "CtsMediaPlayerTestCases",
                     "CtsMediaDecoderTestCases",
                     "CtsQuickAccessWalletTestCases",
diff --git a/javatests/com/android/tradefed/result/ReportPassedTestsTest.java b/javatests/com/android/tradefed/result/ReportPassedTestsTest.java
index b4b1f3a16..36ed98aff 100644
--- a/javatests/com/android/tradefed/result/ReportPassedTestsTest.java
+++ b/javatests/com/android/tradefed/result/ReportPassedTestsTest.java
@@ -81,6 +81,25 @@ public class ReportPassedTestsTest {
         assertTrue(mTestLogCalled);
     }
 
+    @Test
+    public void testReportLarge() {
+        mExpectedString = "";
+        mReporter.testRunStarted("run-name", 0);
+        TestDescription tid = new TestDescription("class", "testName");
+        mReporter.testStarted(tid);
+        mReporter.testFailed(tid, "failed");
+        mReporter.testEnded(tid, Collections.emptyMap());
+        for (int i = 0; i < 550; i++) {
+            TestDescription test = new TestDescription("class", "testName" + i);
+            mReporter.testStarted(test);
+            mReporter.testEnded(test, Collections.emptyMap());
+            mExpectedString += "run-name " + test.toString() + "\n";
+        }
+        mReporter.testRunEnded(0L, Collections.emptyMap());
+        mReporter.invocationEnded(0L);
+        assertTrue(mTestLogCalled);
+    }
+
     @Test
     public void testReport_withRunFailure() {
         mExpectedString = "run-name2\n";
diff --git a/javatests/com/android/tradefed/result/proto/ModuleProtoResultReporterTest.java b/javatests/com/android/tradefed/result/proto/ModuleProtoResultReporterTest.java
index 5cd797b37..3cbb3fbc5 100644
--- a/javatests/com/android/tradefed/result/proto/ModuleProtoResultReporterTest.java
+++ b/javatests/com/android/tradefed/result/proto/ModuleProtoResultReporterTest.java
@@ -16,6 +16,7 @@
 package com.android.tradefed.result.proto;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.verify;
@@ -101,7 +102,7 @@ public class ModuleProtoResultReporterTest {
     public void testModuleReporting_metadata() throws Exception {
         IInvocationContext context = new InvocationContext();
         context.addInvocationAttribute(ModuleProtoResultReporter.INVOCATION_ID_KEY, "I8888");
-        mReporter = new ModuleProtoResultReporter(context);
+        mReporter = new ModuleProtoResultReporter(context, false);
         mReporter.setFileOutput(mOutput);
         TestDescription test1 = new TestDescription("class1", "test1");
 
@@ -109,6 +110,7 @@ public class ModuleProtoResultReporterTest {
         mReporter.testModuleStarted(module1Context);
         mReporter.testRunStarted("run1", 1);
         mReporter.testStarted(test1);
+        mReporter.testFailed(test1, "I failed");
         mReporter.testEnded(test1, new HashMap<String, Metric>());
         mReporter.testRunEnded(200L, new HashMap<String, Metric>());
         module1Context.addInvocationAttribute(ITestSuite.MODULE_END_TIME, "endTime");
@@ -116,6 +118,8 @@ public class ModuleProtoResultReporterTest {
 
         Map<String, String> metadata = ModuleProtoResultReporter.parseResultsMetadata(mOutput);
         assertEquals(metadata.get(ModuleProtoResultReporter.INVOCATION_ID_KEY), "I8888");
+
+        assertTrue(mReporter.stopCaching());
     }
 
     private IInvocationContext createModuleContext(String moduleId) {
diff --git a/javatests/com/android/tradefed/result/proto/ProtoResultReporterTest.java b/javatests/com/android/tradefed/result/proto/ProtoResultReporterTest.java
index 86a92670a..c71343724 100644
--- a/javatests/com/android/tradefed/result/proto/ProtoResultReporterTest.java
+++ b/javatests/com/android/tradefed/result/proto/ProtoResultReporterTest.java
@@ -103,8 +103,6 @@ public class ProtoResultReporterTest {
 
         //  ------ Verify that everything was populated ------
         assertNotNull(mFinalRecord.getTestRecordId());
-        assertNotNull(mFinalRecord.getStartTime().getSeconds());
-        assertNotNull(mFinalRecord.getEndTime().getSeconds());
         assertNotNull(mFinalRecord.getDebugInfo());
 
         // The invocation has 2 modules
@@ -166,8 +164,6 @@ public class ProtoResultReporterTest {
 
         //  ------ Verify that everything was populated ------
         assertNotNull(mFinalRecord.getTestRecordId());
-        assertNotNull(mFinalRecord.getStartTime().getSeconds());
-        assertNotNull(mFinalRecord.getEndTime().getSeconds());
         assertNotNull(mFinalRecord.getDebugInfo());
 
         DebugInfo invocFailure = mFinalRecord.getDebugInfo();
diff --git a/javatests/com/android/tradefed/result/proto/StreamProtoResultReporterTest.java b/javatests/com/android/tradefed/result/proto/StreamProtoResultReporterTest.java
index e4bdf6f67..22981b34a 100644
--- a/javatests/com/android/tradefed/result/proto/StreamProtoResultReporterTest.java
+++ b/javatests/com/android/tradefed/result/proto/StreamProtoResultReporterTest.java
@@ -116,9 +116,9 @@ public class StreamProtoResultReporterTest {
             // Invocation ends
             mReporter.invocationEnded(500L);
         } finally {
+            mReporter.closeSocket();
             receiver.joinReceiver(5000);
             receiver.close();
-            mReporter.closeSocket();
         }
         InOrder inOrder = Mockito.inOrder(mMockListener);
         inOrder.verify(mMockListener).invocationStarted(Mockito.any());
@@ -172,11 +172,11 @@ public class StreamProtoResultReporterTest {
                     "proto-report-port", Integer.toString(receiver.getSocketServerPort()));
             // No calls on the mocks
 
-            // If we join, then we will stop parsing events
-            receiver.joinReceiver(100);
             mReporter.invocationStarted(mInvocationContext);
+            receiver.mStopParsing.set(true);
             // Invocation ends
             mReporter.invocationEnded(500L);
+            receiver.joinReceiver(500L);
         } finally {
             receiver.close();
             mReporter.closeSocket();
@@ -227,9 +227,9 @@ public class StreamProtoResultReporterTest {
             // Invocation ends
             mReporter.invocationEnded(500L);
         } finally {
+            mReporter.closeSocket();
             receiver.joinReceiver(5000);
             receiver.close();
-            mReporter.closeSocket();
         }
 
         verify(mMockListener).testModuleStarted(Mockito.any());
diff --git a/javatests/com/android/tradefed/result/skipped/SkipFeatureTest.java b/javatests/com/android/tradefed/result/skipped/SkipFeatureTest.java
index b4409dace..fd772badf 100644
--- a/javatests/com/android/tradefed/result/skipped/SkipFeatureTest.java
+++ b/javatests/com/android/tradefed/result/skipped/SkipFeatureTest.java
@@ -17,7 +17,6 @@ package com.android.tradefed.result.skipped;
 
 import com.android.tradefed.config.Configuration;
 import com.android.tradefed.config.IConfiguration;
-import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.invoker.InvocationContext;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.service.TradefedFeatureClient;
@@ -79,8 +78,6 @@ public class SkipFeatureTest {
                         return image;
                     }
                 };
-        OptionSetter setter = new OptionSetter(skipManager);
-        setter.setOptionValue("report-module-skipped", "true");
         mConfiguration.setConfigurationObject(Configuration.SKIP_MANAGER_TYPE_NAME, skipManager);
         mSkipGetter.setConfiguration(mConfiguration);
         mSkipGetter.setTestInformation(mTestInfo);
diff --git a/javatests/com/android/tradefed/service/management/DeviceManagementGrpcServerTest.java b/javatests/com/android/tradefed/service/management/DeviceManagementGrpcServerTest.java
index 5aeda72fb..b47bb917d 100644
--- a/javatests/com/android/tradefed/service/management/DeviceManagementGrpcServerTest.java
+++ b/javatests/com/android/tradefed/service/management/DeviceManagementGrpcServerTest.java
@@ -39,6 +39,7 @@ import com.proto.tradefed.device.ReserveDeviceRequest;
 import com.proto.tradefed.device.ReserveDeviceResponse;
 
 import io.grpc.Server;
+import io.grpc.Status;
 import io.grpc.stub.ServerCallStreamObserver;
 import io.grpc.stub.StreamObserver;
 
@@ -260,16 +261,14 @@ public class DeviceManagementGrpcServerTest {
                 .thenReturn(createDescriptor("serial1", DeviceAllocationState.Available));
         ITestDevice mockedDevice = Mockito.mock(ITestDevice.class);
         when(mMockDeviceManager.allocateDevice(Mockito.any())).thenReturn(mockedDevice);
-        when(mReserveDeviceResponseObserver.isCancelled()).thenReturn(false).thenReturn(true);
-        // Allocate a device
-        mServer.reserveDevice(
-                ReserveDeviceRequest.newBuilder().setDeviceId("serial1").build(),
-                mReserveDeviceResponseObserver);
-        verify(mReserveDeviceResponseObserver).onNext(mReserveDeviceResponseCaptor.capture());
-        ReserveDeviceResponse reservation = mReserveDeviceResponseCaptor.getValue();
-        assertThat(reservation.getResult()).isEqualTo(ReserveDeviceResponse.Result.UNKNOWN);
-        String reservationId = reservation.getReservationId();
-        assertThat(reservationId).isEmpty();
+    Mockito.doThrow(
+            Status.CANCELLED.withDescription("call already cancelled.").asRuntimeException())
+        .when(mReserveDeviceResponseObserver)
+        .onNext(Mockito.any());
+    // Allocate a device
+    mServer.reserveDevice(
+        ReserveDeviceRequest.newBuilder().setDeviceId("serial1").build(),
+        mReserveDeviceResponseObserver);
         verify(mMockDeviceManager).allocateDevice(Mockito.any());
         verify(mMockDeviceManager).freeDevice(mockedDevice, FreeDeviceState.AVAILABLE);
     }
diff --git a/javatests/com/android/tradefed/suite/checker/baseline/LockSettingsBaselineSetterTest.java b/javatests/com/android/tradefed/suite/checker/baseline/LockSettingsBaselineSetterTest.java
index 52239ccd4..4aecb532e 100644
--- a/javatests/com/android/tradefed/suite/checker/baseline/LockSettingsBaselineSetterTest.java
+++ b/javatests/com/android/tradefed/suite/checker/baseline/LockSettingsBaselineSetterTest.java
@@ -48,6 +48,7 @@ public final class LockSettingsBaselineSetterTest {
     private static final String LOCK_SCREEN_OFF_COMMAND = "locksettings set-disabled true";
     private static final String CLEAR_PWD_COMMAND = "locksettings clear --old %s";
     private static final String KEYCODE_MENU_COMMAND = "input keyevent KEYCODE_MENU";
+    private static final String KEYCODE_HOME_COMMAND = "input keyevent KEYCODE_HOME";
 
     @Before
     public void setup() throws Exception {
@@ -72,6 +73,8 @@ public final class LockSettingsBaselineSetterTest {
                 .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, "true"));
         when(mMockDevice.executeShellV2Command(KEYCODE_MENU_COMMAND))
                 .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, null));
+        when(mMockDevice.executeShellV2Command(KEYCODE_HOME_COMMAND))
+                .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, null));
         assertTrue(mSetter.setBaseline(mMockDevice));
         verify(mMockDevice, never()).executeShellV2Command(LOCK_SCREEN_OFF_COMMAND);
         verify(mMockDevice, never())
@@ -89,6 +92,8 @@ public final class LockSettingsBaselineSetterTest {
                         getMockCommandResult(CommandStatus.SUCCESS, "true"));
         when(mMockDevice.executeShellV2Command(KEYCODE_MENU_COMMAND))
                 .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, null));
+        when(mMockDevice.executeShellV2Command(KEYCODE_HOME_COMMAND))
+                .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, null));
         assertTrue(mSetter.setBaseline(mMockDevice));
         verify(mMockDevice).executeShellV2Command(LOCK_SCREEN_OFF_COMMAND);
         verify(mMockDevice).executeShellV2Command(String.format(CLEAR_PWD_COMMAND, "0000"));
@@ -102,6 +107,8 @@ public final class LockSettingsBaselineSetterTest {
                 .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, "false"));
         when(mMockDevice.executeShellV2Command(KEYCODE_MENU_COMMAND))
                 .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, null));
+        when(mMockDevice.executeShellV2Command(KEYCODE_HOME_COMMAND))
+                .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, null));
         assertFalse(mSetter.setBaseline(mMockDevice));
     }
 
@@ -112,6 +119,20 @@ public final class LockSettingsBaselineSetterTest {
                 .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, "true"));
         when(mMockDevice.executeShellV2Command(KEYCODE_MENU_COMMAND))
                 .thenReturn(getMockCommandResult(CommandStatus.FAILED, null));
+        when(mMockDevice.executeShellV2Command(KEYCODE_HOME_COMMAND))
+                .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, null));
+        assertFalse(mSetter.setBaseline(mMockDevice));
+    }
+
+    /** Test that the setter returns false when the baseline is failed to input KEYCODE_HOME. */
+    @Test
+    public void setBaseline_inputKeycodeHomeFails_returnFalse() throws Exception {
+        when(mMockDevice.executeShellV2Command(GET_LOCK_SCREEN_COMMAND))
+                .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, "true"));
+        when(mMockDevice.executeShellV2Command(KEYCODE_MENU_COMMAND))
+                .thenReturn(getMockCommandResult(CommandStatus.SUCCESS, null));
+        when(mMockDevice.executeShellV2Command(KEYCODE_HOME_COMMAND))
+                .thenReturn(getMockCommandResult(CommandStatus.FAILED, null));
         assertFalse(mSetter.setBaseline(mMockDevice));
     }
 
diff --git a/javatests/com/android/tradefed/targetprep/DefaultTestsZipInstallerTest.java b/javatests/com/android/tradefed/targetprep/DefaultTestsZipInstallerTest.java
index 440866837..85d2cafc5 100644
--- a/javatests/com/android/tradefed/targetprep/DefaultTestsZipInstallerTest.java
+++ b/javatests/com/android/tradefed/targetprep/DefaultTestsZipInstallerTest.java
@@ -45,7 +45,6 @@ import java.io.File;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collection;
-import java.util.HashSet;
 import java.util.Set;
 
 @RunWith(JUnit4.class)
@@ -54,10 +53,6 @@ public class DefaultTestsZipInstallerTest {
 
     private static final String TEST_STRING = "foo";
 
-    private static final File SOME_PATH_1 = new File("/some/path/1");
-
-    private static final File SOME_PATH_2 = new File("/some/path/2");
-
     @Mock ITestDevice mMockDevice;
     private IDeviceBuildInfo mDeviceBuild;
     private DefaultTestsZipInstaller mZipInstaller;
@@ -74,14 +69,6 @@ public class DefaultTestsZipInstallerTest {
                         return new File[] {new File(TEST_STRING)};
                     }
 
-                    @Override
-                    Set<File> findDirs(File hostDir, File deviceRootPath) {
-                        Set<File> files = new HashSet<File>(2);
-                        files.add(SOME_PATH_1);
-                        files.add(SOME_PATH_2);
-                        return files;
-                    }
-
                     @Override
                     IRunUtil getRunUtil() {
                         return mock(IRunUtil.class);
@@ -165,10 +152,8 @@ public class DefaultTestsZipInstallerTest {
                 .thenReturn(Boolean.TRUE);
 
         when(mMockDevice.executeShellCommand(
-                        Mockito.startsWith("chown system.system " + SOME_PATH_1.getPath())))
-                .thenReturn("");
-        when(mMockDevice.executeShellCommand(
-                        Mockito.startsWith("chown system.system " + SOME_PATH_2.getPath())))
+                        Mockito.startsWith(
+                                "chown -R system.system " + FileListingService.DIRECTORY_DATA)))
                 .thenReturn("");
 
         mZipInstaller.pushTestsZipOntoData(mMockDevice, mDeviceBuild);
diff --git a/javatests/com/android/tradefed/targetprep/FastbootCommandPreparerTest.java b/javatests/com/android/tradefed/targetprep/FastbootCommandPreparerTest.java
new file mode 100644
index 000000000..1d56089e8
--- /dev/null
+++ b/javatests/com/android/tradefed/targetprep/FastbootCommandPreparerTest.java
@@ -0,0 +1,197 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *            http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.tradefed.targetprep;
+
+import static org.junit.Assert.assertThrows;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import com.android.tradefed.build.BuildInfo;
+import com.android.tradefed.build.IBuildInfo;
+import com.android.tradefed.config.OptionSetter;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.invoker.IInvocationContext;
+import com.android.tradefed.invoker.TestInformation;
+import com.android.tradefed.testtype.suite.ModuleDefinition;
+import com.android.tradefed.util.CommandResult;
+import com.android.tradefed.util.CommandStatus;
+import java.io.File;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TemporaryFolder;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Mock;
+import org.mockito.junit.MockitoJUnit;
+import org.mockito.junit.MockitoRule;
+
+/** Unit Tests for {@link FastbootCommandPreparer}. */
+@RunWith(JUnit4.class)
+public final class FastbootCommandPreparerTest {
+    @Rule public final MockitoRule mMockitoRule = MockitoJUnit.rule();
+    @Rule public TemporaryFolder tmpDir = new TemporaryFolder();
+
+    @Mock private TestInformation mMockTestInfo;
+    @Mock private ITestDevice mMockDevice;
+    @Mock private IInvocationContext mMockInvocationContext;
+    @Mock private IBuildInfo mMockBuildInfo;
+
+    private FastbootCommandPreparer mPreparer;
+    private CommandResult fastbootResult;
+
+    @Before
+    public void setUp() throws Exception {
+        mPreparer = new FastbootCommandPreparer();
+        when(mMockTestInfo.getDevice()).thenReturn(mMockDevice);
+        when(mMockTestInfo.getContext()).thenReturn(mMockInvocationContext);
+        when(mMockInvocationContext.getAttribute(ModuleDefinition.MODULE_NAME)).thenReturn(null);
+        when(mMockInvocationContext.getBuildInfo(eq(mMockDevice))).thenReturn(mMockBuildInfo);
+
+        // Default to successful execution.
+        fastbootResult = new CommandResult(CommandStatus.SUCCESS);
+        fastbootResult.setExitCode(0);
+        when(mMockDevice.executeFastbootCommand(any())).thenReturn(fastbootResult);
+    }
+
+    @Test
+    public void testSetUp_extraFile() throws Exception {
+        OptionSetter optionSetter = new OptionSetter(mPreparer);
+        optionSetter.setOptionValue(
+                "command", "command $EXTRA_FILE(test_file1) $EXTRA_FILE(test_file2)");
+
+        BuildInfo stubBuild = new BuildInfo("stub", "stub");
+        File testFile1 = tmpDir.newFile("test_file1");
+        stubBuild.setFile("test_file1", testFile1, "0");
+        when(mMockTestInfo.getBuildInfo()).thenReturn(stubBuild);
+
+        fastbootResult = new CommandResult(CommandStatus.SUCCESS);
+        fastbootResult.setStatus(CommandStatus.SUCCESS);
+        fastbootResult.setExitCode(0);
+        when(mMockDevice.executeFastbootCommand(
+                        eq("command"),
+                        eq(testFile1.getAbsolutePath()),
+                        eq("$EXTRA_FILE(test_file2)")))
+                .thenReturn(fastbootResult);
+        when(mMockDevice.getDeviceDescriptor()).thenReturn(null);
+
+        mPreparer.setUp(mMockTestInfo);
+
+        verify(mMockDevice).rebootIntoBootloader();
+        verify(mMockDevice).executeFastbootCommand(
+                           eq("command"),
+                           eq(testFile1.getAbsolutePath()),
+                           eq("$EXTRA_FILE(test_file2)"));
+        verify(mMockDevice).reboot();
+    }
+
+    @Test
+    public void testTearDown_extraFile() throws Exception {
+        OptionSetter optionSetter = new OptionSetter(mPreparer);
+        optionSetter.setOptionValue(
+                "teardown-command", "command $EXTRA_FILE(test_file1) $EXTRA_FILE(test_file2)");
+
+        BuildInfo stubBuild = new BuildInfo("stub", "stub");
+        File testFile1 = tmpDir.newFile("test_file1");
+        stubBuild.setFile("test_file1", testFile1, "0");
+        when(mMockTestInfo.getBuildInfo()).thenReturn(stubBuild);
+
+        fastbootResult = new CommandResult(CommandStatus.SUCCESS);
+        fastbootResult.setStatus(CommandStatus.SUCCESS);
+        fastbootResult.setExitCode(0);
+        when(mMockDevice.executeFastbootCommand(
+                        eq("command"),
+                        eq(testFile1.getAbsolutePath()),
+                        eq("$EXTRA_FILE(test_file2)")))
+                .thenReturn(fastbootResult);
+        when(mMockDevice.getDeviceDescriptor()).thenReturn(null);
+
+        mPreparer.tearDown(mMockTestInfo, null);
+
+        verify(mMockDevice).rebootIntoBootloader();
+        verify(mMockDevice).executeFastbootCommand(
+                           eq("command"),
+                           eq(testFile1.getAbsolutePath()),
+                           eq("$EXTRA_FILE(test_file2)"));
+        verify(mMockDevice).reboot();
+    }
+
+    @Test
+    public void testSetUp_fastbootdMode() throws Exception {
+        OptionSetter optionSetter = new OptionSetter(mPreparer);
+        optionSetter.setOptionValue("fastboot-mode", "FASTBOOTD");
+        optionSetter.setOptionValue("command", "command");
+
+        mPreparer.setUp(mMockTestInfo);
+
+        verify(mMockDevice).rebootIntoFastbootd();
+        verify(mMockDevice).executeFastbootCommand(eq("command"));
+        verify(mMockDevice).reboot();
+    }
+
+    @Test
+    public void testTearDown_fastbootMode() throws Exception {
+        OptionSetter optionSetter = new OptionSetter(mPreparer);
+        optionSetter.setOptionValue("fastboot-mode", "FASTBOOTD");
+        optionSetter.setOptionValue("teardown-command", "command");
+
+        mPreparer.tearDown(mMockTestInfo, null);
+
+        verify(mMockDevice).rebootIntoFastbootd();
+        verify(mMockDevice).executeFastbootCommand(eq("command"));
+        verify(mMockDevice).reboot();
+    }
+
+    @Test
+    public void testSetUp_stayFastboot() throws Exception {
+        OptionSetter optionSetter = new OptionSetter(mPreparer);
+        optionSetter.setOptionValue("stay-fastboot", "true");
+        optionSetter.setOptionValue("command", "command");
+
+        mPreparer.setUp(mMockTestInfo);
+        verify(mMockDevice, never()).reboot();
+    }
+
+    @Test
+    public void testTearDown_stayFastboot() throws Exception {
+        OptionSetter optionSetter = new OptionSetter(mPreparer);
+        optionSetter.setOptionValue("stay-fastboot", "true");
+        optionSetter.setOptionValue("teardown-command", "command");
+
+        mPreparer.tearDown(mMockTestInfo, null);
+        verify(mMockDevice, never()).reboot();
+    }
+
+    @Test
+    public void testSetUp_withErrors() throws Exception {
+        OptionSetter optionSetter = new OptionSetter(mPreparer);
+        optionSetter.setOptionValue("command", "command");
+
+        when(mMockDevice.getDeviceDescriptor()).thenReturn(null);
+
+        // Verify that failed commands will throw exception during setup
+        fastbootResult = new CommandResult(CommandStatus.FAILED);
+        fastbootResult.setExitCode(1);
+        when(mMockDevice.executeFastbootCommand(any())).thenReturn(fastbootResult);
+        assertThrows(TargetSetupError.class, () -> {
+            mPreparer.setUp(mMockTestInfo);
+        });
+    }
+}
\ No newline at end of file
diff --git a/javatests/com/android/tradefed/targetprep/GkiDeviceFlashPreparerTest.java b/javatests/com/android/tradefed/targetprep/GkiDeviceFlashPreparerTest.java
index 12957eea0..a3a37e511 100644
--- a/javatests/com/android/tradefed/targetprep/GkiDeviceFlashPreparerTest.java
+++ b/javatests/com/android/tradefed/targetprep/GkiDeviceFlashPreparerTest.java
@@ -309,6 +309,9 @@ public class GkiDeviceFlashPreparerTest {
         File otaBinDir = FileUtil.createNamedTempDir(otaDir, "bin");
         File avbtoolFile = new File(otaBinDir, "avbtool");
         FileUtil.writeToFile("ddd", avbtoolFile);
+        File otaKeyDir = FileUtil.createNamedTempDir(otaDir, "external/avb/test/data/");
+        File keyFile = new File(otaKeyDir, "testkey_rsa4096.pem");
+        FileUtil.writeToFile("xyz", keyFile);
         File otatoolsZip = FileUtil.createTempFile("otatools", ".zip", mTmpDir);
         ZipUtil.createZip(List.of(otaDir.listFiles()), otatoolsZip);
         mBuildInfo.setFile("otatools.zip", otatoolsZip, "0");
@@ -328,6 +331,10 @@ public class GkiDeviceFlashPreparerTest {
                         eq(bootImg.getAbsolutePath()),
                         eq("--partition_size"),
                         eq("53477376"),
+                        eq("--algorithm"),
+                        eq("SHA256_RSA4096"),
+                        eq("--key"),
+                        matches(".*testkey_rsa4096.pem"),
                         eq("--partition_name"),
                         eq("boot"),
                         eq("--prop"),
@@ -381,10 +388,10 @@ public class GkiDeviceFlashPreparerTest {
         FileUtil.writeToFile("ddd", bootImg);
         mBuildInfo.setFile("gki_boot.img", bootImg, "0");
 
+        when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
         when(mMockDevice.executeLongFastbootCommand(
                         "flash", "boot", mBuildInfo.getFile("gki_boot.img").getAbsolutePath()))
                 .thenReturn(mSuccessResult);
-        when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
 
         when(mMockDevice.enableAdbRoot()).thenReturn(Boolean.TRUE);
 
@@ -411,13 +418,46 @@ public class GkiDeviceFlashPreparerTest {
         mBuildInfo.setFile("gki_boot.img", bootImg, "0");
         mOptionSetter.setOptionValue("fastboot-flash-option", "--disable-verity");
 
+        when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
         when(mMockDevice.executeLongFastbootCommand(
                         "--disable-verity",
                         "flash",
                         "boot",
                         mBuildInfo.getFile("gki_boot.img").getAbsolutePath()))
                 .thenReturn(mSuccessResult);
+
+        when(mMockDevice.enableAdbRoot()).thenReturn(Boolean.TRUE);
+
+        mPreparer.setUp(mTestInfo);
+        mPreparer.tearDown(mTestInfo, null);
+
+        verify(mMockDevice).rebootIntoBootloader();
+        verify(mMockRunUtil).allowInterrupt(false);
+        verify(mMockRunUtil).allowInterrupt(true);
+        verify(mMockRunUtil).sleep(anyLong());
+        verify(mMockDevice).rebootUntilOnline();
+        verify(mMockDevice).setDate(null);
+        verify(mMockDevice).waitForDeviceAvailable(anyLong());
+        verify(mMockDevice).setRecoveryMode(RecoveryMode.AVAILABLE);
+        verify(mMockDevice).postBootSetup();
+    }
+
+    /* Verifies that preparer can flash GKI boot image with additional fastboot commands */
+    @Test
+    public void testSetup_Success_with_additional_fastboot_commands() throws Exception {
+        File bootImg = FileUtil.createTempFile("boot", ".img", mTmpDir);
+        bootImg.renameTo(new File(mTmpDir, "boot.img"));
+        FileUtil.writeToFile("ddd", bootImg);
+        mBuildInfo.setFile("gki_boot.img", bootImg, "0");
+        mOptionSetter.setOptionValue("additional-fastboot-command", "erase misc");
+        mOptionSetter.setOptionValue("additional-fastboot-command", "erase devinfo");
+
         when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
+        when(mMockDevice.executeLongFastbootCommand(
+                        "flash", "boot", mBuildInfo.getFile("gki_boot.img").getAbsolutePath()))
+                .thenReturn(mSuccessResult);
+        when(mMockDevice.executeLongFastbootCommand("erase misc")).thenReturn(mSuccessResult);
+        when(mMockDevice.executeLongFastbootCommand("erase devinfo")).thenReturn(mSuccessResult);
 
         when(mMockDevice.enableAdbRoot()).thenReturn(Boolean.TRUE);
 
@@ -493,6 +533,7 @@ public class GkiDeviceFlashPreparerTest {
         mBuildInfo.setFile("vendor_dlkm.img", vendorDlkmImg, "0");
         mBuildInfo.setFile("dtbo.img", dtboImg, "0");
 
+        when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
         when(mMockDevice.executeLongFastbootCommand(
                         "flash", "boot", mBuildInfo.getFile("gki_boot.img").getAbsolutePath()))
                 .thenReturn(mSuccessResult);
@@ -514,7 +555,6 @@ public class GkiDeviceFlashPreparerTest {
         when(mMockDevice.executeLongFastbootCommand(
                         "flash", "dtbo", mBuildInfo.getFile("dtbo.img").getAbsolutePath()))
                 .thenReturn(mSuccessResult);
-        when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
 
         when(mMockDevice.enableAdbRoot()).thenReturn(Boolean.TRUE);
 
@@ -551,6 +591,7 @@ public class GkiDeviceFlashPreparerTest {
         mBuildInfo.setFile("vendor_boot.img", imgZip, "0");
         mBuildInfo.setFile("dtbo.img", imgZip, "0");
 
+        when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
         when(mMockDevice.executeLongFastbootCommand(
                         eq("flash"), eq("boot"), matches(".*boot-5.4.img")))
                 .thenReturn(mSuccessResult);
@@ -562,7 +603,6 @@ public class GkiDeviceFlashPreparerTest {
                 .thenReturn(mSuccessResult);
         when(mMockDevice.executeLongFastbootCommand(eq("flash"), eq("dtbo"), matches(".*dtbo.img")))
                 .thenReturn(mSuccessResult);
-        when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
 
         when(mMockDevice.enableAdbRoot()).thenReturn(Boolean.TRUE);
 
@@ -591,6 +631,7 @@ public class GkiDeviceFlashPreparerTest {
         FileUtil.writeToFile("not an empty file", deviceImg);
         mBuildInfo.setDeviceImageFile(deviceImg, "0");
 
+        when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
         when(mMockDevice.executeLongFastbootCommand(
                         "flash", "boot", mBuildInfo.getFile("gki_boot.img").getAbsolutePath()))
                 .thenReturn(mFailureResult);
@@ -618,10 +659,10 @@ public class GkiDeviceFlashPreparerTest {
         FileUtil.writeToFile("not an empty file", deviceImg);
         mBuildInfo.setDeviceImageFile(deviceImg, "0");
 
+        when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
         when(mMockDevice.executeLongFastbootCommand(
                         "flash", "boot", mBuildInfo.getFile("gki_boot.img").getAbsolutePath()))
                 .thenReturn(mSuccessResult);
-        when(mMockDevice.executeLongFastbootCommand("-w")).thenReturn(mSuccessResult);
 
         doThrow(new DeviceNotAvailableException("test", "serial"))
                 .when(mMockDevice)
@@ -747,4 +788,3 @@ public class GkiDeviceFlashPreparerTest {
         }
     }
 }
-
diff --git a/javatests/com/android/tradefed/targetprep/OtaUpdateDeviceFlasherTest.java b/javatests/com/android/tradefed/targetprep/OtaUpdateDeviceFlasherTest.java
index 75e2f23c1..157bd8fe4 100644
--- a/javatests/com/android/tradefed/targetprep/OtaUpdateDeviceFlasherTest.java
+++ b/javatests/com/android/tradefed/targetprep/OtaUpdateDeviceFlasherTest.java
@@ -158,14 +158,48 @@ public class OtaUpdateDeviceFlasherTest {
     }
 
     @Test
-    public void testFlash() throws Exception {
+    public void testFlash_success() throws Exception {
         // prep
+        mFlasher.setUserDataFlashOption(UserDataFlashOption.WIPE);
+        when(mMockDevice.enableAdbRoot()).thenReturn(true);
+        when(mMockDevice.setProperty(
+                        Mockito.eq(OtaUpdateDeviceFlasher.OTA_DOWNGRADE_PROP), Mockito.eq("1")))
+                .thenReturn(true);
+        CommandResult cr = new CommandResult();
+        cr.setStatus(CommandStatus.SUCCESS);
+        cr.setStderr(OtaUpdateDeviceFlasher.UPDATE_SUCCESS_OUTPUT);
+        when(mMockRunUtil.runTimedCmd(Mockito.any(long.class), Mockito.any())).thenReturn(cr);
+        doNothing().when(mMockDevice).rebootUntilOnline();
+        // test
+        IDeviceBuildInfo dbi = setupDeviceBuildInfoForOta();
+        mFlasher.preFlashOperations(mMockDevice, dbi);
+        mFlasher.flash(mMockDevice, dbi);
+        // verify
+        mInOrder.verify(mMockDevice).enableAdbRoot();
+        mInOrder.verify(mMockDevice).executeShellCommand("stop");
+        mInOrder.verify(mMockDevice).executeShellCommand("rm -rf /data/*");
+        mInOrder.verify(mMockDevice).reboot();
+        mInOrder.verify(mMockDevice).waitForDeviceAvailable();
+        mInOrder.verify(mMockDevice).enableAdbRoot();
+        mInOrder.verify(mMockDevice).executeShellCommand("svc power stayon true");
+        mInOrder.verify(mMockDevice)
+                .setProperty(
+                        Mockito.eq(OtaUpdateDeviceFlasher.OTA_DOWNGRADE_PROP), Mockito.eq("1"));
+        mInOrder.verify(mMockRunUtil).runTimedCmd(Mockito.any(long.class), Mockito.any());
+        mInOrder.verify(mMockDevice).rebootUntilOnline();
+    }
+
+    @Test(expected = TargetSetupError.class)
+    public void testFlash_no_success_output() throws Exception {
+        // prep
+        mFlasher.setUserDataFlashOption(UserDataFlashOption.WIPE);
         when(mMockDevice.enableAdbRoot()).thenReturn(true);
         when(mMockDevice.setProperty(
                         Mockito.eq(OtaUpdateDeviceFlasher.OTA_DOWNGRADE_PROP), Mockito.eq("1")))
                 .thenReturn(true);
         CommandResult cr = new CommandResult();
         cr.setStatus(CommandStatus.SUCCESS);
+        cr.setStderr("onPayloadApplicationComplete(ErrorCode::kInstallDeviceOpenError (7))");
         when(mMockRunUtil.runTimedCmd(Mockito.any(long.class), Mockito.any())).thenReturn(cr);
         doNothing().when(mMockDevice).rebootUntilOnline();
         // test
@@ -174,6 +208,44 @@ public class OtaUpdateDeviceFlasherTest {
         mFlasher.flash(mMockDevice, dbi);
         // verify
         mInOrder.verify(mMockDevice).enableAdbRoot();
+        mInOrder.verify(mMockDevice).executeShellCommand("stop");
+        mInOrder.verify(mMockDevice).executeShellCommand("rm -rf /data/*");
+        mInOrder.verify(mMockDevice).reboot();
+        mInOrder.verify(mMockDevice).waitForDeviceAvailable();
+        mInOrder.verify(mMockDevice).enableAdbRoot();
+        mInOrder.verify(mMockDevice).executeShellCommand("svc power stayon true");
+        mInOrder.verify(mMockDevice)
+                .setProperty(
+                        Mockito.eq(OtaUpdateDeviceFlasher.OTA_DOWNGRADE_PROP), Mockito.eq("1"));
+        mInOrder.verify(mMockRunUtil).runTimedCmd(Mockito.any(long.class), Mockito.any());
+        mInOrder.verify(mMockDevice).rebootUntilOnline();
+    }
+
+    @Test(expected = TargetSetupError.class)
+    public void testFlash_command_failure() throws Exception {
+        // prep
+        mFlasher.setUserDataFlashOption(UserDataFlashOption.WIPE);
+        when(mMockDevice.enableAdbRoot()).thenReturn(true);
+        when(mMockDevice.setProperty(
+                        Mockito.eq(OtaUpdateDeviceFlasher.OTA_DOWNGRADE_PROP), Mockito.eq("1")))
+                .thenReturn(true);
+        CommandResult cr = new CommandResult();
+        cr.setStatus(CommandStatus.FAILED);
+        cr.setStderr(OtaUpdateDeviceFlasher.UPDATE_SUCCESS_OUTPUT);
+        when(mMockRunUtil.runTimedCmd(Mockito.any(long.class), Mockito.any())).thenReturn(cr);
+        doNothing().when(mMockDevice).rebootUntilOnline();
+        // test
+        IDeviceBuildInfo dbi = setupDeviceBuildInfoForOta();
+        mFlasher.preFlashOperations(mMockDevice, dbi);
+        mFlasher.flash(mMockDevice, dbi);
+        // verify
+        mInOrder.verify(mMockDevice).enableAdbRoot();
+        mInOrder.verify(mMockDevice).executeShellCommand("stop");
+        mInOrder.verify(mMockDevice).executeShellCommand("rm -rf /data/*");
+        mInOrder.verify(mMockDevice).reboot();
+        mInOrder.verify(mMockDevice).waitForDeviceAvailable();
+        mInOrder.verify(mMockDevice).enableAdbRoot();
+        mInOrder.verify(mMockDevice).executeShellCommand("svc power stayon true");
         mInOrder.verify(mMockDevice)
                 .setProperty(
                         Mockito.eq(OtaUpdateDeviceFlasher.OTA_DOWNGRADE_PROP), Mockito.eq("1"));
diff --git a/javatests/com/android/tradefed/targetprep/TestAppInstallSetupTest.java b/javatests/com/android/tradefed/targetprep/TestAppInstallSetupTest.java
index 6b94998f5..0b1dcfbda 100644
--- a/javatests/com/android/tradefed/targetprep/TestAppInstallSetupTest.java
+++ b/javatests/com/android/tradefed/targetprep/TestAppInstallSetupTest.java
@@ -517,6 +517,35 @@ public class TestAppInstallSetupTest {
         Mockito.verify(mMockIncrementalInstallSessionBuilder).build();
     }
 
+    @Test
+    public void testSetup_incrementalSetupDisabledExplicitly_noOp() throws Exception {
+        when(mMockTestDevice.installPackage(Mockito.eq(fakeApk), Mockito.eq(true)))
+                .thenReturn(null);
+        when(mMockTestDevice.installPackages(Mockito.eq(mTestSplitApkFiles), Mockito.eq(true)))
+                .thenReturn(null);
+        mPrep.setIncrementalSetupEnabled(false);
+
+        mPrep.setUp(mTestInfo);
+
+        Mockito.verify(mMockTestDevice).installPackage(Mockito.eq(fakeApk), Mockito.eq(true));
+        Mockito.verify(mMockTestDevice)
+            .installPackages(Mockito.eq(mTestSplitApkFiles), Mockito.eq(true));
+    }
+
+    @Test
+    public void testSetup_incrementalSetupDisabledByDefault_noOp() throws Exception {
+        when(mMockTestDevice.installPackage(Mockito.eq(fakeApk), Mockito.eq(true)))
+                .thenReturn(null);
+        when(mMockTestDevice.installPackages(Mockito.eq(mTestSplitApkFiles), Mockito.eq(true)))
+                .thenReturn(null);
+
+        mPrep.setUp(mTestInfo);
+
+        Mockito.verify(mMockTestDevice).installPackage(Mockito.eq(fakeApk), Mockito.eq(true));
+        Mockito.verify(mMockTestDevice)
+            .installPackages(Mockito.eq(mTestSplitApkFiles), Mockito.eq(true));
+    }
+
     @Test
     public void testInstallFailure() throws Exception {
         final String failure = "INSTALL_PARSE_FAILED_MANIFEST_MALFORMED";
@@ -822,7 +851,7 @@ public class TestAppInstallSetupTest {
             fail("Should have thrown an exception");
         } catch (TargetSetupError expected) {
             assertEquals(
-                    String.format("Failed to extract info from `%s` using aapt", fakeApk.getName()),
+                    String.format("Failed to extract info from `%s` using aapt2", fakeApk.getName()),
                     expected.getMessage());
         } finally {
         }
diff --git a/javatests/com/android/tradefed/targetprep/incremental/ApkChangeDetectorTest.java b/javatests/com/android/tradefed/targetprep/incremental/ApkChangeDetectorTest.java
new file mode 100644
index 000000000..5e00f4eb4
--- /dev/null
+++ b/javatests/com/android/tradefed/targetprep/incremental/ApkChangeDetectorTest.java
@@ -0,0 +1,225 @@
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
+package com.android.tradefed.targetprep.incremental;
+
+import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.assertThrows;
+import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.doThrow;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.spy;
+
+import com.android.tradefed.device.ITestDevice;
+import java.io.File;
+import java.util.ArrayList;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Set;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Mockito;
+
+@RunWith(JUnit4.class)
+public final class ApkChangeDetectorTest {
+
+    private ApkChangeDetector mApkChangeDetector;
+    private ApkChangeDetector mApkChangeDetectorLessDiskSpace;
+    private ApkChangeDetector mApkChangeDetectorDiskSpaceNotObtained;
+    private ITestDevice mMockDevice;
+    private File mMockFile1;
+    private File mMockFile2;
+    private File mMockFile3;
+    private List<File> mMockTestApps;
+
+    @Before
+    public void setUp() throws Exception {
+        mApkChangeDetector = spy(new ApkChangeDetector());
+        mApkChangeDetectorLessDiskSpace = spy(new ApkChangeDetector());
+        mApkChangeDetectorDiskSpaceNotObtained = spy(new ApkChangeDetector());
+        mMockDevice = mock(ITestDevice.class);
+        mMockFile1 = mock(File.class);
+        mMockFile2 = mock(File.class);
+        mMockFile3 = mock(File.class);
+
+        mMockTestApps = new ArrayList<>();
+        mMockTestApps.add(mMockFile1);
+        mMockTestApps.add(mMockFile2);
+        mMockTestApps.add(mMockFile3);
+        doReturn(1000000L).when(mMockFile1).length();
+        doReturn(2000000L).when(mMockFile2).length();
+        doReturn(3000000L).when(mMockFile3).length();
+
+        List<String> apkInstallPaths = new ArrayList<>();
+        apkInstallPaths.add("/a.b.c.package.installPath/file1.apk");
+        apkInstallPaths.add("/a.b.c.package.installPath/file2.apk");
+        apkInstallPaths.add("/a.b.c.package.installPath/file3.apk");
+
+        doReturn(apkInstallPaths)
+            .when(mApkChangeDetector)
+            .getApkInstallPaths(Mockito.any(), Mockito.any());
+        doReturn(apkInstallPaths)
+            .when(mApkChangeDetectorLessDiskSpace)
+            .getApkInstallPaths(Mockito.any(), Mockito.any());
+        doReturn(apkInstallPaths)
+            .when(mApkChangeDetectorDiskSpaceNotObtained)
+            .getApkInstallPaths(Mockito.any(), Mockito.any());
+        doReturn(2000000000L)
+            .when(mApkChangeDetector)
+            .getFreeDiskSpaceForAppInstallation(Mockito.any());
+        doReturn(15000000L)
+            .when(mApkChangeDetectorLessDiskSpace)
+            .getFreeDiskSpaceForAppInstallation(Mockito.any());
+        doThrow(IllegalArgumentException.class)
+            .when(mApkChangeDetectorDiskSpaceNotObtained)
+            .getFreeDiskSpaceForAppInstallation(Mockito.any());
+        Set<String> sha256SumsOnDevice = new HashSet<>();
+        sha256SumsOnDevice.add("sha256sum1");
+        sha256SumsOnDevice.add("sha256sum2");
+        sha256SumsOnDevice.add("sha256sum3");
+        doReturn(sha256SumsOnDevice)
+            .when(mApkChangeDetector)
+            .getSha256SumsOnDevice(Mockito.any(), Mockito.any());
+        doReturn(sha256SumsOnDevice)
+            .when(mApkChangeDetectorLessDiskSpace)
+            .getSha256SumsOnDevice(Mockito.any(), Mockito.any());
+        doReturn(sha256SumsOnDevice)
+            .when(mApkChangeDetectorDiskSpaceNotObtained)
+            .getSha256SumsOnDevice(Mockito.any(), Mockito.any());
+    }
+
+    @Test
+    public void handleTestAppsPreinstall_doInstallation_noApkInstallPathFound() throws Exception {
+        ApkChangeDetector apkChangeDetector = spy(new ApkChangeDetector());
+        doReturn(new ArrayList<>()).when(apkChangeDetector)
+            .getApkInstallPaths(Mockito.any(), Mockito.any());
+        doReturn(2000000000L)
+            .when(apkChangeDetector)
+            .getFreeDiskSpaceForAppInstallation(Mockito.any());
+
+        boolean shouldSkipInstallation =
+            apkChangeDetector.handleTestAppsPreinstall("a.b.c.package", mMockTestApps, mMockDevice);
+
+        assertThat(shouldSkipInstallation).isFalse();
+    }
+
+    @Test
+    public void handleTestAppsPreinstall_doInstallation_hashesOnHostMismatchThoseOnDevice()
+        throws Exception {
+        doReturn("sha256sum1").when(mApkChangeDetector).calculateSHA256OnHost(mMockFile1);
+        doReturn("sha256sum4").when(mApkChangeDetector).calculateSHA256OnHost(mMockFile2);
+        List<File> testApps = new ArrayList<>();
+        testApps.add(mMockFile1);
+        testApps.add(mMockFile2);
+
+        boolean shouldSkipInstallation =
+            mApkChangeDetector.handleTestAppsPreinstall("a.b.c.package", testApps, mMockDevice);
+
+        assertThat(shouldSkipInstallation).isFalse();
+    }
+
+    @Test
+    public void handleTestAppsPreinstall_doInstallation_hashesOnHostAreSubsetOfThoseOnDevice()
+        throws Exception {
+        doReturn("sha256sum1").when(mApkChangeDetector).calculateSHA256OnHost(mMockFile1);
+        doReturn("sha256sum2").when(mApkChangeDetector).calculateSHA256OnHost(mMockFile2);
+        List<File> testApps = new ArrayList<>();
+        testApps.add(mMockFile1);
+        testApps.add(mMockFile2);
+
+        boolean shouldSkipInstallation =
+            mApkChangeDetector.handleTestAppsPreinstall("a.b.c.package", testApps, mMockDevice);
+
+        assertThat(shouldSkipInstallation).isFalse();
+    }
+
+    @Test
+    public void handleTestAppsPreinstall_skipInstallation_hashesMatchOnDeviceAndHost()
+        throws Exception {
+        doReturn("sha256sum1").when(mApkChangeDetector).calculateSHA256OnHost(mMockFile1);
+        doReturn("sha256sum2").when(mApkChangeDetector).calculateSHA256OnHost(mMockFile2);
+        doReturn("sha256sum3").when(mApkChangeDetector).calculateSHA256OnHost(mMockFile3);
+
+        boolean shouldSkipInstallation =
+            mApkChangeDetector.handleTestAppsPreinstall(
+                "a.b.c.package", mMockTestApps, mMockDevice);
+
+        assertThat(shouldSkipInstallation).isTrue();
+    }
+
+    @Test
+    public void handlePackageCleanup_forSingleUser_skipAppUninstallation() throws Exception {
+        doReturn("Pseudo success message")
+            .when(mMockDevice).executeShellCommand("am force-stop a.b.c.package");
+
+        boolean shouldSkipAppUninstallation =
+            mApkChangeDetector.handlePackageCleanup(
+                "a.b.c.package", mMockDevice, /* userId= */ 12345, /* forAllUsers= */ false);
+
+        assertThat(shouldSkipAppUninstallation).isTrue();
+    }
+
+    @Test
+    public void handlePackageCleanup_forAllUsers_skipAppUninstallation() throws Exception {
+        doReturn("Pseudo success message")
+            .when(mMockDevice).executeShellCommand("am force-stop a.b.c.package");
+
+        boolean shouldSkipAppUninstallation =
+            mApkChangeDetector.handlePackageCleanup(
+                "a.b.c.package", mMockDevice, /* userId= */ null, /* forAllUsers= */ true);
+
+        assertThat(shouldSkipAppUninstallation).isTrue();
+    }
+
+    // TODO: ihcinihsdk - Change the behavior of this test when we have the logic to handle
+    // app cleanups.
+    @Test
+    public void handleTestAppsPreinstall_doAppCleanup_appNeedsInstallationAndDiskSpaceNotEnough()
+        throws Exception {
+        doReturn("sha256sum1").when(mApkChangeDetectorLessDiskSpace)
+            .calculateSHA256OnHost(mMockFile1);
+        doReturn("sha256sum3").when(mApkChangeDetectorLessDiskSpace)
+            .calculateSHA256OnHost(mMockFile3);
+        List<File> testApps = new ArrayList<>();
+        testApps.add(mMockFile1);
+        testApps.add(mMockFile3);
+
+        // The free disk space before installation is 15,000,000 bytes while the two APKs' sizes
+        // are 1,000,000 bytes and 3,000,000 bytes, respectively. Thus the estimated free space
+        // after installation is 15,000,000 - 1.5 * (1,000,000 + 3,000,000) = 9,000,000, which is
+        // less than the threshold 10,000,000 bytes.
+        assertThrows(UnsupportedOperationException.class, () ->
+            mApkChangeDetectorLessDiskSpace.handleTestAppsPreinstall(
+                "a.b.c.package", testApps, mMockDevice));
+    }
+
+    @Test
+    public void handleTestAppsPreinstall_incrementalSetupNotSupported_diskSpaceNotObtained()
+        throws Exception {
+        doReturn("sha256sum1").when(mApkChangeDetectorDiskSpaceNotObtained)
+            .calculateSHA256OnHost(mMockFile1);
+        List<File> testApps = new ArrayList<>();
+        testApps.add(mMockFile1);
+
+        boolean incrementalSetupSupported =
+            mApkChangeDetectorDiskSpaceNotObtained.handleTestAppsPreinstall(
+                "a.b.c.package", testApps, mMockDevice);
+
+        assertThat(incrementalSetupSupported).isFalse();
+    }
+}
+
diff --git a/javatests/com/android/tradefed/targetprep/sync/IncrementalImageFuncTest.java b/javatests/com/android/tradefed/targetprep/sync/IncrementalImageFuncTest.java
index b8cdb2681..667216314 100644
--- a/javatests/com/android/tradefed/targetprep/sync/IncrementalImageFuncTest.java
+++ b/javatests/com/android/tradefed/targetprep/sync/IncrementalImageFuncTest.java
@@ -112,6 +112,7 @@ public class IncrementalImageFuncTest extends BaseHostJUnit4Test {
                         mApplySnapshot,
                         false,
                         false,
+                        false,
                         SnapuserdWaitPhase.BLOCK_AFTER_UPDATE);
         try {
             updateUtil.updateDevice(null, null);
diff --git a/javatests/com/android/tradefed/testtype/AndroidJUnitTestTest.java b/javatests/com/android/tradefed/testtype/AndroidJUnitTestTest.java
index dbc59f8b0..f2fea012d 100644
--- a/javatests/com/android/tradefed/testtype/AndroidJUnitTestTest.java
+++ b/javatests/com/android/tradefed/testtype/AndroidJUnitTestTest.java
@@ -505,9 +505,8 @@ public class AndroidJUnitTestTest {
         File tmpFileExclude = FileUtil.createTempFile("excludeFile", ".txt");
         FileUtil.writeToFile(TEST2.toString(), tmpFileExclude);
         try {
-            OptionSetter setter = new OptionSetter(mAndroidJUnitTest);
-            setter.setOptionValue("test-file-include-filter", tmpFileInclude.getAbsolutePath());
-            setter.setOptionValue("test-file-exclude-filter", tmpFileExclude.getAbsolutePath());
+            mAndroidJUnitTest.setIncludeTestFile(tmpFileInclude);
+            mAndroidJUnitTest.setExcludeTestFile(tmpFileExclude);
             mAndroidJUnitTest.run(mTestInfo, mMockListener);
             verify(mMockTestDevice, times(2))
                     .pushFile(Mockito.<File>any(), Mockito.<String>any(), Mockito.eq(true));
diff --git a/javatests/com/android/tradefed/testtype/ArtRunTestTest.java b/javatests/com/android/tradefed/testtype/ArtRunTestTest.java
index aec6d54e3..837a0fee6 100644
--- a/javatests/com/android/tradefed/testtype/ArtRunTestTest.java
+++ b/javatests/com/android/tradefed/testtype/ArtRunTestTest.java
@@ -16,7 +16,9 @@
 
 package com.android.tradefed.testtype;
 
-import static org.junit.Assert.fail;
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertThrows;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.verify;
@@ -30,7 +32,9 @@ import com.android.tradefed.invoker.IInvocationContext;
 import com.android.tradefed.invoker.InvocationContext;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
+import com.android.tradefed.result.FileInputStreamSource;
 import com.android.tradefed.result.ITestInvocationListener;
+import com.android.tradefed.result.LogDataType;
 import com.android.tradefed.result.TestDescription;
 import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
@@ -135,12 +139,9 @@ public class ArtRunTestTest {
         final String classpath = "/data/local/tmp/test/test.jar";
         mSetter.setOptionValue("classpath", classpath);
 
-        try {
-            mArtRunTest.run(mTestInfo, mMockInvocationListener);
-            fail("An exception should have been thrown.");
-        } catch (IllegalArgumentException e) {
-            // Expected.
-        }
+        assertThrows(
+                IllegalArgumentException.class,
+                () -> mArtRunTest.run(mTestInfo, mMockInvocationListener));
     }
 
     /** Test the behavior of the run method when the `classpath` option is not set. */
@@ -152,12 +153,9 @@ public class ArtRunTestTest {
         createExpectedStdoutFile(runTestName);
         createExpectedStderrFile(runTestName);
 
-        try {
-            mArtRunTest.run(mTestInfo, mMockInvocationListener);
-            fail("An exception should have been thrown.");
-        } catch (IllegalArgumentException e) {
-            // Expected.
-        }
+        assertThrows(
+                IllegalArgumentException.class,
+                () -> mArtRunTest.run(mTestInfo, mMockInvocationListener));
     }
 
     /** Helper containing testing logic for a (single) test expected to run (and succeed). */
@@ -377,6 +375,213 @@ public class ArtRunTestTest {
         verify(mMockITestDevice).deleteFile(tmpTestRemoteDirPath);
     }
 
+    /**
+     * Test the behavior of the run method when the transfer of the standard output file produced by
+     * the shell command fails because of mismatching file sizes.
+     *
+     * <p>This test exercises the {@link com.android.tradefed.testtype.ArtRunTest#pullAndCheckFile}
+     * method.
+     */
+    @Test
+    public void testRunSingleTest_failedStandardOutputTransfer_sizesMismatch()
+            throws ConfigurationException, DeviceNotAvailableException, IOException {
+        final String runTestName = "test";
+        mSetter.setOptionValue("run-test-name", runTestName);
+        createExpectedStdoutFile(runTestName);
+        createExpectedStderrFile(runTestName);
+        final String classpath = "/data/local/tmp/test/test.jar";
+        mSetter.setOptionValue("classpath", classpath);
+
+        // Pre-test checks.
+        when(mMockAbi.getName()).thenReturn("abi");
+        when(mMockITestDevice.getSerialNumber()).thenReturn("");
+        String runName = "ArtRunTest_abi";
+
+        // Beginning of test.
+
+        TestDescription testId = new TestDescription(runName, runTestName);
+
+        final String stdoutFileName = "stdout.txt";
+        final String stderrFileName = "stderr.txt";
+
+        String tmpTestRemoteDirPath = "/data/local/tmp/test.0123456789";
+        String remoteStdoutFilePath = String.format("%s/%s", tmpTestRemoteDirPath, stdoutFileName);
+        String remoteStderrFilePath = String.format("%s/%s", tmpTestRemoteDirPath, stderrFileName);
+
+        // Create remote temporary directory.
+        String mktempCmd = "mktemp -d -p /data/local/tmp test.XXXXXXXXXX";
+        CommandResult mktempResult =
+                createMockCommandResult(
+                        String.format("%s\n", tmpTestRemoteDirPath), "", /* exitCode */ 0);
+        when(mMockITestDevice.executeShellV2Command(mktempCmd, 10000L, TimeUnit.MILLISECONDS, 0))
+                .thenReturn(mktempResult);
+
+        // Test execution.
+        String dalvikvmCmd =
+                String.format(
+                        "dalvikvm64 -Xcompiler-option --compile-art-test -classpath %s Main "
+                                + ">%s 2>%s",
+                        classpath, remoteStdoutFilePath, remoteStderrFilePath);
+        CommandResult dalvikvmResult =
+                createMockCommandResult(/* stdout */ "", /* stderr */ "", /* exitCode */ 0);
+        when(mMockITestDevice.executeShellV2Command(dalvikvmCmd, 60000L, TimeUnit.MILLISECONDS, 0))
+                .thenReturn(dalvikvmResult);
+
+        // Pull and check standard output file from device.
+        String statStdoutCmd = String.format("stat --format %%s %s", remoteStdoutFilePath);
+        File localStdoutFile = new File(mTmpTestLocalDir, stdoutFileName);
+        try (FileWriter fw = new FileWriter(localStdoutFile)) {
+            // Simulate an incorrect transfer by truncating the retrieved standard output.
+            fw.write("output\n".substring(0, 3));
+        }
+        CommandResult statStdoutResult = createMockCommandResult("7\n", "", /* exitCode */ 0);
+        when(mMockITestDevice.executeShellV2Command(
+                        statStdoutCmd, 10000L, TimeUnit.MILLISECONDS, 0))
+                .thenReturn(statStdoutResult);
+        String md5sumStdoutCmd = String.format("md5sum -b %s", remoteStdoutFilePath);
+        CommandResult md5sumStdoutResult =
+                createMockCommandResult("838337db0b65bfd3a542f0c5ca047ae2\n", "", /* exitCode */ 0);
+        when(mMockITestDevice.executeShellV2Command(
+                        md5sumStdoutCmd, 60000L, TimeUnit.MILLISECONDS, 0))
+                .thenReturn(md5sumStdoutResult);
+        when(mMockITestDevice.pullFile(remoteStdoutFilePath, localStdoutFile)).thenReturn(true);
+
+        // Verify that the failed transfer is caught.
+        Exception thrown =
+                assertThrows(
+                        RuntimeException.class,
+                        () -> mArtRunTest.run(mTestInfo, mMockInvocationListener));
+        assertThat(thrown).hasCauseThat().isInstanceOf(IOException.class);
+        assertThat(thrown)
+                .hasMessageThat()
+                .contains(
+                        String.format(
+                                "Size of local file `%s` does not match size of remote file `%s`"
+                                        + " pulled from device: 3 bytes vs 7 bytes",
+                                localStdoutFile.getPath(), remoteStdoutFilePath));
+
+        // End of test.
+
+        verify(mMockInvocationListener)
+                .testLog(
+                        eq(stdoutFileName),
+                        eq(LogDataType.TEXT),
+                        (FileInputStreamSource) Mockito.any());
+        verify(mMockInvocationListener).testRunStarted(runName, 1);
+        verify(mMockInvocationListener).testStarted(testId);
+        verify(mMockInvocationListener)
+                .testEnded(eq(testId), (HashMap<String, Metric>) Mockito.any());
+        verify(mMockInvocationListener)
+                .testRunEnded(Mockito.anyLong(), (HashMap<String, Metric>) Mockito.any());
+
+        verify(mMockITestDevice).deleteFile(tmpTestRemoteDirPath);
+    }
+
+    /**
+     * Test the behavior of the run method when the transfer of the standard output file produced by
+     * the shell command fails because of mismatching MD5 digests.
+     *
+     * <p>This test exercises the {@link com.android.tradefed.testtype.ArtRunTest#pullAndCheckFile}
+     * method.
+     */
+    @Test
+    public void testRunSingleTest_failedStandardOutputTransfer_md5DigestsMismatch()
+            throws ConfigurationException, DeviceNotAvailableException, IOException {
+        final String runTestName = "test";
+        mSetter.setOptionValue("run-test-name", runTestName);
+        createExpectedStdoutFile(runTestName);
+        createExpectedStderrFile(runTestName);
+        final String classpath = "/data/local/tmp/test/test.jar";
+        mSetter.setOptionValue("classpath", classpath);
+
+        // Pre-test checks.
+        when(mMockAbi.getName()).thenReturn("abi");
+        when(mMockITestDevice.getSerialNumber()).thenReturn("");
+        String runName = "ArtRunTest_abi";
+
+        // Beginning of test.
+
+        TestDescription testId = new TestDescription(runName, runTestName);
+
+        final String stdoutFileName = "stdout.txt";
+        final String stderrFileName = "stderr.txt";
+
+        String tmpTestRemoteDirPath = "/data/local/tmp/test.0123456789";
+        String remoteStdoutFilePath = String.format("%s/%s", tmpTestRemoteDirPath, stdoutFileName);
+        String remoteStderrFilePath = String.format("%s/%s", tmpTestRemoteDirPath, stderrFileName);
+
+        // Create remote temporary directory.
+        String mktempCmd = "mktemp -d -p /data/local/tmp test.XXXXXXXXXX";
+        CommandResult mktempResult =
+                createMockCommandResult(
+                        String.format("%s\n", tmpTestRemoteDirPath), "", /* exitCode */ 0);
+        when(mMockITestDevice.executeShellV2Command(mktempCmd, 10000L, TimeUnit.MILLISECONDS, 0))
+                .thenReturn(mktempResult);
+
+        // Test execution.
+        String dalvikvmCmd =
+                String.format(
+                        "dalvikvm64 -Xcompiler-option --compile-art-test -classpath %s Main "
+                                + ">%s 2>%s",
+                        classpath, remoteStdoutFilePath, remoteStderrFilePath);
+        CommandResult dalvikvmResult =
+                createMockCommandResult(/* stdout */ "", /* stderr */ "", /* exitCode */ 0);
+        when(mMockITestDevice.executeShellV2Command(dalvikvmCmd, 60000L, TimeUnit.MILLISECONDS, 0))
+                .thenReturn(dalvikvmResult);
+
+        // Pull and check standard output file from device.
+        String statStdoutCmd = String.format("stat --format %%s %s", remoteStdoutFilePath);
+        File localStdoutFile = new File(mTmpTestLocalDir, stdoutFileName);
+        try (FileWriter fw = new FileWriter(localStdoutFile)) {
+            // Simulate an incorrect transfer by substituting a characted in the retrieved standard
+            // output.
+            fw.write("output\n".replace("p", "c"));
+        }
+        CommandResult statStdoutResult = createMockCommandResult("7\n", "", /* exitCode */ 0);
+        when(mMockITestDevice.executeShellV2Command(
+                        statStdoutCmd, 10000L, TimeUnit.MILLISECONDS, 0))
+                .thenReturn(statStdoutResult);
+        String md5sumStdoutCmd = String.format("md5sum -b %s", remoteStdoutFilePath);
+        CommandResult md5sumStdoutResult =
+                createMockCommandResult("838337db0b65bfd3a542f0c5ca047ae2\n", "", /* exitCode */ 0);
+        when(mMockITestDevice.executeShellV2Command(
+                        md5sumStdoutCmd, 60000L, TimeUnit.MILLISECONDS, 0))
+                .thenReturn(md5sumStdoutResult);
+        when(mMockITestDevice.pullFile(remoteStdoutFilePath, localStdoutFile)).thenReturn(true);
+
+        // Verify that the failed transfer is caught.
+        Exception thrown =
+                assertThrows(
+                        RuntimeException.class,
+                        () -> mArtRunTest.run(mTestInfo, mMockInvocationListener));
+        assertThat(thrown).hasCauseThat().isInstanceOf(IOException.class);
+        assertThat(thrown)
+                .hasMessageThat()
+                .contains(
+                        String.format(
+                                "MD5 digest of local file `%s` does not match MD5 digest of remote"
+                                        + " file `%s` pulled from device:"
+                                        + " 8986be111a9c226a458088dbcf2ba398 vs "
+                                        + "838337db0b65bfd3a542f0c5ca047ae2",
+                                localStdoutFile.getPath(), remoteStdoutFilePath));
+
+        // End of test.
+
+        verify(mMockInvocationListener)
+                .testLog(
+                        eq(stdoutFileName),
+                        eq(LogDataType.TEXT),
+                        (FileInputStreamSource) Mockito.any());
+        verify(mMockInvocationListener).testRunStarted(runName, 1);
+        verify(mMockInvocationListener).testStarted(testId);
+        verify(mMockInvocationListener)
+                .testEnded(eq(testId), (HashMap<String, Metric>) Mockito.any());
+        verify(mMockInvocationListener)
+                .testRunEnded(Mockito.anyLong(), (HashMap<String, Metric>) Mockito.any());
+
+        verify(mMockITestDevice).deleteFile(tmpTestRemoteDirPath);
+    }
+
     /**
      * Test the behavior of the run method when the standard output produced by the shell command on
      * device differs from the expected standard output.
diff --git a/javatests/com/android/tradefed/testtype/GTestParserTestBase.java b/javatests/com/android/tradefed/testtype/GTestParserTestBase.java
index 4ec09c619..eb597a020 100644
--- a/javatests/com/android/tradefed/testtype/GTestParserTestBase.java
+++ b/javatests/com/android/tradefed/testtype/GTestParserTestBase.java
@@ -42,6 +42,7 @@ public abstract class GTestParserTestBase {
     protected static final String GTEST_OUTPUT_FILE_12 = "gtest_output12.txt";
     protected static final String GTEST_OUTPUT_FILE_13 = "gtest_output13.txt";
     protected static final String GTEST_OUTPUT_FILE_14 = "gtest_output14.txt";
+    protected static final String GTEST_OUTPUT_FILE_15 = "gtest_output15.txt";
     protected static final String GTEST_LIST_FILE_1 = "gtest_list1.txt";
     protected static final String GTEST_LIST_FILE_2 = "gtest_list2.txt";
     protected static final String GTEST_LIST_FILE_3 = "gtest_list3.txt";
diff --git a/javatests/com/android/tradefed/testtype/GTestResultParserTest.java b/javatests/com/android/tradefed/testtype/GTestResultParserTest.java
index a66696587..ae75be00f 100644
--- a/javatests/com/android/tradefed/testtype/GTestResultParserTest.java
+++ b/javatests/com/android/tradefed/testtype/GTestResultParserTest.java
@@ -333,6 +333,55 @@ public class GTestResultParserTest extends GTestParserTestBase {
                 .testRunEnded(Mockito.anyLong(), Mockito.<HashMap<String, Metric>>any());
     }
 
+    /**
+     * Tests the parser for a test run output following the rust test naming convention, using `::`
+     * as the test class and name separator
+     */
+    @Test
+    public void testParseRunTestNames() throws Exception {
+        String[] contents = readInFile(GTEST_OUTPUT_FILE_15);
+        ITestInvocationListener mockRunListener = mock(ITestInvocationListener.class);
+
+        GTestResultParser resultParser =
+                new GTestResultParser(
+                        TEST_MODULE_NAME, mockRunListener, true
+                        /** allowRustTestName */
+                        );
+        resultParser.processNewLines(contents);
+        resultParser.flush();
+        TestDescription class1_test1 = new TestDescription("test_class1::tests", "test_case1");
+        TestDescription class1_test2 = new TestDescription("test_class1::tests", "test_case2");
+        TestDescription class2_test1 = new TestDescription("test_class2::tests", "test_case1");
+        TestDescription class2_test2 = new TestDescription("test_class2::tests", "test_case2");
+        verify(mockRunListener).testRunStarted(TEST_MODULE_NAME, 4);
+        verify(mockRunListener).testStarted(Mockito.eq(class1_test1), Mockito.anyLong());
+        verify(mockRunListener)
+                .testEnded(
+                        Mockito.eq(class1_test1),
+                        Mockito.anyLong(),
+                        Mockito.<HashMap<String, Metric>>any());
+        verify(mockRunListener).testStarted(Mockito.eq(class1_test2), Mockito.anyLong());
+        verify(mockRunListener)
+                .testEnded(
+                        Mockito.eq(class1_test2),
+                        Mockito.anyLong(),
+                        Mockito.<HashMap<String, Metric>>any());
+        verify(mockRunListener).testStarted(Mockito.eq(class2_test1), Mockito.anyLong());
+        verify(mockRunListener)
+                .testEnded(
+                        Mockito.eq(class2_test1),
+                        Mockito.anyLong(),
+                        Mockito.<HashMap<String, Metric>>any());
+        verify(mockRunListener).testStarted(Mockito.eq(class2_test2), Mockito.anyLong());
+        verify(mockRunListener)
+                .testEnded(
+                        Mockito.eq(class2_test2),
+                        Mockito.anyLong(),
+                        Mockito.<HashMap<String, Metric>>any());
+        verify(mockRunListener)
+                .testRunEnded(Mockito.anyLong(), Mockito.<HashMap<String, Metric>>any());
+    }
+
     @Test
     public void testParse_interrupted() throws Exception {
         String[] contents = readInFile(GTEST_OUTPUT_FILE_13);
diff --git a/javatests/com/android/tradefed/testtype/GoogleBenchmarkResultParserTest.java b/javatests/com/android/tradefed/testtype/GoogleBenchmarkResultParserTest.java
index 653d4298d..7105eade5 100644
--- a/javatests/com/android/tradefed/testtype/GoogleBenchmarkResultParserTest.java
+++ b/javatests/com/android/tradefed/testtype/GoogleBenchmarkResultParserTest.java
@@ -116,26 +116,29 @@ public class GoogleBenchmarkResultParserTest {
 
         // Test 1
         HashMap<String, Metric> resultTest1 = capture.getAllValues().get(0);
-        assertEquals(4, resultTest1.size());
-        assertEquals("5", resultTest1.get("cpu_time").getMeasurements().getSingleString());
-        assertEquals("5", resultTest1.get("real_time").getMeasurements().getSingleString());
+        assertEquals(5, resultTest1.size());
+        assertEquals("5", resultTest1.get("cpu_time_ns").getMeasurements().getSingleString());
+        assertEquals("5", resultTest1.get("real_time_ns").getMeasurements().getSingleString());
+        assertEquals("ns", resultTest1.get("time_unit").getMeasurements().getSingleString());
         assertEquals("BM_one", resultTest1.get("name").getMeasurements().getSingleString());
         assertEquals(
                 "109451958", resultTest1.get("iterations").getMeasurements().getSingleString());
 
         // Test 2
         HashMap<String, Metric> resultTest2 = capture.getAllValues().get(1);
-        assertEquals(4, resultTest2.size());
-        assertEquals("11", resultTest2.get("cpu_time").getMeasurements().getSingleString());
-        assertEquals("1", resultTest2.get("real_time").getMeasurements().getSingleString());
+        assertEquals(5, resultTest2.size());
+        assertEquals("11", resultTest2.get("cpu_time_ns").getMeasurements().getSingleString());
+        assertEquals("1", resultTest2.get("real_time_ns").getMeasurements().getSingleString());
+        assertEquals("ns", resultTest1.get("time_unit").getMeasurements().getSingleString());
         assertEquals("BM_two", resultTest2.get("name").getMeasurements().getSingleString());
         assertEquals("50906784", resultTest2.get("iterations").getMeasurements().getSingleString());
 
         // Test 3
         HashMap<String, Metric> resultTest3 = capture.getAllValues().get(2);
-        assertEquals(5, resultTest3.size());
-        assertEquals("60", resultTest3.get("cpu_time").getMeasurements().getSingleString());
-        assertEquals("60", resultTest3.get("real_time").getMeasurements().getSingleString());
+        assertEquals(6, resultTest3.size());
+        assertEquals("60", resultTest3.get("cpu_time_ns").getMeasurements().getSingleString());
+        assertEquals("60", resultTest3.get("real_time_ns").getMeasurements().getSingleString());
+        assertEquals("ns", resultTest1.get("time_unit").getMeasurements().getSingleString());
         assertEquals(
                 "BM_string_strlen/64", resultTest3.get("name").getMeasurements().getSingleString());
         assertEquals("10499948", resultTest3.get("iterations").getMeasurements().getSingleString());
@@ -162,9 +165,10 @@ public class GoogleBenchmarkResultParserTest {
                 .testEnded((TestDescription) Mockito.any(), capture.capture());
 
         HashMap<String, Metric> results = capture.getAllValues().get(0);
-        assertEquals(4, results.size());
-        assertEquals("5", results.get("cpu_time").getMeasurements().getSingleString());
-        assertEquals("5", results.get("real_time").getMeasurements().getSingleString());
+        assertEquals(5, results.size());
+        assertEquals("5", results.get("cpu_time_ns").getMeasurements().getSingleString());
+        assertEquals("5", results.get("real_time_ns").getMeasurements().getSingleString());
+        assertEquals("ns", results.get("time_unit").getMeasurements().getSingleString());
         assertEquals("BM_one", results.get("name").getMeasurements().getSingleString());
         assertEquals("109451958", results.get("iterations").getMeasurements().getSingleString());
     }
@@ -262,8 +266,8 @@ public class GoogleBenchmarkResultParserTest {
 
         HashMap<String, Metric> results = capture.getValue();
         assertEquals(5, results.size());
-        assertEquals("19361", results.get("cpu_time").getMeasurements().getSingleString());
-        assertEquals("44930", results.get("real_time").getMeasurements().getSingleString());
+        assertEquals("19361", results.get("cpu_time_ns").getMeasurements().getSingleString());
+        assertEquals("44930", results.get("real_time_ns").getMeasurements().getSingleString());
         assertEquals("BM_addInts", results.get("name").getMeasurements().getSingleString());
         assertEquals("36464", results.get("iterations").getMeasurements().getSingleString());
         assertEquals("ns", results.get("time_unit").getMeasurements().getSingleString());
@@ -290,8 +294,8 @@ public class GoogleBenchmarkResultParserTest {
 
         HashMap<String, Metric> results = capture.getValue();
         assertEquals(5, results.size());
-        assertEquals("19361", results.get("cpu_time").getMeasurements().getSingleString());
-        assertEquals("44930", results.get("real_time").getMeasurements().getSingleString());
+        assertEquals("19361", results.get("cpu_time_ns").getMeasurements().getSingleString());
+        assertEquals("44930", results.get("real_time_ns").getMeasurements().getSingleString());
         assertEquals("BM_addInts", results.get("name").getMeasurements().getSingleString());
         assertEquals("0", results.get("iterations").getMeasurements().getSingleString());
         assertEquals("ns", results.get("time_unit").getMeasurements().getSingleString());
diff --git a/javatests/com/android/tradefed/testtype/HostGTestTest.java b/javatests/com/android/tradefed/testtype/HostGTestTest.java
index 51d82646a..f530bcaff 100644
--- a/javatests/com/android/tradefed/testtype/HostGTestTest.java
+++ b/javatests/com/android/tradefed/testtype/HostGTestTest.java
@@ -25,11 +25,7 @@ import static org.mockito.Mockito.when;
 
 import com.android.tradefed.build.BuildInfoKey;
 import com.android.tradefed.build.DeviceBuildInfo;
-import com.android.tradefed.cache.ICacheClient;
-import com.android.tradefed.command.CommandOptions;
-import com.android.tradefed.config.Configuration;
 import com.android.tradefed.config.ConfigurationException;
-import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.invoker.TestInformation;
@@ -38,7 +34,6 @@ import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
 import com.android.tradefed.util.FakeShellOutputReceiver;
 import com.android.tradefed.util.FileUtil;
-import com.android.tradefed.util.RunUtilTest;
 
 import org.junit.After;
 import org.junit.Before;
@@ -62,7 +57,6 @@ public class HostGTestTest {
     private ITestInvocationListener mMockInvocationListener;
     private FakeShellOutputReceiver mFakeReceiver;
     private OptionSetter mSetter;
-    private RunUtilTest.FakeCacheClient mFakeCacheClient;
 
     /** Helper to initialize the object or folder for unittest need. */
     @Before
@@ -79,19 +73,11 @@ public class HostGTestTest {
         mSetter = new OptionSetter(mHostGTest);
 
         mTestInfo = TestInformation.newBuilder().build();
-
-        mFakeCacheClient = new RunUtilTest.FakeCacheClient();
     }
 
     @After
     public void afterMethod() {
         FileUtil.recursiveDelete(mTestsDir);
-        mFakeCacheClient.getAllCache().values().stream()
-                .forEach(
-                        a -> {
-                            FileUtil.deleteFile(a.stdOut());
-                            FileUtil.deleteFile(a.stdErr());
-                        });
     }
 
     /**
@@ -219,66 +205,6 @@ public class HostGTestTest {
         assertNotEquals(0, mFakeReceiver.getReceivedOutput().length);
     }
 
-    @Test
-    public void testRun_upload_cache_for_success_run() throws Exception {
-        HostGTest hostGTest =
-                createHostGTestWithCache(
-                        "echo \"[==========] Running 1 tests from 1 test suites.\n"
-                                + "[----------] Global test environment set-up.\n"
-                                + "[----------] 1 tests from HelloWorldTest\n"
-                                + "[ RUN      ] HelloWorldTest.Hello \n"
-                                + "[       OK ] HelloWorldTest.Hello (100 ms)\n"
-                                + "[----------] 1 tests from HelloWorldTest (100 ms total)\n"
-                                + "[----------] Global test environment tear-down\n"
-                                + "[==========] 1 tests from 1 test suites ran. (100 ms total)\n"
-                                + "[  PASSED  ] 1 tests.\n"
-                                + "\"");
-
-        hostGTest.run(mTestInfo, mMockInvocationListener);
-
-        assertFalse(mFakeCacheClient.getAllCache().isEmpty());
-    }
-
-    @Test
-    public void testRun_skip_cache_upload_for_timeout_run() throws Exception {
-        HostGTest hostGTest =
-                createHostGTestWithCache(
-                        "echo \"[==========] Running 1 tests from 1 test suites.\n"
-                                + "[----------] Global test environment set-up.\n"
-                                + "[----------] 1 tests from HelloWorldTest\n"
-                                + "[ RUN      ] HelloWorldTest.Hello \n"
-                                + "[       OK ] HelloWorldTest.Hello (10000 ms)\n"
-                                + "[----------] 1 tests from HelloWorldTest (10000 ms total)\n"
-                                + "[----------] Global test environment tear-down\n"
-                                + "[==========] 1 tests from 1 test suites ran. (10000 ms total)\n"
-                                + "[  PASSED  ] 1 tests.\n"
-                                + "\"");
-
-        hostGTest.run(mTestInfo, mMockInvocationListener);
-
-        assertTrue(mFakeCacheClient.getAllCache().isEmpty());
-    }
-
-    @Test
-    public void testRun_skip_cache_upload_for_failed_run() throws Exception {
-        HostGTest hostGTest =
-                createHostGTestWithCache(
-                        "echo \"[==========] Running 1 tests from 1 test suites.\n"
-                                + "[----------] Global test environment set-up.\n"
-                                + "[----------] 1 tests from HelloWorldTest\n"
-                                + "[ RUN      ] HelloWorldTest.Hello \n"
-                                + "[  FAILED  ] HelloWorldTest.Hello (100 ms)\n"
-                                + "[----------] 1 tests from HelloWorldTest (100 ms total)\n"
-                                + "[----------] Global test environment tear-down\n"
-                                + "[==========] 1 tests from 1 test suites ran. (100 ms total)\n"
-                                + "[  FAILED  ] 1 tests.\n"
-                                + "\"");
-
-        hostGTest.run(mTestInfo, mMockInvocationListener);
-
-        assertTrue(mFakeCacheClient.getAllCache().isEmpty());
-    }
-
     /** Test the run method for host linked folder is set. */
     @Test
     public void testRun_priority_get_testcase_from_hostlinked_folder()
@@ -470,32 +396,4 @@ public class HostGTestTest {
 
         assertNotEquals(0, mFakeReceiver.getReceivedOutput().length);
     }
-
-    private HostGTest createHostGTestWithCache(String scriptContent) throws Exception {
-        HostGTest hostGTest =
-                new HostGTest() {
-                    @Override
-                    ICacheClient getCacheClient(File workFolder, String instanceName) {
-                        return mFakeCacheClient;
-                    }
-                };
-        OptionSetter testSetter = new OptionSetter(hostGTest);
-        String moduleName = "hello_world_test";
-        testSetter.setOptionValue("module-name", moduleName);
-        testSetter.setOptionValue("enable-cache", "true");
-        testSetter.setOptionValue("test-case-timeout", "1s");
-        File hostLinkedFolder = createSubFolder("hosttestcases");
-        createExecutableFile(
-                Paths.get(hostLinkedFolder.getAbsolutePath(), moduleName), scriptContent);
-        DeviceBuildInfo buildInfo = new DeviceBuildInfo();
-        buildInfo.setFile(BuildInfoKey.BuildInfoFileKey.HOST_LINKED_DIR, hostLinkedFolder, "0.0");
-        hostGTest.setBuild(buildInfo);
-        CommandOptions commandOptions = new CommandOptions();
-        OptionSetter commandOptionsSetter = new OptionSetter(commandOptions);
-        commandOptionsSetter.setOptionValue("remote-cache-instance-name", "test_instance");
-        IConfiguration config = new Configuration("config", "Test config");
-        config.setCommandOptions(commandOptions);
-        hostGTest.setConfiguration(config);
-        return hostGTest;
-    }
 }
diff --git a/javatests/com/android/tradefed/testtype/IsolatedHostTestTest.java b/javatests/com/android/tradefed/testtype/IsolatedHostTestTest.java
index 77ab61c1c..e9e760b2f 100644
--- a/javatests/com/android/tradefed/testtype/IsolatedHostTestTest.java
+++ b/javatests/com/android/tradefed/testtype/IsolatedHostTestTest.java
@@ -24,8 +24,6 @@ import static org.mockito.Mockito.verify;
 
 import com.android.tradefed.build.BuildInfoKey.BuildInfoFileKey;
 import com.android.tradefed.build.IBuildInfo;
-import com.android.tradefed.cache.ICacheClient;
-import com.android.tradefed.command.CommandOptions;
 import com.android.tradefed.config.Configuration;
 import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.OptionSetter;
@@ -39,7 +37,6 @@ import com.android.tradefed.result.TestDescription;
 import com.android.tradefed.testtype.coverage.CoverageOptions;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.ResourceUtil;
-import com.android.tradefed.util.RunUtilTest;
 
 import org.junit.After;
 import org.junit.Before;
@@ -69,7 +66,6 @@ public class IsolatedHostTestTest {
     private ServerSocket mMockServer;
     private File mMockTestDir;
     private File mWorkFolder;
-    private final ICacheClient mFakeCacheClient = new RunUtilTest.FakeCacheClient();
 
     /**
      * (copied and altered from JarHostTestTest) Helper to read a file from the res/testtype
@@ -141,9 +137,6 @@ public class IsolatedHostTestTest {
         doReturn(Inet4Address.getByName("localhost")).when(mMockServer).getInetAddress();
 
         List<String> commandArgs = mHostTest.compileCommandArgs("", null);
-        assertTrue(commandArgs.contains("-Drobolectric.offline=true"));
-        assertTrue(commandArgs.contains("-Drobolectric.logging=stdout"));
-        assertTrue(commandArgs.contains("-Drobolectric.resourcesMode=BINARY"));
         assertTrue(
                 commandArgs.stream()
                         .anyMatch(
@@ -174,7 +167,7 @@ public class IsolatedHostTestTest {
         assertTrue(mHostTest.compileClassPath().contains("ravenwood-runtime"));
 
         assertEquals(
-                "ravenwood-runtime/lib:ravenwood-runtime/lib64",
+                String.join(java.io.File.pathSeparator, ldLibraryPath),
                 mHostTest.compileLdLibraryPathInner(null));
 
         List<String> commandArgs = mHostTest.compileCommandArgs("", null);
@@ -201,9 +194,6 @@ public class IsolatedHostTestTest {
         doReturn(Inet4Address.getByName("localhost")).when(mMockServer).getInetAddress();
 
         List<String> commandArgs = mHostTest.compileCommandArgs("", null);
-        assertFalse(commandArgs.contains("-Drobolectric.offline=true"));
-        assertFalse(commandArgs.contains("-Drobolectric.logging=stdout"));
-        assertFalse(commandArgs.contains("-Drobolectric.resourcesMode=BINARY"));
         assertFalse(
                 commandArgs.stream().anyMatch(s -> s.contains("-Drobolectric.dependency.dir=")));
     }
@@ -246,29 +236,6 @@ public class IsolatedHostTestTest {
         FileUtil.deleteFile(mHostTest.getCoverageExecFile());
     }
 
-    /**
-     * TODO(murj) need to figure out a strategy with jdesprez on how to test the classpath
-     * determination functionality.
-     *
-     * @throws Exception
-     */
-    @Test
-    public void testRobolectricResourcesClasspathPositive() throws Exception {
-        OptionSetter setter = new OptionSetter(mHostTest);
-        setter.setOptionValue("use-robolectric-resources", "true");
-    }
-
-    /**
-     * TODO(murj) same as above
-     *
-     * @throws Exception
-     */
-    @Test
-    public void testRobolectricResourcesClasspathNegative() throws Exception {
-        OptionSetter setter = new OptionSetter(mHostTest);
-        setter.setOptionValue("use-robolectric-resources", "false");
-    }
-
     private OptionSetter setUpSimpleMockJarTest(String jarName) throws Exception {
         OptionSetter setter = new OptionSetter(mHostTest);
         File jar = getJarResource("/" + jarName, mMockTestDir, jarName);
@@ -301,69 +268,6 @@ public class IsolatedHostTestTest {
         verify(mListener).testRunEnded(Mockito.anyLong(), Mockito.<HashMap<String, Metric>>any());
     }
 
-    @Test
-    public void testCacheWorks() throws Exception {
-        final String jarName = "SimplePassingTest.jar";
-        final String className = "com.android.tradefed.referencetests.SimplePassingTest";
-        InvocationContext context = new InvocationContext();
-        TestInformation testInfo =
-                TestInformation.newBuilder().setInvocationContext(context).build();
-        TestDescription test = new TestDescription(className, "test2Plus2");
-        ITestInvocationListener firstListener = Mockito.mock(ITestInvocationListener.class);
-        ITestInvocationListener secondListener = Mockito.mock(ITestInvocationListener.class);
-        File testDir1 = FileUtil.createTempDir("isolatedhosttesttest", mWorkFolder);
-        IsolatedHostTest runner1 = createTestRunnerForCaching(testDir1);
-        OptionSetter setter = new OptionSetter(runner1);
-        File jar1 = getJarResource("/" + jarName, testDir1, jarName);
-        setter.setOptionValue("jar", jar1.getName());
-        setter.setOptionValue("exclude-paths", "org/junit");
-        setter.setOptionValue("exclude-paths", "junit");
-        File testDir2 = FileUtil.createTempDir("isolatedhosttesttest", mWorkFolder);
-        IsolatedHostTest runner2 = createTestRunnerForCaching(testDir2);
-        setter = new OptionSetter(runner2);
-        File jar2 = getJarResource("/" + jarName, testDir2, jarName);
-        setter.setOptionValue("jar", jar2.getName());
-        // Test that the different order of option values won't affect caching.
-        setter.setOptionValue("exclude-paths", "junit");
-        setter.setOptionValue("exclude-paths", "org/junit");
-
-        doReturn(testDir1).when(mMockBuildInfo).getFile(BuildInfoFileKey.HOST_LINKED_DIR);
-        doReturn(testDir1).when(mMockBuildInfo).getFile(BuildInfoFileKey.TESTDIR_IMAGE);
-        runner1.run(testInfo, firstListener);
-        boolean isFirstRunCached = runner1.isCached();
-        doReturn(testDir2).when(mMockBuildInfo).getFile(BuildInfoFileKey.HOST_LINKED_DIR);
-        doReturn(testDir2).when(mMockBuildInfo).getFile(BuildInfoFileKey.TESTDIR_IMAGE);
-        runner2.run(testInfo, secondListener);
-        boolean isSecondRunCached = runner2.isCached();
-
-        assertFalse(isFirstRunCached);
-        verify(firstListener).testRunStarted((String) Mockito.any(), Mockito.eq(1));
-        verify(firstListener).testStarted(Mockito.eq(test), Mockito.anyLong());
-        verify(firstListener)
-                .testEnded(
-                        Mockito.eq(test),
-                        Mockito.anyLong(),
-                        Mockito.<HashMap<String, Metric>>any());
-        verify(firstListener)
-                .testLog((String) Mockito.any(), Mockito.eq(LogDataType.TEXT), Mockito.any());
-        verify(firstListener)
-                .testRunEnded(Mockito.anyLong(), Mockito.<HashMap<String, Metric>>any());
-        assertTrue(isSecondRunCached);
-        verify(secondListener)
-                .testRunStarted(
-                        (String) Mockito.any(), Mockito.eq(1), Mockito.eq(0), Mockito.anyLong());
-        verify(secondListener).testStarted(Mockito.eq(test), Mockito.anyLong());
-        verify(secondListener)
-                .testEnded(
-                        Mockito.eq(test),
-                        Mockito.anyLong(),
-                        Mockito.<HashMap<String, Metric>>any());
-        verify(secondListener)
-                .testLog((String) Mockito.any(), Mockito.eq(LogDataType.TEXT), Mockito.any());
-        verify(secondListener)
-                .testRunEnded(Mockito.anyLong(), Mockito.<HashMap<String, Metric>>any());
-    }
-
     @Test
     public void testSimplePassingTestLifecycle() throws Exception {
         final String jarName = "SimplePassingTest.jar";
@@ -642,7 +546,7 @@ public class IsolatedHostTestTest {
 
         final String ldLibraryPath =
                 mHostTest.compileLdLibraryPathInner(androidHostOut.getAbsolutePath());
-        assertEquals("ANDROID_HOST_OUT/lib:ANDROID_HOST_OUT/lib64:lib:lib64", ldLibraryPath);
+        assertEquals(String.join(java.io.File.pathSeparator, paths), ldLibraryPath);
     }
 
     @Test
@@ -683,32 +587,4 @@ public class IsolatedHostTestTest {
                 .testLog((String) Mockito.any(), Mockito.eq(LogDataType.TEXT), Mockito.any());
         verify(mListener).testRunEnded(Mockito.anyLong(), Mockito.<HashMap<String, Metric>>any());
     }
-
-    private IsolatedHostTest createTestRunnerForCaching(File testDir) throws Exception {
-        IsolatedHostTest hostTest =
-                new IsolatedHostTest() {
-                    @Override
-                    String getEnvironment(String key) {
-                        return null;
-                    }
-
-                    @Override
-                    ICacheClient getCacheClient(File workFolder, String instanceName) {
-                        return mFakeCacheClient;
-                    }
-                };
-        hostTest.setBuild(mMockBuildInfo);
-        hostTest.setServer(mMockServer);
-        hostTest.setWorkDir(testDir);
-        OptionSetter runnerSetter = new OptionSetter(hostTest);
-        runnerSetter.setOptionValue("enable-cache", "true");
-        runnerSetter.setOptionValue("inherit-env-vars", "false");
-        CommandOptions commandOptions = new CommandOptions();
-        OptionSetter commandOptionsSetter = new OptionSetter(commandOptions);
-        commandOptionsSetter.setOptionValue("remote-cache-instance-name", "test_instance");
-        IConfiguration config = new Configuration("config", "Test config");
-        config.setCommandOptions(commandOptions);
-        hostTest.setConfiguration(config);
-        return hostTest;
-    }
 }
diff --git a/javatests/com/android/tradefed/testtype/binary/ExecutableHostTestTest.java b/javatests/com/android/tradefed/testtype/binary/ExecutableHostTestTest.java
index c5f6b7f21..25f8f519f 100644
--- a/javatests/com/android/tradefed/testtype/binary/ExecutableHostTestTest.java
+++ b/javatests/com/android/tradefed/testtype/binary/ExecutableHostTestTest.java
@@ -15,8 +15,6 @@
  */
 package com.android.tradefed.testtype.binary;
 
-import static org.junit.Assert.assertFalse;
-import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
@@ -31,14 +29,9 @@ import static org.mockito.Mockito.verify;
 import com.android.tradefed.build.BuildInfo;
 import com.android.tradefed.build.DeviceBuildInfo;
 import com.android.tradefed.build.IDeviceBuildInfo;
-import com.android.tradefed.cache.ICacheClient;
-import com.android.tradefed.command.CommandOptions;
-import com.android.tradefed.config.Configuration;
-import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.ITestDevice;
-import com.android.tradefed.device.StubDevice;
 import com.android.tradefed.invoker.InvocationContext;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
@@ -52,7 +45,6 @@ import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.IRunUtil;
-import com.android.tradefed.util.RunUtilTest;
 
 import org.junit.After;
 import org.junit.Before;
@@ -77,7 +69,6 @@ public class ExecutableHostTestTest {
     private IRunUtil mMockRunUtil;
     private TestInformation mTestInfo;
     private File mModuleDir;
-    private RunUtilTest.FakeCacheClient mFakeCacheClient;
 
     @Before
     public void setUp() throws Exception {
@@ -99,40 +90,11 @@ public class ExecutableHostTestTest {
         context.addAllocatedDevice("device", mMockDevice);
         mTestInfo = TestInformation.newBuilder().setInvocationContext(context).build();
         mModuleDir = FileUtil.createTempDir("test-module");
-        mFakeCacheClient = new RunUtilTest.FakeCacheClient();
     }
 
     @After
     public void tearDown() throws Exception {
         FileUtil.recursiveDelete(mModuleDir);
-        mFakeCacheClient.getAllCache().values().stream()
-                .forEach(
-                        a -> {
-                            FileUtil.deleteFile(a.stdOut());
-                            FileUtil.deleteFile(a.stdErr());
-                        });
-    }
-
-    /** Test that a success executable host test run is uploaded to cache service. */
-    @Test
-    public void testRun_upload_cache_for_success_run() throws Exception {
-        doReturn(new StubDevice("123")).when(mMockDevice).getIDevice();
-        ExecutableHostTest executableTest = createExecutableHostTestWithCache("echo hello_world");
-
-        executableTest.run(mTestInfo, mMockListener);
-
-        assertFalse(mFakeCacheClient.getAllCache().isEmpty());
-    }
-
-    /** Test that a failed executable host test run is not uploaded to cache service. */
-    @Test
-    public void testRun_skip_cache_uploading_for_failed_run() throws Exception {
-        doReturn(new StubDevice("123")).when(mMockDevice).getIDevice();
-        ExecutableHostTest executableTest = createExecutableHostTestWithCache("exit 1");
-
-        executableTest.run(mTestInfo, mMockListener);
-
-        assertTrue(mFakeCacheClient.getAllCache().isEmpty());
     }
 
     @Test
@@ -429,29 +391,4 @@ public class ExecutableHostTestTest {
             FileUtil.recursiveDelete(tmpBinary);
         }
     }
-
-    private ExecutableHostTest createExecutableHostTestWithCache(String scriptContent)
-            throws Exception {
-        ExecutableHostTest executableTest =
-                new ExecutableHostTest() {
-                    @Override
-                    ICacheClient getCacheClient(File workFolder, String instanceName) {
-                        return mFakeCacheClient;
-                    }
-                };
-        File binary =
-                new File(FileUtil.createTempDir("hosttestcases", mModuleDir), "hello_world_test");
-        FileUtil.writeToFile(scriptContent, binary);
-        binary.setExecutable(true);
-        OptionSetter testSetter = new OptionSetter(executableTest);
-        testSetter.setOptionValue("binary", binary.getAbsolutePath());
-        testSetter.setOptionValue("enable-cache", "true");
-        CommandOptions commandOptions = new CommandOptions();
-        OptionSetter commandOptionsSetter = new OptionSetter(commandOptions);
-        commandOptionsSetter.setOptionValue("remote-cache-instance-name", "test_instance");
-        IConfiguration config = new Configuration("config", "Test config");
-        config.setCommandOptions(commandOptions);
-        executableTest.setConfiguration(config);
-        return executableTest;
-    }
 }
diff --git a/javatests/com/android/tradefed/testtype/binary/ExecutableTargetTestTest.java b/javatests/com/android/tradefed/testtype/binary/ExecutableTargetTestTest.java
index 79122dd5a..794b10fe9 100644
--- a/javatests/com/android/tradefed/testtype/binary/ExecutableTargetTestTest.java
+++ b/javatests/com/android/tradefed/testtype/binary/ExecutableTargetTestTest.java
@@ -17,11 +17,13 @@ package com.android.tradefed.testtype.binary;
 
 import static org.junit.Assert.assertEquals;
 import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.when;
 
 import com.android.tradefed.config.ConfigurationException;
 import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.device.TestDeviceState;
 import com.android.tradefed.invoker.InvocationContext;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.metrics.proto.MetricMeasurement;
@@ -154,9 +156,7 @@ public class ExecutableTargetTestTest {
                                 FailureStatus.TEST_FAILURE)
                         .setErrorIdentifier(InfraErrorIdentifier.ARTIFACT_NOT_FOUND);
         Mockito.verify(mListener, Mockito.times(1))
-                .testFailed(
-                        Mockito.eq(testDescription1),
-                        Mockito.eq(failure1));
+                .testFailed(Mockito.eq(testDescription1), Mockito.eq(failure1));
         Mockito.verify(mListener, Mockito.times(1))
                 .testEnded(
                         Mockito.eq(testDescription1),
@@ -171,9 +171,7 @@ public class ExecutableTargetTestTest {
                                 FailureStatus.TEST_FAILURE)
                         .setErrorIdentifier(InfraErrorIdentifier.ARTIFACT_NOT_FOUND);
         Mockito.verify(mListener, Mockito.times(1))
-                .testFailed(
-                        Mockito.eq(testDescription2),
-                        Mockito.eq(failure2));
+                .testFailed(Mockito.eq(testDescription2), Mockito.eq(failure2));
         Mockito.verify(mListener, Mockito.times(1))
                 .testEnded(
                         Mockito.eq(testDescription2),
@@ -236,6 +234,105 @@ public class ExecutableTargetTestTest {
                         Mockito.<HashMap<String, MetricMeasurement.Metric>>any());
     }
 
+    /** Test run method aborts due to device going offline after first test */
+    @Test
+    public void testRun_cmdAbortedOffline()
+            throws DeviceNotAvailableException, ConfigurationException {
+        mExecutableTargetTest =
+                new ExecutableTargetTest() {
+                    @Override
+                    public String findBinary(String binary) {
+                        return binary;
+                    }
+
+                    @Override
+                    protected void checkCommandResult(
+                            CommandResult result,
+                            ITestInvocationListener listener,
+                            TestDescription description) {}
+                };
+        when(mMockITestDevice.getDeviceState())
+                .thenReturn(TestDeviceState.ONLINE, TestDeviceState.NOT_AVAILABLE);
+        when(mMockITestDevice.isAdbRoot()).thenReturn(true);
+        mExecutableTargetTest.setDevice(mMockITestDevice);
+        // Set test commands
+        OptionSetter setter = new OptionSetter(mExecutableTargetTest);
+        setter.setOptionValue("abort-if-device-lost", "true");
+        setter.setOptionValue("abort-if-root-lost", "true");
+        setter.setOptionValue("test-command-line", testName1, testCmd1);
+        setter.setOptionValue("test-command-line", testName2, testCmd2);
+        setter.setOptionValue("test-command-line", testName3, testCmd3);
+        TestDescription testDescription = new TestDescription(testName1, testName1);
+        TestDescription testDescription2 = new TestDescription(testName2, testName2);
+        TestDescription testDescription3 = new TestDescription(testName3, testName3);
+        mExecutableTargetTest.run(mTestInfo, mListener);
+        Mockito.verify(mListener, Mockito.times(1))
+                .testRunFailed(Mockito.<FailureDescription>any());
+        // testName1 should run.
+        Mockito.verify(mListener, Mockito.times(1))
+                .testStarted(Mockito.eq(testDescription), Mockito.anyLong());
+        // testName2 should NOT run.
+        Mockito.verify(mListener, Mockito.never())
+                .testStarted(Mockito.eq(testDescription2), Mockito.anyLong());
+        // testName3 should NOT run.
+        Mockito.verify(mListener, Mockito.never())
+                .testStarted(Mockito.eq(testDescription3), Mockito.anyLong());
+
+        Mockito.verify(mListener, Mockito.times(1))
+                .testRunEnded(
+                        Mockito.anyLong(),
+                        Mockito.<HashMap<String, MetricMeasurement.Metric>>any());
+    }
+
+    /** Test run method aborts due to device unrooting after first test */
+    @Test
+    public void testRun_cmdAbortedUnroot()
+            throws DeviceNotAvailableException, ConfigurationException {
+        mExecutableTargetTest =
+                new ExecutableTargetTest() {
+                    @Override
+                    public String findBinary(String binary) {
+                        return binary;
+                    }
+
+                    @Override
+                    protected void checkCommandResult(
+                            CommandResult result,
+                            ITestInvocationListener listener,
+                            TestDescription description) {}
+                };
+        when(mMockITestDevice.getDeviceState()).thenReturn(TestDeviceState.ONLINE);
+        when(mMockITestDevice.isAdbRoot()).thenReturn(true, false);
+        mExecutableTargetTest.setDevice(mMockITestDevice);
+        // Set test commands
+        OptionSetter setter = new OptionSetter(mExecutableTargetTest);
+        setter.setOptionValue("abort-if-device-lost", "true");
+        setter.setOptionValue("abort-if-root-lost", "true");
+        setter.setOptionValue("test-command-line", testName1, testCmd1);
+        setter.setOptionValue("test-command-line", testName2, testCmd2);
+        setter.setOptionValue("test-command-line", testName3, testCmd3);
+        TestDescription testDescription = new TestDescription(testName1, testName1);
+        TestDescription testDescription2 = new TestDescription(testName2, testName2);
+        TestDescription testDescription3 = new TestDescription(testName3, testName3);
+        mExecutableTargetTest.run(mTestInfo, mListener);
+        Mockito.verify(mListener, Mockito.times(1))
+                .testRunFailed(Mockito.<FailureDescription>any());
+        // testName1 should run.
+        Mockito.verify(mListener, Mockito.times(1))
+                .testStarted(Mockito.eq(testDescription), Mockito.anyLong());
+        // testName2 should NOT run.
+        Mockito.verify(mListener, Mockito.never())
+                .testStarted(Mockito.eq(testDescription2), Mockito.anyLong());
+        // testName3 should NOT run.
+        Mockito.verify(mListener, Mockito.never())
+                .testStarted(Mockito.eq(testDescription3), Mockito.anyLong());
+
+        Mockito.verify(mListener, Mockito.times(1))
+                .testRunEnded(
+                        Mockito.anyLong(),
+                        Mockito.<HashMap<String, MetricMeasurement.Metric>>any());
+    }
+
     /** Test the run method for a couple commands with ExcludeFilters */
     @Test
     public void testRun_addExcludeFilter()
diff --git a/javatests/com/android/tradefed/testtype/python/PythonBinaryHostTestTest.java b/javatests/com/android/tradefed/testtype/python/PythonBinaryHostTestTest.java
index 20d05282d..567003b0e 100644
--- a/javatests/com/android/tradefed/testtype/python/PythonBinaryHostTestTest.java
+++ b/javatests/com/android/tradefed/testtype/python/PythonBinaryHostTestTest.java
@@ -20,8 +20,6 @@ import static com.android.tradefed.testtype.python.PythonBinaryHostTest.USE_TEST
 
 import static com.google.common.truth.Truth.assertThat;
 
-import static org.junit.Assert.assertFalse;
-import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.times;
@@ -29,10 +27,6 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import com.android.tradefed.build.IBuildInfo;
-import com.android.tradefed.cache.ICacheClient;
-import com.android.tradefed.command.CommandOptions;
-import com.android.tradefed.config.Configuration;
-import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.device.StubDevice;
@@ -51,7 +45,6 @@ import com.android.tradefed.util.CommandStatus;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.IRunUtil;
 import com.android.tradefed.util.IRunUtil.EnvPriority;
-import com.android.tradefed.util.RunUtilTest;
 import com.android.tradefed.util.StreamUtil;
 
 import org.junit.After;
@@ -85,10 +78,10 @@ public final class PythonBinaryHostTestTest {
     @Mock ITestInvocationListener mMockListener;
     private File mFakeAdb;
     private File mFakeAapt;
+    private File mFakeAapt2;
     private File mPythonBinary;
     private File mOutputFile;
     private File mModuleDir;
-    private RunUtilTest.FakeCacheClient mFakeCacheClient;
 
     @Before
     public void setUp() throws Exception {
@@ -96,6 +89,7 @@ public final class PythonBinaryHostTestTest {
 
         mFakeAdb = FileUtil.createTempFile("adb-python-tests", "");
         mFakeAapt = FileUtil.createTempFile("aapt-python-tests", "");
+        mFakeAapt2 = FileUtil.createTempFile("aapt2-python-tests", "");
 
         mTest =
                 new PythonBinaryHostTest() {
@@ -105,13 +99,18 @@ public final class PythonBinaryHostTestTest {
                     }
 
                     @Override
-                    File getAdb() {
-                        return mFakeAdb;
+                    String getAdb() {
+                        return mFakeAdb.getAbsolutePath();
                     }
 
                     @Override
-                    File getAapt() {
-                        return mFakeAapt;
+                    String getAapt() {
+                        return mFakeAapt.getAbsolutePath();
+                    }
+
+                    @Override
+                    String getAapt2() {
+                        return mFakeAapt2.getAbsolutePath();
                     }
 
                     @Override
@@ -132,61 +131,16 @@ public final class PythonBinaryHostTestTest {
         mModuleDir = FileUtil.createTempDir("python-module");
         mPythonBinary = FileUtil.createTempFile("python-dir", "", mModuleDir);
         mTestInfo.executionFiles().put(FilesKey.HOST_TESTS_DIRECTORY, new File("/path-not-exist"));
-        mFakeCacheClient = new RunUtilTest.FakeCacheClient();
     }
 
     @After
     public void tearDown() throws Exception {
         FileUtil.deleteFile(mFakeAdb);
         FileUtil.deleteFile(mFakeAapt);
+        FileUtil.deleteFile(mFakeAapt2);
         FileUtil.deleteFile(mPythonBinary);
         FileUtil.deleteFile(mOutputFile);
         FileUtil.recursiveDelete(mModuleDir);
-        mFakeCacheClient.getAllCache().values().stream()
-                .forEach(
-                        a -> {
-                            FileUtil.deleteFile(a.stdOut());
-                            FileUtil.deleteFile(a.stdErr());
-                        });
-    }
-
-    /** Test that a success python host test run is uploaded to cache service. */
-    @Test
-    public void testRun_upload_cache_for_success_run() throws Exception {
-        PythonBinaryHostTest pyTest =
-                createPythonBinaryHostTestWithCache(
-                        "echo \"hello_world_test (__main__.HelloWorldTest.hello_world_test) ..."
-                            + " ok\n\n"
-                            + "----------------------------------------------------------------------\n"
-                            + "Ran 1 test in 0.001s\n\n"
-                            + "OK\n"
-                            + "\" >&2");
-
-        pyTest.run(mTestInfo, mMockListener);
-
-        assertFalse(mFakeCacheClient.getAllCache().isEmpty());
-    }
-
-    /** Test that a failed python host test run is not uploaded to cache service. */
-    @Test
-    public void testRun_skip_cache_uploading_for_failed_run() throws Exception {
-        PythonBinaryHostTest pyTest =
-                createPythonBinaryHostTestWithCache(
-                        "echo \"hello_world_test (__main__.HelloWorldTest.hello_world_test) ..."
-                            + " FAIL \n\n"
-                            + "======================================================================\n"
-                            + "FAIL: hello_world_test (__main__.HelloWorldTest.hello_world_test)\n"
-                            + "----------------------------------------------------------------------\n"
-                            + "Traceback (most recent call last):\n"
-                            + "  File \"hello_world_test.py\", line 666, in hello_world_test\n"
-                            + "AssertionError: True is not false\n\n"
-                            + "----------------------------------------------------------------------\n"
-                            + "Ran 1 test in 0.001sFAILED (failures=1)\n"
-                            + "\" >&2");
-
-        pyTest.run(mTestInfo, mMockListener);
-
-        assertTrue(mFakeCacheClient.getAllCache().isEmpty());
     }
 
     /** Test that when running a python binary the output is parsed to obtain results. */
@@ -222,7 +176,10 @@ public final class PythonBinaryHostTestTest {
             mTest.run(mTestInfo, mMockListener);
             mTest.run(mTestInfo, mMockListener);
 
-            verify(mMockRunUtil, times(2)).setEnvVariable("PATH", ".:runtime_deps:/usr/bin");
+            verify(mMockRunUtil, times(2))
+                    .setEnvVariable(
+                            "PATH",
+                            String.format("%s:%s:/usr/bin", mFakeAdb.getParent(), mModuleDir));
             verify(mMockRunUtil, times(2))
                     .setEnvVariable(Mockito.eq("LD_LIBRARY_PATH"), Mockito.any());
             verify(mMockListener, times(2))
@@ -1023,29 +980,4 @@ public final class PythonBinaryHostTestTest {
         FileUtil.writeToFile(stream, output);
         return output;
     }
-
-    private PythonBinaryHostTest createPythonBinaryHostTestWithCache(String scriptContent)
-            throws Exception {
-        PythonBinaryHostTest pyTest =
-                new PythonBinaryHostTest() {
-                    @Override
-                    ICacheClient getCacheClient(File workFolder, String instanceName) {
-                        return mFakeCacheClient;
-                    }
-                };
-        File binary =
-                new File(FileUtil.createTempDir("hosttestcases", mModuleDir), "hello_world_test");
-        FileUtil.writeToFile(scriptContent, binary);
-        binary.setExecutable(true);
-        OptionSetter testSetter = new OptionSetter(pyTest);
-        testSetter.setOptionValue("python-binaries", binary.getAbsolutePath());
-        testSetter.setOptionValue("enable-cache", "true");
-        CommandOptions commandOptions = new CommandOptions();
-        OptionSetter commandOptionsSetter = new OptionSetter(commandOptions);
-        commandOptionsSetter.setOptionValue("remote-cache-instance-name", "test_instance");
-        IConfiguration config = new Configuration("config", "Test config");
-        config.setCommandOptions(commandOptions);
-        pyTest.setConfiguration(config);
-        return pyTest;
-    }
 }
diff --git a/javatests/com/android/tradefed/testtype/rust/RustBinaryHostTestTest.java b/javatests/com/android/tradefed/testtype/rust/RustBinaryHostTestTest.java
index 255c5a117..d8fe4e259 100644
--- a/javatests/com/android/tradefed/testtype/rust/RustBinaryHostTestTest.java
+++ b/javatests/com/android/tradefed/testtype/rust/RustBinaryHostTestTest.java
@@ -16,19 +16,13 @@
 package com.android.tradefed.testtype.rust;
 
 import static org.junit.Assert.assertFalse;
-import static org.junit.Assert.assertTrue;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import com.android.tradefed.build.BuildInfoKey.BuildInfoFileKey;
-import com.android.tradefed.build.DeviceBuildInfo;
 import com.android.tradefed.build.IBuildInfo;
-import com.android.tradefed.cache.ICacheClient;
-import com.android.tradefed.command.CommandOptions;
-import com.android.tradefed.config.Configuration;
-import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.invoker.InvocationContext;
 import com.android.tradefed.invoker.TestInformation;
@@ -43,7 +37,6 @@ import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.IRunUtil;
-import com.android.tradefed.util.RunUtilTest;
 
 import com.google.common.truth.Truth;
 
@@ -63,7 +56,6 @@ import java.util.List;
 /** Unit tests for {@link RustBinaryHostTest}. */
 @RunWith(JUnit4.class)
 public class RustBinaryHostTestTest {
-    private RunUtilTest.FakeCacheClient mFakeCacheClient;
     private RustBinaryHostTest mTest;
     private TestInformation mTestInfo;
     private File mModuleDir;
@@ -87,18 +79,11 @@ public class RustBinaryHostTestTest {
         context.addDeviceBuildInfo("device", mMockBuildInfo);
         mTestInfo = TestInformation.newBuilder().setInvocationContext(context).build();
         mModuleDir = FileUtil.createTempDir("rust-module");
-        mFakeCacheClient = new RunUtilTest.FakeCacheClient();
     }
 
     @After
     public void tearDown() throws Exception {
         FileUtil.recursiveDelete(mModuleDir);
-        mFakeCacheClient.getAllCache().values().stream()
-                .forEach(
-                        a -> {
-                            FileUtil.deleteFile(a.stdOut());
-                            FileUtil.deleteFile(a.stdErr());
-                        });
     }
 
     private CommandResult newCommandResult(CommandStatus status, String stderr, String stdout) {
@@ -218,42 +203,6 @@ public class RustBinaryHostTestTest {
                 .thenReturn(successResult("", output));
     }
 
-    /** Test that a success rust test run is uploaded to cache service. */
-    @Test
-    public void testRun_upload_cache_for_success_run() throws Exception {
-        RustBinaryHostTest rustTest =
-                createRustBinaryHostTestWithCache(
-                        "#!/bin/bash\n"
-                            + "[ \"${@: -1}\" == \"--list\" ] && echo \"hello_world_test : test\""
-                            + " || echo \"running 1 tests\n"
-                            + "test hello_world ... ok <0.001s>\n"
-                            + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0"
-                            + " filtered out; finished in 0.01s\n"
-                            + "\"");
-
-        rustTest.run(mTestInfo, mMockListener);
-
-        assertFalse(mFakeCacheClient.getAllCache().isEmpty());
-    }
-
-    /** Test that a failed rust test run is not uploaded to cache service. */
-    @Test
-    public void testRun_skip_cache_uploading_for_failed_run() throws Exception {
-        RustBinaryHostTest rustTest =
-                createRustBinaryHostTestWithCache(
-                        "#!/bin/bash\n"
-                            + "[ \"${@: -1}\" == \"--list\" ] && echo \"hello_world_test : test\""
-                            + " || echo \"running 1 tests\n"
-                            + "test hello_world ... FAILED <0.001s>\n"
-                            + "test result: ok. 0 passed; 1 failed; 0 ignored; 0 measured; 0"
-                            + " filtered out; finished in 0.01s\n"
-                            + "\"");
-
-        rustTest.run(mTestInfo, mMockListener);
-
-        assertTrue(mFakeCacheClient.getAllCache().isEmpty());
-    }
-
     /** Test that when running a rust binary the output is parsed to obtain results. */
     @Test
     public void testRun() throws Exception {
@@ -764,32 +713,4 @@ public class RustBinaryHostTestTest {
             FileUtil.recursiveDelete(testsDir);
         }
     }
-
-    private RustBinaryHostTest createRustBinaryHostTestWithCache(String scriptContent)
-            throws Exception {
-        RustBinaryHostTest rustTest =
-                new RustBinaryHostTest() {
-                    @Override
-                    ICacheClient getCacheClient(File workFolder, String instanceName) {
-                        return mFakeCacheClient;
-                    }
-                };
-        File hostLinkedFolder = FileUtil.createTempDir("hosttestcases", mModuleDir);
-        File binary = new File(hostLinkedFolder, "hello_world_test");
-        FileUtil.writeToFile(scriptContent, binary);
-        binary.setExecutable(true);
-        OptionSetter testSetter = new OptionSetter(rustTest);
-        testSetter.setOptionValue("test-file", binary.getAbsolutePath());
-        testSetter.setOptionValue("enable-cache", "true");
-        DeviceBuildInfo buildInfo = new DeviceBuildInfo();
-        buildInfo.setFile(BuildInfoFileKey.HOST_LINKED_DIR, hostLinkedFolder, "0.0");
-        rustTest.setBuild(buildInfo);
-        CommandOptions commandOptions = new CommandOptions();
-        OptionSetter commandOptionsSetter = new OptionSetter(commandOptions);
-        commandOptionsSetter.setOptionValue("remote-cache-instance-name", "test_instance");
-        IConfiguration config = new Configuration("config", "Test config");
-        config.setCommandOptions(commandOptions);
-        rustTest.setConfiguration(config);
-        return rustTest;
-    }
 }
diff --git a/javatests/com/android/tradefed/testtype/suite/AtestRunnerTest.java b/javatests/com/android/tradefed/testtype/suite/AtestRunnerTest.java
index 472bfadef..a1d18f60a 100644
--- a/javatests/com/android/tradefed/testtype/suite/AtestRunnerTest.java
+++ b/javatests/com/android/tradefed/testtype/suite/AtestRunnerTest.java
@@ -17,8 +17,13 @@ package com.android.tradefed.testtype.suite;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
+import static org.mockito.Mockito.any;
+import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.spy;
+import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.when;
+import static org.mockito.Mockito.verify;
 
 import com.android.tradefed.build.IDeviceBuildInfo;
 import com.android.tradefed.config.IConfiguration;
@@ -27,6 +32,7 @@ import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.result.ITestInvocationListener;
 import com.android.tradefed.targetprep.ITargetPreparer;
+import com.android.tradefed.targetprep.incremental.IIncrementalSetup;
 import com.android.tradefed.testtype.Abi;
 import com.android.tradefed.testtype.IAbi;
 import com.android.tradefed.testtype.IRemoteTest;
@@ -72,6 +78,7 @@ public class AtestRunnerTest {
 
     private AbiAtestRunner mRunner;
     private OptionSetter setter;
+    private IConfiguration mConfig;
     private IDeviceBuildInfo mBuildInfo;
     private ITestDevice mMockDevice;
     private String classA = "fully.qualified.classA";
@@ -98,6 +105,7 @@ public class AtestRunnerTest {
         mMockDevice = mock(ITestDevice.class);
         mRunner.setBuild(mBuildInfo);
         mRunner.setDevice(mMockDevice);
+        mConfig = mock(IConfiguration.class);
 
         when(mBuildInfo.getTestsDir()).thenReturn(mTempFolder.newFolder());
 
@@ -292,9 +300,98 @@ public class AtestRunnerTest {
         assertEquals(1, listeners.size());
     }
 
+    @Test
+    public void testIncrementalSetup_defaultNoChangeExpectedForTargetPreparers() throws Exception {
+        List<ITargetPreparer> targetPreparers = new ArrayList<>();
+        PseudoTargetPreparer preparer = spy(new PseudoTargetPreparer());
+        targetPreparers.add(preparer);
+        when(mConfig.getName()).thenReturn("custom-configuration");
+        when(mConfig.getTargetPreparers()).thenReturn(targetPreparers);
+
+        LinkedHashMap<String, IConfiguration> pseudoConfigMap = new LinkedHashMap<>();
+        pseudoConfigMap.put("pseudo-config", mConfig);
+        AbiAtestRunner runner = spy(mRunner);
+        doReturn(pseudoConfigMap).when(runner).loadingStrategy(any(), any(), any(), any());
+
+        OptionSetter setter = new OptionSetter(runner);
+
+        LinkedHashMap<String, IConfiguration> configMap = runner.loadTests();
+
+        assertEquals(1, configMap.size());
+        IConfiguration config = configMap.get("pseudo-config");
+        for (ITargetPreparer targetPreparer : config.getTargetPreparers()) {
+            verify((IIncrementalSetup) targetPreparer, times(0))
+                .setIncrementalSetupEnabled(false);
+            verify((IIncrementalSetup) targetPreparer, times(0))
+                .setIncrementalSetupEnabled(true);
+        }
+    }
+
+    @Test
+    public void testIncrementalSetup_disabledForTargetPreparers() throws Exception {
+        List<ITargetPreparer> targetPreparers = new ArrayList<>();
+        PseudoTargetPreparer preparer = spy(new PseudoTargetPreparer());
+        targetPreparers.add(preparer);
+        when(mConfig.getName()).thenReturn("custom-configuration");
+        when(mConfig.getTargetPreparers()).thenReturn(targetPreparers);
+
+        LinkedHashMap<String, IConfiguration> pseudoConfigMap = new LinkedHashMap<>();
+        pseudoConfigMap.put("pseudo-config", mConfig);
+        AbiAtestRunner runner = spy(mRunner);
+        doReturn(pseudoConfigMap).when(runner).loadingStrategy(any(), any(), any(), any());
+
+        OptionSetter setter = new OptionSetter(runner);
+        setter.setOptionValue("incremental-setup", "NO");
+
+        LinkedHashMap<String, IConfiguration> configMap = runner.loadTests();
+
+        assertEquals(1, configMap.size());
+        IConfiguration config = configMap.get("pseudo-config");
+        for (ITargetPreparer targetPreparer : config.getTargetPreparers()) {
+            verify((IIncrementalSetup) targetPreparer).setIncrementalSetupEnabled(false);
+            verify((IIncrementalSetup) targetPreparer, times(0))
+                .setIncrementalSetupEnabled(true);
+        }
+    }
+
+    @Test
+    public void testIncrementalSetup_enabledForTargetPreparers() throws Exception {
+        List<ITargetPreparer> targetPreparers = new ArrayList<>();
+        PseudoTargetPreparer preparer = spy(new PseudoTargetPreparer());
+        targetPreparers.add(preparer);
+        when(mConfig.getName()).thenReturn("custom-configuration");
+        when(mConfig.getTargetPreparers()).thenReturn(targetPreparers);
+
+        LinkedHashMap<String, IConfiguration> pseudoConfigMap = new LinkedHashMap<>();
+        pseudoConfigMap.put("pseudo-config", mConfig);
+        AbiAtestRunner runner = spy(mRunner);
+        doReturn(pseudoConfigMap).when(runner).loadingStrategy(any(), any(), any(), any());
+
+        OptionSetter setter = new OptionSetter(runner);
+        setter.setOptionValue("incremental-setup", "YES");
+
+        LinkedHashMap<String, IConfiguration> configMap = runner.loadTests();
+
+        assertEquals(1, configMap.size());
+        IConfiguration config = configMap.get("pseudo-config");
+        for (ITargetPreparer targetPreparer : config.getTargetPreparers()) {
+            verify((IIncrementalSetup) targetPreparer).setIncrementalSetupEnabled(true);
+            verify((IIncrementalSetup) targetPreparer, times(0))
+                .setIncrementalSetupEnabled(false);
+        }
+    }
+
     private String createModuleConfig(File dir, String moduleName) throws IOException {
         File moduleConfig = new File(dir, moduleName + SuiteModuleLoader.CONFIG_EXT);
         FileUtil.writeToFile(TEST_CONFIG, moduleConfig);
         return moduleConfig.getAbsolutePath();
     }
+
+    /** A pseudo target preparer which is optimizable with incremental setup. */
+    private static class PseudoTargetPreparer implements ITargetPreparer, IIncrementalSetup {
+        @Override
+        public void setIncrementalSetupEnabled(boolean shouldEnable) {
+            // Intentionally left empty.
+        }
+    }
 }
diff --git a/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnCloneProfileParameterHandlerTest.java b/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnCloneProfileParameterHandlerTest.java
index 03dfa6e9b..4c7833f33 100644
--- a/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnCloneProfileParameterHandlerTest.java
+++ b/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnCloneProfileParameterHandlerTest.java
@@ -39,7 +39,7 @@ import java.util.Set;
 public class RunOnCloneProfileParameterHandlerTest {
 
     private static final String REQUIRE_RUN_ON_CLONE_PROFILE_NAME =
-            "com.android.bedstead.harrier.annotations.RequireRunOnCloneProfile";
+            "com.android.bedstead.multiuser.annotations.RequireRunOnCloneProfile";
     private static final String EXISTING_ANNOTATION_FILTER = "existing.annotation.filter";
 
     private RunOnCloneProfileParameterHandler mHandler;
diff --git a/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnPrivateProfileParameterHandlerTest.java b/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnPrivateProfileParameterHandlerTest.java
index b9cff1d8e..30aa0e6e4 100644
--- a/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnPrivateProfileParameterHandlerTest.java
+++ b/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnPrivateProfileParameterHandlerTest.java
@@ -39,7 +39,7 @@ import java.util.Set;
 public class RunOnPrivateProfileParameterHandlerTest {
 
     private static final String REQUIRE_RUN_ON_PRIVATE_PROFILE_NAME =
-            "com.android.bedstead.harrier.annotations.RequireRunOnPrivateProfile";
+            "com.android.bedstead.multiuser.annotations.RequireRunOnPrivateProfile";
     private static final String EXISTING_ANNOTATION_FILTER = "existing.annotation.filter";
 
     private RunOnPrivateProfileParameterHandler mHandler;
diff --git a/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnSecondaryUserParameterHandlerTest.java b/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnSecondaryUserParameterHandlerTest.java
index ec130cce9..3533875dc 100644
--- a/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnSecondaryUserParameterHandlerTest.java
+++ b/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnSecondaryUserParameterHandlerTest.java
@@ -39,7 +39,7 @@ import java.util.Set;
 public class RunOnSecondaryUserParameterHandlerTest {
 
     private static final String REQUIRE_RUN_ON_SECONDARY_USER_NAME =
-            "com.android.bedstead.harrier.annotations.RequireRunOnSecondaryUser";
+            "com.android.bedstead.multiuser.annotations.RequireRunOnSecondaryUser";
     private static final String EXISTING_ANNOTATION_FILTER = "existing.annotation.filter";
 
     private RunOnSecondaryUserParameterHandler mHandler;
diff --git a/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnWorkProfileParameterHandlerTest.java b/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnWorkProfileParameterHandlerTest.java
index 659368b07..12482146d 100644
--- a/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnWorkProfileParameterHandlerTest.java
+++ b/javatests/com/android/tradefed/testtype/suite/params/multiuser/RunOnWorkProfileParameterHandlerTest.java
@@ -39,7 +39,7 @@ import java.util.Set;
 public class RunOnWorkProfileParameterHandlerTest {
 
     private static final String REQUIRE_RUN_ON_WORK_PROFILE_NAME =
-            "com.android.bedstead.harrier.annotations.RequireRunOnWorkProfile";
+            "com.android.bedstead.enterprise.annotations.RequireRunOnWorkProfile";
     private static final String EXISTING_ANNOTATION_FILTER = "existing.annotation.filter";
 
     private RunOnWorkProfileParameterHandler mHandler;
diff --git a/javatests/com/android/tradefed/util/EmailTest.java b/javatests/com/android/tradefed/util/EmailTest.java
index 91638b5a3..688dee258 100644
--- a/javatests/com/android/tradefed/util/EmailTest.java
+++ b/javatests/com/android/tradefed/util/EmailTest.java
@@ -20,6 +20,7 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -204,6 +205,7 @@ public class EmailTest {
      * Not enabled by default because the particular addresses to use will depend on the environment
      */
     @SuppressWarnings("unused")
+    @Ignore
     public void _manual_testFuncSend() throws IOException {
         final String sender = null;
         final String[] to = {"RECIPIENT"};
diff --git a/javatests/com/android/tradefed/util/RunUtilTest.java b/javatests/com/android/tradefed/util/RunUtilTest.java
index 265fd9091..dd06517aa 100644
--- a/javatests/com/android/tradefed/util/RunUtilTest.java
+++ b/javatests/com/android/tradefed/util/RunUtilTest.java
@@ -28,18 +28,12 @@ import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
-import com.android.tradefed.cache.DigestCalculator;
-import com.android.tradefed.cache.ExecutableAction;
-import com.android.tradefed.cache.ExecutableActionResult;
-import com.android.tradefed.cache.ICacheClient;
 import com.android.tradefed.command.CommandInterrupter;
 import com.android.tradefed.result.error.InfraErrorIdentifier;
 import com.android.tradefed.util.IRunUtil.EnvPriority;
 import com.android.tradefed.util.IRunUtil.IRunnableResult;
 import com.android.tradefed.util.RunUtil.RunnableResult;
 
-import build.bazel.remote.execution.v2.Digest;
-
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
@@ -54,8 +48,6 @@ import java.io.IOException;
 import java.io.InputStream;
 import java.io.OutputStream;
 import java.util.ArrayList;
-import java.util.HashMap;
-import java.util.Map;
 import java.util.concurrent.TimeUnit;
 
 /** Unit tests for {@link RunUtil} */
@@ -138,45 +130,6 @@ public class RunUtilTest {
         }
     }
 
-    /** Test class implementing {@link ICacheClient} to mock the cache client. */
-    public static class FakeCacheClient implements ICacheClient {
-        private final Map<Digest, ExecutableActionResult> mCache = new HashMap<>();
-
-        public FakeCacheClient() {}
-
-        public Map<Digest, ExecutableActionResult> getAllCache() {
-            return mCache;
-        }
-
-        @Override
-        public void uploadCache(ExecutableAction action, ExecutableActionResult actionResult) {
-            try {
-                File stdout = FileUtil.createTempFile("stdout_", ".txt");
-                FileUtil.copyFile(actionResult.stdOut(), stdout);
-                File stderr = null;
-                if (actionResult.stdErr() != null) {
-                    stderr = FileUtil.createTempFile("stderr_", ".txt");
-                    FileUtil.copyFile(actionResult.stdErr(), stderr);
-                }
-                mCache.putIfAbsent(
-                        DigestCalculator.compute(action.action()),
-                        ExecutableActionResult.create(actionResult.exitCode(), stdout, stderr));
-            } catch (IOException e) {
-                // Don't fail the invocation if failed to upload cache.
-                return;
-            }
-        }
-
-        @Override
-        public ExecutableActionResult lookupCache(ExecutableAction action) {
-            Digest digest = DigestCalculator.compute(action.action());
-            if (mCache.containsKey(digest)) {
-                return mCache.get(digest);
-            }
-            return null;
-        }
-    }
-
     /** Test success case for {@link RunUtil#runTimed(long, IRunnableResult, boolean)}. */
     @Test
     public void testRunTimed() throws Exception {
@@ -240,83 +193,6 @@ public class RunUtilTest {
         assertTrue(result.getStderr().contains("Cannot run program \"blahggggwarggg\""));
     }
 
-    /**
-     * Test {@link runTimedCmdWithOutputMonitor(long, long, OutputStream, OutputStream,
-     * ICacheClient, String...)} caches command execution successfully.
-     */
-    @Test
-    public void runTimedCmdWithOutputMonitor_cache_same_run() throws IOException {
-        String content = "echo test-cache-stdout";
-        File firstWorkingDir = FileUtil.createTempDir("first_run_", mWorkingDir);
-        File sharedLibA = new File(firstWorkingDir, "lib1");
-        sharedLibA.createNewFile();
-        File sharedLibB = new File(firstWorkingDir, "lib2");
-        sharedLibB.createNewFile();
-        File firstBinary = new File(firstWorkingDir, "hello_world_test.sh");
-        firstBinary.createNewFile();
-        FileUtil.writeToFile(content, firstBinary);
-        FileUtil.ensureGroupRWX(firstBinary);
-        File firstStdout = FileUtil.createTempFile("stdout_subprocess_1_", ".txt", mWorkingDir);
-        File firstStderr = FileUtil.createTempFile("stderr_subprocess_1_", ".txt", mWorkingDir);
-        File secondWorkingDir = FileUtil.createTempDir("second_run_", mWorkingDir);
-        File sharedLibC = new File(secondWorkingDir, "lib1");
-        sharedLibC.createNewFile();
-        File sharedLibD = new File(secondWorkingDir, "lib2");
-        sharedLibD.createNewFile();
-        File secondBinary = new File(secondWorkingDir, "hello_world_test.sh");
-        secondBinary.createNewFile();
-        FileUtil.writeToFile(content, secondBinary);
-        FileUtil.ensureGroupRWX(secondBinary);
-        File secondStdout = FileUtil.createTempFile("stdout_subprocess_2_", ".txt", mWorkingDir);
-        File secondStderr = FileUtil.createTempFile("stderr_subprocess_2_", ".txt", mWorkingDir);
-        MonitoredRunUtil firstRunUtil = new MonitoredRunUtil(false);
-        firstRunUtil.setWorkingDir(firstWorkingDir);
-        firstRunUtil.setEnvVariable(
-                "LD_LIBRARY_PATH",
-                sharedLibA.getAbsolutePath() + ":" + sharedLibB.getAbsolutePath());
-        MonitoredRunUtil secondRunUtil = new MonitoredRunUtil(false);
-        secondRunUtil.setWorkingDir(secondWorkingDir);
-        secondRunUtil.setEnvVariable(
-                "LD_LIBRARY_PATH",
-                sharedLibD.getAbsolutePath() + ":" + sharedLibC.getAbsolutePath());
-        String[] firstCommand = {firstBinary.getAbsolutePath(), "--option"};
-        String[] secondCommand = {secondBinary.getAbsolutePath(), "--option"};
-        ICacheClient cacheClient = new FakeCacheClient();
-
-        CommandResult firstResult =
-                firstRunUtil.runTimedCmdWithOutputMonitor(
-                        LONG_TIMEOUT_MS,
-                        0,
-                        new FileOutputStream(firstStdout),
-                        new FileOutputStream(firstStderr),
-                        cacheClient,
-                        firstCommand);
-        firstRunUtil.uploadCache(
-                cacheClient,
-                ExecutableActionResult.create(firstResult.getExitCode(), firstStdout, firstStderr));
-        CommandResult secondResult =
-                secondRunUtil.runTimedCmdWithOutputMonitor(
-                        LONG_TIMEOUT_MS,
-                        0,
-                        new FileOutputStream(secondStdout),
-                        new FileOutputStream(secondStderr),
-                        cacheClient,
-                        secondCommand);
-        String actualStdout = FileUtil.readStringFromFile(firstStdout);
-
-        assertFalse(firstResult.isCached());
-        assertTrue(secondResult.isCached());
-        assertEquals(CommandStatus.SUCCESS, firstResult.getStatus());
-        assertEquals(CommandStatus.SUCCESS, secondResult.getStatus());
-        // Remove the line break character.
-        assertEquals(actualStdout.substring(0, actualStdout.length() - 1), "test-cache-stdout");
-        assertEquals(actualStdout, FileUtil.readStringFromFile(secondStdout));
-        assertTrue(FileUtil.readStringFromFile(firstStderr).isEmpty());
-        assertTrue(FileUtil.readStringFromFile(secondStderr).isEmpty());
-        assertEquals(
-                firstRunUtil.processBuilder.environment(), Map.of("LD_LIBRARY_PATH", "lib1:lib2"));
-    }
-
     /**
      * Test {@link RunUtil#runTimedCmd(long, String[])} exits with status SUCCESS since the output
      * monitor observed output on streams through the command time until finished.
diff --git a/javatests/com/android/tradefed/util/testmapping/TestMappingTest.java b/javatests/com/android/tradefed/util/testmapping/TestMappingTest.java
index fa89f7c92..875230536 100644
--- a/javatests/com/android/tradefed/util/testmapping/TestMappingTest.java
+++ b/javatests/com/android/tradefed/util/testmapping/TestMappingTest.java
@@ -932,6 +932,53 @@ public class TestMappingTest {
         }
     }
 
+    /**
+     * Test for {@link TestMapping#getTestMappingSources()} for collecting paths of TEST_MAPPING
+     * files from a zip file and a directory.
+     */
+    @Test
+    public void testGetTestMappingSources_Dir() throws Exception {
+        // Test directory structure:
+        // ├── disabled-presubmit-tests
+        // ├── src1
+        // |   ├── sub_dir1
+        // |   |  └── TEST_MAPPING
+        // │   └── TEST_MAPPING
+        // ├── src2
+        // │   └── TEST_MAPPING
+        // └── test_mappings.zip
+        File tempDir = null;
+        try {
+            tempDir = FileUtil.createTempDir("test_mapping");
+            File srcDir = FileUtil.createNamedTempDir(tempDir, "src1");
+            String srcFile = File.separator + TEST_DATA_DIR + File.separator + "test_mapping_1";
+            InputStream resourceStream = this.getClass().getResourceAsStream(srcFile);
+            FileUtil.saveResourceFile(resourceStream, srcDir, TEST_MAPPING);
+
+            File subDir = FileUtil.createNamedTempDir(srcDir, "sub_dir1");
+            srcFile = File.separator + TEST_DATA_DIR + File.separator + "test_mapping_2";
+            resourceStream = this.getClass().getResourceAsStream(srcFile);
+            FileUtil.saveResourceFile(resourceStream, subDir, TEST_MAPPING);
+
+            subDir = FileUtil.createNamedTempDir(tempDir, "src2");
+            srcFile = File.separator + TEST_DATA_DIR + File.separator + "test_mapping_1";
+            resourceStream = this.getClass().getResourceAsStream(srcFile);
+            FileUtil.saveResourceFile(resourceStream, subDir, TEST_MAPPING);
+
+            srcFile = File.separator + TEST_DATA_DIR + File.separator + DISABLED_PRESUBMIT_TESTS;
+            resourceStream = this.getClass().getResourceAsStream(srcFile);
+            FileUtil.saveResourceFile(resourceStream, tempDir, DISABLED_PRESUBMIT_TESTS);
+
+            Set<String> sources = mTestMapping.getTestMappingSources(tempDir);
+            assertEquals(3, sources.size());
+            assertTrue(sources.contains("src1/TEST_MAPPING"));
+            assertTrue(sources.contains("src1/sub_dir1/TEST_MAPPING"));
+            assertTrue(sources.contains("src2/TEST_MAPPING"));
+        } finally {
+            FileUtil.recursiveDelete(tempDir);
+        }
+    }
+
     /**
      * Test for {@link TestMapping#mergeTestMappingZips()} for merging a missed test_mappings.zip.
      */
@@ -1084,6 +1131,65 @@ public class TestMappingTest {
         }
     }
 
+    /**
+     * Test for {@link TestMapping#getTests()} for loading tests from a test_mappings.zip and a
+     * directory
+     */
+    @Test
+    public void testGetTestsWithAdditionalTestMappingDir() throws Exception {
+        // Test directory1 structure:
+        // ├── disabled-presubmit-tests
+        // ├── src1
+        // │   └── TEST_MAPPING
+        // └── test_mappings.zip
+        //
+        // Test directory2 structure:
+        // ├── disabled-presubmit-tests
+        // ├── src2
+        // │   └── TEST_MAPPING
+        File tempDir = null;
+        File tempDir2 = null;
+        IBuildInfo mockBuildInfo = mock(IBuildInfo.class);
+        try {
+            // Create 1 test_mappings.zip
+            tempDir = FileUtil.createTempDir("test_mapping");
+            File srcDir = FileUtil.createNamedTempDir(tempDir, "src1");
+            createTestMapping(srcDir, "test_mapping_kernel1");
+            createTestMapping(tempDir, DISABLED_PRESUBMIT_TESTS);
+            List<File> filesToZip =
+                    Arrays.asList(srcDir, new File(tempDir, DISABLED_PRESUBMIT_TESTS));
+            File zipFile = Paths.get(tempDir.getAbsolutePath(), TEST_MAPPINGS_ZIP).toFile();
+            ZipUtil.createZip(filesToZip, zipFile);
+
+            // Create another 1 test_mappings.zip
+            tempDir2 = FileUtil.createTempDir("test_mapping");
+            File srcDir2 = FileUtil.createNamedTempDir(tempDir2, "src2");
+            createTestMapping(srcDir2, "test_mapping_kernel2");
+
+            when(mockBuildInfo.getFile(TEST_MAPPINGS_ZIP)).thenReturn(zipFile);
+            when(mockBuildInfo.getFile("extra-zip")).thenReturn(tempDir2);
+            Set<TestInfo> results =
+                    mTestMapping.getTests(
+                            mockBuildInfo,
+                            "presubmit",
+                            false,
+                            null,
+                            new HashSet<String>(),
+                            Arrays.asList("extra-zip"),
+                            new HashSet<>());
+            assertEquals(2, results.size());
+            Set<String> names = new HashSet<String>();
+            for (TestInfo test : results) {
+                names.add(test.getName());
+            }
+            assertTrue(names.contains("test1"));
+            assertTrue(names.contains("test2"));
+        } finally {
+            FileUtil.recursiveDelete(tempDir);
+            FileUtil.recursiveDelete(tempDir2);
+        }
+    }
+
     /**
      * Test for {@link TestMapping#getTests(Map, String, Set, boolean, Set)} for parsing
      * TEST_MAPPING with checking file_patterns matched.
diff --git a/javatests/res/device/wifi_status_output_1.txt b/javatests/res/device/wifi_status_output_1.txt
index b08f9500d..52a550589 100644
--- a/javatests/res/device/wifi_status_output_1.txt
+++ b/javatests/res/device/wifi_status_output_1.txt
@@ -2,7 +2,7 @@ Wifi is enabled
 Wifi scanning is only available when wifi is enabled
 ==== ClientModeManager instance: ConcreteClientModeManager{id=69960513 iface=wlan0 role=ROLE_CLIENT_PRIMARY} ====
 Wifi is connected to "GoogleGuest"
-WifiInfo: SSID: "GoogleGuest", BSSID: 48:2f:6b:ac:b2:31, MAC: 82:f2:40:f1:51:be, Security type: 0, Supplicant state: COMPLETED, Wi-Fi standard: 6, RSSI: -60, Link speed: 573Mbps, Tx Link speed: 573Mbps, Max Supported Tx Link speed: 573Mbps, Rx Link speed: 344Mbps, Max Supported Rx Link speed: 573Mbps, Frequency: 5300MHz, Net ID: 0, Metered hint: false, score: 60, CarrierMerged: false, SubscriptionId: -1, IsPrimary: 1
+WifiInfo: SSID: "GoogleGuest", BSSID: 48:2f:6b:ac:b2:31, MAC: 82:f2:40:f1:51:be, Security type: 0, Supplicant state: COMPLETED, Wi-Fi standard: 6, RSSI: -60, Link speed: 573Mbps, Tx Link speed: 573Mbps, Max Supported Tx Link speed: 573Mbps, Rx Link speed: 344Mbps, Max Supported Rx Link speed: 573Mbps, Frequency: 5300MHz, Net ID: 14, Metered hint: false, score: 60, CarrierMerged: false, SubscriptionId: -1, IsPrimary: 1
 successfulTxPackets: 90968
 successfulTxPacketsPerSecond: 24.560942521673798
 retriedTxPackets: 1055
diff --git a/javatests/res/testtype/gbench_output1.json b/javatests/res/testtype/gbench_output1.json
index 7bddf594f..3b854c2b6 100644
--- a/javatests/res/testtype/gbench_output1.json
+++ b/javatests/res/testtype/gbench_output1.json
@@ -11,19 +11,22 @@
       "name": "BM_one",
       "iterations": 109451958,
       "real_time": 5,
-      "cpu_time": 5
+      "cpu_time": 5,
+      "time_unit": "ns"
     },
     {
       "name": "BM_two",
       "iterations": 50906784,
       "real_time": 1,
-      "cpu_time": 11
+      "cpu_time": 11,
+      "time_unit": "ns"
     },
     {
       "name": "BM_string_strlen/64",
       "iterations": 10499948,
       "real_time": 60,
       "cpu_time": 60,
+      "time_unit": "ns",
       "bytes_per_second": 1061047935
     }
   ]
diff --git a/javatests/res/testtype/gbench_output2.json b/javatests/res/testtype/gbench_output2.json
index b0686c0ea..ae281a2ba 100644
--- a/javatests/res/testtype/gbench_output2.json
+++ b/javatests/res/testtype/gbench_output2.json
@@ -11,12 +11,14 @@
       "name": "BM_one",
       "iterations": 109451958,
       "real_time": 5,
-      "cpu_time": 5
+      "cpu_time": 5,
+      "time_unit": "ns"
     },
     {
       "name": "BM_two",
       "real_time": 1,
-      "cpu_time": 11
+      "cpu_time": 11,
+      "time_unit": "ns"
     }
   ]
 }
diff --git a/javatests/res/testtype/gbench_output3.json b/javatests/res/testtype/gbench_output3.json
index 35a1a40c6..0cd78d497 100644
--- a/javatests/res/testtype/gbench_output3.json
+++ b/javatests/res/testtype/gbench_output3.json
@@ -10,7 +10,8 @@
       "name": "BM_one",
       "iterations": 109451958,
       "real_time": 5,
-      "cpu_time": 5
+      "cpu_time": 5,
+      "time_unit": "ns"
     }
   ]
 }
diff --git a/javatests/res/testtype/gbench_output7.json b/javatests/res/testtype/gbench_output7.json
index 6596e5074..4ec337f8c 100644
--- a/javatests/res/testtype/gbench_output7.json
+++ b/javatests/res/testtype/gbench_output7.json
@@ -11,19 +11,22 @@
       "name": "BM_one",
       "iterations": 109451958,
       "real_time": 5,
-      "cpu_time": 5
+      "cpu_time": 5,
+      "time_unit": "ns"
     },
     {
       "name": "BM_two",
       "iterations": 50906784,
       "real_time": 1,
-      "cpu_time": 11
+      "cpu_time": 11,
+      "time_unit": "ns"
     },
     {
       "name": "BM_string_strlen/64",
       "iterations": 10499948,
       "real_time": 60,
       "cpu_time": 60,
+      "time_unit": "ns",
       "bytes_per_second": 1061047935
     },
     {
diff --git a/javatests/res/testtype/gtest_output15.txt b/javatests/res/testtype/gtest_output15.txt
new file mode 100644
index 000000000..48a2c2e78
--- /dev/null
+++ b/javatests/res/testtype/gtest_output15.txt
@@ -0,0 +1,12 @@
+[==========] Running 4 tests from 1 test suite.
+
+[ RUN      ] test_class1::tests::test_case1
+[       OK ] test_class1::tests::test_case1 (10 ms)
+[ RUN      ] test_class1::tests::test_case2
+[       OK ] test_class1::tests::test_case2 (20 ms)
+[ RUN      ] test_class2::tests::test_case1
+[       OK ] test_class2::tests::test_case1 (100 ms)
+[ RUN      ] test_class2::tests::test_case2
+[       OK ] test_class2::tests::test_case2 (200 ms)
+[==========] 4 tests ran (330 ms total).
+[  PASSED  ] 4 tests.
diff --git a/proto/resultdb/artifact.proto b/proto/resultdb/artifact.proto
new file mode 100644
index 000000000..cec9300bf
--- /dev/null
+++ b/proto/resultdb/artifact.proto
@@ -0,0 +1,123 @@
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
+syntax = "proto3";
+
+package luci.resultdb.v1;
+
+import "google/api/field_behavior.proto";
+import "google/protobuf/timestamp.proto";
+import public "tools/tradefederation/core/proto/resultdb/test_result.proto";
+
+option go_package = "go.chromium.org/luci/resultdb/proto/v1;resultpb";
+option java_package = "com.android.resultdb.proto";
+option java_multiple_files = true;
+
+// A file produced during a build/test, typically a test artifact.
+// The parent resource is either a TestResult or an Invocation.
+//
+// An invocation-level artifact might be related to tests, or it might not, for
+// example it may be used to store build step logs when streaming support is
+// added.
+// Next id: 11.
+message Artifact {
+  // Can be used to refer to this artifact.
+  // Format:
+  // - For invocation-level artifacts:
+  //   "invocations/{INVOCATION_ID}/artifacts/{ARTIFACT_ID}".
+  // - For test-result-level artifacts:
+  //   "invocations/{INVOCATION_ID}/tests/{URL_ESCAPED_TEST_ID}/results/{RESULT_ID}/artifacts/{ARTIFACT_ID}".
+  // where URL_ESCAPED_TEST_ID is the test_id escaped with
+  // https://golang.org/pkg/net/url/#PathEscape (see also https://aip.dev/122),
+  // and ARTIFACT_ID is documented below.
+  // Examples: "screenshot.png", "traces/a.txt".
+  string name = 1;
+
+  // A local identifier of the artifact, unique within the parent resource.
+  // MAY have slashes, but MUST NOT start with a slash.
+  // SHOULD not use backslashes.
+  // Regex: ^(?:[[:word:]]|\.)([\p{L}\p{M}\p{N}\p{P}\p{S}\p{Zs}]{0,254}[[:word:]])?$
+  string artifact_id = 2;
+
+  // A signed short-lived URL to fetch the contents of the artifact.
+  // See also fetch_url_expiration.
+  string fetch_url = 3;
+
+  // When fetch_url expires. If expired, re-request this Artifact.
+  google.protobuf.Timestamp fetch_url_expiration = 4;
+
+  // Media type of the artifact.
+  // Logs are typically "text/plain" and screenshots are typically "image/png".
+  // Optional.
+  string content_type = 5;
+
+  // Size of the file.
+  // Can be used in UI to decide between displaying the artifact inline or only
+  // showing a link if it is too large.
+  // If you are using the gcs_uri, this field is not verified, but only treated as a hint.
+  int64 size_bytes = 6;
+
+  // Contents of the artifact.
+  // This is INPUT_ONLY, and taken by BatchCreateArtifacts().
+  // All getter RPCs, such as ListArtifacts(), do not populate values into
+  // the field in the response.
+  // If specified, `gcs_uri` must be empty.
+  bytes contents = 7 [ (google.api.field_behavior) = INPUT_ONLY ];
+
+  // The GCS URI of the artifact if it's stored in GCS.  If specified, `contents` must be empty.
+  string gcs_uri = 8;
+
+  // Status of the test result that the artifact belongs to.
+  // This is only applicable for test-level artifacts, not invocation-level artifacts.
+  // We need this field because when an artifact is created (for example, with BatchCreateArtifact),
+  // the containing test result may or may not be created yet, as they
+  // are created in different channels from result sink.
+  // Having the test status here allows setting the correct status of artifact in BigQuery.
+  TestStatus test_status = 9;
+
+  // Indicates whether ListArtifactLines RPC can be used with this artifact.
+  bool has_lines = 11;
+}
+
+message ArtifactLine {
+  enum Severity {
+    SEVERITY_UNSPECIFIED = 0;
+    VERBOSE = 10;
+    TRACE = 20;
+    DEBUG = 30;
+    INFO = 40;
+    NOTICE = 50;
+    WARNING = 60;
+    ERROR = 70;
+    CRITICAL = 80;
+    FATAL = 90;
+  }
+
+  // The position of this line in the artifact.
+  // The numbers start from 1.
+  int64 number = 1;
+
+  // The extracted timestamp of the log line. Extraction is best effort only.
+  google.protobuf.Timestamp timestamp = 2;
+
+  // The extracted severity of the line. Extraction is best effort only.
+  Severity severity = 3;
+
+  // The content of the line as it is found in the log file.
+  // Lines are split on the \n character and the character is included in the line content that immediately precedes it.
+  // Empty lines will be included in the response.
+  bytes content = 4;
+}
\ No newline at end of file
diff --git a/proto/resultdb/common.proto b/proto/resultdb/common.proto
new file mode 100644
index 000000000..29c252989
--- /dev/null
+++ b/proto/resultdb/common.proto
@@ -0,0 +1,170 @@
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
+syntax = "proto3";
+
+package luci.resultdb.v1;
+
+import "google/protobuf/timestamp.proto";
+
+option go_package = "go.chromium.org/luci/resultdb/proto/v1;resultpb";
+option java_package = "com.android.resultdb.proto";
+option java_multiple_files = true;
+
+// A key-value map describing one variant of a test case.
+//
+// The same test case can be executed in different ways, for example on
+// different OS, GPUs, with different compile options or runtime flags.
+// A variant definition captures one variant.
+// A test case with a specific variant definition is called test variant.
+//
+// Guidelines for variant definition design:
+// - This rule guides what keys MUST be present in the definition.
+//   A single expected result of a given test variant is enough to consider it
+//   passing (potentially flakily). If it is important to differentiate across
+//   a certain dimension (e.g. whether web tests are executed with or without
+//   site per process isolation), then there MUST be a key that captures the
+//   dimension (e.g. a name from test_suites.pyl).
+//   Otherwise, a pass in one variant will hide a failure of another one.
+//
+// - This rule guides what keys MUST NOT be present in the definition.
+//   A change in the key-value set essentially resets the test result history.
+//   For example, if GN args are among variant key-value pairs, then adding a
+//   new GN arg changes the identity of the test variant and resets its history.
+//
+// In Chromium, variant keys are:
+// - bucket: the LUCI bucket, e.g. "ci"
+// - builder: the LUCI builder, e.g. "linux-rel"
+// - test_suite: a name from
+//   https://cs.chromium.org/chromium/src/testing/buildbot/test_suites.pyl
+message Variant {
+  // The definition of the variant.
+  // Key and values must be valid StringPair keys and values, see their
+  // constraints.
+  map<string, string> def = 1;
+}
+
+// A string key-value pair. Typically used for tagging, see Invocation.tags
+message StringPair {
+  // Regex: ^[a-z][a-z0-9_]*(/[a-z][a-z0-9_]*)*$
+  // Max length: 64.
+  string key = 1;
+
+  // Max length: 256.
+  string value = 2;
+}
+
+// GitilesCommit specifies the position of the gitiles commit an invocation
+// ran against, in a repository's commit log. More specifically, a ref's commit
+// log.
+//
+// It also specifies the host/project/ref combination that the commit
+// exists in, to provide context.
+message GitilesCommit {
+  // The identity of the gitiles host, e.g. "chromium.googlesource.com".
+  // Mandatory.
+  string host = 1;
+
+  // Repository name on the host, e.g. "chromium/src". Mandatory.
+  string project = 2;
+
+  // Commit ref, e.g. "refs/heads/main" from which the commit was fetched.
+  // Not the branch name, use "refs/heads/branch"
+  // Mandatory.
+  string ref = 3;
+
+  // Commit HEX SHA1. All lowercase. Mandatory.
+  string commit_hash = 4;
+
+  // Defines a total order of commits on the ref.
+  // A positive, monotonically increasing integer. The recommended
+  // way of obtaining this is by using the goto.google.com/git-numberer
+  // Gerrit plugin. Other solutions can be used as well, so long
+  // as the same scheme is used consistently for a ref.
+  // Mandatory.
+  int64 position = 5;
+}
+
+// A Gerrit patchset.
+message GerritChange {
+  // Gerrit hostname, e.g. "chromium-review.googlesource.com".
+  string host = 1;
+  // Gerrit project, e.g. "chromium/src".
+  string project = 2;
+  // Change number, e.g. 12345.
+  int64 change = 3;
+  // Patch set number, e.g. 1.
+  int64 patchset = 4;
+}
+
+// Deprecated: Use GitilesCommit instead.
+message CommitPosition {
+  // The following fields identify a git repository and a ref within which the
+  // numerical position below identifies a single commit.
+  string host = 1;
+  string project = 2;
+  string ref = 3;
+
+  // The numerical position of the commit in the log for the host/project/ref
+  // above.
+  int64 position = 4;
+}
+
+// Deprecated: Do not use.
+message CommitPositionRange {
+  // The lowest commit position to include in the range.
+  CommitPosition earliest = 1;
+
+  // Include only commit positions that that are strictly lower than this.
+  CommitPosition latest = 2;
+}
+
+// A range of timestamps.
+//
+// Currently unused.
+message TimeRange {
+  // The oldest timestamp to include in the range.
+  google.protobuf.Timestamp earliest = 1;
+
+  // Include only timestamps that are strictly older than this.
+  google.protobuf.Timestamp latest = 2;
+}
+
+
+// Represents a reference in a source control system.
+message SourceRef {
+  // The source control system used.
+  // Only gitiles is supported at this moment. If other systems need to be
+  // supported in future (e.g. non-gitiles git, subversion, google storage
+  // buckets), they can be added here
+  oneof system {
+    // A branch in gitiles repository.
+    GitilesRef gitiles = 1;
+  }
+}
+
+// Represents a branch in a gitiles repository.
+message GitilesRef {
+  // The gitiles host, e.g. "chromium.googlesource.com".
+  string host = 1;
+
+  // The project on the gitiles host, e.g. "chromium/src".
+  string project = 2;
+
+  // Commit ref, e.g. "refs/heads/main" from which the commit was fetched.
+  // Not the branch name, use "refs/heads/branch"
+  string ref = 3;
+}
diff --git a/proto/resultdb/failure_reason.proto b/proto/resultdb/failure_reason.proto
new file mode 100644
index 000000000..a5629fe3b
--- /dev/null
+++ b/proto/resultdb/failure_reason.proto
@@ -0,0 +1,76 @@
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
+syntax = "proto3";
+
+package luci.resultdb.v1;
+
+option go_package = "go.chromium.org/luci/resultdb/proto/v1;resultpb";
+option java_package = "com.android.resultdb.proto";
+option java_multiple_files = true;
+
+// Information about why a test failed. This information may be displayed
+// to developers in result viewing UIs and will also be used to cluster
+// similar failures together.
+// For example, this will contain assertion failure messages and stack traces.
+message FailureReason {
+  // The error message that ultimately caused the test to fail. This should
+  // only be the error message and should not include any stack traces.
+  // An example would be the message from an Exception in a Java test.
+  // In the case that a test failed due to multiple expectation failures, any
+  // immediately fatal failure should be chosen, or otherwise the first
+  // expectation failure.
+  // If this field is empty, other fields (including those from the TestResult)
+  // may be used to cluster the failure instead.
+  //
+  // The size of the message must be equal to or smaller than 1024 bytes in
+  // UTF-8.
+  string primary_error_message = 1;
+
+  // Error represents a problem that caused a test to fail, such as a crash
+  // or expectation failure.
+  message Error {
+    // The error message. This should only be the error message and
+    // should not include any stack traces. An example would be the
+    // message from an Exception in a Java test.
+    //
+    // This message may be used to cluster related failures together.
+    //
+    // The size of the message must be equal to or smaller than 1024 bytes in
+    // UTF-8.
+    string message = 1;
+  }
+
+  // The error(s) that caused the test to fail.
+  //
+  // If there is more than one error (e.g. due to multiple expectation failures),
+  // a stable sorting should be used. A recommended form of stable sorting is:
+  // - Fatal errors (errors that cause the test to terminate immediately first,
+  //   then
+  // - Within fatal/non-fatal errors, sort by chronological order
+  //   (earliest error first).
+  //
+  // Where this field is populated, errors[0].message shall match
+  // primary_error_message.
+  //
+  // The total combined size of all errors (as measured by proto.Size()) must
+  // not exceed 3,172 bytes.
+  repeated Error errors = 2;
+
+  // The number of errors that are truncated from the errors list above due to
+  // the size limits.
+  int32 truncated_errors_count = 3;
+}
diff --git a/proto/resultdb/instruction.proto b/proto/resultdb/instruction.proto
new file mode 100644
index 000000000..4d5459060
--- /dev/null
+++ b/proto/resultdb/instruction.proto
@@ -0,0 +1,147 @@
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
+syntax = "proto3";
+
+package luci.resultdb.v1;
+
+option go_package = "go.chromium.org/luci/resultdb/proto/v1;resultpb";
+option java_package = "com.android.resultdb.proto";
+option java_multiple_files = true;
+
+// A collection of instructions.
+// Used for step and test result instructions.
+// Instructions may mixed between step and test instructions.
+// This has a size limit of 1MB.
+message Instructions {
+  repeated Instruction instructions = 1;
+}
+
+// Instruction is one failure reproduction instruction for a step or test result.
+// Instruction can have different targets, like "local" or "remote".
+// Instructions are stored in invocation level.
+message Instruction {
+  // ID of the instruction. Required.
+  // It is consumer-defined and is unique within the an invocation.
+  // The tuple (invocation_id, instruction_id) can uniquely identify an instruction.
+  // At this moment, we only has use cases for instruction ID for step instructions,
+  // but we also require test instruction to have ID, for possible features
+  // or enhancements in the future.
+  // Format [a-z][a-z0-9_\-:.]{0,99}
+  // Limit: 100 bytes.
+  string id = 1;
+
+  // Either step or test instruction.
+  InstructionType type = 2;
+
+  // List of instruction for different targets.
+  // There is at most 1 instruction per target.
+  // If there is more than 1, an error will be returned.
+  repeated TargetedInstruction targeted_instructions = 3;
+
+  // Specified the collection of test results that this instruction applies to.
+  // For example, we can target all test results within a child invocation.
+  // The consumer needs to make sure that any test result only has at most 1 instruction.
+  // Otherwise, the behavior is undeterministic.
+  // If no filter is applied, assume this applies to all test results contained
+  // in this invocation and included invocations.
+  // Only applicable for test instructions. This field will be ignored for step instructions.
+  InstructionFilter instruction_filter = 4;
+
+  // This is an output only field, representing the name of the instruction.
+  // Format: invocations/<invocation_id>/instructions/<instruction_id>
+  // If this field is set as input, it will be ignored.
+  string name = 5;
+
+  // The descriptive, human-readable name of the instruction.
+  // It will be showed in the dependency section in MILO.
+  // Limit: 100 bytes.
+  string descriptive_name = 6;
+}
+
+// InstructionFilter specifies the test results that this instruction applies to.
+message InstructionFilter{
+  // TODO (nqmtuan): We may support filter by invocation tags if requested.
+  oneof filter_type {
+    InstructionFilterByInvocationID invocation_ids = 1;
+  }
+}
+
+message InstructionFilterByInvocationID {
+  // Only test results contained in these invocation IDs will be selected.
+  repeated string invocation_ids = 1;
+
+  // Whether the check is recursive (i.e. whether it applies to test results
+  // in included invocation).
+  bool recursive = 2;
+}
+
+
+// Instruction for specific targets.
+// Instruction for different targets may have the same or different dependency
+// and content.
+message TargetedInstruction {
+  // The targets that this instruction is for, like "LOCAL", "REMOTE" or "PREBUILT".
+  // A targeted instruction can only depend on another instruction with the same target.
+  // For example, a "LOCAL" instruction can only depend on another "LOCAL" instruction.
+  repeated InstructionTarget targets = 1;
+
+  // Another instruction that this instruction depends on.
+  // At the moment, one instruction can have at most 1 dependency.
+  // Make this repeated for forward compatibility.
+  repeated InstructionDependency dependencies = 2;
+
+  // The content of the instruction, in markdown format.
+  // Placeholders may be used and will be populated with real
+  // information when displayed in the UI.
+  // This will be limit to 10KB. If the content is longer than 10KB,
+  // an error will be returned.
+  // See go/luci-failure-reproduction-instructions-dd for details.
+  string content = 3;
+}
+
+// Specifies a dependency for instruction.
+// An instruction being depended on needs to be step instruction, not test result instruction.
+// If the dependency cannot be found, or the user does not have the ACL,
+// the dependency chain will stop and Milo will not display the dependency.
+// If a dependency cycle is detected, we will stop showing dependency once we detected the cycle.
+message InstructionDependency {
+  // The invocation ID of the instruction being depended on.
+  // Limit: 100 bytes
+  string invocation_id = 1;
+
+  // The instruction ID of the instruction being depended on.
+  // (invocation_id, instruction_id) uniquely identify an invocation.
+  string instruction_id = 2;
+}
+
+enum InstructionTarget {
+  INSTRUCTION_TARGET_UNSPECIFIED = 0;
+  // For running in a local machine.
+  LOCAL = 1;
+  // For running remotely.
+  REMOTE = 2;
+  // For prebuilt images.
+  PREBUILT = 3;
+}
+
+enum InstructionType {
+  INSTRUCTION_TYPE_UNSPECIFIED = 0;
+  // Instruction for step.
+  STEP_INSTRUCTION = 1;
+  // Instruction for test result.
+  TEST_RESULT_INSTRUCTION = 2;
+}
diff --git a/proto/resultdb/invocation.proto b/proto/resultdb/invocation.proto
new file mode 100644
index 000000000..4d49d9c89
--- /dev/null
+++ b/proto/resultdb/invocation.proto
@@ -0,0 +1,399 @@
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
+syntax = "proto3";
+
+package luci.resultdb.v1;
+
+import "google/api/field_behavior.proto";
+import "google/protobuf/struct.proto";
+import "google/protobuf/timestamp.proto";
+import public "tools/tradefederation/core/proto/resultdb/common.proto";
+import public "tools/tradefederation/core/proto/resultdb/instruction.proto";
+import public "tools/tradefederation/core/proto/resultdb/predicate.proto";
+
+
+option go_package = "go.chromium.org/luci/resultdb/proto/v1;resultpb";
+option java_package = "com.android.resultdb.proto";
+option java_multiple_files = true;
+
+// A conceptual container of results. Immutable once finalized.
+// It represents all results of some computation; examples: swarming task,
+// buildbucket build, CQ attempt.
+// Composable: can include other invocations, see inclusion.proto.
+//
+// Next id: 25.
+message Invocation {
+  reserved 3; // bool interrupted, crbug.com/1078696.
+  reserved 17,18; // step and test instructions.
+
+  // Can be used to refer to this invocation, e.g. in ResultDB.GetInvocation
+  // RPC.
+  // Format: invocations/{INVOCATION_ID}
+  // See also https://aip.dev/122.
+  //
+  // Output only.
+  string name = 1 [
+    (google.api.field_behavior) = OUTPUT_ONLY,
+    (google.api.field_behavior) = IMMUTABLE
+  ];
+
+  enum State {
+    // The default value. This value is used if the state is omitted.
+    STATE_UNSPECIFIED = 0;
+
+    // The invocation was created and accepts new results.
+    ACTIVE = 1;
+
+    // The invocation is in the process of transitioning into FINALIZED state.
+    // This will happen automatically soon after all of its directly or
+    // indirectly included invocations become inactive.
+    FINALIZING = 2;
+
+    // The invocation is immutable and no longer accepts new results nor
+    // inclusions directly or indirectly.
+    FINALIZED = 3;
+  }
+
+  // Current state of the invocation.
+  //
+  // At creation time this can be set to FINALIZING e.g. if this invocation is
+  // a simple wrapper of another and will itself not be modified.
+  //
+  // Otherwise this is an output only field.
+  State state = 2;
+
+  // When the invocation was created.
+  // Output only.
+  google.protobuf.Timestamp create_time = 4 [
+    (google.api.field_behavior) = OUTPUT_ONLY,
+    (google.api.field_behavior) = IMMUTABLE
+  ];
+
+  // Invocation-level string key-value pairs.
+  // A key can be repeated.
+  repeated StringPair tags = 5;
+
+  // == Finalization ===========================================================
+
+  // When the invocation started to finalize, i.e. transitioned to FINALIZING
+  // state. This means the invocation is immutable but directly or indirectly
+  // included invocations may not be.
+  //
+  // Output only.
+  google.protobuf.Timestamp finalize_start_time = 19
+      [ (google.api.field_behavior) = OUTPUT_ONLY ];
+
+  // When the invocation was finalized, i.e. transitioned to FINALIZED state.
+  // If this field is set, implies that the invocation is finalized. This
+  // means the invocation and directly or indirectly included invocations
+  // are immutable.
+  //
+  // Output only.
+  google.protobuf.Timestamp finalize_time = 6
+      [ (google.api.field_behavior) = OUTPUT_ONLY ];
+
+  // Timestamp when the invocation will be forcefully finalized.
+  // Can be extended with UpdateInvocation until finalized.
+  google.protobuf.Timestamp deadline = 7;
+
+  // Names of invocations included into this one. Overall results of this
+  // invocation is a UNION of results directly included into this invocation
+  // and results from the included invocations, recursively.
+  // For example, a Buildbucket build invocation may include invocations of its
+  // child swarming tasks and represent overall result of the build,
+  // encapsulating the internal structure of the build.
+  //
+  // The graph is directed.
+  // There can be at most one edge between a given pair of invocations.
+  // The shape of the graph does not matter. What matters is only the set of
+  // reachable invocations. Thus cycles are allowed and are noop.
+  //
+  // QueryTestResults returns test results from the transitive closure of
+  // invocations.
+  //
+  // This field can be set under Recorder.CreateInvocationsRequest to include
+  // existing invocations at the moment of invocation creation.
+  // New invocations created in the same batch (via
+  // Recorder.BatchCreateInvocationsRequest) are also allowed.
+  // Otherwise, this field is to be treated as Output only.
+  //
+  // To modify included invocations, use Recorder.UpdateIncludedInvocations in
+  // all other cases.
+  repeated string included_invocations = 8;
+
+  // Whether this invocation is a root of the invocation graph for export purposes.
+  //
+  // To help downstream systems (like LUCI Analysis) make sense of test results,
+  // and gather overall context for a result, ResultDB data export is centered
+  // around export roots.
+  // The export roots typically represent a top-level buildbucket build, like a
+  // postsubmit build or presubmit tryjob. Test results are only exported if
+  // they are included from a root. They may be exported multiple times of they
+  // are included by multiple roots (e.g. in case of re-used test results).
+  // Re-used test results can be identified because the parent invocation of the
+  // test result will be the same even though the export root will be different.
+  //
+  // N.B. Export roots do not affect legacy BigQuery exports configured by the
+  // BigQueryExports field.
+  bool is_export_root = 21;
+
+  // bigquery_exports indicates what BigQuery table(s) that results in this
+  // invocation should export to.
+  //
+  // Legacy feature: Prefer to use LUCI Analysis exports instead.
+  repeated BigQueryExport bigquery_exports = 9;
+
+  // LUCI identity (e.g. "user:<email>") who created the invocation.
+  // Typically, a LUCI service account (e.g.
+  // "user:cr-buildbucket@appspot.gserviceaccount.com"), but can also be a user
+  // (e.g. "user:johndoe@example.com").
+  //
+  // Output only.
+  string created_by = 10 [ (google.api.field_behavior) = OUTPUT_ONLY ];
+
+  // Full name of the resource that produced results in this invocation.
+  // See also https://aip.dev/122#full-resource-names
+  // Typical examples:
+  // - Swarming task: "//chromium-swarm.appspot.com/tasks/deadbeef"
+  // - Buildbucket build: "//cr-buildbucket.appspot.com/builds/1234567890".
+  string producer_resource = 11;
+
+  // Realm that the invocation exists under.
+  // See https://chromium.googlesource.com/infra/luci/luci-py/+/refs/heads/master/appengine/auth_service/proto/realms_config.proto
+  string realm = 12;
+
+  // Deprecated. Values specified here are ignored.
+  HistoryOptions history_options = 13;
+
+  // Arbitrary JSON object that contains structured, domain-specific properties
+  // of the invocation.
+  //
+  // The serialized size must be <= 16 KB.
+  google.protobuf.Struct properties = 14;
+
+  // The code sources which were tested by this invocation.
+  // This is used to index test results for test history, and for
+  // related analyses (e.g. culprit analysis / changepoint analyses).
+  //
+  // The sources specified here applies only to:
+  // - the test results directly contained in this invocation, and
+  // - any directly included invocations which set their source_spec.inherit to
+  //   true.
+  //
+  // Clients should be careful to ensure the uploaded source spec is consistent
+  // between included invocations that upload the same test variants.
+  // Verdicts are associated with the sources of *any* of their constituent
+  // test results, so if there is inconsistency between included invocations,
+  // the position of the verdict becomes not well defined.
+  //
+  // Note that the sources specified here are shared with included invocations
+  // regardless of the realm of those included invocations.
+  //
+  // Attempting to update this field to a value other than its current value
+  // after is_source_spec_final is set will generate an error.
+  SourceSpec source_spec = 15;
+
+  // Whether the code sources specified by source_spec are final (immutable).
+  //
+  // To facilitate rapid export of invocations inheriting sources from this
+  // invocation, this property should be set to true as soon as possible
+  // after the invocation's sources are fixed. In most cases, clients
+  // will want to set this property to true at the same time as they set
+  // source_spec.
+  //
+  // This field is client owned. Consistent with https://google.aip.dev/129,
+  // it will not be forced to true when the invocation starts to finalize, even
+  // if its effective value will always be true at that point.
+  bool is_source_spec_final = 20;
+
+  // A user-specified baseline identifier that maps to a set of test variants.
+  // Often, this will be the source that generated the test result, such as the
+  // builder name for Chromium. For example, the baseline identifier may be
+  // try:linux-rel. The supported syntax for a baseline identifier is
+  // ^[a-z0-9\-_.]{1,100}:[a-zA-Z0-9\-_.\(\) ]{1,128}`$. This syntax was selected
+  // to allow <buildbucket bucket name>:<buildbucket builder name> as a valid
+  // baseline ID.
+  // See go/src/go.chromium.org/luci/buildbucket/proto/builder_common.proto for
+  // character lengths for buildbucket bucket name and builder name.
+  //
+  // Baselines are used to identify new tests; a subtraction between the set of
+  // test variants for a baseline in the Baselines table and test variants from
+  // a given invocation determines whether a test is new.
+  //
+  // The caller must have `resultdb.baselines.put` to be able to
+  // modify this field.
+  string baseline_id = 16;
+
+  // Instructions for the steps and test results in this invocation.
+  // It may also contain instructions for test results in included invocations.
+  Instructions instructions = 23;
+
+  // Union of all variants of test results directly included by the invocation.
+  // This field will be populated by ResultDB during test result creation time.
+  Variant TestResultVariantUnion = 24 [ (google.api.field_behavior) = OUTPUT_ONLY ];
+
+  // Additional JSON object(s) that contain additional structured data about the
+  // invocation. Unlike `properties` this field is not included (denormalized)
+  // in the test results export, it is only available in the finalized
+  // invocations BigQuery export.
+  //
+  // All google.protobuf.Struct values must contain a field '@type' which is
+  // a URL/resource name that uniquely identifies the type of the source
+  // protocol buffer message. This string must contain at least
+  // one "/" character. The last segment of the URL's path must represent the
+  // fully qualified name of the type (e.g. foo.com/x/some.package.MyMessage)
+  //
+  // ResultDB will not validate the contents with respect to this schema, but
+  // downstream systems may depend on the '@type' field to inform how the
+  // contents are interpreted.
+  //
+  // Each key is limited to 63 characters matching
+  // ^[a-z]([a-z0-9_]{0,61}[a-z0-9])?$.
+  // The size of each value is limited to <= 20,000 bytes.
+  // The total size of the map (as measured by proto.Size())
+  // is limited to <= 100,000 bytes.
+  //
+  // The following paths can be used for field masks:
+  // * "extended_properties" to target the whole extended_properties,
+  // * "extended_properties.some_key" to target one key of extended_properties.
+  map<string, google.protobuf.Struct> extended_properties = 22;
+}
+
+// BigQueryExport indicates that results in this invocation should be exported
+// to BigQuery after finalization.
+message BigQueryExport {
+  // Name of the BigQuery project.
+  string project = 1 [ (google.api.field_behavior) = REQUIRED ];
+
+  // Name of the BigQuery Dataset.
+  string dataset = 2 [ (google.api.field_behavior) = REQUIRED ];
+
+  // Name of the BigQuery Table.
+  string table = 3 [ (google.api.field_behavior) = REQUIRED ];
+
+  // TestResults indicates that test results should be exported.
+  message TestResults {
+    // Use predicate to query test results that should be exported to
+    // BigQuery table.
+    TestResultPredicate predicate = 1;
+  }
+
+  // TextArtifacts indicates that text artifacts should be exported.
+  message TextArtifacts {
+    // Use predicate to query artifacts that should be exported to
+    // BigQuery table.
+    //
+    // Sub-field predicate.content_type_regexp defaults to "text/.*".
+    ArtifactPredicate predicate = 1;
+  }
+
+  oneof result_type {
+    TestResults test_results = 4;
+    TextArtifacts text_artifacts = 6;
+  }
+}
+
+// HistoryOptions indicates how the invocations should be indexed, so that their
+// results can be queried over a range of time or of commits.
+// Deprecated: do not use.
+message HistoryOptions {
+  // Set this to index the results by the containing invocation's create_time.
+  bool use_invocation_timestamp = 1;
+
+  // Set this to index by commit position.
+  // It's up to the creator of the invocation to set this consistently over
+  // time across the same test variant.
+  CommitPosition commit = 2;
+}
+
+// Specifies the source code that was tested in an invocation, either directly
+// (via the sources field) or indirectly (via inherit_sources).
+message SourceSpec {
+   // Specifies the source position that was tested.
+   // Either this or inherit_sources may be set, but not both.
+   Sources sources = 1;
+
+   // Specifies that the source position of the invocation is inherited
+   // from the parent invocation it is included in.
+   //
+   // # Use case
+   // This is useful in situations where the testing infrastructure deduplicates
+   // execution of tests on identical binaries (e.g. using swarming's task
+   // deduplication feature).
+   //
+   // Let A be the invocation for a swarming task that receives only a
+   // test binary as input, with task deduplication enabled.
+   // Let B be the invocation for a buildbucket build which built the
+   // binary from sources (or at the very least knew the sources)
+   // and triggered invocation A.
+   // Invocation B includes invocation A.
+   //
+   // By setting A's source_spec to inherit, and specifying the sources
+   // on invocation B, the test results in A will be associated with
+   // the sources specified on invocation B, when queried via invocation B.
+   //
+   // This allows further invocations B2, B3 ... BN to be created which also
+   // re-use the test results in A but associate them with possibly different
+   // sources when queried via B2 ... BN (this is valid so long as the sources
+   // produce a binary-identical testing input).
+   //
+   // # Multiple inclusion paths
+   // It is possible for an invocation A to be included in the reachable
+   // invocation graph for an invocation C in more than one way.
+   //
+   // For example, we may have:
+   //   A -> B1 -> C
+   //   A -> B2 -> C
+   // as two paths of inclusion.
+   //
+   // If A sets inherit to true, the commit position assigned to its
+   // test results will be selected via *one* of the paths of inclusion
+   // into C (i.e. from B1 or B2).
+   //
+   // However, which path is selected is not guaranteed, so if clients
+   // must include the same invocation multiple times, they should
+   // make the source position via all paths the same.
+   bool inherit = 2;
+}
+
+// Specifies the source code that was tested.
+message Sources {
+    // The base version of code sources checked out. Mandatory.
+    // If necessary, we could add support for non-gitiles sources here in
+    // future, using a oneof statement. E.g.
+    // oneof system {
+    //    GitilesCommit gitiles_commit = 1;
+    //    SubversionRevision svn_revision = 4;
+    //    ...
+    // }
+    GitilesCommit gitiles_commit = 1;
+
+    // The changelist(s) which were applied upon the base version of sources
+    // checked out. E.g. in commit queue tryjobs.
+    //
+    // At most 10 changelist(s) may be specified here. If there
+    // are more, only include the first 10 and set is_dirty.
+    repeated GerritChange changelists = 2;
+
+    // Whether there were any changes made to the sources, not described above.
+    // For example, a version of a dependency was upgraded before testing (e.g.
+    // in an autoroller recipe).
+    //
+    // Cherry-picking a changelist on top of the base checkout is not considered
+    // making the sources dirty as it is reported separately above.
+    bool is_dirty = 3;
+}
diff --git a/proto/resultdb/predicate.proto b/proto/resultdb/predicate.proto
new file mode 100644
index 000000000..96525ce66
--- /dev/null
+++ b/proto/resultdb/predicate.proto
@@ -0,0 +1,138 @@
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
+syntax = "proto3";
+
+package luci.resultdb.v1;
+
+import public "tools/tradefederation/core/proto/resultdb/common.proto";
+
+option go_package = "go.chromium.org/luci/resultdb/proto/v1;resultpb";
+option java_package = "com.android.resultdb.proto";
+option java_multiple_files = true;
+
+// Represents a function TestResult -> bool.
+// Empty message matches all test results.
+//
+// Most clients would want to set expected_results to
+// VARIANTS_WITH_UNEXPECTED_RESULTS.
+message TestResultPredicate {
+  // A test result must have a test id matching this regular expression
+  // entirely, i.e. the expression is implicitly wrapped with ^ and $.
+  string test_id_regexp = 1;
+
+  // A test result must have a variant satisfying this predicate.
+  VariantPredicate variant = 2;
+
+  // Filters test results based on TestResult.expected field.
+  enum Expectancy {
+    // All test results satisfy this.
+    // WARNING: using this significantly increases response size and latency.
+    ALL = 0;
+
+    // A test result must belong to a test variant that has one or more
+    // unexpected results. It can be used to fetch both unexpected and flakily
+    // expected results.
+    //
+    // Note that the predicate is defined at the test variant level.
+    // For example, if a test variant expects a PASS and has results
+    // [FAIL, FAIL, PASS], then all results satisfy the predicate because
+    // the variant satisfies the predicate.
+    VARIANTS_WITH_UNEXPECTED_RESULTS = 1;
+
+    // Similar to VARIANTS_WITH_UNEXPECTED_RESULTS, but the test variant
+    // must not have any expected results.
+    VARIANTS_WITH_ONLY_UNEXPECTED_RESULTS = 2;
+  }
+
+  // A test result must match this predicate based on TestResult.expected field.
+  // Most clients would want to override this field because the default
+  // typically causes a large response size.
+  Expectancy expectancy = 3;
+
+  // If true, filter out exonerated test variants.
+  // Mutually exclusive with Expectancy.ALL.
+  //
+  // If false, the filter is NOT applied.
+  // That is, the test result may or may not be exonerated.
+  bool exclude_exonerated = 4;
+}
+
+// Represents a function TestExoneration -> bool.
+// Empty message matches all test exonerations.
+message TestExonerationPredicate {
+  // A test exoneration must have a test id matching this regular expression
+  // entirely, i.e. the expression is implicitly wrapped with ^ and $.
+  string test_id_regexp = 1;
+
+  // A test exoneration must have a variant satisfying this predicate.
+  VariantPredicate variant = 2;
+}
+
+// Represents a function Variant -> bool.
+message VariantPredicate {
+  oneof predicate {
+    // A variant must be equal this definition exactly.
+    Variant equals = 1;
+
+    // A variant's key-value pairs must contain those in this one.
+    Variant contains = 2;
+  }
+}
+
+// Represents a function Artifact -> bool.
+message ArtifactPredicate {
+  // A set of Invocation's outgoing edge types.
+  message EdgeTypeSet {
+    // The edges represented by Invocation.included_invocations field.
+    bool included_invocations = 1;
+    // The parent-child relationship between Invocation and TestResult.
+    bool test_results = 2;
+  }
+
+  // Specifies which edges to follow when retrieving directly/indirectly
+  // included artifacts.
+  // For example,
+  // - to retrieve only invocation-level artifacts, use
+  //   {included_invocations: true}.
+  // - to retrieve only test-result-level artifacts, use {test_results: true}.
+  //
+  // By default, follows all edges.
+  EdgeTypeSet follow_edges = 1; // defaults to All.
+
+  // If an Artifact belongs to a TestResult, then the test result must satisfy
+  // this predicate.
+  // Note: this predicate does NOT apply to invocation-level artifacts.
+  // To exclude them from the response, use follow_edges.
+  TestResultPredicate test_result_predicate = 2;
+
+  // An artifact must have a content type matching this regular expression
+  // entirely, i.e. the expression is implicitly wrapped with ^ and $.
+  // Defaults to ".*".
+  string content_type_regexp = 3;
+
+  // An artifact must have an ID matching this regular expression entirely, i.e.
+  // the expression is implicitly wrapped with ^ and $.  Defaults to ".*".
+  string artifact_id_regexp = 4;
+}
+
+
+// Represents a function TestMetadata -> bool.
+// Empty message matches all test metadata.
+message TestMetadataPredicate {
+  // A test metadata must have the test id in this list.
+  repeated string test_ids = 1;
+}
diff --git a/proto/resultdb/recorder.proto b/proto/resultdb/recorder.proto
new file mode 100644
index 000000000..7ae42fb90
--- /dev/null
+++ b/proto/resultdb/recorder.proto
@@ -0,0 +1,326 @@
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
+syntax = "proto3";
+
+package luci.resultdb.v1;
+
+import "google/api/field_behavior.proto";
+import "google/protobuf/empty.proto";
+import "google/protobuf/field_mask.proto";
+
+import public "tools/tradefederation/core/proto/resultdb/invocation.proto";
+import public "tools/tradefederation/core/proto/resultdb/artifact.proto";
+import public "tools/tradefederation/core/proto/resultdb/test_result.proto";
+
+option go_package = "go.chromium.org/luci/resultdb/proto/v1;resultpb";
+option java_package = "com.android.resultdb.proto";
+option java_multiple_files = true;
+option java_generic_services = true;
+
+// Service to record test results.
+//
+// CreateInvocation response includes a metadata key "update-token".
+// It MUST be passed to all other mutation RPCs, such as CreateTestResult.
+// Otherwise the request will fail with UNAUTHENTICATED error code.
+//
+// RPCs that mutate an invocation return FAILED_PRECONDITION error code if the
+// invocation is finalized.
+service Recorder {
+
+  // == Invocations ============================================================
+
+  // Creates a new invocation.
+  // The request specifies the invocation id and its contents.
+  //
+  // The response header metadata contains "update-token" required for future
+  // updates, including finalization.
+  //
+  // If invocation with the given ID already exists, returns ALREADY_EXISTS
+  // error code.
+  rpc CreateInvocation(CreateInvocationRequest) returns (Invocation) {};
+
+  // Creates multiple invocations in a single rpc.
+  //
+  // The response header metadata contains a multi-valued "update-token"
+  // required for future updates, including finalization. The tokens will be
+  // given in the same order as BatchCreateInvocationRequest.requests.
+  rpc BatchCreateInvocations(BatchCreateInvocationsRequest)
+      returns (BatchCreateInvocationsResponse) {};
+
+  // Updates an existing non-finalized invocation.
+  rpc UpdateInvocation(UpdateInvocationRequest) returns (Invocation) {};
+
+  // Transitions the given invocation to the state FINALIZED.
+  rpc FinalizeInvocation(FinalizeInvocationRequest) returns (Invocation) {};
+
+  // Updates inclusions for a non-finalized invocation.
+  rpc UpdateIncludedInvocations(UpdateIncludedInvocationsRequest)
+      returns (google.protobuf.Empty) {};
+
+  // Recursively marks all test variants associated with the invocation as
+  // submitted, merging them into the invocation's associated baseline.
+  rpc MarkInvocationSubmitted(MarkInvocationSubmittedRequest)
+      returns (google.protobuf.Empty) {};
+
+  // == Test results ===========================================================
+
+  // Appends a test result to a non-finalized invocation.
+  rpc CreateTestResult(CreateTestResultRequest) returns (TestResult) {};
+  // Atomically appends a batch of test results to a non-finalized invocation.
+  rpc BatchCreateTestResults(BatchCreateTestResultsRequest)
+      returns (BatchCreateTestResultsResponse) {};
+
+  // Appends a test exoneration to a non-finalized invocation.
+  rpc CreateTestExoneration(CreateTestExonerationRequest)
+      returns (TestExoneration) {};
+  // Atomically appends a batch of test exonerations to a non-finalized
+  // invocation.
+  rpc BatchCreateTestExonerations(BatchCreateTestExonerationsRequest)
+      returns (BatchCreateTestExonerationsResponse) {};
+
+  // == Artifacts ==============================================================
+
+  // Create multiple artifacts.
+  //
+  // An artifact can be either invocation-level or test-result-level.
+  // See Artifact.name for more info.
+  rpc BatchCreateArtifacts(BatchCreateArtifactsRequest)
+      returns (BatchCreateArtifactsResponse) {};
+}
+
+// == Invocations ==============================================================
+
+// A request message for CreateInvocation.
+message CreateInvocationRequest {
+  // Invocation identifier, becomes a part of the invocation.name.
+  // LUCI systems MAY create invocations with nicely formatted IDs, such as
+  // "build-1234567890". All other clients MUST use GUIDs.
+  //
+  // Regex: ^[a-z][a-z0-9_\-]*$.
+  string invocation_id = 1 [ (google.api.field_behavior) = REQUIRED ];
+
+  // Invocation data to insert.
+  Invocation invocation = 2;
+
+  // A unique identifier for this request. Restricted to 36 ASCII characters.
+  // A random UUID is recommended.
+  // This request is only idempotent if a `request_id` is provided.
+  string request_id = 3;
+}
+
+// A request message for BatchCreateInvocations
+message BatchCreateInvocationsRequest {
+  // requests[i].request_id MUST be either empty or equal to request_id in
+  // this message.
+  //
+  // Up to 500 requests.
+  repeated CreateInvocationRequest requests = 1;
+
+  // A unique identifier for this request. Restricted to 36 ASCII characters.
+  // A random UUID is recommended.
+  // This request is only idempotent if a `request_id` is provided, so it is
+  // strongly recommended to populate this field.
+  string request_id = 2;
+}
+
+
+// A response message for BatchCreateInvocations RPC.
+message BatchCreateInvocationsResponse {
+  // Invocations created.
+  repeated Invocation invocations = 1;
+
+  // One token per each created invocation.
+  // These are passed in the response instead of as metadata, because large
+  // batches increase the size of the response headers beyond allowed limits and
+  // cause failures like crbug.com/1064496
+  // update_tokens[i] corresponds to invocations[i].
+  // *Do not log these values*.
+  repeated string update_tokens = 2;
+}
+
+
+// A request message for UpdateInvocation RPC.
+message UpdateInvocationRequest {
+  // Invocation to update.
+  Invocation invocation = 1 [ (google.api.field_behavior) = REQUIRED ];
+
+  // The list of fields to be updated.
+  google.protobuf.FieldMask update_mask = 2;
+}
+
+// A request message for FinalizeInvocation RPC.
+message FinalizeInvocationRequest {
+  // Name of the invocation to finalize.
+  string name = 1 [ (google.api.field_behavior) = REQUIRED ];
+}
+
+// A request message for UpdateIncludedInvocations RPC.
+message UpdateIncludedInvocationsRequest {
+  // Name of the invocation to add/remove inclusions to/from,
+  // see Invocation.name.
+  // For example, name of the buildbucket build invocation that should include
+  // a swarming task invocation.
+  string including_invocation = 1 [ (google.api.field_behavior) = REQUIRED ];
+
+  // Names of the invocations to include, see Invocation.name.
+  // If any of these invocations are already included, they will be silently
+  // ignored for idempotency.
+  repeated string add_invocations = 2;
+
+  // Deprecated: Removing invocations is no longer supported. Do not use.
+  repeated string remove_invocations = 3;
+}
+
+// A request message for MarkInvocationSubmitted RPC.
+// To use this RPC, callers need:
+// - resultdb.invocations.setSubmitted in the realm the <project>:@project, where
+//   project is the project of the nominated invocation.
+message MarkInvocationSubmittedRequest {
+  // Name of the invocation, e.g. "invocations/{id}".
+  string invocation = 1 [ (google.api.field_behavior) = REQUIRED ];
+}
+
+
+// A request message for CreateTestResult RPC.
+message CreateTestResultRequest {
+  // Name of the parent invocation, see Invocation.name.
+  string invocation = 1 [ (google.api.field_behavior) = REQUIRED ];
+
+  // The test result to create.
+  // Test id and result id are used to dedupe requests, i.e.
+  // if a test result with the same test id and result id already exists in
+  // the invocation, then the requests succeeds as opposed to returns with
+  // ALREADY_EXISTS error.
+  TestResult test_result = 2 [ (google.api.field_behavior) = REQUIRED ];
+
+  // A unique identifier for this request. Restricted to 36 ASCII characters.
+  // A random UUID is recommended.
+  // This request is only idempotent if a `request_id` is provided, so it is
+  // strongly recommended to populate this field.
+  //
+  // Impl note: this field is used to compute the spanner-level result id, which
+  // will encode tuple (request_id, index_of_request)", where
+  // - request_id is a random GUID if not provided by the user
+  // - index_of_request is 0 in CreateTestResult RPC, or index of the request
+  //   in BatchCreateTestResultsRequest in the batch RPC.
+  // TODO(jchinlee): remove this impl note when it is converted into code.
+  string request_id = 3;
+}
+
+// == Test results =============================================================
+
+// A request message for BatchCreateTestResults RPC.
+message BatchCreateTestResultsRequest {
+  // Name of the parent invocation, see Invocation.name.
+  string invocation = 1 [ (google.api.field_behavior) = REQUIRED ];
+
+  // Requests to create test results.
+  // requests[i].invocation MUST be either empty or equal to invocation in this
+  // message.
+  // requests[i].request_id MUST be either empty or equal to request_id in
+  // this message.
+  //
+  // Up to 500 requests.
+  repeated CreateTestResultRequest requests = 2;
+
+  // A unique identifier for this request. Restricted to 36 ASCII characters.
+  // A random UUID is recommended.
+  // This request is only idempotent if a `request_id` is provided, so it is
+  // strongly recommended to populate this field.
+  //
+  string request_id = 3;
+}
+
+// A response message for BatchCreateTestResults RPC.
+message BatchCreateTestResultsResponse {
+  // Test results created.
+  repeated TestResult test_results = 1;
+}
+
+// A request message for CreateTestExoneration RPC.
+message CreateTestExonerationRequest {
+  // Name of the parent invocation, see Invocation.name.
+  string invocation = 1 [ (google.api.field_behavior) = REQUIRED ];
+
+  // The TestExoneration to create.
+  TestExoneration test_exoneration = 2
+      [ (google.api.field_behavior) = REQUIRED ];
+
+  // A unique identifier for this request. Restricted to 36 ASCII characters.
+  // A random UUID is recommended.
+  // This request is only idempotent if a `request_id` is provided.
+  string request_id = 3;
+}
+
+// A request message for BatchCreateTestExonerations RPC.
+message BatchCreateTestExonerationsRequest {
+  // Name of the parent invocation, see Invocation.name.
+  string invocation = 1 [ (google.api.field_behavior) = REQUIRED ];
+
+  // Requests to create TestExonerations.
+  // requests[i].invocation MUST be either empty or equal to invocation in this
+  // message.
+  // requests[i].request_id MUST be either empty or equal to request_id in
+  // this message.
+  //
+  // Up to 500 requests.
+  repeated CreateTestExonerationRequest requests = 2;
+
+  // A unique identifier for this request. Restricted to 36 ASCII characters.
+  // A random UUID is recommended.
+  // This request is only idempotent if a `request_id` is provided, so it is
+  // strongly recommended to populate this field.
+  string request_id = 3;
+}
+
+// A response message for BatchCreateTestExonerations RPC.
+message BatchCreateTestExonerationsResponse {
+  // Test exonerations created.
+  repeated TestExoneration test_exonerations = 1;
+}
+
+// == Artifacts ================================================================
+
+// A request message for CreateArtifactRequest.
+message CreateArtifactRequest {
+  // Name of the parent resource where the artifact will be created.
+  //
+  // For invocation-level artifacts, it is the invocation name.
+  // For test-result-level artifacts, it is the TestResult name.
+  string parent = 1 [ (google.api.field_behavior) = REQUIRED ];
+
+  // Artifact to upload.
+  // The length of the artifact contents MUST be <= 512KiB.
+  // artifact.artifact_id MUST be set.
+  // artifact.name will be ignored.
+  Artifact artifact = 2 [ (google.api.field_behavior) = REQUIRED ];
+}
+
+// A request message for BatchCreateArtifactsRequest.
+message BatchCreateArtifactsRequest {
+  // Requests to create Artifacts.
+  // The sum of the content lengths MUST be <= 10MiB.
+  // The parents of all the requests must be derived from the same invocation.
+  //
+  // Up to 500 requests.
+  repeated CreateArtifactRequest requests = 2;
+}
+
+message BatchCreateArtifactsResponse {
+  // Artifacts created.
+  repeated Artifact artifacts = 1;
+}
diff --git a/proto/resultdb/test_metadata.proto b/proto/resultdb/test_metadata.proto
new file mode 100644
index 000000000..f1015e258
--- /dev/null
+++ b/proto/resultdb/test_metadata.proto
@@ -0,0 +1,136 @@
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
+syntax = "proto3";
+
+package luci.resultdb.v1;
+
+import "google/protobuf/struct.proto";
+import "google/api/field_behavior.proto";
+import public "tools/tradefederation/core/proto/resultdb/common.proto";
+
+option go_package = "go.chromium.org/luci/resultdb/proto/v1;resultpb";
+option java_package = "com.android.resultdb.proto";
+option java_multiple_files = true;
+
+// Information about a test metadata.
+message TestMetadataDetail {
+  // Can be used to refer to a test metadata, e.g. in ResultDB.QueryTestMetadata
+  // RPC.
+  // Format:
+  // "projects/{PROJECT}/refs/{REF_HASH}/tests/{URL_ESCAPED_TEST_ID}".
+  // where URL_ESCAPED_TEST_ID is test_id escaped with
+  // https://golang.org/pkg/net/url/#PathEscape. See also https://aip.dev/122.
+  //
+  // Output only.
+  string name = 1 [(google.api.field_behavior) = OUTPUT_ONLY];
+
+  // The LUCI project.
+  string project = 2;
+
+  // A unique identifier of a test in a LUCI project.
+  // Refer to TestResult.test_id for details.
+  string test_id = 3;
+
+  // Hexadecimal encoded hash string of the source_ref.
+  // A given source_ref always hashes to the same ref_hash value.
+  string ref_hash = 12;
+
+  // A reference in the source control system where the test metadata comes from.
+  SourceRef source_ref = 4;
+
+  // Test metadata content.
+  TestMetadata testMetadata = 5;
+}
+
+// Information about a test.
+message TestMetadata {
+  // The original test name.
+  string name = 1;
+
+  // Where the test is defined, e.g. the file name.
+  // location.repo MUST be specified.
+  TestLocation location = 2;
+
+  // The issue tracker component associated with the test, if any.
+  // Bugs related to the test may be filed here.
+  BugComponent bug_component = 3;
+
+  // Identifies the schema of the JSON object in the properties field.
+  // Use the fully-qualified name of the source protocol buffer.
+  // eg. chromiumos.test.api.TestCaseInfo
+  // ResultDB will *not* validate the properties field with respect to this
+  // schema. Downstream systems may however use this field to inform how the
+  // properties field is interpreted.
+  string properties_schema = 4;
+
+  // Arbitrary JSON object that contains structured, domain-specific properties
+  // of the test.
+  //
+  // The serialized size must be <= 4096 bytes.
+  //
+  // If this field is specified, properties_schema must also be specified.
+  google.protobuf.Struct properties = 5;
+}
+
+// Location of the test definition.
+message TestLocation {
+  // Gitiles URL as the identifier for a repo.
+  // Format for Gitiles URL: https://<host>/<project>
+  // For example "https://chromium.googlesource.com/chromium/src"
+  // Must not end with ".git".
+  // SHOULD be specified.
+  string repo = 1;
+
+  // Name of the file where the test is defined.
+  // For files in a repository, must start with "//"
+  // Example: "//components/payments/core/payment_request_data_util_unittest.cc"
+  // Max length: 512.
+  // MUST not use backslashes.
+  // Required.
+  string file_name = 2;
+
+  // One-based line number where the test is defined.
+  int32 line = 3;
+}
+
+// Represents a component in an issue tracker. A component is
+// a container for issues.
+message BugComponent {
+  oneof system {
+     // The Google Issue Tracker component.
+     IssueTrackerComponent issue_tracker = 1;
+
+     // The monorail component.
+     MonorailComponent monorail = 2;
+  }
+}
+
+// A component in Google Issue Tracker, sometimes known as Buganizer,
+// available at https://issuetracker.google.com.
+message IssueTrackerComponent {
+  // The Google Issue Tracker component ID.
+  int64 component_id = 1;
+}
+
+// A component in monorail issue tracker, available at
+// https://bugs.chromium.org.
+message MonorailComponent {
+  // The monorail project name.
+  string project = 1;
+  // The monorail component value. E.g. "Blink>Accessibility".
+  string value = 2;
+}
diff --git a/proto/resultdb/test_result.proto b/proto/resultdb/test_result.proto
new file mode 100644
index 000000000..a81581628
--- /dev/null
+++ b/proto/resultdb/test_result.proto
@@ -0,0 +1,320 @@
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
+syntax = "proto3";
+
+package luci.resultdb.v1;
+
+import "google/api/field_behavior.proto";
+import "google/protobuf/duration.proto";
+import "google/protobuf/struct.proto";
+import "google/protobuf/timestamp.proto";
+import public "tools/tradefederation/core/proto/resultdb/common.proto";
+import public "tools/tradefederation/core/proto/resultdb/test_metadata.proto";
+import public "tools/tradefederation/core/proto/resultdb/failure_reason.proto";
+
+option go_package = "go.chromium.org/luci/resultdb/proto/v1;resultpb";
+option java_package = "com.android.resultdb.proto";
+option java_multiple_files = true;
+
+// A result of a functional test case.
+// Often a single test case is executed multiple times and has multiple results,
+// a single test suite has multiple test cases,
+// and the same test suite can be executed in different variants
+// (OS, GPU, compile flags, etc).
+//
+// This message does not specify the test id.
+// It should be available in the message that embeds this message.
+//
+// Next id: 17.
+message TestResult {
+  reserved 11;  // test_location
+
+  // Can be used to refer to this test result, e.g. in ResultDB.GetTestResult
+  // RPC.
+  // Format:
+  // "invocations/{INVOCATION_ID}/tests/{URL_ESCAPED_TEST_ID}/results/{RESULT_ID}".
+  // where URL_ESCAPED_TEST_ID is test_id escaped with
+  // https://golang.org/pkg/net/url/#PathEscape See also https://aip.dev/122.
+  //
+  // Output only.
+  string name = 1 [
+    (google.api.field_behavior) = OUTPUT_ONLY,
+    (google.api.field_behavior) = IMMUTABLE
+  ];
+
+  // Test id, a unique identifier of the test in a LUCI project.
+  // Regex: ^[[::print::]]{1,512}$
+  //
+  // If two tests have a common test id prefix that ends with a
+  // non-alphanumeric character, they considered a part of a group. Examples:
+  // - "a/b/c"
+  // - "a/b/d"
+  // - "a/b/e:x"
+  // - "a/b/e:y"
+  // - "a/f"
+  // This defines the following groups:
+  // - All items belong to one group because of the common prefix "a/"
+  // - Within that group, the first 4 form a sub-group because of the common
+  //   prefix "a/b/"
+  // - Within that group, "a/b/e:x" and "a/b/e:y" form a sub-group because of
+  //   the common prefix "a/b/e:".
+  // This can be used in UI.
+  // LUCI does not interpret test ids in any other way.
+  string test_id = 2 [(google.api.field_behavior) = IMMUTABLE];
+
+  // Identifies a test result in a given invocation and test id.
+  // Regex: ^[a-z0-9\-_.]{1,32}$
+  string result_id = 3 [
+    (google.api.field_behavior) = IMMUTABLE,
+    (google.api.field_behavior) = REQUIRED
+  ];
+
+  // Description of one specific way of running the test,
+  // e.g. a specific bucket, builder and a test suite.
+  Variant variant = 4 [(google.api.field_behavior) = IMMUTABLE];
+
+  // Whether the result of test case execution is expected.
+  // In a typical Chromium CL, 99%+ of test results are expected.
+  // Users are typically interested only in the unexpected results.
+  //
+  // An unexpected result != test case failure. There are test cases that are
+  // expected to fail/skip/crash. The test harness compares the actual status
+  // with the expected one(s) and this field is the result of the comparison.
+  bool expected = 5 [(google.api.field_behavior) = IMMUTABLE];
+
+  // Machine-readable status of the test case.
+  // MUST NOT be STATUS_UNSPECIFIED.
+  TestStatus status = 6 [(google.api.field_behavior) = IMMUTABLE];
+
+  // Human-readable explanation of the result, in HTML.
+  // MUST be sanitized before rendering in the browser.
+  //
+  // The size of the summary must be equal to or smaller than 4096 bytes in
+  // UTF-8.
+  //
+  // Supports artifact embedding using custom tags:
+  // * <text-artifact> renders contents of an artifact as text.
+  //   Usage:
+  //   * To embed result level artifact: <text-artifact
+  //   artifact-id="<artifact_id>">
+  //   * To embed invocation level artifact: <text-artifact
+  //   artifact-id="<artifact_id>" inv-level>
+  string summary_html = 7 [(google.api.field_behavior) = IMMUTABLE];
+
+  // The point in time when the test case started to execute.
+  google.protobuf.Timestamp start_time = 8
+      [(google.api.field_behavior) = IMMUTABLE];
+
+  // Duration of the test case execution.
+  // MUST be equal to or greater than 0.
+  google.protobuf.Duration duration = 9
+      [(google.api.field_behavior) = IMMUTABLE];
+
+  // Metadata for this test result.
+  // It might describe this particular execution or the test case.
+  // A key can be repeated.
+  repeated StringPair tags = 10 [(google.api.field_behavior) = IMMUTABLE];
+
+  // Hash of the variant.
+  // hex(sha256(sorted(''.join('%s:%s\n' for k, v in variant.items())))).
+  //
+  // Output only.
+  string variant_hash = 12 [
+    (google.api.field_behavior) = OUTPUT_ONLY,
+    (google.api.field_behavior) = IMMUTABLE
+  ];
+
+  // Information about the test at the time of its execution.
+  TestMetadata test_metadata = 13;
+
+  // Information about the test failure. Only present if the test failed.
+  FailureReason failure_reason = 14;
+
+  // Arbitrary JSON object that contains structured, domain-specific properties
+  // of the test result.
+  //
+  // The serialized size must be <= 8 KB.
+  google.protobuf.Struct properties = 15;
+
+  // Whether the test result has been masked so that it includes only metadata.
+  // The metadata fields for a TestResult are:
+  // * name
+  // * test_id
+  // * result_id
+  // * expected
+  // * status
+  // * start_time
+  // * duration
+  // * variant_hash
+  // * failure_reason.primary_error_message (truncated to 140 characters)
+  // * skip_reason
+  //
+  // Output only.
+  bool is_masked = 16 [(google.api.field_behavior) = OUTPUT_ONLY];
+
+  // Reasoning behind a test skip, in machine-readable form.
+  // Used to assist downstream analyses, such as automatic bug-filing.
+  // MUST not be set unless status is SKIP.
+  SkipReason skip_reason = 18;
+}
+
+// Machine-readable status of a test result.
+enum TestStatus {
+  // Status was not specified.
+  // Not to be used in actual test results; serves as a default value for an
+  // unset field.
+  STATUS_UNSPECIFIED = 0;
+
+  // The test case has passed.
+  PASS = 1;
+
+  // The test case has failed.
+  // Suggests that the code under test is incorrect, but it is also possible
+  // that the test is incorrect or it is a flake.
+  FAIL = 2;
+
+  // The test case has crashed during execution.
+  // The outcome is inconclusive: the code under test might or might not be
+  // correct, but the test+code is incorrect.
+  CRASH = 3;
+
+  // The test case has started, but was aborted before finishing.
+  // A common reason: timeout.
+  ABORT = 4;
+
+  // The test case did not execute.
+  // Examples:
+  // - The execution of the collection of test cases, such as a test
+  //   binary, was aborted prematurely and execution of some test cases was
+  //   skipped.
+  // - The test harness configuration specified that the test case MUST be
+  //   skipped.
+  SKIP = 5;
+}
+
+// Machine-readable reason that a test execution was skipped.
+// Only reasons actually used are listed here, if you need a new reason
+// please add it here and send a CL to the OWNERS.
+enum SkipReason {
+  // Skip reason was not specified.
+  // This represents an unset field which should be used for non-skip test
+  // result statuses.  It can also be used if none of the other statuses
+  // apply.
+  SKIP_REASON_UNSPECIFIED = 0;
+
+  // Disabled automatically in response to a test skipping policy that skips
+  // flaky tests.
+  // Used for ChromeOS CQ test filtering.
+  AUTOMATICALLY_DISABLED_FOR_FLAKINESS = 1;
+}
+
+// Indicates the test subject (e.g. a CL) is absolved from blame
+// for an unexpected result of a test variant.
+// For example, the test variant fails both with and without CL, so it is not
+// CL's fault.
+message TestExoneration {
+  // Can be used to refer to this test exoneration, e.g. in
+  // ResultDB.GetTestExoneration RPC.
+  // Format:
+  // invocations/{INVOCATION_ID}/tests/{URL_ESCAPED_TEST_ID}/exonerations/{EXONERATION_ID}.
+  // URL_ESCAPED_TEST_ID is test_variant.test_id escaped with
+  // https://golang.org/pkg/net/url/#PathEscape See also https://aip.dev/122.
+  //
+  // Output only.
+  string name = 1 [
+    (google.api.field_behavior) = OUTPUT_ONLY,
+    (google.api.field_behavior) = IMMUTABLE
+  ];
+
+  // Test identifier, see TestResult.test_id.
+  string test_id = 2;
+
+  // Description of the variant of the test, see Variant type.
+  // Unlike TestResult.extra_variant_pairs, this one must be a full definition
+  // of the variant, i.e. it is not combined with Invocation.base_test_variant.
+  Variant variant = 3;
+
+  // Identifies an exoneration in a given invocation and test id.
+  // It is server-generated.
+  string exoneration_id = 4 [
+    (google.api.field_behavior) = OUTPUT_ONLY,
+    (google.api.field_behavior) = IMMUTABLE
+  ];
+
+  // Reasoning behind the exoneration, in HTML.
+  // MUST be sanitized before rendering in the browser.
+  string explanation_html = 5 [(google.api.field_behavior) = IMMUTABLE];
+
+  // Hash of the variant.
+  // hex(sha256(sorted(''.join('%s:%s\n' for k, v in variant.items())))).
+  string variant_hash = 6 [(google.api.field_behavior) = IMMUTABLE];
+
+  // Reasoning behind the exoneration, in machine-readable form.
+  // Used to assist downstream analyses, such as automatic bug-filing.
+  // This allow detection of e.g. critical tests failing in presubmit,
+  // even if they are being exonerated because they fail on other CLs.
+  ExonerationReason reason = 7 [(google.api.field_behavior) = IMMUTABLE];
+
+  // Whether the test exoneration has been masked so that it includes only
+  // metadata. The metadata fields for a TestExoneration are:
+  // * name
+  // * test_id
+  // * exoneration_id
+  // * variant_hash
+  // * explanation_html
+  // * reason
+  //
+  // Output only.
+  bool is_masked = 8 [(google.api.field_behavior) = OUTPUT_ONLY];
+}
+
+// Reason why a test variant was exonerated.
+enum ExonerationReason {
+  // Reason was not specified.
+  // Not to be used in actual test exonerations; serves as a default value for
+  // an unset field.
+  EXONERATION_REASON_UNSPECIFIED = 0;
+
+  // Similar unexpected results were observed on a mainline branch
+  // (i.e. against a build without unsubmitted changes applied).
+  // (For avoidance of doubt, this includes both flakily and
+  // deterministically occurring unexpected results.)
+  // Applies to unexpected results in presubmit/CQ runs only.
+  OCCURS_ON_MAINLINE = 1;
+
+  // Similar unexpected results were observed in presubmit run(s) for other,
+  // unrelated CL(s). (This is suggestive of the issue being present
+  // on mainline but is not confirmed as there are possible confounding
+  // factors, like how tests are run on CLs vs how tests are run on
+  // mainline branches.)
+  // Applies to unexpected results in presubmit/CQ runs only.
+  OCCURS_ON_OTHER_CLS = 2;
+
+  // The tests are not critical to the test subject (e.g. CL) passing.
+  // This could be because more data is being collected to determine if
+  // the tests are stable enough to be made critical (as is often the
+  // case for experimental test suites).
+  // If information exists indicating the tests are producing unexpected
+  // results, and the tests are not critical for that reason,
+  // prefer more specific reasons OCCURS_ON_MAINLINE or OCCURS_ON_OTHER_CLS.
+  NOT_CRITICAL = 3;
+
+  // The test result was an unexpected pass. (Note that such an exoneration is
+  // not automatically created for unexpected passes, unless the option is
+  // specified to ResultSink or the project manually creates one).
+  UNEXPECTED_PASS = 4;
+}
diff --git a/res/config/checker/baseline_config.json b/res/config/checker/baseline_config.json
index 873365a52..fef2a19ac 100644
--- a/res/config/checker/baseline_config.json
+++ b/res/config/checker/baseline_config.json
@@ -42,7 +42,7 @@
   },
   "disable_usb_app_verification": {
     "class_name": "com.android.tradefed.suite.checker.baseline.SettingsBaselineSetter",
-    "namespace": "secure",
+    "namespace": "global",
     "key": "verifier_verify_adb_installs",
     "value": "0"
   },
@@ -56,11 +56,6 @@
     "class_name": "com.android.tradefed.suite.checker.baseline.LockSettingsBaselineSetter",
     "clear_pwds": ["0000", "1234", "12345", "private"]
   },
-  "back_to_home_screen": {
-    "class_name": "com.android.tradefed.suite.checker.baseline.CommandBaselineSetter",
-    "command": "input keyevent KEYCODE_HOME",
-    "min_api_level": "35"
-  },
   "reset_hidden_api_policy": {
     "class_name": "com.android.tradefed.suite.checker.baseline.CommandBaselineSetter",
     "command": "settings delete global hidden_api_policy",
diff --git a/src/com/android/tradefed/build/content/ContentAnalysisContext.java b/src/com/android/tradefed/build/content/ContentAnalysisContext.java
index a02bddd84..a017409f0 100644
--- a/src/com/android/tradefed/build/content/ContentAnalysisContext.java
+++ b/src/com/android/tradefed/build/content/ContentAnalysisContext.java
@@ -66,6 +66,8 @@ public class ContentAnalysisContext {
     }
 
     public Set<String> commonLocations() {
+        // Never consider ignored as part of common locations
+        commonLocations.removeAll(ignoredChange);
         return commonLocations;
     }
 
diff --git a/src/com/android/tradefed/build/content/ContentMerkleTree.java b/src/com/android/tradefed/build/content/ContentMerkleTree.java
new file mode 100644
index 000000000..115e4a4a4
--- /dev/null
+++ b/src/com/android/tradefed/build/content/ContentMerkleTree.java
@@ -0,0 +1,83 @@
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
+package com.android.tradefed.build.content;
+
+import com.android.tradefed.build.content.ArtifactDetails.ArtifactFileDescriptor;
+import com.android.tradefed.cache.DigestCalculator;
+import com.android.tradefed.log.LogUtil.CLog;
+
+import build.bazel.remote.execution.v2.Digest;
+import build.bazel.remote.execution.v2.Directory;
+import build.bazel.remote.execution.v2.FileNode;
+
+import java.io.IOException;
+import java.util.Collections;
+import java.util.Comparator;
+import java.util.List;
+import java.util.stream.Collectors;
+
+/** Compute a MerkleTree from the content information. */
+public class ContentMerkleTree {
+
+    /** Builds a merkle tree and returns the root digest from the common location information */
+    public static Digest buildCommonLocationFromContext(ContentAnalysisContext context) {
+        try {
+            ArtifactDetails currentContent =
+                    ArtifactDetails.parseFile(
+                            context.contentInformation().currentContent, context.contentEntry());
+            Directory.Builder rootBuilder = Directory.newBuilder();
+            List<ArtifactFileDescriptor> allFiles = currentContent.details;
+            List<ArtifactFileDescriptor> commonFiles =
+                    allFiles.parallelStream()
+                            .filter(
+                                    p -> {
+                                        for (String common : context.commonLocations()) {
+                                            if (p.path.startsWith(common)) {
+                                                return true;
+                                            }
+                                        }
+                                        return false;
+                                    })
+                            .collect(Collectors.toList());
+            // Sort to ensure final messages are identical
+            Collections.sort(
+                    commonFiles,
+                    new Comparator<ArtifactFileDescriptor>() {
+                        @Override
+                        public int compare(
+                                ArtifactFileDescriptor arg0, ArtifactFileDescriptor arg1) {
+                            return arg0.path.compareTo(arg1.path);
+                        }
+                    });
+            for (ArtifactFileDescriptor afd : commonFiles) {
+                Digest digest =
+                        Digest.newBuilder().setHash(afd.digest).setSizeBytes(afd.size).build();
+                rootBuilder.addFiles(
+                        FileNode.newBuilder()
+                                .setDigest(digest)
+                                .setName(afd.path)
+                                .setIsExecutable(false));
+            }
+            Directory root = rootBuilder.build();
+            Digest d = DigestCalculator.compute(root);
+            CLog.d("Digest for common location of '%s' is '%s'", context.contentEntry(), d);
+            return d;
+        } catch (IOException | RuntimeException e) {
+            CLog.e(e);
+            return null;
+        }
+    }
+}
diff --git a/src/com/android/tradefed/build/content/ContentModuleLister.java b/src/com/android/tradefed/build/content/ContentModuleLister.java
new file mode 100644
index 000000000..3cbb8b9ab
--- /dev/null
+++ b/src/com/android/tradefed/build/content/ContentModuleLister.java
@@ -0,0 +1,60 @@
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
+package com.android.tradefed.build.content;
+
+import com.android.tradefed.build.content.ArtifactDetails.ArtifactFileDescriptor;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.util.FileUtil;
+
+import java.io.IOException;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Set;
+
+/** Compute a module list from the context. */
+public class ContentModuleLister {
+
+    /** Builds the list of existing modules from the context */
+    public static Set<String> buildModuleList(ContentAnalysisContext context) {
+        try {
+            ArtifactDetails currentContent =
+                    ArtifactDetails.parseFile(
+                            context.contentInformation().currentContent, context.contentEntry());
+            List<ArtifactFileDescriptor> allFiles = currentContent.details;
+            Set<String> moduleNames = new HashSet<>();
+            for (ArtifactFileDescriptor afd : allFiles) {
+                String filePath = afd.path;
+                String[] pathSegments = filePath.split("/");
+                if (filePath.startsWith("host/testcases/")) {
+                    moduleNames.add(pathSegments[2]);
+                } else if (filePath.startsWith("target/testcases/")) {
+                    moduleNames.add(pathSegments[2]);
+                }
+                if (pathSegments.length == 4) {
+                    String possibleConfig = pathSegments[2] + ".config";
+                    if (pathSegments[3].endsWith(".config")
+                            && !possibleConfig.equals(pathSegments[3])) {
+                        moduleNames.add(FileUtil.getBaseName(pathSegments[3]));
+                    }
+                }
+            }
+            return moduleNames;
+        } catch (IOException | RuntimeException e) {
+            CLog.e(e);
+            return new HashSet<>();
+        }
+    }
+}
diff --git a/src/com/android/tradefed/build/content/DeviceMerkleTree.java b/src/com/android/tradefed/build/content/DeviceMerkleTree.java
index a17150dc3..846106a21 100644
--- a/src/com/android/tradefed/build/content/DeviceMerkleTree.java
+++ b/src/com/android/tradefed/build/content/DeviceMerkleTree.java
@@ -18,6 +18,7 @@ package com.android.tradefed.build.content;
 import com.android.tradefed.build.content.ArtifactDetails.ArtifactFileDescriptor;
 import com.android.tradefed.cache.DigestCalculator;
 import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.result.skipped.AnalysisHeuristic;
 
 import build.bazel.remote.execution.v2.Digest;
 import build.bazel.remote.execution.v2.Directory;
@@ -31,15 +32,16 @@ import java.util.List;
 /** Compute a MerkleTree from the device content information. */
 public class DeviceMerkleTree {
 
-    /** Builds a merkle tree and returns the root digest from the device content informaton */
-    public static Digest buildFromContext(ContentAnalysisContext context) {
+    /** Builds a merkle tree and returns the root digest from the device content information */
+    public static Digest buildFromContext(
+            ContentAnalysisContext context, AnalysisHeuristic analysisLevel) {
         try {
             ArtifactDetails currentContent =
                     ArtifactDetails.parseFile(
                             context.contentInformation().currentContent, context.contentEntry());
             Directory.Builder rootBuilder = Directory.newBuilder();
             List<ArtifactFileDescriptor> allFiles = currentContent.details;
-            ImageContentAnalyzer.normalizeDeviceImage(allFiles);
+            ImageContentAnalyzer.normalizeDeviceImage(allFiles, analysisLevel);
             // Sort to ensure final messages are identical
             Collections.sort(
                     allFiles,
diff --git a/src/com/android/tradefed/build/content/ImageContentAnalyzer.java b/src/com/android/tradefed/build/content/ImageContentAnalyzer.java
index d718f7eda..89271c6c8 100644
--- a/src/com/android/tradefed/build/content/ImageContentAnalyzer.java
+++ b/src/com/android/tradefed/build/content/ImageContentAnalyzer.java
@@ -24,6 +24,8 @@ import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.result.skipped.AnalysisHeuristic;
 import com.android.tradefed.testtype.suite.SuiteResultCacheUtil;
 
+import build.bazel.remote.execution.v2.Digest;
+
 import com.google.api.client.util.Joiner;
 
 import java.util.ArrayList;
@@ -47,7 +49,8 @@ public class ImageContentAnalyzer {
     }
 
     /** Remove descriptors for files that do not impact the device image functionally */
-    public static void normalizeDeviceImage(List<ArtifactFileDescriptor> allDescriptors) {
+    public static void normalizeDeviceImage(
+            List<ArtifactFileDescriptor> allDescriptors, AnalysisHeuristic analysisLevel) {
         // Remove all build.prop paths
         allDescriptors.removeIf(d -> d.path.endsWith("/build.prop"));
         allDescriptors.removeIf(d -> d.path.endsWith("/prop.default"));
@@ -61,6 +64,22 @@ public class ImageContentAnalyzer {
         allDescriptors.removeIf(d -> d.path.startsWith("META/"));
         allDescriptors.removeIf(d -> d.path.startsWith("PREBUILT_IMAGES/"));
         allDescriptors.removeIf(d -> d.path.startsWith("RADIO/"));
+
+        if (analysisLevel.ordinal() >= AnalysisHeuristic.REMOVE_EXEMPTION.ordinal()) {
+            boolean removed = false;
+            // b/335722003
+            boolean ota4k =
+                    allDescriptors.removeIf(d -> d.path.endsWith("/boot_otas/boot_ota_4k.zip"));
+            boolean ota16k =
+                    allDescriptors.removeIf(d -> d.path.endsWith("/boot_otas/boot_ota_16k.zip"));
+            if (ota4k || ota16k) {
+                removed = true;
+            }
+            if (removed) {
+                InvocationMetricLogger.addInvocationMetrics(
+                        InvocationMetricKey.DEVICE_IMAGE_USED_HEURISTIC, analysisLevel.name());
+            }
+        }
     }
 
     public ContentAnalysisResults evaluate() {
@@ -69,6 +88,7 @@ public class ImageContentAnalyzer {
             if (presubmitMode) {
                 for (ContentAnalysisContext context : contexts) {
                     if (context.contentInformation() != null
+                            && context.contentInformation().currentBuildId != null
                             && !context.contentInformation().currentBuildId.startsWith("P")) {
                         activeContexts.remove(context);
                         CLog.d(
@@ -86,18 +106,6 @@ public class ImageContentAnalyzer {
                                                     || AnalysisMethod.DEVICE_IMAGE.equals(
                                                             c.analysisMethod())))
                             .collect(Collectors.toList());
-            // Handle invalidation should it be set for a device image.
-            for (ContentAnalysisContext context : buildKeyAnalysis) {
-                if (AnalysisMethod.DEVICE_IMAGE.equals(context.analysisMethod())
-                        && context.abortAnalysis()) {
-                    CLog.w(
-                            "Analysis was aborted: %s for %s",
-                            context.abortReason(), context.contentEntry());
-                    InvocationMetricLogger.addInvocationMetrics(
-                            InvocationMetricKey.ABORT_CONTENT_ANALYSIS, 1);
-                    return null;
-                }
-            }
             ContentAnalysisResults results = new ContentAnalysisResults();
             for (ContentAnalysisContext context : buildKeyAnalysis) {
                 switch (context.analysisMethod()) {
@@ -116,7 +124,8 @@ public class ImageContentAnalyzer {
                                     context.contentEntry());
                         }
                         results.addImageDigestMapping(
-                                context.contentEntry(), DeviceMerkleTree.buildFromContext(context));
+                                context.contentEntry(),
+                                DeviceMerkleTree.buildFromContext(context, mAnalysisLevel));
                         break;
                     case DEVICE_IMAGE:
                         long changeCount = deviceImageAnalysis(context);
@@ -124,9 +133,14 @@ public class ImageContentAnalyzer {
                             CLog.d("device image '%s' has changed.", context.contentEntry());
                             results.addDeviceImageChanges(changeCount);
                         }
+                        Digest imageDigest =
+                                DeviceMerkleTree.buildFromContext(context, mAnalysisLevel);
+                        if (imageDigest != null) {
+                            InvocationMetricLogger.addInvocationMetrics(
+                                    InvocationMetricKey.DEVICE_IMAGE_HASH, imageDigest.getHash());
+                        }
                         results.addImageDigestMapping(
-                                SuiteResultCacheUtil.DEVICE_IMAGE_KEY,
-                                DeviceMerkleTree.buildFromContext(context));
+                                SuiteResultCacheUtil.DEVICE_IMAGE_KEY, imageDigest);
                         break;
                     default:
                         break;
@@ -162,28 +176,21 @@ public class ImageContentAnalyzer {
 
     // Analyze the target files as proxy for the device image
     private long deviceImageAnalysis(ContentAnalysisContext context) {
+        if (context.abortAnalysis()) {
+            CLog.w(
+                    "Analysis was aborted for build key %s: %s",
+                    context.contentEntry(), context.abortReason());
+            InvocationMetricLogger.addInvocationMetrics(
+                    InvocationMetricKey.ABORT_CONTENT_ANALYSIS, 1);
+            return 1; // In case of abort, skew toward image changing
+        }
         try {
             List<ArtifactFileDescriptor> diffs =
                     TestContentAnalyzer.analyzeContentDiff(
                             context.contentInformation(), context.contentEntry());
             // Remove paths that are ignored
             diffs.removeIf(d -> context.ignoredChanges().contains(d.path));
-            normalizeDeviceImage(diffs);
-            if (mAnalysisLevel.ordinal() >= AnalysisHeuristic.REMOVE_EXEMPTION.ordinal()) {
-                boolean removed = false;
-                // b/335722003
-                boolean ota4k =
-                        diffs.removeIf(d -> d.path.endsWith("/boot_otas/boot_ota_4k.zip"));
-                boolean ota16k =
-                        diffs.removeIf(d -> d.path.endsWith("/boot_otas/boot_ota_16k.zip"));
-                if (ota4k || ota16k) {
-                    removed = true;
-                }
-                if (removed) {
-                    InvocationMetricLogger.addInvocationMetrics(
-                            InvocationMetricKey.DEVICE_IMAGE_USED_HEURISTIC, mAnalysisLevel.name());
-                }
-            }
+            normalizeDeviceImage(diffs, mAnalysisLevel);
             if (diffs.isEmpty()) {
                 CLog.d("Device image from '%s' is unchanged", context.contentEntry());
             } else {
diff --git a/src/com/android/tradefed/build/content/TestContentAnalyzer.java b/src/com/android/tradefed/build/content/TestContentAnalyzer.java
index 83503b007..44e611240 100644
--- a/src/com/android/tradefed/build/content/TestContentAnalyzer.java
+++ b/src/com/android/tradefed/build/content/TestContentAnalyzer.java
@@ -82,16 +82,6 @@ public class TestContentAnalyzer {
                     }
                 }
             }
-            // Handle invalidation should it be set.
-            for (ContentAnalysisContext context : activeContexts) {
-                if (context.abortAnalysis()) {
-                    CLog.w("Analysis was aborted: %s", context.abortReason());
-                    InvocationMetricLogger.addInvocationMetrics(
-                            InvocationMetricKey.ABORT_CONTENT_ANALYSIS, 1);
-                    return null;
-                }
-            }
-
             List<ContentAnalysisContext> buildKeyAnalysis =
                     activeContexts.stream()
                             .filter(c -> AnalysisMethod.BUILD_KEY.equals(c.analysisMethod()))
@@ -99,16 +89,19 @@ public class TestContentAnalyzer {
             // Analyze separately the BUILD_KEY files
             int countBuildKeyDiff = 0;
             for (ContentAnalysisContext context : buildKeyAnalysis) {
-                if (AnalysisMethod.BUILD_KEY.equals(context.analysisMethod())) {
-                    boolean hasChanged = buildKeyAnalysis(context);
-                    if (hasChanged) {
-                        CLog.d(
-                                "build key '%s' has changed or couldn't be evaluated.",
-                                context.contentEntry());
-                        countBuildKeyDiff++;
-                        InvocationMetricLogger.addInvocationMetrics(
-                                InvocationMetricKey.BUILD_KEY_WITH_DIFFS, 1);
-                    }
+                boolean hasChanged = true;
+                if (context.abortAnalysis()) {
+                    hasChanged = true;
+                } else {
+                    hasChanged = buildKeyAnalysis(context);
+                }
+                if (hasChanged) {
+                    CLog.d(
+                            "build key '%s' has changed or couldn't be evaluated.",
+                            context.contentEntry());
+                    countBuildKeyDiff++;
+                    InvocationMetricLogger.addInvocationMetrics(
+                            InvocationMetricKey.BUILD_KEY_WITH_DIFFS, 1);
                 }
             }
             activeContexts.removeAll(buildKeyAnalysis);
@@ -118,28 +111,33 @@ public class TestContentAnalyzer {
             }
             List<ContentAnalysisResults> allResults = new ArrayList<>();
             for (ContentAnalysisContext ac : activeContexts) {
-                ContentAnalysisResults results;
+                ContentAnalysisResults results = null;
                 AnalysisMethod method = ac.analysisMethod();
-                switch (method) {
-                    case MODULE_XTS:
-                        results = xtsAnalysis(information.getBuildInfo(), ac);
-                        break;
-                    case FILE:
-                        results = fileAnalysis(information.getBuildInfo(), ac);
-                        break;
-                    case SANDBOX_WORKDIR:
-                        results = workdirAnalysis(information.getBuildInfo(), ac);
-                        break;
-                    default:
-                        // do nothing for the rest for now.
-                        return null;
+                if (!ac.abortAnalysis()) {
+                    switch (method) {
+                        case MODULE_XTS:
+                            results = xtsAnalysis(information.getBuildInfo(), ac);
+                            break;
+                        case FILE:
+                            results = fileAnalysis(information.getBuildInfo(), ac);
+                            break;
+                        case SANDBOX_WORKDIR:
+                            results = workdirAnalysis(information.getBuildInfo(), ac);
+                            break;
+                        default:
+                            // do nothing for the rest for now.
+                            return null;
+                    }
                 }
                 if (results == null) {
                     InvocationMetricLogger.addInvocationMetrics(
                             InvocationMetricKey.ABORT_CONTENT_ANALYSIS, 1);
-                    return null;
+                    // Continue with an invalidated analysis
+                    results = new ContentAnalysisResults().addModifiedSharedFolder(1);
+                    CLog.d("Content analysis results for %s: invalid", ac.contentEntry());
+                } else {
+                    CLog.d("content analysis results for %s: %s", ac.contentEntry(), results);
                 }
-                CLog.d("content analysis results for %s: %s", ac.contentEntry(), results);
                 allResults.add(results);
             }
             ContentAnalysisResults finalResults = ContentAnalysisResults.mergeResults(allResults);
@@ -160,8 +158,19 @@ public class TestContentAnalyzer {
             return null;
         }
         diffs.removeIf(d -> context.ignoredChanges().contains(d.path));
-        return mapDiffsToModule(
-                context.contentEntry(), diffs, build.getFile(BuildInfoFileKey.ROOT_DIRECTORY));
+        ContentAnalysisResults results =
+                mapDiffsToModule(
+                        context.contentEntry(),
+                        diffs,
+                        build.getFile(BuildInfoFileKey.ROOT_DIRECTORY));
+        if (results != null) {
+            if (!context.commonLocations().isEmpty()) {
+                results.addImageDigestMapping(
+                        context.contentEntry() + "_common_location",
+                        ContentMerkleTree.buildCommonLocationFromContext(context));
+            }
+        }
+        return results;
     }
 
     private ContentAnalysisResults mapDiffsToModule(
@@ -184,7 +193,7 @@ public class TestContentAnalyzer {
         }
         File testcasesRoot = FileUtil.findFile(rootDir, "testcases");
         if (testcasesRoot == null) {
-            CLog.e("Could find a testcases directory, something went wrong.");
+            CLog.e("Couldn't find a testcases directory, something went wrong.");
             return null;
         }
         for (String depFile : dependencyFiles) {
@@ -310,6 +319,11 @@ public class TestContentAnalyzer {
         ContentAnalysisResults results = new ContentAnalysisResults();
         List<ArtifactFileDescriptor> diffs = new ArrayList<>();
         Set<String> AllCommonDirs = new HashSet<>();
+        if (!context.commonLocations().isEmpty()) {
+            results.addImageDigestMapping(
+                    context.contentEntry() + "_common_location",
+                    ContentMerkleTree.buildCommonLocationFromContext(context));
+        }
         List<ArtifactFileDescriptor> diff =
                 analyzeContentDiff(context.contentInformation(), context.contentEntry());
         if (diff == null) {
diff --git a/src/com/android/tradefed/command/CommandOptions.java b/src/com/android/tradefed/command/CommandOptions.java
index 95271ce6a..a4445609d 100644
--- a/src/com/android/tradefed/command/CommandOptions.java
+++ b/src/com/android/tradefed/command/CommandOptions.java
@@ -365,6 +365,11 @@ public class CommandOptions implements ICommandOptions {
             description = "Actually enable the reporting of caching status.")
     private boolean mEnableModuleCachingResults = false;
 
+    @Option(
+            name = "report-cache-results-presubmit",
+            description = "Actually enable the reporting of caching status in presubmit.")
+    private boolean mEnableCachingResultsInPresubmit = false;
+
     /**
      * Set the help mode for the config.
      * <p/>
@@ -895,4 +900,10 @@ public class CommandOptions implements ICommandOptions {
     public boolean reportCacheResults() {
         return mEnableModuleCachingResults;
     }
+
+    /** {@inheritDoc} */
+    @Override
+    public boolean reportCacheResultsInPresubmit() {
+        return mEnableCachingResultsInPresubmit;
+    }
 }
diff --git a/src/com/android/tradefed/command/CommandScheduler.java b/src/com/android/tradefed/command/CommandScheduler.java
index 4246664f9..02a768d30 100644
--- a/src/com/android/tradefed/command/CommandScheduler.java
+++ b/src/com/android/tradefed/command/CommandScheduler.java
@@ -987,7 +987,7 @@ public class CommandScheduler extends Thread implements ICommandScheduler, IComm
         private boolean skipExperiment(IConfiguration config, IInvocationContext context) {
             // skip experiment for TRYBOT runs
             return config.getCommandOptions().skipTrybotExperiment()
-                    && "TRYBOT".equals(context.getAttribute("trigger"));
+                    && InvocationContext.isOnDemand(context);
         }
     }
 
diff --git a/src/com/android/tradefed/command/Console.java b/src/com/android/tradefed/command/Console.java
index d0e0ad598..69a9f6c96 100644
--- a/src/com/android/tradefed/command/Console.java
+++ b/src/com/android/tradefed/command/Console.java
@@ -58,6 +58,7 @@ import com.google.common.annotations.VisibleForTesting;
 import org.jline.reader.EndOfFileException;
 import org.jline.reader.LineReader;
 import org.jline.reader.LineReaderBuilder;
+import org.jline.reader.UserInterruptException;
 import org.jline.reader.impl.history.DefaultHistory;
 import org.jline.terminal.TerminalBuilder;
 
@@ -1040,6 +1041,9 @@ public class Console extends Thread {
                 return mConsoleReader.readLine(getConsolePrompt());
             } catch (EndOfFileException e) {
                 return null;
+            } catch (UserInterruptException e) {
+                printLine("\nInterrupted by User.Exiting.");
+                return null;
             }
         } else {
             return null;
diff --git a/src/com/android/tradefed/command/ICommandOptions.java b/src/com/android/tradefed/command/ICommandOptions.java
index 3cebde521..63d89ad93 100644
--- a/src/com/android/tradefed/command/ICommandOptions.java
+++ b/src/com/android/tradefed/command/ICommandOptions.java
@@ -308,4 +308,7 @@ public interface ICommandOptions {
 
     /** Returns true if we should report cache results when available. */
     public boolean reportCacheResults();
+
+    /** Returns true if we should report cache results when available in presubmit. */
+    public boolean reportCacheResultsInPresubmit();
 }
diff --git a/src/com/android/tradefed/config/ConfigurationDef.java b/src/com/android/tradefed/config/ConfigurationDef.java
index cdf1b8cbe..92a354931 100644
--- a/src/com/android/tradefed/config/ConfigurationDef.java
+++ b/src/com/android/tradefed/config/ConfigurationDef.java
@@ -267,9 +267,13 @@ public class ConfigurationDef {
                 boolean shouldAddToFlatConfig = true;
 
                 for (ConfigObjectDef configDef : objClassEntry.getValue()) {
+                    String objectWithoutNamespace = objClassEntry.getKey();
+                    if (objectWithoutNamespace.contains(":")) {
+                        objectWithoutNamespace = objectWithoutNamespace.split(":")[1];
+                    }
                     if (allowedObjects != null
-                            && !allowedObjects.contains(objClassEntry.getKey())) {
-                        CLog.d("Skipping creation of %s", objClassEntry.getKey());
+                            && !allowedObjects.contains(objectWithoutNamespace)) {
+                        CLog.d("Skipping creation of %s", objectWithoutNamespace);
                         mFilteredObjects = true;
                         continue;
                     }
diff --git a/src/com/android/tradefed/config/filter/OptionFetcher.java b/src/com/android/tradefed/config/filter/OptionFetcher.java
index 1b32c2d7f..9d9f2a70f 100644
--- a/src/com/android/tradefed/config/filter/OptionFetcher.java
+++ b/src/com/android/tradefed/config/filter/OptionFetcher.java
@@ -50,7 +50,8 @@ public class OptionFetcher implements AutoCloseable {
                     "remote-dynamic-sharding",
                     "remote-cache-instance-name",
                     "upload-cached-module-results",
-                    "report-cache-results");
+                    "report-cache-results",
+                    "report-cache-results-presubmit");
 
     private TradefedFeatureClient mClient;
 
diff --git a/src/com/android/tradefed/device/DumpsysPackageReceiver.java b/src/com/android/tradefed/device/DumpsysPackageReceiver.java
index cabec529c..5d6bde720 100644
--- a/src/com/android/tradefed/device/DumpsysPackageReceiver.java
+++ b/src/com/android/tradefed/device/DumpsysPackageReceiver.java
@@ -82,8 +82,9 @@ class DumpsysPackageReceiver extends MultiLineReceiver {
      * <p/>
      * Expected pattern is:
      * Package: [com.foo]
-     *   key=value
-     *   key2=value2
+     *   key=value key2=value2
+     *   key3=value with spaces
+     *   key4=value=with=equal=signs key5=normalvalue
      */
     private class PackageParserState implements ParserState {
 
@@ -122,20 +123,36 @@ class DumpsysPackageReceiver extends MultiLineReceiver {
             return this;
         }
 
+        /**
+         * Parse a line containing attributes.
+         *
+         * Attributes are in the following formats:
+         *   key=value key2=value2
+         *   key3=value with spaces
+         *   key4=value=with=equal=signs key5=normalvalue
+         * We assume that key-value pairs with whitespaces will not appear on the same line with
+         * other attributes.
+         */
         private void parseAttributes(String line) {
             String[] prop = line.split("=");
             if (prop.length == 2) {
+                // If there are only two splits, treat the split before = as key and the split
+                // after as value.
                 mPkgInfo.addAttribute(prop[0], prop[1]);
             } else if (prop.length > 2) {
-                // multiple props on one line. Split by both whitespace and =
-                String[] vn = line.split(" |=");
-                if (vn.length % 2 != 0) {
-                    // improper format, ignore
-                    return;
-                }
-                for (int i=0; i < vn.length; i = i + 2) {
-                    mPkgInfo.addAttribute(vn[i], vn[i+1]);
-                }
+              // If there are more than two splits, treat the line containing multiple key-value
+              // pairs, each one not containing whitespaces.
+              // First split by whitespace to get all key-value pairs on a line.
+              for (String keyValuePair : line.split(" ")) {
+                  // Then check the first position of = sign of a single key-value pair, where the
+                  // key and the value are separated.
+                  int firstEqualPos = keyValuePair.indexOf('=');
+                  if (firstEqualPos != -1) {
+                      mPkgInfo.addAttribute(
+                          keyValuePair.substring(0, firstEqualPos),
+                          keyValuePair.substring(firstEqualPos + 1));
+                  }
+              }
             }
 
         }
diff --git a/src/com/android/tradefed/device/NativeDevice.java b/src/com/android/tradefed/device/NativeDevice.java
index 2c8eb8862..5c21fb74d 100644
--- a/src/com/android/tradefed/device/NativeDevice.java
+++ b/src/com/android/tradefed/device/NativeDevice.java
@@ -164,7 +164,7 @@ public class NativeDevice
     private static final int MAX_SYSTEM_SERVER_DELAY_AFTER_BOOT_UP_SEC = 25;
 
     /** The time in ms to wait before starting logcat for a device */
-    private int mLogStartDelay = 5*1000;
+    private int mLogStartDelay = 0;
 
     /** The time in ms to wait for a device to become unavailable. Should usually be short */
     private static final int DEFAULT_UNAVAILABLE_TIMEOUT = 20 * 1000;
@@ -1595,6 +1595,11 @@ public class NativeDevice
             throws DeviceNotAvailableException {
         boolean skipContentProvider = false;
         int userId = getCurrentUserCompatible(remoteFilePath);
+        if (userId == INVALID_USER_ID) {
+            throw new HarnessRuntimeException(
+                    "Device didn't return a valid user id. It might have gone into a bad state.",
+                    DeviceErrorIdentifier.DEVICE_UNEXPECTED_RESPONSE);
+        }
         if (evaluateContentProviderNeeded) {
             skipContentProvider = userId == 0;
         }
@@ -1612,7 +1617,8 @@ public class NativeDevice
         InvocationMetricLogger.addInvocationMetrics(InvocationMetricKey.PUSH_FILE_COUNT, 1);
         try {
             if (!skipContentProvider) {
-                if (isSdcardOrEmulated(remoteFilePath)) {
+                // Skip Content provider for user 0
+                if (isSdcardOrEmulated(remoteFilePath) && userId != 0) {
                     ContentProviderHandler handler = getContentProvider(userId);
                     if (handler != null) {
                         return handler.pushFile(localFile, remoteFilePath);
@@ -1713,8 +1719,16 @@ public class NativeDevice
                 }
             }
             CLog.d("Using 'ls' to check doesFileExist(%s)", deviceFilePath);
-            String lsGrep = executeShellCommand(String.format("ls \"%s\"", deviceFilePath));
-            return !lsGrep.contains("No such file or directory");
+            CommandResult result = executeShellV2Command(String.format("ls '%s'", deviceFilePath));
+            if (CommandStatus.SUCCESS.equals(result.getStatus())
+                    && !result.getStdout().contains("No such file or directory")) {
+                return true;
+            } else {
+                CLog.d(
+                        "File %s does not exist.\nstdout: %s\nstderr: %s",
+                        deviceFilePath, result.getStdout(), result.getStderr());
+                return false;
+            }
         } finally {
             InvocationMetricLogger.addInvocationMetrics(
                     InvocationMetricKey.DOES_FILE_EXISTS_TIME,
@@ -3376,7 +3390,12 @@ public class NativeDevice
         mLastConnectedWifiSsid = null;
         mLastConnectedWifiPsk = null;
 
-        IWifiHelper wifi = createWifiHelper();
+        IWifiHelper wifi = null;
+        if (!getOptions().useCmdWifiCommands() || !enableAdbRoot() || getApiLevel() < 31) {
+            wifi = createWifiHelper(false);
+        } else {
+            wifi = createWifiHelper(true);
+        }
         return wifi.disconnectFromNetwork();
     }
 
@@ -4450,24 +4469,8 @@ public class NativeDevice
         return null;
     }
 
-    /** {@inheritDoc} */
-    @Override
-    public String getFastbootSerialNumber() {
-        if (mFastbootSerialNumber != null) {
-            return mFastbootSerialNumber;
-        }
-
-        // Only devices which use TCP adb have different fastboot serial number because IPv6
-        // link-local address will be used in fastboot mode.
-        if (!isAdbTcp()) {
-            mFastbootSerialNumber = getSerialNumber();
-            CLog.i(
-                    "Device %s's fastboot serial number is %s",
-                    getSerialNumber(), mFastbootSerialNumber);
-            return mFastbootSerialNumber;
-        }
-
-        mFastbootSerialNumber = getSerialNumber();
+    @Nullable
+    private String getLinkLocalIpv6FastbootSerial() {
         byte[] macEui48Bytes;
 
         try {
@@ -4482,15 +4485,12 @@ public class NativeDevice
         } catch (DeviceNotAvailableException e) {
             CLog.e("Device %s isn't available when get fastboot serial number", getSerialNumber());
             CLog.e(e);
-            return getSerialNumber();
+            return null;
         }
 
         String net_interface = getHostOptions().getNetworkInterface();
         if (net_interface == null || macEui48Bytes == null) {
-            CLog.i(
-                    "Device %s's fastboot serial number is %s",
-                    getSerialNumber(), mFastbootSerialNumber);
-            return mFastbootSerialNumber;
+            return null;
         }
 
         // Create a link-local Inet6Address from the MAC address. The EUI-48 MAC address
@@ -4510,12 +4510,40 @@ public class NativeDevice
 
         try {
             String host_addr = Inet6Address.getByAddress(null, addr, 0).getHostAddress();
-            mFastbootSerialNumber = "tcp:" + host_addr.split("%")[0] + "%" + net_interface;
+            return "tcp:" + host_addr.split("%")[0] + "%" + net_interface;
         } catch (UnknownHostException e) {
             CLog.w("Failed to get %s's IPv6 link-local address", getSerialNumber());
             CLog.w(e);
         }
 
+        return null;
+    }
+
+    /** {@inheritDoc} */
+    @Override
+    public String getFastbootSerialNumber() {
+        if (mFastbootSerialNumber != null) {
+            return mFastbootSerialNumber;
+        }
+
+        // Only devices which use TCP adb have different fastboot serial number because IPv6
+        // link-local address will be used in fastboot mode.
+        if (!isAdbTcp()) {
+            mFastbootSerialNumber = getSerialNumber();
+            CLog.i(
+                    "Device %s's fastboot serial number is %s",
+                    getSerialNumber(), mFastbootSerialNumber);
+            return mFastbootSerialNumber;
+        }
+
+        mFastbootSerialNumber = getLinkLocalIpv6FastbootSerial();
+        if (mFastbootSerialNumber != null) {
+            return mFastbootSerialNumber;
+        }
+
+        // Fallback to the same serial over TCP. Used for emulator cases (i.e Cuttlefish).
+        mFastbootSerialNumber = "tcp:" + getSerialNumber();
+
         CLog.i(
                 "Device %s's fastboot serial number is %s",
                 getSerialNumber(), mFastbootSerialNumber);
diff --git a/src/com/android/tradefed/device/RemoteAndroidDevice.java b/src/com/android/tradefed/device/RemoteAndroidDevice.java
index a10bb148c..0ad92d59d 100644
--- a/src/com/android/tradefed/device/RemoteAndroidDevice.java
+++ b/src/com/android/tradefed/device/RemoteAndroidDevice.java
@@ -92,10 +92,6 @@ public class RemoteAndroidDevice extends TestDevice {
         return null;
     }
 
-    @Override
-    public String getFastbootSerialNumber() {
-        return "tcp:" + getSerialNumber();
-    }
 
     @Override
     public DeviceDescriptor getDeviceDescriptor(boolean shortDescriptor) {
diff --git a/src/com/android/tradefed/device/TestDevice.java b/src/com/android/tradefed/device/TestDevice.java
index 2b210114b..d784ec998 100644
--- a/src/com/android/tradefed/device/TestDevice.java
+++ b/src/com/android/tradefed/device/TestDevice.java
@@ -209,6 +209,7 @@ public class TestDevice extends NativeDevice {
         String cid;
     }
 
+    private boolean mFirstBootloaderReboot = false;
     private boolean mWaitForSnapuserd = false;
     private SnapuserdWaitPhase mWaitPhase = null;
     private long mSnapuserNotificationTimestamp = 0L;
@@ -1277,12 +1278,16 @@ public class TestDevice extends NativeDevice {
             try {
                 // check framework running
                 String output = executeShellCommand("pm path android");
-                if (output == null || !output.contains("package:")) {
+                if (output == null || !output.trim().startsWith("package:")) {
                     CLog.v("framework reboot: can't detect framework running");
                     return false;
                 }
                 notifyRebootStarted();
-                String command = "svc power reboot " + rebootMode.formatRebootCommand(reason);
+                String command = "svc power reboot";
+                String mode = rebootMode.formatRebootCommand(reason);
+                if (mode != null && !mode.isEmpty()) {
+                    command = String.format("%s %s", command, mode);
+                }
                 CommandResult result = executeShellV2Command(command);
                 if (result.getStdout().contains(EARLY_REBOOT)
                         || result.getStderr().contains(EARLY_REBOOT)) {
@@ -1316,9 +1321,14 @@ public class TestDevice extends NativeDevice {
     protected void doAdbReboot(RebootMode rebootMode, @Nullable final String reason)
             throws DeviceNotAvailableException {
         getConnection().notifyAdbRebootCalled();
-        if (!TestDeviceState.ONLINE.equals(getDeviceState())
-                || !doAdbFrameworkReboot(rebootMode, reason)) {
-            super.doAdbReboot(rebootMode, reason);
+        try {
+            if (mFirstBootloaderReboot
+                    || (!TestDeviceState.ONLINE.equals(getDeviceState())
+                            || !doAdbFrameworkReboot(rebootMode, reason))) {
+                super.doAdbReboot(rebootMode, reason);
+            }
+        } finally {
+            mFirstBootloaderReboot = false;
         }
     }
 
@@ -2404,6 +2414,7 @@ public class TestDevice extends NativeDevice {
     /** {@inheritDoc} */
     @Override
     public void postInvocationTearDown(Throwable exception) {
+        mFirstBootloaderReboot = false;
         super.postInvocationTearDown(exception);
         // If wifi was installed and it's a real device, attempt to clean it.
         if (mWasWifiHelperInstalled) {
@@ -2736,6 +2747,10 @@ public class TestDevice extends NativeDevice {
         return null;
     }
 
+    public void setFirstBootloaderReboot() {
+        mFirstBootloaderReboot = true;
+    }
+
     /**
      * Checks the preconditions to run a microdroid.
      *
@@ -2889,10 +2904,18 @@ public class TestDevice extends NativeDevice {
                 Strings.isNullOrEmpty(builder.mCpuTopology)
                         ? ""
                         : "--cpu-topology " + builder.mCpuTopology;
+        if (builder.mOs != null && builder.mGki != null) {
+            throw new IllegalStateException("Can't specify both os and gki!");
+        }
+        final String osFlag = Strings.isNullOrEmpty(builder.mOs) ? "" : "--os " + builder.mOs;
         final String gkiFlag = Strings.isNullOrEmpty(builder.mGki) ? "" : "--gki " + builder.mGki;
         final String hugePagesFlag = builder.mHugePages ? "--hugepages" : "";
         final String nameFlag =
                 Strings.isNullOrEmpty(builder.mName) ? "" : "--name " + builder.mName;
+        final String dumpDt =
+                Strings.isNullOrEmpty(builder.mDumpDt)
+                        ? ""
+                        : "--dump-device-tree " + builder.mDumpDt;
 
         List<String> args =
                 new ArrayList<>(
@@ -2910,6 +2933,7 @@ public class TestDevice extends NativeDevice {
                                 cpuFlag,
                                 cpuAffinityFlag,
                                 cpuTopologyFlag,
+                                osFlag,
                                 gkiFlag,
                                 hugePagesFlag,
                                 nameFlag,
@@ -2917,7 +2941,8 @@ public class TestDevice extends NativeDevice {
                                 outApkIdsigPath,
                                 builder.mInstanceImg,
                                 "--config-path",
-                                builder.mConfigPath));
+                                builder.mConfigPath,
+                                dumpDt));
         if (isVirtFeatureEnabled("com.android.kvm.LLPVM_CHANGES")) {
             args.add("--instance-id-file");
             args.add(builder.mInstanceIdFile);
@@ -3256,11 +3281,13 @@ public class TestDevice extends NativeDevice {
         private Map<File, String> mBootFiles;
         private long mAdbConnectTimeoutMs;
         private List<String> mAssignedDevices;
-        private String mGki;
+        @Deprecated private String mGki;
+        private String mOs;
         private String mInstanceIdFile; // Path to instance_id file
         private String mInstanceImg; // Path to instance_img file
         private boolean mHugePages;
         private String mName;
+        private String mDumpDt;
 
         /** Creates a builder for the given APK/apkPath and the payload config file in APK. */
         private MicrodroidBuilder(File apkFile, String apkPath, @Nonnull String configPath) {
@@ -3280,6 +3307,7 @@ public class TestDevice extends NativeDevice {
             mInstanceIdFile = null;
             mInstanceImg = null;
             mName = null;
+            mDumpDt = null;
         }
 
         /** Creates a Microdroid builder for the given APK and the payload config file in APK. */
@@ -3306,6 +3334,16 @@ public class TestDevice extends NativeDevice {
             return this;
         }
 
+        /**
+         * Sets path where device tree blob will be dumped.
+         *
+         * <p>Supported values: null and "path".
+         */
+        public MicrodroidBuilder dumpDt(String dumpDt) {
+            mDumpDt = dumpDt;
+            return this;
+        }
+
         /**
          * Sets the amount of RAM to give the VM. If this is zero or negative then the default will
          * be used.
@@ -3410,12 +3448,24 @@ public class TestDevice extends NativeDevice {
          * Uses GKI kernel instead of microdroid kernel
          *
          * @param version The GKI version to use
+         * @deprecated use {@link #os(String os)}.
          */
+        @Deprecated
         public MicrodroidBuilder gki(String version) {
             mGki = version;
             return this;
         }
 
+        /**
+         * Uses non-default variant of Microdroid OS.
+         *
+         * @param os The Microdroid OS version to use
+         */
+        public MicrodroidBuilder os(String os) {
+            mOs = os;
+            return this;
+        }
+
         /**
          * Sets the instance_id path.
          *
diff --git a/src/com/android/tradefed/device/WifiCommandUtil.java b/src/com/android/tradefed/device/WifiCommandUtil.java
index 6aee0af50..811cd9d87 100644
--- a/src/com/android/tradefed/device/WifiCommandUtil.java
+++ b/src/com/android/tradefed/device/WifiCommandUtil.java
@@ -28,15 +28,18 @@ import java.util.regex.Pattern;
 /** A utility class that can parse wifi command outputs. */
 public class WifiCommandUtil {
 
-    public static final Pattern SSID_PATTERN =
+    private static final Pattern SSID_PATTERN =
             Pattern.compile(".*WifiInfo:.*SSID:\\s*\"([^,]*)\".*");
-    public static final Pattern BSSID_PATTERN = Pattern.compile(".*WifiInfo:.*BSSID:\\s*([^,]*).*");
-    public static final Pattern LINK_SPEED_PATTERN =
+    private static final Pattern BSSID_PATTERN =
+            Pattern.compile(".*WifiInfo:.*BSSID:\\s*([^,]*).*");
+    private static final Pattern LINK_SPEED_PATTERN =
             Pattern.compile(
                     ".*WifiInfo:.*(?<!\\bTx\\s\\b|\\bRx\\s\\b)Link speed:\\s*([^,]*)Mbps.*");
-    public static final Pattern RSSI_PATTERN = Pattern.compile(".*WifiInfo:.*RSSI:\\s*([^,]*).*");
-    public static final Pattern MAC_ADDRESS_PATTERN =
+    private static final Pattern RSSI_PATTERN = Pattern.compile(".*WifiInfo:.*RSSI:\\s*([^,]*).*");
+    private static final Pattern MAC_ADDRESS_PATTERN =
             Pattern.compile(".*WifiInfo:.*MAC:\\s*([^,]*).*");
+    private static final Pattern NETWORK_ID_PATTERN =
+            Pattern.compile(".*WifiInfo:.*Net ID:\\s*([^,]*).*");
 
     /** Represents a wifi network containing its related info. */
     public static class ScanResult {
@@ -151,6 +154,11 @@ public class WifiCommandUtil {
             wifiInfo.put("macAddress", macAddressMatcher.group(1));
         }
 
+        Matcher networkIdMatcher = NETWORK_ID_PATTERN.matcher(input);
+        if (networkIdMatcher.find()) {
+            wifiInfo.put("netId", networkIdMatcher.group(1));
+        }
+
         return wifiInfo;
     }
 }
diff --git a/src/com/android/tradefed/device/WifiHelper.java b/src/com/android/tradefed/device/WifiHelper.java
index 3194b6642..7330364d9 100644
--- a/src/com/android/tradefed/device/WifiHelper.java
+++ b/src/com/android/tradefed/device/WifiHelper.java
@@ -691,6 +691,9 @@ public class WifiHelper implements IWifiHelper {
      */
     @Override
     public boolean disconnectFromNetwork() throws DeviceNotAvailableException {
+        if (mUseV2) {
+            return disconnectFromNetworkV2();
+        }
         if (!asBool(runWifiUtil("disconnectFromNetwork"))) {
             return false;
         }
@@ -701,6 +704,27 @@ public class WifiHelper implements IWifiHelper {
         return true;
     }
 
+    private boolean disconnectFromNetworkV2() throws DeviceNotAvailableException {
+        String networkId = getWifiInfo().get("netId");
+        if (Strings.isNullOrEmpty(networkId)) {
+            CLog.d("Failed to get network id.");
+            return false;
+        }
+        CommandResult forgetNetwork =
+                mDevice.executeShellV2Command(
+                        String.format("cmd -w wifi forget-network %s", networkId));
+        if (!CommandStatus.SUCCESS.equals(forgetNetwork.getStatus())
+                || !forgetNetwork.getStdout().contains("Forget successful")) {
+            CLog.d("forget-network command failed (netId=%s).", networkId);
+            return false;
+        }
+        if (!disableWifi()) {
+            CLog.e("Failed to disable wifi");
+            return false;
+        }
+        return true;
+    }
+
     /**
      * {@inheritDoc}
      */
diff --git a/src/com/android/tradefed/device/cloud/CommonLogRemoteFileUtil.java b/src/com/android/tradefed/device/cloud/CommonLogRemoteFileUtil.java
index e3da1167c..712f624eb 100644
--- a/src/com/android/tradefed/device/cloud/CommonLogRemoteFileUtil.java
+++ b/src/com/android/tradefed/device/cloud/CommonLogRemoteFileUtil.java
@@ -25,10 +25,14 @@ import com.android.tradefed.result.InputStreamSource;
 import com.android.tradefed.result.LogDataType;
 import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
+import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.IRunUtil;
 import com.android.tradefed.util.MultiMap;
 import com.android.tradefed.util.ZipUtil;
+import com.android.tradefed.util.avd.HostOrchestratorUtil;
+
 import com.google.common.base.Strings;
+
 import java.io.File;
 import java.io.IOException;
 import java.util.ArrayList;
@@ -52,6 +56,10 @@ public class CommonLogRemoteFileUtil {
     /** The directory where to find Oxygen device logs. */
     public static final String OXYGEN_CUTTLEFISH_LOG_DIR =
             "/tmp/cfbase/3/cuttlefish/instances/cvd-1/logs/";
+
+    /** cvd fetch log */
+    public static final String OXYGEN_CUTTLEFISH_FETCH_LOG = "/tmp/cfbase/3/fetch.log";
+
     /**
      * The directory where to find Oxygen device runtime logs. Only use this if
      * OXYGEN_CUTTLEFISH_LOG_DIR is not found.
@@ -143,6 +151,9 @@ public class CommonLogRemoteFileUtil {
         OXYGEN_LOG_FILES.add(new KnownLogFileEntry(OXYGEN_EMULATOR_LOG_DIR, null, LogDataType.DIR));
         OXYGEN_LOG_FILES.add(
                 new KnownLogFileEntry(OXYGEN_CUTTLEFISH_LOG_DIR, null, LogDataType.DIR));
+        OXYGEN_LOG_FILES.add(
+                new KnownLogFileEntry(
+                        OXYGEN_CUTTLEFISH_FETCH_LOG, null, LogDataType.CUTTLEFISH_LOG));
         OXYGEN_LOG_FILES.add(new KnownLogFileEntry(OXYGEN_GOLDFISH_LOG_DIR, null, LogDataType.DIR));
         NETSIM_LOG_FILES.add(new KnownLogFileEntry(NETSIM_LOG_DIR, null, LogDataType.DIR));
         NETSIM_LOG_FILES.add(new KnownLogFileEntry(NETSIM_USER_LOG_DIR, null, LogDataType.DIR));
@@ -373,6 +384,41 @@ public class CommonLogRemoteFileUtil {
         }
     }
 
+    /**
+     * Pull CF logs via Host Orchestrator.
+     *
+     * @param gceAvdInfo The descriptor of the remote instance.
+     * @param hOUtil The {@link HostOrchestratorUtil} used to pull CF logs.
+     * @param logger The {@link ITestLogger} where to log the file.
+     */
+    public static void pullCommonCvdLogs(
+            GceAvdInfo gceAvdInfo, HostOrchestratorUtil hOUtil, ITestLogger logger) {
+        if (hOUtil == null || gceAvdInfo == null || gceAvdInfo.hostAndPort() == null) {
+            CLog.e(
+                    "HostOrchestratorUtil, GceAvdInfo or its host setting was null, cannot collect"
+                            + " remote files.");
+            return;
+        }
+        File cvdLogsDir = hOUtil.pullCvdHostLogs();
+        if (cvdLogsDir != null) {
+            GceManager.logDirectory(cvdLogsDir, null, logger, LogDataType.CUTTLEFISH_LOG);
+            FileUtil.recursiveDelete(cvdLogsDir);
+        } else {
+            CLog.i("CVD Logs is null, no logs collected from host orchestrator.");
+        }
+        File tempFile =
+                hOUtil.collectLogByCommand("host_kernel", HostOrchestratorUtil.URL_HOST_KERNEL_LOG);
+        GceManager.logAndDeleteFile(tempFile, "host_kernel", logger);
+        tempFile = hOUtil.collectLogByCommand("host_orchestrator", HostOrchestratorUtil.URL_HO_LOG);
+        GceManager.logAndDeleteFile(tempFile, "host_orchestrator", logger);
+        tempFile = hOUtil.getTunnelLog();
+        GceManager.logAndDeleteFile(tempFile, "host_orchestrator_tunnel_log", logger);
+        tempFile =
+                hOUtil.collectLogByCommand(
+                        "oxygen_container_log", HostOrchestratorUtil.URL_OXYGEN_CONTAINER_LOG);
+        GceManager.logAndDeleteFile(tempFile, "oxygen_container_log", logger);
+    }
+
     /**
      * Captures a log from the remote destination.
      *
diff --git a/src/com/android/tradefed/device/cloud/GceLHPTunnelMonitor.java b/src/com/android/tradefed/device/cloud/GceLHPTunnelMonitor.java
index 44632e1b0..b0f77ca13 100644
--- a/src/com/android/tradefed/device/cloud/GceLHPTunnelMonitor.java
+++ b/src/com/android/tradefed/device/cloud/GceLHPTunnelMonitor.java
@@ -159,8 +159,6 @@ public class GceLHPTunnelMonitor extends AbstractTunnelMonitor {
                 return;
             }
 
-            // Device serial should contain tunnel host and port number.
-            getRunUtil().sleep(WAIT_FOR_FIRST_CONNECT);
             // Checking if it is actually running.
             if (isTunnelAlive()) {
                 mLocalHostAndPort = HostAndPort.fromString(mDevice.getSerialNumber());
diff --git a/src/com/android/tradefed/device/cloud/GceManager.java b/src/com/android/tradefed/device/cloud/GceManager.java
index 694901c04..afb98053f 100644
--- a/src/com/android/tradefed/device/cloud/GceManager.java
+++ b/src/com/android/tradefed/device/cloud/GceManager.java
@@ -41,6 +41,7 @@ import com.android.tradefed.util.IRunUtil;
 import com.android.tradefed.util.MultiMap;
 import com.android.tradefed.util.RunUtil;
 import com.android.tradefed.util.avd.AcloudUtil;
+import com.android.tradefed.util.avd.HostOrchestratorClient;
 import com.android.tradefed.util.avd.HostOrchestratorUtil;
 import com.android.tradefed.util.avd.LogCollector;
 import com.android.tradefed.util.avd.OxygenClient;
@@ -423,7 +424,8 @@ public class GceManager {
                                     mGceAvdInfo.getOxygenationDeviceId(),
                                     OxygenUtil.getTargetRegion(getTestDeviceOptions()),
                                     getTestDeviceOptions().getOxygenAccountingUser(),
-                                    oxygenClient);
+                                    oxygenClient,
+                                    new HostOrchestratorClient.HoHttpClient());
                     bootSuccess = hOUtil.deviceBootCompleted(timeout);
                 } else {
                     final String remoteFile =
@@ -454,33 +456,8 @@ public class GceManager {
 
                 if (!bootSuccess) {
                     if (logger != null) {
-                        if (hOUtil != null) {
-                            File cvdLogsDir = hOUtil.pullCvdHostLogs();
-                            if (cvdLogsDir != null) {
-                                GceManager.logDirectory(
-                                        cvdLogsDir, null, logger, LogDataType.CUTTLEFISH_LOG);
-                                FileUtil.recursiveDelete(cvdLogsDir);
-                            } else {
-                                CLog.i(
-                                        "CVD Logs is null, no logs collected from host"
-                                                + " orchestrator.");
-                            }
-                            File tempFile =
-                                    hOUtil.collectLogByCommand(
-                                            "host_kernel",
-                                            HostOrchestratorUtil.URL_HOST_KERNEL_LOG);
-                            logAndDeleteFile(tempFile, "host_kernel", logger);
-                            tempFile =
-                                    hOUtil.collectLogByCommand(
-                                            "host_orchestrator", HostOrchestratorUtil.URL_HO_LOG);
-                            logAndDeleteFile(tempFile, "host_orchestrator", logger);
-                            tempFile = hOUtil.getTunnelLog();
-                            logAndDeleteFile(tempFile, "host_orchestrator_tunnel_log", logger);
-                            tempFile =
-                                    hOUtil.collectLogByCommand(
-                                            "oxygen_container_log",
-                                            HostOrchestratorUtil.URL_OXYGEN_CONTAINER_LOG);
-                            logAndDeleteFile(tempFile, "oxygen_container_log", logger);
+                        if (getTestDeviceOptions().useCvdCF()) {
+                            CommonLogRemoteFileUtil.pullCommonCvdLogs(mGceAvdInfo, hOUtil, logger);
                         } else {
                             CommonLogRemoteFileUtil.fetchCommonFiles(
                                     logger, mGceAvdInfo, getTestDeviceOptions(), getRunUtil());
diff --git a/src/com/android/tradefed/device/cloud/OxygenUtil.java b/src/com/android/tradefed/device/cloud/OxygenUtil.java
index aec9eac9d..94c21f014 100644
--- a/src/com/android/tradefed/device/cloud/OxygenUtil.java
+++ b/src/com/android/tradefed/device/cloud/OxygenUtil.java
@@ -235,6 +235,8 @@ public class OxygenUtil {
             List<String> cmdArgs =
                     Arrays.asList(
                             SystemUtil.getRunningJavaBinaryPath().getAbsolutePath(),
+                            "-Xmx256m",
+                            "-XX:G1HeapWastePercent=5",
                             "-jar",
                             file.getAbsolutePath());
             return new OxygenClient(cmdArgs);
diff --git a/src/com/android/tradefed/device/connection/AdbSshConnection.java b/src/com/android/tradefed/device/connection/AdbSshConnection.java
index 1547e4af7..31dab99bf 100644
--- a/src/com/android/tradefed/device/connection/AdbSshConnection.java
+++ b/src/com/android/tradefed/device/connection/AdbSshConnection.java
@@ -54,6 +54,7 @@ import com.android.tradefed.util.CommandStatus;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.MultiMap;
 import com.android.tradefed.util.StreamUtil;
+import com.android.tradefed.util.avd.HostOrchestratorClient;
 import com.android.tradefed.util.avd.HostOrchestratorUtil;
 
 import com.google.common.annotations.VisibleForTesting;
@@ -170,7 +171,9 @@ public class AdbSshConnection extends AdbTcpConnection {
                     break;
                 }
                 waitForTunnelOnline(WAIT_FOR_TUNNEL_ONLINE);
-                waitForAdbConnect(getDevice().getSerialNumber(), WAIT_FOR_ADB_CONNECT);
+                waitForAdbConnect(
+                        getDevice().getSerialNumber(),
+                        getDevice().getOptions().getAdbConnectWaitTime());
             }
         } finally {
             getDevice().setRecoveryMode(previousMode);
@@ -229,7 +232,7 @@ public class AdbSshConnection extends AdbTcpConnection {
                 getGceTunnelMonitor().closeConnection();
                 getRunUtil().sleep(WAIT_FOR_TUNNEL_OFFLINE);
                 waitForTunnelOnline(WAIT_FOR_TUNNEL_ONLINE);
-                waitForAdbConnect(serial, WAIT_FOR_ADB_CONNECT);
+                waitForAdbConnect(serial, getDevice().getOptions().getAdbConnectWaitTime());
                 InvocationMetricLogger.addInvocationMetrics(
                         InvocationMetricKey.DEVICE_RECOVERED_FROM_SSH_TUNNEL, 1);
             } catch (Exception e) {
@@ -282,30 +285,7 @@ public class AdbSshConnection extends AdbTcpConnection {
                     CLog.d("Device log collection is skipped per SkipDeviceLogCollection setting.");
                 } else if (getDevice().getOptions().useCvdCF()) {
                     mHOUtil = createHostOrchestratorUtil(mGceAvd);
-                    File cvdLogsDir = mHOUtil.pullCvdHostLogs();
-                    if (cvdLogsDir != null) {
-                        GceManager.logDirectory(
-                                cvdLogsDir, null, getLogger(), LogDataType.CUTTLEFISH_LOG);
-                        FileUtil.recursiveDelete(cvdLogsDir);
-                    } else {
-                        CLog.i("CVD Logs is null, no logs collected from host orchestrator.");
-                    }
-                    File tempFile =
-                            mHOUtil.collectLogByCommand(
-                                    "host_kernel", HostOrchestratorUtil.URL_HOST_KERNEL_LOG);
-                    GceManager.logAndDeleteFile(tempFile, "host_kernel", getLogger());
-                    tempFile =
-                            mHOUtil.collectLogByCommand(
-                                    "host_orchestrator", HostOrchestratorUtil.URL_HO_LOG);
-                    GceManager.logAndDeleteFile(tempFile, "host_orchestrator", getLogger());
-                    tempFile = mHOUtil.getTunnelLog();
-                    GceManager.logAndDeleteFile(
-                            tempFile, "host_orchestrator_tunnel_log", getLogger());
-                    tempFile =
-                            mHOUtil.collectLogByCommand(
-                                    "oxygen_container_log",
-                                    HostOrchestratorUtil.URL_OXYGEN_CONTAINER_LOG);
-                    GceManager.logAndDeleteFile(tempFile, "oxygen_container_log", getLogger());
+                    CommonLogRemoteFileUtil.pullCommonCvdLogs(mGceAvd, mHOUtil, getLogger());
                 } else if (mGceAvd.hostAndPort() != null) {
                     // Host and port can be null in case of acloud timeout
                     // attempt to get a bugreport if Gce Avd is a failure
@@ -695,6 +675,56 @@ public class AdbSshConnection extends AdbTcpConnection {
         return builtCommand;
     }
 
+    /**
+     * Attempt to delete snapshot of a Cuttlefish instance
+     *
+     * @param user the host running user of AVD, <code>null</code> if not applicable.
+     * @return returns CommandResult of the delete snapshot attempts
+     * @throws TargetSetupError
+     */
+    public CommandResult deleteSnapshotGce(String user, String snapshotId) throws TargetSetupError {
+        CommandResult deleteRes = null;
+        if (Strings.isNullOrEmpty(snapshotId)) {
+            throw new TargetSetupError(
+                    "SnapshotId was not passed to delete snapshot.",
+                    getDevice().getDeviceDescriptor(),
+                    DeviceErrorIdentifier.DEVICE_FAILED_TO_DELETE_SNAPSHOT);
+        }
+        if (mGceAvd == null) {
+            String errorMsg = "Can not get GCE AVD Info. launch GCE first?";
+            throw new TargetSetupError(
+                    errorMsg,
+                    getDevice().getDeviceDescriptor(),
+                    DeviceErrorIdentifier.DEVICE_UNAVAILABLE);
+        }
+        if (getDevice().getOptions().useCvdCF()) {
+            deleteRes = mHOUtil.deleteSnapshotGce(snapshotId);
+        } else {
+            // Get the user from options instance-user if user is null.
+            if (user == null) {
+                user = getDevice().getOptions().getInstanceUser();
+            }
+            String deleteSnapshotCmd =
+                    String.format("rm -r /tmp/%s/snapshots/%s", user, snapshotId);
+            deleteRes =
+                    getGceHandler()
+                            .remoteSshCommandExecution(
+                                    mGceAvd,
+                                    getDevice().getOptions(),
+                                    getRunUtil(),
+                                    Math.max(10000L, getDevice().getOptions().getGceCmdTimeout()),
+                                    deleteSnapshotCmd.split(" "));
+        }
+        if (!CommandStatus.SUCCESS.equals(deleteRes.getStatus())) {
+            CLog.e("%s", deleteRes.getStderr());
+            throw new TargetSetupError(
+                    String.format("failed to delete snapshot device: %s", deleteRes.getStderr()),
+                    getDevice().getDeviceDescriptor(),
+                    DeviceErrorIdentifier.DEVICE_FAILED_TO_DELETE_SNAPSHOT);
+        }
+        return deleteRes;
+    }
+
     /**
      * Attempt to snapshot a Cuttlefish instance
      *
@@ -804,13 +834,20 @@ public class AdbSshConnection extends AdbTcpConnection {
 
         if (!CommandStatus.SUCCESS.equals(restoreRes.getStatus())) {
             CLog.e("%s", restoreRes.getStderr());
+            DeviceErrorIdentifier identifier =
+                    DeviceErrorIdentifier.DEVICE_FAILED_TO_RESTORE_SNAPSHOT;
+            if (restoreRes.getStderr().contains("Not enough space remaining in fs containing")) {
+                identifier =
+                        DeviceErrorIdentifier.DEVICE_FAILED_TO_RESTORE_SNAPSHOT_NOT_ENOUGH_SPACE;
+            }
             throw new TargetSetupError(
                     String.format("failed to restore device: %s", restoreRes.getStderr()),
                     getDevice().getDeviceDescriptor(),
-                    DeviceErrorIdentifier.DEVICE_FAILED_TO_RESTORE_SNAPSHOT);
+                    identifier);
         }
         try {
-            waitForAdbConnect(getDevice().getSerialNumber(), WAIT_FOR_ADB_CONNECT);
+            waitForAdbConnect(
+                    getDevice().getSerialNumber(), getDevice().getOptions().getAdbConnectWaitTime());
             getDevice().waitForDeviceOnline(WAIT_FOR_DEVICE_ONLINE);
         } catch (DeviceNotAvailableException e) {
             CLog.e("%s", e.toString());
@@ -983,7 +1020,8 @@ public class AdbSshConnection extends AdbTcpConnection {
                             OxygenUtil.getTargetRegion(getDevice().getOptions()),
                             getDevice().getOptions().getOxygenAccountingUser(),
                             OxygenUtil.createOxygenClient(
-                                    getDevice().getOptions().getAvdDriverBinary()));
+                                    getDevice().getOptions().getAvdDriverBinary()),
+                            new HostOrchestratorClient.HoHttpClient());
         }
         return mHOUtil;
     }
diff --git a/src/com/android/tradefed/device/connection/AdbTcpConnection.java b/src/com/android/tradefed/device/connection/AdbTcpConnection.java
index 6e725f804..b513d74e2 100644
--- a/src/com/android/tradefed/device/connection/AdbTcpConnection.java
+++ b/src/com/android/tradefed/device/connection/AdbTcpConnection.java
@@ -46,7 +46,7 @@ public class AdbTcpConnection extends DefaultConnection {
     protected static final long RETRY_INTERVAL_MS = 5000;
     protected static final int MAX_RETRIES = 5;
     protected static final long DEFAULT_SHORT_CMD_TIMEOUT = 20 * 1000;
-    protected static final long WAIT_FOR_ADB_CONNECT = 2 * 60 * 1000;
+
     private static final String ADB_SUCCESS_CONNECT_TAG = "connected to";
     private static final String ADB_ALREADY_CONNECTED_TAG = "already";
     private static final String ADB_CONN_REFUSED = "Connection refused";
@@ -82,7 +82,7 @@ public class AdbTcpConnection extends DefaultConnection {
     public void reconnect(String serial) throws DeviceNotAvailableException {
         super.reconnect(serial);
         adbTcpConnect(getHostName(serial), getPortNum(serial));
-        waitForAdbConnect(serial, WAIT_FOR_ADB_CONNECT);
+        waitForAdbConnect(serial, getDevice().getOptions().getAdbConnectWaitTime());
     }
 
     /** {@inheritDoc} */
diff --git a/src/com/android/tradefed/device/internal/DeviceSnapshotFeature.java b/src/com/android/tradefed/device/internal/DeviceSnapshotFeature.java
index 934d37586..b8c511c5d 100644
--- a/src/com/android/tradefed/device/internal/DeviceSnapshotFeature.java
+++ b/src/com/android/tradefed/device/internal/DeviceSnapshotFeature.java
@@ -47,6 +47,7 @@ public class DeviceSnapshotFeature
     public static final String DEVICE_NAME = "device_name";
     public static final String SNAPSHOT_ID = "snapshot_id";
     public static final String RESTORE_FLAG = "restore_flag";
+    public static final String DELETE_FLAG = "delete_flag";
 
     private IConfiguration mConfig;
     private TestInformation mTestInformation;
@@ -104,8 +105,11 @@ public class DeviceSnapshotFeature
                 String user = info.getInstanceUser();
 
                 String snapshotId = request.getArgsMap().get(SNAPSHOT_ID);
+                boolean deleteFlag = Boolean.parseBoolean(request.getArgsMap().get(DELETE_FLAG));
                 boolean restoreFlag = Boolean.parseBoolean(request.getArgsMap().get(RESTORE_FLAG));
-                if (restoreFlag) {
+                if (deleteFlag) {
+                    deleteSnapshot(responseBuilder, connection, user, snapshotId);
+                } else if (restoreFlag) {
                     restoreSnapshot(responseBuilder, connection, user, offset, snapshotId);
                 } else {
                     snapshot(responseBuilder, connection, user, offset, snapshotId);
@@ -210,6 +214,43 @@ public class DeviceSnapshotFeature
         }
     }
 
+    private void deleteSnapshot(
+            FeatureResponse.Builder responseBuilder,
+            AbstractConnection connection,
+            String user,
+            String snapshotId)
+            throws DeviceNotAvailableException, TargetSetupError {
+        String response =
+                String.format(
+                        "Attempting delete device snapshot on %s (%s) to %s.",
+                        mTestInformation.getDevice().getSerialNumber(),
+                        mTestInformation.getDevice().getClass().getSimpleName(),
+                        snapshotId);
+        try {
+            long startTime = System.currentTimeMillis();
+            CommandResult result = deleteSnapshotGce(connection, user, snapshotId);
+            if (!CommandStatus.SUCCESS.equals(result.getStatus())) {
+                throw new DeviceNotAvailableException(
+                        String.format(
+                                "Failed to delete snapshot on device: %s. status:%s\n"
+                                        + "stdout: %s\n"
+                                        + "stderr:%s",
+                                mTestInformation.getDevice().getSerialNumber(),
+                                result.getStatus(),
+                                result.getStdout(),
+                                result.getStderr()),
+                        mTestInformation.getDevice().getSerialNumber(),
+                        DeviceErrorIdentifier.DEVICE_FAILED_TO_DELETE_SNAPSHOT);
+            }
+            response +=
+                    String.format(
+                            " Deleting snapshot finished in %d ms.",
+                            System.currentTimeMillis() - startTime);
+        } finally {
+            responseBuilder.setResponse(response);
+        }
+    }
+
     private GceAvdInfo getAvdInfo(ITestDevice device, AbstractConnection connection) {
         if (connection instanceof AdbSshConnection) {
             return ((AdbSshConnection) connection).getAvdInfo();
@@ -241,4 +282,14 @@ public class DeviceSnapshotFeature
         res.setStderr("Incorrect connection type while attempting device restore");
         return res;
     }
+
+    private CommandResult deleteSnapshotGce(
+            AbstractConnection connection, String user, String snapshotId) throws TargetSetupError {
+        if (connection instanceof AdbSshConnection) {
+            return ((AdbSshConnection) connection).deleteSnapshotGce(user, snapshotId);
+        }
+        CommandResult res = new CommandResult(CommandStatus.EXCEPTION);
+        res.setStderr("Incorrect connection type while attempting device delete");
+        return res;
+    }
 }
diff --git a/src/com/android/tradefed/device/internal/DeviceSnapshotHandler.java b/src/com/android/tradefed/device/internal/DeviceSnapshotHandler.java
index 59be57969..d6a9320c0 100644
--- a/src/com/android/tradefed/device/internal/DeviceSnapshotHandler.java
+++ b/src/com/android/tradefed/device/internal/DeviceSnapshotHandler.java
@@ -59,6 +59,63 @@ public class DeviceSnapshotHandler {
         mContext = context;
     }
 
+    /**
+     * Calls delete snapshot of the given device.
+     *
+     * @param device The device to delete a snapshot. Needed to get user.
+     * @param snapshotId Snapshot ID to delete.
+     * @return True if deleting snapshot was successful, false otherwise.
+     * @throws DeviceNotAvailableException
+     */
+    public void deleteSnapshot(ITestDevice device, String snapshotId)
+            throws DeviceNotAvailableException {
+        if (device.getIDevice() instanceof StubDevice) {
+            CLog.d(
+                    "Device '%s' is a stub device. skipping deleting snapshot.",
+                    device.getSerialNumber());
+            return;
+        }
+        FeatureResponse response;
+        try {
+            Map<String, String> args = new HashMap<>();
+            args.put(DeviceSnapshotFeature.SNAPSHOT_ID, snapshotId);
+            args.put(DeviceSnapshotFeature.DEVICE_NAME, mContext.getDeviceName(device));
+            args.put(DeviceSnapshotFeature.DELETE_FLAG, "true");
+            response =
+                    mClient.triggerFeature(
+                            DeviceSnapshotFeature.DEVICE_SNAPSHOT_FEATURE_NAME, args);
+            CLog.d(
+                    "Response from deleting snapshot(%s) request: %s",
+                    snapshotId, response.getResponse());
+        } finally {
+            mClient.close();
+        }
+        if (response.hasErrorInfo()) {
+            String trace = response.getErrorInfo().getErrorTrace();
+            // Handle if it's an exception error.
+            Object o = null;
+            try {
+                o = SerializationUtil.deserialize(trace);
+            } catch (IOException | RuntimeException e) {
+                CLog.e("Failed to deserialize delete snapshot error response: %s", e.getMessage());
+            }
+            if (o instanceof DeviceNotAvailableException) {
+                throw (DeviceNotAvailableException) o;
+            } else if (o instanceof IHarnessException) {
+                IHarnessException exception = (IHarnessException) o;
+                throw new HarnessRuntimeException("Exception while deleting snapshot.", exception);
+            } else if (o instanceof Exception) {
+                throw new HarnessRuntimeException(
+                        "Exception while deleting snapshot.",
+                        (Exception) o,
+                        InfraErrorIdentifier.UNDETERMINED);
+            }
+            throw new HarnessRuntimeException(
+                    "Exception while deleting snapshot. Unserialized error response: " + trace,
+                    InfraErrorIdentifier.UNDETERMINED);
+        }
+    }
+
     /**
      * Calls snapshot of the given device.
      *
diff --git a/src/com/android/tradefed/device/metric/FilePullerDeviceMetricCollector.java b/src/com/android/tradefed/device/metric/FilePullerDeviceMetricCollector.java
index 0bb773775..b71e5cd23 100644
--- a/src/com/android/tradefed/device/metric/FilePullerDeviceMetricCollector.java
+++ b/src/com/android/tradefed/device/metric/FilePullerDeviceMetricCollector.java
@@ -31,7 +31,8 @@ import java.io.IOException;
 import java.util.AbstractMap.SimpleEntry;
 import java.util.Arrays;
 import java.util.HashMap;
-import java.util.HashSet;
+import java.util.LinkedHashMap;
+import java.util.LinkedHashSet;
 import java.util.Map;
 import java.util.Map.Entry;
 import java.util.Set;
@@ -47,12 +48,12 @@ public abstract class FilePullerDeviceMetricCollector extends BaseDeviceMetricCo
             name = "pull-pattern-keys",
             description =
                     "The pattern key name to be pull from the device as a file. Can be repeated.")
-    private Set<String> mKeys = new HashSet<>();
+    private Set<String> mKeys = new LinkedHashSet<>();
 
     @Option(
             name = "directory-keys",
             description = "Path to the directory on the device that contains the metrics.")
-    protected Set<String> mDirectoryKeys = new HashSet<>();
+    protected Set<String> mDirectoryKeys = new LinkedHashSet<>();
 
     @Option(name = "compress-directories",
             description = "Compress multiple files in the matching directory into zip file")
@@ -72,7 +73,8 @@ public abstract class FilePullerDeviceMetricCollector extends BaseDeviceMetricCo
                         + " synchronous."
     )
     private boolean mCollectOnRunEndedOnly = true;
-    public Map<String, String> mTestCaseMetrics = new HashMap<String, String>();
+
+    public Map<String, String> mTestCaseMetrics = new LinkedHashMap<String, String>();
 
     @Override
     public void onTestEnd(DeviceMetricData testData, Map<String, Metric> currentTestCaseMetrics)
diff --git a/src/com/android/tradefed/device/metric/FilePullerLogCollector.java b/src/com/android/tradefed/device/metric/FilePullerLogCollector.java
index 2c53b6336..cebc45bf7 100644
--- a/src/com/android/tradefed/device/metric/FilePullerLogCollector.java
+++ b/src/com/android/tradefed/device/metric/FilePullerLogCollector.java
@@ -15,7 +15,9 @@
  */
 package com.android.tradefed.device.metric;
 
+import com.android.tradefed.config.Option;
 import com.android.tradefed.config.OptionClass;
+import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.result.FileInputStreamSource;
 import com.android.tradefed.result.InputStreamSource;
 import com.android.tradefed.result.LogDataType;
@@ -30,6 +32,10 @@ import java.io.File;
  */
 @OptionClass(alias = "file-puller-log-collector")
 public class FilePullerLogCollector extends FilePullerDeviceMetricCollector {
+    @Option(
+            name = "log-data-type",
+            description = "Type to assign to pulled logs (default: autodetect from extension)")
+    private String mLogDataType;
 
     @Override
     public final void processMetricFile(String key, File metricFile, DeviceMetricData runData) {
@@ -37,38 +43,51 @@ public class FilePullerLogCollector extends FilePullerDeviceMetricCollector {
             postProcessMetricFile(key, metricFile, runData);
         } finally {
             try (InputStreamSource source = new FileInputStreamSource(metricFile, true)) {
-                // Try to infer the type. This will be improved eventually, see todo on the class.
-                LogDataType type = LogDataType.TEXT;
-                String ext = FileUtil.getExtension(metricFile.getName()).toLowerCase();
-                if (".hprof".equals(ext)) {
-                    type = LogDataType.HPROF;
-                } else if (".mp4".equals(ext)) {
-                    type = LogDataType.MP4;
-                } else if (".pb".equals(ext)) {
-                    type = LogDataType.PB;
-                } else if (".png".equals(ext)) {
-                    type = LogDataType.PNG;
-                } else if (".perfetto-trace".equals(ext)) {
-                    type = LogDataType.PERFETTO;
-                } else if (".zip".equals(ext)) {
-                    type = LogDataType.ZIP;
-                } else if (".uix".equals(ext)) {
-                    type = LogDataType.UIX;
-                } else if (".textproto".equals(ext)
-                        && FileUtil.getBaseName(metricFile.getName()).contains("_goldResult")) {
-                    type = LogDataType.GOLDEN_RESULT_PROTO;
-                } else if (".trace".equals(ext)) {
-                    type = LogDataType.TRACE;
-                } else if (".log".equals(ext)) {
-                    type = LogDataType.BT_SNOOP_LOG;
-                } else if (".json".equals(ext)) {
-                    type = LogDataType.JSON;
-                }
+                LogDataType type = guessLogDataType(metricFile);
+
                 testLog(FileUtil.getBaseName(metricFile.getName()), type, source);
             }
         }
     }
 
+    private LogDataType guessLogDataType(File metricFile) {
+        if (mLogDataType != null && mLogDataType.length() > 0) {
+            try {
+                return LogDataType.valueOf(mLogDataType);
+            } catch (IllegalArgumentException e) {
+                CLog.e("Invalid log-data-type option: " + mLogDataType);
+            }
+        }
+
+        // Try to infer the type. This will be improved eventually, see todo on the class.
+        String ext = FileUtil.getExtension(metricFile.getName()).toLowerCase();
+        if (".hprof".equals(ext)) {
+            return LogDataType.HPROF;
+        } else if (".mp4".equals(ext)) {
+            return LogDataType.MP4;
+        } else if (".pb".equals(ext)) {
+            return LogDataType.PB;
+        } else if (".png".equals(ext)) {
+            return LogDataType.PNG;
+        } else if (".perfetto-trace".equals(ext)) {
+            return LogDataType.PERFETTO;
+        } else if (".zip".equals(ext)) {
+            return LogDataType.ZIP;
+        } else if (".uix".equals(ext)) {
+            return LogDataType.UIX;
+        } else if (".textproto".equals(ext)
+                && FileUtil.getBaseName(metricFile.getName()).contains("_goldResult")) {
+            return LogDataType.GOLDEN_RESULT_PROTO;
+        } else if (".trace".equals(ext)) {
+            return LogDataType.TRACE;
+        } else if (".log".equals(ext)) {
+            return LogDataType.BT_SNOOP_LOG;
+        } else if (".json".equals(ext)) {
+            return LogDataType.JSON;
+        }
+        return LogDataType.TEXT;
+    }
+
     @Override
     public void processMetricDirectory(
             String key, File metricDirectory, DeviceMetricData runData) {
diff --git a/src/com/android/tradefed/invoker/InvocationContext.java b/src/com/android/tradefed/invoker/InvocationContext.java
index a9fdec59d..f15b9e106 100644
--- a/src/com/android/tradefed/invoker/InvocationContext.java
+++ b/src/com/android/tradefed/invoker/InvocationContext.java
@@ -32,6 +32,7 @@ import com.android.tradefed.util.MultiMap;
 import com.android.tradefed.util.UniqueMultiMap;
 
 import com.google.common.base.Joiner;
+import com.google.common.collect.ImmutableSet;
 
 import java.io.IOException;
 import java.io.ObjectInputStream;
@@ -40,6 +41,7 @@ import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Map.Entry;
+import java.util.Set;
 
 /**
  * Generic implementation of a {@link IInvocationContext}.
@@ -452,4 +454,16 @@ public class InvocationContext implements IInvocationContext {
         }
         return context;
     }
+
+    /** Returns whether we detect presubmit based on trigger type. */
+    public static boolean isPresubmit(IInvocationContext context) {
+        Set<String> presubmitTrigger = ImmutableSet.of("WORK_NODE", "TREEHUGGER");
+        return presubmitTrigger.contains(context.getAttribute("trigger"));
+    }
+
+    /** Returns whether we detect on demand test invocation based on trigger type. */
+    public static boolean isOnDemand(IInvocationContext context) {
+        Set<String> abtdTrigger = ImmutableSet.of("TRYBOT", "ABTD");
+        return abtdTrigger.contains(context.getAttribute("trigger"));
+    }
 }
diff --git a/src/com/android/tradefed/invoker/TestInvocation.java b/src/com/android/tradefed/invoker/TestInvocation.java
index b1c1d975d..bdddf0865 100644
--- a/src/com/android/tradefed/invoker/TestInvocation.java
+++ b/src/com/android/tradefed/invoker/TestInvocation.java
@@ -1921,7 +1921,7 @@ public class TestInvocation implements ITestInvocation {
     }
 
     private void reportModuleSkip(IConfiguration config, ITestInvocationListener listener) {
-        if (!config.getSkipManager().reportSkippedModule()) {
+        if (!config.getSkipManager().reportInvocationSkippedModule()) {
             return;
         }
         // Make a heuristic determination of ABI.
@@ -1952,6 +1952,9 @@ public class TestInvocation implements ITestInvocation {
             moduleContext.addInvocationAttribute(
                     ModuleDefinition.MODULE_SKIPPED,
                     config.getSkipManager().getInvocationSkipReason());
+            moduleContext.addInvocationAttribute(
+                    ModuleDefinition.SPARSE_MODULE,
+                    "true");
             listener.testModuleStarted(moduleContext);
             listener.testModuleEnded();
         }
diff --git a/src/com/android/tradefed/result/ReportPassedTests.java b/src/com/android/tradefed/result/ReportPassedTests.java
index e6d4132ed..91ea7da75 100644
--- a/src/com/android/tradefed/result/ReportPassedTests.java
+++ b/src/com/android/tradefed/result/ReportPassedTests.java
@@ -26,6 +26,7 @@ import com.android.tradefed.testtype.suite.ModuleDefinition;
 import com.android.tradefed.util.FileUtil;
 
 import com.google.common.annotations.VisibleForTesting;
+import com.google.common.base.Strings;
 
 import java.io.File;
 import java.io.IOException;
@@ -36,6 +37,7 @@ import java.util.Map.Entry;
 public class ReportPassedTests extends CollectingTestListener
         implements IConfigurationReceiver, ISupportGranularResults {
 
+    private static final int MAX_TEST_CASES_BATCH = 500;
     private static final String PASSED_TEST_LOG = "passed_tests";
     private boolean mInvocationFailed = false;
     private ITestLogger mLogger;
@@ -131,16 +133,8 @@ public class ReportPassedTests extends CollectingTestListener
         if (mLogger == null || mPassedTests == null) {
             return;
         }
-        StringBuilder sb = new StringBuilder();
         for (TestRunResult result : getMergedTestRunResults()) {
-            sb.append(createFilters(result, getBaseName(result), false));
-        }
-        if (sb.length() > 0) {
-            try {
-                FileUtil.writeToFile(sb.toString(), mPassedTests, true);
-            } catch (IOException e) {
-                CLog.e(e);
-            }
+            gatherPassedTests(result, getBaseName(result), false);
         }
         if (mPassedTests.length() == 0) {
             CLog.d("No new filter for passed_test");
@@ -166,7 +160,7 @@ public class ReportPassedTests extends CollectingTestListener
         }
     }
 
-    private String createFilters(
+    private void gatherPassedTests(
             TestRunResult runResult, String baseName, boolean invocationFailure) {
         if (mShardIndex != null) {
             baseName = "shard_" + mShardIndex + " " + baseName;
@@ -175,8 +169,10 @@ public class ReportPassedTests extends CollectingTestListener
         if (!runResult.hasFailedTests() && !runResult.isRunFailure() && !invocationFailure) {
             sb.append(baseName);
             sb.append("\n");
-            return sb.toString();
+            writeToFile(sb.toString());
+            return;
         }
+        int i = 0;
         for (Entry<TestDescription, TestResult> res : runResult.getTestResults().entrySet()) {
             if (TestStatus.FAILURE.equals(res.getValue().getResultStatus())) {
                 continue;
@@ -187,19 +183,22 @@ public class ReportPassedTests extends CollectingTestListener
             }
             sb.append(baseName + " " + res.getKey().toString());
             sb.append("\n");
+            i++;
+            if (i > MAX_TEST_CASES_BATCH) {
+                writeToFile(sb.toString());
+                sb = new StringBuilder();
+                i = 0;
+            }
         }
-        return sb.toString();
+        writeToFile(sb.toString());
     }
 
-    private void gatherPassedTests(
-            TestRunResult runResult, String baseName, boolean invocationFailure) {
-        StringBuilder sb = new StringBuilder();
-        sb.append(createFilters(runResult, baseName, invocationFailure));
-        if (sb.length() == 0L) {
+    private void writeToFile(String toWrite) {
+        if (Strings.isNullOrEmpty(toWrite)) {
             return;
         }
         try {
-            FileUtil.writeToFile(sb.toString(), mPassedTests, true);
+            FileUtil.writeToFile(toWrite, mPassedTests, true);
         } catch (IOException e) {
             CLog.e(e);
         }
diff --git a/src/com/android/tradefed/result/proto/ModuleProtoResultReporter.java b/src/com/android/tradefed/result/proto/ModuleProtoResultReporter.java
index de992e1d0..728565213 100644
--- a/src/com/android/tradefed/result/proto/ModuleProtoResultReporter.java
+++ b/src/com/android/tradefed/result/proto/ModuleProtoResultReporter.java
@@ -40,15 +40,18 @@ public class ModuleProtoResultReporter extends FileProtoResultReporter {
     public static final String INVOCATION_ID_KEY = "invocation_id";
     private boolean mStopCache = false;
     private String mInvocationId = null;
+    private boolean mGranularResults = false;
 
     public ModuleProtoResultReporter() {
         setPeriodicWriting(false);
         setDelimitedOutput(false);
     }
 
-    public ModuleProtoResultReporter(IInvocationContext mainInvocationContext) {
+    public ModuleProtoResultReporter(
+            IInvocationContext mainInvocationContext, boolean granularResults) {
         this();
         copyAttributes(mainInvocationContext);
+        mGranularResults = granularResults;
     }
 
     @Override
@@ -68,7 +71,9 @@ public class ModuleProtoResultReporter extends FileProtoResultReporter {
 
     @Override
     public void processTestCaseEnded(TestRecord testCaseRecord) {
-        super.processTestCaseEnded(testCaseRecord);
+        if (mGranularResults) {
+            super.processTestCaseEnded(testCaseRecord);
+        }
         if (testCaseRecord.getStatus().equals(TestStatus.FAIL)) {
             mStopCache = true;
         }
@@ -76,7 +81,9 @@ public class ModuleProtoResultReporter extends FileProtoResultReporter {
 
     @Override
     public void processTestRunEnded(TestRecord runRecord, boolean moduleInProgress) {
-        super.processTestRunEnded(runRecord, moduleInProgress);
+        if (mGranularResults) {
+            super.processTestRunEnded(runRecord, moduleInProgress);
+        }
         if (runRecord.hasDebugInfo()) {
             mStopCache = true;
         }
diff --git a/src/com/android/tradefed/result/proto/StreamProtoReceiver.java b/src/com/android/tradefed/result/proto/StreamProtoReceiver.java
index fc75140fc..4515eda61 100644
--- a/src/com/android/tradefed/result/proto/StreamProtoReceiver.java
+++ b/src/com/android/tradefed/result/proto/StreamProtoReceiver.java
@@ -20,6 +20,7 @@ import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.result.ITestInvocationListener;
 import com.android.tradefed.result.proto.ProtoResultParser.TestLevel;
 import com.android.tradefed.result.proto.TestRecordProto.TestRecord;
+import com.android.tradefed.util.RunUtil;
 import com.android.tradefed.util.StreamUtil;
 import com.android.tradefed.util.TimeUtil;
 
@@ -29,6 +30,8 @@ import java.io.Closeable;
 import java.io.IOException;
 import java.net.ServerSocket;
 import java.net.Socket;
+import java.util.LinkedList;
+import java.util.Queue;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.atomic.AtomicBoolean;
@@ -52,11 +55,12 @@ public class StreamProtoReceiver implements Closeable {
     private long mExtraWaitTimeForEvents = 0L;
 
     private AtomicBoolean mJoinStarted = new AtomicBoolean(false);
+
     /**
      * Stop parsing events when this is set. This allows to avoid a thread parsing the events when
      * we don't expect them anymore.
      */
-    private AtomicBoolean mStopParsing = new AtomicBoolean(false);
+    protected AtomicBoolean mStopParsing = new AtomicBoolean(false);
 
     /**
      * Ctor.
@@ -155,16 +159,63 @@ public class StreamProtoReceiver implements Closeable {
         mEventReceiver.start();
     }
 
+    /** Internal thread class that will be parsing the test records asynchronously using a queue. */
+    private class EventParsingThread extends Thread {
+        private Queue<TestRecord> mTestRecordQueue;
+        private boolean mLastTestReceived = false;
+        private boolean mThreadInterrupted = false;
+
+        public EventParsingThread(Queue<TestRecord> testRecordQueue) {
+            super("ProtoEventParsingThread");
+            setDaemon(true);
+            this.mTestRecordQueue = testRecordQueue;
+        }
+
+        public void notifyLastTestReceived() {
+            mLastTestReceived = true;
+        }
+
+        @Override
+        public void interrupt() {
+            mThreadInterrupted = true;
+            super.interrupt();
+        }
+
+        @Override
+        public void run() {
+            Queue<TestRecord> processingQueue = new LinkedList<>();
+            while (!(mLastTestReceived && mTestRecordQueue.isEmpty()) && !mThreadInterrupted) {
+                if (!mTestRecordQueue.isEmpty()) {
+                    synchronized (mTestRecordQueue) {
+                        processingQueue.addAll(mTestRecordQueue);
+                        mTestRecordQueue.clear();
+                    }
+                    while (!processingQueue.isEmpty() && !mThreadInterrupted) {
+                        parse(processingQueue.poll());
+                    }
+                } else {
+                    RunUtil.getDefault().sleep(500L);
+                }
+            }
+            CLog.d("ProtoEventParsingThread done.");
+        }
+    }
+
     /** Internal receiver thread class with a socket. */
     private class EventReceiverThread extends Thread {
         private ServerSocket mSocket;
+        private Socket mClient;
         private CountDownLatch mCountDown;
+        private Queue<TestRecord> mTestRecordQueue;
+        EventParsingThread mEventParsingThread;
 
         public EventReceiverThread() throws IOException {
             super("ProtoEventReceiverThread");
             setDaemon(true);
             mSocket = new ServerSocket(DEFAULT_AVAILABLE_PORT);
             mCountDown = new CountDownLatch(1);
+            mTestRecordQueue = new LinkedList<>();
+            mEventParsingThread = new EventParsingThread(mTestRecordQueue);
         }
 
         protected int getLocalPort() {
@@ -179,22 +230,40 @@ public class StreamProtoReceiver implements Closeable {
             if (mSocket != null) {
                 mSocket.close();
             }
+            if (mClient != null) {
+                mClient.close();
+            }
+            if (mEventParsingThread.isAlive()) {
+                mEventParsingThread.interrupt();
+            }
         }
 
         @Override
         public void run() {
-            Socket client = null;
             try {
-                client = mSocket.accept();
+                mClient = mSocket.accept();
+                mEventParsingThread.start();
                 TestRecord received = null;
-                while ((received = TestRecord.parseDelimitedFrom(client.getInputStream()))
+                while ((received = TestRecord.parseDelimitedFrom(mClient.getInputStream()))
                         != null) {
-                    parse(received);
+                    synchronized (mTestRecordQueue) {
+                        mTestRecordQueue.add(received);
+                    }
+                }
+                // notify EventParsingThread of last test received so it can finish listening.
+                mEventParsingThread.notifyLastTestReceived();
+                // wait for the event parsing thread to finish
+                try {
+                    mEventParsingThread.join();
+                } catch (InterruptedException e) {
+                    // if EventReceiverThread is interrupted, interrupt the EventParsingThread
+                    mEventParsingThread.interrupt();
                 }
             } catch (IOException e) {
                 CLog.e(e);
+                mEventParsingThread.interrupt();
             } finally {
-                StreamUtil.close(client);
+                StreamUtil.close(mClient);
                 mCountDown.countDown();
             }
             CLog.d("ProtoEventReceiverThread done.");
diff --git a/src/com/android/tradefed/result/skipped/ArtifactsAnalyzer.java b/src/com/android/tradefed/result/skipped/ArtifactsAnalyzer.java
index ff68f3470..04630425e 100644
--- a/src/com/android/tradefed/result/skipped/ArtifactsAnalyzer.java
+++ b/src/com/android/tradefed/result/skipped/ArtifactsAnalyzer.java
@@ -23,6 +23,7 @@ import com.android.tradefed.build.content.ImageContentAnalyzer;
 import com.android.tradefed.build.content.TestContentAnalyzer;
 import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.device.NullDevice;
+import com.android.tradefed.invoker.InvocationContext;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.invoker.logger.InvocationMetricLogger;
 import com.android.tradefed.invoker.logger.InvocationMetricLogger.InvocationMetricKey;
@@ -83,7 +84,7 @@ public class ArtifactsAnalyzer {
         }
         BuildAnalysis finalReport = BuildAnalysis.mergeReports(reports);
         CLog.d("Build analysis report: %s", finalReport.toString());
-        boolean presubmit = "WORK_NODE".equals(information.getContext().getAttribute("trigger"));
+        boolean presubmit = InvocationContext.isPresubmit(information.getContext());
         // Do the analysis regardless
         if (finalReport.hasTestsArtifacts()) {
             if (mTestArtifactsAnalysisContent.isEmpty()) {
@@ -109,6 +110,7 @@ public class ArtifactsAnalyzer {
                         if (!analysisResults.hasSharedFolderChanges()) {
                             finalReport.addUnchangedModules(analysisResults.getUnchangedModules());
                         }
+                        finalReport.addImageDigestMapping(analysisResults.getImageToDigest());
                     }
                 } catch (RuntimeException e) {
                     CLog.e(e);
@@ -135,8 +137,7 @@ public class ArtifactsAnalyzer {
             deviceImageChanged =
                     !"true".equals(build.getBuildAttributes().get(DEVICE_IMAGE_NOT_CHANGED));
             if (context != null) {
-                boolean presubmit =
-                        "WORK_NODE".equals(information.getContext().getAttribute("trigger"));
+                boolean presubmit = InvocationContext.isPresubmit(information.getContext());
                 boolean hasOneDeviceAnalysis =
                         context.stream()
                                 .anyMatch(
diff --git a/src/com/android/tradefed/result/skipped/SkipContext.java b/src/com/android/tradefed/result/skipped/SkipContext.java
index d5aadcb5c..45435a77c 100644
--- a/src/com/android/tradefed/result/skipped/SkipContext.java
+++ b/src/com/android/tradefed/result/skipped/SkipContext.java
@@ -44,7 +44,12 @@ public class SkipContext {
 
     /** Reports whether to use caching or not. */
     public boolean shouldUseCache() {
-        return !presubmit; // For now, we only allow caching in postsubmit.
+        // TODO: Distinguish caching situation
+        return true;
+    }
+
+    public boolean isPresubmit() {
+        return presubmit;
     }
 
     public Map<String, Digest> getImageToDigest() {
diff --git a/src/com/android/tradefed/result/skipped/SkipFeature.java b/src/com/android/tradefed/result/skipped/SkipFeature.java
index 240b64665..898ad3922 100644
--- a/src/com/android/tradefed/result/skipped/SkipFeature.java
+++ b/src/com/android/tradefed/result/skipped/SkipFeature.java
@@ -16,6 +16,7 @@
 package com.android.tradefed.result.skipped;
 import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.IConfigurationReceiver;
+import com.android.tradefed.invoker.InvocationContext;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.service.IRemoteFeature;
@@ -80,40 +81,30 @@ public class SkipFeature
     public FeatureResponse execute(FeatureRequest request) {
         FeatureResponse.Builder responseBuilder = FeatureResponse.newBuilder();
         if (mConfig != null) {
-            // Currently only support presubmit
-            boolean presubmit = "WORK_NODE".equals(mInfo.getContext().getAttribute("trigger"));
-            if (mConfig.getSkipManager().reportSkippedModule()) {
-                MultiPartResponse.Builder multiPartBuilder = MultiPartResponse.newBuilder();
-                multiPartBuilder.addResponsePart(
-                        PartResponse.newBuilder()
-                                .setKey(DELIMITER_NAME)
-                                .setValue(ESCAPED_DELIMITER));
-                multiPartBuilder.addResponsePart(
-                        PartResponse.newBuilder()
-                                .setKey(PRESUBMIT)
-                                .setValue(Boolean.toString(presubmit)));
-                multiPartBuilder.addResponsePart(
-                        PartResponse.newBuilder()
-                                .setKey(SKIPPED_MODULES)
-                                .setValue(
-                                        Joiner.on(DELIMITER)
-                                                .join(
-                                                        mConfig.getSkipManager()
-                                                                .getUnchangedModules())));
-                multiPartBuilder.addResponsePart(
-                        PartResponse.newBuilder()
-                                .setKey(IMAGE_DIGESTS)
-                                .setValue(
-                                        Joiner.on(DELIMITER)
-                                                .join(
-                                                        serializeDigest(
-                                                                mConfig.getSkipManager()
-                                                                        .getImageToDigest()))));
-                responseBuilder.setMultiPartResponse(multiPartBuilder);
-            } else {
-                responseBuilder.setErrorInfo(
-                        ErrorInfo.newBuilder().setErrorTrace("report-module-skipped is disabled."));
-            }
+            boolean presubmit = InvocationContext.isPresubmit(mInfo.getContext());
+            MultiPartResponse.Builder multiPartBuilder = MultiPartResponse.newBuilder();
+            multiPartBuilder.addResponsePart(
+                    PartResponse.newBuilder().setKey(DELIMITER_NAME).setValue(ESCAPED_DELIMITER));
+            multiPartBuilder.addResponsePart(
+                    PartResponse.newBuilder()
+                            .setKey(PRESUBMIT)
+                            .setValue(Boolean.toString(presubmit)));
+            multiPartBuilder.addResponsePart(
+                    PartResponse.newBuilder()
+                            .setKey(SKIPPED_MODULES)
+                            .setValue(
+                                    Joiner.on(DELIMITER)
+                                            .join(mConfig.getSkipManager().getUnchangedModules())));
+            multiPartBuilder.addResponsePart(
+                    PartResponse.newBuilder()
+                            .setKey(IMAGE_DIGESTS)
+                            .setValue(
+                                    Joiner.on(DELIMITER)
+                                            .join(
+                                                    serializeDigest(
+                                                            mConfig.getSkipManager()
+                                                                    .getImageToDigest()))));
+            responseBuilder.setMultiPartResponse(multiPartBuilder);
         } else {
             responseBuilder.setErrorInfo(
                     ErrorInfo.newBuilder().setErrorTrace("Configuration not set."));
diff --git a/src/com/android/tradefed/result/skipped/SkipManager.java b/src/com/android/tradefed/result/skipped/SkipManager.java
index 373c63615..c1c190407 100644
--- a/src/com/android/tradefed/result/skipped/SkipManager.java
+++ b/src/com/android/tradefed/result/skipped/SkipManager.java
@@ -16,14 +16,18 @@
 package com.android.tradefed.result.skipped;
 
 import com.android.tradefed.build.content.ContentAnalysisContext;
+import com.android.tradefed.build.content.ContentAnalysisContext.AnalysisMethod;
+import com.android.tradefed.build.content.ContentModuleLister;
 import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.config.OptionClass;
 import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.invoker.IInvocationContext;
+import com.android.tradefed.invoker.InvocationContext;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.invoker.logger.InvocationMetricLogger;
 import com.android.tradefed.invoker.logger.InvocationMetricLogger.InvocationMetricKey;
+import com.android.tradefed.invoker.tracing.CloseableTraceScope;
 import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.result.skipped.SkipReason.DemotionTrigger;
 import com.android.tradefed.service.TradefedFeatureClient;
@@ -85,10 +89,11 @@ public class SkipManager implements IDisableable {
     private AnalysisHeuristic mAnalysisLevel = AnalysisHeuristic.REMOVE_EXEMPTION;
 
     @Option(
-            name = "report-module-skipped",
+            name = "report-invocation-skipped-module",
             description =
-                    "Report a placeholder skip when module are skipped as unchanged in presubmit.")
-    private boolean mReportModuleSkipped = true;
+                    "Report a placeholder skip when module are skipped as part of invocation"
+                            + " skipped.")
+    private boolean mReportInvocationModuleSkipped = true;
 
     // Contains the filter and reason for demotion
     private final Map<String, SkipReason> mDemotionFilters = new LinkedHashMap<>();
@@ -162,29 +167,53 @@ public class SkipManager implements IDisableable {
 
     /** Reports whether we should skip the current invocation. */
     public boolean shouldSkipInvocation(TestInformation information) {
-        // Build heuristic for skipping invocation
-        if (mNoTestsDiscovered) {
-            InvocationMetricLogger.addInvocationMetrics(
-                    InvocationMetricKey.SKIP_NO_TESTS_DISCOVERED, 1);
-            if (mSkipOnNoTestsDiscovered) {
-                mReasonForSkippingInvocation =
-                        "No tests to be executed where found in the configuration.";
-                return true;
-            } else {
+        try (CloseableTraceScope ignored =
+                new CloseableTraceScope("SkipManager#shouldSkipInvocation")) {
+            // Build heuristic for skipping invocation
+            if (!mNoTestsDiscovered && !mModulesDiscovered.isEmpty()) {
+                Set<String> possibleModules = new HashSet<>();
+                for (ContentAnalysisContext context : mTestArtifactsAnalysisContent) {
+                    if (context.analysisMethod().equals(AnalysisMethod.SANDBOX_WORKDIR)) {
+                        possibleModules.addAll(ContentModuleLister.buildModuleList(context));
+                    }
+                }
+                if (!possibleModules.isEmpty()) {
+                    CLog.d("Module existing in the zips: %s", possibleModules);
+                    Set<String> runnableModules = new HashSet<String>(mModulesDiscovered);
+                    runnableModules.retainAll(possibleModules);
+                    if (runnableModules.isEmpty()) {
+                        mNoTestsDiscovered = true;
+                        CLog.d(
+                                "discovered modules '%s' do not exists in zips.",
+                                mModulesDiscovered);
+                    }
+                }
+            }
+
+            if (mNoTestsDiscovered) {
                 InvocationMetricLogger.addInvocationMetrics(
-                        InvocationMetricKey.SILENT_INVOCATION_SKIP_COUNT, 1);
-                return false;
+                        InvocationMetricKey.SKIP_NO_TESTS_DISCOVERED, 1);
+                if (mSkipOnNoTestsDiscovered) {
+                    mReasonForSkippingInvocation =
+                            "No tests to be executed where found in the configuration.";
+                    return true;
+                } else {
+                    InvocationMetricLogger.addInvocationMetrics(
+                            InvocationMetricKey.SILENT_INVOCATION_SKIP_COUNT, 1);
+                    return false;
+                }
             }
+
+            ArtifactsAnalyzer analyzer =
+                    new ArtifactsAnalyzer(
+                            information,
+                            mImageAnalysis,
+                            mTestArtifactsAnalysisContent,
+                            mModulesDiscovered,
+                            mDependencyFiles,
+                            mAnalysisLevel);
+            return buildAnalysisDecision(information, analyzer.analyzeArtifacts());
         }
-        ArtifactsAnalyzer analyzer =
-                new ArtifactsAnalyzer(
-                        information,
-                        mImageAnalysis,
-                        mTestArtifactsAnalysisContent,
-                        mModulesDiscovered,
-                        mDependencyFiles,
-                        mAnalysisLevel);
-        return buildAnalysisDecision(information, analyzer.analyzeArtifacts());
     }
 
     /**
@@ -195,7 +224,7 @@ public class SkipManager implements IDisableable {
         if (isDisabled()) {
             return;
         }
-        if ("WORK_NODE".equals(context.getAttribute("trigger"))) {
+        if (InvocationContext.isPresubmit(context)) {
             try (TradefedFeatureClient client = new TradefedFeatureClient()) {
                 Map<String, String> args = new HashMap<>();
                 FeatureResponse response = client.triggerFeature("FetchDemotionInformation", args);
@@ -224,7 +253,7 @@ public class SkipManager implements IDisableable {
             return false;
         }
         mImageFileToDigest.putAll(results.getImageToDigest());
-        boolean presubmit = "WORK_NODE".equals(information.getContext().getAttribute("trigger"));
+        boolean presubmit = InvocationContext.isPresubmit(information.getContext());
         if (results.deviceImageChanged()) {
             return false;
         }
@@ -310,7 +339,7 @@ public class SkipManager implements IDisableable {
         return mReasonForSkippingInvocation;
     }
 
-    public boolean reportSkippedModule() {
-        return mReportModuleSkipped;
+    public boolean reportInvocationSkippedModule() {
+        return mReportInvocationModuleSkipped;
     }
 }
diff --git a/src/com/android/tradefed/retry/BaseRetryDecision.java b/src/com/android/tradefed/retry/BaseRetryDecision.java
index 2eadb309c..b609722f0 100644
--- a/src/com/android/tradefed/retry/BaseRetryDecision.java
+++ b/src/com/android/tradefed/retry/BaseRetryDecision.java
@@ -26,6 +26,7 @@ import com.android.tradefed.device.internal.DeviceResetHandler;
 import com.android.tradefed.device.internal.DeviceSnapshotHandler;
 import com.android.tradefed.error.HarnessRuntimeException;
 import com.android.tradefed.invoker.IInvocationContext;
+import com.android.tradefed.invoker.InvocationContext;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.invoker.logger.CurrentInvocation;
 import com.android.tradefed.invoker.logger.CurrentInvocation.IsolationGrade;
@@ -195,7 +196,7 @@ public class BaseRetryDecision
             // No need to retry if it reaches the maximum retry count.
             return decision;
         }
-        if (mSkipRetryInPresubmit && "WORK_NODE".equals(mContext.getAttribute("trigger"))) {
+        if (mSkipRetryInPresubmit && InvocationContext.isPresubmit(mContext)) {
             CLog.d("Skipping retry due to --skip-retry-in-presubmit");
             return decision;
         }
@@ -264,7 +265,7 @@ public class BaseRetryDecision
             mPreviouslyFailing = new HashSet<>();
         }
 
-        if (mSkipRetryInPresubmit && "WORK_NODE".equals(mContext.getAttribute("trigger"))) {
+        if (mSkipRetryInPresubmit && InvocationContext.isPresubmit(mContext)) {
             CLog.d("Skipping retry due to --skip-retry-in-presubmit");
             return false;
         }
@@ -596,22 +597,7 @@ public class BaseRetryDecision
         for (TestDescription testCase : passedTests) {
             String filter = String.format("%s#%s", testCase.getClassName(), testCase.getTestName());
             if (test instanceof ITestFileFilterReceiver) {
-                File excludeFilterFile = ((ITestFileFilterReceiver) test).getExcludeTestFile();
-                if (excludeFilterFile == null) {
-                    try {
-                        excludeFilterFile = FileUtil.createTempFile("exclude-filter", ".txt");
-                    } catch (IOException e) {
-                        throw new HarnessRuntimeException(
-                                e.getMessage(), e, InfraErrorIdentifier.FAIL_TO_CREATE_FILE);
-                    }
-                    ((ITestFileFilterReceiver) test).setExcludeTestFile(excludeFilterFile);
-                }
-                try {
-                    FileUtil.writeToFile(filter + "\n", excludeFilterFile, true);
-                } catch (IOException e) {
-                    CLog.e(e);
-                    continue;
-                }
+                addFilterToExcludeFilterFile((ITestFileFilterReceiver) test, filter);
             } else {
                 test.addExcludeFilter(filter);
             }
@@ -634,14 +620,22 @@ public class BaseRetryDecision
                 // If a test case failure is not retriable, exclude it from the filters.
                 String filter =
                         String.format("%s#%s", testCase.getClassName(), testCase.getTestName());
-                test.addExcludeFilter(filter);
+                if (test instanceof ITestFileFilterReceiver) {
+                    addFilterToExcludeFilterFile((ITestFileFilterReceiver) test, filter);
+                } else {
+                    test.addExcludeFilter(filter);
+                }
                 failedTests.remove(testCase);
             }
             if (skipListForModule.contains(testCase.toString())) {
                 // If a test case failure is excluded from retry, exclude it
                 String filter =
                         String.format("%s#%s", testCase.getClassName(), testCase.getTestName());
-                test.addExcludeFilter(filter);
+                if (test instanceof ITestFileFilterReceiver) {
+                    addFilterToExcludeFilterFile((ITestFileFilterReceiver) test, filter);
+                } else {
+                    test.addExcludeFilter(filter);
+                }
                 InvocationMetricLogger.addInvocationMetrics(
                         InvocationMetricKey.RETRY_TEST_SKIPPED_COUNT, 1);
                 failedTests.remove(testCase);
@@ -652,6 +646,24 @@ public class BaseRetryDecision
         return failedTests.isEmpty();
     }
 
+    private void addFilterToExcludeFilterFile(ITestFileFilterReceiver test, String filter) {
+        File excludeFilterFile = test.getExcludeTestFile();
+        if (excludeFilterFile == null) {
+            try {
+                excludeFilterFile = FileUtil.createTempFile("exclude-filter", ".txt");
+            } catch (IOException e) {
+                throw new HarnessRuntimeException(
+                        e.getMessage(), e, InfraErrorIdentifier.FAIL_TO_CREATE_FILE);
+            }
+            ((ITestFileFilterReceiver) test).setExcludeTestFile(excludeFilterFile);
+        }
+        try {
+            FileUtil.writeToFile(filter + "\n", excludeFilterFile, true);
+        } catch (IOException e) {
+            CLog.e(e);
+        }
+    }
+
     /** Returns all the non-stub device associated with the {@link IRemoteTest}. */
     private List<ITestDevice> getDevices() {
         List<ITestDevice> listDevices = new ArrayList<>(mContext.getDevices());
diff --git a/src/com/android/tradefed/sandbox/TradefedSandbox.java b/src/com/android/tradefed/sandbox/TradefedSandbox.java
index 2289b9378..58bb6ced3 100644
--- a/src/com/android/tradefed/sandbox/TradefedSandbox.java
+++ b/src/com/android/tradefed/sandbox/TradefedSandbox.java
@@ -75,6 +75,7 @@ import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.util.ArrayList;
 import java.util.Arrays;
+import java.util.HashMap;
 import java.util.HashSet;
 import java.util.LinkedHashSet;
 import java.util.List;
@@ -93,6 +94,18 @@ public class TradefedSandbox implements ISandbox {
 
     private static final String SANDBOX_JVM_OPTIONS_ENV_VAR_KEY = "TF_SANDBOX_JVM_OPTIONS";
 
+    // Target name to map to lab specific downloads.
+    public static final String EXTRA_TARGET_LAB = "lab";
+
+    public static final String GENERAL_TESTS_ZIP = "general-tests.zip";
+    private static final Map<String, String> EXTRA_TARGETS = new HashMap<>();
+
+    static {
+        // TODO: Replace by SandboxOptions
+        EXTRA_TARGETS.put(EXTRA_TARGET_LAB, GENERAL_TESTS_ZIP);
+        EXTRA_TARGETS.put("cts", "android-cts.zip");
+    }
+
     private File mStdoutFile = null;
     private File mStderrFile = null;
     private File mHeapDump = null;
@@ -694,4 +707,17 @@ public class TradefedSandbox implements ISandbox {
     private File getWorkFolder() {
         return CurrentInvocation.getWorkFolder();
     }
+
+    /**
+     * Given the test config name, match the extra build targets from Sandbox's extra build targets.
+     */
+    public static Set<String> matchSandboxExtraBuildTargetByConfigName(String configName) {
+        Set<String> extraBuildTarget = new HashSet<>();
+        for (Entry<String, String> possibleTargets : EXTRA_TARGETS.entrySet()) {
+            if (configName.contains(possibleTargets.getKey())) {
+                extraBuildTarget.add(possibleTargets.getValue());
+            }
+        }
+        return extraBuildTarget;
+    }
 }
diff --git a/src/com/android/tradefed/service/management/DeviceManagementGrpcServer.java b/src/com/android/tradefed/service/management/DeviceManagementGrpcServer.java
index 88c4769f3..a5ba66dc6 100644
--- a/src/com/android/tradefed/service/management/DeviceManagementGrpcServer.java
+++ b/src/com/android/tradefed/service/management/DeviceManagementGrpcServer.java
@@ -31,6 +31,7 @@ import com.proto.tradefed.device.StopLeasingResponse;
 
 import io.grpc.Server;
 import io.grpc.ServerBuilder;
+import io.grpc.StatusRuntimeException;
 import io.grpc.stub.ServerCallStreamObserver;
 import io.grpc.stub.StreamObserver;
 
@@ -234,20 +235,17 @@ public class DeviceManagementGrpcServer extends DeviceManagementImplBase {
                 mSerialToReservation.put(serial, new ReservationInformation(device, reservationId));
             }
         }
-        // Double check isCancelled because the client may cancel the RPC when allocating device.
-        if (serverCallStreamObserver.isCancelled()) {
-            CLog.d("The client call is cancelled.");
+
+        try {
+            responseObserver.onNext(responseBuilder.build());
+            responseObserver.onCompleted();
+        } catch (StatusRuntimeException e) {
+            CLog.w("The client call is cancelled. %s", e.getMessage());
             if (responseBuilder.getResult().equals(Result.SUCCEED)
-                    && !responseBuilder.getReservationId().isEmpty()) {
+                && !responseBuilder.getReservationId().isEmpty()) {
                 releaseReservationInternal(responseBuilder.getReservationId());
             }
-            responseBuilder
-                    .clear()
-                    .setResult(Result.UNKNOWN)
-                    .setMessage("The device reservation RPC is cancelled by client.");
         }
-        responseObserver.onNext(responseBuilder.build());
-        responseObserver.onCompleted();
     }
 
     @Override
diff --git a/src/com/android/tradefed/service/management/TestInvocationManagementServer.java b/src/com/android/tradefed/service/management/TestInvocationManagementServer.java
index 85e26e0b4..d0b62dcbe 100644
--- a/src/com/android/tradefed/service/management/TestInvocationManagementServer.java
+++ b/src/com/android/tradefed/service/management/TestInvocationManagementServer.java
@@ -151,7 +151,13 @@ public class TestInvocationManagementServer extends TestInvocationManagementImpl
         String[] command = request.getArgsList().toArray(new String[0]);
         File record = null;
         try {
-            record = FileUtil.createTempFile("test_record", ".pb");
+            // For Cloud ATE, use shared directory for sharing the record file.
+            if(System.getenv("IS_CLOUD_ATE") != null) {
+                File shared = new File("/tmp/cloud-ate-shared/");
+                record = FileUtil.createTempFile("test_record", ".pb", shared);
+            } else {
+                record = FileUtil.createTempFile("test_record", ".pb");
+            }
             CommandStatusHandler handler = new CommandStatusHandler();
             FileProtoResultReporter fileReporter = new FileProtoResultReporter();
             fileReporter.setOutputFile(record);
diff --git a/src/com/android/tradefed/suite/checker/baseline/LockSettingsBaselineSetter.java b/src/com/android/tradefed/suite/checker/baseline/LockSettingsBaselineSetter.java
index f0dba8629..80b3b8910 100644
--- a/src/com/android/tradefed/suite/checker/baseline/LockSettingsBaselineSetter.java
+++ b/src/com/android/tradefed/suite/checker/baseline/LockSettingsBaselineSetter.java
@@ -35,6 +35,7 @@ public class LockSettingsBaselineSetter extends DeviceBaselineSetter {
     private static final String LOCK_SCREEN_OFF_COMMAND = "locksettings set-disabled true";
     private static final String CLEAR_PWD_COMMAND = "locksettings clear --old %s";
     private static final String KEYCODE_MENU_COMMAND = "input keyevent KEYCODE_MENU";
+    private static final String KEYCODE_HOME_COMMAND = "input keyevent KEYCODE_HOME";
 
     public LockSettingsBaselineSetter(JSONObject object, String name) throws JSONException {
         super(object, name);
@@ -59,8 +60,10 @@ public class LockSettingsBaselineSetter extends DeviceBaselineSetter {
         if (!isLockScreenDisabled(mDevice)) {
             return false;
         }
-        CommandResult result = mDevice.executeShellV2Command(KEYCODE_MENU_COMMAND);
-        return CommandStatus.SUCCESS.equals(result.getStatus());
+        CommandResult menuResult = mDevice.executeShellV2Command(KEYCODE_MENU_COMMAND);
+        CommandResult homeResult = mDevice.executeShellV2Command(KEYCODE_HOME_COMMAND);
+        return CommandStatus.SUCCESS.equals(menuResult.getStatus())
+                && CommandStatus.SUCCESS.equals(homeResult.getStatus());
     }
 
     private boolean isLockScreenDisabled(ITestDevice mDevice) throws DeviceNotAvailableException {
diff --git a/src/com/android/tradefed/targetprep/DefaultTestsZipInstaller.java b/src/com/android/tradefed/targetprep/DefaultTestsZipInstaller.java
index e5ab6aeee..a8e1f4935 100644
--- a/src/com/android/tradefed/targetprep/DefaultTestsZipInstaller.java
+++ b/src/com/android/tradefed/targetprep/DefaultTestsZipInstaller.java
@@ -24,7 +24,6 @@ import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.device.ITestDevice.RecoveryMode;
 import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.util.ArrayUtil;
-import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.IRunUtil;
 import com.android.tradefed.util.RunUtil;
 
@@ -34,14 +33,12 @@ import java.util.Collection;
 import java.util.HashSet;
 import java.util.Set;
 
-
 /**
  * A default implementation of tests zip installer.
  */
 public class DefaultTestsZipInstaller implements ITestsZipInstaller {
     private static final int RM_ATTEMPTS = 3;
     private static final String DEVICE_DATA_PATH = buildAbsPath(FileListingService.DIRECTORY_DATA);
-    private static final File DEVICE_DATA_FILE = new File(DEVICE_DATA_PATH);
 
     /**
      * A list of /data subdirectories to NOT wipe when doing UserDataFlashOption.TESTS_ZIP
@@ -127,10 +124,7 @@ public class DefaultTestsZipInstaller implements ITestsZipInstaller {
             device.syncFiles(hostSubDir, DEVICE_DATA_PATH);
         }
 
-        // FIXME: this may end up mixing host slashes and device slashes
-        for (File dir : findDirs(hostDir, DEVICE_DATA_FILE)) {
-            device.executeShellCommand("chown system.system " + dir.getPath());
-        }
+        device.executeShellCommand("chown -R system.system " + DEVICE_DATA_PATH);
 
         device.setRecoveryMode(cachedRecoveryMode);
     }
@@ -250,11 +244,4 @@ public class DefaultTestsZipInstaller implements ITestsZipInstaller {
         }
         return childFiles;
     }
-
-    /**
-     * Indirection to {@link FileUtil#findDirsUnder(File, File)} to allow for unit testing.
-     */
-    Set<File> findDirs(File hostDir, File deviceRootPath) {
-        return FileUtil.findDirsUnder(hostDir, deviceRootPath);
-    }
 }
diff --git a/src/com/android/tradefed/targetprep/DeviceFlashPreparer.java b/src/com/android/tradefed/targetprep/DeviceFlashPreparer.java
index afe159b14..668682ba1 100644
--- a/src/com/android/tradefed/targetprep/DeviceFlashPreparer.java
+++ b/src/com/android/tradefed/targetprep/DeviceFlashPreparer.java
@@ -47,7 +47,6 @@ import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.IRunUtil;
-import com.android.tradefed.util.MultiMap;
 import com.android.tradefed.util.RunUtil;
 import com.android.tradefed.util.image.DeviceImageTracker;
 import com.android.tradefed.util.image.IncrementalImageUtil;
@@ -55,6 +54,8 @@ import com.android.tradefed.util.image.IncrementalImageUtil;
 import java.io.File;
 import java.util.ArrayList;
 import java.util.Collection;
+import java.util.HashSet;
+import java.util.Set;
 import java.util.concurrent.TimeUnit;
 
 /** A {@link ITargetPreparer} that flashes an image on physical Android hardware. */
@@ -178,7 +179,7 @@ public abstract class DeviceFlashPreparer extends BaseTargetPreparer
             description =
                     "Whether to apply the snapshot after mounting it. "
                             + "This changes the baseline and does require reverting.")
-    private boolean mApplySnapshot = false;
+    private boolean mApplySnapshot = true;
 
     @Option(
             name = "wipe-after-apply-snapshot",
@@ -190,6 +191,11 @@ public abstract class DeviceFlashPreparer extends BaseTargetPreparer
             description = "A new update flow possible with latest incremental features.")
     private boolean mNewIncrementalFlow = false;
 
+    @Option(
+            name = "update-bootloader-in-userspace",
+            description = "Allow to update bootloader in userspace in new flow of incremental.")
+    private boolean mUpdateBootloaderFromUserspace = false;
+
     @Option(
             name = "snapuserd-wait-phase",
             description =
@@ -208,7 +214,7 @@ public abstract class DeviceFlashPreparer extends BaseTargetPreparer
 
     private IncrementalImageUtil mIncrementalImageUtil;
     private IConfiguration mConfig;
-    private MultiMap<String, String> mAllowedBranchTransition = new MultiMap<>();
+    private Set<String> mAllowedTransition = new HashSet<>();
 
     @Override
     public void setConfiguration(IConfiguration configuration) {
@@ -351,10 +357,11 @@ public abstract class DeviceFlashPreparer extends BaseTargetPreparer
                                 mCreateSnapshotBinary,
                                 isIsolated,
                                 mAllowIncrementalCrossRelease,
-                                mAllowedBranchTransition,
+                                mAllowedTransition,
                                 mApplySnapshot,
                                 mWipeAfterApplySnapshot,
                                 mNewIncrementalFlow,
+                                mUpdateBootloaderFromUserspace,
                                 mWaitPhase);
                 if (mIncrementalImageUtil == null) {
                     useIncrementalFlashing = false;
@@ -520,42 +527,45 @@ public abstract class DeviceFlashPreparer extends BaseTargetPreparer
 
     private void moveBaseline(
             IDeviceBuildInfo deviceBuild, String serial, boolean useIncrementalFlashing) {
-        if (!getHostOptions().isOptOutOfIncrementalFlashing()) {
-            boolean moveBaseLine = true;
-            if (!mUseIncrementalFlashing || useIncrementalFlashing) {
-                // Do not move baseline if using incremental flashing
-                moveBaseLine = false;
-            }
-            if (mApplySnapshot) {
-                // Move baseline when going with incremental + apply update
-                moveBaseLine = true;
-            }
-            if (moveBaseLine) {
-                File deviceImage = deviceBuild.getDeviceImageFile();
-                File tmpReference = null;
-                try {
-                    if (mAllowUnzippedBaseline
-                            && mIncrementalImageUtil != null
-                            && mIncrementalImageUtil.getExtractedTargetDirectory() != null
-                            && mIncrementalImageUtil.getExtractedTargetDirectory().isDirectory()) {
-                        CLog.d(
-                                "Using unzipped baseline: %s",
-                                mIncrementalImageUtil.getExtractedTargetDirectory());
-                        tmpReference = mIncrementalImageUtil.getExtractedTargetDirectory();
-                        deviceImage = tmpReference;
-                    }
-                    DeviceImageTracker.getDefaultCache()
-                            .trackUpdatedDeviceImage(
-                                    serial,
-                                    deviceImage,
-                                    deviceBuild.getBootloaderImageFile(),
-                                    deviceBuild.getBasebandImageFile(),
-                                    deviceBuild.getBuildId(),
-                                    deviceBuild.getBuildBranch(),
-                                    deviceBuild.getBuildFlavor());
-                } finally {
-                    FileUtil.recursiveDelete(tmpReference);
+        if (getHostOptions().isOptOutOfIncrementalFlashing()) {
+            CLog.d("Opt out of incremental via host_options");
+            return;
+        }
+        boolean moveBaseLine = true;
+        if (!mUseIncrementalFlashing || useIncrementalFlashing) {
+            // Do not move baseline if using incremental flashing
+            moveBaseLine = false;
+        }
+        if (mApplySnapshot) {
+            // Move baseline when going with incremental + apply update
+            moveBaseLine = true;
+        }
+        if (moveBaseLine) {
+            File deviceImage = deviceBuild.getDeviceImageFile();
+            File tmpReference = null;
+            try {
+                if (mAllowUnzippedBaseline
+                        && mIncrementalImageUtil != null
+                        && mIncrementalImageUtil.getExtractedTargetDirectory() != null
+                        && mIncrementalImageUtil.getExtractedTargetDirectory().isDirectory()) {
+                    CLog.d(
+                            "Using unzipped baseline: %s",
+                            mIncrementalImageUtil.getExtractedTargetDirectory());
+                    tmpReference = mIncrementalImageUtil.getExtractedTargetDirectory();
+                    deviceImage = tmpReference;
                 }
+
+                DeviceImageTracker.getDefaultCache()
+                        .trackUpdatedDeviceImage(
+                                serial,
+                                deviceImage,
+                                deviceBuild.getBootloaderImageFile(),
+                                deviceBuild.getBasebandImageFile(),
+                                deviceBuild.getBuildId(),
+                                deviceBuild.getBuildBranch(),
+                                deviceBuild.getBuildFlavor());
+            } finally {
+                FileUtil.recursiveDelete(tmpReference);
             }
         }
     }
@@ -696,6 +706,14 @@ public abstract class DeviceFlashPreparer extends BaseTargetPreparer
         mWipeAfterApplySnapshot = wipeAfterApplySnapshot;
     }
 
+    public void setUseIncrementalNewFlow(boolean useIncrementalNewFlow) {
+        mNewIncrementalFlow = useIncrementalNewFlow;
+    }
+
+    public void setUpdateBootloaderFromUserspace(boolean updateBootloaderFromUserspace) {
+        mUpdateBootloaderFromUserspace = updateBootloaderFromUserspace;
+    }
+
     public void setAllowUnzipBaseline(boolean allowUnzipBaseline) {
         mAllowUnzippedBaseline = allowUnzipBaseline;
     }
@@ -704,7 +722,13 @@ public abstract class DeviceFlashPreparer extends BaseTargetPreparer
         mIgnoreHostOptions = ignoreHostOptions;
     }
 
+    @Deprecated
     public void addBranchTransitionInIncremental(String origin, String destination) {
-        mAllowedBranchTransition.put(origin, destination);
+        mAllowedTransition.add(origin);
+        mAllowedTransition.add(destination);
+    }
+
+    public void addAllowedBranchForTransitionInIncremental(String branch) {
+        mAllowedTransition.add(branch);
     }
 }
diff --git a/src/com/android/tradefed/targetprep/DeviceSetup.java b/src/com/android/tradefed/targetprep/DeviceSetup.java
index 9b997d27c..9692a792d 100644
--- a/src/com/android/tradefed/targetprep/DeviceSetup.java
+++ b/src/com/android/tradefed/targetprep/DeviceSetup.java
@@ -1396,6 +1396,16 @@ public class DeviceSetup extends BaseTargetPreparer implements IExternalDependen
                         dismissed = true;
                         break;
                     } else {
+                        // abort the check if package service is unavailable
+                        if (dumpsysCmdOut.getStderr() != null
+                                && dumpsysCmdOut
+                                        .getStderr()
+                                        .contains("Can't find service: package")) {
+                            CLog.d(
+                                    "package service is not available. Skip checking setup wizard"
+                                            + " dismissal.");
+                            break;
+                        }
                         // Log the package cmd output for debugging purpose
                         CLog.d("Package cmd output: %s", pkgCmdOut.getStdout());
                         CLog.d("Package cmd stderr: %s", pkgCmdOut.getStderr());
@@ -1406,6 +1416,12 @@ public class DeviceSetup extends BaseTargetPreparer implements IExternalDependen
                     break;
                 }
             } else {
+                // abort the check if window service is unavailable
+                if (dumpsysCmdOut.getStderr() != null
+                        && dumpsysCmdOut.getStderr().contains("Can't find service: window")) {
+                    CLog.d("window service is not available. Skip checking setupwizard dismissal.");
+                    break;
+                }
                 // Log the dumpsys cmd output for debugging purpose
                 CLog.d("Dumpsys cmd output: %s", dumpsysCmdOut.getStdout());
                 CLog.d("Dumpsys cmd stderr: %s", dumpsysCmdOut.getStderr());
diff --git a/src/com/android/tradefed/targetprep/FastbootDeviceFlasher.java b/src/com/android/tradefed/targetprep/FastbootDeviceFlasher.java
index 5e44c14ba..5a6a08c7b 100644
--- a/src/com/android/tradefed/targetprep/FastbootDeviceFlasher.java
+++ b/src/com/android/tradefed/targetprep/FastbootDeviceFlasher.java
@@ -200,7 +200,9 @@ public class FastbootDeviceFlasher implements IDeviceFlasher {
             }
         }
 
-        if (mIncrementalFlashing != null && mIncrementalFlashing.useUpdatedFlow()) {
+        if (mIncrementalFlashing != null
+                && mIncrementalFlashing.useUpdatedFlow()
+                && shouldFlashSystem(mSystemBuildId, mSystemBuildFlavor, deviceBuild)) {
             try {
                 mIncrementalFlashing.updateDeviceWithNewFlow(
                         deviceBuild.getBootloaderImageFile(), deviceBuild.getBasebandImageFile());
diff --git a/src/com/android/tradefed/targetprep/GkiDeviceFlashPreparer.java b/src/com/android/tradefed/targetprep/GkiDeviceFlashPreparer.java
index 7524baa27..2f1534acd 100644
--- a/src/com/android/tradefed/targetprep/GkiDeviceFlashPreparer.java
+++ b/src/com/android/tradefed/targetprep/GkiDeviceFlashPreparer.java
@@ -79,7 +79,7 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
     private static final String OTATOOLS_ZIP = "otatools.zip";
     private static final String KERNEL_IMAGE = "Image.gz";
     // Wait time for device state to stablize in millisecond
-    private static final int STATE_STABLIZATION_WAIT_TIME = 60000;
+    private static final int STATE_STABLIZATION_WAIT_TIME = 10000;
 
     @Option(
             name = "device-boot-time",
@@ -133,6 +133,11 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
                     "The file name in BuildInfo that provides system_dlkm_staging_archive.tar.gz.")
     private String mSystemDlkmArchiveName = "system_dlkm_staging_archive.tar.gz";
 
+    @Option(
+            name = "vbmeta-image-name",
+            description = "The file name in BuildInfo that provides vbmeta image.")
+    private String mVbmetaImageName = "vbmeta.img";
+
     @Option(
             name = "boot-image-file-name",
             description =
@@ -176,15 +181,28 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
                             + "BuildInfo is a zip file or directory, for example system_dlkm.img.")
     private String mSystemDlkmImageFileName = "system_dlkm.img";
 
+    @Option(
+            name = "vbmeta-image-file-name",
+            description =
+                    "The vbmeta image file name to search for if vbmeta-image-name in "
+                            + "BuildInfo is a zip file or directory, for example vbmeta.img.")
+    private String mVbmetaImageFileName = "vbmeta.img";
+
     @Option(
             name = "post-reboot-device-into-user-space",
             description = "whether to boot the device in user space after flash.")
     private boolean mPostRebootDeviceIntoUserSpace = true;
 
+    @Option(
+            name = "wipe-device-before-gki-flash",
+            description = "Whether to wipe device before GKI boot image flash.")
+    private boolean mShouldWipeDeviceBeforeFlash = true;
+
+    @Deprecated
     @Option(
             name = "wipe-device-after-gki-flash",
-            description = "Whether to wipe device after GKI boot image flash.")
-    private boolean mShouldWipeDevice = true;
+            description = "deprecated, use option wipe-device-before-gki-flash instead.")
+    private boolean mShouldWipeDevice = false;
 
     @Option(name = "disable-verity", description = "Whether to disable-verity.")
     private boolean mShouldDisableVerity = false;
@@ -197,6 +215,11 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
             description = "additional options to pass with fastboot flash command.")
     private Collection<String> mFastbootFlashOptions = new ArrayList<>();
 
+    @Option(
+            name = "additional-fastboot-command",
+            description = "additional fastboot command to run.")
+    private Collection<String> mFastbootCommands = new ArrayList<>();
+
     @Option(
             name = "boot-header-version",
             description = "The version of the boot.img header. Set to 3 by default.")
@@ -209,6 +232,29 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
                         + "https://android.googlesource.com/platform/external/avb/+/master/README.md")
     private boolean mAddHashFooter = false;
 
+    @Option(
+            name = "security-patch-level",
+            description =
+                    "The security patch level to sign the boot image when add-hash-footer is"
+                            + " enabled.")
+    private String mSecurityPatchLevel = null;
+
+    @Option(
+            name = "boot-image-key-path",
+            description =
+                    "The key path in otatools to sign the boot image when add-hash-footer is"
+                            + " enabled.")
+    private String mBootImgKeyPath = "external/avb/test/data/testkey_rsa4096.pem";
+
+    @Option(
+            name = "boot-image-key-algorithm",
+            description =
+                    "The key algorithm to sign the boot image when add-hash-footer is enabled.")
+    private String mBootImgKeyAlgorithm = "SHA256_RSA4096";
+
+    @Option(name = "support-fastbootd", description = "Whether the device supports fastbootd mode")
+    private boolean mSupportFastbootd = true;
+
     private File mBootImg = null;
     private File mSystemDlkmImg = null;
     private Collection<String> mFlashOptions = new ArrayList<>();
@@ -314,6 +360,10 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
         // Don't allow interruptions during flashing operations.
         getRunUtil().allowInterrupt(false);
         try {
+            if (mShouldWipeDeviceBeforeFlash) {
+                executeFastbootCmd(device, "-w");
+            }
+
             if (buildInfo.getFile(mVendorBootImageName) != null) {
                 File vendorBootImg =
                         getRequestedFile(
@@ -330,8 +380,11 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
                                 mVendorKernelBootImageFileName,
                                 buildInfo.getFile(mVendorKernelBootImageName),
                                 tmpDir);
-                executeFastbootCmd(device, "flash", "vendor_kernel_boot",
-                                vendorKernelBootImg.getAbsolutePath());
+                executeFastbootCmd(
+                        device,
+                        "flash",
+                        "vendor_kernel_boot",
+                        vendorKernelBootImg.getAbsolutePath());
             }
             if (buildInfo.getFile(mInitramfsImageName) != null) {
                 File initramfsImg =
@@ -362,7 +415,8 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
                                 mVendorDlkmImageFileName,
                                 buildInfo.getFile(mVendorDlkmImageName),
                                 tmpDir);
-                if (!TestDeviceState.FASTBOOTD.equals(device.getDeviceState())) {
+                if (mSupportFastbootd
+                        && !TestDeviceState.FASTBOOTD.equals(device.getDeviceState())) {
                     device.rebootIntoFastbootd();
                 }
                 executeFastbootCmd(device, "flash", "vendor_dlkm", vendorDlkmImg.getAbsolutePath());
@@ -375,14 +429,30 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
                                 mSystemDlkmImageFileName,
                                 buildInfo.getFile(mSystemDlkmImageName),
                                 tmpDir);
-                if (!TestDeviceState.FASTBOOTD.equals(device.getDeviceState())) {
+                if (mSupportFastbootd
+                        && !TestDeviceState.FASTBOOTD.equals(device.getDeviceState())) {
                     device.rebootIntoFastbootd();
                 }
                 executeFastbootCmd(device, "flash", "system_dlkm", systemDlkmImg.getAbsolutePath());
             }
 
-            if (mShouldWipeDevice) {
-                executeFastbootCmd(device, "-w");
+            if (buildInfo.getFile(mVbmetaImageName) != null) {
+                File vbmetaImg =
+                        getRequestedFile(
+                                device,
+                                mVbmetaImageFileName,
+                                buildInfo.getFile(mVbmetaImageName),
+                                tmpDir);
+                if (mSupportFastbootd
+                        && !TestDeviceState.FASTBOOTD.equals(device.getDeviceState())) {
+                    device.rebootIntoFastbootd();
+                }
+                executeFastbootCmd(device, "flash", "vbmeta", vbmetaImg.getAbsolutePath());
+            }
+
+            // Run additional fastboot command
+            for (String cmd : mFastbootCommands) {
+                executeFastbootCmd(device, cmd);
             }
         } finally {
             getHostOptions().returnPermit(PermitLimitType.CONCURRENT_FLASHER);
@@ -718,6 +788,8 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
         }
         File avbtool = getRequestedFile(device, AVBTOOL, buildInfo.getFile(OTATOOLS_ZIP), tmpDir);
         avbtool.setExecutable(true, false);
+        File boot_img_key =
+                getRequestedFile(device, mBootImgKeyPath, buildInfo.getFile(OTATOOLS_ZIP), tmpDir);
 
         String android_version = device.getProperty("ro.build.version.release");
         if (Strings.isNullOrEmpty(android_version)) {
@@ -725,12 +797,14 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
                     "Can not get android version from property ro.build.version.release.",
                     device.getDeviceDescriptor());
         }
-        String security_path_version = device.getProperty("ro.build.version.security_patch");
-        if (Strings.isNullOrEmpty(security_path_version)) {
-            throw new TargetSetupError(
-                    "Can not get security path version from property"
-                            + " ro.build.version.security_patch.",
-                    device.getDeviceDescriptor());
+        if (Strings.isNullOrEmpty(mSecurityPatchLevel)) {
+            mSecurityPatchLevel = device.getProperty("ro.build.version.security_patch");
+            if (Strings.isNullOrEmpty(mSecurityPatchLevel)) {
+                throw new TargetSetupError(
+                        "--security-patch-level is not provided. Can not get security patch version"
+                                + " from property ro.build.version.security_patch.",
+                        device.getDeviceDescriptor());
+            }
         }
 
         String command = String.format("du -b %s", mBootImg.getAbsolutePath());
@@ -740,14 +814,18 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
         String cmd =
                 String.format(
                         "%s add_hash_footer --image %s --partition_size %s "
+                                + "--algorithm %s "
+                                + "--key %s "
                                 + "--partition_name boot "
                                 + "--prop com.android.build.boot.os_version:%s "
                                 + "--prop com.android.build.boot.security_patch:%s",
                         avbtool.getAbsolutePath(),
                         mBootImg.getAbsolutePath(),
                         partition_size,
+                        mBootImgKeyAlgorithm,
+                        boot_img_key,
                         android_version,
-                        security_path_version);
+                        mSecurityPatchLevel);
         executeHostCommand(device, cmd);
     }
 
@@ -879,6 +957,14 @@ public class GkiDeviceFlashPreparer extends BaseTargetPreparer implements ILabPr
         CommandResult result =
                 device.executeLongFastbootCommand(
                         fastbootCmdArgs.toArray(new String[fastbootCmdArgs.size()]));
+        if (result == null) {
+            throw new TargetSetupError(
+                    String.format(
+                            "CommandResult with fastboot command '%s' is null",
+                            String.join(" ", fastbootCmdArgs)),
+                    device.getDeviceDescriptor(),
+                    DeviceErrorIdentifier.ERROR_AFTER_FLASHING);
+        }
         CLog.v("fastboot stdout: " + result.getStdout());
         CLog.v("fastboot stderr: " + result.getStderr());
         CommandStatus cmdStatus = result.getStatus();
diff --git a/src/com/android/tradefed/targetprep/OtaUpdateDeviceFlasher.java b/src/com/android/tradefed/targetprep/OtaUpdateDeviceFlasher.java
index 9493ff219..c1e3d7574 100644
--- a/src/com/android/tradefed/targetprep/OtaUpdateDeviceFlasher.java
+++ b/src/com/android/tradefed/targetprep/OtaUpdateDeviceFlasher.java
@@ -28,8 +28,12 @@ import com.android.tradefed.util.IRunUtil;
 import com.android.tradefed.util.RunUtil;
 
 import java.io.File;
+import java.util.Arrays;
 import java.util.Collection;
+import java.util.List;
+import java.util.Objects;
 import java.util.concurrent.TimeUnit;
+import java.util.stream.Collectors;
 
 /**
  * A device flasher that triggers system/update_engine/scripts/update_device.py script with a full
@@ -44,6 +48,8 @@ public class OtaUpdateDeviceFlasher implements IDeviceFlasher {
     private static final long APPLY_OTA_PACKAGE_TIMEOUT_MINS = 25;
     protected static final String IN_ZIP_SCRIPT_PATH =
             String.join(File.separator, "bin", "update_device");
+    protected static final String UPDATE_SUCCESS_OUTPUT =
+            "onPayloadApplicationComplete(ErrorCode::kSuccess (0)";
 
     private UserDataFlashOption mUserDataFlashOptions = null;
     private File mUpdateDeviceScript = null;
@@ -136,25 +142,45 @@ public class OtaUpdateDeviceFlasher implements IDeviceFlasher {
         InvocationMetricLogger.addInvocationMetrics(
                 InvocationMetricKey.FLASHING_METHOD, FlashingMethod.USERSPACE_OTA.toString());
         device.enableAdbRoot();
+        // TODO(guangzhu): Remove this once wipe via OTA script is properly supported
+        if (UserDataFlashOption.WIPE.equals(mUserDataFlashOptions)) {
+            device.executeShellCommand("stop");
+            device.executeShellCommand("rm -rf /data/*");
+            device.reboot();
+            device.waitForDeviceAvailable();
+            device.enableAdbRoot();
+            // ensure that the device won't enter suspend mode
+            device.executeShellCommand("svc power stayon true");
+        }
         // allow OTA downgrade since it can't be assumed that incoming builds are always newer
         device.setProperty(OTA_DOWNGRADE_PROP, "1");
         // trigger the actual flashing
-        CommandResult result =
-                getRunUtil()
-                        .runTimedCmd(
-                                TimeUnit.MINUTES.toMillis(APPLY_OTA_PACKAGE_TIMEOUT_MINS),
+        List<String> cmd =
+                Arrays.asList(
                                 mUpdateDeviceScript.getAbsolutePath(), // the script
                                 "-s",
                                 device.getSerialNumber(),
                                 UserDataFlashOption.WIPE.equals(mUserDataFlashOptions)
                                         ? "--wipe-user-data"
-                                        : "",
+                                        // set to null if no wipe, which will be filtered
+                                        // out via lambda
+                                        : null,
                                 mOtaPackage.getAbsolutePath() // the OTA package
-                                );
+                                )
+                        .stream()
+                        .filter(Objects::nonNull)
+                        .collect(Collectors.toList());
+        CommandResult result =
+                getRunUtil()
+                        .runTimedCmd(
+                                TimeUnit.MINUTES.toMillis(APPLY_OTA_PACKAGE_TIMEOUT_MINS),
+                                cmd.toArray(new String[] {}));
         mOtaCommandStatus = result.getStatus();
+        String stdErr = result.getStderr();
         CLog.v("OTA script stdout: " + result.getStdout());
-        CLog.v("OTA script stderr: " + result.getStderr());
-        if (!CommandStatus.SUCCESS.equals(mOtaCommandStatus)) {
+        CLog.v("OTA script stderr: " + stdErr);
+        if (!CommandStatus.SUCCESS.equals(mOtaCommandStatus)
+                || !stdErr.contains(UPDATE_SUCCESS_OUTPUT)) {
             throw new TargetSetupError(
                     String.format(
                             "Failed to apply OTA update to device. Exit Code: %d, Command Status:"
diff --git a/src/com/android/tradefed/targetprep/TestAppInstallSetup.java b/src/com/android/tradefed/targetprep/TestAppInstallSetup.java
index 7383bcf9c..6a62f825a 100644
--- a/src/com/android/tradefed/targetprep/TestAppInstallSetup.java
+++ b/src/com/android/tradefed/targetprep/TestAppInstallSetup.java
@@ -39,6 +39,8 @@ import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.observatory.IDiscoverDependencies;
 import com.android.tradefed.result.error.DeviceErrorIdentifier;
 import com.android.tradefed.result.error.InfraErrorIdentifier;
+import com.android.tradefed.targetprep.incremental.ApkChangeDetector;
+import com.android.tradefed.targetprep.incremental.IIncrementalSetup;
 import com.android.tradefed.testtype.IAbi;
 import com.android.tradefed.testtype.IAbiReceiver;
 import com.android.tradefed.util.AaptParser;
@@ -82,7 +84,7 @@ import java.util.stream.Stream;
  */
 @OptionClass(alias = "tests-zip-app")
 public class TestAppInstallSetup extends BaseTargetPreparer
-        implements IAbiReceiver, IDiscoverDependencies {
+        implements IAbiReceiver, IDiscoverDependencies, IIncrementalSetup {
 
     /** The mode the apk should be install in. */
     private enum InstallMode {
@@ -224,6 +226,7 @@ public class TestAppInstallSetup extends BaseTargetPreparer
     private Set<String> mPackagesInstalled = new HashSet<>();
     private TestInformation mTestInfo;
     @VisibleForTesting protected IncrementalInstallSession incrementalInstallSession;
+    private ApkChangeDetector mApkChangeDetector = null;
 
     protected void setTestInformation(TestInformation testInfo) {
         mTestInfo = testInfo;
@@ -242,7 +245,7 @@ public class TestAppInstallSetup extends BaseTargetPreparer
     /** Helper to parse an apk file with aapt. */
     @VisibleForTesting
     AaptParser doAaptParse(File apkFile) {
-        return AaptParser.parse(apkFile);
+        return AaptParser.parse(apkFile, mAaptVersion);
     }
 
     @VisibleForTesting
@@ -478,6 +481,11 @@ public class TestAppInstallSetup extends BaseTargetPreparer
         if (mCleanup && !(e instanceof DeviceNotAvailableException)) {
             for (String packageName : mPackagesInstalled) {
                 try {
+                    if (mApkChangeDetector != null
+                        && mApkChangeDetector.handlePackageCleanup(
+                            packageName, getDevice(), mUserId, mInstallForAllUsers)) {
+                        continue;
+                    }
                     uninstallPackage(getDevice(), packageName);
                 } catch (TargetSetupError tse) {
                     CLog.e(tse);
@@ -505,6 +513,16 @@ public class TestAppInstallSetup extends BaseTargetPreparer
         return mCleanup;
     }
 
+    /** {@inheritDoc} */
+    @Override
+    public void setIncrementalSetupEnabled(boolean shouldEnable) {
+        if (shouldEnable) {
+            mApkChangeDetector = new ApkChangeDetector();
+        } else {
+            mApkChangeDetector = null;
+        }
+    }
+
     /**
      * Attempt to install an package or split package on the device.
      *
@@ -513,6 +531,7 @@ public class TestAppInstallSetup extends BaseTargetPreparer
      */
     protected void installer(TestInformation testInfo, Map<File, String> appFilesAndPackages)
             throws TargetSetupError, DeviceNotAvailableException {
+
         ITestDevice device = testInfo.getDevice();
 
         // TODO(hzalek): Consider changing resolveApkFiles's return to a Multimap to avoid building
@@ -526,6 +545,11 @@ public class TestAppInstallSetup extends BaseTargetPreparer
         }
 
         for (Map.Entry<String, List<File>> e : Multimaps.asMap(packageToFiles).entrySet()) {
+            if (mApkChangeDetector != null
+                && mApkChangeDetector.handleTestAppsPreinstall(e.getKey(), e.getValue(), getDevice())) {
+                continue;
+            }
+
             if (mIncrementalInstallation) {
                 CLog.d(
                         "Performing incremental installation of apk %s with %s ...",
@@ -618,7 +642,9 @@ public class TestAppInstallSetup extends BaseTargetPreparer
                 if (aaptParser == null) {
                     throw new TargetSetupError(
                             String.format(
-                                    "Failed to extract info from `%s` using aapt",
+                                    "Failed to extract info from `%s` using "
+                                        + (mAaptVersion == AaptVersion.AAPT
+                                        ? "aapt" : "aapt2"),
                                     testAppFile.getAbsoluteFile().getName()),
                             device.getDeviceDescriptor());
                 }
diff --git a/src/com/android/tradefed/targetprep/incremental/ApkChangeDetector.java b/src/com/android/tradefed/targetprep/incremental/ApkChangeDetector.java
new file mode 100644
index 000000000..e74b51e8c
--- /dev/null
+++ b/src/com/android/tradefed/targetprep/incremental/ApkChangeDetector.java
@@ -0,0 +1,237 @@
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
+package com.android.tradefed.targetprep.incremental;
+
+import static com.google.common.collect.ImmutableList.toImmutableList;
+
+import com.android.annotations.VisibleForTesting;
+import com.android.ddmlib.MultiLineReceiver;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.google.common.base.Splitter;
+import com.google.common.hash.Hashing;
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.IOException;
+import java.nio.file.Paths;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Set;
+import java.util.StringTokenizer;
+import javax.annotation.Nullable;
+
+/**
+ * This class detects whether the APKs to be installed are different from those on the device, in
+ * order to decide whether to skip app installation and uninstallation during {@link
+ * TestAppInstallSetup}'s setUp and tearDown.
+ */
+public class ApkChangeDetector {
+
+    private static final long MIN_FREE_DISK_SPACE_THRESHOLD_IN_BYTES = 10000000L;
+    private static final double DISK_SPACE_TO_USE_ESTIMATE_FACTOR = 1.5;
+
+    /**
+     * Handle app pre-install process.
+     *
+     * @param packageName The name of the package.
+     * @param testApps Indicate all APK files in the package with the name {@link packageName}.
+     * @param device Indicates the device on which the test is running.
+     * @return Whether the APKs in {@link packageName} are fully handled under local incremental
+     *     setup. Default to false, which does not oblige to re-install the package APKs.
+     */
+    public boolean handleTestAppsPreinstall(
+        String packageName, List<File> testApps, ITestDevice device)
+        throws DeviceNotAvailableException {
+        if (!cleanupAppsIfNecessary(device, testApps)) {
+            return false;
+        }
+
+        List<String> apkInstallPaths = getApkInstallPaths(packageName, device);
+        if (apkInstallPaths.size() != testApps.size()) {
+            CLog.d(
+                "The file count of APKs to be installed is not equal to the number of APKs on "
+                    + "the device for the package '%s'. Install the APKs.", packageName);
+            return false;
+        }
+
+        Set<String> sha256SetOnDevice = getSha256SumsOnDevice(apkInstallPaths, device);
+        CLog.d("The SHA256Sums on device contains: ");
+        sha256SetOnDevice.forEach(sha256 -> {
+            CLog.d("%s", sha256);
+        });
+
+        try {
+            Set<String> sha256SumsOnHost = new HashSet<>();
+            for (File testApp : testApps) {
+                sha256SumsOnHost.add(calculateSHA256OnHost(testApp));
+            }
+            return sha256SetOnDevice.equals(sha256SumsOnHost);
+        } catch (IOException ex) {
+            CLog.d(
+                "Exception occurred when calculating the SHA256Sums of APKs to be installed. "
+                    + "Install the APKs. Error message: %s", ex);
+            return false;
+        }
+    }
+
+    /**
+     * Handle package cleanup process.
+     *
+     * @param packageName the name of package to be cleaned up.
+     * @param device Indicates the device on which the test is running.
+     * @param userId The current user ID.
+     * @param forAllUsers Indicates whether the cleanup should be done for all users.
+     * @return Whether the cleanup of an indicated package is done. Default to false, which
+     *     indicates that the cleanup is not done.
+     */
+    public boolean handlePackageCleanup(
+        String packageName, ITestDevice device, Integer userId, boolean forAllUsers)
+        throws DeviceNotAvailableException {
+        // For the current implementation, we stop the app process. If successful, skip the app
+        // uninstallation.
+        String commandToRun = String.format("am force-stop %s", packageName);
+        device.executeShellCommand(commandToRun);
+        return true;
+    }
+
+    /** The receiver class for SHA256Sum outputs. */
+    private static class Sha256SumCommandLineReceiver extends MultiLineReceiver {
+
+        private Set<String> mSha256Sums = new HashSet<>();
+
+        /** Return the calculated SHA256Sums of parsed APK files.*/
+        Set<String> getSha256Sums() {
+            return mSha256Sums;
+        }
+
+        /** {@inheritDoc} */
+        @Override
+        public boolean isCancelled() {
+            return false;
+        }
+
+        /** {@inheritDoc} */
+        @Override
+        public void processNewLines(String[] lines) {
+            for (String line : lines) {
+                StringTokenizer tokenizer = new StringTokenizer(line);
+                if (tokenizer.hasMoreTokens()) {
+                    mSha256Sums.add(tokenizer.nextToken());
+                }
+            }
+        }
+    }
+
+    /** Obtain the APK install paths of the package with {@code packageName}. */
+    @VisibleForTesting
+    @Nullable
+    List<String> getApkInstallPaths(String packageName, ITestDevice device)
+        throws DeviceNotAvailableException {
+        String commandToRun = String.format("pm path %s", packageName);
+        Splitter splitter = Splitter.on('\n').trimResults().omitEmptyStrings();
+        return splitter.splitToList(device.executeShellCommand(commandToRun))
+                .stream()
+                .filter(line -> line.startsWith("package:"))
+                .map(line -> line.substring("package:".length()))
+                .collect(toImmutableList());
+    }
+
+    /** Collect the SHA256Sums of all APK files under {@code apkInstallPaths}. */
+    @VisibleForTesting
+    Set<String> getSha256SumsOnDevice(List<String> apkInstallPaths, ITestDevice device)
+        throws DeviceNotAvailableException {
+        Set<String> packageInstallPaths = new HashSet<>();
+        apkInstallPaths.forEach(apkInstallPath -> {
+            packageInstallPaths.add(Paths.get(apkInstallPath).getParent().toString());
+        });
+
+        Set<String> sha256Sums = new HashSet<>();
+        for (String packageInstallPath : packageInstallPaths) {
+            Sha256SumCommandLineReceiver receiver = new Sha256SumCommandLineReceiver();
+            String commandToRun =
+                String.format("find %s -name \"*.apk\" -exec sha256sum {} \\;", packageInstallPath);
+            device.executeShellCommand(commandToRun, receiver);
+            sha256Sums.addAll(receiver.getSha256Sums());
+        }
+        return sha256Sums;
+    }
+
+    @VisibleForTesting
+    String calculateSHA256OnHost(File file) throws IOException {
+        byte[] byteArray = new byte[(int) file.length()];
+        try (FileInputStream inputStream = new FileInputStream(file)) {
+            inputStream.read(byteArray);
+        }
+        return Hashing.sha256().hashBytes(byteArray).toString();
+    }
+
+    /**
+     * Returns if the processes of checking free disk space and app cleanup are successful.
+     *
+     * Note that this method only returns {@code false} if any issue happens. Upon no needing to
+     * clean up, this method returns {@code true}.
+     */
+    private boolean cleanupAppsIfNecessary(ITestDevice device, List<File> testApps)
+        throws DeviceNotAvailableException {
+        long freeDiskSpace;
+        try {
+            freeDiskSpace = getFreeDiskSpaceForAppInstallation(device);
+        } catch (IllegalArgumentException illegalArgumentEx) {
+            CLog.d(
+                "Not able to obtain free disk space: %s. App cleanup not successful.",
+                illegalArgumentEx);
+            return false;
+        }
+        long totalAppSize = testApps.stream().mapToLong(File::length).sum();
+        if (freeDiskSpace - totalAppSize * DISK_SPACE_TO_USE_ESTIMATE_FACTOR
+                < MIN_FREE_DISK_SPACE_THRESHOLD_IN_BYTES) {
+            throw new UnsupportedOperationException("App cleanup is not yet supported.");
+        }
+        return true;
+    }
+
+    /** Get the free disk space in bytes of the folder "/data" of {@code device}. */
+    @VisibleForTesting
+    long getFreeDiskSpaceForAppInstallation(ITestDevice device)
+        throws DeviceNotAvailableException {
+        String commandToRun = "df /data";
+        return getFreeDiskSpaceFromDfCommandLine(device.executeShellCommand(commandToRun));
+    }
+
+    private long getFreeDiskSpaceFromDfCommandLine(String output) {
+        if (output == null) {
+            throw new IllegalArgumentException(
+                "No output available for obtaining the device's free disk space.");
+        }
+        // The format of the output of `df /data` is as follows:
+        // Filesystem        1K-blocks    Used Available Use% Mounted on
+        // [PATH_FS]         [TOTAL]    [USED] [FREE]    [FREE_PCT] [PATH_MOUNTED_ON]
+        // Thus we need to skip the first line and take token 3 of the second line.
+        final long bytesInKiloBytes = 1024L;
+        Splitter splitter = Splitter.on('\n').trimResults().omitEmptyStrings();
+        List<String> outputLines = splitter.splitToList(output);
+        if (outputLines.size() < 2) {
+            throw new IllegalArgumentException("No free disk space info was emitted.");
+        }
+        String[] tokens = outputLines.get(1).split("\\s+");
+        if (tokens.length < 4) {
+            throw new IllegalArgumentException(
+                "Free disk space info under /data was malformatted.");
+        }
+        return Long.parseLong(tokens[3]) * bytesInKiloBytes;
+    }
+}
diff --git a/src/com/android/tradefed/targetprep/incremental/IIncrementalSetup.java b/src/com/android/tradefed/targetprep/incremental/IIncrementalSetup.java
new file mode 100644
index 000000000..6958f0445
--- /dev/null
+++ b/src/com/android/tradefed/targetprep/incremental/IIncrementalSetup.java
@@ -0,0 +1,23 @@
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
+package com.android.tradefed.targetprep.incremental;
+
+/** An interface which helps decide whether to attempt incremental setup for TradeFed preparers. */
+public interface IIncrementalSetup {
+
+    /** Set whether to enable incremental setup on TradeFed preparers. */
+    public void setIncrementalSetupEnabled(boolean shouldEnable);
+}
diff --git a/src/com/android/tradefed/testtype/SubprocessTfLauncher.java b/src/com/android/tradefed/testtype/SubprocessTfLauncher.java
index 313d27b73..bc69731dc 100644
--- a/src/com/android/tradefed/testtype/SubprocessTfLauncher.java
+++ b/src/com/android/tradefed/testtype/SubprocessTfLauncher.java
@@ -495,10 +495,11 @@ public abstract class SubprocessTfLauncher
             return;
         }
 
-        try (FileInputStreamSource inputStream = new FileInputStreamSource(fileToExport)) {
+        try (FileInputStreamSource inputStream = new FileInputStreamSource(fileToExport, true)) {
             listener.testLog(fileToExport.getName(), LogDataType.TEXT, inputStream);
+        } catch (RuntimeException e) {
+            CLog.e(e);
         }
-        FileUtil.deleteFile(fileToExport);
     }
 
     /**
diff --git a/src/com/android/tradefed/testtype/suite/BaseTestSuite.java b/src/com/android/tradefed/testtype/suite/BaseTestSuite.java
index ff16c940a..a08fd5da6 100644
--- a/src/com/android/tradefed/testtype/suite/BaseTestSuite.java
+++ b/src/com/android/tradefed/testtype/suite/BaseTestSuite.java
@@ -44,8 +44,6 @@ import com.android.tradefed.testtype.suite.params.NegativeHandler;
 import com.android.tradefed.util.ArrayUtil;
 import com.android.tradefed.util.FileUtil;
 
-import com.google.common.annotations.VisibleForTesting;
-
 import java.io.File;
 import java.io.FileNotFoundException;
 import java.io.IOException;
@@ -137,13 +135,6 @@ public class BaseTestSuite extends ITestSuite {
                             + "matching suite tag will be able to run.")
     private String mSuiteTag = null;
 
-    @Option(
-            name = "prioritize-host-config",
-            description =
-                    "If there are duplicate test configs for host/target, prioritize the host"
-                            + " config, otherwise use the target config.")
-    private boolean mPrioritizeHostConfig = false;
-
     @Option(
             name = "suite-config-prefix",
             description = "Search only configs with given prefix for suite tags.")
@@ -355,7 +346,7 @@ public class BaseTestSuite extends ITestSuite {
 
             // Include host or target first in the search if it exists, we have to this in
             // BaseTestSuite because it's the only one with the BuildInfo knowledge of linked files
-            if (mPrioritizeHostConfig) {
+            if (getPrioritizeHostConfig()) {
                 File hostSubDir = getBuildInfo().getFile(BuildInfoFileKey.HOST_LINKED_DIR);
                 if (hostSubDir != null && hostSubDir.exists()) {
                     testsDirectories.add(hostSubDir);
@@ -698,21 +689,6 @@ public class BaseTestSuite extends ITestSuite {
         filters.addAll(cleanedFilters);
     }
 
-    /* Return a {@link boolean} for the setting of prioritize-host-config.*/
-    boolean getPrioritizeHostConfig() {
-        return mPrioritizeHostConfig;
-    }
-
-    /**
-     * Set option prioritize-host-config.
-     *
-     * @param prioritizeHostConfig true to prioritize host config, i.e., run host test if possible.
-     */
-    @VisibleForTesting
-    protected void setPrioritizeHostConfig(boolean prioritizeHostConfig) {
-        mPrioritizeHostConfig = prioritizeHostConfig;
-    }
-
     /** Log a file directly to the result reporter. */
     private void logFilterFile(File filterFile, String dataName, LogDataType type) {
         if (getCurrentTestLogger() == null) {
diff --git a/src/com/android/tradefed/testtype/suite/ITestSuite.java b/src/com/android/tradefed/testtype/suite/ITestSuite.java
index bf8d941e8..d1de192ed 100644
--- a/src/com/android/tradefed/testtype/suite/ITestSuite.java
+++ b/src/com/android/tradefed/testtype/suite/ITestSuite.java
@@ -21,6 +21,7 @@ import com.android.tradefed.build.BuildRetrievalError;
 import com.android.tradefed.build.IBuildInfo;
 import com.android.tradefed.build.IDeviceBuildInfo;
 import com.android.tradefed.config.Configuration;
+import com.android.tradefed.config.ConfigurationDescriptor;
 import com.android.tradefed.config.ConfigurationException;
 import com.android.tradefed.config.DynamicRemoteFileResolver;
 import com.android.tradefed.config.IConfiguration;
@@ -392,6 +393,20 @@ public abstract class ITestSuite
     @Option(name = "stage-remote-file", description = "Whether to allow staging of remote files.")
     private boolean mStageRemoteFile = true;
 
+    @Option(
+            name = "prioritize-host-config",
+            description =
+                    "If there are duplicate test configs for host/target, prioritize the host"
+                            + " config, otherwise use the target config.")
+    private boolean mPrioritizeHostConfig = false;
+
+    @Option(
+            name = "run-test-suite",
+            description =
+                    "Entry point to execute the given test suite as defined by the Soong"
+                            + " test_suites rule")
+    private String mRunTestSuite = null;
+
     public enum IsolatedModuleGrade {
         REBOOT_ISOLATED, // Reboot was done before the test.
         FULLY_ISOLATED; // Test received a fresh device.
@@ -684,6 +699,12 @@ public abstract class ITestSuite
                 ValidateSuiteConfigHelper.validateConfig(config.getValue());
                 Map<String, List<ITargetPreparer>> preparersPerDevice =
                         getPreparerPerDevice(config.getValue());
+                // add the prioritize-host-config value in the module config
+                config.getValue()
+                        .getConfigurationDescription()
+                        .addMetadata(
+                                ConfigurationDescriptor.PRIORITIZE_HOST_CONFIG_KEY,
+                                String.valueOf(mPrioritizeHostConfig));
                 ModuleDefinition module =
                         new ModuleDefinition(
                                 config.getKey(),
@@ -930,21 +951,25 @@ public abstract class ITestSuite
                             module.getModuleInvocationContext()
                                     .getConfigurationDescriptor()
                                     .getModuleName();
+                    boolean shouldSkipModule = mSkipContext.shouldSkipModule(baseModuleName);
                     ModuleProtoResultReporter moduleReporter = null;
                     CacheResultDescriptor cacheDescriptor = null;
-                    File moduleDir = SearchArtifactUtil.findModuleDir(baseModuleName, true);
+                    File moduleDir =
+                            SearchArtifactUtil.getModuleDirFromConfig(
+                                    module.getModuleInvocationContext());
                     if (moduleDir == null) {
                         InvocationMetricLogger.addInvocationMetrics(
                                 InvocationMetricKey.MODULE_CACHE_NO_DIR, 1);
                     }
-                    if (mMainConfiguration.getCommandOptions().shouldUploadCacheResults()
+                    if (!shouldSkipModule
+                            && mMainConfiguration.getCommandOptions().shouldUploadCacheResults()
                             && moduleDir != null
                             && mMainConfiguration.getCommandOptions().getRemoteCacheInstanceName()
                                     != null) {
                         cacheDescriptor =
                                 SuiteResultCacheUtil.lookUpModuleResults(
                                         mMainConfiguration,
-                                        module.getId(),
+                                        module,
                                         moduleConfig,
                                         moduleDir,
                                         mSkipContext);
@@ -952,8 +977,10 @@ public abstract class ITestSuite
                             try {
                                 File protoResults =
                                         FileUtil.createTempFile("module-results", ".proto");
+                                // Do not report granular results until we need them they consume a
+                                // lot of memory
                                 moduleReporter =
-                                        new ModuleProtoResultReporter(testInfo.getContext());
+                                        new ModuleProtoResultReporter(testInfo.getContext(), false);
                                 moduleReporter.setOutputFile(protoResults);
                                 moduleListeners.add(moduleReporter);
                             } catch (IOException e) {
@@ -969,7 +996,17 @@ public abstract class ITestSuite
                     // Trigger module start on module level listener too
                     new ResultForwarder(moduleListeners)
                             .testModuleStarted(module.getModuleInvocationContext());
-                    if (moduleConfig != null) {
+                    boolean applyCachedResults =
+                            cacheDescriptor != null
+                                    && cacheDescriptor.isCacheHit()
+                                    && (mMainConfiguration.getCommandOptions().reportCacheResults()
+                                            || (mSkipContext.isPresubmit()
+                                                    && mMainConfiguration
+                                                            .getCommandOptions()
+                                                            .reportCacheResultsInPresubmit()))
+                                    && mSkipContext.shouldUseCache();
+                    // TODO(b/372243975): report logs even while applying caching
+                    if (moduleConfig != null && !applyCachedResults && !shouldSkipModule) {
                         try (InputStreamSource source =
                                 new FileInputStreamSource(moduleConfig, false)) {
                             listener.testLog(
@@ -981,7 +1018,7 @@ public abstract class ITestSuite
                                     testInfo, module.getModuleInvocationContext());
                     boolean moduleRan = true;
                     try {
-                        if (mSkipContext.shouldSkipModule(baseModuleName)) {
+                        if (shouldSkipModule) {
                             moduleRan = false;
                             CLog.d(
                                     "Skipping module '%s' due to no changes in artifacts.",
@@ -991,18 +1028,18 @@ public abstract class ITestSuite
                                             ModuleDefinition.MODULE_SKIPPED,
                                             "No relevant changes to device image or test artifacts"
                                                     + " detected.");
+                            module.getModuleInvocationContext()
+                                    .addInvocationAttribute(ModuleDefinition.SPARSE_MODULE, "true");
                             InvocationMetricLogger.addInvocationMetrics(
                                     InvocationMetricKey.PARTIAL_SKIP_MODULE_UNCHANGED_COUNT, 1);
-                        } else if (cacheDescriptor != null
-                                && cacheDescriptor.isCacheHit()
-                                && mMainConfiguration.getCommandOptions().reportCacheResults()
-                                && mSkipContext.shouldUseCache()) {
+                        } else if (applyCachedResults) {
                             CLog.d("Reporting cached results for module %s", module.getId());
-                            // TODO: Include pointer to base results
                             module.getModuleInvocationContext()
                                     .addInvocationAttribute(
                                             ModuleDefinition.MODULE_SKIPPED,
                                             cacheDescriptor.getDetails());
+                            module.getModuleInvocationContext()
+                                    .addInvocationAttribute(ModuleDefinition.SPARSE_MODULE, "true");
                         } else {
                             runSingleModule(module, moduleInfo, listener, moduleListeners);
                         }
@@ -1019,7 +1056,7 @@ public abstract class ITestSuite
                                 SuiteResultCacheUtil.uploadModuleResults(
                                         mMainConfiguration,
                                         testInfo,
-                                        module.getId(),
+                                        module,
                                         moduleConfig,
                                         protoResults,
                                         moduleDir,
@@ -1033,8 +1070,10 @@ public abstract class ITestSuite
                         // execution
                         listenerWithCollectors.testModuleEnded();
                         mModuleInProgress = null;
-                        // Following modules will not be isolated if no action is taken
-                        CurrentInvocation.setModuleIsolation(IsolationGrade.NOT_ISOLATED);
+                        if (!applyCachedResults) {
+                            // Following modules will not be isolated if no action is taken
+                            CurrentInvocation.setModuleIsolation(IsolationGrade.NOT_ISOLATED);
+                        }
                     }
                     if (moduleRan) {
                         // Module isolation routine
@@ -1081,6 +1120,7 @@ public abstract class ITestSuite
 
     /** Log the module configuration. */
     private File dumpModuleConfig(ModuleDefinition module) {
+        boolean restore = false;
         try {
             File configFile =
                     FileUtil.createTempFile(
@@ -1089,6 +1129,10 @@ public abstract class ITestSuite
                                     .getModuleName(),
                             ".xml",
                             CurrentInvocation.getWorkFolder());
+            if (module.getModuleConfiguration().getTests().isEmpty()) {
+                module.getModuleConfiguration().setTests(module.getTests());
+                restore = true;
+            }
             try (FileOutputStream stream = new FileOutputStream(configFile);
                     PrintWriter pw = new PrintWriter(stream, true)) {
                 module.getModuleConfiguration()
@@ -1099,6 +1143,10 @@ public abstract class ITestSuite
                                 false);
                 pw.flush();
                 return configFile;
+            } finally {
+                if (restore) {
+                    module.getModuleConfiguration().setTests(new ArrayList<>());
+                }
             }
         } catch (RuntimeException | IOException e) {
             CLog.e(e);
@@ -1927,4 +1975,19 @@ public abstract class ITestSuite
     public void setSkipContext(SkipContext skipContext) {
         mSkipContext = skipContext;
     }
+
+    /* Return a {@link boolean} for the setting of prioritize-host-config.*/
+    boolean getPrioritizeHostConfig() {
+        return mPrioritizeHostConfig;
+    }
+
+    /**
+     * Set option prioritize-host-config.
+     *
+     * @param prioritizeHostConfig true to prioritize host config, i.e., run host test if possible.
+     */
+    @com.google.common.annotations.VisibleForTesting
+    protected void setPrioritizeHostConfig(boolean prioritizeHostConfig) {
+        mPrioritizeHostConfig = prioritizeHostConfig;
+    }
 }
diff --git a/src/com/android/tradefed/testtype/suite/ModuleDefinition.java b/src/com/android/tradefed/testtype/suite/ModuleDefinition.java
index c7f173ac8..b5d253d94 100644
--- a/src/com/android/tradefed/testtype/suite/ModuleDefinition.java
+++ b/src/com/android/tradefed/testtype/suite/ModuleDefinition.java
@@ -165,6 +165,9 @@ public class ModuleDefinition implements Comparable<ModuleDefinition>, ITestColl
 
     private final String mId;
     private Collection<IRemoteTest> mTests = null;
+    private Integer mIntraModuleShardCount = null;
+    private Integer mIntraModuleShardIndex = null;
+
     private Map<String, List<ITargetPreparer>> mPreparersPerDevice = null;
     private Map<String, List<ITargetPreparer>> mSuitePreparersPerDevice = null;
 
@@ -305,6 +308,19 @@ public class ModuleDefinition implements Comparable<ModuleDefinition>, ITestColl
         }
     }
 
+    public void setIntraModuleInformation(int shardCount, int shardIndex) {
+        mIntraModuleShardCount = shardCount;
+        mIntraModuleShardIndex = shardIndex;
+    }
+
+    public Integer getIntraModuleShardCount() {
+        return mIntraModuleShardCount;
+    }
+
+    public Integer getIntraModuleShardIndex() {
+        return mIntraModuleShardIndex;
+    }
+
     /** Returns the number of devices expected to run this test. */
     public int neededDevices() {
         return mModuleConfiguration.getDeviceConfig().size();
diff --git a/src/com/android/tradefed/testtype/suite/ModuleSplitter.java b/src/com/android/tradefed/testtype/suite/ModuleSplitter.java
index 118175118..cbb5cf5d4 100644
--- a/src/com/android/tradefed/testtype/suite/ModuleSplitter.java
+++ b/src/com/android/tradefed/testtype/suite/ModuleSplitter.java
@@ -185,17 +185,22 @@ public class ModuleSplitter {
                                             clonePreparersMap(suitePreparersPerDevice),
                                             clonePreparers(config.getMultiTargetPreparers()),
                                             config);
+                            module.setIntraModuleInformation(shardedTests.size(), i);
                             currentList.add(module);
                         }
                     } else {
                         // We create independent modules with each sharded test.
+                        int i = 0;
                         for (IRemoteTest moduleTest : shardedTests) {
-                            addModuleToListFromSingleTest(
-                                    currentList,
-                                    moduleTest,
-                                    moduleName,
-                                    config,
-                                    suitePreparersPerDevice);
+                            ModuleDefinition module =
+                                    addModuleToListFromSingleTest(
+                                            currentList,
+                                            moduleTest,
+                                            moduleName,
+                                            config,
+                                            suitePreparersPerDevice);
+                            module.setIntraModuleInformation(shardedTests.size(), i);
+                            i++;
                         }
                     }
                     continue;
@@ -212,7 +217,7 @@ public class ModuleSplitter {
      * Helper to add a new {@link ModuleDefinition} to our list of Modules from a single {@link
      * IRemoteTest}.
      */
-    private static void addModuleToListFromSingleTest(
+    private static ModuleDefinition addModuleToListFromSingleTest(
             List<ModuleDefinition> currentList,
             IRemoteTest test,
             String moduleName,
@@ -229,6 +234,7 @@ public class ModuleSplitter {
                         clonePreparers(config.getMultiTargetPreparers()),
                         config);
         currentList.add(module);
+        return module;
     }
 
     /**
diff --git a/src/com/android/tradefed/testtype/suite/SuiteModuleLoader.java b/src/com/android/tradefed/testtype/suite/SuiteModuleLoader.java
index c13095fd0..c33ad539f 100644
--- a/src/com/android/tradefed/testtype/suite/SuiteModuleLoader.java
+++ b/src/com/android/tradefed/testtype/suite/SuiteModuleLoader.java
@@ -45,7 +45,6 @@ import com.android.tradefed.testtype.suite.params.NegativeHandler;
 import com.android.tradefed.testtype.suite.params.NotMultiAbiHandler;
 import com.android.tradefed.util.AbiUtils;
 import com.android.tradefed.util.FileUtil;
-import com.android.tradefed.util.StreamUtil;
 
 import com.google.common.base.Strings;
 import com.google.common.net.UrlEscapers;
@@ -173,9 +172,22 @@ public class SuiteModuleLoader {
             List<File> listConfigFiles, Set<IAbi> abis, String suiteTag) {
         LinkedHashMap<String, IConfiguration> toRun = new LinkedHashMap<>();
         for (File configFile : listConfigFiles) {
-            toRun.putAll(
+            Map<String, IConfiguration> loadedConfigs =
                     loadOneConfig(
-                            configFile.getName(), configFile.getAbsolutePath(), abis, suiteTag));
+                            configFile.getParentFile(),
+                            configFile.getName(),
+                            configFile.getAbsolutePath(),
+                            abis,
+                            suiteTag);
+            // store the module dir path for each config
+            for (IConfiguration loadedConfig : loadedConfigs.values()) {
+                loadedConfig
+                        .getConfigurationDescription()
+                        .addMetadata(
+                                ConfigurationDescriptor.MODULE_DIR_PATH_KEY,
+                                configFile.getParentFile().getAbsolutePath());
+            }
+            toRun.putAll(loadedConfigs);
         }
         return toRun;
     }
@@ -235,7 +247,7 @@ public class SuiteModuleLoader {
             List<String> configs, Set<IAbi> abis, String suiteTag) {
         LinkedHashMap<String, IConfiguration> toRun = new LinkedHashMap<>();
         for (String configName : configs) {
-            toRun.putAll(loadOneConfig(configName, configName, abis, suiteTag));
+            toRun.putAll(loadOneConfig(null, configName, configName, abis, suiteTag));
         }
         return toRun;
     }
@@ -245,6 +257,7 @@ public class SuiteModuleLoader {
      * does not implements {@link ITestFileFilterReceiver}. This can be overriden to create a more
      * restrictive behavior.
      *
+     * @param moduleDir The module directory
      * @param test The {@link IRemoteTest} that is being considered.
      * @param abi The Abi we are currently working on.
      * @param moduleId The id of the module (usually abi + module name).
@@ -252,6 +265,7 @@ public class SuiteModuleLoader {
      * @param excludeFilters The formatted and parsed exclude filters.
      */
     public void addFiltersToTest(
+            File moduleDir,
             IRemoteTest test,
             IAbi abi,
             String moduleId,
@@ -267,10 +281,10 @@ public class SuiteModuleLoader {
         LinkedHashSet<SuiteTestFilter> mdIncludes = getFilterList(includeFilters, moduleId);
         LinkedHashSet<SuiteTestFilter> mdExcludes = getFilterList(excludeFilters, moduleId);
         if (!mdIncludes.isEmpty()) {
-            addTestIncludes((ITestFilterReceiver) test, mdIncludes, moduleId);
+            addTestIncludes(moduleDir, (ITestFilterReceiver) test, mdIncludes, moduleId);
         }
         if (!mdExcludes.isEmpty()) {
-            addTestExcludes((ITestFilterReceiver) test, mdExcludes, moduleId);
+            addTestExcludes(moduleDir, (ITestFilterReceiver) test, mdExcludes, moduleId);
         }
     }
 
@@ -285,7 +299,11 @@ public class SuiteModuleLoader {
      * @return A map of loaded configuration.
      */
     private LinkedHashMap<String, IConfiguration> loadOneConfig(
-            String configName, String configFullName, Set<IAbi> abis, String suiteTag) {
+            File moduleDir,
+            String configName,
+            String configFullName,
+            Set<IAbi> abis,
+            String suiteTag) {
         LinkedHashMap<String, IConfiguration> toRun = new LinkedHashMap<>();
         final String name = configName.replace(CONFIG_EXT, "");
         final String[] pathArg = new String[] {configFullName};
@@ -418,7 +436,14 @@ public class SuiteModuleLoader {
                                             ConfigurationDescriptor.ACTIVE_PARAMETER_KEY,
                                             param.getParameterIdentifier());
                             param.addParameterSpecificConfig(paramConfig);
-                            setUpConfig(name, nameWithParam, baseId, fullId, paramConfig, abi);
+                            setUpConfig(
+                                    name,
+                                    nameWithParam,
+                                    baseId,
+                                    fullId,
+                                    paramConfig,
+                                    moduleDir,
+                                    abi);
                             param.applySetup(paramConfig);
                             toRun.put(fullId, paramConfig);
                         }
@@ -452,7 +477,8 @@ public class SuiteModuleLoader {
                         paramConfig
                                 .getConfigurationDescription()
                                 .addMetadata(ITestSuite.ACTIVE_MAINLINE_PARAMETER_KEY, param);
-                        setUpConfig(name, nameWithParam, baseId, fullId, paramConfig, abi);
+                        setUpConfig(
+                                name, nameWithParam, baseId, fullId, paramConfig, moduleDir, abi);
                         handler.applySetup(paramConfig);
                         toRun.put(fullId, paramConfig);
                     }
@@ -468,7 +494,7 @@ public class SuiteModuleLoader {
                     // Always add the base regular configuration to the execution.
                     // Do not pass the nameWithParam in because it would cause the module args be
                     // injected into config twice if we pass nameWithParam using name.
-                    setUpConfig(name, null, baseId, baseId, config, abi);
+                    setUpConfig(name, null, baseId, baseId, config, moduleDir, abi);
                     toRun.put(baseId, config);
                 }
             }
@@ -606,11 +632,16 @@ public class SuiteModuleLoader {
     }
 
     private void addTestIncludes(
-            ITestFilterReceiver test, Collection<SuiteTestFilter> includes, String moduleId) {
+            File moduleDir,
+            ITestFilterReceiver test,
+            Collection<SuiteTestFilter> includes,
+            String moduleId) {
         if (test instanceof ITestFileFilterReceiver) {
             String escapedFileName = escapeFilterFileName(moduleId);
-            File includeFile = createFilterFile(escapedFileName, ".include", includes);
-            ((ITestFileFilterReceiver) test).setIncludeTestFile(includeFile);
+            File includeFile = createFilterFile(escapedFileName, ".include", moduleDir, includes);
+            if (includeFile != null) {
+                ((ITestFileFilterReceiver) test).setIncludeTestFile(includeFile);
+            }
         } else {
             // add test includes one at a time
             for (SuiteTestFilter include : includes) {
@@ -623,11 +654,16 @@ public class SuiteModuleLoader {
     }
 
     private void addTestExcludes(
-            ITestFilterReceiver test, Collection<SuiteTestFilter> excludes, String moduleId) {
+            File moduleDir,
+            ITestFilterReceiver test,
+            Collection<SuiteTestFilter> excludes,
+            String moduleId) {
         if (test instanceof ITestFileFilterReceiver) {
             String escapedFileName = escapeFilterFileName(moduleId);
-            File excludeFile = createFilterFile(escapedFileName, ".exclude", excludes);
-            ((ITestFileFilterReceiver) test).setExcludeTestFile(excludeFile);
+            File excludeFile = createFilterFile(escapedFileName, ".exclude", moduleDir, excludes);
+            if (excludeFile != null) {
+                ((ITestFileFilterReceiver) test).setExcludeTestFile(excludeFile);
+            }
         } else {
             // add test excludes one at a time
             for (SuiteTestFilter exclude : excludes) {
@@ -643,24 +679,36 @@ public class SuiteModuleLoader {
     }
 
     private File createFilterFile(
-            String prefix, String suffix, Collection<SuiteTestFilter> filters) {
+            String prefix, String suffix, File moduleDir, Collection<SuiteTestFilter> filters) {
+        if (filters.isEmpty()) {
+            return null;
+        }
         File filterFile = null;
-        PrintWriter out = null;
         try {
-            filterFile = FileUtil.createTempFile(prefix, suffix);
-            out = new PrintWriter(filterFile);
-            for (SuiteTestFilter filter : filters) {
-                String filterTest = filter.getTest();
-                if (filterTest != null) {
-                    out.println(filterTest);
+            if (moduleDir == null) {
+                filterFile = FileUtil.createTempFile(prefix, suffix);
+            } else {
+                filterFile = new File(moduleDir, prefix + suffix);
+            }
+            try (PrintWriter out = new PrintWriter(filterFile)) {
+                for (SuiteTestFilter filter : filters) {
+                    String filterTest = filter.getTest();
+                    if (filterTest != null) {
+                        out.println(filterTest);
+                    }
                 }
+                out.flush();
             }
-            out.flush();
         } catch (IOException e) {
             throw new HarnessRuntimeException(
                     "Failed to create filter file", e, InfraErrorIdentifier.FAIL_TO_CREATE_FILE);
-        } finally {
-            StreamUtil.close(out);
+        }
+        if (!filterFile.exists()) {
+            return null;
+        }
+        if (filterFile.length() == 0) {
+            FileUtil.deleteFile(filterFile);
+            return null;
         }
         filterFile.deleteOnExit();
         return filterFile;
@@ -696,7 +744,9 @@ public class SuiteModuleLoader {
         for (String arg : args) {
             int moduleSep = arg.indexOf(":");
             if (moduleSep == -1) {
-                throw new RuntimeException("Expected delimiter ':' for module or class.");
+                throw new HarnessRuntimeException(
+                        "Expected delimiter ':' for module or class.",
+                        InfraErrorIdentifier.OPTION_CONFIGURATION_ERROR);
             }
             String moduleName = arg.substring(0, moduleSep);
             String remainder = arg.substring(moduleSep + 1);
@@ -707,8 +757,9 @@ public class SuiteModuleLoader {
             }
             int optionNameSep = remainder.indexOf(":");
             if (optionNameSep == -1) {
-                throw new RuntimeException(
-                        "Expected delimiter ':' between option name and values.");
+                throw new HarnessRuntimeException(
+                        "Expected delimiter ':' between option name and values.",
+                        InfraErrorIdentifier.OPTION_CONFIGURATION_ERROR);
             }
             String optionName = remainder.substring(0, optionNameSep);
             Pattern pattern = Pattern.compile("\\{(.*)\\}(.*)");
@@ -888,6 +939,7 @@ public class SuiteModuleLoader {
             String id,
             String fullId,
             IConfiguration config,
+            File moduleDir,
             IAbi abi)
             throws ConfigurationException {
         List<OptionDef> optionsToInject = new ArrayList<>();
@@ -931,7 +983,7 @@ public class SuiteModuleLoader {
                     preparerSetter.setOptionValue(def.name, def.key, def.value);
                 }
             }
-            addFiltersToTest(test, abi, fullId, mIncludeFilters, mExcludeFilters);
+            addFiltersToTest(moduleDir, test, abi, fullId, mIncludeFilters, mExcludeFilters);
             if (test instanceof IAbiReceiver) {
                 ((IAbiReceiver) test).setAbi(abi);
             }
diff --git a/src/com/android/tradefed/testtype/suite/SuiteResultCacheUtil.java b/src/com/android/tradefed/testtype/suite/SuiteResultCacheUtil.java
index 459c75a15..29b205e4e 100644
--- a/src/com/android/tradefed/testtype/suite/SuiteResultCacheUtil.java
+++ b/src/com/android/tradefed/testtype/suite/SuiteResultCacheUtil.java
@@ -45,6 +45,8 @@ import java.util.Map.Entry;
 public class SuiteResultCacheUtil {
 
     public static final String DEVICE_IMAGE_KEY = "device_image";
+    public static final String MODULE_CONFIG_KEY = "module_config";
+    public static final String TRADEFED_JAR_VERSION_KEY = "tradefed.jar_version";
 
     /** Describes the cache results. */
     public static class CacheResultDescriptor {
@@ -69,6 +71,8 @@ public class SuiteResultCacheUtil {
      * Upload results to RBE
      *
      * @param mainConfig
+     * @param testInfo
+     * @param module
      * @param moduleConfig
      * @param protoResults
      * @param moduleDir
@@ -77,7 +81,7 @@ public class SuiteResultCacheUtil {
     public static void uploadModuleResults(
             IConfiguration mainConfig,
             TestInformation testInfo,
-            String moduleId,
+            ModuleDefinition module,
             File moduleConfig,
             File protoResults,
             File moduleDir,
@@ -99,7 +103,8 @@ public class SuiteResultCacheUtil {
                     InvocationMetricKey.MODULE_RESULTS_CACHE_DEVICE_MISMATCH, 1);
             return;
         }
-        // TODO: Ensure we have the link to the results
+        String moduleId = module.getId();
+        long startTime = System.currentTimeMillis();
         try (CloseableTraceScope ignored = new CloseableTraceScope("upload_module_results")) {
             String cacheInstance = mainConfig.getCommandOptions().getRemoteCacheInstanceName();
             ICacheClient cacheClient =
@@ -110,7 +115,20 @@ public class SuiteResultCacheUtil {
                 environment.put(entry.getKey(), entry.getValue().getHash());
             }
             Digest configDigest = DigestCalculator.compute(moduleConfig);
-            environment.put("module_config", configDigest.getHash());
+            environment.put(MODULE_CONFIG_KEY, configDigest.getHash());
+            Digest tradefedDigest = computeTradefedVersion();
+            if (tradefedDigest != null) {
+                environment.put(TRADEFED_JAR_VERSION_KEY, tradefedDigest.getHash());
+            }
+            if (module.getIntraModuleShardCount() != null
+                    && module.getIntraModuleShardIndex() != null) {
+                environment.put(
+                        "intra_module_shard_index",
+                        Integer.toString(module.getIntraModuleShardIndex()));
+                environment.put(
+                        "intra_module_shard_count",
+                        Integer.toString(module.getIntraModuleShardCount()));
+            }
             ExecutableAction action =
                     ExecutableAction.create(
                             moduleDir, Arrays.asList(moduleId), environment, 60000L);
@@ -119,6 +137,13 @@ public class SuiteResultCacheUtil {
             cacheClient.uploadCache(action, result);
         } catch (IOException | RuntimeException | InterruptedException e) {
             CLog.e(e);
+            InvocationMetricLogger.addInvocationMetrics(
+                    InvocationMetricKey.MODULE_CACHE_UPLOAD_ERROR, 1);
+        } finally {
+            InvocationMetricLogger.addInvocationPairMetrics(
+                    InvocationMetricKey.MODULE_CACHE_UPLOAD_TIME,
+                    startTime,
+                    System.currentTimeMillis());
         }
     }
 
@@ -126,7 +151,7 @@ public class SuiteResultCacheUtil {
      * Look up results in RBE for the test module.
      *
      * @param mainConfig
-     * @param moduleId
+     * @param module
      * @param moduleConfig
      * @param moduleDir
      * @param skipContext
@@ -134,7 +159,7 @@ public class SuiteResultCacheUtil {
      */
     public static CacheResultDescriptor lookUpModuleResults(
             IConfiguration mainConfig,
-            String moduleId,
+            ModuleDefinition module,
             File moduleConfig,
             File moduleDir,
             SkipContext skipContext) {
@@ -144,6 +169,8 @@ public class SuiteResultCacheUtil {
             CLog.d("No digest for device.");
             return new CacheResultDescriptor(false, null);
         }
+        String moduleId = module.getId();
+        long startTime = System.currentTimeMillis();
         try (CloseableTraceScope ignored = new CloseableTraceScope("lookup_module_results")) {
             String cacheInstance = mainConfig.getCommandOptions().getRemoteCacheInstanceName();
             ICacheClient cacheClient =
@@ -153,8 +180,23 @@ public class SuiteResultCacheUtil {
             for (Entry<String, Digest> entry : skipContext.getImageToDigest().entrySet()) {
                 environment.put(entry.getKey(), entry.getValue().getHash());
             }
-            Digest configDigest = DigestCalculator.compute(moduleConfig);
-            environment.put("module_config", configDigest.getHash());
+            try (CloseableTraceScope computeDigest = new CloseableTraceScope("compute_digest")) {
+                Digest configDigest = DigestCalculator.compute(moduleConfig);
+                environment.put(MODULE_CONFIG_KEY, configDigest.getHash());
+                Digest tradefedDigest = computeTradefedVersion();
+                if (tradefedDigest != null) {
+                    environment.put(TRADEFED_JAR_VERSION_KEY, tradefedDigest.getHash());
+                }
+            }
+            if (module.getIntraModuleShardCount() != null
+                    && module.getIntraModuleShardIndex() != null) {
+                environment.put(
+                        "intra_module_shard_index",
+                        Integer.toString(module.getIntraModuleShardIndex()));
+                environment.put(
+                        "intra_module_shard_count",
+                        Integer.toString(module.getIntraModuleShardCount()));
+            }
             ExecutableAction action =
                     ExecutableAction.create(
                             moduleDir, Arrays.asList(moduleId), environment, 60000L);
@@ -162,9 +204,13 @@ public class SuiteResultCacheUtil {
             ExecutableActionResult cachedResults = cacheClient.lookupCache(action);
             if (cachedResults == null) {
                 CLog.d("No cached results for %s", moduleId);
+                InvocationMetricLogger.addInvocationMetrics(
+                        InvocationMetricKey.MODULE_CACHE_MISS_ID, moduleId);
             } else {
                 InvocationMetricLogger.addInvocationMetrics(
                         InvocationMetricKey.MODULE_RESULTS_CACHE_HIT, 1);
+                InvocationMetricLogger.addInvocationMetrics(
+                        InvocationMetricKey.MODULE_CACHE_HIT_ID, moduleId);
                 String details = "Cached results.";
                 Map<String, String> metadata =
                         ModuleProtoResultReporter.parseResultsMetadata(cachedResults.stdOut());
@@ -181,7 +227,31 @@ public class SuiteResultCacheUtil {
             }
         } catch (IOException | RuntimeException | InterruptedException e) {
             CLog.e(e);
+            InvocationMetricLogger.addInvocationMetrics(
+                    InvocationMetricKey.MODULE_CACHE_DOWNLOAD_ERROR, 1);
+        } finally {
+            InvocationMetricLogger.addInvocationPairMetrics(
+                    InvocationMetricKey.MODULE_CACHE_DOWNLOAD_TIME,
+                    startTime,
+                    System.currentTimeMillis());
         }
         return new CacheResultDescriptor(false, null);
     }
+
+    /**
+     * Hash Tradefed.jar as a denominator to keep results. This helps consider changes to Tradefed.
+     */
+    private static Digest computeTradefedVersion() throws IOException {
+        String classpathStr = System.getProperty("java.class.path");
+        if (classpathStr == null) {
+            return null;
+        }
+        for (String file : classpathStr.split(":")) {
+            File currentJar = new File(file);
+            if (currentJar.exists() && "tradefed.jar".equals(currentJar.getName())) {
+                return DigestCalculator.compute(currentJar);
+            }
+        }
+        return null;
+    }
 }
diff --git a/src/com/android/tradefed/testtype/suite/TfSuiteRunner.java b/src/com/android/tradefed/testtype/suite/TfSuiteRunner.java
index 7bb9bea0a..aa263016f 100644
--- a/src/com/android/tradefed/testtype/suite/TfSuiteRunner.java
+++ b/src/com/android/tradefed/testtype/suite/TfSuiteRunner.java
@@ -16,6 +16,7 @@
 package com.android.tradefed.testtype.suite;
 
 import com.android.tradefed.build.IDeviceBuildInfo;
+import com.android.tradefed.config.ConfigurationDescriptor;
 import com.android.tradefed.config.ConfigurationException;
 import com.android.tradefed.config.ConfigurationFactory;
 import com.android.tradefed.config.ConfigurationUtil;
@@ -134,6 +135,15 @@ public class TfSuiteRunner extends ITestSuite {
             try {
                 IConfiguration testConfig =
                         configFactory.createConfigurationFromArgs(new String[]{configName});
+                // Store the module dir path
+                File moduleDir = new File(configName).getParentFile();
+                if (moduleDir != null && moduleDir.exists()) {
+                    testConfig
+                            .getConfigurationDescription()
+                            .addMetadata(
+                                    ConfigurationDescriptor.MODULE_DIR_PATH_KEY,
+                                    moduleDir.getAbsolutePath());
+                }
                 if (testConfig.getConfigurationDescription().getSuiteTags().contains(mSuiteTag)) {
                     // If this config supports running against different ABIs we need to queue up
                     // multiple instances of this config.
diff --git a/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnCloneProfileParameterHandler.java b/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnCloneProfileParameterHandler.java
index 1ba49d117..3bf77bc9e 100644
--- a/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnCloneProfileParameterHandler.java
+++ b/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnCloneProfileParameterHandler.java
@@ -26,7 +26,7 @@ public class RunOnCloneProfileParameterHandler extends ProfileParameterHandler
         implements IModuleParameterHandler {
 
     private static final String REQUIRE_RUN_ON_CLONE_PROFILE_NAME =
-            "com.android.bedstead.harrier.annotations.RequireRunOnCloneProfile";
+            "com.android.bedstead.multiuser.annotations.RequireRunOnCloneProfile";
 
     public RunOnCloneProfileParameterHandler() {
         super(
diff --git a/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnPrivateProfileParameterHandler.java b/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnPrivateProfileParameterHandler.java
index 248eaa79e..df43bed10 100644
--- a/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnPrivateProfileParameterHandler.java
+++ b/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnPrivateProfileParameterHandler.java
@@ -26,7 +26,7 @@ public class RunOnPrivateProfileParameterHandler extends ProfileParameterHandler
         IModuleParameterHandler {
 
     private static final String REQUIRE_RUN_ON_PRIVATE_PROFILE_NAME =
-            "com.android.bedstead.harrier.annotations.RequireRunOnPrivateProfile";
+            "com.android.bedstead.multiuser.annotations.RequireRunOnPrivateProfile";
 
     public RunOnPrivateProfileParameterHandler() {
         super(REQUIRE_RUN_ON_PRIVATE_PROFILE_NAME, new RunOnPrivateProfileTargetPreparer(),
diff --git a/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnSecondaryUserParameterHandler.java b/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnSecondaryUserParameterHandler.java
index f6f487fea..082ba2e8c 100644
--- a/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnSecondaryUserParameterHandler.java
+++ b/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnSecondaryUserParameterHandler.java
@@ -32,7 +32,7 @@ import java.util.Set;
 public class RunOnSecondaryUserParameterHandler implements IModuleParameterHandler {
 
     private static final String REQUIRE_RUN_ON_SECONDARY_USER_NAME =
-            "com.android.bedstead.harrier.annotations.RequireRunOnSecondaryUser";
+            "com.android.bedstead.multiuser.annotations.RequireRunOnSecondaryUser";
 
     @Override
     public String getParameterIdentifier() {
diff --git a/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnWorkProfileParameterHandler.java b/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnWorkProfileParameterHandler.java
index 94cbf2414..ea3af0f02 100644
--- a/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnWorkProfileParameterHandler.java
+++ b/src/com/android/tradefed/testtype/suite/params/multiuser/RunOnWorkProfileParameterHandler.java
@@ -23,7 +23,7 @@ public class RunOnWorkProfileParameterHandler extends ProfileParameterHandler
         implements IModuleParameterHandler {
 
     private static final String REQUIRE_RUN_ON_WORK_PROFILE_NAME =
-            "com.android.bedstead.harrier.annotations.RequireRunOnWorkProfile";
+            "com.android.bedstead.enterprise.annotations.RequireRunOnWorkProfile";
 
     public RunOnWorkProfileParameterHandler() {
         super(REQUIRE_RUN_ON_WORK_PROFILE_NAME, new RunOnWorkProfileTargetPreparer());
diff --git a/src/com/android/tradefed/util/SubprocessExceptionParser.java b/src/com/android/tradefed/util/SubprocessExceptionParser.java
index cb2884586..8134f0859 100644
--- a/src/com/android/tradefed/util/SubprocessExceptionParser.java
+++ b/src/com/android/tradefed/util/SubprocessExceptionParser.java
@@ -21,6 +21,7 @@ import com.android.tradefed.error.IHarnessException;
 import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.result.error.ErrorIdentifier;
 import com.android.tradefed.result.error.InfraErrorIdentifier;
+import com.android.tradefed.result.error.TestErrorIdentifier;
 import com.android.tradefed.sandbox.TradefedSandboxRunner;
 
 import org.json.JSONException;
@@ -76,7 +77,10 @@ public class SubprocessExceptionParser {
                     throw (DeviceNotAvailableException) obj;
                 }
                 if (obj instanceof IHarnessException) {
-                    throw new HarnessRuntimeException(message, (IHarnessException) obj);
+                    throw new HarnessRuntimeException(
+                            message,
+                            TestErrorIdentifier.SUBPROCESS_UNCATEGORIZED_EXCEPTION,
+                            (IHarnessException) obj);
                 }
                 throw new HarnessRuntimeException(message, obj, InfraErrorIdentifier.UNDETERMINED);
             } catch (IOException e) {
diff --git a/src/com/android/tradefed/util/SubprocessTestResultsParser.java b/src/com/android/tradefed/util/SubprocessTestResultsParser.java
index edc31083b..373c86efd 100644
--- a/src/com/android/tradefed/util/SubprocessTestResultsParser.java
+++ b/src/com/android/tradefed/util/SubprocessTestResultsParser.java
@@ -126,6 +126,7 @@ public class SubprocessTestResultsParser implements Closeable {
      */
     private class EventReceiverThread extends Thread {
         private ServerSocket mSocket;
+        private Socket mClient;
         // initial state: 1 permit available, joins that don't wait for connection will succeed
         private Semaphore mSemaphore = new Semaphore(1);
         private boolean mShouldParse = true;
@@ -155,6 +156,9 @@ public class SubprocessTestResultsParser implements Closeable {
             if (mSocket != null) {
                 mSocket.close();
             }
+            if (mClient != null) {
+                mClient.close();
+            }
         }
 
         /**
@@ -167,12 +171,11 @@ public class SubprocessTestResultsParser implements Closeable {
 
         @Override
         public void run() {
-            Socket client = null;
             BufferedReader in = null;
             try {
-                client = mSocket.accept();
+                mClient = mSocket.accept();
                 mSemaphore.acquire(); // connected: 0 permits available, all joins will wait
-                in = new BufferedReader(new InputStreamReader(client.getInputStream()));
+                in = new BufferedReader(new InputStreamReader(mClient.getInputStream()));
                 String event = null;
                 while ((event = in.readLine()) != null) {
                     try {
diff --git a/src/com/android/tradefed/util/TestRunnerUtil.java b/src/com/android/tradefed/util/TestRunnerUtil.java
index c879ee713..91610e164 100644
--- a/src/com/android/tradefed/util/TestRunnerUtil.java
+++ b/src/com/android/tradefed/util/TestRunnerUtil.java
@@ -72,6 +72,10 @@ public class TestRunnerUtil {
                 }
             }
         }
+        File moduleSharedLibs = new File(testFile.getParentFile(), "shared_libs");
+        if (moduleSharedLibs.exists()) {
+            paths.add(moduleSharedLibs.getAbsolutePath());
+        }
         if (paths.isEmpty()) {
             return null;
         }
diff --git a/src/com/android/tradefed/util/image/DeviceImageTracker.java b/src/com/android/tradefed/util/image/DeviceImageTracker.java
index 6f3e0dc3e..e7425ebf0 100644
--- a/src/com/android/tradefed/util/image/DeviceImageTracker.java
+++ b/src/com/android/tradefed/util/image/DeviceImageTracker.java
@@ -153,6 +153,7 @@ public class DeviceImageTracker {
                 CLog.d("Tracking device image as directory: %s", copyInCacheDeviceImage);
                 FileUtil.recursiveHardlink(deviceImage, copyInCacheDeviceImage);
             } else {
+                CLog.d("Tracking device image: %s", copyInCacheDeviceImage);
                 FileUtil.hardlinkFile(deviceImage, copyInCacheDeviceImage);
             }
             FileUtil.hardlinkFile(bootloader, copyInCacheBootloader);
diff --git a/src/com/android/tradefed/util/image/FastbootPack.java b/src/com/android/tradefed/util/image/FastbootPack.java
new file mode 100644
index 000000000..aafab626b
--- /dev/null
+++ b/src/com/android/tradefed/util/image/FastbootPack.java
@@ -0,0 +1,109 @@
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
+package com.android.tradefed.util.image;
+
+import com.android.tradefed.log.LogUtil.CLog;
+
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
+import java.nio.channels.FileChannel;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
+
+/** Follow the specification of bootloader to unpack it. */
+public class FastbootPack {
+
+    /** Utility to unpack a bootloader file per specification. Similar to fastboot code. */
+    public static void unpack(
+            File bootloader, File outputDir, String product, boolean unpackVersion)
+            throws IOException {
+        PackHeader packHeader = readPackHeader(bootloader);
+        List<PackEntry> packEntries = new ArrayList<>();
+
+        try (FileInputStream fis = new FileInputStream(bootloader);
+                FileChannel fileChannel = fis.getChannel()) {
+            fileChannel.position(packHeader.headerSize);
+            for (int i = 0; i < packHeader.totalEntries; i++) {
+                packEntries.add(readPackEntry(fileChannel));
+            }
+        }
+
+        for (PackEntry packEntry : packEntries) {
+            if (product != null && !productMatch(packEntry.product, product)) {
+                continue;
+            }
+
+            String name = bytesToString(packEntry.name);
+            CLog.d(
+                    "Unpacking "
+                            + name
+                            + " (size: "
+                            + packEntry.size
+                            + ", offset: "
+                            + packEntry.offset
+                            + ")");
+            try (FileInputStream fis = new FileInputStream(bootloader);
+                    FileChannel fileChannel = fis.getChannel()) {
+                fileChannel.position(packEntry.offset);
+                File outputFile = new File(outputDir, name + ".img");
+                try (FileOutputStream fos = new FileOutputStream(outputFile);
+                        FileChannel outputChannel = fos.getChannel()) {
+                    outputChannel.transferFrom(fileChannel, 0, packEntry.size);
+                }
+            }
+        }
+
+        if (unpackVersion) {
+            File versionFile = new File(outputDir, "version.txt");
+            try (FileOutputStream fos = new FileOutputStream(versionFile)) {
+                fos.write(packHeader.packVersion);
+            }
+        }
+    }
+
+    private static boolean productMatch(byte[] product, String targetProduct) {
+        String productString = bytesToString(product);
+        return Arrays.asList(productString.split("\\|")).contains(targetProduct);
+    }
+
+    private static PackHeader readPackHeader(File file) throws IOException {
+        try (FileInputStream fis = new FileInputStream(file);
+                FileChannel fileChannel = fis.getChannel()) {
+            ByteBuffer buffer = ByteBuffer.allocate(PackHeader.SIZE);
+            buffer.order(ByteOrder.LITTLE_ENDIAN);
+            fileChannel.read(buffer);
+            buffer.flip();
+            return new PackHeader(buffer);
+        }
+    }
+
+    private static PackEntry readPackEntry(FileChannel fileChannel) throws IOException {
+        ByteBuffer buffer = ByteBuffer.allocate(PackEntry.SIZE);
+        buffer.order(ByteOrder.LITTLE_ENDIAN);
+        fileChannel.read(buffer);
+        buffer.flip();
+        return new PackEntry(buffer);
+    }
+
+    private static String bytesToString(byte[] bytes) {
+        return new String(bytes).trim();
+    }
+}
diff --git a/src/com/android/tradefed/util/image/IncrementalImageUtil.java b/src/com/android/tradefed/util/image/IncrementalImageUtil.java
index 7db933701..92eed3757 100644
--- a/src/com/android/tradefed/util/image/IncrementalImageUtil.java
+++ b/src/com/android/tradefed/util/image/IncrementalImageUtil.java
@@ -25,6 +25,7 @@ import com.android.tradefed.device.IManagedTestDevice;
 import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.device.ITestDevice.RecoveryMode;
 import com.android.tradefed.device.SnapuserdWaitPhase;
+import com.android.tradefed.device.TestDevice;
 import com.android.tradefed.device.TestDeviceState;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.invoker.logger.CurrentInvocation;
@@ -43,7 +44,6 @@ import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.IRunUtil;
-import com.android.tradefed.util.MultiMap;
 import com.android.tradefed.util.RunUtil;
 import com.android.tradefed.util.ZipUtil;
 import com.android.tradefed.util.ZipUtil2;
@@ -57,6 +57,7 @@ import java.io.IOException;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashMap;
+import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
@@ -68,6 +69,7 @@ import java.util.concurrent.Future;
 import java.util.concurrent.ThreadFactory;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.atomic.AtomicInteger;
+import java.util.stream.Collectors;
 
 /** A utility to leverage the incremental image and device update. */
 public class IncrementalImageUtil {
@@ -91,6 +93,7 @@ public class IncrementalImageUtil {
     private final File mCreateSnapshotBinary;
     private final boolean mApplySnapshot;
     private final boolean mWipeAfterApplySnapshot;
+    private final boolean mUpdateBootloaderFromUserspace;
     private boolean mNewFlow;
     private final SnapuserdWaitPhase mWaitPhase;
 
@@ -111,10 +114,11 @@ public class IncrementalImageUtil {
             File createSnapshot,
             boolean isIsolatedSetup,
             boolean allowCrossRelease,
-            MultiMap<String, String> allowedbranchTransition,
+            Set<String> allowedTransition,
             boolean applySnapshot,
             boolean wipeAfterApply,
             boolean newFlow,
+            boolean updateBootloaderFromUserspace,
             SnapuserdWaitPhase waitPhase)
             throws DeviceNotAvailableException {
         // With apply snapshot, device reset is supported
@@ -141,10 +145,8 @@ public class IncrementalImageUtil {
         if (!tracker.branch.equals(build.getBuildBranch())) {
             if (applySnapshot
                     && wipeAfterApply
-                    && allowedbranchTransition.containsKey(tracker.branch)
-                    && allowedbranchTransition
-                            .get(tracker.branch)
-                            .contains(build.getBuildBranch())) {
+                    && allowedTransition.contains(tracker.branch)
+                    && allowedTransition.contains(build.getBuildBranch())) {
                 CLog.d("Allowing transition from %s => %s", tracker.branch, build.getBuildBranch());
             } else {
                 CLog.d("Newer build is not on the same branch.");
@@ -214,6 +216,7 @@ public class IncrementalImageUtil {
                 applySnapshot,
                 wipeAfterApply,
                 newFlow,
+                updateBootloaderFromUserspace,
                 waitPhase);
     }
 
@@ -227,6 +230,7 @@ public class IncrementalImageUtil {
             boolean applySnapshot,
             boolean wipeAfterApply,
             boolean newFlow,
+            boolean updateBootloaderFromUserspace,
             SnapuserdWaitPhase waitPhase) {
         mDevice = device;
         mSrcImage = deviceImage;
@@ -235,6 +239,7 @@ public class IncrementalImageUtil {
         mApplySnapshot = applySnapshot;
         mWipeAfterApplySnapshot = wipeAfterApply;
         mNewFlow = newFlow;
+        mUpdateBootloaderFromUserspace = updateBootloaderFromUserspace;
         mWaitPhase = waitPhase;
 
         mTargetImage = targetImage;
@@ -355,6 +360,10 @@ public class IncrementalImageUtil {
             return;
         }
         InvocationMetricLogger.addInvocationMetrics(InvocationMetricKey.INCREMENTAL_NEW_FLOW, 1);
+        // If enable, push the bootloader from userspace like OTA
+        if (mUpdateBootloaderFromUserspace) {
+            updateBootloaderFromUserspace(currentBootloader);
+        }
         updateDevice(currentBootloader, currentRadio);
     }
 
@@ -378,6 +387,82 @@ public class IncrementalImageUtil {
         }
     }
 
+    private void updateBootloaderFromUserspace(File currentBootloader)
+            throws DeviceNotAvailableException, TargetSetupError {
+        File bootloaderDir = null;
+        try (CloseableTraceScope ignored = new CloseableTraceScope("update_bootloader_userspace")) {
+            String listAbPartitions = mDevice.getProperty("ro.product.ab_ota_partitions");
+            if (listAbPartitions == null) {
+                throw new TargetSetupError(
+                        "Couldn't query ab_ota_partitions",
+                        InfraErrorIdentifier.INCREMENTAL_FLASHING_ERROR);
+            }
+            String bootSuffix = mDevice.getProperty("ro.boot.slot_suffix");
+            if (bootSuffix == null) {
+                throw new TargetSetupError(
+                        "Couldn't query ro.boot.slot_suffix",
+                        InfraErrorIdentifier.INCREMENTAL_FLASHING_ERROR);
+            }
+            if (bootSuffix.equals("_a")) {
+                bootSuffix = "_b";
+            } else if (bootSuffix.equals("_b")) {
+                bootSuffix = "_a";
+            } else {
+                throw new TargetSetupError(
+                        String.format("unexpected ro.boot.slot_suffix: %s", bootSuffix),
+                        InfraErrorIdentifier.INCREMENTAL_FLASHING_ERROR);
+            }
+
+            Set<String> partitions =
+                    Arrays.asList(listAbPartitions.split(",")).stream()
+                            .map(p -> p + ".img")
+                            .collect(Collectors.toSet());
+            CLog.d("Bootloader partitions to be considered: %s", partitions);
+            try {
+                bootloaderDir =
+                        FileUtil.createTempDir("bootloader", CurrentInvocation.getWorkFolder());
+                FastbootPack.unpack(currentBootloader, bootloaderDir, null, false);
+            } catch (IOException e) {
+                throw new TargetSetupError(
+                        e.getMessage(), e, InfraErrorIdentifier.INCREMENTAL_FLASHING_ERROR);
+            }
+            Set<File> toBePushed = new LinkedHashSet<File>();
+            for (File f : bootloaderDir.listFiles()) {
+                if (partitions.contains(f.getName())) {
+                    toBePushed.add(f);
+                }
+            }
+            CLog.d("Bootloader partitions to be updated: %s", toBePushed);
+            mDevice.executeShellV2Command("mkdir -p /data/bootloader");
+            for (File push : toBePushed) {
+                boolean success = mDevice.pushFile(push, "/data/bootloader/" + push.getName());
+                if (!success) {
+                    throw new TargetSetupError(
+                            "Failed to push bootloader partition.",
+                            InfraErrorIdentifier.INCREMENTAL_FLASHING_ERROR);
+                }
+            }
+            for (File write : toBePushed) {
+                CommandResult writeRes =
+                        mDevice.executeShellV2Command(
+                                String.format(
+                                        "dd if=/data/bootloader/%s of=/dev/block/by-name/%s%s",
+                                        write.getName(),
+                                        FileUtil.getBaseName(write.getName()),
+                                        bootSuffix));
+                if (!CommandStatus.SUCCESS.equals(writeRes.getStatus())) {
+                    throw new TargetSetupError(
+                            String.format(
+                                    "Failed to write bootloader partition: %s",
+                                    writeRes.getStderr()),
+                            InfraErrorIdentifier.INCREMENTAL_FLASHING_ERROR);
+                }
+            }
+        } finally {
+            FileUtil.recursiveDelete(bootloaderDir);
+        }
+    }
+
     private void internalUpdateDevice(File currentBootloader, File currentRadio)
             throws DeviceNotAvailableException, TargetSetupError {
         InvocationMetricLogger.addInvocationMetrics(
@@ -420,7 +505,19 @@ public class IncrementalImageUtil {
         try (CloseableTraceScope ignored = new CloseableTraceScope("update_device")) {
             // Once block comparison is successful, log the information
             logTargetInformation(targetDirectory);
-            logPatchesInformation(workDir);
+            long totalPatchSizes = logPatchesInformation(workDir);
+            // if we have more than 2.5GB we will overflow super partition size to /data and we
+            // can't use the feature
+            if (totalPatchSizes > 2300000000L) {
+                InvocationMetricLogger.addInvocationMetrics(
+                        InvocationMetricKey.INCREMENTAL_FALLBACK_REASON, "Patches too large.");
+                throw new TargetSetupError(
+                        String.format(
+                                "Total patch size is %s bytes. Too large to use the feature."
+                                        + " falling back",
+                                totalPatchSizes),
+                        InfraErrorIdentifier.INCREMENTAL_FLASHING_ERROR);
+            }
 
             mDevice.executeShellV2Command("mkdir -p /data/ndb");
             mDevice.executeShellV2Command("rm -rf /data/ndb/*.patch");
@@ -484,6 +581,9 @@ public class IncrementalImageUtil {
                 if (!CommandStatus.SUCCESS.equals(mapOutput.getStatus())) {
                     InvocationMetricLogger.addInvocationMetrics(
                             InvocationMetricKey.INCREMENTAL_FALLBACK_REASON, "Failed apply-update");
+                    // Clean state if apply-update fails
+                    mDevice.executeShellV2Command("snapshotctl unmap-snapshots");
+                    mDevice.executeShellV2Command("snapshotctl delete-snapshots");
                     throw new TargetSetupError(
                             String.format(
                                     "Failed to apply-update.\nstdout:%s\nstderr:%s",
@@ -505,7 +605,19 @@ public class IncrementalImageUtil {
                             InfraErrorIdentifier.INCREMENTAL_FLASHING_ERROR);
                 }
             }
-            mDevice.rebootIntoBootloader();
+            try {
+                if (mNewFlow && mDevice instanceof TestDevice) {
+                    ((TestDevice) mDevice).setFirstBootloaderReboot();
+                }
+                mDevice.rebootIntoBootloader();
+            } catch (DeviceNotAvailableException e) {
+                if (mNewFlow) {
+                    InvocationMetricLogger.addInvocationMetrics(
+                            InvocationMetricKey.INCREMENTAL_FIRST_BOOTLOADER_REBOOT_FAIL, 1);
+                }
+                throw e;
+            }
+
             if (mApplySnapshot) {
                 if (mWipeAfterApplySnapshot) {
                     CommandResult cancelResults =
@@ -595,11 +707,15 @@ public class IncrementalImageUtil {
                         mDevice.executeShellV2Command(
                                 "snapshotctl revert-snapshots", 60L, TimeUnit.SECONDS, 0);
                 if (!CommandStatus.SUCCESS.equals(revertOutput.getStatus())) {
-                    CLog.d(
-                            "Failed revert-snapshots. stdout: %s, stderr: %s",
-                            revertOutput.getStdout(), revertOutput.getStderr());
+                    String failedMessage =
+                            String.format(
+                                    "Failed revert-snapshots. stdout: %s, stderr: %s",
+                                    revertOutput.getStdout(), revertOutput.getStderr());
+                    CLog.d(failedMessage);
                     InvocationMetricLogger.addInvocationMetrics(
                             InvocationMetricKey.INCREMENTAL_FLASHING_TEARDOWN_FAILURE, 1);
+                    // Invalidate the device since it failed the revert
+                    throw new DeviceDisconnectedException(failedMessage, mDevice.getSerialNumber());
                 }
                 if (mSourceDirectory != null) {
                     // flash all static partition in bootloader
@@ -784,17 +900,20 @@ public class IncrementalImageUtil {
         return true;
     }
 
-    private void logPatchesInformation(File patchesDirectory) {
+    private long logPatchesInformation(File patchesDirectory) {
+        long totalPatchesSize = 0L;
         for (File patch : patchesDirectory.listFiles()) {
             if (patch == null) {
                 CLog.w("Something went wrong listing %s", patchesDirectory);
-                return;
+                return 0L;
             }
+            totalPatchesSize += patch.length();
             InvocationMetricLogger.addInvocationMetrics(
                     InvocationGroupMetricKey.INCREMENTAL_FLASHING_PATCHES_SIZE,
                     patch.getName(),
                     patch.length());
         }
+        return totalPatchesSize;
     }
 
     private void logTargetInformation(File targetDirectory) {
diff --git a/src/com/android/tradefed/util/image/PackEntry.java b/src/com/android/tradefed/util/image/PackEntry.java
new file mode 100644
index 000000000..90f5fb62c
--- /dev/null
+++ b/src/com/android/tradefed/util/image/PackEntry.java
@@ -0,0 +1,41 @@
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
+package com.android.tradefed.util.image;
+
+import java.nio.ByteBuffer;
+
+class PackEntry {
+    public static final int SIZE = 104; // 4 bytes per field
+    public int type;
+    public byte[] name;
+    public byte[] product;
+    public long offset;
+    public long size;
+    public int slotted;
+    public int crc32;
+
+    public PackEntry(ByteBuffer buffer) {
+        type = buffer.getInt();
+        name = new byte[36];
+        buffer.get(name);
+        product = new byte[40];
+        buffer.get(product);
+        offset = buffer.getLong();
+        size = buffer.getLong();
+        slotted = buffer.getInt();
+        crc32 = buffer.getInt();
+    }
+}
diff --git a/src/com/android/tradefed/util/image/PackHeader.java b/src/com/android/tradefed/util/image/PackHeader.java
new file mode 100644
index 000000000..9e90ae2ae
--- /dev/null
+++ b/src/com/android/tradefed/util/image/PackHeader.java
@@ -0,0 +1,47 @@
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
+package com.android.tradefed.util.image;
+
+import java.nio.ByteBuffer;
+
+class PackHeader {
+    public static final int SIZE = 112; // 4 bytes per field
+    public int magic;
+    public int version;
+    public int headerSize;
+    public int entryHeaderSize;
+    public byte[] platform;
+    public byte[] packVersion;
+    public int slotType;
+    public int dataAlign;
+    public int totalEntries;
+    public int totalSize;
+
+    public PackHeader(ByteBuffer buffer) {
+        magic = buffer.getInt();
+        version = buffer.getInt();
+        headerSize = buffer.getInt();
+        entryHeaderSize = buffer.getInt();
+        platform = new byte[16];
+        buffer.get(platform);
+        packVersion = new byte[64];
+        buffer.get(packVersion);
+        slotType = buffer.getInt();
+        dataAlign = buffer.getInt();
+        totalEntries = buffer.getInt();
+        totalSize = buffer.getInt();
+    }
+}
diff --git a/src/com/android/tradefed/util/testmapping/TestMapping.java b/src/com/android/tradefed/util/testmapping/TestMapping.java
index 2199a8abd..818fa17af 100644
--- a/src/com/android/tradefed/util/testmapping/TestMapping.java
+++ b/src/com/android/tradefed/util/testmapping/TestMapping.java
@@ -713,7 +713,11 @@ public class TestMapping {
             Set<String> targetNames = getTestMappingSources(zipFile);
             validateSources(baseNames, targetNames, zipName);
             baseNames.addAll(targetNames);
-            ZipUtil2.extractZip(zipFile, baseDir);
+            if (zipFile.isDirectory()) {
+                FileUtil.recursiveHardlink(zipFile, baseDir);
+            } else {
+                ZipUtil2.extractZip(zipFile, baseDir);
+            }
         }
     }
 
@@ -743,26 +747,47 @@ public class TestMapping {
     @VisibleForTesting
     Set<String> getTestMappingSources(File zipFile) {
         Set<String> fileNames = new HashSet<>();
-        Enumeration<? extends ZipArchiveEntry> entries = null;
-        ZipFile f = null;
-        try {
-            f = new ZipFile(zipFile);
-            entries = f.getEntries();
-        } catch (IOException e) {
-            throw new RuntimeException(
-                    String.format(
-                            "IO exception (%s) when accessing test_mappings.zip (%s)",
-                            e.getMessage(), zipFile),
-                    e);
-        } finally {
-            ZipUtil2.closeZip(f);
-        }
-        while (entries.hasMoreElements()) {
-            ZipArchiveEntry entry = entries.nextElement();
-            // TODO: Temporarily exclude disabled-presubmit-test file. We'll need to revisit if that
-            // file is used on the older branch/target, if no, remove that file.
-            if (!entry.isDirectory() && !entry.getName().equals(DISABLED_PRESUBMIT_TESTS_FILE)) {
-                fileNames.add(entry.getName());
+        if (zipFile.isDirectory()) {
+            Path zipFileDir = Paths.get(zipFile.getAbsolutePath());
+            try (Stream<Path> stream = Files.walk(zipFileDir, FileVisitOption.FOLLOW_LINKS)) {
+                stream.filter(path -> path.getFileName().toString().equals(TEST_MAPPING))
+                        .forEach(
+                                path ->
+                                        fileNames.add(
+                                                zipFileDir
+                                                        .relativize(path.toAbsolutePath())
+                                                        .toString()));
+
+            } catch (IOException e) {
+                throw new RuntimeException(
+                        String.format(
+                                "IO exception (%s) when reading tests from TEST_MAPPING files (%s)",
+                                e.getMessage(), zipFile.getAbsolutePath()),
+                        e);
+            }
+        } else {
+            Enumeration<? extends ZipArchiveEntry> entries = null;
+            ZipFile f = null;
+            try {
+                f = new ZipFile(zipFile);
+                entries = f.getEntries();
+            } catch (IOException e) {
+                throw new RuntimeException(
+                        String.format(
+                                "IO exception (%s) when accessing test_mappings.zip (%s)",
+                                e.getMessage(), zipFile),
+                        e);
+            } finally {
+                ZipUtil2.closeZip(f);
+            }
+            while (entries.hasMoreElements()) {
+                ZipArchiveEntry entry = entries.nextElement();
+                // TODO: Temporarily exclude disabled-presubmit-test file. We'll need to revisit if
+                // that file is used on the older branch/target, if no, remove that file.
+                if (!entry.isDirectory()
+                        && !entry.getName().equals(DISABLED_PRESUBMIT_TESTS_FILE)) {
+                    fileNames.add(entry.getName());
+                }
             }
         }
         return fileNames;
diff --git a/test_framework/com/android/tradefed/targetprep/FastbootCommandPreparer.java b/test_framework/com/android/tradefed/targetprep/FastbootCommandPreparer.java
index 003fbf55d..82417891e 100644
--- a/test_framework/com/android/tradefed/targetprep/FastbootCommandPreparer.java
+++ b/test_framework/com/android/tradefed/targetprep/FastbootCommandPreparer.java
@@ -15,6 +15,7 @@
  */
 package com.android.tradefed.targetprep;
 
+import com.android.tradefed.build.IBuildInfo;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.config.OptionClass;
 import com.android.tradefed.device.DeviceNotAvailableException;
@@ -22,18 +23,20 @@ import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.result.error.InfraErrorIdentifier;
 import com.android.tradefed.util.CommandResult;
-
+import java.io.File;
 import java.util.ArrayList;
 import java.util.List;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
 
-/**
- * Target preparer that triggers fastboot and sends fastboot commands.
- *
- * <p>TODO(b/122592575): Add tests for this preparer.
- */
+/** Target preparer that triggers fastboot and sends fastboot commands. */
 @OptionClass(alias = "fastboot-command-preparer")
 public final class FastbootCommandPreparer extends BaseTargetPreparer {
 
+    /** Placeholder to be replaced with real file path in commands */
+    private static final Pattern EXTRA_FILE_PATTERSTRING =
+            Pattern.compile("\\$EXTRA_FILE\\(([^()]+)\\)");
+
     private enum FastbootMode {
         BOOTLOADER,
         FASTBOOTD,
@@ -41,7 +44,9 @@ public final class FastbootCommandPreparer extends BaseTargetPreparer {
 
     @Option(
             name = "fastboot-mode",
-            description = "True to boot the device into bootloader mode, false for fastbootd mode.")
+            description =
+                    "'BOOTLOADER' to boot the device into bootloader mode, "
+                            + "'FASTBOOTD' for fastbootd mode.")
     private FastbootMode mFastbootMode = FastbootMode.BOOTLOADER;
 
     @Option(
@@ -69,8 +74,10 @@ public final class FastbootCommandPreparer extends BaseTargetPreparer {
     public void setUp(TestInformation testInformation)
             throws TargetSetupError, BuildError, DeviceNotAvailableException {
         if (!mFastbootCommands.isEmpty()) {
+            final IBuildInfo buildInfo = testInformation.getBuildInfo();
             final ITestDevice device = testInformation.getDevice();
             enterFastboot(device);
+            replaceExtraFile(mFastbootCommands, buildInfo);
             for (String cmd : mFastbootCommands) {
                 final CommandResult result = device.executeFastbootCommand(cmd.split("\\s+"));
                 if (result.getExitCode() != 0) {
@@ -92,7 +99,9 @@ public final class FastbootCommandPreparer extends BaseTargetPreparer {
             throws DeviceNotAvailableException {
         if (!mFastbootTearDownCommands.isEmpty()) {
             final ITestDevice device = testInformation.getDevice();
+            final IBuildInfo buildInfo = testInformation.getBuildInfo();
             enterFastboot(device);
+            replaceExtraFile(mFastbootTearDownCommands, buildInfo);
             for (String cmd : mFastbootTearDownCommands) {
                 device.executeFastbootCommand(cmd.split("\\s+"));
             }
@@ -113,4 +122,29 @@ public final class FastbootCommandPreparer extends BaseTargetPreparer {
             device.reboot();
         }
     }
-}
+
+    /**
+     * For each command in the list, replace placeholder (if any) with the file name indicated in
+     * the build information
+     *
+     * @param commands list of host commands
+     * @param buildInfo build artifact information
+     */
+    private void replaceExtraFile(final List<String> commands, IBuildInfo buildInfo) {
+        for (int i = 0; i < commands.size(); i++) {
+            Matcher matcher = EXTRA_FILE_PATTERSTRING.matcher(commands.get(i));
+            StringBuffer command = new StringBuffer();
+
+            while (matcher.find()) {
+                String fileName = matcher.group(1);
+                File file = buildInfo.getFile(fileName);
+                if (file == null || !file.exists()) {
+                    continue;
+                }
+                matcher.appendReplacement(command, file.getPath());
+            }
+            matcher.appendTail(command);
+            commands.set(i, command.toString());
+        }
+    }
+}
\ No newline at end of file
diff --git a/test_framework/com/android/tradefed/targetprep/PushFilePreparer.java b/test_framework/com/android/tradefed/targetprep/PushFilePreparer.java
index f242f5013..ce32b5181 100644
--- a/test_framework/com/android/tradefed/targetprep/PushFilePreparer.java
+++ b/test_framework/com/android/tradefed/targetprep/PushFilePreparer.java
@@ -41,6 +41,7 @@ import com.android.tradefed.testtype.suite.ModuleDefinition;
 import com.android.tradefed.util.AbiUtils;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.MultiMap;
+import com.android.tradefed.util.SearchArtifactUtil;
 
 import java.io.File;
 import java.io.IOException;
@@ -247,6 +248,9 @@ public class PushFilePreparer extends BaseTargetPreparer
                         File moduleDir =
                                 FileUtil.findDirectory(
                                         mModuleName, scanDirs.toArray(new File[] {}));
+                        if (moduleDir == null) {
+                            moduleDir = SearchArtifactUtil.getModuleDirFromConfig();
+                        }
                         if (moduleDir != null) {
                             // If the spec is pushing the module itself
                             if (mModuleName.equals(fileName)) {
diff --git a/test_framework/com/android/tradefed/testtype/AndroidJUnitTest.java b/test_framework/com/android/tradefed/testtype/AndroidJUnitTest.java
index 6033b2d46..fac906bb6 100644
--- a/test_framework/com/android/tradefed/testtype/AndroidJUnitTest.java
+++ b/test_framework/com/android/tradefed/testtype/AndroidJUnitTest.java
@@ -54,9 +54,8 @@ import java.util.ArrayList;
 import java.util.Collection;
 import java.util.Collections;
 import java.util.HashMap;
-import java.util.HashSet;
-import java.util.List;
 import java.util.LinkedHashSet;
+import java.util.List;
 import java.util.Set;
 import java.util.regex.Pattern;
 import java.util.regex.PatternSyntaxException;
@@ -132,23 +131,13 @@ public class AndroidJUnitTest extends InstrumentationTest
             name = "include-annotation",
             description = "The annotation class name of the test name to run, can be repeated",
             requiredForRerun = true)
-    private Set<String> mIncludeAnnotation = new HashSet<>();
+    private Set<String> mIncludeAnnotation = new LinkedHashSet<>();
 
     @Option(
             name = "exclude-annotation",
             description = "The notAnnotation class name of the test name to run, can be repeated",
             requiredForRerun = true)
-    private Set<String> mExcludeAnnotation = new HashSet<>();
-
-    @Option(name = "test-file-include-filter",
-            description="A file containing a list of line separated test classes and optionally"
-            + " methods to include")
-    private File mIncludeTestFile = null;
-
-    @Option(name = "test-file-exclude-filter",
-            description="A file containing a list of line separated test classes and optionally"
-            + " methods to exclude")
-    private File mExcludeTestFile = null;
+    private Set<String> mExcludeAnnotation = new LinkedHashSet<>();
 
     @Option(name = "test-filter-dir",
             description="The device directory path to which the test filtering files are pushed")
@@ -187,6 +176,8 @@ public class AndroidJUnitTest extends InstrumentationTest
     // Default to true as it is harmless if not supported.
     private boolean mNewRunListenerOrderMode = true;
 
+    private File mInternalIncludeTestFile = null;
+    private File mInternalExcludeTestFile = null;
     private String mDeviceIncludeFile = null;
     private String mDeviceExcludeFile = null;
     private int mTotalShards = 0;
@@ -266,13 +257,13 @@ public class AndroidJUnitTest extends InstrumentationTest
     /** {@inheritDoc} */
     @Override
     public void setIncludeTestFile(File testFile) {
-        mIncludeTestFile = testFile;
+        mInternalIncludeTestFile = testFile;
     }
 
     /** {@inheritDoc} */
     @Override
     public File getIncludeTestFile() {
-        return mIncludeTestFile;
+        return mInternalIncludeTestFile;
     }
 
     /**
@@ -280,13 +271,13 @@ public class AndroidJUnitTest extends InstrumentationTest
      */
     @Override
     public void setExcludeTestFile(File testFile) {
-        mExcludeTestFile = testFile;
+        mInternalExcludeTestFile = testFile;
     }
 
     /** {@inheritDoc} */
     @Override
     public File getExcludeTestFile() {
-        return mExcludeTestFile;
+        return mInternalExcludeTestFile;
     }
 
     /**
@@ -375,30 +366,32 @@ public class AndroidJUnitTest extends InstrumentationTest
 
         boolean pushedFile = false;
         try (CloseableTraceScope filter = new CloseableTraceScope("push_filter_files")) {
-            // if mIncludeTestFile is set, perform filtering with this file
-            if (mIncludeTestFile != null && mIncludeTestFile.length() > 0) {
+            // if mInternalIncludeTestFile is set, perform filtering with this file
+            if (mInternalIncludeTestFile != null && mInternalIncludeTestFile.length() > 0) {
                 mDeviceIncludeFile = mTestFilterDir.replaceAll("/$", "") + "/" + INCLUDE_FILE;
-                pushTestFile(mIncludeTestFile, mDeviceIncludeFile, listener);
+                pushTestFile(mInternalIncludeTestFile, mDeviceIncludeFile, listener, false);
                 if (mUseTestStorage) {
                     pushTestFile(
-                            mIncludeTestFile,
+                            mInternalIncludeTestFile,
                             mTestStorageInternalDir + mDeviceIncludeFile,
-                            listener);
+                            listener,
+                            true);
                 }
                 pushedFile = true;
                 // If an explicit include file filter is provided, do not use the package
                 setTestPackageName(null);
             }
 
-            // if mExcludeTestFile is set, perform filtering with this file
-            if (mExcludeTestFile != null && mExcludeTestFile.length() > 0) {
+            // if mInternalExcludeTestFile is set, perform filtering with this file
+            if (mInternalExcludeTestFile != null && mInternalExcludeTestFile.length() > 0) {
                 mDeviceExcludeFile = mTestFilterDir.replaceAll("/$", "") + "/" + EXCLUDE_FILE;
-                pushTestFile(mExcludeTestFile, mDeviceExcludeFile, listener);
+                pushTestFile(mInternalExcludeTestFile, mDeviceExcludeFile, listener, false);
                 if (mUseTestStorage) {
                     pushTestFile(
-                            mExcludeTestFile,
+                            mInternalExcludeTestFile,
                             mTestStorageInternalDir + mDeviceExcludeFile,
-                            listener);
+                            listener,
+                            true);
                 }
                 pushedFile = true;
             }
@@ -503,9 +496,24 @@ public class AndroidJUnitTest extends InstrumentationTest
                         || !notClassArg.isEmpty()
                         || !packageArg.isEmpty()
                         || !notPackageArg.isEmpty())) {
+            StringBuilder sb = new StringBuilder();
+            if (!classArg.isEmpty()) {
+                sb.append("classArg: " + classArg);
+            }
+            if (!notClassArg.isEmpty()) {
+                sb.append("notClassArg: " + notClassArg);
+            }
+            if (!packageArg.isEmpty()) {
+                sb.append("packageArg: " + packageArg);
+            }
+            if (!notPackageArg.isEmpty()) {
+                sb.append("notPackageArg: " + notPackageArg);
+            }
             throw new IllegalArgumentException(
-                    "Mixed filter types found. AndroidJUnitTest does not support mixing both regex"
-                            + " and class/method/package filters.");
+                    String.format(
+                            "Mixed filter types found. AndroidJUnitTest does not support mixing"
+                                    + " both regex [%s] and class/method/package filters: [%s]",
+                            regexArg, sb.toString()));
         }
         if (!classArg.isEmpty()) {
             runner.addInstrumentationArg(INCLUDE_CLASS_INST_ARGS_KEY,
@@ -565,7 +573,8 @@ public class AndroidJUnitTest extends InstrumentationTest
      * @param destination the path on the device to which testFile is pushed
      * @param listener {@link ITestInvocationListener} to report failures.
      */
-    private void pushTestFile(File testFile, String destination, ITestInvocationListener listener)
+    private void pushTestFile(
+            File testFile, String destination, ITestInvocationListener listener, boolean skipLog)
             throws DeviceNotAvailableException {
         if (!testFile.canRead() || !testFile.isFile()) {
             String message = String.format("Cannot read test file %s", testFile.getAbsolutePath());
@@ -597,6 +606,9 @@ public class AndroidJUnitTest extends InstrumentationTest
             reportEarlyFailure(listener, e.getMessage());
             throw e;
         }
+        if (skipLog) {
+            return;
+        }
         try (FileInputStreamSource source = new FileInputStreamSource(testFile)) {
             listener.testLog("filter-" + testFile.getName(), LogDataType.TEXT, source);
         }
@@ -719,6 +731,8 @@ public class AndroidJUnitTest extends InstrumentationTest
         shard.mTotalShards = shardCount;
         shard.mIsSharded = true;
         shard.setAbi(getAbi());
+        shard.mInternalExcludeTestFile = mInternalExcludeTestFile;
+        shard.mInternalIncludeTestFile = mInternalIncludeTestFile;
         // We approximate the runtime of each shard to be equal since we can't know.
         shard.mRuntimeHint = mRuntimeHint / shardCount;
         return shard;
diff --git a/test_framework/com/android/tradefed/testtype/ArtRunTest.java b/test_framework/com/android/tradefed/testtype/ArtRunTest.java
index 6038f1973..07dc25acf 100644
--- a/test_framework/com/android/tradefed/testtype/ArtRunTest.java
+++ b/test_framework/com/android/tradefed/testtype/ArtRunTest.java
@@ -282,7 +282,8 @@ public class ArtRunTest
             CLog.d("Created temporary local directory `%s` for test", tmpTestLocalDir);
 
             File localStdoutFile = new File(tmpTestLocalDir, STDOUT_FILE_NAME);
-            if (!pullAndCheckFile(remoteStdoutFilePath, localStdoutFile)) {
+            if (!pullAndCheckFile(
+                    remoteStdoutFilePath, localStdoutFile, LogDataType.TEXT, listener)) {
                 throw new IOException(
                         String.format(
                                 "Error while pulling remote file `%s` to local file `%s`",
@@ -291,7 +292,8 @@ public class ArtRunTest
             String actualStdoutText = FileUtil.readStringFromFile(localStdoutFile);
 
             File localStderrFile = new File(tmpTestLocalDir, STDERR_FILE_NAME);
-            if (!pullAndCheckFile(remoteStderrFilePath, localStderrFile)) {
+            if (!pullAndCheckFile(
+                    remoteStderrFilePath, localStderrFile, LogDataType.TEXT, listener)) {
                 throw new IOException(
                         String.format(
                                 "Error while pulling remote file `%s` to local file `%s`",
@@ -338,9 +340,7 @@ public class ArtRunTest
             }
 
             // If the test is a Checker test, run Checker and check its output.
-            // Do not run Checker tests in code coverage runs, as the Checker assumption might fail
-            // because of the added instrumentation code (see b/356852324).
-            if (mRunTestName.contains("-checker-") && !isJavaCoverageEnabled()) {
+            if (mRunTestName.contains("-checker-")) {
                 Optional<String> checkerError = executeCheckerTest(testInfo, listener);
                 checkerError.ifPresent(errors::add);
             }
@@ -511,6 +511,13 @@ public class ArtRunTest
                         "Error while running dex2oat: %s", dex2oatResult.getStderr());
             }
 
+            // Skip pulling the CFG file and running the Checker script if Java
+            // code coverage is enabled, as the Checker assumptions might fail
+            // because of the added instrumentation code (see b/356852324).
+            if (isJavaCoverageEnabled()) {
+                return Optional.empty();
+            }
+
             tmpCheckerLocalDir =
                     FileUtil.createTempDir(mRunTestName, CurrentInvocation.getWorkFolder());
             CLog.d("Created temporary local directory `%s` for Checker test", tmpCheckerLocalDir);
@@ -520,12 +527,12 @@ public class ArtRunTest
                 localCfgPath.delete();
             }
 
-            if (!pullAndCheckFile(cfgPath, localCfgPath)) {
+            if (!pullAndCheckFile(cfgPath, localCfgPath, LogDataType.CFG, listener)) {
                 throw new IOException("Cannot pull CFG file from the device");
             }
 
             File tempJar = new File(tmpCheckerLocalDir, "temp.jar");
-            if (!pullAndCheckFile(mClasspath.get(0), tempJar)) {
+            if (!pullAndCheckFile(mClasspath.get(0), tempJar, LogDataType.ZIP, listener)) {
                 throw new IOException("Cannot pull JAR file from the device");
             }
 
@@ -713,7 +720,8 @@ public class ArtRunTest
 
     /**
      * Retrieve a file off device and verify that file was transferred correctly by comparing the
-     * sizes and MD5 digests of the original file (on device) and its (local) copy.
+     * sizes and MD5 digests of the original file (on device) and its (local) copy. In the case of
+     * an incorrect transfer, log the filed pulled from the device as a TradeFed artifact.
      *
      * <p>This method is essentially a wrapper around {@link
      * com.android.tradefed.device.INativeDevice#pullFile}, which has its own way to signal that a
@@ -724,6 +732,9 @@ public class ArtRunTest
      * @param remoteFilePath The absolute path to file on device.
      * @param localFile The local file to store contents in. If non-empty, contents will be
      *     replaced.
+     * @param logDataType The data type of the logged pulled filed, in case of an incorrect
+     *     transfer.
+     * @param listener The {@link ITestInvocationListener} object associated to the executed test.
      * @return <code>true</code> if file was retrieved successfully. <code>false</code> otherwise.
      * @throws DeviceNotAvailableException If connection with device is lost and cannot be
      *     recovered.
@@ -731,7 +742,11 @@ public class ArtRunTest
      *     from the device failed.
      * @throws IOException If the file size check or the MD5 digest check failed.
      */
-    private boolean pullAndCheckFile(String remoteFilePath, File localFile)
+    private boolean pullAndCheckFile(
+            String remoteFilePath,
+            File localFile,
+            LogDataType logDataType,
+            ITestInvocationListener listener)
             throws DeviceNotAvailableException, AdbShellCommandException, IOException {
         // Get the size of the remote file on device.
         long maxStatCmdTimeInMs = 10 * 1000; // 10 seconds.
@@ -770,6 +785,11 @@ public class ArtRunTest
                                     + "pulled from device: %d bytes vs %d bytes",
                             localFile, remoteFilePath, localFileSize, remoteFileSize);
             CLog.e(message);
+            try (FileInputStreamSource source = new FileInputStreamSource(localFile)) {
+                String fileName = localFile.getName();
+                listener.testLog(fileName, logDataType, source);
+                CLog.d("Logged incorrectly transferred file `%s`", fileName);
+            }
             throw new IOException(message);
         }
 
@@ -781,6 +801,11 @@ public class ArtRunTest
                                     + "file `%s` pulled from device: %s vs %s",
                             localFile, remoteFilePath, localMd5Digest, remoteMd5Digest);
             CLog.e(message);
+            try (FileInputStreamSource source = new FileInputStreamSource(localFile)) {
+                String fileName = localFile.getName();
+                listener.testLog(fileName, logDataType, source);
+                CLog.d("Logged incorrectly transferred file `%s`", fileName);
+            }
             throw new IOException(message);
         }
 
diff --git a/test_framework/com/android/tradefed/testtype/GTest.java b/test_framework/com/android/tradefed/testtype/GTest.java
index 6c470c1ed..894e29849 100644
--- a/test_framework/com/android/tradefed/testtype/GTest.java
+++ b/test_framework/com/android/tradefed/testtype/GTest.java
@@ -252,7 +252,7 @@ public class GTest extends GTestBase implements IDeviceTest {
         }
 
         // filter out files excluded by the exclusion regex, for example .so files
-        List<String> fileExclusionFilterRegex = getFileExclusionFilterRegex();
+        Set<String> fileExclusionFilterRegex = getFileExclusionFilterRegex();
         for (String regex : fileExclusionFilterRegex) {
             if (fullPath.matches(regex)) {
                 CLog.i("File %s matches exclusion file regex %s, skipping", fullPath, regex);
diff --git a/test_framework/com/android/tradefed/testtype/GTestBase.java b/test_framework/com/android/tradefed/testtype/GTestBase.java
index 78acce987..cc2b0e55e 100644
--- a/test_framework/com/android/tradefed/testtype/GTestBase.java
+++ b/test_framework/com/android/tradefed/testtype/GTestBase.java
@@ -76,7 +76,8 @@ public abstract class GTestBase
     @Option(
             name = "file-exclusion-filter-regex",
             description = "Regex to exclude certain files from executing. Can be repeated")
-    private List<String> mFileExclusionFilterRegex = new ArrayList<>(DEFAULT_FILE_EXCLUDE_FILTERS);
+    private Set<String> mFileExclusionFilterRegex =
+            new LinkedHashSet<>(DEFAULT_FILE_EXCLUDE_FILTERS);
 
     @Option(
             name = "positive-testname-filter",
@@ -415,7 +416,7 @@ public abstract class GTestBase
     }
 
     /** Gets regex to exclude certain files from executing. */
-    public List<String> getFileExclusionFilterRegex() {
+    public Set<String> getFileExclusionFilterRegex() {
         return mFileExclusionFilterRegex;
     }
 
diff --git a/test_framework/com/android/tradefed/testtype/GTestResultParser.java b/test_framework/com/android/tradefed/testtype/GTestResultParser.java
index 5fb17fd10..7716c8106 100644
--- a/test_framework/com/android/tradefed/testtype/GTestResultParser.java
+++ b/test_framework/com/android/tradefed/testtype/GTestResultParser.java
@@ -105,6 +105,8 @@ public class GTestResultParser extends MultiLineReceiver {
     private boolean mTestInProgress = false;
     private CloseableTraceScope mMethodScope = null;
     private boolean mTestRunInProgress = false;
+    private boolean mAllowRustTestName = false;
+
     private final String mTestRunName;
     private final Collection<ITestInvocationListener> mTestListeners;
 
@@ -252,6 +254,21 @@ public class GTestResultParser extends MultiLineReceiver {
         setTrimLine(false);
     }
 
+    /**
+     * Creates the GTestResultParser.
+     *
+     * @param testRunName the test run name to provide to {@link
+     *     ITestInvocationListener#testRunStarted(String, int)}
+     * @param listeners informed of test results as the tests are executing
+     * @param allowRustTestName allow test names to not follow the '::' separation pattern
+     */
+    public GTestResultParser(
+            String testRunName,
+            Collection<ITestInvocationListener> listeners,
+            boolean allowRustTestName) {
+        this(testRunName, listeners);
+    }
+
     /**
      * Creates the GTestResultParser for a single listener.
      *
@@ -263,6 +280,20 @@ public class GTestResultParser extends MultiLineReceiver {
         this(testRunName, Arrays.asList(listener));
     }
 
+    /**
+     * Creates the GTestResultParser for a single listener.
+     *
+     * @param testRunName the test run name to provide to {@link
+     *     ITestInvocationListener#testRunStarted(String, int)}
+     * @param listener informed of test results as the tests are executing
+     * @param allowRustTestName allow test names to not follow the '.' separated pattern
+     */
+    public GTestResultParser(
+            String testRunName, ITestInvocationListener listener, boolean allowRustTestName) {
+        this(testRunName, listener);
+        mAllowRustTestName = allowRustTestName;
+    }
+
     /**
      * Returns the current TestResult for test in progress, or a new default one.
      *
@@ -519,6 +550,12 @@ public class GTestResultParser extends MultiLineReceiver {
         }
 
         String[] testId = identifier.split("\\.");
+        if (testId.length < 2) {
+            if (mAllowRustTestName) {
+                // split from the last `::`
+                testId = identifier.split("::(?!.*::.*)");
+            }
+        }
         if (testId.length < 2) {
             CLog.e("Could not detect the test class and test name, received: %s", identifier);
             returnInfo.mTestClassName = null;
diff --git a/test_framework/com/android/tradefed/testtype/GoogleBenchmarkResultParser.java b/test_framework/com/android/tradefed/testtype/GoogleBenchmarkResultParser.java
index 1148b77e6..78e8b6cf4 100644
--- a/test_framework/com/android/tradefed/testtype/GoogleBenchmarkResultParser.java
+++ b/test_framework/com/android/tradefed/testtype/GoogleBenchmarkResultParser.java
@@ -17,10 +17,10 @@ package com.android.tradefed.testtype;
 
 import com.android.tradefed.invoker.tracing.CloseableTraceScope;
 import com.android.tradefed.log.LogUtil.CLog;
-import com.android.tradefed.result.error.TestErrorIdentifier;
 import com.android.tradefed.result.FailureDescription;
 import com.android.tradefed.result.ITestInvocationListener;
 import com.android.tradefed.result.TestDescription;
+import com.android.tradefed.result.error.TestErrorIdentifier;
 import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
 import com.android.tradefed.util.proto.TfMetricProtoUtil;
@@ -36,6 +36,7 @@ import java.util.Iterator;
 import java.util.Map;
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
+
 /**
  * Parses the results of Google Benchmark that run from shell,
  * and return a map with all the results.
@@ -52,7 +53,8 @@ public class GoogleBenchmarkResultParser {
 
     /**
      * Parse an individual output line.
-     * name,iterations,real_time,cpu_time,bytes_per_second,items_per_second,label
+     * name,iterations,real_time,cpu_time,time_unit,bytes_per_second,items_per_second,label,
+     * error_occurred,error_message
      *
      * @param cmd_result device command result that contains the test output
      * @return a map containing the number of tests that ran.
@@ -180,7 +182,11 @@ public class GoogleBenchmarkResultParser {
         Iterator<?> i = j.keys();
         while(i.hasNext()) {
             String key = (String) i.next();
-            testResults.put(key, j.get(key).toString());
+            if (key.endsWith("time")) {
+                testResults.put(key + "_" + j.get("time_unit").toString(), j.get(key).toString());
+            } else {
+                testResults.put(key, j.get(key).toString());
+            }
         }
         return testResults;
     }
diff --git a/test_framework/com/android/tradefed/testtype/HostGTest.java b/test_framework/com/android/tradefed/testtype/HostGTest.java
index bdc57e77f..3e0798a58 100644
--- a/test_framework/com/android/tradefed/testtype/HostGTest.java
+++ b/test_framework/com/android/tradefed/testtype/HostGTest.java
@@ -17,30 +17,24 @@
 package com.android.tradefed.testtype;
 
 import static com.android.tradefed.testtype.coverage.CoverageOptions.Toolchain.CLANG;
+import static com.android.tradefed.util.EnvironmentVariableUtil.buildMinimalLdLibraryPath;
 
 import com.android.ddmlib.IShellOutputReceiver;
 import com.android.tradefed.build.BuildInfoKey.BuildInfoFileKey;
 import com.android.tradefed.build.DeviceBuildInfo;
 import com.android.tradefed.build.IBuildInfo;
-import com.android.tradefed.cache.ExecutableActionResult;
 import com.android.tradefed.cache.ICacheClient;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.config.OptionClass;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.error.HarnessRuntimeException;
 import com.android.tradefed.invoker.TestInformation;
-import com.android.tradefed.invoker.TestInvocation;
-import com.android.tradefed.invoker.logger.CurrentInvocation;
 import com.android.tradefed.log.ITestLogger;
 import com.android.tradefed.log.LogUtil.CLog;
-import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
-import com.android.tradefed.result.FailureDescription;
 import com.android.tradefed.result.FileInputStreamSource;
 import com.android.tradefed.result.ITestInvocationListener;
 import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.TestRunResultListener;
 import com.android.tradefed.result.error.TestErrorIdentifier;
-import com.android.tradefed.result.proto.TestRecordProto.FailureStatus;
 import com.android.tradefed.util.CacheClientFactory;
 import com.android.tradefed.util.ClangProfileIndexer;
 import com.android.tradefed.util.CommandResult;
@@ -51,8 +45,6 @@ import com.android.tradefed.util.RunUtil;
 import com.android.tradefed.util.ShellOutputReceiverStream;
 import com.android.tradefed.util.TestRunnerUtil;
 
-import com.google.common.base.Strings;
-
 import org.json.JSONException;
 import org.json.JSONObject;
 
@@ -60,7 +52,7 @@ import java.io.File;
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.util.ArrayList;
-import java.util.HashMap;
+import java.util.Arrays;
 import java.util.LinkedHashMap;
 import java.util.LinkedHashSet;
 import java.util.List;
@@ -80,11 +72,6 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
             description = "Whether to use the updated logic for retry with sharding.")
     private boolean mUseUpdatedShardRetry = true;
 
-    @Option(
-            name = "enable-cache",
-            description = "Used to enable/disable caching for specific modules.")
-    private boolean mEnableCache = false;
-
     @Option(
             name = "inherit-env-vars",
             description =
@@ -92,14 +79,17 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
                             + " process.")
     private boolean mInheritEnvVars = true;
 
+    @Option(
+            name = "use-minimal-shared-libs",
+            description = "Whether use the shared libs in per module folder.")
+    private boolean mUseMinimalSharedLibs = false;
+
     /** Whether any incomplete test is found in the current run. */
     private boolean mIncompleteTestFound = false;
 
     /** List of tests that failed in the current test run when test run was complete. */
     private Set<String> mCurFailedTests = new LinkedHashSet<>();
 
-    private TestRunResultListener mTestRunResultListener;
-
     @Override
     public void setBuild(IBuildInfo buildInfo) {
         this.mBuildInfo = buildInfo;
@@ -154,11 +144,6 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
         // Set the working dir to the folder containing the binary to execute from the same path.
         runUtil.setWorkingDir(gtestFile.getParentFile());
 
-        String instanceName =
-                mEnableCache
-                        ? getConfiguration().getCommandOptions().getRemoteCacheInstanceName()
-                        : null;
-
         String separator = System.getProperty("path.separator");
         List<String> paths = new ArrayList<>();
         paths.add("/usr/bin");
@@ -170,7 +155,11 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
         runUtil.setEnvVariable("PATH", path);
 
         // Update LD_LIBRARY_PATH
-        String ldLibraryPath = TestRunnerUtil.getLdLibraryPath(gtestFile);
+        String ldLibraryPath =
+                mUseMinimalSharedLibs
+                        ? buildMinimalLdLibraryPath(
+                                gtestFile.getParentFile(), Arrays.asList("shared_libs"))
+                        : TestRunnerUtil.getLdLibraryPath(gtestFile);
         if (ldLibraryPath != null) {
             runUtil.setEnvVariable("LD_LIBRARY_PATH", ldLibraryPath);
         }
@@ -192,19 +181,13 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
         // command output will just be ignored.
         CommandResult result = null;
         File stdout = null;
-        ICacheClient cacheClient =
-                Strings.isNullOrEmpty(instanceName)
-                        ? null
-                        : getCacheClient(CurrentInvocation.getWorkFolder(), instanceName);
         try {
             stdout =
                     FileUtil.createTempFile(
                             String.format("%s-output", gtestFile.getName()), ".txt");
             try (ShellOutputReceiverStream stream =
                     new ShellOutputReceiverStream(receiver, new FileOutputStream(stdout))) {
-                result =
-                        runUtil.runTimedCmdWithOutputMonitor(
-                                timeoutMs, 0, stream, null, cacheClient, cmds);
+                result = runUtil.runTimedCmdWithOutputMonitor(timeoutMs, 0, stream, null, cmds);
             } catch (IOException e) {
                 throw new RuntimeException(
                         "Should never happen, ShellOutputReceiverStream.close is a no-op", e);
@@ -225,20 +208,13 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
                 // Ignore
             }
             if (stdout != null && stdout.length() > 0L) {
-
-                try (FileInputStreamSource source = new FileInputStreamSource(stdout)) {
+                try (FileInputStreamSource source = new FileInputStreamSource(stdout, true)) {
                     logger.testLog(
                             String.format("%s-output", gtestFile.getName()),
                             LogDataType.TEXT,
                             source);
                 }
             }
-            if (!result.isCached()
-                    && !mTestRunResultListener.isTestRunFailed(gtestFile.getName())) {
-                runUtil.uploadCache(
-                        cacheClient,
-                        ExecutableActionResult.create(result.getExitCode(), stdout, null));
-            }
             FileUtil.deleteFile(stdout);
 
             if (isClangCoverageEnabled()) {
@@ -349,7 +325,6 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
     public void run(TestInformation testInfo, ITestInvocationListener listener)
             throws DeviceNotAvailableException { // DNAE is part of IRemoteTest.
         try {
-            mTestRunResultListener = new TestRunResultListener();
             // Reset flags that are used to track results of current test run.
             mIncompleteTestFound = false;
             mCurFailedTests = new LinkedHashSet<>();
@@ -408,7 +383,7 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
                     continue;
                 }
 
-                listener = getGTestListener(listener, mTestRunResultListener);
+                listener = getGTestListener(listener);
                 // TODO: Need to support XML test output based on isEnableXmlOutput
                 IShellOutputReceiver resultParser =
                         createResultParser(gTestFile.getName(), listener);
@@ -443,17 +418,6 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
         }
     }
 
-    private void reportFailure(
-            ITestInvocationListener listener, String runName, RuntimeException exception) {
-        listener.testRunStarted(runName, 0);
-        listener.testRunFailed(createFailure(exception));
-        listener.testRunEnded(0L, new HashMap<String, Metric>());
-    }
-
-    private FailureDescription createFailure(Exception e) {
-        return TestInvocation.createFailureFromException(e, FailureStatus.TEST_FAILURE);
-    }
-
     /**
      * Apply exclusion filters and return the remaining files.
      *
@@ -462,7 +426,7 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
      */
     private Set<File> applyFileExclusionFilters(Set<File> filesToFilterFrom) {
         Set<File> retFiles = new LinkedHashSet<>();
-        List<String> fileExclusionFilterRegex = getFileExclusionFilterRegex();
+        Set<String> fileExclusionFilterRegex = getFileExclusionFilterRegex();
         for (File file : filesToFilterFrom) {
             boolean matchedRegex = false;
             for (String regex : fileExclusionFilterRegex) {
@@ -495,7 +459,7 @@ public class HostGTest extends GTestBase implements IBuildReceiver {
                 seen.put(file.getName(), file);
             }
         }
-        return new LinkedHashSet(seen.values());
+        return new LinkedHashSet<>(seen.values());
     }
 
     /** Returns whether Clang code coverage is enabled. */
diff --git a/test_framework/com/android/tradefed/testtype/HostTest.java b/test_framework/com/android/tradefed/testtype/HostTest.java
index be3145482..7af69fe74 100644
--- a/test_framework/com/android/tradefed/testtype/HostTest.java
+++ b/test_framework/com/android/tradefed/testtype/HostTest.java
@@ -125,11 +125,10 @@ public class HostTest
     private String mMethodName;
 
     @Option(
-        name = "jar",
-        description = "The jars containing the JUnit test class to run.",
-        importance = Importance.IF_UNSET
-    )
-    private Set<String> mJars = new HashSet<>();
+            name = "jar",
+            description = "The jars containing the JUnit test class to run.",
+            importance = Importance.IF_UNSET)
+    private Set<String> mJars = new LinkedHashSet<>();
 
     public static final String SET_OPTION_NAME = "set-option";
     public static final String SET_OPTION_DESC =
@@ -144,14 +143,17 @@ public class HostTest
     @Option(name = SET_OPTION_NAME, description = SET_OPTION_DESC)
     private List<String> mKeyValueOptions = new ArrayList<>();
 
-    @Option(name = "include-annotation",
+    @Option(
+            name = "include-annotation",
             description = "The set of annotations a test must have to be run.")
-    private Set<String> mIncludeAnnotations = new HashSet<>();
+    private Set<String> mIncludeAnnotations = new LinkedHashSet<>();
 
-    @Option(name = "exclude-annotation",
-            description = "The set of annotations to exclude tests from running. A test must have "
-                    + "none of the annotations in this list to run.")
-    private Set<String> mExcludeAnnotations = new HashSet<>();
+    @Option(
+            name = "exclude-annotation",
+            description =
+                    "The set of annotations to exclude tests from running. A test must have "
+                            + "none of the annotations in this list to run.")
+    private Set<String> mExcludeAnnotations = new LinkedHashSet<>();
 
     /**
      * It is strongly recommended that clients set include and exclude filters at the suite level
@@ -161,7 +163,7 @@ public class HostTest
     @Option(
             name = "include-filter",
             description = "The set of annotations a test must have to be run.")
-    private Set<String> mIncludeFilters = new HashSet<>();
+    private Set<String> mIncludeFilters = new LinkedHashSet<>();
 
     /**
      * It is strongly recommended that clients set include and exclude filters at the suite level
@@ -173,7 +175,7 @@ public class HostTest
             description =
                     "The set of annotations to exclude tests from running. A test must have "
                             + "none of the annotations in this list to run.")
-    private Set<String> mExcludeFilters = new HashSet<>();
+    private Set<String> mExcludeFilters = new LinkedHashSet<>();
 
     @Option(name = "collect-tests-only",
             description = "Only invoke the instrumentation to collect list of applicable test "
diff --git a/test_framework/com/android/tradefed/testtype/InstrumentationTest.java b/test_framework/com/android/tradefed/testtype/InstrumentationTest.java
index 7affdc415..e4c7aa83b 100644
--- a/test_framework/com/android/tradefed/testtype/InstrumentationTest.java
+++ b/test_framework/com/android/tradefed/testtype/InstrumentationTest.java
@@ -75,6 +75,7 @@ import java.io.IOException;
 import java.util.ArrayList;
 import java.util.Collection;
 import java.util.HashMap;
+import java.util.LinkedHashMap;
 import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Map;
@@ -211,7 +212,7 @@ public class InstrumentationTest
             name = "instrumentation-arg",
             description = "Additional instrumentation arguments to provide.",
             requiredForRerun = true)
-    private final Map<String, String> mInstrArgMap = new HashMap<String, String>();
+    private final Map<String, String> mInstrArgMap = new LinkedHashMap<String, String>();
 
     @Option(
             name = "rerun-from-file",
diff --git a/test_framework/com/android/tradefed/testtype/IsolatedHostTest.java b/test_framework/com/android/tradefed/testtype/IsolatedHostTest.java
index 185a76165..e1474fbb5 100644
--- a/test_framework/com/android/tradefed/testtype/IsolatedHostTest.java
+++ b/test_framework/com/android/tradefed/testtype/IsolatedHostTest.java
@@ -15,10 +15,10 @@
  */
 package com.android.tradefed.testtype;
 
+import static com.android.tradefed.util.EnvironmentVariableUtil.buildMinimalLdLibraryPath;
+
 import com.android.tradefed.build.BuildInfoKey.BuildInfoFileKey;
 import com.android.tradefed.build.IBuildInfo;
-import com.android.tradefed.cache.ExecutableAction;
-import com.android.tradefed.cache.ExecutableActionResult;
 import com.android.tradefed.cache.ICacheClient;
 import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.IConfigurationReceiver;
@@ -43,24 +43,17 @@ import com.android.tradefed.result.FileInputStreamSource;
 import com.android.tradefed.result.ITestInvocationListener;
 import com.android.tradefed.result.InputStreamSource;
 import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.ResultForwarder;
 import com.android.tradefed.result.TestDescription;
 import com.android.tradefed.result.error.InfraErrorIdentifier;
-import com.android.tradefed.result.proto.FileProtoResultReporter;
-import com.android.tradefed.result.proto.ProtoResultParser;
 import com.android.tradefed.result.proto.TestRecordProto.FailureStatus;
-import com.android.tradefed.result.proto.TestRecordProto.TestRecord;
 import com.android.tradefed.util.CacheClientFactory;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.ResourceUtil;
-import com.android.tradefed.util.RunInterruptedException;
 import com.android.tradefed.util.RunUtil;
 import com.android.tradefed.util.StreamUtil;
 import com.android.tradefed.util.SystemUtil;
-import com.android.tradefed.util.proto.TestRecordProtoUtil;
 
 import com.google.common.annotations.VisibleForTesting;
-import com.google.common.base.Strings;
 
 import java.io.File;
 import java.io.FileNotFoundException;
@@ -79,7 +72,6 @@ import java.util.HashMap;
 import java.util.HashSet;
 import java.util.LinkedHashSet;
 import java.util.List;
-import java.util.Map;
 import java.util.Set;
 import java.util.TreeSet;
 import java.util.concurrent.TimeUnit;
@@ -114,7 +106,7 @@ public class IsolatedHostTest
             name = "jar",
             description = "The jars containing the JUnit test class to run.",
             importance = Importance.IF_UNSET)
-    private Set<String> mJars = new HashSet<String>();
+    private Set<String> mJars = new LinkedHashSet<String>();
 
     @Option(
             name = "socket-timeout",
@@ -127,14 +119,14 @@ public class IsolatedHostTest
     @Option(
             name = "include-annotation",
             description = "The set of annotations a test must have to be run.")
-    private Set<String> mIncludeAnnotations = new HashSet<>();
+    private Set<String> mIncludeAnnotations = new LinkedHashSet<>();
 
     @Option(
             name = "exclude-annotation",
             description =
                     "The set of annotations to exclude tests from running. A test must have "
                             + "none of the annotations in this list to run.")
-    private Set<String> mExcludeAnnotations = new HashSet<>();
+    private Set<String> mExcludeAnnotations = new LinkedHashSet<>();
 
     @Option(
             name = "java-flags",
@@ -156,13 +148,6 @@ public class IsolatedHostTest
     private Set<String> mExcludePaths =
             new HashSet<>(Arrays.asList("org/junit", "com/google/common/collect/testing/google"));
 
-    @Option(
-            name = "exclude-robolectric-packages",
-            description =
-                    "Indicates whether to exclude 'org/robolectric' when robolectric resources."
-                            + " Defaults to be true.")
-    private boolean mExcludeRobolectricPackages = true;
-
     @Option(
             name = "java-folder",
             description = "The JDK to be used. If unset, the JDK on $PATH will be used.")
@@ -194,11 +179,6 @@ public class IsolatedHostTest
                             + "the Java command line.")
     private boolean mRavenwoodResources = false;
 
-    @Option(
-            name = "enable-cache",
-            description = "Used to enable/disable caching for specific modules.")
-    private boolean mEnableCache = false;
-
     @Option(
             name = "inherit-env-vars",
             description =
@@ -206,6 +186,19 @@ public class IsolatedHostTest
                             + " process.")
     private boolean mInheritEnvVars = true;
 
+    @Option(
+            name = "use-minimal-shared-libs",
+            description = "Whether use the shared libs in per module folder.")
+    private boolean mUseMinimalSharedLibs = false;
+
+    @Option(
+            name = "do-not-swallow-runner-errors",
+            description =
+                    "Whether the subprocess should not swallow runner errors. This should be set"
+                            + " to true. Setting it to false (default, legacy behavior) can cause"
+                            + " test problems to silently fail.")
+    private boolean mDoNotSwallowRunnerErrors = false;
+
     private static final String QUALIFIED_PATH = "/com/android/tradefed/isolation";
     private static final String ISOLATED_JAVA_LOG = "isolated-java-logs";
     private IBuildInfo mBuildInfo;
@@ -243,14 +236,6 @@ public class IsolatedHostTest
         mCached = false;
 
         try {
-            File workFolder = CurrentInvocation.getWorkFolder();
-            String instanceName =
-                    mEnableCache ? mConfig.getCommandOptions().getRemoteCacheInstanceName() : null;
-            ICacheClient cacheClient =
-                    Strings.isNullOrEmpty(instanceName)
-                            ? null
-                            : getCacheClient(workFolder, instanceName);
-
             // Note the below chooses a working directory based on the jar that happens to
             // be first in the list of configured jars.  The baked-in assumption is that
             // all configured jars are in the same parent directory, otherwise the behavior
@@ -263,28 +248,27 @@ public class IsolatedHostTest
             }
             artifactsDir = FileUtil.createTempDir("robolectric-screenshot-artifacts");
             Set<File> classpathFiles = this.getClasspathFiles();
-            if (cacheClient != null) {
-                Map<String, File> nameToSymlink = new HashMap<>();
-                for (File f : classpathFiles) {
-                    if (nameToSymlink.containsKey(f.getName())) {
-                        throw new RuntimeException(
-                                "Jar files with same name have not been supported when caching is"
-                                        + " enabled. Please file a feature request!");
-                    }
-                    nameToSymlink.put(f.getName(), linkFileToWorkingDir("classpath", f));
-                }
-                classpathFiles = new HashSet<>(nameToSymlink.values());
-            }
             String classpath = this.compileClassPath(classpathFiles);
-            List<String> cmdArgs =
-                    this.compileCommand(classpath, artifactsDir, cacheClient != null);
+            List<String> cmdArgs = this.compileCommandArgs(classpath, artifactsDir);
             CLog.v(String.join(" ", cmdArgs));
             RunUtil runner = new RunUtil(mInheritEnvVars);
 
-            String ldLibraryPath = this.compileLdLibraryPath();
+            String ldLibraryPath =
+                    mUseMinimalSharedLibs
+                            ? buildMinimalLdLibraryPath(
+                                    mWorkDir, Arrays.asList("lib", "lib64", "shared_libs"))
+                            : this.compileLdLibraryPath();
             if (ldLibraryPath != null) {
                 runner.setEnvVariable("LD_LIBRARY_PATH", ldLibraryPath);
             }
+            if (!mInheritEnvVars) {
+                // We have to carry the proper java via path to the environment otherwise
+                // we can run into issue
+                runner.setEnvVariable("PATH",
+                          String.format("%s:/usr/bin", SystemUtil.getRunningJavaBinaryPath()
+                                          .getParentFile()
+                                          .getAbsolutePath()));
+            }
 
             runner.setWorkingDir(mWorkDir);
             CLog.v("Using PWD: %s", mWorkDir.getAbsolutePath());
@@ -292,12 +276,12 @@ public class IsolatedHostTest
             mSubprocessLog = FileUtil.createTempFile("subprocess-logs", "");
             runner.setRedirectStderrToStdout(true);
 
-            List<String> testJarAbsPaths = getJarPaths(mJars, cacheClient != null);
+            List<String> testJarAbsPaths = getJarPaths(mJars);
             TestParameters.Builder paramsBuilder =
                     TestParameters.newBuilder()
-                            .addAllTestClasses(new TreeSet(mClasses))
+                            .addAllTestClasses(new TreeSet<>(mClasses))
                             .addAllTestJarAbsPaths(testJarAbsPaths)
-                            .addAllExcludePaths(new TreeSet(mExcludePaths))
+                            .addAllExcludePaths(new TreeSet<>(mExcludePaths))
                             .setDryRun(mCollectTestsOnly);
 
             if (!mIncludeFilters.isEmpty()
@@ -306,10 +290,10 @@ public class IsolatedHostTest
                     || !mExcludeAnnotations.isEmpty()) {
                 paramsBuilder.setFilter(
                         FilterSpec.newBuilder()
-                                .addAllIncludeFilters(new TreeSet(mIncludeFilters))
-                                .addAllExcludeFilters(new TreeSet(mExcludeFilters))
-                                .addAllIncludeAnnotations(new TreeSet(mIncludeAnnotations))
-                                .addAllExcludeAnnotations(new TreeSet(mExcludeAnnotations)));
+                                .addAllIncludeFilters(new TreeSet<>(mIncludeFilters))
+                                .addAllExcludeFilters(new TreeSet<>(mExcludeFilters))
+                                .addAllIncludeAnnotations(new TreeSet<>(mIncludeAnnotations))
+                                .addAllExcludeAnnotations(new TreeSet<>(mExcludeAnnotations)));
             }
 
             RunnerMessage runnerMessage =
@@ -320,63 +304,6 @@ public class IsolatedHostTest
 
             ProcessBuilder processBuilder =
                     runner.createProcessBuilder(Redirect.to(mSubprocessLog), cmdArgs, false);
-
-            ExecutableAction action = null;
-            ExecutableActionResult actionResult = null;
-            if (cacheClient != null) {
-                try {
-                    action =
-                            ExecutableAction.create(
-                                    processBuilder.directory(),
-                                    Arrays.asList(runnerMessage.toString()),
-                                    processBuilder.environment(),
-                                    mSocketTimeout);
-                    actionResult = cacheClient.lookupCache(action);
-                    if (actionResult != null) {
-                        CLog.d(
-                                "Cache is hit with action:\n"
-                                        + "%s\n"
-                                        + "runner configuration:\n"
-                                        + "%s\n"
-                                        + "environment:\n"
-                                        + "%s",
-                                action.action(),
-                                runnerMessage.toString(),
-                                processBuilder.environment());
-                        ProtoResultParser parser =
-                                new ProtoResultParser(
-                                        listener, testInfo.getContext(), false, "cached-");
-                        parser.setMergeInvocationContext(false);
-                        TestRecord record = TestRecordProtoUtil.readFromFile(actionResult.stdOut());
-                        parser.processFinalizedProto(record);
-                        // TODO(b/357695016): Use output dir for subprocess log instead of the field
-                        // for stderr.
-                        try (FileInputStreamSource source =
-                                new FileInputStreamSource(actionResult.stdErr())) {
-                            listener.testLog(ISOLATED_JAVA_LOG, LogDataType.TEXT, source);
-                        }
-                        mCached = true;
-                        return;
-                    }
-                    CLog.d(
-                            "Caching action:\n%s\nwith runner configuration:\n%s\nenvironment:\n%s",
-                            action.action(),
-                            runnerMessage.toString(),
-                            processBuilder.environment());
-                } catch (IOException e) {
-                    CLog.e("Failed to lookup cache!");
-                    CLog.e(e);
-                } catch (InterruptedException e) {
-                    throw new RunInterruptedException(
-                            e.getMessage(), e, InfraErrorIdentifier.UNDETERMINED);
-                } finally {
-                    if (actionResult != null) {
-                        FileUtil.deleteFile(actionResult.stdOut());
-                        FileUtil.deleteFile(actionResult.stdErr());
-                    }
-                }
-            }
-
             isolationRunner = processBuilder.start();
             CLog.v("Started subprocess.");
 
@@ -392,40 +319,8 @@ public class IsolatedHostTest
             }
             CLog.v("Connected to subprocess.");
 
-            File cacheResults = null;
-            FileProtoResultReporter protoResultReporter = null;
-            if (cacheClient != null && action != null) {
-                cacheResults =
-                        FileUtil.createTempFile("results-to-upload", ".textproto", workFolder);
-                cacheResults.deleteOnExit();
-                protoResultReporter = new FileProtoResultReporter();
-                protoResultReporter.setFileOutput(cacheResults);
-                // Call invocationStarted since the proto machinery doesn't work well without it.
-                protoResultReporter.invocationStarted(testInfo.getContext());
-                listener = new ResultForwarder(List.of(listener, protoResultReporter));
-            }
-
             boolean runSuccess = executeTests(socket, listener, runnerMessage);
-
-            if (cacheClient != null && action != null && cacheResults != null && runSuccess) {
-                // It should not matter what we provide here since invocation-level reporting is not
-                // being done.
-                protoResultReporter.invocationEnded(1000);
-                try {
-                    CLog.d("Uploading cache for action: %s", action.action());
-                    // TODO(b/357695016): Use output dir for subprocess log instead of the field
-                    // for stderr.
-                    cacheClient.uploadCache(
-                            action, ExecutableActionResult.create(0, cacheResults, mSubprocessLog));
-                } catch (IOException e) {
-                    CLog.e("Failed to upload cache!");
-                    CLog.e(e);
-                } catch (InterruptedException e) {
-                    throw new RunInterruptedException(
-                            e.getMessage(), e, InfraErrorIdentifier.UNDETERMINED);
-                }
-            }
-
+            CLog.d("Execution was successful: %s", runSuccess);
             RunnerMessage.newBuilder()
                     .setCommand(RunnerOp.RUNNER_OP_STOP)
                     .build()
@@ -485,10 +380,6 @@ public class IsolatedHostTest
 
     /** Assembles the command arguments to execute the subprocess runner. */
     public List<String> compileCommandArgs(String classpath, File artifactsDir) {
-        return compileCommand(classpath, artifactsDir, false);
-    }
-
-    private List<String> compileCommand(String classpath, File artifactsDir, boolean enableCache) {
         List<String> cmdArgs = new ArrayList<>();
 
         File javaExec;
@@ -505,9 +396,6 @@ public class IsolatedHostTest
             }
             CLog.v("Using java executable at %s", javaExec.getAbsolutePath());
         }
-        if (enableCache) {
-            javaExec = linkFileToWorkingDir("java_binary", javaExec);
-        }
         cmdArgs.add(javaExec.getAbsolutePath());
         if (isCoverageEnabled()) {
             if (mConfig.getCoverageOptions().getJaCoCoAgentPath() != null) {
@@ -537,11 +425,6 @@ public class IsolatedHostTest
 
         if (mRobolectricResources) {
             cmdArgs.addAll(compileRobolectricOptions(artifactsDir));
-            // Prevent tradefed from eagerly loading classes, which may not load without shadows
-            // applied.
-            if (mExcludeRobolectricPackages) {
-                mExcludePaths.add("org/robolectric");
-            }
         }
         if (mRavenwoodResources) {
             // For the moment, swap in the default JUnit upstream runner
@@ -562,6 +445,9 @@ public class IsolatedHostTest
                         mServer.getInetAddress().getHostAddress(),
                         "--timeout",
                         Integer.toString(mSocketTimeout)));
+        if (mDoNotSwallowRunnerErrors) {
+            cmdArgs.add("--do-not-swallow-runner-errors");
+        }
         return cmdArgs;
     }
 
@@ -699,7 +585,7 @@ public class IsolatedHostTest
 
     /** Add all files under {@code File} sorted by filename to {@code paths}. */
     private static void addAllFilesUnder(Set<File> paths, File parentDirectory) {
-        var files = parentDirectory.listFiles((f) -> f.isFile());
+        var files = parentDirectory.listFiles((f) -> f.isFile() && f.getName().endsWith(".jar"));
         Arrays.sort(files, Comparator.comparing(File::getName));
 
         for (File file : files) {
@@ -773,7 +659,7 @@ public class IsolatedHostTest
         // add it to LD_LIBRARY_PATH.
         String libs[] = {"lib", "lib64"};
 
-        Set<File> result = new LinkedHashSet<>();
+        Set<String> result = new LinkedHashSet<>();
 
         for (String dir : dirs) {
             File path = new File(dir);
@@ -785,20 +671,22 @@ public class IsolatedHostTest
                 File libFile = new File(path, lib);
 
                 if (libFile.isDirectory()) {
-                    result.add(libFile);
+                    result.add(libFile.getAbsolutePath());
                 }
             }
         }
         if (result.isEmpty()) {
             return null;
         }
-        return result.stream()
-                .map(f -> RunUtil.toRelative(mWorkDir, f))
-                .sorted()
-                .collect(Collectors.joining(java.io.File.pathSeparator));
+        return String.join(java.io.File.pathSeparator, result);
     }
 
     private List<String> compileRobolectricOptions(File artifactsDir) {
+        // TODO: allow tests to specify the android-all jar versions they need (perhaps prebuilts as
+        // well).
+        // This is a byproduct of limits in Soong.   When android-all jars can be depended on as
+        // standard prebuilts,
+        // this will not be needed.
         List<String> options = new ArrayList<>();
         File testDir = findTestDirectory();
         File androidAllDir = FileUtil.findFile(testDir, "android-all");
@@ -808,22 +696,15 @@ public class IsolatedHostTest
         String dependencyDir =
                 "-Drobolectric.dependency.dir=" + androidAllDir.getAbsolutePath() + "/";
         options.add(dependencyDir);
+        // TODO: Clean up this debt to allow RNG tests to upload images to scuba
+        // Should likely be done as multiple calls/CLs - one per class and then could be done in a
+        // rule in Robolectric.
+        // Perhaps as a class rule once Robolectric has support.
         if (artifactsDir != null) {
             String artifactsDirFull =
                     "-Drobolectric.artifacts.dir=" + artifactsDir.getAbsolutePath() + "/";
             options.add(artifactsDirFull);
         }
-        options.add("-Drobolectric.offline=true");
-        options.add("-Drobolectric.logging=stdout");
-        options.add("-Drobolectric.resourcesMode=BINARY");
-        options.add("-Drobolectric.usePreinstrumentedJars=false");
-        // TODO(rexhoffman) figure out how to get the local conscrypt working - shared objects and
-        // such.
-        options.add("-Drobolectric.conscryptMode=OFF");
-
-        if (this.debug) {
-            options.add("-Drobolectric.logging.enabled=true");
-        }
         return options;
     }
 
@@ -872,7 +753,18 @@ public class IsolatedHostTest
         boolean runStarted = false;
         boolean success = true;
         while (true) {
-            RunnerReply reply = RunnerReply.parseDelimitedFrom(input);
+            RunnerReply reply = null;
+            try {
+                reply = RunnerReply.parseDelimitedFrom(input);
+            } catch (SocketTimeoutException ste) {
+                if (currentTest != null) {
+                    // Subprocess has hard crashed
+                    listener.testFailed(currentTest, StreamUtil.getStackTrace(ste));
+                    listener.testEnded(
+                            currentTest, System.currentTimeMillis(), new HashMap<String, Metric>());
+                }
+                throw ste;
+            }
             if (reply == null) {
                 if (currentTest != null) {
                     // Subprocess has hard crashed
@@ -1000,18 +892,14 @@ public class IsolatedHostTest
      * implementation, but somewhat difficult to extract well due to the various method calls it
      * uses.
      */
-    private List<String> getJarPaths(Set<String> jars, boolean enableCache)
-            throws FileNotFoundException {
+    private List<String> getJarPaths(Set<String> jars) throws FileNotFoundException {
         Set<String> output = new HashSet<>();
 
         for (String jar : jars) {
-            output.add(
-                    enableCache
-                            ? RunUtil.toRelative(mWorkDir, FileUtil.findFile(mWorkDir, jar))
-                            : getJarFile(jar, mBuildInfo).getAbsolutePath());
+            output.add(getJarFile(jar, mBuildInfo).getAbsolutePath());
         }
 
-        return output.stream().sorted().collect(Collectors.toList());
+        return output.stream().collect(Collectors.toList());
     }
 
     /**
@@ -1251,15 +1139,4 @@ public class IsolatedHostTest
     ICacheClient getCacheClient(File workFolder, String instanceName) {
         return CacheClientFactory.createCacheClient(workFolder, instanceName);
     }
-
-    /** Links a target file to another place under {@code mWorkDir}. */
-    private File linkFileToWorkingDir(String relToWorkingDir, File target) {
-        try {
-            return RunUtil.linkFile(mWorkDir, relToWorkingDir, target);
-        } catch (IOException e) {
-            CLog.e("Failed to symlink %s.", target);
-            CLog.e(e);
-            return target;
-        }
-    }
 }
diff --git a/test_framework/com/android/tradefed/testtype/binary/ExecutableBaseTest.java b/test_framework/com/android/tradefed/testtype/binary/ExecutableBaseTest.java
index 26c8735be..aba6b0416 100644
--- a/test_framework/com/android/tradefed/testtype/binary/ExecutableBaseTest.java
+++ b/test_framework/com/android/tradefed/testtype/binary/ExecutableBaseTest.java
@@ -146,6 +146,10 @@ public abstract class ExecutableBaseTest
         return false;
     }
 
+    protected boolean doesRunBinaryGenerateTestRuns() {
+        return true;
+    }
+
     protected boolean isTestFailed(String testName) {
         return mTestRunResultListener.isTestFailed(testName);
     }
@@ -217,14 +221,20 @@ public abstract class ExecutableBaseTest
         long startTimeMs = System.currentTimeMillis();
 
         try {
-            listener.testRunStarted(testRunName, testDescriptions.length);
-
+            if (doesRunBinaryGenerateTestRuns()) {
+                listener.testRunStarted(testRunName, testDescriptions.length);
+            }
             for (TestDescription description : testDescriptions) {
                 String testName = description.getTestName();
                 String cmd = testCommands.get(testName);
                 String path = findBinary(cmd);
 
-                if (path == null) {
+                FailureDescription abortDescription = shouldAbortRun(description);
+
+                if (abortDescription != null) {
+                    listener.testRunFailed(abortDescription);
+                    break;
+                } else if (path == null) {
                     listener.testStarted(description);
                     listener.testFailed(
                             description,
@@ -262,8 +272,10 @@ public abstract class ExecutableBaseTest
                 }
             }
         } finally {
-            listener.testRunEnded(
-                    System.currentTimeMillis() - startTimeMs, new HashMap<String, Metric>());
+            if (doesRunBinaryGenerateTestRuns()) {
+                listener.testRunEnded(
+                        System.currentTimeMillis() - startTimeMs, new HashMap<String, Metric>());
+            }
         }
     }
 
@@ -288,6 +300,16 @@ public abstract class ExecutableBaseTest
         return false;
     }
 
+    /**
+     * Check if the testRun should end early.
+     *
+     * @param description The test in progress.
+     * @return FailureDescription if the run loop should terminate.
+     */
+    public FailureDescription shouldAbortRun(TestDescription description) {
+        return null;
+    }
+
     /**
      * Search for the binary to be able to run it.
      *
diff --git a/test_framework/com/android/tradefed/testtype/binary/ExecutableHostTest.java b/test_framework/com/android/tradefed/testtype/binary/ExecutableHostTest.java
index 8e71f6d84..66659bc1b 100644
--- a/test_framework/com/android/tradefed/testtype/binary/ExecutableHostTest.java
+++ b/test_framework/com/android/tradefed/testtype/binary/ExecutableHostTest.java
@@ -15,19 +15,19 @@
  */
 package com.android.tradefed.testtype.binary;
 
-import static com.android.tradefed.util.EnvironmentVariableUtil.buildPathWithRelativePaths;
+import static com.android.tradefed.util.EnvironmentVariableUtil.buildMinimalLdLibraryPath;
+import static com.android.tradefed.util.EnvironmentVariableUtil.buildPath;
 
 import com.android.annotations.VisibleForTesting;
 import com.android.tradefed.build.BuildInfoKey.BuildInfoFileKey;
 import com.android.tradefed.build.IDeviceBuildInfo;
-import com.android.tradefed.cache.ExecutableActionResult;
 import com.android.tradefed.cache.ICacheClient;
 import com.android.tradefed.config.GlobalConfiguration;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.config.OptionClass;
 import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.device.IManagedTestDevice;
 import com.android.tradefed.device.StubDevice;
-import com.android.tradefed.invoker.logger.CurrentInvocation;
 import com.android.tradefed.log.ITestLogger;
 import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.result.FailureDescription;
@@ -48,14 +48,14 @@ import com.android.tradefed.util.RunUtil;
 import com.android.tradefed.util.SystemUtil;
 import com.android.tradefed.util.TestRunnerUtil;
 
-import com.google.common.base.Strings;
-
 import java.io.File;
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.util.ArrayList;
-import java.util.Collections;
+import java.util.Arrays;
+import java.util.HashSet;
 import java.util.List;
+import java.util.Set;
 
 /**
  * Test runner for executable running on the host. The runner implements {@link IDeviceTest} since
@@ -78,11 +78,6 @@ public class ExecutableHostTest extends ExecutableBaseTest {
     )
     private boolean mExecuteRelativeToScript = false;
 
-    @Option(
-            name = "enable-cache",
-            description = "Used to enable/disable caching for specific modules.")
-    private boolean mEnableCache = false;
-
     @Option(
             name = "inherit-env-vars",
             description =
@@ -90,6 +85,11 @@ public class ExecutableHostTest extends ExecutableBaseTest {
                             + " process.")
     private boolean mInheritEnvVars = true;
 
+    @Option(
+            name = "use-minimal-shared-libs",
+            description = "Whether use the shared libs in per module folder.")
+    private boolean mUseMinimalSharedLibs = false;
+
     @Override
     public String findBinary(String binary) {
         File bin = new File(binary);
@@ -135,31 +135,39 @@ public class ExecutableHostTest extends ExecutableBaseTest {
         if (!(getTestInfo().getDevice().getIDevice() instanceof StubDevice)) {
             runUtil.setEnvVariable(ANDROID_SERIAL, getTestInfo().getDevice().getSerialNumber());
         }
-        String ldLibraryPath = TestRunnerUtil.getLdLibraryPath(new File(binaryPath));
+        String ldLibraryPath;
         // Also add the directory of the binary path as the test may package library as data
         // dependency.
         File workingDir = new File(binaryPath).getParentFile();
         runUtil.setWorkingDir(workingDir);
-        if (ldLibraryPath != null) {
-            ldLibraryPath =
-                    String.format(
-                            "%s%s%s",
-                            ldLibraryPath,
-                            java.io.File.pathSeparator,
-                            workingDir.getAbsolutePath());
+        if (mUseMinimalSharedLibs) {
+            ldLibraryPath = buildMinimalLdLibraryPath(workingDir, Arrays.asList("shared_libs"));
         } else {
-            ldLibraryPath = workingDir.getAbsolutePath();
+            ldLibraryPath = TestRunnerUtil.getLdLibraryPath(new File(binaryPath));
+            if (ldLibraryPath != null) {
+                ldLibraryPath =
+                        String.format(
+                                "%s%s%s",
+                                ldLibraryPath,
+                                java.io.File.pathSeparator,
+                                workingDir.getAbsolutePath());
+            } else {
+                ldLibraryPath = workingDir.getAbsolutePath();
+            }
         }
         runUtil.setEnvVariable(LD_LIBRARY_PATH, ldLibraryPath);
 
+        Set<String> tools = new HashSet<>();
         // Update Tradefed adb on $PATH of binary
         File adbBinary = AdbUtils.getAdbToUpdate(getTestInfo(), getAdbPath());
+        tools.add(adbBinary != null ? adbBinary.getAbsolutePath() : "adb");
+        if (getTestInfo().getDevice() instanceof IManagedTestDevice) {
+            tools.add(((IManagedTestDevice) getTestInfo().getDevice()).getFastbootPath());
+        }
         runUtil.setEnvVariable(
                 "PATH",
-                buildPathWithRelativePaths(
-                        workingDir,
-                        Collections.singleton(
-                                adbBinary != null ? adbBinary.getAbsolutePath() : "adb"),
+                buildPath(
+                        tools,
                         String.format(
                                 "%s:/usr/bin",
                                 SystemUtil.getRunningJavaBinaryPath()
@@ -177,31 +185,15 @@ public class ExecutableHostTest extends ExecutableBaseTest {
         }
         File stdout = FileUtil.createTempFile(scriptName + LOG_STDOUT_TAG, ".txt");
         File stderr = FileUtil.createTempFile(scriptName + LOG_STDERR_TAG, ".txt");
-        ICacheClient cacheClient = null;
 
         try (FileOutputStream stdoutStream = new FileOutputStream(stdout);
                 FileOutputStream stderrStream = new FileOutputStream(stderr); ) {
-            String instanceName =
-                    mEnableCache
-                            ? getConfiguration().getCommandOptions().getRemoteCacheInstanceName()
-                            : null;
-            if (!Strings.isNullOrEmpty(instanceName)) {
-                cacheClient = getCacheClient(CurrentInvocation.getWorkFolder(), instanceName);
-            }
             CommandResult res =
-                    cacheClient == null
-                            ? runUtil.runTimedCmd(
-                                    getTimeoutPerBinaryMs(),
-                                    stdoutStream,
-                                    stderrStream,
-                                    command.toArray(new String[0]))
-                            : runUtil.runTimedCmdWithOutputMonitor(
-                                    getTimeoutPerBinaryMs(),
-                                    0,
-                                    stdoutStream,
-                                    stderrStream,
-                                    cacheClient,
-                                    command.toArray(new String[0]));
+                    runUtil.runTimedCmd(
+                            getTimeoutPerBinaryMs(),
+                            stdoutStream,
+                            stderrStream,
+                            command.toArray(new String[0]));
             if (!CommandStatus.SUCCESS.equals(res.getStatus())) {
                 FailureStatus status = FailureStatus.TEST_FAILURE;
                 // Everything should be outputted in stdout with our redirect above.
@@ -216,10 +208,6 @@ public class ExecutableHostTest extends ExecutableBaseTest {
                 listener.testFailed(
                         description,
                         FailureDescription.create(errorMessage).setFailureStatus(status));
-            } else if (!res.isCached() && !isTestFailed(description.getTestName())) {
-                runUtil.uploadCache(
-                        cacheClient,
-                        ExecutableActionResult.create(res.getExitCode(), stdout, stderr));
             }
         } finally {
             logFile(stdout, listener);
diff --git a/test_framework/com/android/tradefed/testtype/binary/ExecutableTargetTest.java b/test_framework/com/android/tradefed/testtype/binary/ExecutableTargetTest.java
index 0876838f5..2c41531f6 100644
--- a/test_framework/com/android/tradefed/testtype/binary/ExecutableTargetTest.java
+++ b/test_framework/com/android/tradefed/testtype/binary/ExecutableTargetTest.java
@@ -15,14 +15,17 @@
  */
 package com.android.tradefed.testtype.binary;
 
+import com.android.ddmlib.MultiLineReceiver;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.config.OptionClass;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.device.TestDeviceState;
 import com.android.tradefed.result.FailureDescription;
 import com.android.tradefed.result.ITestInvocationListener;
 import com.android.tradefed.result.TestDescription;
 import com.android.tradefed.result.proto.TestRecordProto.FailureStatus;
+import com.android.tradefed.testtype.GTestResultParser;
 import com.android.tradefed.testtype.IDeviceTest;
 import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
@@ -37,11 +40,44 @@ import java.util.concurrent.TimeUnit;
 @OptionClass(alias = "executable-target-test")
 public class ExecutableTargetTest extends ExecutableBaseTest implements IDeviceTest {
 
+    public static final String DEVICE_LOST_ERROR = "Device was lost prior to %s; aborting run.";
+    public static final String ROOT_LOST_ERROR = "Root access was lost prior to %s; aborting run.";
+
     private ITestDevice mDevice = null;
 
+    @Option(name = "abort-if-device-lost", description = "Abort the test if the device is lost.")
+    private boolean mAbortIfDeviceLost = false;
+
+    @Option(name = "abort-if-root-lost", description = "Abort the test if root access is lost.")
+    private boolean mAbortIfRootLost = false;
+
     @Option(name = "skip-binary-check", description = "Skip the binary check in findBinary().")
     private boolean mSkipBinaryCheck = false;
 
+    @Option(name = "parse-gtest", description = "Parse test outputs in GTest format")
+    private boolean mParseGTest = false;
+
+    @Override
+    protected boolean doesRunBinaryGenerateTestResults() {
+        return mParseGTest;
+    }
+
+    @Override
+    protected boolean doesRunBinaryGenerateTestRuns() {
+        // when using the GTestParser testRun events are triggered
+        // by the TEST_RUN_MARKER in stdout
+        // so we should not generate testRuns on the RunBinary event
+        return !mParseGTest;
+    }
+
+    @Override
+    public boolean getCollectTestsOnly() {
+        if (super.getCollectTestsOnly()) {
+            throw new UnsupportedOperationException("collect-tests-only mode not support");
+        }
+        return false;
+    }
+
     /** {@inheritDoc} */
     @Override
     public void setDevice(ITestDevice device) {
@@ -58,6 +94,31 @@ public class ExecutableTargetTest extends ExecutableBaseTest implements IDeviceT
         return mSkipBinaryCheck;
     }
 
+    @Override
+    public FailureDescription shouldAbortRun(TestDescription description) {
+        if (mAbortIfDeviceLost) {
+            if (!TestDeviceState.ONLINE.equals(getDevice().getDeviceState())) {
+                return FailureDescription.create(
+                        String.format(DEVICE_LOST_ERROR, description),
+                        FailureStatus.SYSTEM_UNDER_TEST_CRASHED);
+            }
+        }
+        if (mAbortIfRootLost) {
+            try {
+                if (!getDevice().isAdbRoot()) {
+                    return FailureDescription.create(
+                            String.format(ROOT_LOST_ERROR, description),
+                            FailureStatus.DEPENDENCY_ISSUE);
+                }
+            } catch (DeviceNotAvailableException e) {
+                return FailureDescription.create(
+                        String.format(DEVICE_LOST_ERROR, description),
+                        FailureStatus.SYSTEM_UNDER_TEST_CRASHED);
+            }
+        }
+        return null;
+    }
+
     @Override
     public String findBinary(String binary) throws DeviceNotAvailableException {
         if (getSkipBinaryCheck()) {
@@ -93,7 +154,18 @@ public class ExecutableTargetTest extends ExecutableBaseTest implements IDeviceT
      */
     protected void checkCommandResult(
             CommandResult result, ITestInvocationListener listener, TestDescription description) {
-        if (!CommandStatus.SUCCESS.equals(result.getStatus())) {
+        if (mParseGTest) {
+            MultiLineReceiver parser;
+            // the parser automatically reports the test result back to the infra through the
+            // listener.
+            parser =
+                    new GTestResultParser(
+                            description.getTestName(), listener, true
+                            /** allowRustTestName */
+                            );
+            parser.processNewLines(result.getStdout().split("\n"));
+            parser.done();
+        } else if (!CommandStatus.SUCCESS.equals(result.getStatus())) {
             String error_message;
             error_message =
                     String.format(
diff --git a/test_framework/com/android/tradefed/testtype/binary/KernelTargetTest.java b/test_framework/com/android/tradefed/testtype/binary/KernelTargetTest.java
index bc20436d6..194be18a3 100644
--- a/test_framework/com/android/tradefed/testtype/binary/KernelTargetTest.java
+++ b/test_framework/com/android/tradefed/testtype/binary/KernelTargetTest.java
@@ -69,6 +69,12 @@ public class KernelTargetTest extends ExecutableTargetTest {
     @Option(name = "parse-ktap", description = "Parse test outputs in KTAP format")
     private boolean mParseKTAP = false;
 
+    @Option(
+            name = "ktap-result-parser-resolution",
+            description = "Parser resolution for KTap results if test outputs are in KTAP format.")
+    private KTapResultParser.ParseResolution mKTapResultParserResolution =
+            KTapResultParser.ParseResolution.AGGREGATED_SUITE;
+
     @Override
     protected boolean doesRunBinaryGenerateTestResults() {
         return mParseKTAP;
@@ -170,7 +176,7 @@ public class KernelTargetTest extends ExecutableTargetTest {
                         listener,
                         description.getTestName(),
                         List.of(result.getStdout()),
-                        KTapResultParser.ParseResolution.AGGREGATED_SUITE);
+                        mKTapResultParserResolution);
             } catch (RuntimeException exception) {
                 CLog.e("KTAP parse error: %s", exception.toString());
                 listener.testStarted(description);
diff --git a/test_framework/com/android/tradefed/testtype/pandora/PtsBotTest.java b/test_framework/com/android/tradefed/testtype/pandora/PtsBotTest.java
index f90d01ac2..ac97529ee 100644
--- a/test_framework/com/android/tradefed/testtype/pandora/PtsBotTest.java
+++ b/test_framework/com/android/tradefed/testtype/pandora/PtsBotTest.java
@@ -25,8 +25,12 @@ import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.invoker.ExecutionFiles.FilesKey;
 import com.android.tradefed.invoker.TestInformation;
+import com.android.tradefed.log.ITestLogger;
 import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.result.FileInputStreamSource;
 import com.android.tradefed.result.ITestInvocationListener;
+import com.android.tradefed.result.InputStreamSource;
+import com.android.tradefed.result.LogDataType;
 import com.android.tradefed.result.TestDescription;
 import com.android.tradefed.testtype.IRemoteTest;
 import com.android.tradefed.testtype.IShardableTest;
@@ -71,7 +75,7 @@ import java.util.stream.Collectors;
  * (see
  * https://www.bluetooth.com/develop-with-bluetooth/qualification-listing/qualification-test-tools/profile-tuning-suite/).
  */
-public class PtsBotTest implements IRemoteTest, ITestFilterReceiver, IShardableTest {
+public class PtsBotTest implements IRemoteTest, ITestFilterReceiver, IShardableTest, ITestLogger {
 
     private static final String TAG = "PandoraPtsBot";
 
@@ -522,9 +526,22 @@ public class PtsBotTest implements IRemoteTest, ITestFilterReceiver, IShardableT
                     if (!matchingFlagConfig || unflagged) {
                         runPtsBotTest(profile, testName, testInfo, listener);
                     }
-                    long endTimestamp = System.currentTimeMillis();
-                    listener.testRunEnded(endTimestamp - startTimestamp, runMetrics);
+                    try {
+                        File snoopFile = FileUtil.createTempFile("android_snoop_log", ".log");
+                        testDevice.pullFile("/data/misc/bluetooth/logs/btsnoop_hci.log", snoopFile);
+                        try (InputStreamSource source =
+                                new FileInputStreamSource(snoopFile, true)) {
+                            listener.testLog(
+                                    String.format("android_btsnoop_%s", testName),
+                                    LogDataType.BT_SNOOP_LOG,
+                                    source);
+                        }
+                    } catch (DeviceNotAvailableException | IOException e) {
+                        CLog.e("Cannot fetch Android snoop logs: " + e.toString());
+                    }
                 }
+                long endTimestamp = System.currentTimeMillis();
+                listener.testRunEnded(endTimestamp - startTimestamp, runMetrics);
             } else {
                 CLog.i("No tests applicable for %s", profile);
             }
@@ -765,6 +782,7 @@ public class PtsBotTest implements IRemoteTest, ITestFilterReceiver, IShardableT
 
         ProcessBuilder builder = new ProcessBuilder(command);
 
+        builder.environment().put("PYTHONDONTWRITEBYTECODE", "1");
         if (binTempDir != null) builder.environment().put("XDG_CACHE_HOME", binTempDir.getPath());
         if (pythonHome != null) builder.environment().put("PYTHONHOME", pythonHome.getPath());
 
diff --git a/test_framework/com/android/tradefed/testtype/python/PythonBinaryHostTest.java b/test_framework/com/android/tradefed/testtype/python/PythonBinaryHostTest.java
index bebda62b6..2981e0d1d 100644
--- a/test_framework/com/android/tradefed/testtype/python/PythonBinaryHostTest.java
+++ b/test_framework/com/android/tradefed/testtype/python/PythonBinaryHostTest.java
@@ -15,20 +15,18 @@
  */
 package com.android.tradefed.testtype.python;
 
+import static com.android.tradefed.util.EnvironmentVariableUtil.buildMinimalLdLibraryPath;
+import static com.android.tradefed.util.EnvironmentVariableUtil.buildPath;
+
 import com.android.annotations.VisibleForTesting;
-import com.android.tradefed.cache.ExecutableActionResult;
 import com.android.tradefed.cache.ICacheClient;
-import com.android.tradefed.config.Configuration;
 import com.android.tradefed.config.GlobalConfiguration;
-import com.android.tradefed.config.IConfiguration;
-import com.android.tradefed.config.IConfigurationReceiver;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.config.OptionClass;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.StubDevice;
 import com.android.tradefed.invoker.ExecutionFiles.FilesKey;
 import com.android.tradefed.invoker.TestInformation;
-import com.android.tradefed.invoker.logger.CurrentInvocation;
 import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
 import com.android.tradefed.result.ByteArrayInputStreamSource;
@@ -38,7 +36,6 @@ import com.android.tradefed.result.ITestInvocationListener;
 import com.android.tradefed.result.InputStreamSource;
 import com.android.tradefed.result.LogDataType;
 import com.android.tradefed.result.ResultForwarder;
-import com.android.tradefed.result.TestRunResultListener;
 import com.android.tradefed.result.proto.TestRecordProto.FailureStatus;
 import com.android.tradefed.testtype.IRemoteTest;
 import com.android.tradefed.testtype.ITestFilterReceiver;
@@ -47,7 +44,6 @@ import com.android.tradefed.testtype.TestTimeoutEnforcer;
 import com.android.tradefed.util.AdbUtils;
 import com.android.tradefed.util.CacheClientFactory;
 import com.android.tradefed.util.CommandResult;
-import com.android.tradefed.util.DeviceActionUtil;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.IRunUtil;
 import com.android.tradefed.util.IRunUtil.EnvPriority;
@@ -83,8 +79,7 @@ import javax.annotation.Nullable;
  * exclude-filter will still be executed.
  */
 @OptionClass(alias = "python-host")
-public class PythonBinaryHostTest
-        implements IRemoteTest, ITestFilterReceiver, IConfigurationReceiver {
+public class PythonBinaryHostTest implements IRemoteTest, ITestFilterReceiver {
 
     protected static final String ANDROID_SERIAL_VAR = "ANDROID_SERIAL";
     protected static final String LD_LIBRARY_PATH = "LD_LIBRARY_PATH";
@@ -151,11 +146,6 @@ public class PythonBinaryHostTest
                             + "in the expected format.")
     private boolean mUseTestOutputFile = false;
 
-    @Option(
-            name = "enable-cache",
-            description = "Used to enable/disable caching for specific modules.")
-    private boolean mEnableCache = false;
-
     @Option(
             name = "inherit-env-vars",
             description =
@@ -163,6 +153,11 @@ public class PythonBinaryHostTest
                             + " process.")
     private boolean mInheritEnvVars = true;
 
+    @Option(
+            name = "use-minimal-shared-libs",
+            description = "Whether use the shared libs in per module folder.")
+    private boolean mUseMinimalSharedLibs = false;
+
     @Option(
             name = TestTimeoutEnforcer.TEST_CASE_TIMEOUT_OPTION,
             description = TestTimeoutEnforcer.TEST_CASE_TIMEOUT_DESCRIPTION)
@@ -180,8 +175,6 @@ public class PythonBinaryHostTest
 
     private TestInformation mTestInfo;
     private IRunUtil mRunUtil;
-    private IConfiguration mConfiguration = new Configuration("", "");
-    private TestRunResultListener mTestRunResultListener;
 
     /** {@inheritDoc} */
     @Override
@@ -231,24 +224,16 @@ public class PythonBinaryHostTest
         return mExcludeFilters;
     }
 
-    /** {@inheritDoc} */
-    @Override
-    public void setConfiguration(IConfiguration configuration) {
-        mConfiguration = configuration;
-    }
-
     @Override
     public final void run(TestInformation testInfo, ITestInvocationListener listener)
             throws DeviceNotAvailableException {
-        mTestRunResultListener = new TestRunResultListener();
-        listener = new ResultForwarder(listener, mTestRunResultListener);
         mTestInfo = testInfo;
         File testDir = mTestInfo.executionFiles().get(FilesKey.HOST_TESTS_DIRECTORY);
         if (testDir == null || !testDir.exists()) {
             testDir = mTestInfo.executionFiles().get(FilesKey.TESTS_DIRECTORY);
         }
         List<String> ldLibraryPath = new ArrayList<>();
-        if (testDir != null && testDir.exists()) {
+        if (!mUseMinimalSharedLibs && testDir != null && testDir.exists()) {
             List<String> libPaths =
                     Arrays.asList("lib", "lib64", "host/testcases/lib", "host/testcases/lib64");
             for (String path : libPaths) {
@@ -313,39 +298,26 @@ public class PythonBinaryHostTest
         File workingDir = pyFile.getParentFile();
         getRunUtil().setWorkingDir(workingDir);
         // Set the parent dir on the PATH
-        String separator = System.getProperty("path.separator");
         List<String> paths = new ArrayList<>();
-        // Link adb and aapt to working dir as default dependencies.
-        String runtimeDepsFolderName = "runtime_deps";
-        try {
-            RunUtil.linkFile(workingDir, runtimeDepsFolderName, getAdb());
-        } catch (IOException | DeviceActionUtil.DeviceActionConfigError e) {
-            CLog.e("Failed to link adb to working dir %s", workingDir);
-            CLog.e(e);
-        }
-        try {
-            // This is for backward compatibility. Nowaday we only use aapt2, but in some older
-            // branches, such as git_tm-dev, aapt is still required.
-            RunUtil.linkFile(workingDir, runtimeDepsFolderName, getAapt());
-        } catch (IOException | DeviceActionUtil.DeviceActionConfigError e) {
-            CLog.e("Failed to link aapt to working dir %s", workingDir);
-            CLog.e(e);
-        }
-        try {
-            RunUtil.linkFile(workingDir, runtimeDepsFolderName, getAapt2());
-        } catch (IOException | DeviceActionUtil.DeviceActionConfigError e) {
-            CLog.e("Failed to link aapt2 to working dir %s", workingDir);
-            CLog.e(e);
-        }
         // Bundle binaries / dependencies have priorities over existing PATH
-        paths.addAll(toRelative(workingDir, findAllSubdir(workingDir, new ArrayList<>())));
+        paths.addAll(findAllSubdir(pyFile.getParentFile(), new ArrayList<>()));
         paths.addAll(mAdditionalPaths);
         paths.add("/usr/bin");
-        String path = paths.stream().distinct().collect(Collectors.joining(separator));
+        // Adding aapt for backward compatibility. Nowaday we only use aapt2, but in some older
+        // branches, such as git_tm-dev, aapt is still required.
+        String path =
+                buildPath(
+                        Set.of(getAdb(), getAapt(), getAapt2()),
+                        paths.stream()
+                                .distinct()
+                                .collect(Collectors.joining(System.getProperty("path.separator"))));
         CLog.d("Using updated $PATH: %s", path);
         getRunUtil().setEnvVariablePriority(EnvPriority.SET);
         getRunUtil().setEnvVariable("PATH", path);
 
+        if (mUseMinimalSharedLibs) {
+            mLdLibraryPath = buildMinimalLdLibraryPath(workingDir, Arrays.asList("shared_libs"));
+        }
         if (mLdLibraryPath != null) {
             getRunUtil().setEnvVariable(LD_LIBRARY_PATH, mLdLibraryPath);
         }
@@ -405,15 +377,6 @@ public class PythonBinaryHostTest
         PythonUnitTestResultParser pythonParser =
                 new PythonUnitTestResultParser(
                         Arrays.asList(receiver), "python-run", mIncludeFilters, mExcludeFilters);
-        String instanceName =
-                mEnableCache
-                        ? mConfiguration.getCommandOptions().getRemoteCacheInstanceName()
-                        : null;
-        ICacheClient cacheClient =
-                Strings.isNullOrEmpty(instanceName)
-                        ? null
-                        : getCacheClient(CurrentInvocation.getWorkFolder(), instanceName);
-
         CommandResult result = null;
         File stderrFile = null;
         File stdoutFile = null;
@@ -424,21 +387,12 @@ public class PythonBinaryHostTest
             } else {
                 try (FileOutputStream fileOutputParser = new FileOutputStream(stderrFile)) {
                     result =
-                            cacheClient == null
-                                    ? getRunUtil()
-                                            .runTimedCmd(
-                                                    mTestTimeout,
-                                                    null,
-                                                    fileOutputParser,
-                                                    commandLine.toArray(new String[0]))
-                                    : getRunUtil()
-                                            .runTimedCmdWithOutputMonitor(
-                                                    mTestTimeout,
-                                                    0,
-                                                    null,
-                                                    fileOutputParser,
-                                                    cacheClient,
-                                                    commandLine.toArray(new String[0]));
+                            getRunUtil()
+                                    .runTimedCmd(
+                                            mTestTimeout,
+                                            null,
+                                            fileOutputParser,
+                                            commandLine.toArray(new String[0]));
                     fileOutputParser.flush();
                 }
             }
@@ -469,13 +423,6 @@ public class PythonBinaryHostTest
             }
             String testOutput = FileUtil.readStringFromFile(testOutputFile);
             pythonParser.processNewLines(testOutput.split("\n"));
-            if (!result.isCached() && !mTestRunResultListener.isTestRunFailed(runName)) {
-                getRunUtil()
-                        .uploadCache(
-                                cacheClient,
-                                ExecutableActionResult.create(
-                                        result.getExitCode(), stdoutFile, stderrFile));
-            }
         } catch (RuntimeException e) {
             StringBuilder message = new StringBuilder();
             String stderr = "";
@@ -549,18 +496,18 @@ public class PythonBinaryHostTest
     }
 
     @VisibleForTesting
-    File getAapt() throws DeviceActionUtil.DeviceActionConfigError {
-        return DeviceActionUtil.findExecutableOnPath("aapt");
+    String getAapt() {
+        return "aapt";
     }
 
     @VisibleForTesting
-    File getAapt2() throws DeviceActionUtil.DeviceActionConfigError {
-        return DeviceActionUtil.findExecutableOnPath("aapt2");
+    String getAapt2() {
+        return "aapt2";
     }
 
     @VisibleForTesting
-    File getAdb() throws DeviceActionUtil.DeviceActionConfigError {
-        return DeviceActionUtil.findExecutableOnPath("adb");
+    String getAdb() {
+        return "adb";
     }
 
     @VisibleForTesting
@@ -584,13 +531,6 @@ public class PythonBinaryHostTest
         return subDir;
     }
 
-    private static List<String> toRelative(File start, List<String> paths) {
-        return paths.stream()
-                .map(p -> RunUtil.toRelative(start, p))
-                .sorted()
-                .collect(Collectors.toList());
-    }
-
     private void reportFailure(
             ITestInvocationListener listener, String runName, String errorMessage) {
         listener.testRunStarted(runName, 0);
diff --git a/test_framework/com/android/tradefed/testtype/rust/RustBenchmarkResultParser.java b/test_framework/com/android/tradefed/testtype/rust/RustBenchmarkResultParser.java
index 4725dc1bc..ff82e8366 100644
--- a/test_framework/com/android/tradefed/testtype/rust/RustBenchmarkResultParser.java
+++ b/test_framework/com/android/tradefed/testtype/rust/RustBenchmarkResultParser.java
@@ -122,13 +122,16 @@ public class RustBenchmarkResultParser extends MultiLineReceiver {
                     for (ITestInvocationListener listener : mListeners) {
                         listener.testFailed(
                                 mLastTestId, String.join("\n", mTrackLogsSinceLastStart));
-                        listener.testEnded(mLastTestId, new HashMap<String, Metric>());
+                        listener.testEnded(
+                                mLastTestId,
+                                System.currentTimeMillis(),
+                                new HashMap<String, Metric>());
                     }
                     mLastTestId = null;
                 }
                 mLastTestId = new TestDescription(mCurrentTestFile, startMatcher.group(1));
                 for (ITestInvocationListener listener : mListeners) {
-                    listener.testStarted(mLastTestId);
+                    listener.testStarted(mLastTestId, System.currentTimeMillis());
                 }
                 mTrackLogsSinceLastStart.clear();
                 mAnyTestSeen = true;
@@ -137,7 +140,10 @@ public class RustBenchmarkResultParser extends MultiLineReceiver {
                 if (mLastTestId != null) {
                     for (ITestInvocationListener listener : mListeners) {
                         // TODO(qtr): Report metrics.
-                        listener.testEnded(mLastTestId, new HashMap<String, Metric>());
+                        listener.testEnded(
+                                mLastTestId,
+                                System.currentTimeMillis(),
+                                new HashMap<String, Metric>());
                     }
                     mLastTestId = null;
                 } else {
@@ -168,7 +174,8 @@ public class RustBenchmarkResultParser extends MultiLineReceiver {
         if (mLastTestId != null) {
             for (ITestInvocationListener listener : mListeners) {
                 listener.testFailed(mLastTestId, String.join("\n", mTrackLogsSinceLastStart));
-                listener.testEnded(mLastTestId, new HashMap<String, Metric>());
+                listener.testEnded(
+                        mLastTestId, System.currentTimeMillis(), new HashMap<String, Metric>());
                 listener.testRunFailed(mCurrentTestFile + " execution failed.");
             }
         }
diff --git a/test_framework/com/android/tradefed/testtype/rust/RustBinaryHostTest.java b/test_framework/com/android/tradefed/testtype/rust/RustBinaryHostTest.java
index a1668c607..138a92bbb 100644
--- a/test_framework/com/android/tradefed/testtype/rust/RustBinaryHostTest.java
+++ b/test_framework/com/android/tradefed/testtype/rust/RustBinaryHostTest.java
@@ -16,28 +16,25 @@
 package com.android.tradefed.testtype.rust;
 
 import static com.android.tradefed.testtype.coverage.CoverageOptions.Toolchain.CLANG;
-import static com.android.tradefed.util.EnvironmentVariableUtil.buildPathWithRelativePaths;
+import static com.android.tradefed.util.EnvironmentVariableUtil.buildMinimalLdLibraryPath;
+import static com.android.tradefed.util.EnvironmentVariableUtil.buildPath;
 
 import com.android.annotations.VisibleForTesting;
 import com.android.ddmlib.IShellOutputReceiver;
 import com.android.tradefed.build.BuildInfoKey.BuildInfoFileKey;
 import com.android.tradefed.build.IBuildInfo;
 import com.android.tradefed.build.IDeviceBuildInfo;
-import com.android.tradefed.cache.ExecutableActionResult;
 import com.android.tradefed.cache.ICacheClient;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.config.OptionClass;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.invoker.TestInformation;
-import com.android.tradefed.invoker.logger.CurrentInvocation;
 import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
 import com.android.tradefed.result.FailureDescription;
 import com.android.tradefed.result.FileInputStreamSource;
 import com.android.tradefed.result.ITestInvocationListener;
 import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.ResultForwarder;
-import com.android.tradefed.result.TestRunResultListener;
 import com.android.tradefed.result.error.TestErrorIdentifier;
 import com.android.tradefed.result.proto.TestRecordProto.FailureStatus;
 import com.android.tradefed.testtype.IBuildReceiver;
@@ -50,8 +47,6 @@ import com.android.tradefed.util.IRunUtil;
 import com.android.tradefed.util.RunUtil;
 import com.android.tradefed.util.TestRunnerUtil;
 
-import com.google.common.base.Strings;
-
 import java.io.File;
 import java.io.IOException;
 import java.util.ArrayList;
@@ -72,11 +67,6 @@ public class RustBinaryHostTest extends RustTestBase implements IBuildReceiver {
     @Option(name = "test-file", description = "The test file name or file path.")
     private Set<String> mBinaryNames = new HashSet<>();
 
-    @Option(
-            name = "enable-cache",
-            description = "Used to enable/disable caching for specific modules.")
-    private boolean mEnableCache = false;
-
     @Option(
             name = "inherit-env-vars",
             description =
@@ -84,9 +74,13 @@ public class RustBinaryHostTest extends RustTestBase implements IBuildReceiver {
                             + " process.")
     private boolean mInheritEnvVars = true;
 
+    @Option(
+            name = "use-minimal-shared-libs",
+            description = "Whether use the shared libs in per module folder.")
+    private boolean mUseMinimalSharedLibs = false;
+
     private File mCoverageDir;
     private IBuildInfo mBuildInfo;
-    private TestRunResultListener mTestRunResultListener;
 
     @Override
     public void setBuild(IBuildInfo buildInfo) {
@@ -97,8 +91,6 @@ public class RustBinaryHostTest extends RustTestBase implements IBuildReceiver {
     public final void run(TestInformation testInfo, ITestInvocationListener listener)
             throws DeviceNotAvailableException {
         try {
-            mTestRunResultListener = new TestRunResultListener();
-            listener = new ResultForwarder(listener, mTestRunResultListener);
             List<File> rustFilesList = findFiles();
             for (File file : rustFilesList) {
                 if (!file.exists()) {
@@ -245,7 +237,7 @@ public class RustBinaryHostTest extends RustTestBase implements IBuildReceiver {
     }
 
     private boolean countTests(Invocation invocation, Set<String> foundTests) {
-        CommandResult listResult = runInvocation(invocation, null, getRunUtil(), "--list");
+        CommandResult listResult = runInvocation(invocation, getRunUtil(), "--list");
         // TODO: Do we want to handle non-standard test harnesses without a
         // --list param? Currently we will report 0 tests, which will cause an
         // overall failure, but we don't know how to parse arbitrary test
@@ -265,7 +257,6 @@ public class RustBinaryHostTest extends RustTestBase implements IBuildReceiver {
 
     private CommandResult runInvocation(
             final Invocation invocation,
-            ICacheClient cacheClient,
             IRunUtil runUtil,
             final String... extraArgs) {
         runUtil.setWorkingDir(invocation.workingDir);
@@ -278,8 +269,12 @@ public class RustBinaryHostTest extends RustTestBase implements IBuildReceiver {
                 ldLibraryPathSetInEnv = true;
             }
         }
-        // Update LD_LIBRARY_PATH if it's not set already through command line args.
-        if (!ldLibraryPathSetInEnv) {
+        if (mUseMinimalSharedLibs) {
+            runUtil.setEnvVariable(
+                    "LD_LIBRARY_PATH",
+                    buildMinimalLdLibraryPath(invocation.workingDir, Arrays.asList("shared_libs")));
+        } else if (!ldLibraryPathSetInEnv) {
+            // Update LD_LIBRARY_PATH if it's not set already through command line args.
             String ldLibraryPath = TestRunnerUtil.getLdLibraryPath(new File(invocation.command[0]));
             if (ldLibraryPath != null) {
                 runUtil.setEnvVariable("LD_LIBRARY_PATH", ldLibraryPath);
@@ -295,33 +290,17 @@ public class RustBinaryHostTest extends RustTestBase implements IBuildReceiver {
                     "LLVM_PROFILE_FILE", mCoverageDir.getAbsolutePath() + "/clang-%m.profraw");
         }
 
-        runUtil.setEnvVariable(
-                "PATH",
-                buildPathWithRelativePaths(
-                        invocation.workingDir, Collections.singleton("adb"), "/usr/bin"));
+        runUtil.setEnvVariable("PATH", buildPath(Collections.singleton("adb"), ".:/usr/bin"));
         ArrayList<String> command = new ArrayList<String>(Arrays.asList(invocation.command));
         command.addAll(Arrays.asList(extraArgs));
-        return cacheClient == null
-                ? runUtil.runTimedCmd(mTestTimeout, command.toArray(new String[0]))
-                : runUtil.runTimedCmdWithOutputMonitor(
-                        mTestTimeout, 0, null, null, cacheClient, command.toArray(new String[0]));
+        return runUtil.runTimedCmd(mTestTimeout, command.toArray(new String[0]));
     }
 
     private void runTest(
             ITestInvocationListener listener, final Invocation invocation, final String runName)
             throws IOException {
-
-        String instanceName =
-                mEnableCache
-                        ? getConfiguration().getCommandOptions().getRemoteCacheInstanceName()
-                        : null;
-        ICacheClient cacheClient =
-                Strings.isNullOrEmpty(instanceName)
-                        ? null
-                        : getCacheClient(CurrentInvocation.getWorkFolder(), instanceName);
-
         IRunUtil runUtil = getRunUtil();
-        CommandResult result = runInvocation(invocation, cacheClient, runUtil);
+        CommandResult result = runInvocation(invocation, runUtil);
 
         if (!CommandStatus.SUCCESS.equals(result.getStatus())) {
             String message =
@@ -358,12 +337,6 @@ public class RustBinaryHostTest extends RustTestBase implements IBuildReceiver {
             IShellOutputReceiver parser = createParser(listener, runName);
             parser.addOutput(result.getStdout().getBytes(), 0, result.getStdout().length());
             parser.flush();
-            if (!result.isCached() && !mTestRunResultListener.isTestRunFailed(runName)) {
-                runUtil.uploadCache(
-                        cacheClient,
-                        ExecutableActionResult.create(
-                                result.getExitCode(), stdoutFile, stderrFile));
-            }
         } catch (RuntimeException e) {
             listener.testRunFailed(
                     String.format("Failed to parse the rust test output: %s", e.getMessage()));
diff --git a/test_framework/com/android/tradefed/testtype/suite/AtestRunner.java b/test_framework/com/android/tradefed/testtype/suite/AtestRunner.java
index 10d73139f..832e0d3c3 100644
--- a/test_framework/com/android/tradefed/testtype/suite/AtestRunner.java
+++ b/test_framework/com/android/tradefed/testtype/suite/AtestRunner.java
@@ -25,6 +25,7 @@ import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.result.ITestInvocationListener;
 import com.android.tradefed.result.SubprocessResultsReporter;
 import com.android.tradefed.targetprep.ITargetPreparer;
+import com.android.tradefed.targetprep.incremental.IIncrementalSetup;
 import com.android.tradefed.testtype.IAbi;
 import com.android.tradefed.testtype.IRemoteTest;
 import com.android.tradefed.testtype.ITestFilterReceiver;
@@ -97,6 +98,20 @@ public class AtestRunner extends BaseTestSuite {
     )
     private List<File> mModuleConfigPaths = new ArrayList<>();
 
+    @Option(
+        name = "incremental-setup",
+        description =
+                "Indicates the user specification of whether to enable incremental setup, "
+                    + "default to UNSPECIFIED."
+    )
+    private IncrementalSetupEnabled mIncrementalSetupEnabled = IncrementalSetupEnabled.UNSPECIFIED;
+
+    private static enum IncrementalSetupEnabled {
+        UNSPECIFIED,
+        NO,
+        YES,
+    }
+
     public AtestRunner() {
         setMultiDeviceStrategy(MultiDeviceModuleStrategy.RUN);
     }
@@ -133,6 +148,12 @@ public class AtestRunner extends BaseTestSuite {
                 addDebugger(testConfig);
             }
 
+            if (mIncrementalSetupEnabled == IncrementalSetupEnabled.YES) {
+                setIncrementalSetupEnabledForTargetPreparers(testConfig, /* shouldEnable= */ true);
+            } else if (mIncrementalSetupEnabled == IncrementalSetupEnabled.NO) {
+                setIncrementalSetupEnabledForTargetPreparers(testConfig, /* shouldEnable= */ false);
+            }
+
             // Inject include-filter to test.
             HashSet<String> moduleFilters =
                     includeFilters.get(canonicalizeConfigName(testConfig.getName()));
@@ -249,4 +270,20 @@ public class AtestRunner extends BaseTestSuite {
             }
         }
     }
+
+    /**
+     * Helper to set incremental setup enabled or disabled to TargetPreparers of a test.
+     *
+     * @param testConfig the test config which contains all target preparers.
+     * @param shouldEnable {@code true} to enable incremental setup, otherwise disable incremental
+     *     setup.
+     */
+    private static void setIncrementalSetupEnabledForTargetPreparers(
+        IConfiguration testConfig, boolean shouldEnable) {
+        for (ITargetPreparer targetPreparer : testConfig.getTargetPreparers()) {
+            if (targetPreparer instanceof IIncrementalSetup) {
+                ((IIncrementalSetup) targetPreparer).setIncrementalSetupEnabled(shouldEnable);
+            }
+        }
+    }
 }
diff --git a/test_framework/com/android/tradefed/util/EnvironmentVariableUtil.java b/test_framework/com/android/tradefed/util/EnvironmentVariableUtil.java
index b3c3e4ba1..77c0e481d 100644
--- a/test_framework/com/android/tradefed/util/EnvironmentVariableUtil.java
+++ b/test_framework/com/android/tradefed/util/EnvironmentVariableUtil.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2010 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -19,37 +19,60 @@ package com.android.tradefed.util;
 import com.android.tradefed.log.LogUtil.CLog;
 
 import java.io.File;
-import java.io.IOException;
+import java.util.ArrayList;
+import java.util.List;
 import java.util.Set;
+import java.util.stream.Collectors;
 
 /** A collection of helper methods to prepare environment variables. */
 public class EnvironmentVariableUtil {
 
     /**
-     * Builds the value of PATH with relative paths to the {@code workingDir}.
+     * Builds the value of PATH.
      *
-     * @param workingDir The root of the relative paths in the return.
-     * @param tools A list of tools that will be linked to a folder named `runtime_deps` under the
-     *     {@code workingDir} and included in the return.
+     * @param tools A list of tools that will be added to PATH.
      * @param addition The String that will be appended to the end of the return.
      * @return The value of PATH.
      */
-    public static String buildPathWithRelativePaths(
-            File workingDir, Set<String> tools, String addition) {
-        String runtimeDepsFolderName = "runtime_deps";
+    public static String buildPath(Set<String> tools, String addition) {
+        List<String> paths = new ArrayList<>();
         for (String t : tools) {
             try {
                 File tool = new File(t);
-                RunUtil.linkFile(
-                        workingDir,
-                        runtimeDepsFolderName,
-                        tool.exists() ? tool : DeviceActionUtil.findExecutableOnPath(t));
-            } catch (IOException | DeviceActionUtil.DeviceActionConfigError e) {
-                CLog.e("Failed to link %s to working dir %s", t, workingDir);
+                paths.add(
+                        tool.exists()
+                                ? tool.getParent()
+                                : DeviceActionUtil.findExecutableOnPath(t).getParent());
+            } catch (DeviceActionUtil.DeviceActionConfigError e) {
+                CLog.e("Failed to find %s!", t);
                 CLog.e(e);
             }
         }
 
-        return String.format(".:%s:%s", runtimeDepsFolderName, addition);
+        paths.add(addition);
+        return paths.stream().distinct().collect(Collectors.joining(getPathSeparator()));
+    }
+
+    /**
+     * Builds the value of LD_LIBRARY_PATH that uses the shared libs inside module folder.
+     *
+     * @param moduleDir The root of module folder.
+     * @param subDirs The sub-directories that are relative to the root of module folder.
+     * @return The value of LD_LIBRARY_PATH.
+     */
+    public static String buildMinimalLdLibraryPath(File moduleDir, List<String> subDirs) {
+        List<String> paths = new ArrayList<>();
+        paths.add(moduleDir.getAbsolutePath());
+        paths.addAll(
+                subDirs.stream()
+                        .map(d -> new File(moduleDir, d))
+                        .filter(f -> f.exists())
+                        .map(f -> f.getAbsolutePath())
+                        .collect(Collectors.toList()));
+        return paths.stream().distinct().collect(Collectors.joining(getPathSeparator()));
+    }
+
+    private static String getPathSeparator() {
+        return System.getProperty("path.separator");
     }
 }
diff --git a/test_observatory/com/android/tradefed/observatory/ConfigurationTestMappingParserSettings.java b/test_observatory/com/android/tradefed/observatory/ConfigurationTestMappingParserSettings.java
index eecff98c6..ad6c7afb8 100644
--- a/test_observatory/com/android/tradefed/observatory/ConfigurationTestMappingParserSettings.java
+++ b/test_observatory/com/android/tradefed/observatory/ConfigurationTestMappingParserSettings.java
@@ -28,4 +28,11 @@ public class ConfigurationTestMappingParserSettings {
                             + "will be run. If no list is specified, the tests will not be "
                             + "filtered by allowed tests.")
     public Set<String> mAllowedTestLists = new HashSet<>();
+
+    @Option(
+            name = "run-test-suite",
+            description =
+                    "Entry point to execute the given test suite as defined by the Soong"
+                            + " test_suites rule")
+    public String mRunTestSuite = null;
 }
diff --git a/test_observatory/com/android/tradefed/observatory/DiscoveryExitCode.java b/test_observatory/com/android/tradefed/observatory/DiscoveryExitCode.java
index 8882020b6..07fe9d9bb 100644
--- a/test_observatory/com/android/tradefed/observatory/DiscoveryExitCode.java
+++ b/test_observatory/com/android/tradefed/observatory/DiscoveryExitCode.java
@@ -21,6 +21,7 @@ public enum DiscoveryExitCode {
     COMPONENT_METADATA(5),
     NO_DISCOVERY_POSSIBLE(6), // When the command doesn't have any properties useful for discovery.
     CONFIGURATION_EXCEPTION(7), // When the command itself doesn't parse
+    DISCOVERY_RESULTS_CORREPUTED(8), // When the discovery results are corrupted.
     ERROR(1);
 
     private final int code;
diff --git a/test_observatory/com/android/tradefed/observatory/IDiscoverDependencies.java b/test_observatory/com/android/tradefed/observatory/IDiscoverDependencies.java
index 2e0126eb4..711bb4c83 100644
--- a/test_observatory/com/android/tradefed/observatory/IDiscoverDependencies.java
+++ b/test_observatory/com/android/tradefed/observatory/IDiscoverDependencies.java
@@ -16,13 +16,21 @@
 package com.android.tradefed.observatory;
 
 import java.util.Set;
+import javax.annotation.Nullable;
 
-/**
- * Interface allowing a TF non-core object to report extra dependencies to be considered as part of
- * the discovery of dependencies.
- */
 public interface IDiscoverDependencies {
 
-    /** Returns a list of named dependencies that are needed to execute the object. */
-    Set<String> reportDependencies();
+    /**
+    * Returns a set of named dependencies that are needed to execute the object. Return <code>null
+    * </code> if not provided.
+    */
+    default @Nullable Set<String> reportDependencies() {
+        return null;
+    }
+
+    /** Returns a set of zip regexes that are needed to execute the object.
+     * Return <code>null</code> if not provided. */
+    default @Nullable Set<String> reportTestZipFileFilter() {
+        return null;
+    }
 }
diff --git a/test_observatory/com/android/tradefed/observatory/TestDiscoveryExecutor.java b/test_observatory/com/android/tradefed/observatory/TestDiscoveryExecutor.java
index 6d1508bab..ae73cfa7e 100644
--- a/test_observatory/com/android/tradefed/observatory/TestDiscoveryExecutor.java
+++ b/test_observatory/com/android/tradefed/observatory/TestDiscoveryExecutor.java
@@ -16,13 +16,10 @@
 
 package com.android.tradefed.observatory;
 
-import com.android.annotations.VisibleForTesting;
 import com.android.ddmlib.DdmPreferences;
 import com.android.tradefed.config.Configuration;
 import com.android.tradefed.config.ConfigurationException;
-import com.android.tradefed.config.ConfigurationFactory;
 import com.android.tradefed.config.IConfiguration;
-import com.android.tradefed.config.IConfigurationFactory;
 import com.android.tradefed.invoker.tracing.ActiveTrace;
 import com.android.tradefed.invoker.tracing.CloseableTraceScope;
 import com.android.tradefed.invoker.tracing.TracingLogger;
@@ -68,17 +65,10 @@ import java.util.stream.Collectors;
  * <p>
  */
 public class TestDiscoveryExecutor {
-
-    IConfigurationFactory getConfigurationFactory() {
-        return ConfigurationFactory.getInstance();
-    }
-
     private boolean mReportPartialFallback = false;
     private boolean mReportNoPossibleDiscovery = false;
 
-    private static boolean hasOutputResultFile() {
-        return System.getenv(TestDiscoveryInvoker.OUTPUT_FILE) != null;
-    }
+    private static TestDiscoveryUtil mTestDiscoveryUtil;
 
     /**
      * An TradeFederation entry point that will use command args to discover test artifact
@@ -91,6 +81,14 @@ public class TestDiscoveryExecutor {
      *
      * <p>Expected arguments: [commands options] (config to run)
      */
+    public TestDiscoveryExecutor() {
+        mTestDiscoveryUtil = new TestDiscoveryUtil();
+    }
+
+    public TestDiscoveryExecutor(TestDiscoveryUtil testDiscoveryUtil) {
+        mTestDiscoveryUtil = testDiscoveryUtil;
+    }
+
     public static void main(String[] args) {
         long pid = ProcessHandle.current().pid();
         long tid = Thread.currentThread().getId();
@@ -100,7 +98,7 @@ public class TestDiscoveryExecutor {
         TestDiscoveryExecutor testDiscoveryExecutor = new TestDiscoveryExecutor();
         try (CloseableTraceScope ignored = new CloseableTraceScope("main_discovery")) {
             String testModules = testDiscoveryExecutor.discoverDependencies(args);
-            if (hasOutputResultFile()) {
+            if (mTestDiscoveryUtil.hasOutputResultFile()) {
                 FileUtil.writeToFile(
                         testModules, new File(System.getenv(TestDiscoveryInvoker.OUTPUT_FILE)));
             }
@@ -144,9 +142,9 @@ public class TestDiscoveryExecutor {
     public String discoverDependencies(String[] args)
             throws TestDiscoveryException, ConfigurationException, JSONException {
         // Create IConfiguration base on command line args.
-        IConfiguration config = getConfiguration(args);
+        IConfiguration config = mTestDiscoveryUtil.getConfiguration(args);
 
-        if (hasOutputResultFile()) {
+        if (mTestDiscoveryUtil.hasOutputResultFile()) {
             DdmPreferences.setLogLevel(LogLevel.VERBOSE.getStringValue());
             Log.setLogOutput(LogRegistry.getLogRegistry());
             StdoutLogger logger = new StdoutLogger();
@@ -186,29 +184,12 @@ public class TestDiscoveryExecutor {
                 return j.toString();
             }
         } finally {
-            if (hasOutputResultFile()) {
+            if (mTestDiscoveryUtil.hasOutputResultFile()) {
                 LogRegistry.getLogRegistry().unregisterLogger();
             }
         }
     }
 
-    /**
-     * Retrieve configuration base on command line args.
-     *
-     * @param args the command line args of the test.
-     * @return A {@link IConfiguration} which constructed based on command line args.
-     */
-    private IConfiguration getConfiguration(String[] args) throws ConfigurationException {
-        try (CloseableTraceScope ignored = new CloseableTraceScope("create_configuration")) {
-            IConfigurationFactory configurationFactory = getConfigurationFactory();
-            return configurationFactory.createPartialConfigurationFromArgs(
-                    args,
-                    new DryRunKeyStore(),
-                    Set.of(Configuration.TEST_TYPE_NAME, Configuration.TARGET_PREPARER_TYPE_NAME),
-                    null);
-        }
-    }
-
     /**
      * Discover configuration by a list of {@link IRemoteTest}.
      *
@@ -250,7 +231,8 @@ public class TestDiscoveryExecutor {
                     includeFilters.addAll(suiteIncludeFilters);
                 } else if (!moduleMetadataIncludeFilters.isEmpty()) {
                     String rootDirPath =
-                            getEnvironment(TestDiscoveryInvoker.ROOT_DIRECTORY_ENV_VARIABLE_KEY);
+                            mTestDiscoveryUtil.getEnvironment(
+                                    TestDiscoveryInvoker.ROOT_DIRECTORY_ENV_VARIABLE_KEY);
                     boolean throwException = true;
                     if (rootDirPath != null) {
                         File rootDir = new File(rootDirPath);
@@ -274,7 +256,8 @@ public class TestDiscoveryExecutor {
                 } else if (MultiDeviceModuleStrategy.ONLY_MULTI_DEVICES.equals(
                         ((BaseTestSuite) test).getMultiDeviceStrategy())) {
                     String rootDirPath =
-                            getEnvironment(TestDiscoveryInvoker.ROOT_DIRECTORY_ENV_VARIABLE_KEY);
+                            mTestDiscoveryUtil.getEnvironment(
+                                    TestDiscoveryInvoker.ROOT_DIRECTORY_ENV_VARIABLE_KEY);
                     boolean throwException = true;
                     if (rootDirPath != null) {
                         File rootDir = new File(rootDirPath);
@@ -296,7 +279,8 @@ public class TestDiscoveryExecutor {
                     }
                 } else if (!Strings.isNullOrEmpty(((BaseTestSuite) test).getRunSuiteTag())) {
                     String rootDirPath =
-                            getEnvironment(TestDiscoveryInvoker.ROOT_DIRECTORY_ENV_VARIABLE_KEY);
+                            mTestDiscoveryUtil.getEnvironment(
+                                    TestDiscoveryInvoker.ROOT_DIRECTORY_ENV_VARIABLE_KEY);
                     boolean throwException = true;
                     if (rootDirPath != null) {
                         File rootDir = new File(rootDirPath);
@@ -326,7 +310,7 @@ public class TestDiscoveryExecutor {
                 mReportNoPossibleDiscovery = true;
             }
             // Extract test module names from included filters.
-            if (hasOutputResultFile()) {
+            if (mTestDiscoveryUtil.hasOutputResultFile()) {
                 System.out.println(String.format("include filters: %s", includeFilters));
             }
             Set<String> moduleOnlyIncludeFilters =
@@ -371,7 +355,9 @@ public class TestDiscoveryExecutor {
      */
     private Set<String> findExtraConfigsParents(Set<String> moduleNames) {
         Set<String> parentModules = Collections.synchronizedSet(new HashSet<>());
-        String rootDirPath = getEnvironment(TestDiscoveryInvoker.ROOT_DIRECTORY_ENV_VARIABLE_KEY);
+        String rootDirPath =
+                mTestDiscoveryUtil.getEnvironment(
+                        TestDiscoveryInvoker.ROOT_DIRECTORY_ENV_VARIABLE_KEY);
         if (rootDirPath == null) {
             CLog.w("root dir env not set.");
             return parentModules;
@@ -455,7 +441,8 @@ public class TestDiscoveryExecutor {
                                     f -> {
                                         try {
                                             IConfiguration c =
-                                                    getConfigurationFactory()
+                                                    mTestDiscoveryUtil
+                                                            .getConfigurationFactory()
                                                             .createPartialConfigurationFromArgs(
                                                                     new String[] {
                                                                         f.getAbsolutePath()
@@ -493,7 +480,8 @@ public class TestDiscoveryExecutor {
                                     f -> {
                                         try {
                                             IConfiguration c =
-                                                    getConfigurationFactory()
+                                                    mTestDiscoveryUtil
+                                                            .getConfigurationFactory()
                                                             .createPartialConfigurationFromArgs(
                                                                     new String[] {
                                                                         f.getAbsolutePath()
@@ -550,9 +538,4 @@ public class TestDiscoveryExecutor {
         }
         return null;
     }
-
-    @VisibleForTesting
-    protected String getEnvironment(String var) {
-        return System.getenv(var);
-    }
 }
diff --git a/test_observatory/com/android/tradefed/observatory/TestDiscoveryInvoker.java b/test_observatory/com/android/tradefed/observatory/TestDiscoveryInvoker.java
index 96ae529cc..5383b36b7 100644
--- a/test_observatory/com/android/tradefed/observatory/TestDiscoveryInvoker.java
+++ b/test_observatory/com/android/tradefed/observatory/TestDiscoveryInvoker.java
@@ -41,6 +41,7 @@ import com.android.tradefed.util.testmapping.TestMapping;
 import com.google.common.annotations.VisibleForTesting;
 import com.google.common.base.Joiner;
 
+import com.google.common.base.Strings;
 import org.json.JSONArray;
 import org.json.JSONException;
 import org.json.JSONObject;
@@ -81,6 +82,7 @@ public class TestDiscoveryInvoker {
             TestDiscoveryExecutor.class.getName();
     public static final String TEST_DEPENDENCIES_LIST_KEY = "TestDependencies";
     public static final String TEST_MODULES_LIST_KEY = "TestModules";
+    public static final String TEST_ZIP_REGEXES_LIST_KEY = "TestZipRegexes";
     public static final String PARTIAL_FALLBACK_KEY = "PartialFallback";
     public static final String NO_POSSIBLE_TEST_DISCOVERY_KEY = "NoPossibleTestDiscovery";
     public static final String TEST_MAPPING_ZIP_FILE = "TF_TEST_MAPPING_ZIP_FILE";
@@ -89,6 +91,7 @@ public class TestDiscoveryInvoker {
 
     public static final String OUTPUT_FILE = "DISCOVERY_OUTPUT_FILE";
     public static final String DISCOVERY_TRACE_FILE = "DISCOVERY_TRACE_FILE";
+    public static final String BWYN_DISCOVER_TEST_ZIP = "BWYN_DISCOVER_TEST_ZIP";
 
     private static final long DISCOVERY_TIMEOUT_MS = 180000L;
 
@@ -340,6 +343,14 @@ public class TestDiscoveryInvoker {
                     }
                 }
             }
+            if (!Strings.isNullOrEmpty(mappingParserSettings.mRunTestSuite)) {
+                throw new TestDiscoveryException(
+                        String.format(
+                                "Test discovery for test suite is not supported yet. Test suite:"
+                                        + " %s",
+                                mappingParserSettings.mRunTestSuite),
+                        null);
+            }
 
             if (mHasConfigFallback) {
                 getRunUtil()
diff --git a/test_observatory/com/android/tradefed/observatory/TestDiscoveryUtil.java b/test_observatory/com/android/tradefed/observatory/TestDiscoveryUtil.java
new file mode 100644
index 000000000..ed1713780
--- /dev/null
+++ b/test_observatory/com/android/tradefed/observatory/TestDiscoveryUtil.java
@@ -0,0 +1,62 @@
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
+package com.android.tradefed.observatory;
+
+import com.android.tradefed.config.Configuration;
+import com.android.tradefed.config.ConfigurationException;
+import com.android.tradefed.config.ConfigurationFactory;
+import com.android.tradefed.config.IConfiguration;
+import com.android.tradefed.config.IConfigurationFactory;
+import com.android.tradefed.invoker.tracing.CloseableTraceScope;
+import com.android.tradefed.util.keystore.DryRunKeyStore;
+
+import java.util.Set;
+
+/** A utility class for test discovery. */
+public class TestDiscoveryUtil {
+    public IConfigurationFactory getConfigurationFactory() {
+        return ConfigurationFactory.getInstance();
+    }
+
+    public boolean hasOutputResultFile() {
+        return System.getenv(TestDiscoveryInvoker.OUTPUT_FILE) != null;
+    }
+
+    protected String getEnvironment(String var) {
+        return System.getenv(var);
+    }
+
+    /**
+     * Retrieve configuration base on command line args.
+     *
+     * @param args the command line args of the test.
+     * @return A {@link IConfiguration} which constructed based on command line args.
+     */
+    public IConfiguration getConfiguration(String[] args) throws ConfigurationException {
+        try (CloseableTraceScope ignored = new CloseableTraceScope("create_configuration")) {
+            IConfigurationFactory configurationFactory = getConfigurationFactory();
+            return configurationFactory.createPartialConfigurationFromArgs(
+                    args,
+                    new DryRunKeyStore(),
+                    Set.of(
+                            Configuration.BUILD_PROVIDER_TYPE_NAME,
+                            Configuration.TEST_TYPE_NAME,
+                            Configuration.TARGET_PREPARER_TYPE_NAME),
+                    null);
+        }
+    }
+}
diff --git a/test_observatory/com/android/tradefed/observatory/TestZipDiscoveryExecutor.java b/test_observatory/com/android/tradefed/observatory/TestZipDiscoveryExecutor.java
new file mode 100644
index 000000000..cc1081bca
--- /dev/null
+++ b/test_observatory/com/android/tradefed/observatory/TestZipDiscoveryExecutor.java
@@ -0,0 +1,233 @@
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
+package com.android.tradefed.observatory;
+
+import com.android.ddmlib.DdmPreferences;
+import com.android.tradefed.config.Configuration;
+import com.android.tradefed.config.ConfigurationException;
+import com.android.tradefed.config.IConfiguration;
+import com.android.tradefed.config.IDeviceConfiguration;
+import com.android.tradefed.invoker.tracing.ActiveTrace;
+import com.android.tradefed.invoker.tracing.CloseableTraceScope;
+import com.android.tradefed.invoker.tracing.TracingLogger;
+import com.android.tradefed.log.Log;
+import com.android.tradefed.log.LogRegistry;
+import com.android.tradefed.log.StdoutLogger;
+import com.android.tradefed.sandbox.SandboxOptions;
+import com.android.tradefed.sandbox.TradefedSandbox;
+import com.android.tradefed.testtype.IRemoteTest;
+import com.android.tradefed.testtype.suite.ITestSuite;
+import com.android.tradefed.util.FileUtil;
+
+import org.json.JSONArray;
+import org.json.JSONException;
+import org.json.JSONObject;
+
+import java.io.File;
+import java.io.IOException;
+import java.util.LinkedHashSet;
+import java.util.List;
+import java.util.Set;
+
+/**
+ * A class for getting test zipsfor a given command line args.
+ *
+ * <p>TestZipDiscoveryExecutor will consume the command line args and print test zip regexes for the
+ * caller to receive and parse it.
+ *
+ * <p>
+ */
+public class TestZipDiscoveryExecutor {
+
+    private boolean mReportNoPossibleDiscovery = false;
+
+    private static TestDiscoveryUtil mTestDiscoveryUtil;
+
+    public TestZipDiscoveryExecutor() {
+        mTestDiscoveryUtil = new TestDiscoveryUtil();
+    }
+
+    public TestZipDiscoveryExecutor(TestDiscoveryUtil testDiscoveryUtil) {
+        mTestDiscoveryUtil = testDiscoveryUtil;
+    }
+
+    /**
+     * Discover test zips base on command line args.
+     *
+     * @param args the command line args of the test.
+     * @return A JSON string with one test zip regex array.
+     */
+    public String discoverTestZips(String[] args)
+            throws TestDiscoveryException, ConfigurationException, JSONException {
+        // Create IConfiguration base on command line args.
+        IConfiguration config = mTestDiscoveryUtil.getConfiguration(args);
+
+        if (mTestDiscoveryUtil.hasOutputResultFile()) {
+            DdmPreferences.setLogLevel(Log.LogLevel.VERBOSE.getStringValue());
+            Log.setLogOutput(LogRegistry.getLogRegistry());
+            StdoutLogger logger = new StdoutLogger();
+            logger.setLogLevel(Log.LogLevel.VERBOSE);
+            LogRegistry.getLogRegistry().registerLogger(logger);
+        }
+
+        try {
+            // Get tests from the configuration.
+            List<IRemoteTest> tests = config.getTests();
+
+            // Tests could be empty if input args are corrupted.
+            if (tests == null || tests.isEmpty()) {
+                throw new TestDiscoveryException(
+                        "Tradefed Observatory discovered no tests from the IConfiguration created"
+                                + " from command line args.",
+                        null,
+                        DiscoveryExitCode.ERROR);
+            }
+
+            Set<String> testZipRegexSet = new LinkedHashSet<>();
+            SandboxOptions sandboxOptions = null;
+
+            // If sandbox is in use, we always need to download the tradefed zip.
+            if (config.getCommandOptions().shouldUseSandboxing()
+                    || config.getCommandOptions().shouldUseRemoteSandboxMode()) {
+                // Report targets for compatibility with build commands names
+                testZipRegexSet.add("tradefed.zip");
+                testZipRegexSet.add("tradefed-all.zip");
+                testZipRegexSet.add("google-tradefed.zip");
+                testZipRegexSet.add("google-tradefed-all.zip");
+            }
+
+            if (config.getConfigurationObject(Configuration.SANBOX_OPTIONS_TYPE_NAME) != null) {
+                sandboxOptions = (SandboxOptions) config.getConfigurationObject(
+                        Configuration.SANBOX_OPTIONS_TYPE_NAME);
+            }
+
+            // Retrieve the value of option --sandbox-tests-zips
+            if (sandboxOptions != null) {
+                testZipRegexSet.addAll(sandboxOptions.getTestsZips());
+            }
+
+            List<IDeviceConfiguration> list = config.getDeviceConfig();
+
+            if (list != null && list.size() > 0) {
+                for (IDeviceConfiguration deviceConfiguration : list) {
+                    // Attempt to retrieve test zip filters from the build provider."
+                    if (deviceConfiguration.getBuildProvider() instanceof IDiscoverDependencies) {
+                        Set<String> testZipFileFilters =
+                                ((IDiscoverDependencies) deviceConfiguration.getBuildProvider())
+                                        .reportTestZipFileFilter();
+                        if (testZipFileFilters != null) {
+                            testZipRegexSet.addAll(testZipFileFilters);
+                        }
+                    }
+                }
+            }
+
+            for (IRemoteTest test : tests) {
+                // For test mapping suite, match the corresponding test zip by test config name.
+                // Suppress the extra target if sandbox is not downloading the default zip.
+                if (test instanceof ITestSuite && sandboxOptions != null
+                        && sandboxOptions.getTestsZips().isEmpty()
+                        && sandboxOptions.downloadDefaultZips()) {
+                    testZipRegexSet.addAll(
+                            TradefedSandbox.matchSandboxExtraBuildTargetByConfigName(
+                                    config.getName()));
+                }
+            }
+
+            // If no test zip related info discovered, report a no possible discovery.
+            if (testZipRegexSet.isEmpty()) {
+                mReportNoPossibleDiscovery = true;
+            }
+
+            if (testZipRegexSet.contains(null)) {
+                throw new TestDiscoveryException(
+                        "Tradefed Observatory discovered null test zip regex. This is likely due to a corrupted discovery result. Test config: %s"
+                                .format(config.getName()),
+                        null,
+                        DiscoveryExitCode.DISCOVERY_RESULTS_CORREPUTED);
+            }
+
+            try (CloseableTraceScope ignored = new CloseableTraceScope("format_results")) {
+                JSONObject j = new JSONObject();
+                j.put(
+                        TestDiscoveryInvoker.TEST_ZIP_REGEXES_LIST_KEY,
+                        new JSONArray(testZipRegexSet));
+                if (mReportNoPossibleDiscovery) {
+                    j.put(TestDiscoveryInvoker.NO_POSSIBLE_TEST_DISCOVERY_KEY, "true");
+                }
+                return j.toString();
+            }
+        } finally {
+            if (mTestDiscoveryUtil.hasOutputResultFile()) {
+                LogRegistry.getLogRegistry().unregisterLogger();
+            }
+        }
+    }
+
+    /**
+     * A TradeFederation entry point that will use command args to discover test zip information.
+     *
+     * <p>Intended for use with BWYN in Android CI build optimization.
+     *
+     * <p>Will only exit with 0 when successfully discovered test zips.
+     *
+     * <p>Expected arguments: [commands options] (config to run)
+     */
+    public static void main(String[] args) {
+        long pid = ProcessHandle.current().pid();
+        long tid = Thread.currentThread().getId();
+        ActiveTrace trace = TracingLogger.createActiveTrace(pid, tid);
+        trace.startTracing(false);
+        DiscoveryExitCode exitCode = DiscoveryExitCode.SUCCESS;
+        TestZipDiscoveryExecutor testZipDiscoveryExecutor = new TestZipDiscoveryExecutor();
+        try (CloseableTraceScope ignored = new CloseableTraceScope("main_discovery")) {
+            String testModules = testZipDiscoveryExecutor.discoverTestZips(args);
+            if (mTestDiscoveryUtil.hasOutputResultFile()) {
+                FileUtil.writeToFile(
+                        testModules, new File(System.getenv(TestDiscoveryInvoker.OUTPUT_FILE)));
+            }
+            System.out.print(testModules);
+        } catch (TestDiscoveryException e) {
+            System.err.print(e.getMessage());
+            if (e.exitCode() != null) {
+                exitCode = e.exitCode();
+            } else {
+                exitCode = DiscoveryExitCode.ERROR;
+            }
+        } catch (ConfigurationException e) {
+            System.err.print(e.getMessage());
+            exitCode = DiscoveryExitCode.CONFIGURATION_EXCEPTION;
+        } catch (Exception e) {
+            System.err.print(e.getMessage());
+            exitCode = DiscoveryExitCode.ERROR;
+        }
+        File traceFile = trace.finalizeTracing();
+        if (traceFile != null) {
+            if (System.getenv(TestDiscoveryInvoker.DISCOVERY_TRACE_FILE) != null) {
+                try {
+                    FileUtil.copyFile(
+                            traceFile,
+                            new File(System.getenv(TestDiscoveryInvoker.DISCOVERY_TRACE_FILE)));
+                } catch (IOException | RuntimeException e) {
+                    System.err.print(e.getMessage());
+                }
+            }
+            FileUtil.deleteFile(traceFile);
+        }
+        System.exit(exitCode.exitCode());
+    }
+}
diff --git a/tools/content_uploader/content_uploader_script.py b/tools/content_uploader/content_uploader_script.py
index f5aebf475..78063c973 100644
--- a/tools/content_uploader/content_uploader_script.py
+++ b/tools/content_uploader/content_uploader_script.py
@@ -373,10 +373,11 @@ def _upload_all_artifacts(cas_info: CasInfo, all_artifacts: ArtifactConfig,
     for artifact in all_artifacts:
         for f in glob.glob(dist_dir + '/**/' + artifact.source_path, recursive=True):
             start = time.time()
-            name = _artifact_name(os.path.basename(f), artifact.chunk, artifact.unzip)
+            rel_path = _get_relative_path(dist_dir, f)
+            path = _artifact_path(rel_path, artifact.chunk, artifact.unzip)
 
             # Avoid redundant upload if multiple ArtifactConfigs share files.
-            if name in file_digests or name in skip_files:
+            if path in file_digests or path in skip_files:
                 continue
 
             artifact.source_path = f
@@ -384,18 +385,18 @@ def _upload_all_artifacts(cas_info: CasInfo, all_artifacts: ArtifactConfig,
             result = _upload(cas_info, artifact, working_dir, log_file, metrics_file)
 
             if result and result.digest:
-                file_digests[name] = result.digest
+                file_digests[path] = result.digest
                 if artifact.chunk and (not artifact.chunk_fallback or artifact.unzip):
                     # Skip the regular version even it matches other configs.
-                    skip_files.append(os.path.basename(f))
+                    skip_files.append(rel_path)
             else:
                 logging.warning(
-                    'Skip to save the digest of file %s, the uploading may fail', name
+                    'Skip to save the digest of file %s, the uploading may fail', path
                 )
             if result and result.content_details:
-                content_details.append({"artifact": name, "details": result.content_details})
+                content_details.append({"artifact": path, "details": result.content_details})
             else:
-                logging.warning('Skip to save the content details of file %s', name)
+                logging.warning('Skip to save the content details of file %s', path)
 
             if os.path.exists(metrics_file):
                 _add_artifact_metrics(metrics_file, cas_metrics)
@@ -444,12 +445,20 @@ def _add_fallback_artifacts(artifacts: list[ArtifactConfig]):
             artifacts.append(fallback_artifact)
 
 
-def _artifact_name(basename: str, chunk: bool, unzip: bool) -> str:
+def _get_relative_path(dir: str, file: str) -> str:
+    try:
+        return os.path.relpath(file, dir)
+    except ValueError as e:
+        print(f"Error calculating relative path: {e}")  # should never happen
+        return os.path.basename(file)
+
+
+def _artifact_path(path: str, chunk: bool, unzip: bool) -> str:
     if not chunk:
-        return basename
+        return path
     if unzip:
-        return CHUNKED_DIR_ARTIFACT_NAME_PREFIX + basename
-    return CHUNKED_ARTIFACT_NAME_PREFIX + basename
+        return CHUNKED_DIR_ARTIFACT_NAME_PREFIX + path
+    return CHUNKED_ARTIFACT_NAME_PREFIX + path
 
 
 def main():
diff --git a/util_apps/ContentProvider/main/java/android/tradefed/contentprovider/ManagedFileContentProvider.java b/util_apps/ContentProvider/main/java/android/tradefed/contentprovider/ManagedFileContentProvider.java
index 52579e381..ad3a8ebfd 100644
--- a/util_apps/ContentProvider/main/java/android/tradefed/contentprovider/ManagedFileContentProvider.java
+++ b/util_apps/ContentProvider/main/java/android/tradefed/contentprovider/ManagedFileContentProvider.java
@@ -130,7 +130,6 @@ public class ManagedFileContentProvider extends ContentProvider {
 
     @Override
     public Uri insert(Uri uri, ContentValues contentValues) {
-        String extra = "";
         File file = getFileForUri(uri);
         if (!file.exists()) {
             Log.e(TAG, String.format("Insert - File from uri: '%s' does not exists.", uri));
```

