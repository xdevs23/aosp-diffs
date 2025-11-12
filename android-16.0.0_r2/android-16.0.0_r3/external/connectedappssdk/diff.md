```diff
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java
index b612c78..6d54df6 100644
--- a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java
@@ -57,6 +57,7 @@ import java.util.WeakHashMap;
 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.ConcurrentLinkedDeque;
 import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.ExecutionException;
 import java.util.concurrent.ScheduledExecutorService;
 import java.util.concurrent.ScheduledFuture;
 import java.util.concurrent.atomic.AtomicBoolean;
@@ -393,7 +394,18 @@ public final class CrossProfileSender {
       throw new UnavailableProfileException("Permission not granted");
     }
 
-    cancelAutomaticDisconnection();
+    // Note that cancelAutomaticDisconnection would not cancel any ongoing disconnection call, just
+    // future ones.
+    // We guarantee no disconnection is ongoing by scheduling a cancel on the executor thread and
+    // waiting for it. The executor thread must be single threaded.
+    ScheduledFuture<?> automaticDisconnectionCancelled =
+        scheduledExecutorService.schedule(this::cancelAutomaticDisconnection, 1, MILLISECONDS);
+    try {
+      automaticDisconnectionCancelled.get();
+    } catch (InterruptedException | ExecutionException e) {
+      throw new UnavailableProfileException(
+          "Interrupted waiting for automatic disconnection to be cancelled", e);
+    }
 
     scheduledExecutorService.execute(
         () -> {
diff --git a/tests/instrumented/src/main/java/com/google/android/enterprise/connectedapps/instrumented/tests/ConnectTest.java b/tests/instrumented/src/main/java/com/google/android/enterprise/connectedapps/instrumented/tests/ConnectTest.java
index 9d3d5da..05b8312 100644
--- a/tests/instrumented/src/main/java/com/google/android/enterprise/connectedapps/instrumented/tests/ConnectTest.java
+++ b/tests/instrumented/src/main/java/com/google/android/enterprise/connectedapps/instrumented/tests/ConnectTest.java
@@ -25,6 +25,8 @@ import com.google.android.enterprise.connectedapps.exceptions.UnavailableProfile
 import com.google.android.enterprise.connectedapps.instrumented.utils.InstrumentedTestUtilities;
 import com.google.android.enterprise.connectedapps.testapp.connector.TestProfileConnector;
 import com.google.android.enterprise.connectedapps.testapp.types.ProfileTestCrossProfileType;
+import java.util.concurrent.Executors;
+import java.util.concurrent.ScheduledExecutorService;
 import org.junit.After;
 import org.junit.AfterClass;
 import org.junit.Before;
@@ -46,7 +48,11 @@ public class ConnectTest {
 
   private static final String STRING = "String";
 
-  private static final TestProfileConnector connector = TestProfileConnector.create(context);
+  private static final ScheduledExecutorService scheduledExecutorService =
+      Executors.newSingleThreadScheduledExecutor();
+
+  private static final TestProfileConnector connector =
+      TestProfileConnector.create(context, scheduledExecutorService);
   private final ProfileTestCrossProfileType type = ProfileTestCrossProfileType.create(connector);
   private static final InstrumentedTestUtilities utilities =
       new InstrumentedTestUtilities(context, connector);
@@ -113,6 +119,27 @@ public class ConnectTest {
     }
   }
 
+  @Test
+  public void connect_and_disconnect_manyTimes_succeeds() throws Exception {
+    // A connection will be auto closed, and if there's no more connection holders after closing
+    // (always the case here), a connection close will be scheduled in 30s.
+    // A race condition occurs if we try to reconnect again at the exact time the connection is
+    // closed, causing a lost open connection and preventing reconnections.
+    // To enforce this race condition, we sleep for 25s, and then fire new connections for 10s.
+    try (ProfileConnectionHolder ignored = connector.connect()) {
+      assertThat(connector.isConnected()).isTrue();
+    }
+    Thread.sleep(25_000);
+    int timeMillis = 10_000; // 10s of connection attempts.
+    int tries = 100;
+    for (int i = 0; i < tries; i++) {
+      try (ProfileConnectionHolder ignored = connector.connect()) {
+        assertThat(connector.isConnected()).isTrue();
+        Thread.sleep(timeMillis / tries);
+      }
+    }
+  }
+
   private void connectIgnoreExceptions() {
     try {
       connector.connect();
```

