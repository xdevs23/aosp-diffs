```diff
diff --git a/Android.bp b/Android.bp
index 104071a..8cc7174 100644
--- a/Android.bp
+++ b/Android.bp
@@ -79,6 +79,7 @@ android_library {
         "ConnectedAppsSDK_Annotations",
         "guava-android-annotation-stubs",
         "error_prone_annotations",
+        "guava",
     ],
     manifest: "sdk/src/main/AndroidManifest.xml",
     min_sdk_version: "28",
diff --git a/OWNERS b/OWNERS
index ce3438f..31e31f1 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 scottjonathan@google.com
-alexkershaw@google.com
\ No newline at end of file
+alexkershaw@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/ConnectionBinder.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/ConnectionBinder.java
index 0438b65..3cdd1d5 100644
--- a/sdk/src/main/java/com/google/android/enterprise/connectedapps/ConnectionBinder.java
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/ConnectionBinder.java
@@ -32,13 +32,17 @@ public interface ConnectionBinder {
    *
    * <p>This should not be called if {@link #hasPermissionToBind(Context)} returns {@code False} or
    * {@link #bindingIsPossible(Context, AvailabilityRestrictions)} returns {@code False}.
+   *
+   * <p>For certain devices, despite the initial binding failing, calling unbindService() will throw
+   * an IllegalArgumentException. This is a known issue with certain devices and we should not
+   * crash. See b/353372299 for context.
    */
   boolean tryBind(
       Context context,
       ComponentName bindToService,
       ServiceConnection connection,
       AvailabilityRestrictions availabilityRestrictions)
-      throws MissingApiException, UnavailableProfileException;
+      throws MissingApiException, UnavailableProfileException, IllegalArgumentException;
 
   /**
    * Return true if there is a profile available to bind to, while enforcing the passed in {@link
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSDKUtilities.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSDKUtilities.java
index 16bcebf..85dc33f 100644
--- a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSDKUtilities.java
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSDKUtilities.java
@@ -15,6 +15,8 @@
  */
 package com.google.android.enterprise.connectedapps;
 
+import static com.google.common.collect.ImmutableList.toImmutableList;
+
 import android.app.admin.DevicePolicyManager;
 import android.content.Context;
 import android.content.pm.CrossProfileApps;
@@ -28,7 +30,6 @@ import com.google.android.enterprise.connectedapps.annotations.AvailabilityRestr
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.List;
-
 import org.checkerframework.checker.nullness.qual.Nullable;
 
 /** Utility methods for acting on profiles. These methods should only be used by the SDK. */
@@ -109,7 +110,7 @@ class CrossProfileSDKUtilities {
       userHandles =
           userHandles.stream()
               .filter(userHandle -> isPersonalOrWorkProfile(crossProfileApps, userHandle))
-                  .toList();
+              .collect(toImmutableList());
     }
 
     if (userHandles.isEmpty()) {
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java
index 33ee4bb..b612c78 100644
--- a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java
@@ -326,7 +326,7 @@ public final class CrossProfileSender {
     this.availabilityListener = availabilityListener;
     bindToService = new ComponentName(context.getPackageName(), connectedAppsServiceClassName);
     canUseReflectedApis = ReflectionUtilities.canUseReflectedApis();
-    this.scheduledExecutorService = scheduledExecutorService;
+    this.scheduledExecutorService = new DebuggableScheduledExecutorService(scheduledExecutorService);
     this.availabilityRestrictions = availabilityRestrictions;
 
     senders.add(this);
@@ -511,9 +511,9 @@ public final class CrossProfileSender {
    */
   private void unbind() {
     Log.i(LOG_TAG, "Unbind");
-    if (isBound()) {
+    boolean isBound = iCrossProfileService.getAndSet(null) != null;
+    if (isBound) {
       context.unbindService(connection);
-      iCrossProfileService.set(null);
       checkConnected();
       cancelAutomaticDisconnection();
     }
@@ -582,6 +582,9 @@ public final class CrossProfileSender {
     } catch (UnavailableProfileException e) {
       Log.e(LOG_TAG, "Error while trying to bind", e);
       onBindingAttemptFailed(e);
+    } catch (IllegalArgumentException e) {
+      Log.e(LOG_TAG, "IllegalArgumentException when trying to bind", e);
+      onBindingAttemptFailed("IllegalArgumentException", e);
     }
   }
 
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/DebuggableScheduledExecutorService.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/DebuggableScheduledExecutorService.java
new file mode 100644
index 0000000..280a84f
--- /dev/null
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/DebuggableScheduledExecutorService.java
@@ -0,0 +1,158 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps;
+
+import android.util.Log;
+import java.util.Collection;
+import java.util.List;
+import java.util.concurrent.Callable;
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.Future;
+import java.util.concurrent.ScheduledExecutorService;
+import java.util.concurrent.ScheduledFuture;
+import java.util.concurrent.TimeUnit;
+import java.util.concurrent.TimeoutException;
+
+//TODO(olit) remove this when b/371963670 is fixed
+/**
+ * A ScheduledExecutorService wrapper that adds logging for debugging purposes.
+ *
+ * <p>This class is intended to be used for debugging only and should be removed once
+ * b/371963670 is fixed.
+ *
+ */
+final class DebuggableScheduledExecutorService implements ScheduledExecutorService {
+
+  private static final String LOG_TAG = "DebugExecutorService";
+  private final ScheduledExecutorService real;
+
+  /**
+   * @param real The underlying ScheduledExecutorService to wrap.
+   */
+  public DebuggableScheduledExecutorService(ScheduledExecutorService real) {
+    this.real = real;
+  }
+
+  @Override
+  public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
+    return real.schedule(command, delay, unit);
+  }
+
+  @Override
+  public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
+    return real.schedule(callable, delay, unit);
+  }
+
+  @Override
+  public ScheduledFuture<?> scheduleAtFixedRate(
+      Runnable command, long initialDelay, long period, TimeUnit unit) {
+    return real.scheduleAtFixedRate(command, initialDelay, period, unit);
+  }
+
+  @Override
+  public ScheduledFuture<?> scheduleWithFixedDelay(
+      Runnable command, long initialDelay, long delay, TimeUnit unit) {
+    return real.scheduleWithFixedDelay(command, initialDelay, delay, unit);
+  }
+
+  @Override
+  public void shutdown() {
+    Log.i(LOG_TAG, "shutdown() called");
+    real.shutdown();
+  }
+
+  @Override
+  public List<Runnable> shutdownNow() {
+    Log.i(LOG_TAG, "shutdownNow() called");
+    return real.shutdownNow();
+  }
+
+  @Override
+  public boolean isShutdown() {
+    Log.i(LOG_TAG, "isShutdown() called");
+    return real.isShutdown();
+  }
+
+  @Override
+  public boolean isTerminated() {
+    Log.i(LOG_TAG, "isTerminated() called");
+    return real.isTerminated();
+  }
+
+  @Override
+  public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
+    Log.i(LOG_TAG, "awaitTermination() called with timeout: " + timeout + ", unit: " + unit);
+    return real.awaitTermination(timeout, unit);
+  }
+
+  @Override
+  public <T> Future<T> submit(Callable<T> task) {
+    Log.i(LOG_TAG, "submit() called with Callable: " + task);
+    return real.submit(task);
+  }
+
+  @Override
+  public <T> Future<T> submit(Runnable task, T result) {
+    Log.i(LOG_TAG, "submit() called with Runnable: " + task + ", result: " + result);
+    return real.submit(task, result);
+  }
+
+  @Override
+  public Future<?> submit(Runnable task) {
+    Log.i(LOG_TAG, "submit() called with Runnable: " + task);
+    return real.submit(task);
+  }
+
+  @Override
+  public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks)
+      throws InterruptedException {
+    Log.i(LOG_TAG, "invokeAll() called with tasks: " + tasks);
+    return real.invokeAll(tasks);
+  }
+
+  @Override
+  public <T> List<Future<T>> invokeAll(
+      Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
+      throws InterruptedException {
+    Log.i(
+        LOG_TAG,
+        "invokeAll() called with tasks: " + tasks + ", timeout: " + timeout + ", unit: " + unit);
+    return real.invokeAll(tasks, timeout, unit);
+  }
+
+  @Override
+  public <T> T invokeAny(Collection<? extends Callable<T>> tasks)
+      throws ExecutionException, InterruptedException {
+    Log.i(LOG_TAG, "invokeAny() called with tasks: " + tasks);
+    return real.invokeAny(tasks);
+  }
+
+  @Override
+  public <T> T invokeAny(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
+      throws ExecutionException, InterruptedException, TimeoutException {
+    Log.i(
+        LOG_TAG,
+        "invokeAny() called with tasks: " + tasks + ", timeout: " + timeout + ", unit: " + unit);
+    return real.invokeAny(tasks, timeout, unit);
+  }
+
+  @Override
+  public void execute(Runnable command) {
+    Log.i(LOG_TAG, "execute() called with Runnable: " + command);
+    real.execute(command);
+    Log.i(LOG_TAG, command + " finished on thread");
+  }
+}
```

