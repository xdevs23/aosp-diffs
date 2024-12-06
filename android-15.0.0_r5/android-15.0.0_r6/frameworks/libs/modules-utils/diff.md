```diff
diff --git a/OWNERS b/OWNERS
index 9dd4ae9..9ff63ce 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,6 +1,5 @@
 dariofreni@google.com
 hackbod@google.com
-hansson@google.com
 narayan@google.com
 omakoto@google.com
 
diff --git a/java/Android.bp b/java/Android.bp
index a872c41..ea03aea 100644
--- a/java/Android.bp
+++ b/java/Android.bp
@@ -88,6 +88,10 @@ java_library {
     sdk_version: "none",
     system_modules: "core-all-system-modules",
     host_supported: true,
+    optimize: {
+        proguard_flags_files: ["aconfig_proguard.flags"],
+        export_proguard_flags_files: true,
+    },
     visibility: [
         "//visibility:public",
     ],
@@ -128,19 +132,6 @@ filegroup {
     ],
 }
 
-filegroup {
-    name: "modules-utils-synchronous-result-receiver-aidl",
-    srcs: [
-        "com/android/modules/utils/ISynchronousResultReceiver.aidl",
-        "com/android/modules/utils/SynchronousResultReceiver.aidl",
-    ],
-    visibility: [
-        "//frameworks/libs/modules-utils/java/com/android/modules/utils",
-        "//packages/modules/Bluetooth/system/binder",
-        "//packages/modules/Bluetooth/android/app/aidl",
-    ],
-}
-
 // This file group is deprecated; new users should use modules-utils-preconditions
 filegroup {
     name: "modules-utils-preconditions-srcs",
diff --git a/java/aconfig_proguard.flags b/java/aconfig_proguard.flags
index 2e0bea4..e0024ed 100644
--- a/java/aconfig_proguard.flags
+++ b/java/aconfig_proguard.flags
@@ -4,11 +4,17 @@
 -assumevalues class * {
     @com.android.aconfig.annotations.AssumeFalseForR8 boolean *(...) return false;
 }
+-assumenosideeffects class * {
+    @com.android.aconfig.annotations.AssumeFalseForR8 boolean *(...) return false;
+}
 
 # This rule is used to indicate a method will always return true.
 -assumevalues class * {
     @com.android.aconfig.annotations.AssumeTrueForR8 boolean *(...) return true;
 }
+-assumenosideeffects class * {
+    @com.android.aconfig.annotations.AssumeTrueForR8 boolean *(...) return true;
+}
 
 # Keep members with @VisibleForTesting annotation.
 -keepclassmembers class * {
diff --git a/java/android/annotation/RestrictedFor.java b/java/android/annotation/RestrictedForEnvironment.java
similarity index 89%
rename from java/android/annotation/RestrictedFor.java
rename to java/android/annotation/RestrictedForEnvironment.java
index 94a8895..d471f5e 100644
--- a/java/android/annotation/RestrictedFor.java
+++ b/java/android/annotation/RestrictedForEnvironment.java
@@ -42,8 +42,8 @@ import java.lang.annotation.Target;
  */
 @Target({TYPE})
 @Retention(RetentionPolicy.RUNTIME)
-@Repeatable(RestrictedFor.Container.class)
-public @interface RestrictedFor {
+@Repeatable(RestrictedForEnvironment.Container.class)
+public @interface RestrictedForEnvironment {
 
     /** List of environments where the entity is restricted. */
     Environment[] environments();
@@ -68,11 +68,12 @@ public @interface RestrictedFor {
     }
 
     /**
-     * Container for {@link RestrictedFor} that allows it to be applied repeatedly to types.
+     * Container for {@link RestrictedForEnvironment} that allows it to be applied repeatedly to
+     * types.
      */
     @Retention(RetentionPolicy.RUNTIME)
     @Target(TYPE)
     @interface Container {
-        RestrictedFor[] value();
+        RestrictedForEnvironment[] value();
     }
 }
diff --git a/java/com/android/internal/util/Preconditions.java b/java/com/android/internal/util/Preconditions.java
index 0bfa507..894f61c 100644
--- a/java/com/android/internal/util/Preconditions.java
+++ b/java/com/android/internal/util/Preconditions.java
@@ -730,12 +730,12 @@ public class Preconditions {
                 throw new IllegalArgumentException(valueName + "[" + i + "] must not be NaN");
             } else if (v < lower) {
                 throw new IllegalArgumentException(
-                        String.format("%s[%d] is out of range of [%f, %f] (too low)",
-                                valueName, i, lower, upper));
+                        String.format("%s[%d]: %f is out of range of [%f, %f] (too low)",
+                                valueName, i, v, lower, upper));
             } else if (v > upper) {
                 throw new IllegalArgumentException(
-                        String.format("%s[%d] is out of range of [%f, %f] (too high)",
-                                valueName, i, lower, upper));
+                        String.format("%s[%d]: %f is out of range of [%f, %f] (too high)",
+                                valueName, i, v, lower, upper));
             }
         }
 
@@ -764,12 +764,12 @@ public class Preconditions {
 
             if (v < lower) {
                 throw new IllegalArgumentException(
-                        String.format("%s[%d] is out of range of [%d, %d] (too low)",
-                                valueName, i, lower, upper));
+                        String.format("%s[%d]: %d is out of range of [%d, %d] (too low)",
+                                valueName, v, i, lower, upper));
             } else if (v > upper) {
                 throw new IllegalArgumentException(
-                        String.format("%s[%d] is out of range of [%d, %d] (too high)",
-                                valueName, i, lower, upper));
+                        String.format("%s[%d]: %d is out of range of [%d, %d] (too high)",
+                                valueName, v, i, lower, upper));
             }
         }
 
diff --git a/java/com/android/modules/expresslog/Android.bp b/java/com/android/modules/expresslog/Android.bp
index 59504bd..fec346c 100644
--- a/java/com/android/modules/expresslog/Android.bp
+++ b/java/com/android/modules/expresslog/Android.bp
@@ -26,7 +26,7 @@ java_library {
         ":statslog-expresslog-java-gen",
     ],
     libs: [
-        "framework-statsd",
+        "framework-statsd.stubs.module_lib",
     ],
     static_libs: [
         "expresslog-catalog",
diff --git a/java/com/android/modules/utils/Android.bp b/java/com/android/modules/utils/Android.bp
index 14b375f..cb4aca1 100644
--- a/java/com/android/modules/utils/Android.bp
+++ b/java/com/android/modules/utils/Android.bp
@@ -109,12 +109,3 @@ java_library {
     defaults: ["modules-utils-defaults"],
     srcs: ["BasicShellCommandHandler.java"],
 }
-
-java_library {
-    name: "modules-utils-synchronous-result-receiver",
-    defaults: ["modules-utils-defaults"],
-    srcs: [
-        ":modules-utils-synchronous-result-receiver-aidl",
-        "SynchronousResultReceiver.java",
-    ],
-}
diff --git a/java/com/android/modules/utils/ISynchronousResultReceiver.aidl b/java/com/android/modules/utils/ISynchronousResultReceiver.aidl
deleted file mode 100644
index 4f47436..0000000
--- a/java/com/android/modules/utils/ISynchronousResultReceiver.aidl
+++ /dev/null
@@ -1,25 +0,0 @@
-/* //device/java/android/android/app/IActivityPendingResult.aidl
-**
-** Copyright 2009, The Android Open Source Project
-**
-** Licensed under the Apache License, Version 2.0 (the "License");
-** you may not use this file except in compliance with the License.
-** You may obtain a copy of the License at
-**
-**     http://www.apache.org/licenses/LICENSE-2.0
-**
-** Unless required by applicable law or agreed to in writing, software
-** distributed under the License is distributed on an "AS IS" BASIS,
-** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-** See the License for the specific language governing permissions and
-** limitations under the License.
-*/
-
-package com.android.modules.utils;
-
-import com.android.modules.utils.SynchronousResultReceiver;
-
-/** @hide */
-oneway interface ISynchronousResultReceiver {
-    void send(in SynchronousResultReceiver.Result resultData);
-}
diff --git a/java/com/android/modules/utils/SynchronousResultReceiver.aidl b/java/com/android/modules/utils/SynchronousResultReceiver.aidl
deleted file mode 100644
index 2ee652d..0000000
--- a/java/com/android/modules/utils/SynchronousResultReceiver.aidl
+++ /dev/null
@@ -1,20 +0,0 @@
-/*
-** Copyright 2021, The Android Open Source Project
-**
-** Licensed under the Apache License, Version 2.0 (the "License");
-** you may not use this file except in compliance with the License.
-** You may obtain a copy of the License at
-**
-**     http://www.apache.org/licenses/LICENSE-2.0
-**
-** Unless required by applicable law or agreed to in writing, software
-** distributed under the License is distributed on an "AS IS" BASIS,
-** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-** See the License for the specific language governing permissions and
-** limitations under the License.
-*/
-
-package com.android.modules.utils;
-
-@JavaOnlyStableParcelable parcelable SynchronousResultReceiver<T>;
-@JavaOnlyStableParcelable parcelable SynchronousResultReceiver.Result<T>;
diff --git a/java/com/android/modules/utils/SynchronousResultReceiver.java b/java/com/android/modules/utils/SynchronousResultReceiver.java
deleted file mode 100644
index c12d739..0000000
--- a/java/com/android/modules/utils/SynchronousResultReceiver.java
+++ /dev/null
@@ -1,272 +0,0 @@
-/*
- * Copyright (C) 2016 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License"); you may not
- * use this file except in compliance with the License. You may obtain a copy of
- * the License at
- *
- * http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
- * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
- * License for the specific language governing permissions and limitations under
- * the License.
- */
-package com.android.modules.utils;
-
-
-import android.annotation.NonNull;
-import android.annotation.Nullable;
-import android.os.Handler;
-import android.os.Parcel;
-import android.os.Parcelable;
-import android.os.RemoteException;
-import android.os.SystemClock;
-import android.util.Log;
-
-import com.android.internal.annotations.GuardedBy;
-
-import java.io.Serializable;
-import java.time.Duration;
-import java.util.List;
-import java.util.Objects;
-import java.util.concurrent.CompletableFuture;
-import java.util.concurrent.ConcurrentLinkedQueue;
-import java.util.concurrent.ExecutionException;
-import java.util.concurrent.TimeUnit;
-import java.util.concurrent.TimeoutException;
-
-/**
- * Generic interface for receiving a callback result from someone.
- * Allow the server end to synchronously wait on the response from the client.
- * This enables an RPC like system but with the ability to timeout and discard late results.
- *
- * <p>NOTE: Use the static {@link #get} method to retrieve an available instance of this class.
- * If no instances are available, a new one is created.
- */
-public final class SynchronousResultReceiver<T> implements Parcelable {
-    private static final String TAG = "SynchronousResultReceiver";
-    private final boolean mLocal;
-    private boolean mIsCompleted;
-    private final static Object sLock = new Object();
-    private final static int QUEUE_THRESHOLD = 4;
-
-    @GuardedBy("sLock")
-    private CompletableFuture<Result<T>> mFuture = new CompletableFuture<>();
-
-    @GuardedBy("sLock")
-    private static final ConcurrentLinkedQueue<SynchronousResultReceiver> sAvailableReceivers
-            = new ConcurrentLinkedQueue<>();
-
-    public static <T> SynchronousResultReceiver<T> get() {
-        synchronized(sLock) {
-            if (sAvailableReceivers.isEmpty()) {
-                return new SynchronousResultReceiver();
-            }
-            SynchronousResultReceiver receiver = sAvailableReceivers.poll();
-            receiver.resetLocked();
-            return receiver;
-        }
-    }
-
-    private SynchronousResultReceiver() {
-        mLocal = true;
-        mIsCompleted = false;
-    }
-
-    @GuardedBy("sLock")
-    private void releaseLocked() {
-        mFuture = null;
-        if (sAvailableReceivers.size() < QUEUE_THRESHOLD) {
-            sAvailableReceivers.add(this);
-        }
-    }
-
-    @GuardedBy("sLock")
-    private void resetLocked() {
-        mFuture = new CompletableFuture<>();
-        mIsCompleted = false;
-    }
-
-    private CompletableFuture<Result<T>> getFuture() {
-       synchronized (sLock) {
-           return mFuture;
-       }
-    }
-
-    public static class Result<T> implements Parcelable {
-        private final @Nullable T mObject;
-        private final RuntimeException mException;
-
-        public Result(RuntimeException exception) {
-            mObject = null;
-            mException = exception;
-        }
-
-        public Result(@Nullable T object) {
-            mObject = object;
-            mException = null;
-        }
-
-        /**
-         * Return the stored value
-         * May throw a {@link RuntimeException} thrown from the client
-         */
-        public T getValue(T defaultValue) {
-            if (mException != null) {
-                throw mException;
-            }
-            if (mObject == null) {
-                return defaultValue;
-            }
-            return mObject;
-        }
-
-        public int describeContents() {
-            return 0;
-        }
-
-        public void writeToParcel(@NonNull Parcel out, int flags) {
-            out.writeValue(mObject);
-            out.writeValue(mException);
-        }
-
-        private Result(Parcel in) {
-            mObject = (T)in.readValue(null);
-            mException= (RuntimeException)in.readValue(null);
-        }
-
-        public static final @NonNull Parcelable.Creator<Result<?>> CREATOR =
-            new Parcelable.Creator<Result<?>>() {
-                public Result createFromParcel(Parcel in) {
-                    return new Result(in);
-                }
-                public Result[] newArray(int size) {
-                    return new Result[size];
-                }
-            };
-    }
-
-    private void complete(Result<T> result) {
-        if (mIsCompleted) {
-            throw new IllegalStateException("Receiver has already been completed");
-        }
-        mIsCompleted = true;
-        if (mLocal) {
-            getFuture().complete(result);
-        } else {
-            final ISynchronousResultReceiver rr;
-            synchronized (this) {
-                rr = mReceiver;
-            }
-            if (rr != null) {
-                try {
-                    rr.send(result);
-                } catch (RemoteException e) {
-                    Log.w(TAG, "Failed to complete future");
-                }
-            }
-        }
-    }
-
-    /**
-     * Deliver a result to this receiver.
-     *
-     * @param resultData Additional data provided by you.
-     */
-    public void send(@Nullable T resultData) {
-        complete(new Result<>(resultData));
-    }
-
-    /**
-     * Deliver an {@link Exception} to this receiver
-     *
-     * @param e exception to be sent
-     */
-    public void propagateException(@NonNull RuntimeException e) {
-        Objects.requireNonNull(e, "RuntimeException cannot be null");
-        complete(new Result<>(e));
-    }
-
-    /**
-     * Blocks waiting for the result from the remote client.
-     *
-     * If it is interrupted before completion of the duration, wait again with remaining time until
-     * the deadline.
-     *
-     * @param timeout The duration to wait before sending a {@link TimeoutException}
-     * @return the Result
-     * @throws TimeoutException if the timeout in milliseconds expired.
-     */
-    public @NonNull Result<T> awaitResultNoInterrupt(@NonNull Duration timeout)
-            throws TimeoutException {
-        Objects.requireNonNull(timeout, "Null timeout is not allowed");
-
-        final long startWaitNanoTime = SystemClock.elapsedRealtimeNanos();
-        Duration remainingTime = timeout;
-        while (!remainingTime.isNegative()) {
-            try {
-                Result<T> result = getFuture().get(remainingTime.toMillis(), TimeUnit.MILLISECONDS);
-                synchronized (sLock) {
-                    releaseLocked();
-                    return result;
-                }
-            } catch (ExecutionException e) {
-                // This will NEVER happen.
-                throw new AssertionError("Error receiving response", e);
-            } catch (InterruptedException e) {
-                // The thread was interrupted, try and get the value again, this time
-                // with the remaining time until the deadline.
-                remainingTime = timeout.minus(
-                        Duration.ofNanos(SystemClock.elapsedRealtimeNanos() - startWaitNanoTime));
-            }
-        }
-        synchronized (sLock) {
-            releaseLocked();
-        }
-        throw new TimeoutException();
-    }
-
-    ISynchronousResultReceiver mReceiver = null;
-
-    private final class MyResultReceiver extends ISynchronousResultReceiver.Stub {
-        public void send(@SuppressWarnings("rawtypes") @NonNull Result result) {
-            @SuppressWarnings("unchecked") Result<T> res = (Result<T>) result;
-            CompletableFuture<Result<T>> future;
-            future = getFuture();
-            if (future != null) {
-                future.complete(res);
-            }
-        }
-    }
-
-    public int describeContents() {
-        return 0;
-    }
-
-    public void writeToParcel(@NonNull Parcel out, int flags) {
-        synchronized (this) {
-            if (mReceiver == null) {
-                mReceiver = new MyResultReceiver();
-            }
-            out.writeStrongBinder(mReceiver.asBinder());
-        }
-    }
-
-    private SynchronousResultReceiver(Parcel in) {
-        mLocal = false;
-        mIsCompleted = false;
-        mReceiver = ISynchronousResultReceiver.Stub.asInterface(in.readStrongBinder());
-    }
-
-    public static final @NonNull Parcelable.Creator<SynchronousResultReceiver<?>> CREATOR =
-            new Parcelable.Creator<SynchronousResultReceiver<?>>() {
-            public SynchronousResultReceiver<?> createFromParcel(Parcel in) {
-                return new SynchronousResultReceiver(in);
-            }
-            public SynchronousResultReceiver<?>[] newArray(int size) {
-                return new SynchronousResultReceiver[size];
-            }
-        };
-}
diff --git a/java/com/android/modules/utils/testing/Android.bp b/java/com/android/modules/utils/testing/Android.bp
index f6574b4..fdc074f 100644
--- a/java/com/android/modules/utils/testing/Android.bp
+++ b/java/com/android/modules/utils/testing/Android.bp
@@ -42,7 +42,7 @@ java_library {
         "modules-utils-extended-mockito-rule",
     ],
     libs: [
-        "framework-configinfrastructure",
+        "framework-configinfrastructure.stubs.module_lib",
     ],
     visibility: ["//visibility:public"],
 }
diff --git a/java/com/android/modules/utils/testing/TestableDeviceConfig.java b/java/com/android/modules/utils/testing/TestableDeviceConfig.java
index 710dc1f..6d0db8e 100644
--- a/java/com/android/modules/utils/testing/TestableDeviceConfig.java
+++ b/java/com/android/modules/utils/testing/TestableDeviceConfig.java
@@ -31,6 +31,7 @@ import static org.mockito.Mockito.spy;
 import android.provider.DeviceConfig;
 import android.provider.DeviceConfig.Properties;
 import android.util.ArrayMap;
+import android.util.Log;
 import android.util.Pair;
 
 import com.android.dx.mockito.inline.extended.StaticMockitoSessionBuilder;
@@ -41,13 +42,16 @@ import com.android.modules.utils.build.SdkLevel;
 import org.junit.rules.TestRule;
 import org.mockito.ArgumentMatchers;
 import org.mockito.Mockito;
+import org.mockito.invocation.InvocationOnMock;
 import org.mockito.stubbing.Answer;
 
+import java.util.Arrays;
 import java.util.Collections;
 import java.util.HashMap;
 import java.util.Map;
 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.Executor;
+import java.util.stream.Collectors;
 
 /**
  * TestableDeviceConfig is a {@link StaticMockFixture} that uses ExtendedMockito to replace the real
@@ -56,20 +60,20 @@ import java.util.concurrent.Executor;
  */
 public final class TestableDeviceConfig implements StaticMockFixture {
 
-    private Map<DeviceConfig.OnPropertiesChangedListener, Pair<String, Executor>>
+    private static final String TAG = TestableDeviceConfig.class.getSimpleName();
+
+    private final Map<DeviceConfig.OnPropertiesChangedListener, Pair<String, Executor>>
             mOnPropertiesChangedListenerMap = new HashMap<>();
-    private Map<String, String> mKeyValueMap = new ConcurrentHashMap<>();
+    private final Map<String, String> mKeyValueMap = new ConcurrentHashMap<>();
 
     /**
      * Clears out all local overrides.
      */
     public void clearDeviceConfig() {
+        Log.i(TAG, "clearDeviceConfig()");
         mKeyValueMap.clear();
     }
 
-    /**
-     * {@inheritDoc}
-     */
     @Override
     public StaticMockitoSessionBuilder setUpMockedClasses(
             StaticMockitoSessionBuilder sessionBuilder) {
@@ -77,12 +81,10 @@ public final class TestableDeviceConfig implements StaticMockFixture {
         return sessionBuilder;
     }
 
-    /**
-     * {@inheritDoc}
-     */
     @Override
     public void setUpMockBehaviors() {
         doAnswer((Answer<Void>) invocationOnMock -> {
+            log(invocationOnMock);
             String namespace = invocationOnMock.getArgument(0);
             Executor executor = invocationOnMock.getArgument(1);
             DeviceConfig.OnPropertiesChangedListener onPropertiesChangedListener =
@@ -95,6 +97,7 @@ public final class TestableDeviceConfig implements StaticMockFixture {
                 any(DeviceConfig.OnPropertiesChangedListener.class)));
 
         doAnswer((Answer<Boolean>) invocationOnMock -> {
+            log(invocationOnMock);
             String namespace = invocationOnMock.getArgument(0);
             String name = invocationOnMock.getArgument(1);
             String value = invocationOnMock.getArgument(2);
@@ -106,6 +109,7 @@ public final class TestableDeviceConfig implements StaticMockFixture {
 
         if (SdkLevel.isAtLeastT()) {
             doAnswer((Answer<Boolean>) invocationOnMock -> {
+                log(invocationOnMock);
                 String namespace = invocationOnMock.getArgument(0);
                 String name = invocationOnMock.getArgument(1);
                 mKeyValueMap.remove(getKey(namespace, name));
@@ -114,6 +118,7 @@ public final class TestableDeviceConfig implements StaticMockFixture {
             }).when(() -> DeviceConfig.deleteProperty(anyString(), anyString()));
 
             doAnswer((Answer<Boolean>) invocationOnMock -> {
+                log(invocationOnMock);
                 Properties properties = invocationOnMock.getArgument(0);
                 String namespace = properties.getNamespace();
                 Map<String, String> keyValues = new ArrayMap<>();
@@ -128,12 +133,14 @@ public final class TestableDeviceConfig implements StaticMockFixture {
         }
 
         doAnswer((Answer<String>) invocationOnMock -> {
+            log(invocationOnMock);
             String namespace = invocationOnMock.getArgument(0);
             String name = invocationOnMock.getArgument(1);
             return mKeyValueMap.get(getKey(namespace, name));
         }).when(() -> DeviceConfig.getProperty(anyString(), anyString()));
         if (SdkLevel.isAtLeastR()) {
             doAnswer((Answer<Properties>) invocationOnMock -> {
+                log(invocationOnMock);
                 String namespace = invocationOnMock.getArgument(0);
                 final int varargStartIdx = 1;
                 Map<String, String> keyValues = new ArrayMap<>();
@@ -157,11 +164,9 @@ public final class TestableDeviceConfig implements StaticMockFixture {
         }
     }
 
-    /**
-     * {@inheritDoc}
-     */
     @Override
     public void tearDown() {
+        Log.i(TAG, "tearDown()");
         clearDeviceConfig();
         mOnPropertiesChangedListenerMap.clear();
     }
@@ -179,12 +184,30 @@ public final class TestableDeviceConfig implements StaticMockFixture {
         for (DeviceConfig.OnPropertiesChangedListener listener :
                 mOnPropertiesChangedListenerMap.keySet()) {
             if (namespace.equals(mOnPropertiesChangedListenerMap.get(listener).first)) {
+                Log.d(TAG, "Calling listener " + listener + " for changes on namespace "
+                        + namespace);
                 mOnPropertiesChangedListenerMap.get(listener).second.execute(
                         () -> listener.onPropertiesChanged(properties));
             }
         }
     }
 
+    private void log(InvocationOnMock invocation) {
+        if (!Log.isLoggable(TAG, Log.VERBOSE)) {
+            // Avoid stream allocation below if it's disabled...
+            return;
+        }
+        // InvocationOnMock.toString() prints one argument per line, which would spam logcat
+        try {
+            Log.v(TAG, "answering " + invocation.getMethod().getName() + "("
+                    + Arrays.stream(invocation.getArguments()).map(Object::toString)
+                    .collect(Collectors.joining(", ")) + ")");
+        } catch (Exception e) {
+            // Fallback in case logic above fails
+            Log.v(TAG, "answering " + invocation);
+        }
+    }
+
     private Properties getProperties(String namespace, String name, String value) {
         return getProperties(namespace, Collections.singletonMap(name.toLowerCase(), value));
     }
@@ -199,6 +222,7 @@ public final class TestableDeviceConfig implements StaticMockFixture {
         when(properties.getKeyset()).thenReturn(keyValues.keySet());
         when(properties.getBoolean(anyString(), anyBoolean())).thenAnswer(
                 invocation -> {
+                    log(invocation);
                     String key = invocation.getArgument(0);
                     boolean defaultValue = invocation.getArgument(1);
                     final String value = keyValues.get(key.toLowerCase());
@@ -211,6 +235,7 @@ public final class TestableDeviceConfig implements StaticMockFixture {
         );
         when(properties.getFloat(anyString(), anyFloat())).thenAnswer(
                 invocation -> {
+                    log(invocation);
                     String key = invocation.getArgument(0);
                     float defaultValue = invocation.getArgument(1);
                     final String value = keyValues.get(key.toLowerCase());
@@ -227,6 +252,7 @@ public final class TestableDeviceConfig implements StaticMockFixture {
         );
         when(properties.getInt(anyString(), anyInt())).thenAnswer(
                 invocation -> {
+                    log(invocation);
                     String key = invocation.getArgument(0);
                     int defaultValue = invocation.getArgument(1);
                     final String value = keyValues.get(key.toLowerCase());
@@ -243,6 +269,7 @@ public final class TestableDeviceConfig implements StaticMockFixture {
         );
         when(properties.getLong(anyString(), anyLong())).thenAnswer(
                 invocation -> {
+                    log(invocation);
                     String key = invocation.getArgument(0);
                     long defaultValue = invocation.getArgument(1);
                     final String value = keyValues.get(key.toLowerCase());
@@ -259,6 +286,7 @@ public final class TestableDeviceConfig implements StaticMockFixture {
         );
         when(properties.getString(anyString(), nullable(String.class))).thenAnswer(
                 invocation -> {
+                    log(invocation);
                     String key = invocation.getArgument(0);
                     String defaultValue = invocation.getArgument(1);
                     final String value = keyValues.get(key.toLowerCase());
diff --git a/javatests/Android.bp b/javatests/Android.bp
index c17641e..cd2ad18 100644
--- a/javatests/Android.bp
+++ b/javatests/Android.bp
@@ -38,13 +38,12 @@ android_test {
         "modules-utils-list-slice",
         "modules-utils-shell-command-handler",
         "modules-utils-statemachine",
-        "modules-utils-synchronous-result-receiver",
     ],
 
     libs: [
-        "android.test.base",
-        "android.test.runner",
-        "framework-configinfrastructure",
+        "android.test.base.stubs.system",
+        "android.test.runner.stubs.system",
+        "framework-configinfrastructure.stubs.module_lib",
     ],
 
     test_suites: ["general-tests"],
diff --git a/javatests/android/annotation/Android.bp b/javatests/android/annotation/Android.bp
index f793cbb..89af442 100644
--- a/javatests/android/annotation/Android.bp
+++ b/javatests/android/annotation/Android.bp
@@ -27,7 +27,7 @@ android_test {
         "truth",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "framework-annotations-lib",
     ],
     test_suites: ["general-tests"],
diff --git a/javatests/android/annotation/RestrictedForTests.java b/javatests/android/annotation/RestrictedForEnvironmentTests.java
similarity index 68%
rename from javatests/android/annotation/RestrictedForTests.java
rename to javatests/android/annotation/RestrictedForEnvironmentTests.java
index a2b932f..9ab45f8 100644
--- a/javatests/android/annotation/RestrictedForTests.java
+++ b/javatests/android/annotation/RestrictedForEnvironmentTests.java
@@ -18,19 +18,20 @@ package android.annotation;
 
 import static com.google.common.truth.Truth.assertThat;
 
-import android.annotation.RestrictedFor.Environment;
+import android.annotation.RestrictedForEnvironment.Environment;
 
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
 @RunWith(JUnit4.class)
-public class RestrictedForTests {
+public class RestrictedForEnvironmentTests {
 
     @Test
     public void testAnnotationAvailableInRuntime() throws Exception {
         ClassWithAnnotation clz = new ClassWithAnnotation();
-        RestrictedFor annotation = clz.getClass().getAnnotation(RestrictedFor.class);
+        RestrictedForEnvironment annotation = clz.getClass().getAnnotation(
+                RestrictedForEnvironment.class);
 
         assertThat(annotation).isNotNull();
     }
@@ -38,7 +39,8 @@ public class RestrictedForTests {
     @Test
     public void testAnnotationIsRepeatable() throws Exception {
         ClassWithRepeatedAnnotation clz = new ClassWithRepeatedAnnotation();
-        RestrictedFor[] annotations = clz.getClass().getAnnotationsByType(RestrictedFor.class);
+        RestrictedForEnvironment[] annotations = clz.getClass().getAnnotationsByType(
+                RestrictedForEnvironment.class);
 
         assertThat(annotations).hasLength(2);
     }
@@ -46,7 +48,8 @@ public class RestrictedForTests {
     @Test
     public void testAnnotationParameters() throws Exception {
         ClassWithAnnotation clz = new ClassWithAnnotation();
-        RestrictedFor annotation = clz.getClass().getAnnotation(RestrictedFor.class);
+        RestrictedForEnvironment annotation = clz.getClass().getAnnotation(
+                RestrictedForEnvironment.class);
 
         Environment[] e = annotation.environments();
         assertThat(e).asList().containsExactly(Environment.SDK_SANDBOX);
@@ -57,7 +60,8 @@ public class RestrictedForTests {
     @Test
     public void testAnnotationParameters_environmentToString() throws Exception {
         ClassWithAnnotation clz = new ClassWithAnnotation();
-        RestrictedFor annotation = clz.getClass().getAnnotation(RestrictedFor.class);
+        RestrictedForEnvironment annotation = clz.getClass().getAnnotation(
+                RestrictedForEnvironment.class);
 
         Environment e = annotation.environments()[0];
         assertThat(e).isEqualTo(Environment.SDK_SANDBOX);
@@ -67,22 +71,25 @@ public class RestrictedForTests {
     @Test
     public void testAnnotationParameters_environment_multipleEnvironments() throws Exception {
         ClassWithMultipleEnvironment clz = new ClassWithMultipleEnvironment();
-        RestrictedFor annotation = clz.getClass().getAnnotation(RestrictedFor.class);
+        RestrictedForEnvironment annotation = clz.getClass().getAnnotation(
+                RestrictedForEnvironment.class);
 
         Environment[] e = annotation.environments();
         assertThat(e).asList().containsExactly(Environment.SDK_SANDBOX, Environment.SDK_SANDBOX);
     }
 
-    @RestrictedFor(environments=Environment.SDK_SANDBOX, from=33)
+    @RestrictedForEnvironment(environments=Environment.SDK_SANDBOX, from=33)
     private static class ClassWithAnnotation {
     }
 
-    @RestrictedFor(environments=Environment.SDK_SANDBOX, from=0)
-    @RestrictedFor(environments=Environment.SDK_SANDBOX, from=0)
+    @RestrictedForEnvironment(environments=Environment.SDK_SANDBOX, from=0)
+    @RestrictedForEnvironment(environments=Environment.SDK_SANDBOX, from=0)
     private static class ClassWithRepeatedAnnotation {
     }
 
-    @RestrictedFor(environments={Environment.SDK_SANDBOX, Environment.SDK_SANDBOX}, from=0)
+    @RestrictedForEnvironment(
+        environments={Environment.SDK_SANDBOX, Environment.SDK_SANDBOX},
+        from=0)
     private static class ClassWithMultipleEnvironment {
     }
 }
diff --git a/javatests/com/android/internal/annotations/Android.bp b/javatests/com/android/internal/annotations/Android.bp
index 836f822..bf85703 100644
--- a/javatests/com/android/internal/annotations/Android.bp
+++ b/javatests/com/android/internal/annotations/Android.bp
@@ -32,7 +32,7 @@ android_test {
         "framework-annotations-lib",
     ],
 
-    libs: ["android.test.runner"],
+    libs: ["android.test.runner.stubs.system"],
 
     // Note: We explicitly optimize this test target to validate post-optimized
     // code paths and their interop with annotations.
diff --git a/javatests/com/android/modules/expresslog/Android.bp b/javatests/com/android/modules/expresslog/Android.bp
index 9396e17..1746486 100644
--- a/javatests/com/android/modules/expresslog/Android.bp
+++ b/javatests/com/android/modules/expresslog/Android.bp
@@ -33,8 +33,8 @@ android_test {
     ],
 
     libs: [
-        "android.test.base",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.runner.stubs.system",
     ],
 
     test_suites: [
diff --git a/javatests/com/android/modules/utils/SynchronousResultReceiverTest.java b/javatests/com/android/modules/utils/SynchronousResultReceiverTest.java
deleted file mode 100644
index 82aa97d..0000000
--- a/javatests/com/android/modules/utils/SynchronousResultReceiverTest.java
+++ /dev/null
@@ -1,81 +0,0 @@
-/*
- * Copyright (C) 2009 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.modules.utils;
-
-import androidx.test.filters.SmallTest;
-import junit.framework.TestCase;
-
-import org.junit.Assert;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
-
-import java.time.Duration;
-import java.util.concurrent.TimeoutException;
-
-@RunWith(JUnit4.class)
-@SmallTest
-public class SynchronousResultReceiverTest extends TestCase {
-    private static final Duration OK_TIME = Duration.ofMillis(100);
-    private static final Duration NEG_TIME = Duration.ofSeconds(-1);
-
-    @Test
-    public void testSimpleData() throws Exception {
-        final SynchronousResultReceiver<Boolean> recv = SynchronousResultReceiver.get();
-        recv.send(true);
-        final boolean result = recv.awaitResultNoInterrupt(OK_TIME).getValue(false);
-        assertTrue(result);
-    }
-
-    @Test
-    public void testDoubleComplete() throws Exception {
-        final SynchronousResultReceiver<Boolean> recv = SynchronousResultReceiver.get();
-        recv.send(true);
-        Assert.assertThrows(IllegalStateException.class,
-                () -> recv.send(true));
-    }
-
-    @Test
-    public void testDefaultValue() throws Exception {
-        final SynchronousResultReceiver<Boolean> recv = SynchronousResultReceiver.get();
-        recv.send(null);
-        assertTrue(recv.awaitResultNoInterrupt(OK_TIME).getValue(true));
-    }
-
-    @Test
-    public void testPropagateException() throws Exception {
-        final SynchronousResultReceiver<Boolean> recv = SynchronousResultReceiver.get();
-        recv.propagateException(new RuntimeException("Placeholder exception"));
-        Assert.assertThrows(RuntimeException.class,
-                () -> recv.awaitResultNoInterrupt(OK_TIME).getValue(false));
-    }
-
-    @Test
-    public void testTimeout() throws Exception {
-        final SynchronousResultReceiver<Boolean> recv = SynchronousResultReceiver.get();
-        Assert.assertThrows(TimeoutException.class,
-                () -> recv.awaitResultNoInterrupt(OK_TIME));
-    }
-
-    @Test
-    public void testNegativeTime() throws Exception {
-        final SynchronousResultReceiver<Boolean> recv = SynchronousResultReceiver.get();
-        recv.send(false);
-        Assert.assertThrows(TimeoutException.class,
-                () -> recv.awaitResultNoInterrupt(NEG_TIME));
-    }
-}
diff --git a/javatests/com/android/modules/utils/testing/Android.bp b/javatests/com/android/modules/utils/testing/Android.bp
index c5e5969..60a3d88 100644
--- a/javatests/com/android/modules/utils/testing/Android.bp
+++ b/javatests/com/android/modules/utils/testing/Android.bp
@@ -39,9 +39,9 @@ android_test {
     ],
 
     libs: [
-        "android.test.mock",
-        "android.test.runner",
-        "framework-configinfrastructure",
+        "android.test.mock.stubs.system",
+        "android.test.runner.stubs.system",
+        "framework-configinfrastructure.stubs.module_lib",
     ],
 
     test_suites: [
```

