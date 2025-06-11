```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 0000000..9965cdf
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,13 @@
+{
+  "crashrecovery-mainline-presubmit": [
+    {
+      "name": "CtsPackageWatchdogTestCases"
+    },
+    {
+      "name": "FrameworksMockingServicesTests_android_server_crashrecovery"
+    },
+    {
+      "name": "RollbackPackageHealthObserverTests_server_rollback"
+    }
+  ]
+}
\ No newline at end of file
diff --git a/apex/Android.bp b/apex/Android.bp
index ec52e2d..248a3d9 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -80,7 +80,7 @@ apex {
     }),
 
     name: "com.android.crashrecovery",
-    defaults: ["v-launched-apex-module"],
+    defaults: ["b-launched-apex-module"],
     bootclasspath_fragments: ["com.android.crashrecovery-bootclasspath-fragment"],
     systemserverclasspath_fragments: [
         "com.android.crashrecovery-systemserverclasspath-fragment",
@@ -92,7 +92,6 @@ apex {
     key: "com.android.crashrecovery.key",
     certificate: ":com.android.crashrecovery.certificate",
     manifest: "manifest.json",
-    min_sdk_version: "34",
 }
 
 sdk {
diff --git a/framework/Android.bp b/framework/Android.bp
index 40d61d3..1cbb4f1 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -16,10 +16,24 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+// Temporary till we move the files in this directory
+filegroup {
+    name: "framework-crashrecovery-module-sources",
+    srcs: [
+        "java/**/*.java",
+        "java/**/*.aidl",
+    ],
+    path: "java",
+    visibility: [
+        "//frameworks/base/packages/CrashRecovery/framework",
+    ],
+}
+
 java_sdk_library {
     name: "framework-crashrecovery",
     srcs: [
         "java/**/*.java",
+        "java/**/*.aidl",
         ":framework-crashrecovery-sources",
     ],
     apex_available: [
@@ -34,6 +48,7 @@ java_sdk_library {
         "android.crashrecovery",
     ],
     defaults: ["framework-module-defaults"],
+    min_sdk_version: "36",
     sdk_version: "module_current",
     impl_library_visibility: [
         "//packages/modules/CrashRecovery:__subpackages__",
diff --git a/framework/api/system-current.txt b/framework/api/system-current.txt
index 68429ea..ad17ec6 100644
--- a/framework/api/system-current.txt
+++ b/framework/api/system-current.txt
@@ -9,7 +9,7 @@ package android.service.watchdog {
     method @NonNull public abstract java.util.List<java.lang.String> onGetRequestedPackages();
     method @NonNull public abstract java.util.List<android.service.watchdog.ExplicitHealthCheckService.PackageConfig> onGetSupportedPackages();
     method public abstract void onRequestHealthCheck(@NonNull String);
-    method @FlaggedApi("android.crashrecovery.flags.enable_crashrecovery") public final void setHealthCheckResultCallback(@Nullable java.util.concurrent.Executor, @Nullable java.util.function.Consumer<android.os.Bundle>);
+    method @FlaggedApi("android.crashrecovery.flags.enable_crashrecovery") public final void setHealthCheckPassedCallback(@Nullable java.util.concurrent.Executor, @Nullable java.util.function.Consumer<android.os.Bundle>);
     field public static final String BIND_PERMISSION = "android.permission.BIND_EXPLICIT_HEALTH_CHECK_SERVICE";
     field @FlaggedApi("android.crashrecovery.flags.enable_crashrecovery") public static final String EXTRA_HEALTH_CHECK_PASSED_PACKAGE = "android.service.watchdog.extra.HEALTH_CHECK_PASSED_PACKAGE";
     field public static final String SERVICE_INTERFACE = "android.service.watchdog.ExplicitHealthCheckService";
diff --git a/framework/java/android/service/watchdog/ExplicitHealthCheckService.java b/framework/java/android/service/watchdog/ExplicitHealthCheckService.java
new file mode 100644
index 0000000..fdb0fc5
--- /dev/null
+++ b/framework/java/android/service/watchdog/ExplicitHealthCheckService.java
@@ -0,0 +1,359 @@
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
+
+package android.service.watchdog;
+
+import static android.os.Parcelable.Creator;
+
+import android.annotation.CallbackExecutor;
+import android.annotation.FlaggedApi;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.SdkConstant;
+import android.annotation.SuppressLint;
+import android.annotation.SystemApi;
+import android.app.Service;
+import android.content.Intent;
+import android.content.pm.PackageManager;
+import android.crashrecovery.flags.Flags;
+import android.os.Bundle;
+import android.os.Handler;
+import android.os.IBinder;
+import android.os.Looper;
+import android.os.Parcel;
+import android.os.Parcelable;
+import android.os.RemoteCallback;
+import android.os.RemoteException;
+import android.util.Log;
+
+import com.android.internal.util.Preconditions;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.Objects;
+import java.util.concurrent.Executor;
+import java.util.concurrent.TimeUnit;
+import java.util.function.Consumer;
+
+/**
+ * A service to provide packages supporting explicit health checks and route checks to these
+ * packages on behalf of the package watchdog.
+ *
+ * <p>To extend this class, you must declare the service in your manifest file with the
+ * {@link android.Manifest.permission#BIND_EXPLICIT_HEALTH_CHECK_SERVICE} permission,
+ * and include an intent filter with the {@link #SERVICE_INTERFACE} action. In adddition,
+ * your implementation must live in
+ * {@link PackageManager#getServicesSystemSharedLibraryPackageName()}.
+ * For example:</p>
+ * <pre>
+ *     &lt;service android:name=".FooExplicitHealthCheckService"
+ *             android:exported="true"
+ *             android:priority="100"
+ *             android:permission="android.permission.BIND_EXPLICIT_HEALTH_CHECK_SERVICE"&gt;
+ *         &lt;intent-filter&gt;
+ *             &lt;action android:name="android.service.watchdog.ExplicitHealthCheckService" /&gt;
+ *         &lt;/intent-filter&gt;
+ *     &lt;/service&gt;
+ * </pre>
+ * @hide
+ */
+@SystemApi
+public abstract class ExplicitHealthCheckService extends Service {
+
+    private static final String TAG = "ExplicitHealthCheckService";
+
+    /**
+     * {@link Bundle} key for a {@link List} of {@link PackageConfig} value.
+     *
+     * {@hide}
+     */
+    public static final String EXTRA_SUPPORTED_PACKAGES =
+            "android.service.watchdog.extra.supported_packages";
+
+    /**
+     * {@link Bundle} key for a {@link List} of {@link String} value.
+     *
+     * {@hide}
+     */
+    public static final String EXTRA_REQUESTED_PACKAGES =
+            "android.service.watchdog.extra.requested_packages";
+
+    /**
+     * {@link Bundle} key for a {@link String} value.
+     */
+    @FlaggedApi(Flags.FLAG_ENABLE_CRASHRECOVERY)
+    public static final String EXTRA_HEALTH_CHECK_PASSED_PACKAGE =
+            "android.service.watchdog.extra.HEALTH_CHECK_PASSED_PACKAGE";
+
+    /**
+     * The Intent action that a service must respond to. Add it to the intent filter of the service
+     * in its manifest.
+     */
+    @SdkConstant(SdkConstant.SdkConstantType.SERVICE_ACTION)
+    public static final String SERVICE_INTERFACE =
+            "android.service.watchdog.ExplicitHealthCheckService";
+
+    /**
+     * The permission that a service must require to ensure that only Android system can bind to it.
+     * If this permission is not enforced in the AndroidManifest of the service, the system will
+     * skip that service.
+     */
+    public static final String BIND_PERMISSION =
+            "android.permission.BIND_EXPLICIT_HEALTH_CHECK_SERVICE";
+
+    private final ExplicitHealthCheckServiceWrapper mWrapper =
+            new ExplicitHealthCheckServiceWrapper();
+
+    /**
+     * Called when the system requests an explicit health check for {@code packageName}.
+     *
+     * <p> When {@code packageName} passes the check, implementors should call
+     * {@link #notifyHealthCheckPassed} to inform the system.
+     *
+     * <p> It could take many hours before a {@code packageName} passes a check and implementors
+     * should never drop requests unless {@link onCancel} is called or the service dies.
+     *
+     * <p> Requests should not be queued and additional calls while expecting a result for
+     * {@code packageName} should have no effect.
+     */
+    public abstract void onRequestHealthCheck(@NonNull String packageName);
+
+    /**
+     * Called when the system cancels the explicit health check request for {@code packageName}.
+     * Should do nothing if there are is no active request for {@code packageName}.
+     */
+    public abstract void onCancelHealthCheck(@NonNull String packageName);
+
+    /**
+     * Called when the system requests for all the packages supporting explicit health checks. The
+     * system may request an explicit health check for any of these packages with
+     * {@link #onRequestHealthCheck}.
+     *
+     * @return all packages supporting explicit health checks
+     */
+    @NonNull public abstract List<PackageConfig> onGetSupportedPackages();
+
+    /**
+     * Called when the system requests for all the packages that it has currently requested
+     * an explicit health check for.
+     *
+     * @return all packages expecting an explicit health check result
+     */
+    @NonNull public abstract List<String> onGetRequestedPackages();
+
+    private final Handler mHandler = Handler.createAsync(Looper.getMainLooper());
+    @Nullable private Consumer<Bundle> mHealthCheckResultCallback;
+    @Nullable private Executor mCallbackExecutor;
+
+    @Override
+    @NonNull
+    public final IBinder onBind(@NonNull Intent intent) {
+        return mWrapper;
+    }
+
+    /**
+     * Sets a callback to be invoked when an explicit health check passes for a package.
+     * <p>
+     * The callback will receive a {@link Bundle} containing the package name that passed the
+     * health check, identified by the key {@link #EXTRA_HEALTH_CHECK_PASSED_PACKAGE}.
+     * <p>
+     * <b>Note:</b> This API is primarily intended for testing purposes. Calling this outside of a
+     * test environment will override the default callback mechanism used to notify the system
+     * about health check results. Use with caution in production code.
+     *
+     * @param executor The executor on which the callback should be invoked. If {@code null}, the
+     *                 callback will be executed on the main thread.
+     * @param callback A callback that receives a {@link Bundle} containing the package name that
+     *                 passed the health check.
+     */
+    @FlaggedApi(Flags.FLAG_ENABLE_CRASHRECOVERY)
+    public final void setHealthCheckPassedCallback(@CallbackExecutor @Nullable Executor executor,
+            @Nullable Consumer<Bundle> callback) {
+        mCallbackExecutor = executor;
+        mHealthCheckResultCallback = callback;
+    }
+
+    private void executeCallback(@NonNull String packageName) {
+        if (mHealthCheckResultCallback != null) {
+            Objects.requireNonNull(packageName,
+                    "Package passing explicit health check must be non-null");
+            Bundle bundle = new Bundle();
+            bundle.putString(EXTRA_HEALTH_CHECK_PASSED_PACKAGE, packageName);
+            mHealthCheckResultCallback.accept(bundle);
+        } else {
+            Log.wtf(TAG, "System missed explicit health check result for " + packageName);
+        }
+    }
+
+    /**
+     * Implementors should call this to notify the system when explicit health check passes
+     * for {@code packageName};
+     */
+    public final void notifyHealthCheckPassed(@NonNull String packageName) {
+        if (mCallbackExecutor != null) {
+            mCallbackExecutor.execute(() -> executeCallback(packageName));
+        } else {
+            mHandler.post(() -> executeCallback(packageName));
+        }
+    }
+
+    /**
+     * A PackageConfig contains a package supporting explicit health checks and the
+     * timeout in {@link System#uptimeMillis} across reboots after which health
+     * check requests from clients are failed.
+     *
+     * @hide
+     */
+    @SystemApi
+    public static final class PackageConfig implements Parcelable {
+        private static final long DEFAULT_HEALTH_CHECK_TIMEOUT_MILLIS = TimeUnit.HOURS.toMillis(1);
+
+        private final String mPackageName;
+        private final long mHealthCheckTimeoutMillis;
+
+        /**
+         * Creates a new instance.
+         *
+         * @param packageName the package name
+         * @param durationMillis the duration in milliseconds, must be greater than or
+         * equal to 0. If it is 0, it will use a system default value.
+         */
+        public PackageConfig(@NonNull String packageName, long healthCheckTimeoutMillis) {
+            mPackageName = Preconditions.checkNotNull(packageName);
+            if (healthCheckTimeoutMillis == 0) {
+                mHealthCheckTimeoutMillis = DEFAULT_HEALTH_CHECK_TIMEOUT_MILLIS;
+            } else {
+                mHealthCheckTimeoutMillis = Preconditions.checkArgumentNonnegative(
+                        healthCheckTimeoutMillis);
+            }
+        }
+
+        private PackageConfig(Parcel parcel) {
+            mPackageName = parcel.readString();
+            mHealthCheckTimeoutMillis = parcel.readLong();
+        }
+
+        /**
+         * Gets the package name.
+         *
+         * @return the package name
+         */
+        public @NonNull String getPackageName() {
+            return mPackageName;
+        }
+
+        /**
+         * Gets the timeout in milliseconds to evaluate an explicit health check result after a
+         * request.
+         *
+         * @return the duration in {@link System#uptimeMillis} across reboots
+         */
+        public long getHealthCheckTimeoutMillis() {
+            return mHealthCheckTimeoutMillis;
+        }
+
+        @NonNull
+        @Override
+        public String toString() {
+            return "PackageConfig{" + mPackageName + ", " + mHealthCheckTimeoutMillis + "}";
+        }
+
+        @Override
+        public boolean equals(@Nullable Object other) {
+            if (other == this) {
+                return true;
+            }
+            if (!(other instanceof PackageConfig)) {
+                return false;
+            }
+
+            PackageConfig otherInfo = (PackageConfig) other;
+            return Objects.equals(otherInfo.getHealthCheckTimeoutMillis(),
+                    mHealthCheckTimeoutMillis)
+                    && Objects.equals(otherInfo.getPackageName(), mPackageName);
+        }
+
+        @Override
+        public int hashCode() {
+            return Objects.hash(mPackageName, mHealthCheckTimeoutMillis);
+        }
+
+        @Override
+        public int describeContents() {
+            return 0;
+        }
+
+        @Override
+        public void writeToParcel(@SuppressLint({"MissingNullability"}) Parcel parcel, int flags) {
+            parcel.writeString(mPackageName);
+            parcel.writeLong(mHealthCheckTimeoutMillis);
+        }
+
+        public static final @NonNull Creator<PackageConfig> CREATOR = new Creator<PackageConfig>() {
+                @Override
+                public PackageConfig createFromParcel(Parcel source) {
+                    return new PackageConfig(source);
+                }
+
+                @Override
+                public PackageConfig[] newArray(int size) {
+                    return new PackageConfig[size];
+                }
+            };
+    }
+
+
+    private class ExplicitHealthCheckServiceWrapper extends IExplicitHealthCheckService.Stub {
+        @Override
+        public void setCallback(RemoteCallback callback) throws RemoteException {
+            mHandler.post(() -> mHealthCheckResultCallback = callback::sendResult);
+        }
+
+        @Override
+        public void request(String packageName) throws RemoteException {
+            mHandler.post(() -> ExplicitHealthCheckService.this.onRequestHealthCheck(packageName));
+        }
+
+        @Override
+        public void cancel(String packageName) throws RemoteException {
+            mHandler.post(() -> ExplicitHealthCheckService.this.onCancelHealthCheck(packageName));
+        }
+
+        @Override
+        public void getSupportedPackages(RemoteCallback callback) throws RemoteException {
+            mHandler.post(() -> {
+                List<PackageConfig> packages =
+                        ExplicitHealthCheckService.this.onGetSupportedPackages();
+                Objects.requireNonNull(packages, "Supported package list must be non-null");
+                Bundle bundle = new Bundle();
+                bundle.putParcelableArrayList(EXTRA_SUPPORTED_PACKAGES, new ArrayList<>(packages));
+                callback.sendResult(bundle);
+            });
+        }
+
+        @Override
+        public void getRequestedPackages(RemoteCallback callback) throws RemoteException {
+            mHandler.post(() -> {
+                List<String> packages =
+                        ExplicitHealthCheckService.this.onGetRequestedPackages();
+                Objects.requireNonNull(packages, "Requested  package list must be non-null");
+                Bundle bundle = new Bundle();
+                bundle.putStringArrayList(EXTRA_REQUESTED_PACKAGES, new ArrayList<>(packages));
+                callback.sendResult(bundle);
+            });
+        }
+    }
+}
diff --git a/framework/java/android/service/watchdog/IExplicitHealthCheckService.aidl b/framework/java/android/service/watchdog/IExplicitHealthCheckService.aidl
new file mode 100644
index 0000000..9096509
--- /dev/null
+++ b/framework/java/android/service/watchdog/IExplicitHealthCheckService.aidl
@@ -0,0 +1,32 @@
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
+
+package android.service.watchdog;
+
+import android.os.RemoteCallback;
+
+/**
+ * @hide
+ */
+@PermissionManuallyEnforced
+oneway interface IExplicitHealthCheckService
+{
+    void setCallback(in @nullable RemoteCallback callback);
+    void request(String packageName);
+    void cancel(String packageName);
+    void getSupportedPackages(in RemoteCallback callback);
+    void getRequestedPackages(in RemoteCallback callback);
+}
diff --git a/framework/java/android/service/watchdog/OWNERS b/framework/java/android/service/watchdog/OWNERS
new file mode 100644
index 0000000..1c045e1
--- /dev/null
+++ b/framework/java/android/service/watchdog/OWNERS
@@ -0,0 +1,3 @@
+narayan@google.com
+nandana@google.com
+olilan@google.com
diff --git a/service/java/com/android/server/FoobarService.java b/framework/java/android/service/watchdog/PackageConfig.aidl
similarity index 81%
rename from service/java/com/android/server/FoobarService.java
rename to framework/java/android/service/watchdog/PackageConfig.aidl
index 93653a8..0131586 100644
--- a/service/java/com/android/server/FoobarService.java
+++ b/framework/java/android/service/watchdog/PackageConfig.aidl
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2019 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,10 +14,9 @@
  * limitations under the License.
  */
 
-package com.android.server;
+package android.service.watchdog;
 
-
-/** @hide */
-public class FoobarService {
-
-}
\ No newline at end of file
+/**
+ * @hide
+ */
+parcelable PackageConfig;
diff --git a/service/Android.bp b/service/Android.bp
index 9cc28de..5ed09b6 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -57,6 +57,7 @@ java_defaults {
         "framework-crashrecovery.impl",
         "framework-statsd.stubs.module_lib",
     ],
+    min_sdk_version: "36",
     sdk_version: "system_server_current",
 }
 
diff --git a/service/api/system-server-current.txt b/service/api/system-server-current.txt
index c10104d..adcbed2 100644
--- a/service/api/system-server-current.txt
+++ b/service/api/system-server-current.txt
@@ -6,8 +6,8 @@ package com.android.server {
     method @NonNull public static com.android.server.PackageWatchdog getInstance(@NonNull android.content.Context);
     method public static boolean isRecoveryTriggeredReboot();
     method public void notifyPackageFailure(@NonNull java.util.List<android.content.pm.VersionedPackage>, int);
-    method public void registerHealthObserver(@NonNull com.android.server.PackageWatchdog.PackageHealthObserver, @NonNull java.util.concurrent.Executor);
-    method public void startExplicitHealthCheck(@NonNull com.android.server.PackageWatchdog.PackageHealthObserver, @NonNull java.util.List<java.lang.String>, long);
+    method public void registerHealthObserver(@NonNull java.util.concurrent.Executor, @NonNull com.android.server.PackageWatchdog.PackageHealthObserver);
+    method public void startExplicitHealthCheck(@NonNull java.util.List<java.lang.String>, long, @NonNull com.android.server.PackageWatchdog.PackageHealthObserver);
     method public void unregisterHealthObserver(@NonNull com.android.server.PackageWatchdog.PackageHealthObserver);
     field public static final int FAILURE_REASON_APP_CRASH = 3; // 0x3
     field public static final int FAILURE_REASON_APP_NOT_RESPONDING = 4; // 0x4
@@ -15,6 +15,8 @@ package com.android.server {
     field public static final int FAILURE_REASON_EXPLICIT_HEALTH_CHECK = 2; // 0x2
     field public static final int FAILURE_REASON_NATIVE_CRASH = 1; // 0x1
     field public static final int FAILURE_REASON_UNKNOWN = 0; // 0x0
+    field public static final int MITIGATION_RESULT_SKIPPED = 2; // 0x2
+    field public static final int MITIGATION_RESULT_SUCCESS = 1; // 0x1
     field public static final int USER_IMPACT_THRESHOLD_HIGH = 71; // 0x47
     field public static final int USER_IMPACT_THRESHOLD_MEDIUM = 20; // 0x14
     field public static final int USER_IMPACT_THRESHOLD_NONE = 0; // 0x0
@@ -25,8 +27,8 @@ package com.android.server {
     method public default boolean isPersistent();
     method public default boolean mayObservePackage(@NonNull String);
     method public default int onBootLoop(int);
-    method public default boolean onExecuteBootLoopMitigation(int);
-    method public boolean onExecuteHealthCheckMitigation(@Nullable android.content.pm.VersionedPackage, int, int);
+    method public default int onExecuteBootLoopMitigation(int);
+    method public int onExecuteHealthCheckMitigation(@Nullable android.content.pm.VersionedPackage, int, int);
     method public int onHealthCheckFailed(@Nullable android.content.pm.VersionedPackage, int, int);
   }
 
@@ -42,8 +44,8 @@ package com.android.server.rollback {
     method @AnyThread @NonNull public void notifyRollbackAvailable(@NonNull android.content.rollback.RollbackInfo);
     method @AnyThread public void onBootCompletedAsync();
     method public int onBootLoop(int);
-    method public boolean onExecuteBootLoopMitigation(int);
-    method public boolean onExecuteHealthCheckMitigation(@Nullable android.content.pm.VersionedPackage, int, int);
+    method public int onExecuteBootLoopMitigation(int);
+    method public int onExecuteHealthCheckMitigation(@Nullable android.content.pm.VersionedPackage, int, int);
     method public int onHealthCheckFailed(@Nullable android.content.pm.VersionedPackage, int, int);
   }
 
diff --git a/service/java/com/android/server/ExplicitHealthCheckController.java b/service/java/com/android/server/ExplicitHealthCheckController.java
new file mode 100644
index 0000000..da9a139
--- /dev/null
+++ b/service/java/com/android/server/ExplicitHealthCheckController.java
@@ -0,0 +1,447 @@
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
+
+package com.android.server;
+
+import static android.service.watchdog.ExplicitHealthCheckService.EXTRA_HEALTH_CHECK_PASSED_PACKAGE;
+import static android.service.watchdog.ExplicitHealthCheckService.EXTRA_REQUESTED_PACKAGES;
+import static android.service.watchdog.ExplicitHealthCheckService.EXTRA_SUPPORTED_PACKAGES;
+import static android.service.watchdog.ExplicitHealthCheckService.PackageConfig;
+
+import android.Manifest;
+import android.annotation.MainThread;
+import android.annotation.Nullable;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.content.ServiceConnection;
+import android.content.pm.PackageManager;
+import android.content.pm.ResolveInfo;
+import android.content.pm.ServiceInfo;
+import android.os.IBinder;
+import android.os.RemoteCallback;
+import android.os.RemoteException;
+import android.os.UserHandle;
+import android.service.watchdog.ExplicitHealthCheckService;
+import android.service.watchdog.IExplicitHealthCheckService;
+import android.text.TextUtils;
+import android.util.ArraySet;
+import android.util.Slog;
+
+import com.android.internal.annotations.GuardedBy;
+
+import java.util.Collection;
+import java.util.Collections;
+import java.util.Iterator;
+import java.util.List;
+import java.util.Objects;
+import java.util.Set;
+import java.util.function.Consumer;
+
+// TODO(b/120598832): Add tests
+/**
+ * Controls the connections with {@link ExplicitHealthCheckService}.
+ */
+class ExplicitHealthCheckController {
+    private static final String TAG = "ExplicitHealthCheckController";
+    private final Object mLock = new Object();
+    private final Context mContext;
+
+    // Called everytime a package passes the health check, so the watchdog is notified of the
+    // passing check. In practice, should never be null after it has been #setEnabled.
+    // To prevent deadlocks between the controller and watchdog threads, we have
+    // a lock invariant to ALWAYS acquire the PackageWatchdog#mLock before #mLock in this class.
+    // It's easier to just NOT hold #mLock when calling into watchdog code on this consumer.
+    @GuardedBy("mLock") @Nullable private Consumer<String> mPassedConsumer;
+    // Called everytime after a successful #syncRequest call, so the watchdog can receive packages
+    // supporting health checks and update its internal state. In practice, should never be null
+    // after it has been #setEnabled.
+    // To prevent deadlocks between the controller and watchdog threads, we have
+    // a lock invariant to ALWAYS acquire the PackageWatchdog#mLock before #mLock in this class.
+    // It's easier to just NOT hold #mLock when calling into watchdog code on this consumer.
+    @GuardedBy("mLock") @Nullable private Consumer<List<PackageConfig>> mSupportedConsumer;
+    // Called everytime we need to notify the watchdog to sync requests between itself and the
+    // health check service. In practice, should never be null after it has been #setEnabled.
+    // To prevent deadlocks between the controller and watchdog threads, we have
+    // a lock invariant to ALWAYS acquire the PackageWatchdog#mLock before #mLock in this class.
+    // It's easier to just NOT hold #mLock when calling into watchdog code on this runnable.
+    @GuardedBy("mLock") @Nullable private Runnable mNotifySyncRunnable;
+    // Actual binder object to the explicit health check service.
+    @GuardedBy("mLock") @Nullable private IExplicitHealthCheckService mRemoteService;
+    // Connection to the explicit health check service, necessary to unbind.
+    // We should only try to bind if mConnection is null, non-null indicates we
+    // are connected or at least connecting.
+    @GuardedBy("mLock") @Nullable private ServiceConnection mConnection;
+    // Bind state of the explicit health check service.
+    @GuardedBy("mLock") private boolean mEnabled;
+
+    ExplicitHealthCheckController(Context context) {
+        mContext = context;
+    }
+
+    /** Enables or disables explicit health checks. */
+    public void setEnabled(boolean enabled) {
+        synchronized (mLock) {
+            Slog.i(TAG, "Explicit health checks " + (enabled ? "enabled." : "disabled."));
+            mEnabled = enabled;
+        }
+    }
+
+    /**
+     * Sets callbacks to listen to important events from the controller.
+     *
+     * <p> Should be called once at initialization before any other calls to the controller to
+     * ensure a happens-before relationship of the set parameters and visibility on other threads.
+     */
+    public void setCallbacks(Consumer<String> passedConsumer,
+            Consumer<List<PackageConfig>> supportedConsumer, Runnable notifySyncRunnable) {
+        synchronized (mLock) {
+            if (mPassedConsumer != null || mSupportedConsumer != null
+                    || mNotifySyncRunnable != null) {
+                Slog.wtf(TAG, "Resetting health check controller callbacks");
+            }
+
+            mPassedConsumer = Objects.requireNonNull(passedConsumer);
+            mSupportedConsumer = Objects.requireNonNull(supportedConsumer);
+            mNotifySyncRunnable = Objects.requireNonNull(notifySyncRunnable);
+        }
+    }
+
+    /**
+     * Calls the health check service to request or cancel packages based on
+     * {@code newRequestedPackages}.
+     *
+     * <p> Supported packages in {@code newRequestedPackages} that have not been previously
+     * requested will be requested while supported packages not in {@code newRequestedPackages}
+     * but were previously requested will be cancelled.
+     *
+     * <p> This handles binding and unbinding to the health check service as required.
+     *
+     * <p> Note, calling this may modify {@code newRequestedPackages}.
+     *
+     * <p> Note, this method is not thread safe, all calls should be serialized.
+     */
+    public void syncRequests(Set<String> newRequestedPackages) {
+        boolean enabled;
+        synchronized (mLock) {
+            enabled = mEnabled;
+        }
+
+        if (!enabled) {
+            Slog.i(TAG, "Health checks disabled, no supported packages");
+            // Call outside lock
+            mSupportedConsumer.accept(Collections.emptyList());
+            return;
+        }
+
+        getSupportedPackages(supportedPackageConfigs -> {
+            // Notify the watchdog without lock held
+            mSupportedConsumer.accept(supportedPackageConfigs);
+            getRequestedPackages(previousRequestedPackages -> {
+                synchronized (mLock) {
+                    // Hold lock so requests and cancellations are sent atomically.
+                    // It is important we don't mix requests from multiple threads.
+
+                    Set<String> supportedPackages = new ArraySet<>();
+                    for (PackageConfig config : supportedPackageConfigs) {
+                        supportedPackages.add(config.getPackageName());
+                    }
+                    // Note, this may modify newRequestedPackages
+                    newRequestedPackages.retainAll(supportedPackages);
+
+                    // Cancel packages no longer requested
+                    actOnDifference(previousRequestedPackages,
+                            newRequestedPackages, p -> cancel(p));
+                    // Request packages not yet requested
+                    actOnDifference(newRequestedPackages,
+                            previousRequestedPackages, p -> request(p));
+
+                    if (newRequestedPackages.isEmpty()) {
+                        Slog.i(TAG, "No more health check requests, unbinding...");
+                        unbindService();
+                        return;
+                    }
+                }
+            });
+        });
+    }
+
+    private void actOnDifference(Collection<String> collection1, Collection<String> collection2,
+            Consumer<String> action) {
+        Iterator<String> iterator = collection1.iterator();
+        while (iterator.hasNext()) {
+            String packageName = iterator.next();
+            if (!collection2.contains(packageName)) {
+                action.accept(packageName);
+            }
+        }
+    }
+
+    /**
+     * Requests an explicit health check for {@code packageName}.
+     * After this request, the callback registered on {@link #setCallbacks} can receive explicit
+     * health check passed results.
+     */
+    private void request(String packageName) {
+        synchronized (mLock) {
+            if (!prepareServiceLocked("request health check for " + packageName)) {
+                return;
+            }
+
+            Slog.i(TAG, "Requesting health check for package " + packageName);
+            try {
+                mRemoteService.request(packageName);
+            } catch (RemoteException e) {
+                Slog.w(TAG, "Failed to request health check for package " + packageName, e);
+            }
+        }
+    }
+
+    /**
+     * Cancels all explicit health checks for {@code packageName}.
+     * After this request, the callback registered on {@link #setCallbacks} can no longer receive
+     * explicit health check passed results.
+     */
+    private void cancel(String packageName) {
+        synchronized (mLock) {
+            if (!prepareServiceLocked("cancel health check for " + packageName)) {
+                return;
+            }
+
+            Slog.i(TAG, "Cancelling health check for package " + packageName);
+            try {
+                mRemoteService.cancel(packageName);
+            } catch (RemoteException e) {
+                // Do nothing, if the service is down, when it comes up, we will sync requests,
+                // if there's some other error, retrying wouldn't fix anyways.
+                Slog.w(TAG, "Failed to cancel health check for package " + packageName, e);
+            }
+        }
+    }
+
+    /**
+     * Returns the packages that we can request explicit health checks for.
+     * The packages will be returned to the {@code consumer}.
+     */
+    private void getSupportedPackages(Consumer<List<PackageConfig>> consumer) {
+        synchronized (mLock) {
+            if (!prepareServiceLocked("get health check supported packages")) {
+                return;
+            }
+
+            Slog.d(TAG, "Getting health check supported packages");
+            try {
+                mRemoteService.getSupportedPackages(new RemoteCallback(result -> {
+                    List<PackageConfig> packages =
+                            result.getParcelableArrayList(EXTRA_SUPPORTED_PACKAGES, android.service.watchdog.ExplicitHealthCheckService.PackageConfig.class);
+                    Slog.i(TAG, "Explicit health check supported packages " + packages);
+                    consumer.accept(packages);
+                }));
+            } catch (RemoteException e) {
+                // Request failed, treat as if all observed packages are supported, if any packages
+                // expire during this period, we may incorrectly treat it as failing health checks
+                // even if we don't support health checks for the package.
+                Slog.w(TAG, "Failed to get health check supported packages", e);
+            }
+        }
+    }
+
+    /**
+     * Returns the packages for which health checks are currently in progress.
+     * The packages will be returned to the {@code consumer}.
+     */
+    private void getRequestedPackages(Consumer<List<String>> consumer) {
+        synchronized (mLock) {
+            if (!prepareServiceLocked("get health check requested packages")) {
+                return;
+            }
+
+            Slog.d(TAG, "Getting health check requested packages");
+            try {
+                mRemoteService.getRequestedPackages(new RemoteCallback(result -> {
+                    List<String> packages = result.getStringArrayList(EXTRA_REQUESTED_PACKAGES);
+                    Slog.i(TAG, "Explicit health check requested packages " + packages);
+                    consumer.accept(packages);
+                }));
+            } catch (RemoteException e) {
+                // Request failed, treat as if we haven't requested any packages, if any packages
+                // were actually requested, they will not be cancelled now. May be cancelled later
+                Slog.w(TAG, "Failed to get health check requested packages", e);
+            }
+        }
+    }
+
+    /**
+     * Binds to the explicit health check service if the controller is enabled and
+     * not already bound.
+     */
+    private void bindService() {
+        synchronized (mLock) {
+            if (!mEnabled || mConnection != null || mRemoteService != null) {
+                if (!mEnabled) {
+                    Slog.i(TAG, "Not binding to service, service disabled");
+                } else if (mRemoteService != null) {
+                    Slog.i(TAG, "Not binding to service, service already connected");
+                } else {
+                    Slog.i(TAG, "Not binding to service, service already connecting");
+                }
+                return;
+            }
+            ComponentName component = getServiceComponentNameLocked();
+            if (component == null) {
+                Slog.wtf(TAG, "Explicit health check service not found");
+                return;
+            }
+
+            Intent intent = new Intent();
+            intent.setComponent(component);
+            mConnection = new ServiceConnection() {
+                @Override
+                public void onServiceConnected(ComponentName name, IBinder service) {
+                    Slog.i(TAG, "Explicit health check service is connected " + name);
+                    initState(service);
+                }
+
+                @Override
+                @MainThread
+                public void onServiceDisconnected(ComponentName name) {
+                    // Service crashed or process was killed, #onServiceConnected will be called.
+                    // Don't need to re-bind.
+                    Slog.i(TAG, "Explicit health check service is disconnected " + name);
+                    synchronized (mLock) {
+                        mRemoteService = null;
+                    }
+                }
+
+                @Override
+                public void onBindingDied(ComponentName name) {
+                    // Application hosting service probably got updated
+                    // Need to re-bind.
+                    Slog.i(TAG, "Explicit health check service binding is dead. Rebind: " + name);
+                    unbindService();
+                    bindService();
+                }
+
+                @Override
+                public void onNullBinding(ComponentName name) {
+                    // Should never happen. Service returned null from #onBind.
+                    Slog.wtf(TAG, "Explicit health check service binding is null?? " + name);
+                }
+            };
+
+            mContext.bindServiceAsUser(intent, mConnection,
+                    Context.BIND_AUTO_CREATE, UserHandle.SYSTEM);
+            Slog.i(TAG, "Explicit health check service is bound");
+        }
+    }
+
+    /** Unbinds the explicit health check service. */
+    private void unbindService() {
+        synchronized (mLock) {
+            if (mRemoteService != null) {
+                mContext.unbindService(mConnection);
+                mRemoteService = null;
+                mConnection = null;
+            }
+            Slog.i(TAG, "Explicit health check service is unbound");
+        }
+    }
+
+    @GuardedBy("mLock")
+    @Nullable
+    private ServiceInfo getServiceInfoLocked() {
+        final Intent intent = new Intent(ExplicitHealthCheckService.SERVICE_INTERFACE);
+        final ResolveInfo resolveInfo = mContext.getPackageManager().resolveService(intent,
+                PackageManager.GET_SERVICES | PackageManager.GET_META_DATA
+                        |  PackageManager.MATCH_SYSTEM_ONLY);
+        if (resolveInfo == null || resolveInfo.serviceInfo == null) {
+            Slog.w(TAG, "No valid components found.");
+            return null;
+        }
+        return resolveInfo.serviceInfo;
+    }
+
+    @GuardedBy("mLock")
+    @Nullable
+    private ComponentName getServiceComponentNameLocked() {
+        final ServiceInfo serviceInfo = getServiceInfoLocked();
+        if (serviceInfo == null) {
+            return null;
+        }
+
+        final ComponentName name = new ComponentName(serviceInfo.packageName, serviceInfo.name);
+        if (!Manifest.permission.BIND_EXPLICIT_HEALTH_CHECK_SERVICE
+                .equals(serviceInfo.permission)) {
+            Slog.w(TAG, name.flattenToShortString() + " does not require permission "
+                    + Manifest.permission.BIND_EXPLICIT_HEALTH_CHECK_SERVICE);
+            return null;
+        }
+        return name;
+    }
+
+    private void initState(IBinder service) {
+        synchronized (mLock) {
+            if (!mEnabled) {
+                Slog.w(TAG, "Attempting to connect disabled service?? Unbinding...");
+                // Very unlikely, but we disabled the service after binding but before we connected
+                unbindService();
+                return;
+            }
+            mRemoteService = IExplicitHealthCheckService.Stub.asInterface(service);
+            try {
+                mRemoteService.setCallback(new RemoteCallback(result -> {
+                    String packageName = result.getString(EXTRA_HEALTH_CHECK_PASSED_PACKAGE);
+                    if (!TextUtils.isEmpty(packageName)) {
+                        if (mPassedConsumer == null) {
+                            Slog.wtf(TAG, "Health check passed for package " + packageName
+                                    + "but no consumer registered.");
+                        } else {
+                            // Call without lock held
+                            mPassedConsumer.accept(packageName);
+                        }
+                    } else {
+                        Slog.wtf(TAG, "Empty package passed explicit health check?");
+                    }
+                }));
+                Slog.i(TAG, "Service initialized, syncing requests");
+            } catch (RemoteException e) {
+                Slog.wtf(TAG, "Could not setCallback on explicit health check service");
+            }
+        }
+        // Calling outside lock
+        mNotifySyncRunnable.run();
+    }
+
+    /**
+     * Prepares the health check service to receive requests.
+     *
+     * @return {@code true} if it is ready and we can proceed with a request,
+     * {@code false} otherwise. If it is not ready, and the service is enabled,
+     * we will bind and the request should be automatically attempted later.
+     */
+    @GuardedBy("mLock")
+    private boolean prepareServiceLocked(String action) {
+        if (mRemoteService != null && mEnabled) {
+            return true;
+        }
+        Slog.i(TAG, "Service not ready to " + action
+                + (mEnabled ? ". Binding..." : ". Disabled"));
+        if (mEnabled) {
+            bindService();
+        }
+        return false;
+    }
+}
diff --git a/service/java/com/android/server/PackageWatchdog.java b/service/java/com/android/server/PackageWatchdog.java
new file mode 100644
index 0000000..318a749
--- /dev/null
+++ b/service/java/com/android/server/PackageWatchdog.java
@@ -0,0 +1,2205 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package com.android.server;
+
+import static android.content.Intent.ACTION_REBOOT;
+import static android.content.Intent.ACTION_SHUTDOWN;
+import static android.service.watchdog.ExplicitHealthCheckService.PackageConfig;
+import static android.util.Xml.Encoding.UTF_8;
+
+import static com.android.server.crashrecovery.CrashRecoveryUtils.dumpCrashRecoveryEvents;
+
+import static java.lang.annotation.RetentionPolicy.SOURCE;
+
+import android.annotation.CallbackExecutor;
+import android.annotation.FlaggedApi;
+import android.annotation.IntDef;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.SuppressLint;
+import android.annotation.SystemApi;
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.pm.PackageInfo;
+import android.content.pm.PackageManager;
+import android.content.pm.VersionedPackage;
+import android.crashrecovery.flags.Flags;
+import android.os.Environment;
+import android.os.Handler;
+import android.os.Looper;
+import android.os.Process;
+import android.os.SystemProperties;
+import android.provider.DeviceConfig;
+import android.sysprop.CrashRecoveryProperties;
+import android.text.TextUtils;
+import android.util.ArrayMap;
+import android.util.ArraySet;
+import android.util.AtomicFile;
+import android.util.EventLog;
+import android.util.IndentingPrintWriter;
+import android.util.LongArrayQueue;
+import android.util.Slog;
+import android.util.Xml;
+import android.util.XmlUtils;
+
+import com.android.internal.annotations.GuardedBy;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.internal.util.FastXmlSerializer;
+import com.android.modules.utils.BackgroundThread;
+
+import libcore.io.IoUtils;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+import org.xmlpull.v1.XmlSerializer;
+
+import java.io.BufferedReader;
+import java.io.BufferedWriter;
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.FileNotFoundException;
+import java.io.FileOutputStream;
+import java.io.FileReader;
+import java.io.FileWriter;
+import java.io.IOException;
+import java.io.InputStream;
+import java.io.ObjectInputStream;
+import java.io.ObjectOutputStream;
+import java.io.PrintWriter;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.util.ArrayList;
+import java.util.Collections;
+import java.util.HashMap;
+import java.util.Iterator;
+import java.util.List;
+import java.util.Map;
+import java.util.NoSuchElementException;
+import java.util.Set;
+import java.util.concurrent.Executor;
+import java.util.concurrent.TimeUnit;
+
+/**
+ * Monitors the health of packages on the system and notifies interested observers when packages
+ * fail. On failure, the registered observer with the least user impacting mitigation will
+ * be notified.
+ * @hide
+ */
+@FlaggedApi(Flags.FLAG_ENABLE_CRASHRECOVERY)
+@SystemApi(client = SystemApi.Client.SYSTEM_SERVER)
+public class PackageWatchdog {
+    private static final String TAG = "PackageWatchdog";
+
+    static final String PROPERTY_WATCHDOG_TRIGGER_DURATION_MILLIS =
+            "watchdog_trigger_failure_duration_millis";
+    static final String PROPERTY_WATCHDOG_TRIGGER_FAILURE_COUNT =
+            "watchdog_trigger_failure_count";
+    static final String PROPERTY_WATCHDOG_EXPLICIT_HEALTH_CHECK_ENABLED =
+            "watchdog_explicit_health_check_enabled";
+
+    // TODO: make the following values configurable via DeviceConfig
+    private static final long NATIVE_CRASH_POLLING_INTERVAL_MILLIS =
+            TimeUnit.SECONDS.toMillis(30);
+    private static final long NUMBER_OF_NATIVE_CRASH_POLLS = 10;
+
+
+    /** Reason for package failure could not be determined. */
+    public static final int FAILURE_REASON_UNKNOWN = 0;
+
+    /** The package had a native crash. */
+    public static final int FAILURE_REASON_NATIVE_CRASH = 1;
+
+    /** The package failed an explicit health check. */
+    public static final int FAILURE_REASON_EXPLICIT_HEALTH_CHECK = 2;
+
+    /** The app crashed. */
+    public static final int FAILURE_REASON_APP_CRASH = 3;
+
+    /** The app was not responding. */
+    public static final int FAILURE_REASON_APP_NOT_RESPONDING = 4;
+
+    /** The device was boot looping. */
+    public static final int FAILURE_REASON_BOOT_LOOP = 5;
+
+    /** @hide */
+    @IntDef(prefix = { "FAILURE_REASON_" }, value = {
+            FAILURE_REASON_UNKNOWN,
+            FAILURE_REASON_NATIVE_CRASH,
+            FAILURE_REASON_EXPLICIT_HEALTH_CHECK,
+            FAILURE_REASON_APP_CRASH,
+            FAILURE_REASON_APP_NOT_RESPONDING,
+            FAILURE_REASON_BOOT_LOOP
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface FailureReasons {}
+
+    // Duration to count package failures before it resets to 0
+    @VisibleForTesting
+    static final int DEFAULT_TRIGGER_FAILURE_DURATION_MS =
+            (int) TimeUnit.MINUTES.toMillis(1);
+    // Number of package failures within the duration above before we notify observers
+    @VisibleForTesting
+    static final int DEFAULT_TRIGGER_FAILURE_COUNT = 5;
+    @VisibleForTesting
+    static final long DEFAULT_OBSERVING_DURATION_MS = TimeUnit.DAYS.toMillis(2);
+    // Sliding window for tracking how many mitigation calls were made for a package.
+    @VisibleForTesting
+    static final long DEFAULT_DEESCALATION_WINDOW_MS = TimeUnit.HOURS.toMillis(1);
+    // Whether explicit health checks are enabled or not
+    private static final boolean DEFAULT_EXPLICIT_HEALTH_CHECK_ENABLED = true;
+
+    @VisibleForTesting
+    static final int DEFAULT_BOOT_LOOP_TRIGGER_COUNT = 5;
+
+    static final long DEFAULT_BOOT_LOOP_TRIGGER_WINDOW_MS = TimeUnit.MINUTES.toMillis(10);
+
+    // Time needed to apply mitigation
+    private static final String MITIGATION_WINDOW_MS =
+            "persist.device_config.configuration.mitigation_window_ms";
+    @VisibleForTesting
+    static final long DEFAULT_MITIGATION_WINDOW_MS = TimeUnit.SECONDS.toMillis(5);
+
+    // Threshold level at which or above user might experience significant disruption.
+    private static final String MAJOR_USER_IMPACT_LEVEL_THRESHOLD =
+            "persist.device_config.configuration.major_user_impact_level_threshold";
+    private static final int DEFAULT_MAJOR_USER_IMPACT_LEVEL_THRESHOLD =
+            PackageHealthObserverImpact.USER_IMPACT_LEVEL_71;
+
+    // Comma separated list of all packages exempt from user impact level threshold. If a package
+    // in the list is crash looping, all the mitigations including factory reset will be performed.
+    private static final String PACKAGES_EXEMPT_FROM_IMPACT_LEVEL_THRESHOLD =
+            "persist.device_config.configuration.packages_exempt_from_impact_level_threshold";
+
+    // Comma separated list of default packages exempt from user impact level threshold.
+    private static final String DEFAULT_PACKAGES_EXEMPT_FROM_IMPACT_LEVEL_THRESHOLD =
+            "com.android.systemui";
+
+    private long mNumberOfNativeCrashPollsRemaining;
+
+    private static final int DB_VERSION = 1;
+    private static final String TAG_PACKAGE_WATCHDOG = "package-watchdog";
+    private static final String TAG_PACKAGE = "package";
+    private static final String TAG_OBSERVER = "observer";
+    private static final String ATTR_VERSION = "version";
+    private static final String ATTR_NAME = "name";
+    private static final String ATTR_DURATION = "duration";
+    private static final String ATTR_EXPLICIT_HEALTH_CHECK_DURATION = "health-check-duration";
+    private static final String ATTR_PASSED_HEALTH_CHECK = "passed-health-check";
+    private static final String ATTR_MITIGATION_CALLS = "mitigation-calls";
+    private static final String ATTR_MITIGATION_COUNT = "mitigation-count";
+
+    // A file containing information about the current mitigation count in the case of a boot loop.
+    // This allows boot loop information to persist in the case of an fs-checkpoint being
+    // aborted.
+    private static final String METADATA_FILE = "/metadata/watchdog/mitigation_count.txt";
+
+    /**
+     * EventLog tags used when logging into the event log. Note the values must be sync with
+     * frameworks/base/services/core/java/com/android/server/EventLogTags.logtags to get correct
+     * name translation.
+     */
+    private static final int LOG_TAG_RESCUE_NOTE = 2900;
+
+    private static final Object sPackageWatchdogLock = new Object();
+    @GuardedBy("sPackageWatchdogLock")
+    private static PackageWatchdog sPackageWatchdog;
+
+    private static final Object sLock = new Object();
+    // System server context
+    private final Context mContext;
+    // Handler to run short running tasks
+    private final Handler mShortTaskHandler;
+    // Handler for processing IO and long running tasks
+    private final Handler mLongTaskHandler;
+    // Contains (observer-name -> observer-handle) that have ever been registered from
+    // previous boots. Observers with all packages expired are periodically pruned.
+    // It is saved to disk on system shutdown and repouplated on startup so it survives reboots.
+    @GuardedBy("sLock")
+    private final ArrayMap<String, ObserverInternal> mAllObservers = new ArrayMap<>();
+    // File containing the XML data of monitored packages /data/system/package-watchdog.xml
+    private final AtomicFile mPolicyFile;
+    private final ExplicitHealthCheckController mHealthCheckController;
+    private final Runnable mSyncRequests = this::syncRequests;
+    private final Runnable mSyncStateWithScheduledReason = this::syncStateWithScheduledReason;
+    private final Runnable mSaveToFile = this::saveToFile;
+    private final SystemClock mSystemClock;
+    private final BootThreshold mBootThreshold;
+    private final DeviceConfig.OnPropertiesChangedListener
+            mOnPropertyChangedListener = this::onPropertyChanged;
+
+    private final Set<String> mPackagesExemptFromImpactLevelThreshold = new ArraySet<>();
+
+    // The set of packages that have been synced with the ExplicitHealthCheckController
+    @GuardedBy("sLock")
+    private Set<String> mRequestedHealthCheckPackages = new ArraySet<>();
+    @GuardedBy("sLock")
+    private boolean mIsPackagesReady;
+    // Flag to control whether explicit health checks are supported or not
+    @GuardedBy("sLock")
+    private boolean mIsHealthCheckEnabled = DEFAULT_EXPLICIT_HEALTH_CHECK_ENABLED;
+    @GuardedBy("sLock")
+    private int mTriggerFailureDurationMs = DEFAULT_TRIGGER_FAILURE_DURATION_MS;
+    @GuardedBy("sLock")
+    private int mTriggerFailureCount = DEFAULT_TRIGGER_FAILURE_COUNT;
+    // SystemClock#uptimeMillis when we last executed #syncState
+    // 0 if no prune is scheduled.
+    @GuardedBy("sLock")
+    private long mUptimeAtLastStateSync;
+    // If true, sync explicit health check packages with the ExplicitHealthCheckController.
+    @GuardedBy("sLock")
+    private boolean mSyncRequired = false;
+
+    @GuardedBy("sLock")
+    private long mLastMitigation = -1000000;
+
+    @FunctionalInterface
+    @VisibleForTesting
+    interface SystemClock {
+        long uptimeMillis();
+    }
+
+    private PackageWatchdog(Context context) {
+        // Needs to be constructed inline
+        this(context, new AtomicFile(
+                        new File(new File(Environment.getDataDirectory(), "system"),
+                                "package-watchdog.xml")),
+                new Handler(Looper.myLooper()), BackgroundThread.getHandler(),
+                new ExplicitHealthCheckController(context),
+                android.os.SystemClock::uptimeMillis);
+    }
+
+    /**
+     * Creates a PackageWatchdog that allows injecting dependencies.
+     */
+    @VisibleForTesting
+    PackageWatchdog(Context context, AtomicFile policyFile, Handler shortTaskHandler,
+            Handler longTaskHandler, ExplicitHealthCheckController controller,
+            SystemClock clock) {
+        mContext = context;
+        mPolicyFile = policyFile;
+        mShortTaskHandler = shortTaskHandler;
+        mLongTaskHandler = longTaskHandler;
+        mHealthCheckController = controller;
+        mSystemClock = clock;
+        mNumberOfNativeCrashPollsRemaining = NUMBER_OF_NATIVE_CRASH_POLLS;
+        mBootThreshold = new BootThreshold(DEFAULT_BOOT_LOOP_TRIGGER_COUNT,
+                DEFAULT_BOOT_LOOP_TRIGGER_WINDOW_MS);
+
+        loadFromFile();
+        sPackageWatchdog = this;
+    }
+
+    /**
+     * Creates or gets singleton instance of PackageWatchdog.
+     *
+     * @param context The system server context.
+     */
+    public static  @NonNull PackageWatchdog getInstance(@NonNull Context context) {
+        synchronized (sPackageWatchdogLock) {
+            if (sPackageWatchdog == null) {
+                new PackageWatchdog(context);
+            }
+            return sPackageWatchdog;
+        }
+    }
+
+    /**
+     * Called during boot to notify when packages are ready on the device so we can start
+     * binding.
+     * @hide
+     */
+    public void onPackagesReady() {
+        synchronized (sLock) {
+            mIsPackagesReady = true;
+            mHealthCheckController.setCallbacks(packageName -> onHealthCheckPassed(packageName),
+                    packages -> onSupportedPackages(packages),
+                    this::onSyncRequestNotified);
+            setPropertyChangedListenerLocked();
+            updateConfigs();
+        }
+    }
+
+    /**
+     * Registers {@code observer} to listen for package failures. Add a new ObserverInternal for
+     * this observer if it does not already exist.
+     * For executing mitigations observers will receive callback on the given executor.
+     *
+     * <p>Observers are expected to call this on boot. It does not specify any packages but
+     * it will resume observing any packages requested from a previous boot.
+     *
+     * @param observer instance of {@link PackageHealthObserver} for observing package failures
+     *                 and boot loops.
+     * @param executor Executor for the thread on which observers would receive callbacks
+     */
+    public void registerHealthObserver(@NonNull @CallbackExecutor Executor executor,
+            @NonNull PackageHealthObserver observer) {
+        synchronized (sLock) {
+            ObserverInternal internalObserver = mAllObservers.get(observer.getUniqueIdentifier());
+            if (internalObserver != null) {
+                internalObserver.registeredObserver = observer;
+                internalObserver.observerExecutor = executor;
+            } else {
+                internalObserver = new ObserverInternal(observer.getUniqueIdentifier(),
+                        new ArrayList<>());
+                internalObserver.registeredObserver = observer;
+                internalObserver.observerExecutor = executor;
+                mAllObservers.put(observer.getUniqueIdentifier(), internalObserver);
+                syncState("added new observer");
+            }
+        }
+    }
+
+    /**
+     * Starts observing the health of the {@code packages} for {@code observer}.
+     * Note: Observer needs to be registered with {@link #registerHealthObserver} before calling
+     * this API.
+     *
+     * <p>If monitoring a package supporting explicit health check, at the end of the monitoring
+     * duration if {@link #onHealthCheckPassed} was never called,
+     * {@link PackageHealthObserver#onExecuteHealthCheckMitigation} will be called as if the
+     * package failed.
+     *
+     * <p>If {@code observer} is already monitoring a package in {@code packageNames},
+     * the monitoring window of that package will be reset to {@code durationMs} and the health
+     * check state will be reset to a default.
+     *
+     * <p>The {@code observer} must be registered with {@link #registerHealthObserver} before
+     * calling this method.
+     *
+     * @param packageNames The list of packages to check. If this is empty, the call will be a
+     *                     no-op.
+     *
+     * @param timeoutMs The timeout after which Explicit Health Checks would not run. If this is
+     *                  less than 1, a default monitoring duration 2 days will be used.
+     *
+     * @throws IllegalStateException if the observer was not previously registered
+     */
+    public void startExplicitHealthCheck(@NonNull List<String> packageNames, long timeoutMs,
+            @NonNull PackageHealthObserver observer) {
+        synchronized (sLock) {
+            if (!mAllObservers.containsKey(observer.getUniqueIdentifier())) {
+                Slog.wtf(TAG, "No observer found, need to register the observer: "
+                        + observer.getUniqueIdentifier());
+                throw new IllegalStateException("Observer not registered");
+            }
+        }
+        if (packageNames.isEmpty()) {
+            Slog.wtf(TAG, "No packages to observe, " + observer.getUniqueIdentifier());
+            return;
+        }
+        if (timeoutMs < 1) {
+            Slog.wtf(TAG, "Invalid duration " + timeoutMs + "ms for observer "
+                    + observer.getUniqueIdentifier() + ". Not observing packages " + packageNames);
+            timeoutMs = DEFAULT_OBSERVING_DURATION_MS;
+        }
+
+        List<MonitoredPackage> packages = new ArrayList<>();
+        for (int i = 0; i < packageNames.size(); i++) {
+            // Health checks not available yet so health check state will start INACTIVE
+            MonitoredPackage pkg = newMonitoredPackage(packageNames.get(i), timeoutMs, false);
+            if (pkg != null) {
+                packages.add(pkg);
+            } else {
+                Slog.w(TAG, "Failed to create MonitoredPackage for pkg=" + packageNames.get(i));
+            }
+        }
+
+        if (packages.isEmpty()) {
+            return;
+        }
+
+        // Sync before we add the new packages to the observers. This will #pruneObservers,
+        // causing any elapsed time to be deducted from all existing packages before we add new
+        // packages. This maintains the invariant that the elapsed time for ALL (new and existing)
+        // packages is the same.
+        mLongTaskHandler.post(() -> {
+            syncState("observing new packages");
+
+            synchronized (sLock) {
+                ObserverInternal oldObserver = mAllObservers.get(observer.getUniqueIdentifier());
+                if (oldObserver == null) {
+                    Slog.d(TAG, observer.getUniqueIdentifier() + " started monitoring health "
+                            + "of packages " + packageNames);
+                    mAllObservers.put(observer.getUniqueIdentifier(),
+                            new ObserverInternal(observer.getUniqueIdentifier(), packages));
+                } else {
+                    Slog.d(TAG, observer.getUniqueIdentifier() + " added the following "
+                            + "packages to monitor " + packageNames);
+                    oldObserver.updatePackagesLocked(packages);
+                }
+            }
+
+            // Sync after we add the new packages to the observers. We may have received packges
+            // requiring an earlier schedule than we are currently scheduled for.
+            syncState("updated observers");
+        });
+
+    }
+
+    /**
+     * Unregisters {@code observer} from listening to package failure.
+     * Additionally, this stops observing any packages that may have previously been observed
+     * even from a previous boot.
+     */
+    public void unregisterHealthObserver(@NonNull PackageHealthObserver observer) {
+        mLongTaskHandler.post(() -> {
+            synchronized (sLock) {
+                mAllObservers.remove(observer.getUniqueIdentifier());
+            }
+            syncState("unregistering observer: " + observer.getUniqueIdentifier());
+        });
+    }
+
+    /**
+     * Called when a process fails due to a crash, ANR or explicit health check.
+     *
+     * <p>For each package contained in the process, one registered observer with the least user
+     * impact will be notified for mitigation.
+     *
+     * <p>This method could be called frequently if there is a severe problem on the device.
+     */
+    public void notifyPackageFailure(@NonNull List<VersionedPackage> packages,
+            @FailureReasons int failureReason) {
+        if (packages == null) {
+            Slog.w(TAG, "Could not resolve a list of failing packages");
+            return;
+        }
+        synchronized (sLock) {
+            final long now = mSystemClock.uptimeMillis();
+            if (now >= mLastMitigation
+                    && (now - mLastMitigation) < getMitigationWindowMs()) {
+                Slog.i(TAG, "Skipping notifyPackageFailure mitigation");
+                return;
+            }
+        }
+        mLongTaskHandler.post(() -> {
+            synchronized (sLock) {
+                if (mAllObservers.isEmpty()) {
+                    return;
+                }
+                boolean requiresImmediateAction = (failureReason == FAILURE_REASON_NATIVE_CRASH
+                        || failureReason == FAILURE_REASON_EXPLICIT_HEALTH_CHECK);
+                if (requiresImmediateAction) {
+                    handleFailureImmediately(packages, failureReason);
+                } else {
+                    for (int pIndex = 0; pIndex < packages.size(); pIndex++) {
+                        VersionedPackage versionedPackage = packages.get(pIndex);
+                        // Observer that will receive failure for versionedPackage
+                        ObserverInternal currentObserverToNotify = null;
+                        int currentObserverImpact = Integer.MAX_VALUE;
+                        MonitoredPackage currentMonitoredPackage = null;
+
+                        // Find observer with least user impact
+                        for (int oIndex = 0; oIndex < mAllObservers.size(); oIndex++) {
+                            ObserverInternal observer = mAllObservers.valueAt(oIndex);
+                            PackageHealthObserver registeredObserver = observer.registeredObserver;
+                            if (registeredObserver != null
+                                    && observer.notifyPackageFailureLocked(
+                                    versionedPackage.getPackageName())) {
+                                MonitoredPackage p = observer.getMonitoredPackage(
+                                        versionedPackage.getPackageName());
+                                int mitigationCount = 1;
+                                if (p != null) {
+                                    mitigationCount = p.getMitigationCountLocked() + 1;
+                                }
+                                int impact = registeredObserver.onHealthCheckFailed(
+                                        versionedPackage, failureReason, mitigationCount);
+                                if (impact != PackageHealthObserverImpact.USER_IMPACT_LEVEL_0
+                                        && impact < currentObserverImpact) {
+                                    currentObserverToNotify = observer;
+                                    currentObserverImpact = impact;
+                                    currentMonitoredPackage = p;
+                                }
+                            }
+                        }
+
+                        // Execute action with least user impact
+                        if (currentObserverToNotify != null) {
+                            int mitigationCount;
+                            if (currentMonitoredPackage != null) {
+                                currentMonitoredPackage.noteMitigationCallLocked();
+                                mitigationCount =
+                                        currentMonitoredPackage.getMitigationCountLocked();
+                            } else {
+                                mitigationCount = 1;
+                            }
+                            maybeExecute(currentObserverToNotify, versionedPackage,
+                                    failureReason, currentObserverImpact, mitigationCount);
+                        }
+                    }
+                }
+            }
+        });
+    }
+
+    /**
+     * For native crashes or explicit health check failures, call directly into each observer to
+     * mitigate the error without going through failure threshold logic.
+     */
+    @GuardedBy("sLock")
+    private void handleFailureImmediately(List<VersionedPackage> packages,
+            @FailureReasons int failureReason) {
+        VersionedPackage failingPackage = packages.size() > 0 ? packages.get(0) : null;
+        ObserverInternal currentObserverToNotify = null;
+        int currentObserverImpact = Integer.MAX_VALUE;
+        for (ObserverInternal observer: mAllObservers.values()) {
+            PackageHealthObserver registeredObserver = observer.registeredObserver;
+            if (registeredObserver != null) {
+                int impact = registeredObserver.onHealthCheckFailed(
+                        failingPackage, failureReason, 1);
+                if (impact != PackageHealthObserverImpact.USER_IMPACT_LEVEL_0
+                        && impact < currentObserverImpact) {
+                    currentObserverToNotify = observer;
+                    currentObserverImpact = impact;
+                }
+            }
+        }
+        if (currentObserverToNotify != null) {
+            maybeExecute(currentObserverToNotify, failingPackage, failureReason,
+                    currentObserverImpact, /*mitigationCount=*/ 1);
+        }
+    }
+
+    private void maybeExecute(ObserverInternal currentObserverToNotify,
+                              VersionedPackage versionedPackage,
+                              @FailureReasons int failureReason,
+                              int currentObserverImpact,
+                              int mitigationCount) {
+        if (allowMitigations(currentObserverImpact, versionedPackage)) {
+            PackageHealthObserver registeredObserver;
+            synchronized (sLock) {
+                mLastMitigation = mSystemClock.uptimeMillis();
+                registeredObserver = currentObserverToNotify.registeredObserver;
+            }
+            currentObserverToNotify.observerExecutor.execute(() ->
+                    registeredObserver.onExecuteHealthCheckMitigation(versionedPackage,
+                            failureReason, mitigationCount));
+        }
+    }
+
+    private boolean allowMitigations(int currentObserverImpact,
+            VersionedPackage versionedPackage) {
+        return currentObserverImpact < getUserImpactLevelLimit()
+                || getPackagesExemptFromImpactLevelThreshold().contains(
+                versionedPackage.getPackageName());
+    }
+
+    private long getMitigationWindowMs() {
+        return SystemProperties.getLong(MITIGATION_WINDOW_MS, DEFAULT_MITIGATION_WINDOW_MS);
+    }
+
+
+    /**
+     * Called when the system server boots. If the system server is detected to be in a boot loop,
+     * query each observer and perform the mitigation action with the lowest user impact.
+     *
+     * Note: PackageWatchdog considers system_server restart loop as bootloop. Full reboots
+     * are not counted in bootloop.
+     * @hide
+     */
+    @SuppressWarnings("GuardedBy")
+    public void noteBoot() {
+        synchronized (sLock) {
+            // if boot count has reached threshold, start mitigation.
+            // We wait until threshold number of restarts only for the first time. Perform
+            // mitigations for every restart after that.
+            boolean mitigate = mBootThreshold.incrementAndTest();
+            if (mitigate) {
+                int mitigationCount = mBootThreshold.getMitigationCount() + 1;
+                ObserverInternal currentObserverToNotify = null;
+                int currentObserverImpact = Integer.MAX_VALUE;
+                for (int i = 0; i < mAllObservers.size(); i++) {
+                    final ObserverInternal observer = mAllObservers.valueAt(i);
+                    PackageHealthObserver registeredObserver = observer.registeredObserver;
+                    if (registeredObserver != null) {
+                        int impact = registeredObserver.onBootLoop(
+                                observer.getBootMitigationCount() + 1);
+                        if (impact != PackageHealthObserverImpact.USER_IMPACT_LEVEL_0
+                                && impact < currentObserverImpact) {
+                            currentObserverToNotify = observer;
+                            currentObserverImpact = impact;
+                        }
+                    }
+                }
+
+                if (currentObserverToNotify != null) {
+                    PackageHealthObserver registeredObserver =
+                            currentObserverToNotify.registeredObserver;
+                    int currentObserverMitigationCount =
+                            currentObserverToNotify.getBootMitigationCount() + 1;
+                    currentObserverToNotify.setBootMitigationCount(
+                            currentObserverMitigationCount);
+                    saveAllObserversBootMitigationCountToMetadata(METADATA_FILE);
+                    currentObserverToNotify.observerExecutor
+                            .execute(() -> registeredObserver.onExecuteBootLoopMitigation(
+                                    currentObserverMitigationCount));
+                }
+            }
+        }
+    }
+
+    // TODO(b/120598832): Optimize write? Maybe only write a separate smaller file? Also
+    // avoid holding lock?
+    // This currently adds about 7ms extra to shutdown thread
+    /** @hide Writes the package information to file during shutdown. */
+    public void writeNow() {
+        synchronized (sLock) {
+            // Must only run synchronous tasks as this runs on the ShutdownThread and no other
+            // thread is guaranteed to run during shutdown.
+            if (!mAllObservers.isEmpty()) {
+                mLongTaskHandler.removeCallbacks(mSaveToFile);
+                pruneObserversLocked();
+                saveToFile();
+                Slog.i(TAG, "Last write to update package durations");
+            }
+        }
+    }
+
+    /**
+     * Enables or disables explicit health checks.
+     * <p> If explicit health checks are enabled, the health check service is started.
+     * <p> If explicit health checks are disabled, pending explicit health check requests are
+     * passed and the health check service is stopped.
+     */
+    private void setExplicitHealthCheckEnabled(boolean enabled) {
+        synchronized (sLock) {
+            mIsHealthCheckEnabled = enabled;
+            mHealthCheckController.setEnabled(enabled);
+            mSyncRequired = true;
+            // Prune to update internal state whenever health check is enabled/disabled
+            syncState("health check state " + (enabled ? "enabled" : "disabled"));
+        }
+    }
+
+    /**
+     * This method should be only called on mShortTaskHandler, since it modifies
+     * {@link #mNumberOfNativeCrashPollsRemaining}.
+     */
+    private void checkAndMitigateNativeCrashes() {
+        mNumberOfNativeCrashPollsRemaining--;
+        // Check if native watchdog reported a crash
+        if ("1".equals(SystemProperties.get("sys.init.updatable_crashing"))) {
+            // We rollback all available low impact rollbacks when crash is unattributable
+            notifyPackageFailure(Collections.EMPTY_LIST, FAILURE_REASON_NATIVE_CRASH);
+            // we stop polling after an attempt to execute rollback, regardless of whether the
+            // attempt succeeds or not
+        } else {
+            if (mNumberOfNativeCrashPollsRemaining > 0) {
+                mShortTaskHandler.postDelayed(() -> checkAndMitigateNativeCrashes(),
+                        NATIVE_CRASH_POLLING_INTERVAL_MILLIS);
+            }
+        }
+    }
+
+    /**
+     * Since this method can eventually trigger a rollback, it should be called
+     * only once boot has completed {@code onBootCompleted} and not earlier, because the install
+     * session must be entirely completed before we try to rollback.
+     * @hide
+     */
+    public void scheduleCheckAndMitigateNativeCrashes() {
+        Slog.i(TAG, "Scheduling " + mNumberOfNativeCrashPollsRemaining + " polls to check "
+                + "and mitigate native crashes");
+        mShortTaskHandler.post(()->checkAndMitigateNativeCrashes());
+    }
+
+    private int getUserImpactLevelLimit() {
+        return SystemProperties.getInt(MAJOR_USER_IMPACT_LEVEL_THRESHOLD,
+                DEFAULT_MAJOR_USER_IMPACT_LEVEL_THRESHOLD);
+    }
+
+    private Set<String> getPackagesExemptFromImpactLevelThreshold() {
+        if (mPackagesExemptFromImpactLevelThreshold.isEmpty()) {
+            String packageNames = SystemProperties.get(PACKAGES_EXEMPT_FROM_IMPACT_LEVEL_THRESHOLD,
+                    DEFAULT_PACKAGES_EXEMPT_FROM_IMPACT_LEVEL_THRESHOLD);
+            return Set.of(packageNames.split("\\s*,\\s*"));
+        }
+        return mPackagesExemptFromImpactLevelThreshold;
+    }
+
+    /**
+     * Indicates that a mitigation was successfully triggered or executed during
+     * {@link PackageHealthObserver#onExecuteHealthCheckMitigation} or
+     * {@link PackageHealthObserver#onExecuteBootLoopMitigation}.
+     */
+    public static final int MITIGATION_RESULT_SUCCESS =
+            ObserverMitigationResult.MITIGATION_RESULT_SUCCESS;
+
+    /**
+     * Indicates that a mitigation executed during
+     * {@link PackageHealthObserver#onExecuteHealthCheckMitigation} or
+     * {@link PackageHealthObserver#onExecuteBootLoopMitigation} was skipped.
+     */
+    public static final int MITIGATION_RESULT_SKIPPED =
+            ObserverMitigationResult.MITIGATION_RESULT_SKIPPED;
+
+
+    /**
+     * Possible return values of the for mitigations executed during
+     * {@link PackageHealthObserver#onExecuteHealthCheckMitigation} and
+     * {@link PackageHealthObserver#onExecuteBootLoopMitigation}.
+     * @hide
+     */
+    @Retention(SOURCE)
+    @IntDef(prefix = "MITIGATION_RESULT_", value = {
+            ObserverMitigationResult.MITIGATION_RESULT_SUCCESS,
+            ObserverMitigationResult.MITIGATION_RESULT_SKIPPED,
+            })
+    public @interface ObserverMitigationResult {
+        int MITIGATION_RESULT_SUCCESS = 1;
+        int MITIGATION_RESULT_SKIPPED = 2;
+    }
+
+    /**
+     * The minimum value that can be returned by any observer.
+     * It represents that no mitigations were available.
+     */
+    public static final int USER_IMPACT_THRESHOLD_NONE =
+            PackageHealthObserverImpact.USER_IMPACT_LEVEL_0;
+
+    /**
+     * The mitigation impact beyond which the user will start noticing the mitigations.
+     */
+    public static final int USER_IMPACT_THRESHOLD_MEDIUM =
+            PackageHealthObserverImpact.USER_IMPACT_LEVEL_20;
+
+    /**
+     * The mitigation impact beyond which the user impact is severely high.
+     */
+    public static final int USER_IMPACT_THRESHOLD_HIGH =
+            PackageHealthObserverImpact.USER_IMPACT_LEVEL_71;
+
+    /**
+     * Possible severity values of the user impact of a
+     * {@link PackageHealthObserver#onExecuteHealthCheckMitigation}.
+     * @hide
+     */
+    @Retention(SOURCE)
+    @IntDef(value = {PackageHealthObserverImpact.USER_IMPACT_LEVEL_0,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_10,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_20,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_30,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_40,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_50,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_70,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_71,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_75,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_80,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_90,
+                     PackageHealthObserverImpact.USER_IMPACT_LEVEL_100})
+    public @interface PackageHealthObserverImpact {
+        /** No action to take. */
+        int USER_IMPACT_LEVEL_0 = 0;
+        /* Action has low user impact, user of a device will barely notice. */
+        int USER_IMPACT_LEVEL_10 = 10;
+        /* Actions having medium user impact, user of a device will likely notice. */
+        int USER_IMPACT_LEVEL_20 = 20;
+        int USER_IMPACT_LEVEL_30 = 30;
+        int USER_IMPACT_LEVEL_40 = 40;
+        int USER_IMPACT_LEVEL_50 = 50;
+        int USER_IMPACT_LEVEL_70 = 70;
+        /* Action has high user impact, a last resort, user of a device will be very frustrated. */
+        int USER_IMPACT_LEVEL_71 = 71;
+        int USER_IMPACT_LEVEL_75 = 75;
+        int USER_IMPACT_LEVEL_80 = 80;
+        int USER_IMPACT_LEVEL_90 = 90;
+        int USER_IMPACT_LEVEL_100 = 100;
+    }
+
+    /** Register instances of this interface to receive notifications on package failure. */
+    @SuppressLint({"CallbackName"})
+    public interface PackageHealthObserver {
+        /**
+         * Called when health check fails for the {@code versionedPackage}.
+         * Note: if the returned user impact is higher than {@link #USER_IMPACT_THRESHOLD_HIGH},
+         * then {@link #onExecuteHealthCheckMitigation} would be called only in severe device
+         * conditions like boot-loop or network failure.
+         *
+         * @param versionedPackage the package that is failing. This may be null if a native
+         *                          service is crashing.
+         * @param failureReason   the type of failure that is occurring.
+         * @param mitigationCount the number of times mitigation has been called for this package
+         *                        (including this time).
+         *
+         * @return any value greater than {@link #USER_IMPACT_THRESHOLD_NONE} to express
+         * the impact of mitigation on the user in {@link #onExecuteHealthCheckMitigation}.
+         * Returning {@link #USER_IMPACT_THRESHOLD_NONE} would indicate no mitigations available.
+         */
+        @PackageHealthObserverImpact int onHealthCheckFailed(
+                @Nullable VersionedPackage versionedPackage,
+                @FailureReasons int failureReason,
+                int mitigationCount);
+
+        /**
+         * This would be called after {@link #onHealthCheckFailed}.
+         * This is called only if current observer returned least impact mitigation for failed
+         * health check.
+         *
+         * @param versionedPackage the package that is failing. This may be null if a native
+         *                         service is crashing.
+         * @param failureReason    the type of failure that is occurring.
+         * @param mitigationCount the number of times mitigation has been called for this package
+         *                         (including this time).
+         * @return {@link #MITIGATION_RESULT_SUCCESS} if the mitigation was successful,
+         *         or {@link #MITIGATION_RESULT_SKIPPED} if the mitigation was skipped.
+         */
+        @ObserverMitigationResult int onExecuteHealthCheckMitigation(
+                @Nullable VersionedPackage versionedPackage,
+                @FailureReasons int failureReason, int mitigationCount);
+
+
+        /**
+         * Called when the system server has booted several times within a window of time, defined
+         * by {@link #mBootThreshold}
+         *
+         * @param mitigationCount the number of times mitigation has been attempted for this
+         *                        boot loop (including this time).
+         *
+         * @return any value greater than {@link #USER_IMPACT_THRESHOLD_NONE} to express
+         * the impact of mitigation on the user in {@link #onExecuteBootLoopMitigation}.
+         * Returning {@link #USER_IMPACT_THRESHOLD_NONE} would indicate no mitigations available.
+         */
+        default @PackageHealthObserverImpact int onBootLoop(int mitigationCount) {
+            return PackageHealthObserverImpact.USER_IMPACT_LEVEL_0;
+        }
+
+        /**
+         * This would be called after {@link #onBootLoop}.
+         * This is called only if current observer returned least impact mitigation for fixing
+         * boot loop.
+         *
+         * @param mitigationCount the number of times mitigation has been attempted for this
+         *                        boot loop (including this time).
+         *
+         * @return {@link #MITIGATION_RESULT_SUCCESS} if the mitigation was successful,
+         *         or {@link #MITIGATION_RESULT_SKIPPED} if the mitigation was skipped.
+         */
+        default @ObserverMitigationResult int onExecuteBootLoopMitigation(int mitigationCount) {
+            return ObserverMitigationResult.MITIGATION_RESULT_SKIPPED;
+        }
+
+        // TODO(b/120598832): Ensure uniqueness?
+        /**
+         * Identifier for the observer, should not change across device updates otherwise the
+         * watchdog may drop observing packages with the old name.
+         */
+        @NonNull String getUniqueIdentifier();
+
+        /**
+         * An observer will not be pruned if this is set, even if the observer is not explicitly
+         * monitoring any packages.
+         */
+        default boolean isPersistent() {
+            return false;
+        }
+
+        /**
+         * Returns {@code true} if this observer wishes to observe the given package, {@code false}
+         * otherwise.
+         * Any failing package can be passed on to the observer. Currently the packages that have
+         * ANRs and perform {@link android.service.watchdog.ExplicitHealthCheckService} are being
+         * passed to observers in these API.
+         *
+         * <p> A persistent observer may choose to start observing certain failing packages, even if
+         * it has not explicitly asked to watch the package with {@link #startExplicitHealthCheck}.
+         */
+        default boolean mayObservePackage(@NonNull String packageName) {
+            return false;
+        }
+    }
+
+    @VisibleForTesting
+    long getTriggerFailureCount() {
+        synchronized (sLock) {
+            return mTriggerFailureCount;
+        }
+    }
+
+    @VisibleForTesting
+    long getTriggerFailureDurationMs() {
+        synchronized (sLock) {
+            return mTriggerFailureDurationMs;
+        }
+    }
+
+    /**
+     * Serializes and syncs health check requests with the {@link ExplicitHealthCheckController}.
+     */
+    private void syncRequestsAsync() {
+        mShortTaskHandler.removeCallbacks(mSyncRequests);
+        mShortTaskHandler.post(mSyncRequests);
+    }
+
+    /**
+     * Syncs health check requests with the {@link ExplicitHealthCheckController}.
+     * Calls to this must be serialized.
+     *
+     * @see #syncRequestsAsync
+     */
+    private void syncRequests() {
+        boolean syncRequired = false;
+        synchronized (sLock) {
+            if (mIsPackagesReady) {
+                Set<String> packages = getPackagesPendingHealthChecksLocked();
+                if (mSyncRequired || !packages.equals(mRequestedHealthCheckPackages)
+                        || packages.isEmpty()) {
+                    syncRequired = true;
+                    mRequestedHealthCheckPackages = packages;
+                }
+            } // else, we will sync requests when packages become ready
+        }
+
+        // Call outside lock to avoid holding lock when calling into the controller.
+        if (syncRequired) {
+            Slog.i(TAG, "Syncing health check requests for packages: "
+                    + mRequestedHealthCheckPackages);
+            mHealthCheckController.syncRequests(mRequestedHealthCheckPackages);
+            mSyncRequired = false;
+        }
+    }
+
+    /**
+     * Updates the observers monitoring {@code packageName} that explicit health check has passed.
+     *
+     * <p> This update is strictly for registered observers at the time of the call
+     * Observers that register after this signal will have no knowledge of prior signals and will
+     * effectively behave as if the explicit health check hasn't passed for {@code packageName}.
+     *
+     * <p> {@code packageName} can still be considered failed if reported by
+     * {@link #notifyPackageFailureLocked} before the package expires.
+     *
+     * <p> Triggered by components outside the system server when they are fully functional after an
+     * update.
+     */
+    private void onHealthCheckPassed(String packageName) {
+        Slog.i(TAG, "Health check passed for package: " + packageName);
+        boolean isStateChanged = false;
+
+        synchronized (sLock) {
+            for (int observerIdx = 0; observerIdx < mAllObservers.size(); observerIdx++) {
+                ObserverInternal observer = mAllObservers.valueAt(observerIdx);
+                MonitoredPackage monitoredPackage = observer.getMonitoredPackage(packageName);
+
+                if (monitoredPackage != null) {
+                    int oldState = monitoredPackage.getHealthCheckStateLocked();
+                    int newState = monitoredPackage.tryPassHealthCheckLocked();
+                    isStateChanged |= oldState != newState;
+                }
+            }
+        }
+
+        if (isStateChanged) {
+            syncState("health check passed for " + packageName);
+        }
+    }
+
+    private void onSupportedPackages(List<PackageConfig> supportedPackages) {
+        boolean isStateChanged = false;
+
+        Map<String, Long> supportedPackageTimeouts = new ArrayMap<>();
+        Iterator<PackageConfig> it = supportedPackages.iterator();
+        while (it.hasNext()) {
+            PackageConfig info = it.next();
+            supportedPackageTimeouts.put(info.getPackageName(), info.getHealthCheckTimeoutMillis());
+        }
+
+        synchronized (sLock) {
+            Slog.d(TAG, "Received supported packages " + supportedPackages);
+            Iterator<ObserverInternal> oit = mAllObservers.values().iterator();
+            while (oit.hasNext()) {
+                Iterator<MonitoredPackage> pit = oit.next().getMonitoredPackages()
+                        .values().iterator();
+                while (pit.hasNext()) {
+                    MonitoredPackage monitoredPackage = pit.next();
+                    String packageName = monitoredPackage.getName();
+                    int oldState = monitoredPackage.getHealthCheckStateLocked();
+                    int newState;
+
+                    if (supportedPackageTimeouts.containsKey(packageName)) {
+                        // Supported packages become ACTIVE if currently INACTIVE
+                        newState = monitoredPackage.setHealthCheckActiveLocked(
+                                supportedPackageTimeouts.get(packageName));
+                    } else {
+                        // Unsupported packages are marked as PASSED unless already FAILED
+                        newState = monitoredPackage.tryPassHealthCheckLocked();
+                    }
+                    isStateChanged |= oldState != newState;
+                }
+            }
+        }
+
+        if (isStateChanged) {
+            syncState("updated health check supported packages " + supportedPackages);
+        }
+    }
+
+    private void onSyncRequestNotified() {
+        synchronized (sLock) {
+            mSyncRequired = true;
+            syncRequestsAsync();
+        }
+    }
+
+    @GuardedBy("sLock")
+    private Set<String> getPackagesPendingHealthChecksLocked() {
+        Set<String> packages = new ArraySet<>();
+        Iterator<ObserverInternal> oit = mAllObservers.values().iterator();
+        while (oit.hasNext()) {
+            ObserverInternal observer = oit.next();
+            Iterator<MonitoredPackage> pit =
+                    observer.getMonitoredPackages().values().iterator();
+            while (pit.hasNext()) {
+                MonitoredPackage monitoredPackage = pit.next();
+                String packageName = monitoredPackage.getName();
+                if (monitoredPackage.isPendingHealthChecksLocked()) {
+                    packages.add(packageName);
+                }
+            }
+        }
+        return packages;
+    }
+
+    /**
+     * Syncs the state of the observers.
+     *
+     * <p> Prunes all observers, saves new state to disk, syncs health check requests with the
+     * health check service and schedules the next state sync.
+     */
+    private void syncState(String reason) {
+        synchronized (sLock) {
+            Slog.i(TAG, "Syncing state, reason: " + reason);
+            pruneObserversLocked();
+
+            saveToFileAsync();
+            syncRequestsAsync();
+
+            // Done syncing state, schedule the next state sync
+            scheduleNextSyncStateLocked();
+        }
+    }
+
+    private void syncStateWithScheduledReason() {
+        syncState("scheduled");
+    }
+
+    @GuardedBy("sLock")
+    private void scheduleNextSyncStateLocked() {
+        long durationMs = getNextStateSyncMillisLocked();
+        mShortTaskHandler.removeCallbacks(mSyncStateWithScheduledReason);
+        if (durationMs == Long.MAX_VALUE) {
+            Slog.i(TAG, "Cancelling state sync, nothing to sync");
+            mUptimeAtLastStateSync = 0;
+        } else {
+            mUptimeAtLastStateSync = mSystemClock.uptimeMillis();
+            mShortTaskHandler.postDelayed(mSyncStateWithScheduledReason, durationMs);
+        }
+    }
+
+    /**
+     * Returns the next duration in millis to sync the watchdog state.
+     *
+     * @returns Long#MAX_VALUE if there are no observed packages.
+     */
+    @GuardedBy("sLock")
+    private long getNextStateSyncMillisLocked() {
+        long shortestDurationMs = Long.MAX_VALUE;
+        for (int oIndex = 0; oIndex < mAllObservers.size(); oIndex++) {
+            ArrayMap<String, MonitoredPackage> packages = mAllObservers.valueAt(oIndex)
+                    .getMonitoredPackages();
+            for (int pIndex = 0; pIndex < packages.size(); pIndex++) {
+                MonitoredPackage mp = packages.valueAt(pIndex);
+                long duration = mp.getShortestScheduleDurationMsLocked();
+                if (duration < shortestDurationMs) {
+                    shortestDurationMs = duration;
+                }
+            }
+        }
+        return shortestDurationMs;
+    }
+
+    /**
+     * Removes {@code elapsedMs} milliseconds from all durations on monitored packages
+     * and updates other internal state.
+     */
+    @GuardedBy("sLock")
+    private void pruneObserversLocked() {
+        long elapsedMs = mUptimeAtLastStateSync == 0
+                ? 0 : mSystemClock.uptimeMillis() - mUptimeAtLastStateSync;
+        if (elapsedMs <= 0) {
+            Slog.i(TAG, "Not pruning observers, elapsed time: " + elapsedMs + "ms");
+            return;
+        }
+
+        Iterator<ObserverInternal> it = mAllObservers.values().iterator();
+        while (it.hasNext()) {
+            ObserverInternal observer = it.next();
+            Set<MonitoredPackage> failedPackages =
+                    observer.prunePackagesLocked(elapsedMs);
+            if (!failedPackages.isEmpty()) {
+                onHealthCheckFailed(observer, failedPackages);
+            }
+            if (observer.getMonitoredPackages().isEmpty() && (observer.registeredObserver == null
+                    || !observer.registeredObserver.isPersistent())) {
+                Slog.i(TAG, "Discarding observer " + observer.name + ". All packages expired");
+                it.remove();
+            }
+        }
+    }
+
+    private void onHealthCheckFailed(ObserverInternal observer,
+            Set<MonitoredPackage> failedPackages) {
+        mLongTaskHandler.post(() -> {
+            synchronized (sLock) {
+                PackageHealthObserver registeredObserver = observer.registeredObserver;
+                if (registeredObserver != null) {
+                    Iterator<MonitoredPackage> it = failedPackages.iterator();
+                    while (it.hasNext()) {
+                        VersionedPackage versionedPkg = getVersionedPackage(it.next().getName());
+                        if (versionedPkg != null) {
+                            Slog.i(TAG,
+                                    "Explicit health check failed for package " + versionedPkg);
+                            observer.observerExecutor.execute(() ->
+                                    registeredObserver.onExecuteHealthCheckMitigation(versionedPkg,
+                                            PackageWatchdog.FAILURE_REASON_EXPLICIT_HEALTH_CHECK,
+                                            1));
+                        }
+                    }
+                }
+            }
+        });
+    }
+
+    /**
+     * Gets PackageInfo for the given package. Matches any user and apex.
+     *
+     * @throws PackageManager.NameNotFoundException if no such package is installed.
+     */
+    private PackageInfo getPackageInfo(String packageName)
+            throws PackageManager.NameNotFoundException {
+        PackageManager pm = mContext.getPackageManager();
+        try {
+            // The MATCH_ANY_USER flag doesn't mix well with the MATCH_APEX
+            // flag, so make two separate attempts to get the package info.
+            // We don't need both flags at the same time because we assume
+            // apex files are always installed for all users.
+            return pm.getPackageInfo(packageName, PackageManager.MATCH_ANY_USER);
+        } catch (PackageManager.NameNotFoundException e) {
+            return pm.getPackageInfo(packageName, PackageManager.MATCH_APEX);
+        }
+    }
+
+    @Nullable
+    private VersionedPackage getVersionedPackage(String packageName) {
+        final PackageManager pm = mContext.getPackageManager();
+        if (pm == null || TextUtils.isEmpty(packageName)) {
+            return null;
+        }
+        try {
+            final long versionCode = getPackageInfo(packageName).getLongVersionCode();
+            return new VersionedPackage(packageName, versionCode);
+        } catch (PackageManager.NameNotFoundException e) {
+            return null;
+        }
+    }
+
+    /**
+     * Loads mAllObservers from file.
+     *
+     * <p>Note that this is <b>not</b> thread safe and should only called be called
+     * from the constructor.
+     */
+    private void loadFromFile() {
+        InputStream infile = null;
+        mAllObservers.clear();
+        try {
+            infile = mPolicyFile.openRead();
+            final XmlPullParser parser = Xml.newPullParser();
+            parser.setInput(infile, UTF_8.name());
+            XmlUtils.beginDocument(parser, TAG_PACKAGE_WATCHDOG);
+            int outerDepth = parser.getDepth();
+            while (XmlUtils.nextElementWithin(parser, outerDepth)) {
+                ObserverInternal observer = ObserverInternal.read(parser, this);
+                if (observer != null) {
+                    mAllObservers.put(observer.name, observer);
+                }
+            }
+        } catch (FileNotFoundException e) {
+            // Nothing to monitor
+        } catch (Exception e) {
+            Slog.wtf(TAG, "Unable to read monitored packages, deleting file", e);
+            mPolicyFile.delete();
+        } finally {
+            IoUtils.closeQuietly(infile);
+        }
+    }
+
+    private void onPropertyChanged(DeviceConfig.Properties properties) {
+        try {
+            updateConfigs();
+        } catch (Exception ignore) {
+            Slog.w(TAG, "Failed to reload device config changes");
+        }
+    }
+
+    /** Adds a {@link DeviceConfig#OnPropertiesChangedListener}. */
+    private void setPropertyChangedListenerLocked() {
+        DeviceConfig.addOnPropertiesChangedListener(
+                DeviceConfig.NAMESPACE_ROLLBACK,
+                mContext.getMainExecutor(),
+                mOnPropertyChangedListener);
+    }
+
+    @VisibleForTesting
+    void removePropertyChangedListener() {
+        DeviceConfig.removeOnPropertiesChangedListener(mOnPropertyChangedListener);
+    }
+
+    /**
+     * Health check is enabled or disabled after reading the flags
+     * from DeviceConfig.
+     */
+    @VisibleForTesting
+    void updateConfigs() {
+        synchronized (sLock) {
+            mTriggerFailureCount = DeviceConfig.getInt(
+                    DeviceConfig.NAMESPACE_ROLLBACK,
+                    PROPERTY_WATCHDOG_TRIGGER_FAILURE_COUNT,
+                    DEFAULT_TRIGGER_FAILURE_COUNT);
+            if (mTriggerFailureCount <= 0) {
+                mTriggerFailureCount = DEFAULT_TRIGGER_FAILURE_COUNT;
+            }
+
+            mTriggerFailureDurationMs = DeviceConfig.getInt(
+                    DeviceConfig.NAMESPACE_ROLLBACK,
+                    PROPERTY_WATCHDOG_TRIGGER_DURATION_MILLIS,
+                    DEFAULT_TRIGGER_FAILURE_DURATION_MS);
+            if (mTriggerFailureDurationMs <= 0) {
+                mTriggerFailureDurationMs = DEFAULT_TRIGGER_FAILURE_DURATION_MS;
+            }
+
+            setExplicitHealthCheckEnabled(DeviceConfig.getBoolean(
+                    DeviceConfig.NAMESPACE_ROLLBACK,
+                    PROPERTY_WATCHDOG_EXPLICIT_HEALTH_CHECK_ENABLED,
+                    DEFAULT_EXPLICIT_HEALTH_CHECK_ENABLED));
+        }
+    }
+
+    /**
+     * Persists mAllObservers to file. Threshold information is ignored.
+     */
+    private boolean saveToFile() {
+        Slog.i(TAG, "Saving observer state to file");
+        synchronized (sLock) {
+            FileOutputStream stream;
+            try {
+                stream = mPolicyFile.startWrite();
+            } catch (IOException e) {
+                Slog.w(TAG, "Cannot update monitored packages", e);
+                return false;
+            }
+
+            try {
+                XmlSerializer out = new FastXmlSerializer();
+                out.setOutput(stream, UTF_8.name());
+                out.startDocument(null, true);
+                out.startTag(null, TAG_PACKAGE_WATCHDOG);
+                out.attribute(null, ATTR_VERSION, Integer.toString(DB_VERSION));
+                for (int oIndex = 0; oIndex < mAllObservers.size(); oIndex++) {
+                    mAllObservers.valueAt(oIndex).writeLocked(out);
+                }
+                out.endTag(null, TAG_PACKAGE_WATCHDOG);
+                out.endDocument();
+                mPolicyFile.finishWrite(stream);
+                return true;
+            } catch (IOException e) {
+                Slog.w(TAG, "Failed to save monitored packages, restoring backup", e);
+                mPolicyFile.failWrite(stream);
+                return false;
+            }
+        }
+    }
+
+    private void saveToFileAsync() {
+        if (!mLongTaskHandler.hasCallbacks(mSaveToFile)) {
+            mLongTaskHandler.post(mSaveToFile);
+        }
+    }
+
+    /** @hide Convert a {@code LongArrayQueue} to a String of comma-separated values. */
+    public static String longArrayQueueToString(LongArrayQueue queue) {
+        if (queue.size() > 0) {
+            StringBuilder sb = new StringBuilder();
+            sb.append(queue.get(0));
+            for (int i = 1; i < queue.size(); i++) {
+                sb.append(",");
+                sb.append(queue.get(i));
+            }
+            return sb.toString();
+        }
+        return "";
+    }
+
+    /** @hide Parse a comma-separated String of longs into a LongArrayQueue. */
+    public static LongArrayQueue parseLongArrayQueue(String commaSeparatedValues) {
+        LongArrayQueue result = new LongArrayQueue();
+        if (!TextUtils.isEmpty(commaSeparatedValues)) {
+            String[] values = commaSeparatedValues.split(",");
+            for (String value : values) {
+                result.addLast(Long.parseLong(value));
+            }
+        }
+        return result;
+    }
+
+
+    /** Dump status of every observer in mAllObservers. */
+    public void dump(@NonNull PrintWriter pw) {
+        if (Flags.synchronousRebootInRescueParty() && isRecoveryTriggeredReboot()) {
+            dumpInternal(pw);
+        } else {
+            synchronized (sLock) {
+                dumpInternal(pw);
+            }
+        }
+    }
+
+    /**
+     * Check if we're currently attempting to reboot during mitigation. This method must return
+     * true if triggered reboot early during a boot loop, since the device will not be fully booted
+     * at this time.
+     */
+    public static boolean isRecoveryTriggeredReboot() {
+        return isFactoryResetPropertySet() || isRebootPropertySet();
+    }
+
+    private static boolean isFactoryResetPropertySet() {
+        return CrashRecoveryProperties.attemptingFactoryReset().orElse(false);
+    }
+
+    private static boolean isRebootPropertySet() {
+        return CrashRecoveryProperties.attemptingReboot().orElse(false);
+    }
+
+    private void dumpInternal(@NonNull PrintWriter pw) {
+        IndentingPrintWriter ipw = new IndentingPrintWriter(pw, "  ");
+        ipw.println("Package Watchdog status");
+        ipw.increaseIndent();
+        synchronized (sLock) {
+            for (String observerName : mAllObservers.keySet()) {
+                ipw.println("Observer name: " + observerName);
+                ipw.increaseIndent();
+                ObserverInternal observerInternal = mAllObservers.get(observerName);
+                observerInternal.dump(ipw);
+                ipw.decreaseIndent();
+            }
+        }
+        ipw.decreaseIndent();
+        dumpCrashRecoveryEvents(ipw);
+    }
+
+    @VisibleForTesting
+    @GuardedBy("sLock")
+    void registerObserverInternal(ObserverInternal observerInternal) {
+        mAllObservers.put(observerInternal.name, observerInternal);
+    }
+
+    /**
+     * Represents an observer monitoring a set of packages along with the failure thresholds for
+     * each package.
+     *
+     * <p> Note, the PackageWatchdog#sLock must always be held when reading or writing
+     * instances of this class.
+     */
+    static class ObserverInternal {
+        public final String name;
+        @GuardedBy("sLock")
+        private final ArrayMap<String, MonitoredPackage> mPackages = new ArrayMap<>();
+        @Nullable
+        @GuardedBy("sLock")
+        public PackageHealthObserver registeredObserver;
+        public Executor observerExecutor;
+        private int mMitigationCount;
+
+        ObserverInternal(String name, List<MonitoredPackage> packages) {
+            this(name, packages, /*mitigationCount=*/ 0);
+        }
+
+        ObserverInternal(String name, List<MonitoredPackage> packages, int mitigationCount) {
+            this.name = name;
+            updatePackagesLocked(packages);
+            this.mMitigationCount = mitigationCount;
+        }
+
+        /**
+         * Writes important {@link MonitoredPackage} details for this observer to file.
+         * Does not persist any package failure thresholds.
+         */
+        @GuardedBy("sLock")
+        public boolean writeLocked(XmlSerializer out) {
+            try {
+                out.startTag(null, TAG_OBSERVER);
+                out.attribute(null, ATTR_NAME, name);
+                out.attribute(null, ATTR_MITIGATION_COUNT, Integer.toString(mMitigationCount));
+                for (int i = 0; i < mPackages.size(); i++) {
+                    MonitoredPackage p = mPackages.valueAt(i);
+                    p.writeLocked(out);
+                }
+                out.endTag(null, TAG_OBSERVER);
+                return true;
+            } catch (IOException e) {
+                Slog.w(TAG, "Cannot save observer", e);
+                return false;
+            }
+        }
+
+        public int getBootMitigationCount() {
+            return mMitigationCount;
+        }
+
+        public void setBootMitigationCount(int mitigationCount) {
+            mMitigationCount = mitigationCount;
+        }
+
+        @GuardedBy("sLock")
+        public void updatePackagesLocked(List<MonitoredPackage> packages) {
+            for (int pIndex = 0; pIndex < packages.size(); pIndex++) {
+                MonitoredPackage p = packages.get(pIndex);
+                MonitoredPackage existingPackage = getMonitoredPackage(p.getName());
+                if (existingPackage != null) {
+                    existingPackage.updateHealthCheckDuration(p.mDurationMs);
+                } else {
+                    putMonitoredPackage(p);
+                }
+            }
+        }
+
+        /**
+         * Reduces the monitoring durations of all packages observed by this observer by
+         * {@code elapsedMs}. If any duration is less than 0, the package is removed from
+         * observation. If any health check duration is less than 0, the health check result
+         * is evaluated.
+         *
+         * @return a {@link Set} of packages that were removed from the observer without explicit
+         * health check passing, or an empty list if no package expired for which an explicit health
+         * check was still pending
+         */
+        @GuardedBy("sLock")
+        private Set<MonitoredPackage> prunePackagesLocked(long elapsedMs) {
+            Set<MonitoredPackage> failedPackages = new ArraySet<>();
+            Iterator<MonitoredPackage> it = mPackages.values().iterator();
+            while (it.hasNext()) {
+                MonitoredPackage p = it.next();
+                int oldState = p.getHealthCheckStateLocked();
+                int newState = p.handleElapsedTimeLocked(elapsedMs);
+                if (oldState != HealthCheckState.FAILED
+                        && newState == HealthCheckState.FAILED) {
+                    Slog.i(TAG, "Package " + p.getName() + " failed health check");
+                    failedPackages.add(p);
+                }
+                if (p.isExpiredLocked()) {
+                    it.remove();
+                }
+            }
+            return failedPackages;
+        }
+
+        /**
+         * Increments failure counts of {@code packageName}.
+         * @returns {@code true} if failure threshold is exceeded, {@code false} otherwise
+         * @hide
+         */
+        @GuardedBy("sLock")
+        public boolean notifyPackageFailureLocked(String packageName) {
+            if (getMonitoredPackage(packageName) == null && registeredObserver.isPersistent()
+                    && registeredObserver.mayObservePackage(packageName)) {
+                putMonitoredPackage(sPackageWatchdog.newMonitoredPackage(
+                        packageName, DEFAULT_OBSERVING_DURATION_MS, false));
+            }
+            MonitoredPackage p = getMonitoredPackage(packageName);
+            if (p != null) {
+                return p.onFailureLocked();
+            }
+            return false;
+        }
+
+        /**
+         * Returns the map of packages monitored by this observer.
+         *
+         * @return a mapping of package names to {@link MonitoredPackage} objects.
+         */
+        @GuardedBy("sLock")
+        public ArrayMap<String, MonitoredPackage> getMonitoredPackages() {
+            return mPackages;
+        }
+
+        /**
+         * Returns the {@link MonitoredPackage} associated with a given package name if the
+         * package is being monitored by this observer.
+         *
+         * @param packageName: the name of the package.
+         * @return the {@link MonitoredPackage} object associated with the package name if one
+         *         exists, {@code null} otherwise.
+         */
+        @GuardedBy("sLock")
+        @Nullable
+        public MonitoredPackage getMonitoredPackage(String packageName) {
+            return mPackages.get(packageName);
+        }
+
+        /**
+         * Associates a {@link MonitoredPackage} with the observer.
+         *
+         * @param p: the {@link MonitoredPackage} to store.
+         */
+        @GuardedBy("sLock")
+        public void putMonitoredPackage(MonitoredPackage p) {
+            mPackages.put(p.getName(), p);
+        }
+
+        /**
+         * Returns one ObserverInternal from the {@code parser} and advances its state.
+         *
+         * <p>Note that this method is <b>not</b> thread safe. It should only be called from
+         * #loadFromFile which in turn is only called on construction of the
+         * singleton PackageWatchdog.
+         **/
+        public static ObserverInternal read(XmlPullParser parser, PackageWatchdog watchdog) {
+            String observerName = null;
+            int observerMitigationCount = 0;
+            if (TAG_OBSERVER.equals(parser.getName())) {
+                observerName = parser.getAttributeValue(null, ATTR_NAME);
+                if (TextUtils.isEmpty(observerName)) {
+                    Slog.wtf(TAG, "Unable to read observer name");
+                    return null;
+                }
+            }
+            List<MonitoredPackage> packages = new ArrayList<>();
+            int innerDepth = parser.getDepth();
+            try {
+                try {
+                    observerMitigationCount = Integer.parseInt(
+                            parser.getAttributeValue(null, ATTR_MITIGATION_COUNT));
+                } catch (Exception e) {
+                    Slog.i(
+                        TAG,
+                        "ObserverInternal mitigation count was not present.");
+                }
+                while (XmlUtils.nextElementWithin(parser, innerDepth)) {
+                    if (TAG_PACKAGE.equals(parser.getName())) {
+                        try {
+                            MonitoredPackage pkg = watchdog.parseMonitoredPackage(parser);
+                            if (pkg != null) {
+                                packages.add(pkg);
+                            }
+                        } catch (NumberFormatException e) {
+                            Slog.wtf(TAG, "Skipping package for observer " + observerName, e);
+                            continue;
+                        }
+                    }
+                }
+            } catch (XmlPullParserException | IOException e) {
+                Slog.wtf(TAG, "Unable to read observer " + observerName, e);
+                return null;
+            }
+            if (packages.isEmpty()) {
+                return null;
+            }
+            return new ObserverInternal(observerName, packages, observerMitigationCount);
+        }
+
+        /** Dumps information about this observer and the packages it watches. */
+        public void dump(IndentingPrintWriter pw) {
+            boolean isPersistent = registeredObserver != null && registeredObserver.isPersistent();
+            pw.println("Persistent: " + isPersistent);
+            for (String packageName : mPackages.keySet()) {
+                MonitoredPackage p = getMonitoredPackage(packageName);
+                pw.println(packageName +  ": ");
+                pw.increaseIndent();
+                pw.println("# Failures: " + p.mFailureHistory.size());
+                pw.println("Monitoring duration remaining: " + p.mDurationMs + "ms");
+                pw.println("Explicit health check duration: " + p.mHealthCheckDurationMs + "ms");
+                pw.println("Health check state: " + p.toString(p.mHealthCheckState));
+                pw.decreaseIndent();
+            }
+        }
+    }
+
+    /** @hide */
+    @Retention(SOURCE)
+    @IntDef(value = {
+            HealthCheckState.ACTIVE,
+            HealthCheckState.INACTIVE,
+            HealthCheckState.PASSED,
+            HealthCheckState.FAILED})
+    public @interface HealthCheckState {
+        // The package has not passed health check but has requested a health check
+        int ACTIVE = 0;
+        // The package has not passed health check and has not requested a health check
+        int INACTIVE = 1;
+        // The package has passed health check
+        int PASSED = 2;
+        // The package has failed health check
+        int FAILED = 3;
+    }
+
+    MonitoredPackage newMonitoredPackage(
+            String name, long durationMs, boolean hasPassedHealthCheck) {
+        return newMonitoredPackage(name, durationMs, Long.MAX_VALUE, hasPassedHealthCheck,
+                new LongArrayQueue());
+    }
+
+    MonitoredPackage newMonitoredPackage(String name, long durationMs, long healthCheckDurationMs,
+            boolean hasPassedHealthCheck, LongArrayQueue mitigationCalls) {
+        return new MonitoredPackage(name, durationMs, healthCheckDurationMs,
+                hasPassedHealthCheck, mitigationCalls);
+    }
+
+    MonitoredPackage parseMonitoredPackage(XmlPullParser parser)
+            throws XmlPullParserException {
+        String packageName = parser.getAttributeValue(null, ATTR_NAME);
+        long duration = Long.parseLong(parser.getAttributeValue(null, ATTR_DURATION));
+        long healthCheckDuration = Long.parseLong(parser.getAttributeValue(null,
+                ATTR_EXPLICIT_HEALTH_CHECK_DURATION));
+        boolean hasPassedHealthCheck = Boolean.parseBoolean(parser.getAttributeValue(null,
+                ATTR_PASSED_HEALTH_CHECK));
+        LongArrayQueue mitigationCalls = parseLongArrayQueue(
+                parser.getAttributeValue(null, ATTR_MITIGATION_CALLS));
+        return newMonitoredPackage(packageName,
+                duration, healthCheckDuration, hasPassedHealthCheck, mitigationCalls);
+    }
+
+    /**
+     * Represents a package and its health check state along with the time
+     * it should be monitored for.
+     *
+     * <p> Note, the PackageWatchdog#sLock must always be held when reading or writing
+     * instances of this class.
+     */
+    class MonitoredPackage {
+        private final String mPackageName;
+        // Times when package failures happen sorted in ascending order
+        @GuardedBy("sLock")
+        private final LongArrayQueue mFailureHistory = new LongArrayQueue();
+        // Times when an observer was called to mitigate this package's failure. Sorted in
+        // ascending order.
+        @GuardedBy("sLock")
+        private final LongArrayQueue mMitigationCalls;
+        // One of STATE_[ACTIVE|INACTIVE|PASSED|FAILED]. Updated on construction and after
+        // methods that could change the health check state: handleElapsedTimeLocked and
+        // tryPassHealthCheckLocked
+        private int mHealthCheckState = HealthCheckState.INACTIVE;
+        // Whether an explicit health check has passed.
+        // This value in addition with mHealthCheckDurationMs determines the health check state
+        // of the package, see #getHealthCheckStateLocked
+        @GuardedBy("sLock")
+        private boolean mHasPassedHealthCheck;
+        // System uptime duration to monitor package.
+        @GuardedBy("sLock")
+        private long mDurationMs;
+        // System uptime duration to check the result of an explicit health check
+        // Initially, MAX_VALUE until we get a value from the health check service
+        // and request health checks.
+        // This value in addition with mHasPassedHealthCheck determines the health check state
+        // of the package, see #getHealthCheckStateLocked
+        @GuardedBy("sLock")
+        private long mHealthCheckDurationMs = Long.MAX_VALUE;
+
+        MonitoredPackage(String packageName, long durationMs,
+                long healthCheckDurationMs, boolean hasPassedHealthCheck,
+                LongArrayQueue mitigationCalls) {
+            mPackageName = packageName;
+            mDurationMs = durationMs;
+            mHealthCheckDurationMs = healthCheckDurationMs;
+            mHasPassedHealthCheck = hasPassedHealthCheck;
+            mMitigationCalls = mitigationCalls;
+            updateHealthCheckStateLocked();
+        }
+
+        /** Writes the salient fields to disk using {@code out}.
+         * @hide
+         */
+        @GuardedBy("sLock")
+        public void writeLocked(XmlSerializer out) throws IOException {
+            out.startTag(null, TAG_PACKAGE);
+            out.attribute(null, ATTR_NAME, getName());
+            out.attribute(null, ATTR_DURATION, Long.toString(mDurationMs));
+            out.attribute(null, ATTR_EXPLICIT_HEALTH_CHECK_DURATION,
+                    Long.toString(mHealthCheckDurationMs));
+            out.attribute(null, ATTR_PASSED_HEALTH_CHECK, Boolean.toString(mHasPassedHealthCheck));
+            LongArrayQueue normalizedCalls = normalizeMitigationCalls();
+            out.attribute(null, ATTR_MITIGATION_CALLS, longArrayQueueToString(normalizedCalls));
+            out.endTag(null, TAG_PACKAGE);
+        }
+
+        /**
+         * Increment package failures or resets failure count depending on the last package failure.
+         *
+         * @return {@code true} if failure count exceeds a threshold, {@code false} otherwise
+         */
+        @GuardedBy("sLock")
+        public boolean onFailureLocked() {
+            // Sliding window algorithm: find out if there exists a window containing failures >=
+            // mTriggerFailureCount.
+            final long now = mSystemClock.uptimeMillis();
+            mFailureHistory.addLast(now);
+            while (now - mFailureHistory.peekFirst() > mTriggerFailureDurationMs) {
+                // Prune values falling out of the window
+                mFailureHistory.removeFirst();
+            }
+            boolean failed = mFailureHistory.size() >= mTriggerFailureCount;
+            if (failed) {
+                mFailureHistory.clear();
+            }
+            return failed;
+        }
+
+        /**
+         * Notes the timestamp of a mitigation call into the observer.
+         */
+        @GuardedBy("sLock")
+        public void noteMitigationCallLocked() {
+            mMitigationCalls.addLast(mSystemClock.uptimeMillis());
+        }
+
+        /**
+         * Prunes any mitigation calls outside of the de-escalation window, and returns the
+         * number of calls that are in the window afterwards.
+         *
+         * @return the number of mitigation calls made in the de-escalation window.
+         */
+        @GuardedBy("sLock")
+        public int getMitigationCountLocked() {
+            try {
+                final long now = mSystemClock.uptimeMillis();
+                while (now - mMitigationCalls.peekFirst() > DEFAULT_DEESCALATION_WINDOW_MS) {
+                    mMitigationCalls.removeFirst();
+                }
+            } catch (NoSuchElementException ignore) {
+            }
+
+            return mMitigationCalls.size();
+        }
+
+        /**
+         * Before writing to disk, make the mitigation call timestamps relative to the current
+         * system uptime. This is because they need to be relative to the uptime which will reset
+         * at the next boot.
+         *
+         * @return a LongArrayQueue of the mitigation calls relative to the current system uptime.
+         */
+        @GuardedBy("sLock")
+        public LongArrayQueue normalizeMitigationCalls() {
+            LongArrayQueue normalized = new LongArrayQueue();
+            final long now = mSystemClock.uptimeMillis();
+            for (int i = 0; i < mMitigationCalls.size(); i++) {
+                normalized.addLast(mMitigationCalls.get(i) - now);
+            }
+            return normalized;
+        }
+
+        /**
+         * Sets the initial health check duration.
+         *
+         * @return the new health check state
+         */
+        @GuardedBy("sLock")
+        public int setHealthCheckActiveLocked(long initialHealthCheckDurationMs) {
+            if (initialHealthCheckDurationMs <= 0) {
+                Slog.wtf(TAG, "Cannot set non-positive health check duration "
+                        + initialHealthCheckDurationMs + "ms for package " + getName()
+                        + ". Using total duration " + mDurationMs + "ms instead");
+                initialHealthCheckDurationMs = mDurationMs;
+            }
+            if (mHealthCheckState == HealthCheckState.INACTIVE) {
+                // Transitions to ACTIVE
+                mHealthCheckDurationMs = initialHealthCheckDurationMs;
+            }
+            return updateHealthCheckStateLocked();
+        }
+
+        /**
+         * Updates the monitoring durations of the package.
+         *
+         * @return the new health check state
+         */
+        @GuardedBy("sLock")
+        public int handleElapsedTimeLocked(long elapsedMs) {
+            if (elapsedMs <= 0) {
+                Slog.w(TAG, "Cannot handle non-positive elapsed time for package " + getName());
+                return mHealthCheckState;
+            }
+            // Transitions to FAILED if now <= 0 and health check not passed
+            mDurationMs -= elapsedMs;
+            if (mHealthCheckState == HealthCheckState.ACTIVE) {
+                // We only update health check durations if we have #setHealthCheckActiveLocked
+                // This ensures we don't leave the INACTIVE state for an unexpected elapsed time
+                // Transitions to FAILED if now <= 0 and health check not passed
+                mHealthCheckDurationMs -= elapsedMs;
+            }
+            return updateHealthCheckStateLocked();
+        }
+
+        /** Explicitly update the monitoring duration of the package. */
+        @GuardedBy("sLock")
+        public void updateHealthCheckDuration(long newDurationMs) {
+            mDurationMs = newDurationMs;
+        }
+
+        /**
+         * Marks the health check as passed and transitions to {@link HealthCheckState.PASSED}
+         * if not yet {@link HealthCheckState.FAILED}.
+         *
+         * @return the new {@link HealthCheckState health check state}
+         */
+        @GuardedBy("sLock")
+        @HealthCheckState
+        public int tryPassHealthCheckLocked() {
+            if (mHealthCheckState != HealthCheckState.FAILED) {
+                // FAILED is a final state so only pass if we haven't failed
+                // Transition to PASSED
+                mHasPassedHealthCheck = true;
+            }
+            return updateHealthCheckStateLocked();
+        }
+
+        /** Returns the monitored package name. */
+        private String getName() {
+            return mPackageName;
+        }
+
+        /**
+         * Returns the current {@link HealthCheckState health check state}.
+         */
+        @GuardedBy("sLock")
+        @HealthCheckState
+        public int getHealthCheckStateLocked() {
+            return mHealthCheckState;
+        }
+
+        /**
+         * Returns the shortest duration before the package should be scheduled for a prune.
+         *
+         * @return the duration or {@link Long#MAX_VALUE} if the package should not be scheduled
+         */
+        @GuardedBy("sLock")
+        public long getShortestScheduleDurationMsLocked() {
+            // Consider health check duration only if #isPendingHealthChecksLocked is true
+            return Math.min(toPositive(mDurationMs),
+                    isPendingHealthChecksLocked()
+                    ? toPositive(mHealthCheckDurationMs) : Long.MAX_VALUE);
+        }
+
+        /**
+         * Returns {@code true} if the total duration left to monitor the package is less than or
+         * equal to 0 {@code false} otherwise.
+         */
+        @GuardedBy("sLock")
+        public boolean isExpiredLocked() {
+            return mDurationMs <= 0;
+        }
+
+        /**
+         * Returns {@code true} if the package, {@link #getName} is expecting health check results
+         * {@code false} otherwise.
+         */
+        @GuardedBy("sLock")
+        public boolean isPendingHealthChecksLocked() {
+            return mHealthCheckState == HealthCheckState.ACTIVE
+                    || mHealthCheckState == HealthCheckState.INACTIVE;
+        }
+
+        /**
+         * Updates the health check state based on {@link #mHasPassedHealthCheck}
+         * and {@link #mHealthCheckDurationMs}.
+         *
+         * @return the new {@link HealthCheckState health check state}
+         */
+        @GuardedBy("sLock")
+        @HealthCheckState
+        private int updateHealthCheckStateLocked() {
+            int oldState = mHealthCheckState;
+            if (mHasPassedHealthCheck) {
+                // Set final state first to avoid ambiguity
+                mHealthCheckState = HealthCheckState.PASSED;
+            } else if (mHealthCheckDurationMs <= 0 || mDurationMs <= 0) {
+                // Set final state first to avoid ambiguity
+                mHealthCheckState = HealthCheckState.FAILED;
+            } else if (mHealthCheckDurationMs == Long.MAX_VALUE) {
+                mHealthCheckState = HealthCheckState.INACTIVE;
+            } else {
+                mHealthCheckState = HealthCheckState.ACTIVE;
+            }
+
+            if (oldState != mHealthCheckState) {
+                Slog.i(TAG, "Updated health check state for package " + getName() + ": "
+                        + toString(oldState) + " -> " + toString(mHealthCheckState));
+            }
+            return mHealthCheckState;
+        }
+
+        /** Returns a {@link String} representation of the current health check state. */
+        private String toString(@HealthCheckState int state) {
+            switch (state) {
+                case HealthCheckState.ACTIVE:
+                    return "ACTIVE";
+                case HealthCheckState.INACTIVE:
+                    return "INACTIVE";
+                case HealthCheckState.PASSED:
+                    return "PASSED";
+                case HealthCheckState.FAILED:
+                    return "FAILED";
+                default:
+                    return "UNKNOWN";
+            }
+        }
+
+        /** Returns {@code value} if it is greater than 0 or {@link Long#MAX_VALUE} otherwise. */
+        private long toPositive(long value) {
+            return value > 0 ? value : Long.MAX_VALUE;
+        }
+
+        /** Compares the equality of this object with another {@link MonitoredPackage}. */
+        @VisibleForTesting
+        boolean isEqualTo(MonitoredPackage pkg) {
+            return (getName().equals(pkg.getName()))
+                    && mDurationMs == pkg.mDurationMs
+                    && mHasPassedHealthCheck == pkg.mHasPassedHealthCheck
+                    && mHealthCheckDurationMs == pkg.mHealthCheckDurationMs
+                    && (mMitigationCalls.toString()).equals(pkg.mMitigationCalls.toString());
+        }
+    }
+
+    @GuardedBy("sLock")
+    @SuppressWarnings("GuardedBy")
+    void saveAllObserversBootMitigationCountToMetadata(String filePath) {
+        HashMap<String, Integer> bootMitigationCounts = new HashMap<>();
+        for (int i = 0; i < mAllObservers.size(); i++) {
+            final ObserverInternal observer = mAllObservers.valueAt(i);
+            bootMitigationCounts.put(observer.name, observer.getBootMitigationCount());
+        }
+
+        FileOutputStream fileStream = null;
+        ObjectOutputStream objectStream = null;
+        try {
+            fileStream = new FileOutputStream(new File(filePath));
+            objectStream = new ObjectOutputStream(fileStream);
+            objectStream.writeObject(bootMitigationCounts);
+            objectStream.flush();
+        } catch (Exception e) {
+            Slog.i(TAG, "Could not save observers metadata to file: " + e);
+            return;
+        } finally {
+            IoUtils.closeQuietly(objectStream);
+            IoUtils.closeQuietly(fileStream);
+        }
+    }
+
+    /**
+     * Handles the thresholding logic for system server boots.
+     */
+    class BootThreshold {
+
+        private final int mBootTriggerCount;
+        private final long mTriggerWindow;
+
+        BootThreshold(int bootTriggerCount, long triggerWindow) {
+            this.mBootTriggerCount = bootTriggerCount;
+            this.mTriggerWindow = triggerWindow;
+        }
+
+        public void reset() {
+            setStart(0);
+            setCount(0);
+        }
+
+        protected int getCount() {
+            return CrashRecoveryProperties.rescueBootCount().orElse(0);
+        }
+
+        protected void setCount(int count) {
+            CrashRecoveryProperties.rescueBootCount(count);
+        }
+
+        public long getStart() {
+            return CrashRecoveryProperties.rescueBootStart().orElse(0L);
+        }
+
+        public int getMitigationCount() {
+            return CrashRecoveryProperties.bootMitigationCount().orElse(0);
+        }
+
+        public void setStart(long start) {
+            CrashRecoveryProperties.rescueBootStart(getStartTime(start));
+        }
+
+        public void setMitigationStart(long start) {
+            CrashRecoveryProperties.bootMitigationStart(getStartTime(start));
+        }
+
+        public long getMitigationStart() {
+            return CrashRecoveryProperties.bootMitigationStart().orElse(0L);
+        }
+
+        public void setMitigationCount(int count) {
+            CrashRecoveryProperties.bootMitigationCount(count);
+        }
+
+        private static long constrain(long amount, long low, long high) {
+            return amount < low ? low : (amount > high ? high : amount);
+        }
+
+        public long getStartTime(long start) {
+            final long now = mSystemClock.uptimeMillis();
+            return constrain(start, 0, now);
+        }
+
+        public void saveMitigationCountToMetadata() {
+            try (BufferedWriter writer = new BufferedWriter(new FileWriter(METADATA_FILE))) {
+                writer.write(String.valueOf(getMitigationCount()));
+            } catch (Exception e) {
+                Slog.e(TAG, "Could not save metadata to file: " + e);
+            }
+        }
+
+        public void readMitigationCountFromMetadataIfNecessary() {
+            File bootPropsFile = new File(METADATA_FILE);
+            if (bootPropsFile.exists()) {
+                try (BufferedReader reader = new BufferedReader(new FileReader(METADATA_FILE))) {
+                    String mitigationCount = reader.readLine();
+                    setMitigationCount(Integer.parseInt(mitigationCount));
+                    bootPropsFile.delete();
+                } catch (Exception e) {
+                    Slog.i(TAG, "Could not read metadata file: " + e);
+                }
+            }
+        }
+
+
+        /** Increments the boot counter, and returns whether the device is bootlooping. */
+        @GuardedBy("sLock")
+        public boolean incrementAndTest() {
+            readAllObserversBootMitigationCountIfNecessary(METADATA_FILE);
+
+            final long now = mSystemClock.uptimeMillis();
+            if (now - getStart() < 0) {
+                Slog.e(TAG, "Window was less than zero. Resetting start to current time.");
+                setStart(now);
+                setMitigationStart(now);
+            }
+            if (now - getMitigationStart() > DEFAULT_DEESCALATION_WINDOW_MS) {
+                setMitigationStart(now);
+                resetAllObserversBootMitigationCount();
+            }
+            final long window = now - getStart();
+            if (window >= mTriggerWindow) {
+                setCount(1);
+                setStart(now);
+                return false;
+            } else {
+                int count = getCount() + 1;
+                setCount(count);
+                EventLog.writeEvent(LOG_TAG_RESCUE_NOTE, Process.ROOT_UID, count, window);
+                // After a reboot (e.g. by WARM_REBOOT or mainline rollback) we apply
+                // mitigations without waiting for DEFAULT_BOOT_LOOP_TRIGGER_COUNT.
+                return (count >= mBootTriggerCount)
+                        || (performedMitigationsDuringWindow() && count > 1);
+            }
+        }
+
+        @GuardedBy("sLock")
+        private boolean performedMitigationsDuringWindow() {
+            for (ObserverInternal observerInternal: mAllObservers.values()) {
+                if (observerInternal.getBootMitigationCount() > 0) {
+                    return true;
+                }
+            }
+            return false;
+        }
+
+        @GuardedBy("sLock")
+        private void resetAllObserversBootMitigationCount() {
+            for (int i = 0; i < mAllObservers.size(); i++) {
+                final ObserverInternal observer = mAllObservers.valueAt(i);
+                observer.setBootMitigationCount(0);
+            }
+            saveAllObserversBootMitigationCountToMetadata(METADATA_FILE);
+        }
+
+        @GuardedBy("sLock")
+        @SuppressWarnings("GuardedBy")
+        void readAllObserversBootMitigationCountIfNecessary(String filePath) {
+            File metadataFile = new File(filePath);
+            if (metadataFile.exists()) {
+                FileInputStream fileStream = null;
+                ObjectInputStream objectStream = null;
+                HashMap<String, Integer> bootMitigationCounts = null;
+                try {
+                    fileStream = new FileInputStream(metadataFile);
+                    objectStream = new ObjectInputStream(fileStream);
+                    bootMitigationCounts =
+                            (HashMap<String, Integer>) objectStream.readObject();
+                } catch (Exception e) {
+                    Slog.i(TAG, "Could not read observer metadata file: " + e);
+                   return;
+                } finally {
+                    IoUtils.closeQuietly(objectStream);
+                    IoUtils.closeQuietly(fileStream);
+                }
+
+                if (bootMitigationCounts == null || bootMitigationCounts.isEmpty()) {
+                    Slog.i(TAG, "No observer in metadata file");
+                    return;
+                }
+                for (int i = 0; i < mAllObservers.size(); i++) {
+                    final ObserverInternal observer = mAllObservers.valueAt(i);
+                    if (bootMitigationCounts.containsKey(observer.name)) {
+                        observer.setBootMitigationCount(
+                                bootMitigationCounts.get(observer.name));
+                    }
+                }
+            }
+        }
+    }
+
+    /**
+     * Register broadcast receiver for shutdown.
+     * We would save the observer state to persist across boots.
+     *
+     * @hide
+     */
+    public void registerShutdownBroadcastReceiver() {
+        BroadcastReceiver shutdownEventReceiver = new BroadcastReceiver() {
+            @Override
+            public void onReceive(Context context, Intent intent) {
+                // Only write if intent is relevant to device reboot or shutdown.
+                String intentAction = intent.getAction();
+                if (ACTION_REBOOT.equals(intentAction)
+                        || ACTION_SHUTDOWN.equals(intentAction)) {
+                    writeNow();
+                }
+            }
+        };
+
+        // Setup receiver for device reboots or shutdowns.
+        IntentFilter filter = new IntentFilter(ACTION_REBOOT);
+        filter.addAction(ACTION_SHUTDOWN);
+        mContext.registerReceiverForAllUsers(shutdownEventReceiver, filter, null,
+                /* run on main thread */ null);
+    }
+}
diff --git a/service/java/com/android/server/RescueParty.java b/service/java/com/android/server/RescueParty.java
new file mode 100644
index 0000000..3bf2ce5
--- /dev/null
+++ b/service/java/com/android/server/RescueParty.java
@@ -0,0 +1,590 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
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
+package com.android.server;
+
+import static com.android.server.PackageWatchdog.MITIGATION_RESULT_SKIPPED;
+import static com.android.server.PackageWatchdog.MITIGATION_RESULT_SUCCESS;
+import static com.android.server.crashrecovery.CrashRecoveryUtils.logCrashRecoveryEvent;
+
+import android.annotation.IntDef;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.content.Context;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageManager;
+import android.content.pm.VersionedPackage;
+import android.crashrecovery.flags.Flags;
+import android.os.Build;
+import android.os.PowerManager;
+import android.os.RecoverySystem;
+import android.os.SystemClock;
+import android.os.SystemProperties;
+import android.sysprop.CrashRecoveryProperties;
+import android.text.TextUtils;
+import android.util.EventLog;
+import android.util.FileUtils;
+import android.util.Log;
+import android.util.Slog;
+
+import com.android.internal.annotations.GuardedBy;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.PackageWatchdog.FailureReasons;
+import com.android.server.PackageWatchdog.PackageHealthObserver;
+import com.android.server.PackageWatchdog.PackageHealthObserverImpact;
+import com.android.server.crashrecovery.proto.CrashRecoveryStatsLog;
+
+import java.io.File;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.util.concurrent.TimeUnit;
+
+/**
+ * Utilities to help rescue the system from crash loops. Callers are expected to
+ * report boot events and persistent app crashes, and if they happen frequently
+ * enough this class will slowly escalate through several rescue operations
+ * before finally rebooting and prompting the user if they want to wipe data as
+ * a last resort.
+ *
+ * @hide
+ */
+public class RescueParty {
+    @VisibleForTesting
+    static final String PROP_ENABLE_RESCUE = "persist.sys.enable_rescue";
+    @VisibleForTesting
+    static final int LEVEL_FACTORY_RESET = 5;
+    @VisibleForTesting
+    static final int RESCUE_LEVEL_NONE = 0;
+    @VisibleForTesting
+    static final int RESCUE_LEVEL_SCOPED_DEVICE_CONFIG_RESET = 1;
+    @VisibleForTesting
+    static final int RESCUE_LEVEL_ALL_DEVICE_CONFIG_RESET = 2;
+    @VisibleForTesting
+    static final int RESCUE_LEVEL_WARM_REBOOT = 3;
+    @VisibleForTesting
+    static final int RESCUE_LEVEL_RESET_SETTINGS_UNTRUSTED_DEFAULTS = 4;
+    @VisibleForTesting
+    static final int RESCUE_LEVEL_RESET_SETTINGS_UNTRUSTED_CHANGES = 5;
+    @VisibleForTesting
+    static final int RESCUE_LEVEL_RESET_SETTINGS_TRUSTED_DEFAULTS = 6;
+    @VisibleForTesting
+    static final int RESCUE_LEVEL_FACTORY_RESET = 7;
+
+    @IntDef(prefix = { "RESCUE_LEVEL_" }, value = {
+        RESCUE_LEVEL_NONE,
+        RESCUE_LEVEL_SCOPED_DEVICE_CONFIG_RESET,
+        RESCUE_LEVEL_ALL_DEVICE_CONFIG_RESET,
+        RESCUE_LEVEL_WARM_REBOOT,
+        RESCUE_LEVEL_RESET_SETTINGS_UNTRUSTED_DEFAULTS,
+        RESCUE_LEVEL_RESET_SETTINGS_UNTRUSTED_CHANGES,
+        RESCUE_LEVEL_RESET_SETTINGS_TRUSTED_DEFAULTS,
+        RESCUE_LEVEL_FACTORY_RESET
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    @interface RescueLevels {}
+
+    @VisibleForTesting
+    static final String TAG = "RescueParty";
+    @VisibleForTesting
+    static final long DEFAULT_FACTORY_RESET_THROTTLE_DURATION_MIN = 1440;
+
+    private static final String NAME = "rescue-party-observer";
+
+    private static final String PROP_DISABLE_RESCUE = "persist.sys.disable_rescue";
+    private static final String PROP_VIRTUAL_DEVICE = "ro.hardware.virtual_device";
+    private static final String PROP_DEVICE_CONFIG_DISABLE_FLAG =
+            "persist.device_config.configuration.disable_rescue_party";
+    private static final String PROP_DISABLE_FACTORY_RESET_FLAG =
+            "persist.device_config.configuration.disable_rescue_party_factory_reset";
+    private static final String PROP_THROTTLE_DURATION_MIN_FLAG =
+            "persist.device_config.configuration.rescue_party_throttle_duration_min";
+
+    private static final int PERSISTENT_MASK = ApplicationInfo.FLAG_PERSISTENT
+            | ApplicationInfo.FLAG_SYSTEM;
+
+    /**
+     * EventLog tags used when logging into the event log. Note the values must be sync with
+     * frameworks/base/services/core/java/com/android/server/EventLogTags.logtags to get correct
+     * name translation.
+     */
+    private static final int LOG_TAG_RESCUE_SUCCESS = 2902;
+    private static final int LOG_TAG_RESCUE_FAILURE = 2903;
+
+    /** Register the Rescue Party observer as a Package Watchdog health observer */
+    public static void registerHealthObserver(Context context) {
+        PackageWatchdog.getInstance(context).registerHealthObserver(
+                context.getMainExecutor(), RescuePartyObserver.getInstance(context));
+    }
+
+    private static boolean isDisabled() {
+        // Check if we're explicitly enabled for testing
+        if (SystemProperties.getBoolean(PROP_ENABLE_RESCUE, false)) {
+            return false;
+        }
+
+        // We're disabled if the DeviceConfig disable flag is set to true.
+        // This is in case that an emergency rollback of the feature is needed.
+        if (SystemProperties.getBoolean(PROP_DEVICE_CONFIG_DISABLE_FLAG, false)) {
+            Slog.v(TAG, "Disabled because of DeviceConfig flag");
+            return true;
+        }
+
+        // We're disabled on all engineering devices
+        if (Build.TYPE.equals("eng")) {
+            Slog.v(TAG, "Disabled because of eng build");
+            return true;
+        }
+
+        // We're disabled on userdebug devices connected over USB, since that's
+        // a decent signal that someone is actively trying to debug the device,
+        // or that it's in a lab environment.
+        if (Build.TYPE.equals("userdebug") && isUsbActive()) {
+            Slog.v(TAG, "Disabled because of active USB connection");
+            return true;
+        }
+
+        // One last-ditch check
+        if (SystemProperties.getBoolean(PROP_DISABLE_RESCUE, false)) {
+            Slog.v(TAG, "Disabled because of manual property");
+            return true;
+        }
+
+        return false;
+    }
+
+    /**
+     * Check if we're currently attempting to reboot for a factory reset. This method must
+     * return true if RescueParty tries to reboot early during a boot loop, since the device
+     * will not be fully booted at this time.
+     */
+    public static boolean isRecoveryTriggeredReboot() {
+        return isFactoryResetPropertySet() || isRebootPropertySet();
+    }
+
+    static boolean isFactoryResetPropertySet() {
+        return CrashRecoveryProperties.attemptingFactoryReset().orElse(false);
+    }
+
+    static boolean isRebootPropertySet() {
+        return CrashRecoveryProperties.attemptingReboot().orElse(false);
+    }
+
+    protected static long getLastFactoryResetTimeMs() {
+        return CrashRecoveryProperties.lastFactoryResetTimeMs().orElse(0L);
+    }
+
+    protected static int getMaxRescueLevelAttempted() {
+        return CrashRecoveryProperties.maxRescueLevelAttempted().orElse(RESCUE_LEVEL_NONE);
+    }
+
+    protected static void setFactoryResetProperty(boolean value) {
+        CrashRecoveryProperties.attemptingFactoryReset(value);
+    }
+    protected static void setRebootProperty(boolean value) {
+        CrashRecoveryProperties.attemptingReboot(value);
+    }
+
+    protected static void setLastFactoryResetTimeMs(long value) {
+        CrashRecoveryProperties.lastFactoryResetTimeMs(value);
+    }
+
+    protected static void setMaxRescueLevelAttempted(int level) {
+        CrashRecoveryProperties.maxRescueLevelAttempted(level);
+    }
+
+    @VisibleForTesting
+    static long getElapsedRealtime() {
+        return SystemClock.elapsedRealtime();
+    }
+
+    private static int getMaxRescueLevel() {
+        if (!SystemProperties.getBoolean(PROP_DISABLE_FACTORY_RESET_FLAG, false)) {
+            return Level.factoryReset();
+        }
+        return Level.reboot();
+    }
+
+    /**
+     * Get the rescue level to perform if this is the n-th attempt at mitigating failure.
+     *
+     * @param mitigationCount the mitigation attempt number (1 = first attempt etc.).
+     * @return the rescue level for the n-th mitigation attempt.
+     */
+    private static @RescueLevels int getRescueLevel(int mitigationCount) {
+        if (mitigationCount == 1) {
+            return Level.reboot();
+        } else if (mitigationCount >= 2) {
+            return Math.min(getMaxRescueLevel(), Level.factoryReset());
+        } else {
+            return Level.none();
+        }
+    }
+
+    private static void executeRescueLevel(Context context, @Nullable String failedPackage,
+            int level) {
+        Slog.w(TAG, "Attempting rescue level " + levelToString(level));
+        try {
+            executeRescueLevelInternal(context, level, failedPackage);
+            EventLog.writeEvent(LOG_TAG_RESCUE_SUCCESS, level);
+            String successMsg = "Finished rescue level " + levelToString(level);
+            if (!TextUtils.isEmpty(failedPackage)) {
+                successMsg += " for package " + failedPackage;
+            }
+            logCrashRecoveryEvent(Log.DEBUG, successMsg);
+        } catch (Throwable t) {
+            logRescueException(level, failedPackage, t);
+        }
+    }
+
+    private static void executeRescueLevelInternal(Context context, @RescueLevels int level,
+            @Nullable String failedPackage) {
+        CrashRecoveryStatsLog.write(CrashRecoveryStatsLog.RESCUE_PARTY_RESET_REPORTED,
+                level, levelToString(level));
+        switch (level) {
+            case RESCUE_LEVEL_SCOPED_DEVICE_CONFIG_RESET:
+                break;
+            case RESCUE_LEVEL_ALL_DEVICE_CONFIG_RESET:
+                break;
+            case RESCUE_LEVEL_WARM_REBOOT:
+                executeWarmReboot(context, level, failedPackage);
+                break;
+            case RESCUE_LEVEL_RESET_SETTINGS_UNTRUSTED_DEFAULTS:
+                // do nothing
+                break;
+            case RESCUE_LEVEL_RESET_SETTINGS_UNTRUSTED_CHANGES:
+                // do nothing
+                break;
+            case RESCUE_LEVEL_RESET_SETTINGS_TRUSTED_DEFAULTS:
+                // do nothing
+                break;
+            case RESCUE_LEVEL_FACTORY_RESET:
+                // Before the completion of Reboot, if any crash happens then PackageWatchdog
+                // escalates to next level i.e. factory reset, as they happen in separate threads.
+                // Adding a check to prevent factory reset to execute before above reboot completes.
+                // Note: this reboot property is not persistent resets after reboot is completed.
+                if (isRebootPropertySet()) {
+                    return;
+                }
+                executeFactoryReset(context, level, failedPackage);
+                break;
+        }
+    }
+
+    private static void executeWarmReboot(Context context, int level,
+            @Nullable String failedPackage) {
+        if (shouldThrottleReboot()) {
+            return;
+        }
+
+        // Request the reboot from a separate thread to avoid deadlock on PackageWatchdog
+        // when device shutting down.
+        setRebootProperty(true);
+
+        if (Flags.synchronousRebootInRescueParty()) {
+            try {
+                PowerManager pm = context.getSystemService(PowerManager.class);
+                if (pm != null) {
+                    pm.reboot(TAG);
+                }
+            } catch (Throwable t) {
+                logRescueException(level, failedPackage, t);
+            }
+        } else {
+            Runnable runnable = () -> {
+                try {
+                    PowerManager pm = context.getSystemService(PowerManager.class);
+                    if (pm != null) {
+                        pm.reboot(TAG);
+                    }
+                } catch (Throwable t) {
+                    logRescueException(level, failedPackage, t);
+                }
+            };
+            Thread thread = new Thread(runnable);
+            thread.start();
+        }
+    }
+
+    private static void executeFactoryReset(Context context, int level,
+            @Nullable String failedPackage) {
+        if (shouldThrottleReboot()) {
+            return;
+        }
+        setFactoryResetProperty(true);
+        long now = System.currentTimeMillis();
+        setLastFactoryResetTimeMs(now);
+
+        if (Flags.synchronousRebootInRescueParty()) {
+            try {
+                RecoverySystem.rebootPromptAndWipeUserData(context, TAG + "," + failedPackage);
+            } catch (Throwable t) {
+                logRescueException(level, failedPackage, t);
+            }
+        } else {
+            Runnable runnable = new Runnable() {
+                @Override
+                public void run() {
+                    try {
+                        RecoverySystem.rebootPromptAndWipeUserData(context,
+                            TAG + "," + failedPackage);
+                    } catch (Throwable t) {
+                        logRescueException(level, failedPackage, t);
+                    }
+                }
+            };
+            Thread thread = new Thread(runnable);
+            thread.start();
+        }
+    }
+
+
+    private static String getCompleteMessage(Throwable t) {
+        final StringBuilder builder = new StringBuilder();
+        builder.append(t.getMessage());
+        while ((t = t.getCause()) != null) {
+            builder.append(": ").append(t.getMessage());
+        }
+        return builder.toString();
+    }
+
+    private static void logRescueException(int level, @Nullable String failedPackageName,
+            Throwable t) {
+        final String msg = getCompleteMessage(t);
+        EventLog.writeEvent(LOG_TAG_RESCUE_FAILURE, level, msg);
+        String failureMsg = "Failed rescue level " + levelToString(level);
+        if (!TextUtils.isEmpty(failedPackageName)) {
+            failureMsg += " for package " + failedPackageName;
+        }
+        logCrashRecoveryEvent(Log.ERROR, failureMsg + ": " + msg);
+    }
+
+    private static int mapRescueLevelToUserImpact(int rescueLevel) {
+        switch (rescueLevel) {
+            case RESCUE_LEVEL_SCOPED_DEVICE_CONFIG_RESET:
+                return PackageHealthObserverImpact.USER_IMPACT_LEVEL_10;
+            case RESCUE_LEVEL_ALL_DEVICE_CONFIG_RESET:
+                return PackageHealthObserverImpact.USER_IMPACT_LEVEL_40;
+            case RESCUE_LEVEL_WARM_REBOOT:
+                return PackageHealthObserverImpact.USER_IMPACT_LEVEL_50;
+            case RESCUE_LEVEL_RESET_SETTINGS_UNTRUSTED_DEFAULTS:
+                return PackageHealthObserverImpact.USER_IMPACT_LEVEL_71;
+            case RESCUE_LEVEL_RESET_SETTINGS_UNTRUSTED_CHANGES:
+                return PackageHealthObserverImpact.USER_IMPACT_LEVEL_75;
+            case RESCUE_LEVEL_RESET_SETTINGS_TRUSTED_DEFAULTS:
+                return PackageHealthObserverImpact.USER_IMPACT_LEVEL_80;
+            case RESCUE_LEVEL_FACTORY_RESET:
+                return PackageHealthObserverImpact.USER_IMPACT_LEVEL_100;
+            default:
+                return PackageHealthObserverImpact.USER_IMPACT_LEVEL_0;
+        }
+    }
+
+    /**
+     * Handle mitigation action for package failures. This observer will be register to Package
+     * Watchdog and will receive calls about package failures. This observer is persistent so it
+     * may choose to mitigate failures for packages it has not explicitly asked to observe.
+     */
+    public static class RescuePartyObserver implements PackageHealthObserver {
+
+        private final Context mContext;
+
+        @GuardedBy("RescuePartyObserver.class")
+        static RescuePartyObserver sRescuePartyObserver;
+
+        private RescuePartyObserver(Context context) {
+            mContext = context;
+        }
+
+        /** Creates or gets singleton instance of RescueParty. */
+        public static RescuePartyObserver getInstance(Context context) {
+            synchronized (RescuePartyObserver.class) {
+                if (sRescuePartyObserver == null) {
+                    sRescuePartyObserver = new RescuePartyObserver(context);
+                }
+                return sRescuePartyObserver;
+            }
+        }
+
+        @VisibleForTesting
+        static void reset() {
+            synchronized (RescuePartyObserver.class) {
+                sRescuePartyObserver = null;
+            }
+        }
+
+        @Override
+        public int onHealthCheckFailed(@Nullable VersionedPackage failedPackage,
+                @FailureReasons int failureReason, int mitigationCount) {
+            int impact = PackageHealthObserverImpact.USER_IMPACT_LEVEL_0;
+            if (!isDisabled() && (failureReason == PackageWatchdog.FAILURE_REASON_APP_CRASH
+                    || failureReason == PackageWatchdog.FAILURE_REASON_APP_NOT_RESPONDING)) {
+                impact = mapRescueLevelToUserImpact(getRescueLevel(mitigationCount));
+            }
+
+            Slog.i(TAG, "Checking available remediations for health check failure."
+                    + " failedPackage: "
+                    + (failedPackage == null ? null : failedPackage.getPackageName())
+                    + " failureReason: " + failureReason
+                    + " available impact: " + impact);
+            return impact;
+        }
+
+        @Override
+        public int onExecuteHealthCheckMitigation(@Nullable VersionedPackage failedPackage,
+                @FailureReasons int failureReason, int mitigationCount) {
+            if (isDisabled()) {
+                return MITIGATION_RESULT_SKIPPED;
+            }
+            Slog.i(TAG, "Executing remediation."
+                    + " failedPackage: "
+                    + (failedPackage == null ? null : failedPackage.getPackageName())
+                    + " failureReason: " + failureReason
+                    + " mitigationCount: " + mitigationCount);
+            if (failureReason == PackageWatchdog.FAILURE_REASON_APP_CRASH
+                    || failureReason == PackageWatchdog.FAILURE_REASON_APP_NOT_RESPONDING) {
+                final int level;
+                level = getRescueLevel(mitigationCount);
+                executeRescueLevel(mContext,
+                        failedPackage == null ? null : failedPackage.getPackageName(), level);
+                return MITIGATION_RESULT_SUCCESS;
+            } else {
+                return MITIGATION_RESULT_SKIPPED;
+            }
+        }
+
+        @Override
+        public boolean isPersistent() {
+            return true;
+        }
+
+        @Override
+        public boolean mayObservePackage(@NonNull String packageName) {
+            PackageManager pm = mContext.getPackageManager();
+            try {
+                // A package is a module if this is non-null
+                if (pm.getModuleInfo(packageName, 0) != null) {
+                    return true;
+                }
+            } catch (PackageManager.NameNotFoundException | IllegalStateException ignore) {
+            }
+
+            return isPersistentSystemApp(packageName);
+        }
+
+        @Override
+        public int onBootLoop(int mitigationCount) {
+            if (isDisabled()) {
+                return PackageHealthObserverImpact.USER_IMPACT_LEVEL_0;
+            }
+            return mapRescueLevelToUserImpact(getRescueLevel(mitigationCount));
+        }
+
+        @Override
+        public int onExecuteBootLoopMitigation(int mitigationCount) {
+            if (isDisabled()) {
+                return MITIGATION_RESULT_SKIPPED;
+            }
+            final int level;
+            level = getRescueLevel(mitigationCount);
+            executeRescueLevel(mContext, /*failedPackage=*/ null, level);
+            return MITIGATION_RESULT_SUCCESS;
+        }
+
+        @Override
+        public String getUniqueIdentifier() {
+            return NAME;
+        }
+
+        private boolean isPersistentSystemApp(@NonNull String packageName) {
+            PackageManager pm = mContext.getPackageManager();
+            try {
+                ApplicationInfo info = pm.getApplicationInfo(packageName, 0);
+                return (info.flags & PERSISTENT_MASK) == PERSISTENT_MASK;
+            } catch (PackageManager.NameNotFoundException e) {
+                return false;
+            }
+        }
+
+    }
+
+    /**
+     * Returns {@code true} if Rescue Party is allowed to attempt a reboot or factory reset.
+     * Will return {@code false} if a factory reset was already offered recently.
+     */
+    private static boolean shouldThrottleReboot() {
+        Long lastResetTime = getLastFactoryResetTimeMs();
+        long now = System.currentTimeMillis();
+        long throttleDurationMin = SystemProperties.getLong(PROP_THROTTLE_DURATION_MIN_FLAG,
+                DEFAULT_FACTORY_RESET_THROTTLE_DURATION_MIN);
+        return now < lastResetTime + TimeUnit.MINUTES.toMillis(throttleDurationMin);
+    }
+
+    /**
+     * Hacky test to check if the device has an active USB connection, which is
+     * a good proxy for someone doing local development work.
+     */
+    private static boolean isUsbActive() {
+        if (SystemProperties.getBoolean(PROP_VIRTUAL_DEVICE, false)) {
+            Slog.v(TAG, "Assuming virtual device is connected over USB");
+            return true;
+        }
+        try {
+            final String state = FileUtils
+                    .readTextFile(new File("/sys/class/android_usb/android0/state"), 128, "");
+            return "CONFIGURED".equals(state.trim());
+        } catch (Throwable t) {
+            Slog.w(TAG, "Failed to determine if device was on USB", t);
+            return false;
+        }
+    }
+
+    private static class Level {
+        static int none() {
+            return RESCUE_LEVEL_NONE;
+        }
+
+        static int reboot() {
+            return RESCUE_LEVEL_WARM_REBOOT;
+        }
+
+        static int factoryReset() {
+            return RESCUE_LEVEL_FACTORY_RESET;
+        }
+    }
+
+    private static String levelToString(int level) {
+        switch (level) {
+            case RESCUE_LEVEL_NONE:
+                return "NONE";
+            case RESCUE_LEVEL_SCOPED_DEVICE_CONFIG_RESET:
+                return "SCOPED_DEVICE_CONFIG_RESET";
+            case RESCUE_LEVEL_ALL_DEVICE_CONFIG_RESET:
+                return "ALL_DEVICE_CONFIG_RESET";
+            case RESCUE_LEVEL_WARM_REBOOT:
+                return "WARM_REBOOT";
+            case RESCUE_LEVEL_RESET_SETTINGS_UNTRUSTED_DEFAULTS:
+                return "RESET_SETTINGS_UNTRUSTED_DEFAULTS";
+            case RESCUE_LEVEL_RESET_SETTINGS_UNTRUSTED_CHANGES:
+                return "RESET_SETTINGS_UNTRUSTED_CHANGES";
+            case RESCUE_LEVEL_RESET_SETTINGS_TRUSTED_DEFAULTS:
+                return "RESET_SETTINGS_TRUSTED_DEFAULTS";
+            case RESCUE_LEVEL_FACTORY_RESET:
+                return "FACTORY_RESET";
+            default:
+                return Integer.toString(level);
+        }
+    }
+}
diff --git a/service/java/com/android/server/crashrecovery/CrashRecoveryModule.java b/service/java/com/android/server/crashrecovery/CrashRecoveryModule.java
new file mode 100644
index 0000000..8a81aaa
--- /dev/null
+++ b/service/java/com/android/server/crashrecovery/CrashRecoveryModule.java
@@ -0,0 +1,58 @@
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
+package com.android.server.crashrecovery;
+
+import android.content.Context;
+
+import com.android.server.PackageWatchdog;
+import com.android.server.RescueParty;
+import com.android.server.SystemService;
+
+
+/** This class encapsulate the lifecycle methods of CrashRecovery module.
+ *
+ * @hide
+ */
+public class CrashRecoveryModule {
+    private static final String TAG = "CrashRecoveryModule";
+
+    /** Lifecycle definition for CrashRecovery module. */
+    public static class Lifecycle extends SystemService {
+        private Context mSystemContext;
+        private PackageWatchdog mPackageWatchdog;
+
+        public Lifecycle(Context context) {
+            super(context);
+            mSystemContext = context;
+            mPackageWatchdog = PackageWatchdog.getInstance(context);
+        }
+
+        @Override
+        public void onStart() {
+            RescueParty.registerHealthObserver(mSystemContext);
+            mPackageWatchdog.registerShutdownBroadcastReceiver();
+            mPackageWatchdog.noteBoot();
+        }
+
+        @Override
+        public void onBootPhase(int phase) {
+            if (phase == PHASE_THIRD_PARTY_APPS_CAN_START) {
+                mPackageWatchdog.onPackagesReady();
+            }
+        }
+    }
+}
diff --git a/service/java/com/android/server/crashrecovery/CrashRecoveryUtils.java b/service/java/com/android/server/crashrecovery/CrashRecoveryUtils.java
new file mode 100644
index 0000000..2e2a937
--- /dev/null
+++ b/service/java/com/android/server/crashrecovery/CrashRecoveryUtils.java
@@ -0,0 +1,85 @@
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
+package com.android.server.crashrecovery;
+
+import android.os.Environment;
+import android.util.IndentingPrintWriter;
+import android.util.Log;
+
+import java.io.BufferedReader;
+import java.io.File;
+import java.io.FileOutputStream;
+import java.io.FileReader;
+import java.io.IOException;
+import java.io.PrintWriter;
+import java.time.LocalDateTime;
+import java.time.ZoneId;
+
+/**
+ * Class containing helper methods for the CrashRecoveryModule.
+ *
+ * @hide
+ */
+public class CrashRecoveryUtils {
+    private static final String TAG = "CrashRecoveryUtils";
+    private static final long MAX_CRITICAL_INFO_DUMP_SIZE = 1000 * 1000; // ~1MB
+    private static final Object sFileLock = new Object();
+
+    /** Persist recovery related events in crashrecovery events file.**/
+    public static void logCrashRecoveryEvent(int priority, String msg) {
+        Log.println(priority, TAG, msg);
+        try {
+            File fname = getCrashRecoveryEventsFile();
+            synchronized (sFileLock) {
+                FileOutputStream out = new FileOutputStream(fname, true);
+                PrintWriter pw = new PrintWriter(out);
+                String dateString = LocalDateTime.now(ZoneId.systemDefault()).toString();
+                pw.println(dateString + ": " + msg);
+                pw.close();
+            }
+        } catch (IOException e) {
+            Log.e(TAG, "Unable to log CrashRecoveryEvents " + e.getMessage());
+        }
+    }
+
+    /** Dump recovery related events from crashrecovery events file.**/
+    public static void dumpCrashRecoveryEvents(IndentingPrintWriter pw) {
+        pw.println("CrashRecovery Events: ");
+        pw.increaseIndent();
+        final File file = getCrashRecoveryEventsFile();
+        final long skipSize = file.length() - MAX_CRITICAL_INFO_DUMP_SIZE;
+        synchronized (sFileLock) {
+            try (BufferedReader in = new BufferedReader(new FileReader(file))) {
+                if (skipSize > 0) {
+                    in.skip(skipSize);
+                }
+                String line;
+                while ((line = in.readLine()) != null) {
+                    pw.println(line);
+                }
+            } catch (IOException e) {
+                Log.e(TAG, "Unable to dump CrashRecoveryEvents " + e.getMessage());
+            }
+        }
+        pw.decreaseIndent();
+    }
+
+    private static File getCrashRecoveryEventsFile() {
+        File systemDir = new File(Environment.getDataDirectory(), "system");
+        return new File(systemDir, "crashrecovery-events.txt");
+    }
+}
diff --git a/service/java/com/android/server/rollback/RollbackPackageHealthObserver.java b/service/java/com/android/server/rollback/RollbackPackageHealthObserver.java
new file mode 100644
index 0000000..ef89305
--- /dev/null
+++ b/service/java/com/android/server/rollback/RollbackPackageHealthObserver.java
@@ -0,0 +1,692 @@
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
+
+package com.android.server.rollback;
+
+import static com.android.server.PackageWatchdog.MITIGATION_RESULT_SUCCESS;
+import static com.android.server.crashrecovery.CrashRecoveryUtils.logCrashRecoveryEvent;
+
+import android.annotation.AnyThread;
+import android.annotation.FlaggedApi;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.SuppressLint;
+import android.annotation.SystemApi;
+import android.annotation.WorkerThread;
+import android.app.PendingIntent;
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageInfo;
+import android.content.pm.PackageManager;
+import android.content.pm.VersionedPackage;
+import android.content.rollback.PackageRollbackInfo;
+import android.content.rollback.RollbackInfo;
+import android.content.rollback.RollbackManager;
+import android.crashrecovery.flags.Flags;
+import android.os.Environment;
+import android.os.Handler;
+import android.os.HandlerThread;
+import android.os.PowerManager;
+import android.os.SystemProperties;
+import android.sysprop.CrashRecoveryProperties;
+import android.util.ArraySet;
+import android.util.FileUtils;
+import android.util.Log;
+import android.util.Slog;
+import android.util.SparseArray;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.internal.util.Preconditions;
+import com.android.server.PackageWatchdog;
+import com.android.server.PackageWatchdog.FailureReasons;
+import com.android.server.PackageWatchdog.PackageHealthObserver;
+import com.android.server.PackageWatchdog.PackageHealthObserverImpact;
+import com.android.server.crashrecovery.proto.CrashRecoveryStatsLog;
+
+import java.io.BufferedReader;
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.FileOutputStream;
+import java.io.FileReader;
+import java.io.IOException;
+import java.io.PrintWriter;
+import java.util.Collections;
+import java.util.Comparator;
+import java.util.List;
+import java.util.Set;
+import java.util.function.Consumer;
+
+/**
+ * {@link PackageHealthObserver} for {@link RollbackManagerService}.
+ * This class monitors crashes and triggers RollbackManager rollback accordingly.
+ * It also monitors native crashes for some short while after boot.
+ *
+ * @hide
+ */
+@FlaggedApi(Flags.FLAG_ENABLE_CRASHRECOVERY)
+@SuppressLint({"CallbackName"})
+@SystemApi(client = SystemApi.Client.SYSTEM_SERVER)
+public final class RollbackPackageHealthObserver implements PackageHealthObserver {
+    private static final String TAG = "RollbackPackageHealthObserver";
+    private static final String NAME = "rollback-observer";
+    private static final String CLASS_NAME = RollbackPackageHealthObserver.class.getName();
+
+    private static final int PERSISTENT_MASK = ApplicationInfo.FLAG_PERSISTENT
+            | ApplicationInfo.FLAG_SYSTEM;
+
+    private static final String PROP_DISABLE_HIGH_IMPACT_ROLLBACK_FLAG =
+            "persist.device_config.configuration.disable_high_impact_rollback";
+
+    private final Context mContext;
+    private final Handler mHandler;
+    private final File mLastStagedRollbackIdsFile;
+    private final File mTwoPhaseRollbackEnabledFile;
+    // Staged rollback ids that have been committed but their session is not yet ready
+    private final Set<Integer> mPendingStagedRollbackIds = new ArraySet<>();
+    // True if needing to roll back only rebootless apexes when native crash happens
+    private boolean mTwoPhaseRollbackEnabled;
+
+    @VisibleForTesting
+    public RollbackPackageHealthObserver(@NonNull Context context) {
+        mContext = context;
+        HandlerThread handlerThread = new HandlerThread("RollbackPackageHealthObserver");
+        handlerThread.start();
+        mHandler = new Handler(handlerThread.getLooper());
+        File dataDir = new File(Environment.getDataDirectory(), "rollback-observer");
+        dataDir.mkdirs();
+        mLastStagedRollbackIdsFile = new File(dataDir, "last-staged-rollback-ids");
+        mTwoPhaseRollbackEnabledFile = new File(dataDir, "two-phase-rollback-enabled");
+        PackageWatchdog.getInstance(mContext).registerHealthObserver(context.getMainExecutor(),
+                this);
+
+        if (SystemProperties.getBoolean("sys.boot_completed", false)) {
+            // Load the value from the file if system server has crashed and restarted
+            mTwoPhaseRollbackEnabled = readBoolean(mTwoPhaseRollbackEnabledFile);
+        } else {
+            // Disable two-phase rollback for a normal reboot. We assume the rebootless apex
+            // installed before reboot is stable if native crash didn't happen.
+            mTwoPhaseRollbackEnabled = false;
+            writeBoolean(mTwoPhaseRollbackEnabledFile, false);
+        }
+    }
+
+    @Override
+    public int onHealthCheckFailed(@Nullable VersionedPackage failedPackage,
+            @FailureReasons int failureReason, int mitigationCount) {
+        int impact = PackageHealthObserverImpact.USER_IMPACT_LEVEL_0;
+        List<RollbackInfo> availableRollbacks = getAvailableRollbacks();
+        List<RollbackInfo> lowImpactRollbacks = getRollbacksAvailableForImpactLevel(
+                availableRollbacks, PackageManager.ROLLBACK_USER_IMPACT_LOW);
+        if (!lowImpactRollbacks.isEmpty()) {
+            if (failureReason == PackageWatchdog.FAILURE_REASON_NATIVE_CRASH) {
+                // For native crashes, we will directly roll back any available rollbacks at low
+                // impact level
+                impact = PackageHealthObserverImpact.USER_IMPACT_LEVEL_30;
+            } else if (getRollbackForPackage(failedPackage, lowImpactRollbacks) != null) {
+                // Rollback is available for crashing low impact package
+                impact = PackageHealthObserverImpact.USER_IMPACT_LEVEL_30;
+            } else {
+                impact = PackageHealthObserverImpact.USER_IMPACT_LEVEL_70;
+            }
+        }
+
+        Slog.i(TAG, "Checking available remediations for health check failure."
+                + " failedPackage: "
+                + (failedPackage == null ? null : failedPackage.getPackageName())
+                + " failureReason: " + failureReason
+                + " available impact: " + impact);
+        return impact;
+    }
+
+    @Override
+    public int onExecuteHealthCheckMitigation(@Nullable VersionedPackage failedPackage,
+            @FailureReasons int rollbackReason, int mitigationCount) {
+        Slog.i(TAG, "Executing remediation."
+                + " failedPackage: "
+                + (failedPackage == null ? null : failedPackage.getPackageName())
+                + " rollbackReason: " + rollbackReason
+                + " mitigationCount: " + mitigationCount);
+        List<RollbackInfo> availableRollbacks = getAvailableRollbacks();
+        if (rollbackReason == PackageWatchdog.FAILURE_REASON_NATIVE_CRASH) {
+            mHandler.post(() -> rollbackAllLowImpact(availableRollbacks, rollbackReason));
+            return MITIGATION_RESULT_SUCCESS;
+        }
+
+        List<RollbackInfo> lowImpactRollbacks = getRollbacksAvailableForImpactLevel(
+                availableRollbacks, PackageManager.ROLLBACK_USER_IMPACT_LOW);
+        RollbackInfo rollback = getRollbackForPackage(failedPackage, lowImpactRollbacks);
+        if (rollback != null) {
+            mHandler.post(() -> rollbackPackage(rollback, failedPackage, rollbackReason));
+        } else if (!lowImpactRollbacks.isEmpty()) {
+            // Apply all available low impact rollbacks.
+            mHandler.post(() -> rollbackAllLowImpact(availableRollbacks, rollbackReason));
+        }
+
+        // Assume rollbacks executed successfully
+        return MITIGATION_RESULT_SUCCESS;
+    }
+
+    @Override
+    public int onBootLoop(int mitigationCount) {
+        int impact = PackageHealthObserverImpact.USER_IMPACT_LEVEL_0;
+        List<RollbackInfo> availableRollbacks = getAvailableRollbacks();
+        if (!availableRollbacks.isEmpty()) {
+            impact = getUserImpactBasedOnRollbackImpactLevel(availableRollbacks);
+        }
+        return impact;
+    }
+
+    @Override
+    public int onExecuteBootLoopMitigation(int mitigationCount) {
+        List<RollbackInfo> availableRollbacks = getAvailableRollbacks();
+
+        triggerLeastImpactLevelRollback(availableRollbacks,
+                PackageWatchdog.FAILURE_REASON_BOOT_LOOP);
+        return MITIGATION_RESULT_SUCCESS;
+    }
+
+    @Override
+    @NonNull
+    public String getUniqueIdentifier() {
+        return NAME;
+    }
+
+    @Override
+    public boolean isPersistent() {
+        return true;
+    }
+
+    @Override
+    public boolean mayObservePackage(@NonNull String packageName) {
+        if (getAvailableRollbacks().isEmpty()) {
+            return false;
+        }
+        return isPersistentSystemApp(packageName);
+    }
+
+    private List<RollbackInfo> getAvailableRollbacks() {
+        return mContext.getSystemService(RollbackManager.class).getAvailableRollbacks();
+    }
+
+    private boolean isPersistentSystemApp(@NonNull String packageName) {
+        PackageManager pm = mContext.getPackageManager();
+        try {
+            ApplicationInfo info = pm.getApplicationInfo(packageName, 0);
+            return (info.flags & PERSISTENT_MASK) == PERSISTENT_MASK;
+        } catch (PackageManager.NameNotFoundException e) {
+            return false;
+        }
+    }
+
+    private void assertInWorkerThread() {
+        Preconditions.checkState(mHandler.getLooper().isCurrentThread());
+    }
+
+    @AnyThread
+    @NonNull
+    public void notifyRollbackAvailable(@NonNull RollbackInfo rollback) {
+        mHandler.post(() -> {
+            // Enable two-phase rollback when a rebootless apex rollback is made available.
+            // We assume the rebootless apex is stable and is less likely to be the cause
+            // if native crash doesn't happen before reboot. So we will clear the flag and disable
+            // two-phase rollback after reboot.
+            if (isRebootlessApex(rollback)) {
+                mTwoPhaseRollbackEnabled = true;
+                writeBoolean(mTwoPhaseRollbackEnabledFile, true);
+            }
+        });
+    }
+
+    private static boolean isRebootlessApex(RollbackInfo rollback) {
+        if (!rollback.isStaged()) {
+            for (PackageRollbackInfo info : rollback.getPackages()) {
+                if (info.isApex()) {
+                    return true;
+                }
+            }
+        }
+        return false;
+    }
+
+    /** Verifies the rollback state after a reboot and schedules polling for sometime after reboot
+     * to check for native crashes and mitigate them if needed.
+     */
+    @AnyThread
+    public void onBootCompletedAsync() {
+        mHandler.post(()->onBootCompleted());
+    }
+
+    @WorkerThread
+    private void onBootCompleted() {
+        assertInWorkerThread();
+
+        RollbackManager rollbackManager = mContext.getSystemService(RollbackManager.class);
+        if (!rollbackManager.getAvailableRollbacks().isEmpty()) {
+            // TODO(gavincorkery): Call into Package Watchdog from outside the observer
+            PackageWatchdog.getInstance(mContext).scheduleCheckAndMitigateNativeCrashes();
+        }
+
+        SparseArray<String> rollbackIds = popLastStagedRollbackIds();
+        for (int i = 0; i < rollbackIds.size(); i++) {
+            WatchdogRollbackLogger.logRollbackStatusOnBoot(mContext,
+                    rollbackIds.keyAt(i), rollbackIds.valueAt(i),
+                    rollbackManager.getRecentlyCommittedRollbacks());
+        }
+    }
+
+    @AnyThread
+    private RollbackInfo getRollbackForPackage(@Nullable VersionedPackage failedPackage,
+            List<RollbackInfo> availableRollbacks) {
+        if (failedPackage == null) {
+            return null;
+        }
+
+        for (RollbackInfo rollback : availableRollbacks) {
+            for (PackageRollbackInfo packageRollback : rollback.getPackages()) {
+                if (packageRollback.getVersionRolledBackFrom().equals(failedPackage)) {
+                    return rollback;
+                }
+                // TODO(b/147666157): Extract version number of apk-in-apex so that we don't have
+                //  to rely on complicated reasoning as below
+
+                // Due to b/147666157, for apk in apex, we do not know the version we are rolling
+                // back from. But if a package X is embedded in apex A exclusively (not embedded in
+                // any other apex), which is not guaranteed, then it is sufficient to check only
+                // package names here, as the version of failedPackage and the PackageRollbackInfo
+                // can't be different. If failedPackage has a higher version, then it must have
+                // been updated somehow. There are two ways: it was updated by an update of apex A
+                // or updated directly as apk. In both cases, this rollback would have gotten
+                // expired when onPackageReplaced() was called. Since the rollback exists, it has
+                // same version as failedPackage.
+                if (packageRollback.isApkInApex()
+                        && packageRollback.getVersionRolledBackFrom().getPackageName()
+                        .equals(failedPackage.getPackageName())) {
+                    return rollback;
+                }
+            }
+        }
+        return null;
+    }
+
+    /**
+     * Returns {@code true} if staged session associated with {@code rollbackId} was marked
+     * as handled, {@code false} if already handled.
+     */
+    @WorkerThread
+    private boolean markStagedSessionHandled(int rollbackId) {
+        assertInWorkerThread();
+        return mPendingStagedRollbackIds.remove(rollbackId);
+    }
+
+    /**
+     * Returns {@code true} if all pending staged rollback sessions were marked as handled,
+     * {@code false} if there is any left.
+     */
+    @WorkerThread
+    private boolean isPendingStagedSessionsEmpty() {
+        assertInWorkerThread();
+        return mPendingStagedRollbackIds.isEmpty();
+    }
+
+    private static boolean readBoolean(File file) {
+        try (FileInputStream fis = new FileInputStream(file)) {
+            return fis.read() == 1;
+        } catch (IOException ignore) {
+            return false;
+        }
+    }
+
+    private static void writeBoolean(File file, boolean value) {
+        try (FileOutputStream fos = new FileOutputStream(file)) {
+            fos.write(value ? 1 : 0);
+            fos.flush();
+            FileUtils.sync(fos);
+        } catch (IOException ignore) {
+        }
+    }
+
+    @WorkerThread
+    private void saveStagedRollbackId(int stagedRollbackId, @Nullable VersionedPackage logPackage) {
+        assertInWorkerThread();
+        writeStagedRollbackId(mLastStagedRollbackIdsFile, stagedRollbackId, logPackage);
+    }
+
+    static void writeStagedRollbackId(File file, int stagedRollbackId,
+            @Nullable VersionedPackage logPackage) {
+        try {
+            FileOutputStream fos = new FileOutputStream(file, true);
+            PrintWriter pw = new PrintWriter(fos);
+            String logPackageName = logPackage != null ? logPackage.getPackageName() : "";
+            pw.append(String.valueOf(stagedRollbackId)).append(",").append(logPackageName);
+            pw.println();
+            pw.flush();
+            FileUtils.sync(fos);
+            pw.close();
+        } catch (IOException e) {
+            Slog.e(TAG, "Failed to save last staged rollback id", e);
+            file.delete();
+        }
+    }
+
+    @WorkerThread
+    private SparseArray<String> popLastStagedRollbackIds() {
+        assertInWorkerThread();
+        try {
+            return readStagedRollbackIds(mLastStagedRollbackIdsFile);
+        } finally {
+            mLastStagedRollbackIdsFile.delete();
+        }
+    }
+
+    static SparseArray<String> readStagedRollbackIds(File file) {
+        SparseArray<String> result = new SparseArray<>();
+        try {
+            String line;
+            BufferedReader reader = new BufferedReader(new FileReader(file));
+            while ((line = reader.readLine()) != null) {
+                // Each line is of the format: "id,logging_package"
+                String[] values = line.trim().split(",");
+                String rollbackId = values[0];
+                String logPackageName = "";
+                if (values.length > 1) {
+                    logPackageName = values[1];
+                }
+                result.put(Integer.parseInt(rollbackId), logPackageName);
+            }
+        } catch (Exception ignore) {
+            return new SparseArray<>();
+        }
+        return result;
+    }
+
+
+    /**
+     * Returns true if the package name is the name of a module.
+     */
+    @AnyThread
+    private boolean isModule(String packageName) {
+        // Check if the package is listed among the system modules or is an
+        // APK inside an updatable APEX.
+        try {
+            PackageManager pm = mContext.getPackageManager();
+            final PackageInfo pkg = pm.getPackageInfo(packageName, 0 /* flags */);
+            String apexPackageName = pkg.getApexPackageName();
+            if (apexPackageName != null) {
+                packageName = apexPackageName;
+            }
+
+            return pm.getModuleInfo(packageName, 0 /* flags */) != null;
+        } catch (PackageManager.NameNotFoundException e) {
+            return false;
+        }
+    }
+
+    /**
+     * Rolls back the session that owns {@code failedPackage}
+     *
+     * @param rollback {@code rollbackInfo} of the {@code failedPackage}
+     * @param failedPackage the package that needs to be rolled back
+     */
+    @WorkerThread
+    private void rollbackPackage(RollbackInfo rollback, VersionedPackage failedPackage,
+            @FailureReasons int rollbackReason) {
+        assertInWorkerThread();
+        String failedPackageName = (failedPackage == null ? null : failedPackage.getPackageName());
+
+        Slog.i(TAG, "Rolling back package. RollbackId: " + rollback.getRollbackId()
+                + " failedPackage: " + failedPackageName
+                + " rollbackReason: " + rollbackReason);
+        logCrashRecoveryEvent(Log.DEBUG, String.format("Rolling back %s. Reason: %s",
+                failedPackageName, rollbackReason));
+        final RollbackManager rollbackManager = mContext.getSystemService(RollbackManager.class);
+        int reasonToLog = WatchdogRollbackLogger.mapFailureReasonToMetric(rollbackReason);
+        final String failedPackageToLog;
+        if (rollbackReason == PackageWatchdog.FAILURE_REASON_NATIVE_CRASH) {
+            failedPackageToLog = SystemProperties.get(
+                    "sys.init.updatable_crashing_process_name", "");
+        } else {
+            failedPackageToLog = failedPackage.getPackageName();
+        }
+        VersionedPackage logPackageTemp = null;
+        if (isModule(failedPackage.getPackageName())) {
+            logPackageTemp = WatchdogRollbackLogger.getLogPackage(mContext, failedPackage);
+        }
+
+        final VersionedPackage logPackage = logPackageTemp;
+        WatchdogRollbackLogger.logEvent(logPackage,
+                CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_INITIATE,
+                reasonToLog, failedPackageToLog);
+
+        Consumer<Intent> onResult = result -> {
+            assertInWorkerThread();
+            int status = result.getIntExtra(RollbackManager.EXTRA_STATUS,
+                    RollbackManager.STATUS_FAILURE);
+            if (status == RollbackManager.STATUS_SUCCESS) {
+                if (rollback.isStaged()) {
+                    int rollbackId = rollback.getRollbackId();
+                    saveStagedRollbackId(rollbackId, logPackage);
+                    WatchdogRollbackLogger.logEvent(logPackage,
+                            CrashRecoveryStatsLog
+                            .WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_BOOT_TRIGGERED,
+                            reasonToLog, failedPackageToLog);
+
+                } else {
+                    WatchdogRollbackLogger.logEvent(logPackage,
+                            CrashRecoveryStatsLog
+                                    .WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_SUCCESS,
+                            reasonToLog, failedPackageToLog);
+                }
+            } else {
+                WatchdogRollbackLogger.logEvent(logPackage,
+                        CrashRecoveryStatsLog
+                                .WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_FAILURE,
+                        reasonToLog, failedPackageToLog);
+            }
+            if (rollback.isStaged()) {
+                markStagedSessionHandled(rollback.getRollbackId());
+                // Wait for all pending staged sessions to get handled before rebooting.
+                if (isPendingStagedSessionsEmpty()) {
+                    CrashRecoveryProperties.attemptingReboot(true);
+                    mContext.getSystemService(PowerManager.class).reboot("Rollback staged install");
+                }
+            }
+        };
+
+        // Define a BroadcastReceiver to handle the result
+        BroadcastReceiver rollbackReceiver = new BroadcastReceiver() {
+            @Override
+            public void onReceive(Context context, Intent result) {
+                mHandler.post(() -> onResult.accept(result));
+            }
+        };
+
+        String intentActionName = CLASS_NAME + rollback.getRollbackId();
+        // Register the BroadcastReceiver
+        mContext.registerReceiver(rollbackReceiver,
+                new IntentFilter(intentActionName),
+                Context.RECEIVER_NOT_EXPORTED);
+
+        Intent intentReceiver = new Intent(intentActionName);
+        intentReceiver.putExtra("rollbackId", rollback.getRollbackId());
+        intentReceiver.setPackage(mContext.getPackageName());
+        intentReceiver.setFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY);
+
+        PendingIntent rollbackPendingIntent = PendingIntent.getBroadcast(mContext,
+                rollback.getRollbackId(),
+                intentReceiver,
+                PendingIntent.FLAG_MUTABLE);
+
+        rollbackManager.commitRollback(rollback.getRollbackId(),
+                Collections.singletonList(failedPackage),
+                rollbackPendingIntent.getIntentSender());
+    }
+
+    /**
+     * Two-phase rollback:
+     * 1. roll back rebootless apexes first
+     * 2. roll back all remaining rollbacks if native crash doesn't stop after (1) is done
+     *
+     * This approach gives us a better chance to correctly attribute native crash to rebootless
+     * apex update without rolling back Mainline updates which might contains critical security
+     * fixes.
+     */
+    @WorkerThread
+    private boolean useTwoPhaseRollback(List<RollbackInfo> rollbacks) {
+        assertInWorkerThread();
+        if (!mTwoPhaseRollbackEnabled) {
+            return false;
+        }
+
+        Slog.i(TAG, "Rolling back all rebootless APEX rollbacks");
+        boolean found = false;
+        for (RollbackInfo rollback : rollbacks) {
+            if (isRebootlessApex(rollback)) {
+                VersionedPackage firstRollback =
+                        rollback.getPackages().get(0).getVersionRolledBackFrom();
+                rollbackPackage(rollback, firstRollback,
+                        PackageWatchdog.FAILURE_REASON_NATIVE_CRASH);
+                found = true;
+            }
+        }
+        return found;
+    }
+
+    /**
+     * Rollback the package that has minimum rollback impact level.
+     * @param availableRollbacks all available rollbacks
+     * @param rollbackReason reason to rollback
+     */
+    private void triggerLeastImpactLevelRollback(List<RollbackInfo> availableRollbacks,
+            @FailureReasons int rollbackReason) {
+        int minRollbackImpactLevel = getMinRollbackImpactLevel(availableRollbacks);
+
+        if (minRollbackImpactLevel == PackageManager.ROLLBACK_USER_IMPACT_LOW) {
+            // Apply all available low impact rollbacks.
+            mHandler.post(() -> rollbackAllLowImpact(availableRollbacks, rollbackReason));
+        } else if (minRollbackImpactLevel == PackageManager.ROLLBACK_USER_IMPACT_HIGH) {
+            // Check disable_high_impact_rollback device config before performing rollback
+            if (SystemProperties.getBoolean(PROP_DISABLE_HIGH_IMPACT_ROLLBACK_FLAG, false)) {
+                return;
+            }
+            // Rollback one package at a time. If that doesn't resolve the issue, rollback
+            // next with same impact level.
+            mHandler.post(() -> rollbackHighImpact(availableRollbacks, rollbackReason));
+        }
+    }
+
+    /**
+     * sort the available high impact rollbacks by first package name to have a deterministic order.
+     * Apply the first available rollback.
+     * @param availableRollbacks all available rollbacks
+     * @param rollbackReason reason to rollback
+     */
+    @WorkerThread
+    private void rollbackHighImpact(List<RollbackInfo> availableRollbacks,
+            @FailureReasons int rollbackReason) {
+        assertInWorkerThread();
+        List<RollbackInfo> highImpactRollbacks =
+                getRollbacksAvailableForImpactLevel(
+                        availableRollbacks, PackageManager.ROLLBACK_USER_IMPACT_HIGH);
+
+        // sort rollbacks based on package name of the first package. This is to have a
+        // deterministic order of rollbacks.
+        List<RollbackInfo> sortedHighImpactRollbacks = highImpactRollbacks.stream().sorted(
+                Comparator.comparing(a -> a.getPackages().get(0).getPackageName())).toList();
+        VersionedPackage firstRollback =
+                sortedHighImpactRollbacks
+                        .get(0)
+                        .getPackages()
+                        .get(0)
+                        .getVersionRolledBackFrom();
+        Slog.i(TAG, "Rolling back high impact rollback for package: "
+                + firstRollback.getPackageName());
+        rollbackPackage(sortedHighImpactRollbacks.get(0), firstRollback, rollbackReason);
+    }
+
+    /**
+     * Rollback all available low impact rollbacks
+     * @param availableRollbacks all available rollbacks
+     * @param rollbackReason reason to rollbacks
+     */
+    @WorkerThread
+    private void rollbackAllLowImpact(
+            List<RollbackInfo> availableRollbacks, @FailureReasons int rollbackReason) {
+        assertInWorkerThread();
+
+        List<RollbackInfo> lowImpactRollbacks = getRollbacksAvailableForImpactLevel(
+                availableRollbacks,
+                PackageManager.ROLLBACK_USER_IMPACT_LOW);
+        if (useTwoPhaseRollback(lowImpactRollbacks)) {
+            return;
+        }
+
+        Slog.i(TAG, "Rolling back all available low impact rollbacks");
+        logCrashRecoveryEvent(Log.DEBUG, "Rolling back all available. Reason: " + rollbackReason);
+        // Add all rollback ids to mPendingStagedRollbackIds, so that we do not reboot before all
+        // pending staged rollbacks are handled.
+        for (RollbackInfo rollback : lowImpactRollbacks) {
+            if (rollback.isStaged()) {
+                mPendingStagedRollbackIds.add(rollback.getRollbackId());
+            }
+        }
+
+        for (RollbackInfo rollback : lowImpactRollbacks) {
+            VersionedPackage firstRollback =
+                    rollback.getPackages().get(0).getVersionRolledBackFrom();
+            rollbackPackage(rollback, firstRollback, rollbackReason);
+        }
+    }
+
+    private List<RollbackInfo> getRollbacksAvailableForImpactLevel(
+            List<RollbackInfo> availableRollbacks, int impactLevel) {
+        return availableRollbacks.stream()
+                .filter(rollbackInfo -> rollbackInfo.getRollbackImpactLevel() == impactLevel)
+                .toList();
+    }
+
+    private int getMinRollbackImpactLevel(List<RollbackInfo> availableRollbacks) {
+        return availableRollbacks.stream()
+                .mapToInt(RollbackInfo::getRollbackImpactLevel)
+                .min()
+                .orElse(-1);
+    }
+
+    private int getUserImpactBasedOnRollbackImpactLevel(List<RollbackInfo> availableRollbacks) {
+        int impact = PackageHealthObserverImpact.USER_IMPACT_LEVEL_0;
+        int minImpact = getMinRollbackImpactLevel(availableRollbacks);
+        switch (minImpact) {
+            case PackageManager.ROLLBACK_USER_IMPACT_LOW:
+                impact = PackageHealthObserverImpact.USER_IMPACT_LEVEL_70;
+                break;
+            case PackageManager.ROLLBACK_USER_IMPACT_HIGH:
+                if (!SystemProperties.getBoolean(PROP_DISABLE_HIGH_IMPACT_ROLLBACK_FLAG, false)) {
+                    impact = PackageHealthObserverImpact.USER_IMPACT_LEVEL_90;
+                }
+                break;
+            default:
+                impact = PackageHealthObserverImpact.USER_IMPACT_LEVEL_0;
+        }
+        return impact;
+    }
+
+    @VisibleForTesting
+    Handler getHandler() {
+        return mHandler;
+    }
+}
diff --git a/service/java/com/android/server/rollback/WatchdogRollbackLogger.java b/service/java/com/android/server/rollback/WatchdogRollbackLogger.java
new file mode 100644
index 0000000..9cfed02
--- /dev/null
+++ b/service/java/com/android/server/rollback/WatchdogRollbackLogger.java
@@ -0,0 +1,255 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+package com.android.server.rollback;
+
+import static com.android.server.crashrecovery.CrashRecoveryUtils.logCrashRecoveryEvent;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_APP_CRASH;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_APP_NOT_RESPONDING;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_BOOT_LOOPING;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_EXPLICIT_HEALTH_CHECK;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_NATIVE_CRASH;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_NATIVE_CRASH_DURING_BOOT;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_UNKNOWN;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_BOOT_TRIGGERED;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_FAILURE;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_INITIATE;
+import static com.android.server.crashrecovery.proto.CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_SUCCESS;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.content.Context;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageInstaller;
+import android.content.pm.PackageManager;
+import android.content.pm.VersionedPackage;
+import android.content.rollback.PackageRollbackInfo;
+import android.content.rollback.RollbackInfo;
+import android.os.SystemProperties;
+import android.text.TextUtils;
+import android.util.Log;
+import android.util.Slog;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.PackageWatchdog;
+import com.android.server.crashrecovery.proto.CrashRecoveryStatsLog;
+
+import java.util.List;
+
+/**
+ * This class handles the logic for logging Watchdog-triggered rollback events.
+ * @hide
+ */
+public final class WatchdogRollbackLogger {
+    private static final String TAG = "WatchdogRollbackLogger";
+
+    private static final String LOGGING_PARENT_KEY = "android.content.pm.LOGGING_PARENT";
+
+    private WatchdogRollbackLogger() {
+    }
+
+    @Nullable
+    private static String getLoggingParentName(Context context, @NonNull String packageName) {
+        PackageManager packageManager = context.getPackageManager();
+        try {
+            int flags = PackageManager.MATCH_APEX | PackageManager.GET_META_DATA;
+            ApplicationInfo ai = packageManager.getPackageInfo(packageName, flags).applicationInfo;
+            if (ai.metaData == null) {
+                return null;
+            }
+            return ai.metaData.getString(LOGGING_PARENT_KEY);
+        } catch (Exception e) {
+            Slog.w(TAG, "Unable to discover logging parent package: " + packageName, e);
+            return null;
+        }
+    }
+
+    /**
+     * Returns the logging parent of a given package if it exists, {@code null} otherwise.
+     *
+     * The logging parent is defined by the {@code android.content.pm.LOGGING_PARENT} field in the
+     * metadata of a package's AndroidManifest.xml.
+     */
+    @VisibleForTesting
+    @Nullable
+    static VersionedPackage getLogPackage(Context context,
+            @NonNull VersionedPackage failingPackage) {
+        String logPackageName;
+        VersionedPackage loggingParent;
+        logPackageName = getLoggingParentName(context, failingPackage.getPackageName());
+        if (logPackageName == null) {
+            return null;
+        }
+        try {
+            loggingParent = new VersionedPackage(logPackageName, context.getPackageManager()
+                    .getPackageInfo(logPackageName, 0 /* flags */).getLongVersionCode());
+        } catch (PackageManager.NameNotFoundException e) {
+            return null;
+        }
+        return loggingParent;
+    }
+
+    static void logRollbackStatusOnBoot(Context context, int rollbackId, String logPackageName,
+            List<RollbackInfo> recentlyCommittedRollbacks) {
+        PackageInstaller packageInstaller = context.getPackageManager().getPackageInstaller();
+
+        RollbackInfo rollback = null;
+        for (RollbackInfo info : recentlyCommittedRollbacks) {
+            if (rollbackId == info.getRollbackId()) {
+                rollback = info;
+                break;
+            }
+        }
+
+        if (rollback == null) {
+            Slog.e(TAG, "rollback info not found for last staged rollback: " + rollbackId);
+            return;
+        }
+
+        // Use the version of the logging parent that was installed before
+        // we rolled back for logging purposes.
+        VersionedPackage oldLoggingPackage = null;
+        if (!TextUtils.isEmpty(logPackageName)) {
+            for (PackageRollbackInfo packageRollback : rollback.getPackages()) {
+                if (logPackageName.equals(packageRollback.getPackageName())) {
+                    oldLoggingPackage = packageRollback.getVersionRolledBackFrom();
+                    break;
+                }
+            }
+        }
+
+        int sessionId = rollback.getCommittedSessionId();
+        PackageInstaller.SessionInfo sessionInfo = packageInstaller.getSessionInfo(sessionId);
+        if (sessionInfo == null) {
+            Slog.e(TAG, "On boot completed, could not load session id " + sessionId);
+            return;
+        }
+
+        if (sessionInfo.isStagedSessionApplied()) {
+            logEvent(oldLoggingPackage,
+                    WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_SUCCESS,
+                    WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_UNKNOWN, "");
+        } else if (sessionInfo.isStagedSessionFailed()) {
+            logEvent(oldLoggingPackage,
+                    WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_FAILURE,
+                    WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_UNKNOWN, "");
+        }
+    }
+
+    /**
+     * Log a Watchdog rollback event to statsd.
+     *
+     * @param logPackage the package to associate the rollback with.
+     * @param type the state of the rollback.
+     * @param rollbackReason the reason Watchdog triggered a rollback, if known.
+     * @param failingPackageName the failing package or process which triggered the rollback.
+     */
+    public static void logEvent(@Nullable VersionedPackage logPackage, int type,
+            int rollbackReason, @NonNull String failingPackageName) {
+        String logMsg = "Watchdog event occurred with type: " + rollbackTypeToString(type)
+                + " logPackage: " + logPackage
+                + " rollbackReason: " + rollbackReasonToString(rollbackReason)
+                + " failedPackageName: " + failingPackageName;
+        Slog.i(TAG, logMsg);
+        if (logPackage != null) {
+            CrashRecoveryStatsLog.write(
+                    CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED,
+                    type,
+                    logPackage.getPackageName(),
+                    logPackage.getVersionCode(),
+                    rollbackReason,
+                    failingPackageName,
+                    new byte[]{});
+        } else {
+            // In the case that the log package is null, still log an empty string as an
+            // indication that retrieving the logging parent failed.
+            CrashRecoveryStatsLog.write(
+                    CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED,
+                    type,
+                    "",
+                    0,
+                    rollbackReason,
+                    failingPackageName,
+                    new byte[]{});
+        }
+
+        logTestProperties(logMsg);
+    }
+
+    /**
+     * Writes properties which will be used by rollback tests to check if particular rollback
+     * events have occurred.
+     */
+    private static void logTestProperties(String logMsg) {
+        // This property should be on only during the tests
+        if (!SystemProperties.getBoolean("persist.sys.rollbacktest.enabled", false)) {
+            return;
+        }
+        logCrashRecoveryEvent(Log.DEBUG, logMsg);
+    }
+
+    @VisibleForTesting
+    static int mapFailureReasonToMetric(@PackageWatchdog.FailureReasons int failureReason) {
+        switch (failureReason) {
+            case PackageWatchdog.FAILURE_REASON_NATIVE_CRASH:
+                return WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_NATIVE_CRASH;
+            case PackageWatchdog.FAILURE_REASON_EXPLICIT_HEALTH_CHECK:
+                return WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_EXPLICIT_HEALTH_CHECK;
+            case PackageWatchdog.FAILURE_REASON_APP_CRASH:
+                return WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_APP_CRASH;
+            case PackageWatchdog.FAILURE_REASON_APP_NOT_RESPONDING:
+                return WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_APP_NOT_RESPONDING;
+            case PackageWatchdog.FAILURE_REASON_BOOT_LOOP:
+                return WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_BOOT_LOOPING;
+            default:
+                return WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_UNKNOWN;
+        }
+    }
+
+    private static String rollbackTypeToString(int type) {
+        switch (type) {
+            case WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_INITIATE:
+                return "ROLLBACK_INITIATE";
+            case WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_SUCCESS:
+                return "ROLLBACK_SUCCESS";
+            case WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_FAILURE:
+                return "ROLLBACK_FAILURE";
+            case WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_BOOT_TRIGGERED:
+                return "ROLLBACK_BOOT_TRIGGERED";
+            default:
+                return "UNKNOWN";
+        }
+    }
+
+    private static String rollbackReasonToString(int reason) {
+        switch (reason) {
+            case WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_NATIVE_CRASH:
+                return "REASON_NATIVE_CRASH";
+            case WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_EXPLICIT_HEALTH_CHECK:
+                return "REASON_EXPLICIT_HEALTH_CHECK";
+            case WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_APP_CRASH:
+                return "REASON_APP_CRASH";
+            case WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_APP_NOT_RESPONDING:
+                return "REASON_APP_NOT_RESPONDING";
+            case WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_NATIVE_CRASH_DURING_BOOT:
+                return "REASON_NATIVE_CRASH_DURING_BOOT";
+            case WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_REASON__REASON_BOOT_LOOPING:
+                return "REASON_BOOT_LOOP";
+            default:
+                return "UNKNOWN";
+        }
+    }
+}
diff --git a/service/java/com/android/util/ArrayUtils.java b/service/java/com/android/util/ArrayUtils.java
new file mode 100644
index 0000000..29ff7cc
--- /dev/null
+++ b/service/java/com/android/util/ArrayUtils.java
@@ -0,0 +1,42 @@
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
+package android.util;
+
+import android.annotation.Nullable;
+
+/**
+ * Copied over from frameworks/base/core/java/com/android/internal/util/ArrayUtils.java
+ *
+ * @hide
+ */
+public class ArrayUtils {
+    private ArrayUtils() { /* cannot be instantiated */ }
+
+    /**
+     * Checks if given array is null or has zero elements.
+     */
+    public static boolean isEmpty(@Nullable int[] array) {
+        return array == null || array.length == 0;
+    }
+
+    /**
+     * True if the byte array is null or has length 0.
+     */
+    public static boolean isEmpty(@Nullable byte[] array) {
+        return array == null || array.length == 0;
+    }
+}
diff --git a/service/java/com/android/util/FileUtils.java b/service/java/com/android/util/FileUtils.java
new file mode 100644
index 0000000..d60a9b9
--- /dev/null
+++ b/service/java/com/android/util/FileUtils.java
@@ -0,0 +1,117 @@
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
+package android.util;
+
+import android.annotation.Nullable;
+
+import java.io.BufferedInputStream;
+import java.io.ByteArrayOutputStream;
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.io.InputStream;
+
+/**
+ * Bits and pieces copied from hidden API of android.os.FileUtils.
+ *
+ * @hide
+ */
+public class FileUtils {
+    /**
+     * Read a text file into a String, optionally limiting the length.
+     *
+     * @param file     to read (will not seek, so things like /proc files are OK)
+     * @param max      length (positive for head, negative of tail, 0 for no limit)
+     * @param ellipsis to add of the file was truncated (can be null)
+     * @return the contents of the file, possibly truncated
+     * @throws IOException if something goes wrong reading the file
+     * @hide
+     */
+    public static @Nullable String readTextFile(@Nullable File file, @Nullable int max,
+            @Nullable String ellipsis) throws IOException {
+        InputStream input = new FileInputStream(file);
+        // wrapping a BufferedInputStream around it because when reading /proc with unbuffered
+        // input stream, bytes read not equal to buffer size is not necessarily the correct
+        // indication for EOF; but it is true for BufferedInputStream due to its implementation.
+        BufferedInputStream bis = new BufferedInputStream(input);
+        try {
+            long size = file.length();
+            if (max > 0 || (size > 0 && max == 0)) {  // "head" mode: read the first N bytes
+                if (size > 0 && (max == 0 || size < max)) max = (int) size;
+                byte[] data = new byte[max + 1];
+                int length = bis.read(data);
+                if (length <= 0) return "";
+                if (length <= max) return new String(data, 0, length);
+                if (ellipsis == null) return new String(data, 0, max);
+                return new String(data, 0, max) + ellipsis;
+            } else if (max < 0) {  // "tail" mode: keep the last N
+                int len;
+                boolean rolled = false;
+                byte[] last = null;
+                byte[] data = null;
+                do {
+                    if (last != null) rolled = true;
+                    byte[] tmp = last;
+                    last = data;
+                    data = tmp;
+                    if (data == null) data = new byte[-max];
+                    len = bis.read(data);
+                } while (len == data.length);
+
+                if (last == null && len <= 0) return "";
+                if (last == null) return new String(data, 0, len);
+                if (len > 0) {
+                    rolled = true;
+                    System.arraycopy(last, len, last, 0, last.length - len);
+                    System.arraycopy(data, 0, last, last.length - len, len);
+                }
+                if (ellipsis == null || !rolled) return new String(last);
+                return ellipsis + new String(last);
+            } else {  // "cat" mode: size unknown, read it all in streaming fashion
+                ByteArrayOutputStream contents = new ByteArrayOutputStream();
+                int len;
+                byte[] data = new byte[1024];
+                do {
+                    len = bis.read(data);
+                    if (len > 0) contents.write(data, 0, len);
+                } while (len == data.length);
+                return contents.toString();
+            }
+        } finally {
+            bis.close();
+            input.close();
+        }
+    }
+
+    /**
+     * Perform an fsync on the given FileOutputStream. The stream at this
+     * point must be flushed but not yet closed.
+     *
+     * @hide
+     */
+    public static boolean sync(FileOutputStream stream) {
+        try {
+            if (stream != null) {
+                stream.getFD().sync();
+            }
+            return true;
+        } catch (IOException e) {
+        }
+        return false;
+    }
+}
diff --git a/service/java/com/android/util/LongArrayQueue.java b/service/java/com/android/util/LongArrayQueue.java
new file mode 100644
index 0000000..9a24ada
--- /dev/null
+++ b/service/java/com/android/util/LongArrayQueue.java
@@ -0,0 +1,188 @@
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
+package android.util;
+
+import libcore.util.EmptyArray;
+
+import java.util.NoSuchElementException;
+
+/**
+ * Copied from frameworks/base/core/java/android/util/LongArrayQueue.java
+ *
+ * @hide
+ */
+public class LongArrayQueue {
+
+    private long[] mValues;
+    private int mSize;
+    private int mHead;
+    private int mTail;
+
+    private long[] newUnpaddedLongArray(int num) {
+        return new long[num];
+    }
+    /**
+     * Initializes a queue with the given starting capacity.
+     *
+     * @param initialCapacity the capacity.
+     */
+    public LongArrayQueue(int initialCapacity) {
+        if (initialCapacity == 0) {
+            mValues = EmptyArray.LONG;
+        } else {
+            mValues = newUnpaddedLongArray(initialCapacity);
+        }
+        mSize = 0;
+        mHead = mTail = 0;
+    }
+
+    /**
+     * Initializes a queue with default starting capacity.
+     */
+    public LongArrayQueue() {
+        this(16);
+    }
+
+    /** @hide */
+    public static int growSize(int currentSize) {
+        return currentSize <= 4 ? 8 : currentSize * 2;
+    }
+
+    private void grow() {
+        if (mSize < mValues.length) {
+            throw new IllegalStateException("Queue not full yet!");
+        }
+        final int newSize = growSize(mSize);
+        final long[] newArray = newUnpaddedLongArray(newSize);
+        final int r = mValues.length - mHead; // Number of elements on and to the right of head.
+        System.arraycopy(mValues, mHead, newArray, 0, r);
+        System.arraycopy(mValues, 0, newArray, r, mHead);
+        mValues = newArray;
+        mHead = 0;
+        mTail = mSize;
+    }
+
+    /**
+     * Returns the number of elements in the queue.
+     */
+    public int size() {
+        return mSize;
+    }
+
+    /**
+     * Removes all elements from this queue.
+     */
+    public void clear() {
+        mSize = 0;
+        mHead = mTail = 0;
+    }
+
+    /**
+     * Adds a value to the tail of the queue.
+     *
+     * @param value the value to be added.
+     */
+    public void addLast(long value) {
+        if (mSize == mValues.length) {
+            grow();
+        }
+        mValues[mTail] = value;
+        mTail = (mTail + 1) % mValues.length;
+        mSize++;
+    }
+
+    /**
+     * Removes an element from the head of the queue.
+     *
+     * @return the element at the head of the queue.
+     * @throws NoSuchElementException if the queue is empty.
+     */
+    public long removeFirst() {
+        if (mSize == 0) {
+            throw new NoSuchElementException("Queue is empty!");
+        }
+        final long ret = mValues[mHead];
+        mHead = (mHead + 1) % mValues.length;
+        mSize--;
+        return ret;
+    }
+
+    /**
+     * Returns the element at the given position from the head of the queue, where 0 represents the
+     * head of the queue.
+     *
+     * @param position the position from the head of the queue.
+     * @return the element found at the given position.
+     * @throws IndexOutOfBoundsException if {@code position} < {@code 0} or
+     *                                   {@code position} >= {@link #size()}
+     */
+    public long get(int position) {
+        if (position < 0 || position >= mSize) {
+            throw new IndexOutOfBoundsException("Index " + position
+                + " not valid for a queue of size " + mSize);
+        }
+        final int index = (mHead + position) % mValues.length;
+        return mValues[index];
+    }
+
+    /**
+     * Returns the element at the head of the queue, without removing it.
+     *
+     * @return the element at the head of the queue.
+     * @throws NoSuchElementException if the queue is empty
+     */
+    public long peekFirst() {
+        if (mSize == 0) {
+            throw new NoSuchElementException("Queue is empty!");
+        }
+        return mValues[mHead];
+    }
+
+    /**
+     * Returns the element at the tail of the queue.
+     *
+     * @return the element at the tail of the queue.
+     * @throws NoSuchElementException if the queue is empty.
+     */
+    public long peekLast() {
+        if (mSize == 0) {
+            throw new NoSuchElementException("Queue is empty!");
+        }
+        final int index = (mTail == 0) ? mValues.length - 1 : mTail - 1;
+        return mValues[index];
+    }
+
+    /**
+     * {@inheritDoc}
+     */
+    @Override
+    public String toString() {
+        if (mSize <= 0) {
+            return "{}";
+        }
+
+        final StringBuilder buffer = new StringBuilder(mSize * 64);
+        buffer.append('{');
+        buffer.append(get(0));
+        for (int i = 1; i < mSize; i++) {
+            buffer.append(", ");
+            buffer.append(get(i));
+        }
+        buffer.append('}');
+        return buffer.toString();
+    }
+}
diff --git a/service/java/com/android/util/XmlUtils.java b/service/java/com/android/util/XmlUtils.java
new file mode 100644
index 0000000..488b531
--- /dev/null
+++ b/service/java/com/android/util/XmlUtils.java
@@ -0,0 +1,66 @@
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
+package android.util;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+/**
+ *  Bits and pieces copied from hidden API of
+ *  frameworks/base/core/java/com/android/internal/util/XmlUtils.java
+ *
+ * @hide
+ */
+public class XmlUtils {
+
+    /** @hide */
+    public static final void beginDocument(XmlPullParser parser, String firstElementName)
+            throws XmlPullParserException, IOException {
+        int type;
+        while ((type = parser.next()) != parser.START_TAG
+            && type != parser.END_DOCUMENT) {
+            // Do nothing
+        }
+
+        if (type != parser.START_TAG) {
+            throw new XmlPullParserException("No start tag found");
+        }
+
+        if (!parser.getName().equals(firstElementName)) {
+            throw new XmlPullParserException("Unexpected start tag: found " + parser.getName()
+                + ", expected " + firstElementName);
+        }
+    }
+
+    /** @hide */
+    public static boolean nextElementWithin(XmlPullParser parser, int outerDepth)
+            throws IOException, XmlPullParserException {
+        for (;;) {
+            int type = parser.next();
+            if (type == XmlPullParser.END_DOCUMENT
+                    || (type == XmlPullParser.END_TAG && parser.getDepth() == outerDepth)) {
+                return false;
+            }
+            if (type == XmlPullParser.START_TAG
+                    && parser.getDepth() == outerDepth + 1) {
+                return true;
+            }
+        }
+    }
+}
```

