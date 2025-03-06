```diff
diff --git a/framework/Android.bp b/framework/Android.bp
index 0d03367..40d61d3 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -20,13 +20,24 @@ java_sdk_library {
     name: "framework-crashrecovery",
     srcs: [
         "java/**/*.java",
+        ":framework-crashrecovery-sources",
     ],
     apex_available: [
-            "com.android.crashrecovery",
-     ],
+        "com.android.crashrecovery",
+    ],
+    static_libs: ["android.crashrecovery.flags-aconfig-java"],
+    libs: [
+        "modules-utils-preconditions",
+    ],
+    permitted_packages: [
+        "android.service.watchdog",
+        "android.crashrecovery",
+    ],
     defaults: ["framework-module-defaults"],
     sdk_version: "module_current",
     impl_library_visibility: [
-            "//packages/modules/CrashRecovery:__subpackages__"
+        "//packages/modules/CrashRecovery:__subpackages__",
+        "//frameworks/base/tests:__subpackages__",
+        "//cts:__subpackages__",
     ],
-}
\ No newline at end of file
+}
diff --git a/framework/api/system-current.txt b/framework/api/system-current.txt
index d802177..68429ea 100644
--- a/framework/api/system-current.txt
+++ b/framework/api/system-current.txt
@@ -1 +1,28 @@
 // Signature format: 2.0
+package android.service.watchdog {
+
+  public abstract class ExplicitHealthCheckService extends android.app.Service {
+    ctor public ExplicitHealthCheckService();
+    method public final void notifyHealthCheckPassed(@NonNull String);
+    method @NonNull public final android.os.IBinder onBind(@NonNull android.content.Intent);
+    method public abstract void onCancelHealthCheck(@NonNull String);
+    method @NonNull public abstract java.util.List<java.lang.String> onGetRequestedPackages();
+    method @NonNull public abstract java.util.List<android.service.watchdog.ExplicitHealthCheckService.PackageConfig> onGetSupportedPackages();
+    method public abstract void onRequestHealthCheck(@NonNull String);
+    method @FlaggedApi("android.crashrecovery.flags.enable_crashrecovery") public final void setHealthCheckResultCallback(@Nullable java.util.concurrent.Executor, @Nullable java.util.function.Consumer<android.os.Bundle>);
+    field public static final String BIND_PERMISSION = "android.permission.BIND_EXPLICIT_HEALTH_CHECK_SERVICE";
+    field @FlaggedApi("android.crashrecovery.flags.enable_crashrecovery") public static final String EXTRA_HEALTH_CHECK_PASSED_PACKAGE = "android.service.watchdog.extra.HEALTH_CHECK_PASSED_PACKAGE";
+    field public static final String SERVICE_INTERFACE = "android.service.watchdog.ExplicitHealthCheckService";
+  }
+
+  public static final class ExplicitHealthCheckService.PackageConfig implements android.os.Parcelable {
+    ctor public ExplicitHealthCheckService.PackageConfig(@NonNull String, long);
+    method public int describeContents();
+    method public long getHealthCheckTimeoutMillis();
+    method @NonNull public String getPackageName();
+    method public void writeToParcel(android.os.Parcel, int);
+    field @NonNull public static final android.os.Parcelable.Creator<android.service.watchdog.ExplicitHealthCheckService.PackageConfig> CREATOR;
+  }
+
+}
+
diff --git a/framework/api/system-lint-baseline.txt b/framework/api/system-lint-baseline.txt
new file mode 100644
index 0000000..8d5603c
--- /dev/null
+++ b/framework/api/system-lint-baseline.txt
@@ -0,0 +1,37 @@
+// Baseline format: 1.0
+InvalidNullabilityOverride: android.service.watchdog.ExplicitHealthCheckService#onBind(android.content.Intent) parameter #0:
+    Invalid nullability on type android.content.Intent in parameter `intent` in method `onBind`. Parameter in method override cannot use a non-null type when the corresponding type from the super method is platform-nullness.
+
+
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService:
+    New API must be flagged with @FlaggedApi: class android.service.watchdog.ExplicitHealthCheckService
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService#BIND_PERMISSION:
+    New API must be flagged with @FlaggedApi: field android.service.watchdog.ExplicitHealthCheckService.BIND_PERMISSION
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService#SERVICE_INTERFACE:
+    New API must be flagged with @FlaggedApi: field android.service.watchdog.ExplicitHealthCheckService.SERVICE_INTERFACE
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService#notifyHealthCheckPassed(String):
+    New API must be flagged with @FlaggedApi: method android.service.watchdog.ExplicitHealthCheckService.notifyHealthCheckPassed(String)
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService#onBind(android.content.Intent):
+    New API must be flagged with @FlaggedApi: method android.service.watchdog.ExplicitHealthCheckService.onBind(android.content.Intent)
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService#onCancelHealthCheck(String):
+    New API must be flagged with @FlaggedApi: method android.service.watchdog.ExplicitHealthCheckService.onCancelHealthCheck(String)
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService#onGetRequestedPackages():
+    New API must be flagged with @FlaggedApi: method android.service.watchdog.ExplicitHealthCheckService.onGetRequestedPackages()
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService#onGetSupportedPackages():
+    New API must be flagged with @FlaggedApi: method android.service.watchdog.ExplicitHealthCheckService.onGetSupportedPackages()
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService#onRequestHealthCheck(String):
+    New API must be flagged with @FlaggedApi: method android.service.watchdog.ExplicitHealthCheckService.onRequestHealthCheck(String)
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService.PackageConfig:
+    New API must be flagged with @FlaggedApi: class android.service.watchdog.ExplicitHealthCheckService.PackageConfig
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService.PackageConfig#CREATOR:
+    New API must be flagged with @FlaggedApi: field android.service.watchdog.ExplicitHealthCheckService.PackageConfig.CREATOR
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService.PackageConfig#PackageConfig(String, long):
+    New API must be flagged with @FlaggedApi: constructor android.service.watchdog.ExplicitHealthCheckService.PackageConfig(String,long)
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService.PackageConfig#describeContents():
+    New API must be flagged with @FlaggedApi: method android.service.watchdog.ExplicitHealthCheckService.PackageConfig.describeContents()
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService.PackageConfig#getHealthCheckTimeoutMillis():
+    New API must be flagged with @FlaggedApi: method android.service.watchdog.ExplicitHealthCheckService.PackageConfig.getHealthCheckTimeoutMillis()
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService.PackageConfig#getPackageName():
+    New API must be flagged with @FlaggedApi: method android.service.watchdog.ExplicitHealthCheckService.PackageConfig.getPackageName()
+UnflaggedApi: android.service.watchdog.ExplicitHealthCheckService.PackageConfig#writeToParcel(android.os.Parcel, int):
+    New API must be flagged with @FlaggedApi: method android.service.watchdog.ExplicitHealthCheckService.PackageConfig.writeToParcel(android.os.Parcel,int)
diff --git a/framework/java/com/android/service/watchdog/Foobar.java b/framework/java/com/android/service/watchdog/Foobar.java
deleted file mode 100644
index d888545..0000000
--- a/framework/java/com/android/service/watchdog/Foobar.java
+++ /dev/null
@@ -1,23 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package com.android.service.watchdog;
-
-
-/** @hide */
-public class Foobar {
-
-}
\ No newline at end of file
diff --git a/service/Android.bp b/service/Android.bp
index e756272..9cc28de 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -16,20 +16,74 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-java_sdk_library {
-    name: "service-crashrecovery",
+java_library {
+    name: "crashrecovery-statslog",
+    srcs: [
+        ":statslog-crashrecovery-java-gen",
+    ],
+    libs: [
+        "framework-statsd.stubs.module_lib",
+    ],
+    apex_available: [
+        "com.android.crashrecovery",
+    ],
+    installable: false,
+    min_sdk_version: "35",
+    sdk_version: "system_server_current",
+}
+
+java_defaults {
+    name: "service-crashrecovery-shared",
     srcs: [
         "java/**/*.java",
-     ],
+        ":services-crashrecovery-module-sources",
+        ":service-crashrecovery-shared-srcs",
+    ],
     defaults: [
         "framework-system-server-module-defaults",
     ],
-    permitted_packages: [],
+    static_libs: [
+        "android.crashrecovery.flags-aconfig-java",
+        "crashrecovery-statslog",
+        "modules-utils-preconditions",
+        "modules-utils-backgroundthread",
+        "modules-utils-binary-xml",
+        "modules-utils-fastxmlserializer",
+        "PlatformProperties",
+    ],
+    libs: [
+        "unsupportedappusage",
+        "framework-configinfrastructure.stubs.module_lib",
+        "framework-crashrecovery.impl",
+        "framework-statsd.stubs.module_lib",
+    ],
+    sdk_version: "system_server_current",
+}
+
+java_sdk_library {
+    name: "service-crashrecovery",
+    defaults: ["service-crashrecovery-shared"],
+    permitted_packages: [
+        "com.android.server",
+        "android.crashrecovery",
+    ],
     apex_available: [
         "com.android.crashrecovery",
     ],
-    sdk_version: "module_current",
     impl_library_visibility: [
-            "//packages/modules/CrashRecovery:__subpackages__"
+        "//packages/modules/CrashRecovery:__subpackages__",
+        "//cts:__subpackages__",
+        "//frameworks/base/tests:__subpackages__",
+        "//frameworks/base/services/tests:__subpackages__",
+        "//test/cts-root/tests/packagewatchdog",
+    ],
+    aconfig_declarations: [
+        "android.crashrecovery.flags-aconfig",
     ],
-}
\ No newline at end of file
+    jarjar_rules: "jarjar-rules.txt",
+}
+
+java_library {
+    name: "service-crashrecovery-pre-jarjar",
+    defaults: ["service-crashrecovery-shared"],
+}
diff --git a/service/api/system-server-current.txt b/service/api/system-server-current.txt
index d802177..c10104d 100644
--- a/service/api/system-server-current.txt
+++ b/service/api/system-server-current.txt
@@ -1 +1,51 @@
 // Signature format: 2.0
+package com.android.server {
+
+  @FlaggedApi("android.crashrecovery.flags.enable_crashrecovery") public class PackageWatchdog {
+    method public void dump(@NonNull java.io.PrintWriter);
+    method @NonNull public static com.android.server.PackageWatchdog getInstance(@NonNull android.content.Context);
+    method public static boolean isRecoveryTriggeredReboot();
+    method public void notifyPackageFailure(@NonNull java.util.List<android.content.pm.VersionedPackage>, int);
+    method public void registerHealthObserver(@NonNull com.android.server.PackageWatchdog.PackageHealthObserver, @NonNull java.util.concurrent.Executor);
+    method public void startExplicitHealthCheck(@NonNull com.android.server.PackageWatchdog.PackageHealthObserver, @NonNull java.util.List<java.lang.String>, long);
+    method public void unregisterHealthObserver(@NonNull com.android.server.PackageWatchdog.PackageHealthObserver);
+    field public static final int FAILURE_REASON_APP_CRASH = 3; // 0x3
+    field public static final int FAILURE_REASON_APP_NOT_RESPONDING = 4; // 0x4
+    field public static final int FAILURE_REASON_BOOT_LOOP = 5; // 0x5
+    field public static final int FAILURE_REASON_EXPLICIT_HEALTH_CHECK = 2; // 0x2
+    field public static final int FAILURE_REASON_NATIVE_CRASH = 1; // 0x1
+    field public static final int FAILURE_REASON_UNKNOWN = 0; // 0x0
+    field public static final int USER_IMPACT_THRESHOLD_HIGH = 71; // 0x47
+    field public static final int USER_IMPACT_THRESHOLD_MEDIUM = 20; // 0x14
+    field public static final int USER_IMPACT_THRESHOLD_NONE = 0; // 0x0
+  }
+
+  public static interface PackageWatchdog.PackageHealthObserver {
+    method @NonNull public String getUniqueIdentifier();
+    method public default boolean isPersistent();
+    method public default boolean mayObservePackage(@NonNull String);
+    method public default int onBootLoop(int);
+    method public default boolean onExecuteBootLoopMitigation(int);
+    method public boolean onExecuteHealthCheckMitigation(@Nullable android.content.pm.VersionedPackage, int, int);
+    method public int onHealthCheckFailed(@Nullable android.content.pm.VersionedPackage, int, int);
+  }
+
+}
+
+package com.android.server.rollback {
+
+  @FlaggedApi("android.crashrecovery.flags.enable_crashrecovery") public final class RollbackPackageHealthObserver implements com.android.server.PackageWatchdog.PackageHealthObserver {
+    ctor public RollbackPackageHealthObserver(@NonNull android.content.Context);
+    method @NonNull public String getUniqueIdentifier();
+    method public boolean isPersistent();
+    method public boolean mayObservePackage(@NonNull String);
+    method @AnyThread @NonNull public void notifyRollbackAvailable(@NonNull android.content.rollback.RollbackInfo);
+    method @AnyThread public void onBootCompletedAsync();
+    method public int onBootLoop(int);
+    method public boolean onExecuteBootLoopMitigation(int);
+    method public boolean onExecuteHealthCheckMitigation(@Nullable android.content.pm.VersionedPackage, int, int);
+    method public int onHealthCheckFailed(@Nullable android.content.pm.VersionedPackage, int, int);
+  }
+
+}
+
diff --git a/service/jarjar-rules.txt b/service/jarjar-rules.txt
new file mode 100644
index 0000000..253d6e4
--- /dev/null
+++ b/service/jarjar-rules.txt
@@ -0,0 +1,11 @@
+rule android.crashrecovery.flags.** android.crashrecovery.server.flags.@1
+rule android.sysprop.** com.android.server.crashrecovery.sysprop.@1
+rule com.android.server.crashrecovery.proto.** com.android.server.crashrecovery.module.proto.@1
+rule com.android.modules.utils.** com.android.server.crashrecovery.modules.utils.@1
+rule com.android.internal.util.** com.android.server.crashrecovery.internal.util.@1
+
+rule android.util.LongArrayQueue com.android.server.crashrecovery.util.LongArrayQueue
+rule android.util.IndentingPrintWriter com.android.server.crashrecovery.util.IndentingPrintWriter
+rule android.util.ArrayUtils com.android.server.crashrecovery.ArrayUtils
+rule android.util.XmlUtils com.android.server.crashrecovery.XmlUtils
+rule android.util.FileUtils com.android.server.crashrecovery.FileUtils
```

