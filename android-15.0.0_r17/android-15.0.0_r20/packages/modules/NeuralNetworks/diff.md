```diff
diff --git a/NNAPI_OWNERS b/NNAPI_OWNERS
index a0325c5ec..9e90eb202 100644
--- a/NNAPI_OWNERS
+++ b/NNAPI_OWNERS
@@ -1,5 +1,7 @@
 ianhua@google.com
 mattalexander@google.com
 pszczepaniak@google.com
+shiqing@google.com
+sandeepbandaru@google.com
 butlermichael@google.com #{LAST_RESORT_SUGGESTION}
 miaowang@google.com #{LAST_RESORT_SUGGESTION}
diff --git a/apex/Android.bp b/apex/Android.bp
index 464419a82..296f1874e 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -54,6 +54,67 @@ apex_defaults {
 
 apex {
     name: "com.android.neuralnetworks",
-    defaults: ["com.android.neuralnetworks-defaults"],
+    defaults: [
+        "com.android.neuralnetworks-defaults",
+    ],
     manifest: "manifest.json",
+    prebuilts: ["current_sdkinfo"],
+    bootclasspath_fragments: select(release_flag("RELEASE_ONDEVICE_INTELLIGENCE_MODULE"), {
+        true: ["com.android.ondeviceintelligence-bootclasspath-fragment"],
+        default: [],
+    }),
+    systemserverclasspath_fragments: select(release_flag("RELEASE_ONDEVICE_INTELLIGENCE_MODULE"), {
+        true: ["com.android.ondeviceintelligence-systemserverclasspath-fragment"],
+        default: [],
+    }),
+}
+
+sdk {
+    enabled: select(release_flag("RELEASE_ONDEVICE_INTELLIGENCE_MODULE"), {
+        true: true,
+        default: false,
+    }),
+    name: "neuralnetworks-module-sdk",
+    apexes: [
+        // Adds exportable dependencies of the APEX to the sdk,
+        // e.g. *classpath_fragments.
+        "com.android.neuralnetworks",
+    ],
+}
+
+// Encapsulate the contributions made by com.android.neuralnetworks to the bootclasspath.
+bootclasspath_fragment {
+    enabled: select(release_flag("RELEASE_ONDEVICE_INTELLIGENCE_MODULE"), {
+        true: true,
+        default: false,
+    }),
+    name: "com.android.ondeviceintelligence-bootclasspath-fragment",
+    contents: ["framework-ondeviceintelligence"],
+    apex_available: ["com.android.neuralnetworks"],
+    hidden_api: {
+        split_packages: ["*"],
+    },
+    additional_stubs: [
+        "android-non-updatable",
+    ],
+    // The bootclasspath_fragments that provide APIs on which this depends.
+    fragments: [
+        {
+            apex: "com.android.art",
+            module: "art-bootclasspath-fragment",
+        },
+    ],
+}
+
+// Encapsulate the contributions made by the com.android.crashrecovery to the systemserverclasspath.
+systemserverclasspath_fragment {
+    // This fragment will be enabled using release_crashrecovery_module flag
+    enabled: select(release_flag("RELEASE_ONDEVICE_INTELLIGENCE_MODULE"), {
+        true: true,
+        default: false,
+    }),
+
+    name: "com.android.ondeviceintelligence-systemserverclasspath-fragment",
+    contents: ["service-ondeviceintelligence"],
+    apex_available: ["com.android.neuralnetworks"],
 }
diff --git a/driver/sample/Android.bp b/driver/sample/Android.bp
index 85a29c37d..d8ed0448d 100644
--- a/driver/sample/Android.bp
+++ b/driver/sample/Android.bp
@@ -146,5 +146,12 @@ cc_fuzz {
         cc: [
             "butlermichael@google.com",
         ],
+        triage_assignee: "waghpawan@google.com",
+        componentid: 195575,
+        description: "The fuzzer targets the APIs of libneuralnetworks_common",
+        vector: "host_access",
+        service_privilege: "nsi",
+        users: "single_user",
+        fuzzed_code_usage: "experimental",
     },
 }
diff --git a/flags/Android.bp b/flags/Android.bp
new file mode 100644
index 000000000..78dae684e
--- /dev/null
+++ b/flags/Android.bp
@@ -0,0 +1,39 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// OnDeviceIntelligence
+aconfig_declarations {
+    name: "android.app.ondeviceintelligence-aconfig",
+    exportable: true,
+    package: "android.app.ondeviceintelligence.flags",
+    container: "system",
+    srcs: ["ondevice_intelligence.aconfig"],
+}
+
+java_aconfig_library {
+    name: "android.app.ondeviceintelligence-aconfig-java",
+    aconfig_declarations: "android.app.ondeviceintelligence-aconfig",
+    defaults: ["framework-minus-apex-aconfig-java-defaults"],
+    min_sdk_version: "35",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.neuralnetworks",
+    ],
+}
diff --git a/flags/ondevice_intelligence.aconfig b/flags/ondevice_intelligence.aconfig
new file mode 100644
index 000000000..a8574527c
--- /dev/null
+++ b/flags/ondevice_intelligence.aconfig
@@ -0,0 +1,17 @@
+package: "android.app.ondeviceintelligence.flags"
+container: "system"
+
+flag {
+    name: "enable_on_device_intelligence"
+    is_exported: true
+    namespace: "ondeviceintelligence"
+    description: "Make methods on OnDeviceIntelligenceManager available for local inference."
+    bug: "304755128"
+}
+flag {
+    name: "enable_on_device_intelligence_module"
+    is_exported: true
+    namespace: "ondeviceintelligence"
+    description: "Enable migration to mainline module and related changes."
+    bug: "376427781"
+}
diff --git a/framework/Android.bp b/framework/Android.bp
new file mode 100644
index 000000000..1d6210d03
--- /dev/null
+++ b/framework/Android.bp
@@ -0,0 +1,82 @@
+// Copyright (C) 2022 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_sdk_library {
+    name: "framework-ondeviceintelligence-platform",
+    srcs: [
+        ":framework-ondeviceintelligence-sources-platform",
+    ],
+    defaults: ["framework-non-updatable-unbundled-defaults"],
+    impl_library_visibility: [
+        "//frameworks/base:__subpackages__",
+    ],
+    static_libs: [
+        "android.app.ondeviceintelligence-aconfig-java",
+    ],
+    aidl: {
+        include_dirs: [
+            "frameworks/base/core/java",
+            "frameworks/base/packages/NeuralNetworks/framework/platform/java",
+            "frameworks/native/aidl/binder", // For PersistableBundle.aidl
+        ],
+    },
+}
+
+java_sdk_library {
+    name: "framework-ondeviceintelligence",
+    srcs: [
+        ":framework-ondeviceintelligence-sources",
+        ":module-utils-future-aidls",
+    ],
+    defaults: ["framework-module-defaults"],
+    sdk_version: "module_current",
+    apex_available: [
+        "com.android.neuralnetworks",
+        "//apex_available:platform",
+    ],
+    permitted_packages: [
+        "android.app.ondeviceintelligence",
+        "android.service.ondeviceintelligence",
+        "com.android.neuralnetworks.framework.jarjar",
+        "com.android.modules.utils",
+    ],
+    impl_library_visibility: [
+        "//packages/modules/NeuralNetworks:__subpackages__",
+        "//frameworks/base:__subpackages__",
+    ],
+    min_sdk_version: "35",
+    static_libs: [
+        "android.app.ondeviceintelligence-aconfig-java",
+        "modules-utils-preconditions",
+        "modules-utils-infra",
+    ],
+    aidl: {
+        include_dirs: [
+            "frameworks/base/packages/NeuralNetworks/framework/module/java",
+        ],
+    },
+    libs: [
+        "unsupportedappusage",
+    ],
+    jarjar_rules: "jarjar-rules.txt",
+}
+
+platform_compat_config {
+    name: "framework-ondeviceintelligence-platform-compat-config",
+    src: ":framework-ondeviceintelligence-platform",
+}
diff --git a/framework/OWNERS b/framework/OWNERS
new file mode 100644
index 000000000..9c0e71ccd
--- /dev/null
+++ b/framework/OWNERS
@@ -0,0 +1,5 @@
+# Bug component: 195575
+
+sandeepbandaru@google.com
+shivanker@google.com
+shiqing@google.com
diff --git a/framework/api/current.txt b/framework/api/current.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/framework/api/current.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/framework/api/module-lib-current.txt b/framework/api/module-lib-current.txt
new file mode 100644
index 000000000..50f0d3ab6
--- /dev/null
+++ b/framework/api/module-lib-current.txt
@@ -0,0 +1,9 @@
+// Signature format: 2.0
+package android.app.ondeviceintelligence {
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public class OnDeviceIntelligenceFrameworkInitializer {
+    method public static void registerServiceWrappers();
+  }
+
+}
+
diff --git a/framework/api/module-lib-removed.txt b/framework/api/module-lib-removed.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/framework/api/module-lib-removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/framework/api/removed.txt b/framework/api/removed.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/framework/api/removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/framework/api/system-current.txt b/framework/api/system-current.txt
new file mode 100644
index 000000000..9c8be45f7
--- /dev/null
+++ b/framework/api/system-current.txt
@@ -0,0 +1,178 @@
+// Signature format: 2.0
+package android.app.ondeviceintelligence {
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public interface DownloadCallback {
+    method public void onDownloadCompleted(@NonNull android.os.PersistableBundle);
+    method public void onDownloadFailed(int, @Nullable String, @NonNull android.os.PersistableBundle);
+    method public default void onDownloadProgress(long);
+    method public default void onDownloadStarted(long);
+    field public static final int DOWNLOAD_FAILURE_STATUS_DOWNLOADING = 3; // 0x3
+    field public static final int DOWNLOAD_FAILURE_STATUS_NETWORK_FAILURE = 2; // 0x2
+    field public static final int DOWNLOAD_FAILURE_STATUS_NOT_ENOUGH_DISK_SPACE = 1; // 0x1
+    field public static final int DOWNLOAD_FAILURE_STATUS_UNAVAILABLE = 4; // 0x4
+    field public static final int DOWNLOAD_FAILURE_STATUS_UNKNOWN = 0; // 0x0
+  }
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public final class Feature implements android.os.Parcelable {
+    method public int describeContents();
+    method @NonNull public android.os.PersistableBundle getFeatureParams();
+    method public int getId();
+    method @Nullable public String getModelName();
+    method @Nullable public String getName();
+    method public int getType();
+    method public int getVariant();
+    method public void writeToParcel(@NonNull android.os.Parcel, int);
+    field @NonNull public static final android.os.Parcelable.Creator<android.app.ondeviceintelligence.Feature> CREATOR;
+  }
+
+  public static final class Feature.Builder {
+    ctor public Feature.Builder(int);
+    method @NonNull public android.app.ondeviceintelligence.Feature build();
+    method @NonNull public android.app.ondeviceintelligence.Feature.Builder setFeatureParams(@NonNull android.os.PersistableBundle);
+    method @NonNull public android.app.ondeviceintelligence.Feature.Builder setModelName(@NonNull String);
+    method @NonNull public android.app.ondeviceintelligence.Feature.Builder setName(@NonNull String);
+    method @NonNull public android.app.ondeviceintelligence.Feature.Builder setType(int);
+    method @NonNull public android.app.ondeviceintelligence.Feature.Builder setVariant(int);
+  }
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public final class FeatureDetails implements android.os.Parcelable {
+    ctor public FeatureDetails(int, @NonNull android.os.PersistableBundle);
+    ctor public FeatureDetails(int);
+    method public int describeContents();
+    method @NonNull public android.os.PersistableBundle getFeatureDetailParams();
+    method public int getFeatureStatus();
+    method public void writeToParcel(@NonNull android.os.Parcel, int);
+    field @NonNull public static final android.os.Parcelable.Creator<android.app.ondeviceintelligence.FeatureDetails> CREATOR;
+    field public static final int FEATURE_STATUS_AVAILABLE = 3; // 0x3
+    field public static final int FEATURE_STATUS_DOWNLOADABLE = 1; // 0x1
+    field public static final int FEATURE_STATUS_DOWNLOADING = 2; // 0x2
+    field public static final int FEATURE_STATUS_SERVICE_UNAVAILABLE = 4; // 0x4
+    field public static final int FEATURE_STATUS_UNAVAILABLE = 0; // 0x0
+  }
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence_module") public final class InferenceInfo implements android.os.Parcelable {
+    method public int describeContents();
+    method public long getEndTimeMillis();
+    method public long getStartTimeMillis();
+    method public long getSuspendedTimeMillis();
+    method public int getUid();
+    method public void writeToParcel(@NonNull android.os.Parcel, int);
+    field @NonNull public static final android.os.Parcelable.Creator<android.app.ondeviceintelligence.InferenceInfo> CREATOR;
+  }
+
+  public static final class InferenceInfo.Builder {
+    ctor public InferenceInfo.Builder(int);
+    method @NonNull public android.app.ondeviceintelligence.InferenceInfo build();
+    method @NonNull public android.app.ondeviceintelligence.InferenceInfo.Builder setEndTimeMillis(long);
+    method @NonNull public android.app.ondeviceintelligence.InferenceInfo.Builder setStartTimeMillis(long);
+    method @NonNull public android.app.ondeviceintelligence.InferenceInfo.Builder setSuspendedTimeMillis(long);
+  }
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public class OnDeviceIntelligenceException extends java.lang.Exception {
+    ctor public OnDeviceIntelligenceException(int, @NonNull String, @NonNull android.os.PersistableBundle);
+    ctor public OnDeviceIntelligenceException(int, @NonNull android.os.PersistableBundle);
+    ctor public OnDeviceIntelligenceException(int, @NonNull String);
+    ctor public OnDeviceIntelligenceException(int);
+    method public int getErrorCode();
+    method @NonNull public android.os.PersistableBundle getErrorParams();
+    field public static final int ON_DEVICE_INTELLIGENCE_SERVICE_UNAVAILABLE = 100; // 0x64
+    field public static final int PROCESSING_ERROR_BAD_DATA = 2; // 0x2
+    field public static final int PROCESSING_ERROR_BAD_REQUEST = 3; // 0x3
+    field public static final int PROCESSING_ERROR_BUSY = 9; // 0x9
+    field public static final int PROCESSING_ERROR_CANCELLED = 7; // 0x7
+    field public static final int PROCESSING_ERROR_COMPUTE_ERROR = 5; // 0x5
+    field public static final int PROCESSING_ERROR_INTERNAL = 14; // 0xe
+    field public static final int PROCESSING_ERROR_IPC_ERROR = 6; // 0x6
+    field public static final int PROCESSING_ERROR_NOT_AVAILABLE = 8; // 0x8
+    field public static final int PROCESSING_ERROR_REQUEST_NOT_SAFE = 4; // 0x4
+    field public static final int PROCESSING_ERROR_REQUEST_TOO_LARGE = 12; // 0xc
+    field public static final int PROCESSING_ERROR_RESPONSE_NOT_SAFE = 11; // 0xb
+    field public static final int PROCESSING_ERROR_SAFETY_ERROR = 10; // 0xa
+    field public static final int PROCESSING_ERROR_SERVICE_UNAVAILABLE = 15; // 0xf
+    field public static final int PROCESSING_ERROR_SUSPENDED = 13; // 0xd
+    field public static final int PROCESSING_ERROR_UNKNOWN = 1; // 0x1
+    field public static final int PROCESSING_UPDATE_STATUS_CONNECTION_FAILED = 200; // 0xc8
+  }
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public final class OnDeviceIntelligenceManager {
+    method @RequiresPermission(android.Manifest.permission.USE_ON_DEVICE_INTELLIGENCE) public void getFeature(int, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<android.app.ondeviceintelligence.Feature,android.app.ondeviceintelligence.OnDeviceIntelligenceException>);
+    method @RequiresPermission(android.Manifest.permission.USE_ON_DEVICE_INTELLIGENCE) public void getFeatureDetails(@NonNull android.app.ondeviceintelligence.Feature, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<android.app.ondeviceintelligence.FeatureDetails,android.app.ondeviceintelligence.OnDeviceIntelligenceException>);
+    method @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence_module") @NonNull @RequiresPermission(android.Manifest.permission.DUMP) public java.util.List<android.app.ondeviceintelligence.InferenceInfo> getLatestInferenceInfo(long);
+    method @Nullable @RequiresPermission(android.Manifest.permission.USE_ON_DEVICE_INTELLIGENCE) public String getRemoteServicePackageName();
+    method @RequiresPermission(android.Manifest.permission.USE_ON_DEVICE_INTELLIGENCE) public void getVersion(@NonNull java.util.concurrent.Executor, @NonNull java.util.function.LongConsumer);
+    method @RequiresPermission(android.Manifest.permission.USE_ON_DEVICE_INTELLIGENCE) public void listFeatures(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.util.List<android.app.ondeviceintelligence.Feature>,android.app.ondeviceintelligence.OnDeviceIntelligenceException>);
+    method @RequiresPermission(android.Manifest.permission.USE_ON_DEVICE_INTELLIGENCE) public void processRequest(@NonNull android.app.ondeviceintelligence.Feature, @NonNull android.os.Bundle, int, @Nullable android.os.CancellationSignal, @Nullable android.app.ondeviceintelligence.ProcessingSignal, @NonNull java.util.concurrent.Executor, @NonNull android.app.ondeviceintelligence.ProcessingCallback);
+    method @RequiresPermission(android.Manifest.permission.USE_ON_DEVICE_INTELLIGENCE) public void processRequestStreaming(@NonNull android.app.ondeviceintelligence.Feature, @NonNull android.os.Bundle, int, @Nullable android.os.CancellationSignal, @Nullable android.app.ondeviceintelligence.ProcessingSignal, @NonNull java.util.concurrent.Executor, @NonNull android.app.ondeviceintelligence.StreamingProcessingCallback);
+    method @RequiresPermission(android.Manifest.permission.USE_ON_DEVICE_INTELLIGENCE) public void requestFeatureDownload(@NonNull android.app.ondeviceintelligence.Feature, @Nullable android.os.CancellationSignal, @NonNull java.util.concurrent.Executor, @NonNull android.app.ondeviceintelligence.DownloadCallback);
+    method @RequiresPermission(android.Manifest.permission.USE_ON_DEVICE_INTELLIGENCE) public void requestTokenInfo(@NonNull android.app.ondeviceintelligence.Feature, @NonNull android.os.Bundle, @Nullable android.os.CancellationSignal, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<android.app.ondeviceintelligence.TokenInfo,android.app.ondeviceintelligence.OnDeviceIntelligenceException>);
+    field public static final int REQUEST_TYPE_EMBEDDINGS = 2; // 0x2
+    field public static final int REQUEST_TYPE_INFERENCE = 0; // 0x0
+    field public static final int REQUEST_TYPE_PREPARE = 1; // 0x1
+  }
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public interface ProcessingCallback {
+    method public default void onDataAugmentRequest(@NonNull android.os.Bundle, @NonNull java.util.function.Consumer<android.os.Bundle>);
+    method public void onError(@NonNull android.app.ondeviceintelligence.OnDeviceIntelligenceException);
+    method public void onResult(@NonNull android.os.Bundle);
+  }
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public final class ProcessingSignal {
+    ctor public ProcessingSignal();
+    method public void sendSignal(@NonNull android.os.PersistableBundle);
+    method public void setOnProcessingSignalCallback(@NonNull java.util.concurrent.Executor, @Nullable android.app.ondeviceintelligence.ProcessingSignal.OnProcessingSignalCallback);
+  }
+
+  public static interface ProcessingSignal.OnProcessingSignalCallback {
+    method public void onSignalReceived(@NonNull android.os.PersistableBundle);
+  }
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public interface StreamingProcessingCallback extends android.app.ondeviceintelligence.ProcessingCallback {
+    method public void onPartialResult(@NonNull android.os.Bundle);
+  }
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public final class TokenInfo implements android.os.Parcelable {
+    ctor public TokenInfo(long, @NonNull android.os.PersistableBundle);
+    ctor public TokenInfo(long);
+    method public int describeContents();
+    method public long getCount();
+    method @NonNull public android.os.PersistableBundle getInfoParams();
+    method public void writeToParcel(@NonNull android.os.Parcel, int);
+    field @NonNull public static final android.os.Parcelable.Creator<android.app.ondeviceintelligence.TokenInfo> CREATOR;
+  }
+
+}
+
+package android.service.ondeviceintelligence {
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public abstract class OnDeviceIntelligenceService extends android.app.Service {
+    ctor public OnDeviceIntelligenceService();
+    method @Nullable public final android.os.IBinder onBind(@NonNull android.content.Intent);
+    method public abstract void onDownloadFeature(int, @NonNull android.app.ondeviceintelligence.Feature, @Nullable android.os.CancellationSignal, @NonNull android.app.ondeviceintelligence.DownloadCallback);
+    method public abstract void onGetFeature(int, int, @NonNull android.os.OutcomeReceiver<android.app.ondeviceintelligence.Feature,android.app.ondeviceintelligence.OnDeviceIntelligenceException>);
+    method public abstract void onGetFeatureDetails(int, @NonNull android.app.ondeviceintelligence.Feature, @NonNull android.os.OutcomeReceiver<android.app.ondeviceintelligence.FeatureDetails,android.app.ondeviceintelligence.OnDeviceIntelligenceException>);
+    method public abstract void onGetReadOnlyFeatureFileDescriptorMap(@NonNull android.app.ondeviceintelligence.Feature, @NonNull java.util.function.Consumer<java.util.Map<java.lang.String,android.os.ParcelFileDescriptor>>);
+    method public abstract void onGetVersion(@NonNull java.util.function.LongConsumer);
+    method public abstract void onInferenceServiceConnected();
+    method public abstract void onInferenceServiceDisconnected();
+    method public abstract void onListFeatures(int, @NonNull android.os.OutcomeReceiver<java.util.List<android.app.ondeviceintelligence.Feature>,android.app.ondeviceintelligence.OnDeviceIntelligenceException>);
+    method public void onReady();
+    method public final void updateProcessingState(@NonNull android.os.Bundle, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<android.os.PersistableBundle,android.app.ondeviceintelligence.OnDeviceIntelligenceException>);
+    field public static final String SERVICE_INTERFACE = "android.service.ondeviceintelligence.OnDeviceIntelligenceService";
+  }
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence") public abstract class OnDeviceSandboxedInferenceService extends android.app.Service {
+    ctor public OnDeviceSandboxedInferenceService();
+    method public final void fetchFeatureFileDescriptorMap(@NonNull android.app.ondeviceintelligence.Feature, @NonNull java.util.concurrent.Executor, @NonNull java.util.function.Consumer<java.util.Map<java.lang.String,android.os.ParcelFileDescriptor>>);
+    method @NonNull public java.util.concurrent.Executor getCallbackExecutor();
+    method public final void getReadOnlyFileDescriptor(@NonNull String, @NonNull java.util.concurrent.Executor, @NonNull java.util.function.Consumer<android.os.ParcelFileDescriptor>) throws java.io.FileNotFoundException;
+    method @Nullable public final android.os.IBinder onBind(@NonNull android.content.Intent);
+    method @NonNull public abstract void onProcessRequest(int, @NonNull android.app.ondeviceintelligence.Feature, @NonNull android.os.Bundle, int, @Nullable android.os.CancellationSignal, @Nullable android.app.ondeviceintelligence.ProcessingSignal, @NonNull android.app.ondeviceintelligence.ProcessingCallback);
+    method @NonNull public abstract void onProcessRequestStreaming(int, @NonNull android.app.ondeviceintelligence.Feature, @NonNull android.os.Bundle, int, @Nullable android.os.CancellationSignal, @Nullable android.app.ondeviceintelligence.ProcessingSignal, @NonNull android.app.ondeviceintelligence.StreamingProcessingCallback);
+    method @NonNull public abstract void onTokenInfoRequest(int, @NonNull android.app.ondeviceintelligence.Feature, @NonNull android.os.Bundle, @Nullable android.os.CancellationSignal, @NonNull android.os.OutcomeReceiver<android.app.ondeviceintelligence.TokenInfo,android.app.ondeviceintelligence.OnDeviceIntelligenceException>);
+    method public abstract void onUpdateProcessingState(@NonNull android.os.Bundle, @NonNull android.os.OutcomeReceiver<android.os.PersistableBundle,android.app.ondeviceintelligence.OnDeviceIntelligenceException>);
+    method public final java.io.FileInputStream openFileInput(@NonNull String) throws java.io.FileNotFoundException;
+    field public static final String SERVICE_INTERFACE = "android.service.ondeviceintelligence.OnDeviceSandboxedInferenceService";
+  }
+
+}
+
diff --git a/framework/api/system-removed.txt b/framework/api/system-removed.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/framework/api/system-removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/framework/api/test-current.txt b/framework/api/test-current.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/framework/api/test-current.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/framework/api/test-removed.txt b/framework/api/test-removed.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/framework/api/test-removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/framework/jarjar-rules.txt b/framework/jarjar-rules.txt
new file mode 100644
index 000000000..5e308e554
--- /dev/null
+++ b/framework/jarjar-rules.txt
@@ -0,0 +1,3 @@
+rule com.android.internal.** com.android.neuralnetworks.framework.jarjar.@0
+rule android.app.ondeviceintelligence.flags.** com.android.neuralnetworks.framework.jarjar.@0
+rule com.android.modules.utils.HandlerExecutor com.android.neuralnetworks.framework.jarjar.HandlerExecutor
\ No newline at end of file
diff --git a/runtime/Android.bp b/runtime/Android.bp
index 81f4f9617..46063d82d 100644
--- a/runtime/Android.bp
+++ b/runtime/Android.bp
@@ -203,6 +203,7 @@ cc_library_shared {
     llndk: {
         symbol_file: "libneuralnetworks.map.txt",
         override_export_include_dirs: ["include"],
+        moved_to_apex: true,
     },
     defaults: [
         "libneuralnetworks_defaults",
diff --git a/service/Android.bp b/service/Android.bp
new file mode 100644
index 000000000..b192742d5
--- /dev/null
+++ b/service/Android.bp
@@ -0,0 +1,66 @@
+// Copyright (C) 2022 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_sdk_library {
+    name: "service-ondeviceintelligence",
+    srcs: [
+        ":service-ondeviceintelligence-sources",
+        "proto/*.proto",
+    ],
+    defaults: ["framework-system-server-module-defaults"],
+    sdk_version: "system_server_current",
+    apex_available: [
+        "com.android.neuralnetworks",
+        "//apex_available:platform",
+    ],
+    impl_library_visibility: [
+        "//packages/modules/NeuralNetworks:__subpackages__",
+        "//frameworks/base:__subpackages__",
+    ],
+    proto: {
+        type: "nano",
+    },
+    static_libs: [
+        "android.app.ondeviceintelligence-aconfig-java",
+        "modules-utils-shell-command-handler",
+        "modules-utils-backgroundthread",
+    ],
+    permitted_packages: [
+        "com.android.server.ondeviceintelligence",
+        "com.android.neuralnetworks",
+        "com.android.modules.utils",
+    ],
+    min_sdk_version: "35",
+    libs: [
+        "framework-ondeviceintelligence.impl",
+        "framework-configinfrastructure.stubs.module_lib",
+        "modules-utils-infra",
+    ],
+    jarjar_rules: "jarjar-rules.txt",
+    errorprone: {
+        extra_check_modules: [
+            "//external/nullaway:nullaway_plugin",
+        ],
+        javacflags: [
+            "-XepExcludedPaths:.*/out/soong/.*",
+            "-Xep:NullAway:ERROR",
+            "-XepOpt:NullAway:AnnotatedPackages=android.app.ondeviceintelligence",
+            "-XepOpt:NullAway:AnnotatedPackages=android.service.ondeviceintelligence",
+        ],
+    },
+}
diff --git a/service/OWNERS b/service/OWNERS
new file mode 100644
index 000000000..9c0e71ccd
--- /dev/null
+++ b/service/OWNERS
@@ -0,0 +1,5 @@
+# Bug component: 195575
+
+sandeepbandaru@google.com
+shivanker@google.com
+shiqing@google.com
diff --git a/service/api/current.txt b/service/api/current.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/service/api/current.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/service/api/module-lib-current.txt b/service/api/module-lib-current.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/service/api/module-lib-current.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/service/api/module-lib-removed.txt b/service/api/module-lib-removed.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/service/api/module-lib-removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/service/api/removed.txt b/service/api/removed.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/service/api/removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/service/api/system-server-current.txt b/service/api/system-server-current.txt
new file mode 100644
index 000000000..666a7b117
--- /dev/null
+++ b/service/api/system-server-current.txt
@@ -0,0 +1,9 @@
+// Signature format: 2.0
+package com.android.server.ondeviceintelligence {
+
+  @FlaggedApi("android.app.ondeviceintelligence.flags.enable_on_device_intelligence_module") public interface OnDeviceIntelligenceManagerLocal {
+    method public int getInferenceServiceUid();
+  }
+
+}
+
diff --git a/service/api/system-server-removed.txt b/service/api/system-server-removed.txt
new file mode 100644
index 000000000..d802177e2
--- /dev/null
+++ b/service/api/system-server-removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/service/jarjar-rules.txt b/service/jarjar-rules.txt
new file mode 100644
index 000000000..5893d6afb
--- /dev/null
+++ b/service/jarjar-rules.txt
@@ -0,0 +1,5 @@
+rule com.android.modules.utils.BasicShellCommandHandler com.android.neuralnetworks.service.jarjar.BasicShellCommandHandler
+rule android.app.ondeviceintelligence.flags.** com.android.neuralnetworks.service.jarjar.@0
+rule com.google.protobuf.** com.android.neuralnetworks.service.jarjar.@0
+rule com.android.server.ondeviceintelligence.nano.** com.android.neuralnetworks.service.jarjar.nano.@0
+rule com.android.modules.utils.HandlerExecutor com.android.neuralnetworks.service.jarjar.HandlerExecutor
diff --git a/service/proto/inference_info.proto b/service/proto/inference_info.proto
new file mode 100644
index 000000000..a6f4f4fa4
--- /dev/null
+++ b/service/proto/inference_info.proto
@@ -0,0 +1,34 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+syntax = "proto2";
+
+package android.ondeviceintelligence;
+
+option java_package = "com.android.server.ondeviceintelligence";
+option java_multiple_files = true;
+
+
+message InferenceInfo {
+  // Uid for the caller app.
+  optional int32 uid = 1;
+  // Inference start time(milliseconds from the epoch time).
+  optional int64 start_time_ms = 2;
+  // Inference end time(milliseconds from the epoch time).
+  optional int64 end_time_ms = 3;
+  // Suspended time in milliseconds.
+  optional int64 suspended_time_ms = 4;
+}
\ No newline at end of file
```

