```diff
diff --git a/automotive/vehicle/OWNERS b/automotive/vehicle/OWNERS
index d9af9be2..e69de29b 100644
--- a/automotive/vehicle/OWNERS
+++ b/automotive/vehicle/OWNERS
@@ -1,3 +0,0 @@
-ramperry@google.com
-pavelm@google.com
-kwangsudo@google.com
diff --git a/neuralnetworks/V1_2/benchmark/java/OWNERS b/neuralnetworks/V1_2/benchmark/java/OWNERS
index a48301dd..035eefb8 100644
--- a/neuralnetworks/V1_2/benchmark/java/OWNERS
+++ b/neuralnetworks/V1_2/benchmark/java/OWNERS
@@ -1,4 +1,3 @@
 # Bug component: 195575
-jeanluc@google.com
 miaowang@google.com
 pszczepaniak@google.com
diff --git a/neuralnetworks/V1_3/benchmark/java/OWNERS b/neuralnetworks/V1_3/benchmark/java/OWNERS
index a48301dd..035eefb8 100644
--- a/neuralnetworks/V1_3/benchmark/java/OWNERS
+++ b/neuralnetworks/V1_3/benchmark/java/OWNERS
@@ -1,4 +1,3 @@
 # Bug component: 195575
-jeanluc@google.com
 miaowang@google.com
 pszczepaniak@google.com
diff --git a/treble/OWNERS b/treble/OWNERS
index f32487df..7cbf0789 100644
--- a/treble/OWNERS
+++ b/treble/OWNERS
@@ -1,4 +1,3 @@
 elsk@google.com
 malchev@google.com
 smoreland@google.com
-trong@google.com
diff --git a/treble/platform_version/Android.bp b/treble/platform_version/Android.bp
index 9a59e772..ea861fcf 100644
--- a/treble/platform_version/Android.bp
+++ b/treble/platform_version/Android.bp
@@ -33,11 +33,6 @@ python_test_host {
         "vts",
     ],
     auto_gen_config: true,
-    version: {
-        py3: {
-            embedded_launcher: true,
-        }
-    },
     test_options: {
         unit_test: false,
     },
diff --git a/treble/vintf/Android.bp b/treble/vintf/Android.bp
index f2cefdea..1453bac3 100644
--- a/treble/vintf/Android.bp
+++ b/treble/vintf/Android.bp
@@ -49,6 +49,7 @@ cc_defaults {
         "VtsTrebleVintfTestBase.cpp",
         "utils.cpp",
         "main.cpp",
+        ":libvintf_service_info_aidl",
     ],
     data: [
         ":android.hardware",
@@ -58,6 +59,15 @@ cc_defaults {
     ],
 }
 
+filegroup {
+    name: "libvintf_service_info_aidl",
+    srcs: [
+        "aidl/android/vintf/ServiceInfo.aidl",
+        "aidl/android/vintf/IServiceInfoFetcher.aidl",
+    ],
+    path: "aidl",
+}
+
 // Test vendor image that has the highest target FCM version. This test binary
 // has no system XML dependencies.
 cc_test {
@@ -76,6 +86,38 @@ cc_test {
     ],
 }
 
+cc_test {
+    name: "vts_treble_vintf_trusted_hal_test",
+    //Use test_config for vts suite.
+    test_config: "vts_treble_vintf_trusted_hal_test.xml",
+    test_suites: [
+        "vts",
+        "general-tests",
+    ],
+    defaults: ["vts_treble_vintf_test_defaults"],
+    srcs: [
+        "DeviceManifestTest.cpp",
+        "DeviceMatrixTest.cpp",
+        "SingleManifestTest.cpp",
+    ],
+    data: [
+        ":trusty_test_vm_elf",
+        ":trusty_test_vm_config",
+        ":trusty_vm_launcher_sh",
+        ":trusty_wait_ready_sh",
+        ":trusty-ut-ctrl.system",
+    ],
+    cflags: [
+        "-DTRUSTED_HAL_TEST",
+    ],
+    enabled: false,
+    arch: {
+        arm64: {
+            enabled: true,
+        },
+    },
+}
+
 // Check for HIDL services on device launching after Android 14.
 cc_test {
     name: "vts_treble_no_hidl",
diff --git a/treble/vintf/SingleManifestTest.cpp b/treble/vintf/SingleManifestTest.cpp
index 3b23c2d3..7e7f9a5e 100644
--- a/treble/vintf/SingleManifestTest.cpp
+++ b/treble/vintf/SingleManifestTest.cpp
@@ -23,8 +23,11 @@
 #include <android-base/strings.h>
 #include <android/apex/ApexInfo.h>
 #include <android/apex/IApexService.h>
+#include <android/vintf/IServiceInfoFetcher.h>
+#include <android/vintf/ServiceInfo.h>
 #include <binder/IServiceManager.h>
 #include <binder/Parcel.h>
+#include <binder/RpcSession.h>
 #include <binder/Stability.h>
 #include <binder/Status.h>
 #include <dirent.h>
@@ -51,9 +54,13 @@ namespace testing {
 namespace {
 
 constexpr int kAndroidApi202404 = 202404;
+constexpr int kAndroidApi202504 = 202504;
+constexpr int kTrustyTestVmVintfTaPort = 1000;
 
 }  // namespace
 using android::FqInstance;
+using android::vintf::IServiceInfoFetcher;
+using android::vintf::ServiceInfo;
 using android::vintf::toFQNameString;
 
 // For devices that launched <= Android O-MR1, systems/hals/implementations
@@ -93,6 +100,15 @@ void FailureHashMissing(const FQName &fq_name) {
   }
 }
 
+static inline std::string ServiceName(const AidlInstance &aidl_instance) {
+  return aidl_instance.package() + "." + aidl_instance.interface() + "/" +
+         aidl_instance.instance();
+}
+
+static inline std::string ServiceName(const ServiceInfo &hal_info) {
+  return hal_info.type + "/" + hal_info.instance;
+}
+
 static FqInstance ToFqInstance(const string &interface,
                                const string &instance) {
   FqInstance fq_interface;
@@ -562,25 +578,59 @@ static std::optional<AidlInterfaceMetadata> metadataForInterface(
   return std::nullopt;
 }
 
-// TODO(b/150155678): using standard code to do this
-static std::string getInterfaceHash(const sp<IBinder> &binder) {
-  Parcel data;
-  Parcel reply;
-  data.writeInterfaceToken(binder->getInterfaceDescriptor());
-  status_t err =
-      binder->transact(IBinder::LAST_CALL_TRANSACTION - 1, data, &reply, 0);
-  if (err == UNKNOWN_TRANSACTION) {
-    return "";
+#ifdef TRUSTED_HAL_TEST
+sp<IServiceInfoFetcher> GetTrustedHalInfoFetcher() {
+  int test_vm_cid = base::GetIntProperty("trusty.test_vm.vm_cid", -1);
+  if (test_vm_cid == -1) {
+    cout << "no test VM is running";
+    return nullptr;
   }
-  EXPECT_EQ(OK, err);
-  binder::Status status;
-  EXPECT_EQ(OK, status.readFromParcel(reply));
-  EXPECT_TRUE(status.isOk()) << status.toString8().c_str();
-  std::string str;
-  EXPECT_EQ(OK, reply.readUtf8FromUtf16(&str));
-  return str;
+
+  auto session = RpcSession::make();
+  status_t status =
+      session->setupVsockClient(test_vm_cid, kTrustyTestVmVintfTaPort);
+  if (status != android::OK) {
+    cout << "unable to set up vsock client";
+    return nullptr;
+  }
+  sp<IBinder> root = session->getRootObject();
+  if (root == nullptr) {
+    cout << "failed to get root object for IServiceInfoFetcher";
+    return nullptr;
+  }
+  return IServiceInfoFetcher::asInterface(root);
+}
+
+TEST(TrustedHalDeclaredTest, TrustedHalDeclaredMatchesInstalled) {
+  auto trusted_hal_info_fetcher = GetTrustedHalInfoFetcher();
+  ASSERT_NE(trusted_hal_info_fetcher, nullptr)
+      << "failed to get IServiceInfoFetcher";
+
+  // Retrieve the list of actually installed Trusted HALs.
+  std::vector<std::string> actual_trusted_hal_list;
+  ASSERT_TRUE(
+      trusted_hal_info_fetcher->listAllServices(&actual_trusted_hal_list)
+          .isOk())
+      << "failed to list all services";
+  std::set<std::string> actual_instances(actual_trusted_hal_list.begin(),
+                                         actual_trusted_hal_list.end());
+
+  // Retrieve the list of declared Trusted HALs from the vintf manifest.
+  std::set<std::string> declared_instances = {};
+  for (const auto &aidl_instance : VtsTrebleVintfTestBase::GetAidlInstances(
+           VintfObject::GetDeviceHalManifest())) {
+    if (aidl_instance.exclusiveTo() == ExclusiveTo::VM) {
+      declared_instances.insert(ServiceName(aidl_instance));
+    }
+  }
+
+  // Compare the declared and actual sets.
+  ASSERT_EQ(declared_instances, actual_instances)
+      << "Declared Trusted HAL instances (exclusive to VM) do not match the "
+      << "actually installed instances.";
 }
 
+#else   // TRUSTED_HAL_TEST
 // TODO(b/150155678): using standard code to do this
 static int32_t getInterfaceVersion(const sp<IBinder> &binder) {
   Parcel data;
@@ -604,22 +654,74 @@ static int32_t getInterfaceVersion(const sp<IBinder> &binder) {
   return version;
 }
 
-static bool CheckAidlVersionMatchesDeclared(sp<IBinder> binder,
-                                            const std::string &name,
-                                            uint64_t declared_version,
-                                            bool allow_upgrade) {
-  const int32_t actual_version = getInterfaceVersion(binder);
+// TODO(b/150155678): using standard code to do this
+static std::string getInterfaceHash(const sp<IBinder> &binder) {
+  Parcel data;
+  Parcel reply;
+  data.writeInterfaceToken(binder->getInterfaceDescriptor());
+  status_t err =
+      binder->transact(IBinder::LAST_CALL_TRANSACTION - 1, data, &reply, 0);
+  if (err == UNKNOWN_TRANSACTION) {
+    return "";
+  }
+  EXPECT_EQ(OK, err);
+  binder::Status status;
+  EXPECT_EQ(OK, status.readFromParcel(reply));
+  EXPECT_TRUE(status.isOk()) << status.toString8().c_str();
+  std::string str;
+  EXPECT_EQ(OK, reply.readUtf8FromUtf16(&str));
+  return str;
+}
+
+std::vector<ServiceInfo> getExtensionInfos(const sp<IBinder> &binder) {
+  // if you end up here because of a stack overflow when running this
+  // test... you have a cycle in your interface extensions. Break that
+  // cycle to continue.
+  std::vector<ServiceInfo> extensions = {};
+  sp<IBinder> parent = binder;
+  sp<IBinder> extension;
+  while (parent) {
+    status_t status = parent->getExtension(&extension);
+    if (status != OK || !extension) {
+      break;
+    }
+    ServiceInfo info;
+    info.type =
+        std::string(String8(extension->getInterfaceDescriptor()).c_str());
+    info.requireVintfDeclaration =
+        android::internal::Stability::requiresVintfDeclaration(extension);
+    info.hash = getInterfaceHash(parent);
+    extensions.push_back(info);
+    parent = extension;
+  }
+  return extensions;
+}
+#endif  // TRUSTED_HAL_TEST
+
+static bool CheckAidlVersionMatchesDeclared(
+    const AidlInstance &declared_instance, const ServiceInfo &actual_hal_info) {
+  const auto name = ServiceName(actual_hal_info);
+  const auto actual_version = actual_hal_info.version;
   if (actual_version < 1) {
     ADD_FAILURE() << "For " << name << ", version should be >= 1 but it is "
                   << actual_version << ".";
     return false;
   }
 
+  uint64_t declared_version = declared_instance.version();
   if (declared_version == actual_version) {
     std::cout << "For " << name << ", version " << actual_version
               << " matches declared value." << std::endl;
     return true;
   }
+
+  const optional<string> &updatable_via_apex =
+      declared_instance.updatable_via_apex();
+  // allow upgrade if updatable HAL's declared APEX is actually updated.
+  // or if the HAL is updatable via system.
+  const bool allow_upgrade = (updatable_via_apex.has_value() &&
+                              IsApexUpdated(updatable_via_apex.value())) ||
+                             declared_instance.updatable_via_system();
   if (allow_upgrade && actual_version > declared_version) {
     std::cout << "For " << name << ", upgraded version " << actual_version
               << " is okay. (declared value = " << declared_version << ".)"
@@ -667,59 +769,93 @@ static std::vector<std::string> halsUpdatableViaSystem() {
   return hals;
 }
 
+static inline void checkHash(
+    const ServiceInfo &hal_info, bool ignore_rel,
+    const std::optional<const std::string> &parent_interface) {
+  const std::string &interface = hal_info.type;
+  const std::string &hash = hal_info.hash;
+  const std::optional<AidlInterfaceMetadata> metadata =
+      metadataForInterface(interface);
+  const std::string parent_log =
+      parent_interface
+          ? "\nThis interface is set as an extension via setExtension on " +
+                *parent_interface
+          : "";
+
+  const bool is_aosp = base::StartsWith(interface, "android.");
+  ASSERT_TRUE(!is_aosp || metadata)
+      << "AOSP interface must have metadata: "
+      << interface << ". Do not use the "
+      << "'android.' prefix for non-AOSP HALs" << parent_log;
+  const bool is_release =
+      base::GetProperty("ro.build.version.codename", "") == "REL";
+
+  const std::vector<std::string> hashes =
+      metadata ? metadata->hashes : std::vector<std::string>();
+  const bool found_hash =
+      std::find(hashes.begin(), hashes.end(), hash) != hashes.end();
+
+  if (is_aosp) {
+    if (!found_hash) {
+      if (is_release || ignore_rel) {
+        ADD_FAILURE() << "Interface "
+                      << interface << " has an unrecognized hash: '" << hash
+                      << "'. The following hashes are known:\n"
+                      << base::Join(hashes, '\n')
+                      << "\nHAL interfaces must be released and unchanged."
+                      << parent_log;
+      } else {
+        std::cout << "INFO: using unfrozen hash '" << hash << "' for "
+                  << interface << ". This will become an error upon release."
+                  << parent_log << std::endl;
+      }
+    }
+  } else {
+    // is partner-owned
+    //
+    // we only require that these are frozen, but we cannot check them for
+    // accuracy
+    if (hash.empty() || hash == "notfrozen") {
+      if (is_release) {
+        ADD_FAILURE()
+            << "Interface "
+            << interface << " is used but not frozen (cannot find hash for it)."
+            << parent_log;
+      } else {
+        std::cout << "INFO: missing hash for "
+                  << interface << ". This will become an error upon release."
+                  << parent_log << std::endl;
+      }
+    }
+  }
+}
+
 // This checks to make sure all vintf extensions are frozen.
 // We do not check for known hashes because the Android framework does not
 // support these extensions without out-of-tree changes from partners.
 // @param binder - the parent binder to check all of its extensions
-void checkVintfExtensionInterfaces(const sp<IBinder> &binder, bool is_release) {
+void checkVintfExtensionInterfaces(const ServiceInfo &info) {
   // if you end up here because of a stack overflow when running this
   // test... you have a cycle in your interface extensions. Break that
   // cycle to continue.
-  if (!binder) return;
-  sp<IBinder> extension;
-  status_t status = binder->getExtension(&extension);
-  if (status != OK || !extension) return;
-
-  if (android::internal::Stability::requiresVintfDeclaration(extension)) {
-    const std::string hash = getInterfaceHash(extension);
-    if (hash.empty() || hash == "notfrozen") {
-      if (is_release) {
-        ADD_FAILURE() << "Interface extension "
-                      << extension->getInterfaceDescriptor()
-                      << " is unfrozen! It is attached to "
-                      << " a binder for frozen VINTF interface ("
-                      << binder->getInterfaceDescriptor()
-                      << " so it must also be frozen.";
-      } else {
-        std::cout << "INFO: missing hash for vintf interface extension "
-                  << binder->getInterfaceDescriptor()
-                  << " which is attached to "
-                  << binder->getInterfaceDescriptor()
-                  << ". This will become an error upon release." << std::endl;
-      }
+  for (const auto &extension : info.extensions) {
+    if (extension.requireVintfDeclaration) {
+      checkHash(extension, false, info.type);
     }
+    checkVintfExtensionInterfaces(extension);
   }
-  checkVintfExtensionInterfaces(extension, is_release);
 }
 
 // This checks if @updatable-via-apex in VINTF is correct.
-void checkVintfUpdatableViaApex(const sp<IBinder> &binder,
+void checkVintfUpdatableViaApex(const std::string &exe,
                                 const std::string &apex_name) {
-  pid_t pid;
-  ASSERT_EQ(OK, binder->getDebugPid(&pid));
-
-  std::string exe;
-  ASSERT_TRUE(base::Readlink("/proc/" + std::to_string(pid) + "/exe", &exe));
-
   // HAL service should start from the apex
   ASSERT_THAT(exe, StartsWith("/apex/" + apex_name + "/"));
 }
 
 TEST_P(SingleAidlTest, ExpectedUpdatableViaSystemHals) {
   const auto &[aidl_instance, _] = GetParam();
-  const std::string name = aidl_instance.package() + "." +
-                           aidl_instance.interface() + "/" +
-                           aidl_instance.instance();
+  const std::string name = ServiceName(aidl_instance);
 
   const auto hals = halsUpdatableViaSystem();
   if (std::find(hals.begin(), hals.end(), name) != hals.end()) {
@@ -749,82 +885,85 @@ TEST_P(SingleAidlTest, HalIsServed) {
   const std::string type = package + "." + interface;
   const std::string name = type + "/" + instance;
 
-  sp<IBinder> binder = GetAidlService(name);
+  ServiceInfo actual_hal_info;
+  Partition actual_partition;
 
+#ifdef TRUSTED_HAL_TEST
+  if (aidl_instance.exclusiveTo() != ExclusiveTo::VM) {
+    GTEST_SKIP() << name
+                 << " is not check in this test as it is not exclusive to VM";
+  }
+  auto trusted_hal_info_fetcher = GetTrustedHalInfoFetcher();
+  ASSERT_NE(trusted_hal_info_fetcher, nullptr)
+      << "failed to get IServiceInfoFetcher";
+
+  ASSERT_TRUE(
+      trusted_hal_info_fetcher->getServiceInfo(name, &actual_hal_info).isOk())
+      << "failed to get service info for HAL exclusive to VM: " << name;
+
+  actual_partition = Partition::VENDOR;
+#else   // TRUSTED_HAL_TEST
+  if (aidl_instance.exclusiveTo() == ExclusiveTo::VM) {
+    GTEST_SKIP() << name
+                 << " is not check in this test as it is exclusive to VM";
+  }
+  sp<IBinder> binder = GetAidlService(name);
   ASSERT_NE(binder, nullptr) << "Failed to get " << name;
 
-  // allow upgrade if updatable HAL's declared APEX is actually updated.
-  // or if the HAL is updatable via system.
-  const bool allow_upgrade = (updatable_via_apex.has_value() &&
-                              IsApexUpdated(updatable_via_apex.value())) ||
-                             aidl_instance.updatable_via_system();
+  actual_hal_info.type = type;
+  actual_hal_info.instance = instance;
+  actual_hal_info.requireVintfDeclaration =
+      android::internal::Stability::requiresVintfDeclaration(binder);
+  actual_hal_info.version = getInterfaceVersion(binder);
+  actual_hal_info.hash = getInterfaceHash(binder);
 
-  const bool reliable_version =
-      CheckAidlVersionMatchesDeclared(binder, name, version, allow_upgrade);
+  pid_t pid;
+  ASSERT_EQ(OK, binder->getDebugPid(&pid));
+  actual_partition = PartitionOfProcess(pid);
 
-  const std::string hash = getInterfaceHash(binder);
-  const std::optional<AidlInterfaceMetadata> metadata =
-      metadataForInterface(type);
+  ASSERT_TRUE(base::Readlink("/proc/" + std::to_string(pid) + "/exe",
+                             &actual_hal_info.exe));
 
-  const bool is_aosp = base::StartsWith(package, "android.");
-  ASSERT_TRUE(!is_aosp || metadata)
-      << "AOSP interface must have metadata: " << package;
+  actual_hal_info.extensions = getExtensionInfos(binder);
+#endif  // TRUSTED_HAL_TEST
 
+  ASSERT_EQ(name, ServiceName(actual_hal_info));
   if (GetVendorApiLevel() >= kAndroidApi202404 &&
-      !android::internal::Stability::requiresVintfDeclaration(binder)) {
+      !actual_hal_info.requireVintfDeclaration) {
     ADD_FAILURE() << "Interface " << name
                   << " is declared in the VINTF manifest "
                   << "but it does not have \"vintf\" stability. "
                   << "Add 'stability: \"vintf\" to the aidl_interface module, "
                   << "or remove it from the VINTF manifest.";
   }
-
-  const bool is_release =
-      base::GetProperty("ro.build.version.codename", "") == "REL";
-
+  // If we know this version is frozen, even on non-REL builds we should throw
+  // an error if this is an AOSP interfaces with a hash that we don't know
+  // about.
+  const bool reliable_version =
+      CheckAidlVersionMatchesDeclared(aidl_instance, actual_hal_info);
+  const std::optional<AidlInterfaceMetadata> metadata =
+      metadataForInterface(type);
   const bool is_existing =
       metadata ? std::find(metadata->versions.begin(), metadata->versions.end(),
                            version) != metadata->versions.end()
                : false;
+  const bool ignore_rel_for_aosp = reliable_version && is_existing;
 
-  const std::vector<std::string> hashes =
-      metadata ? metadata->hashes : std::vector<std::string>();
-  const bool found_hash =
-      std::find(hashes.begin(), hashes.end(), hash) != hashes.end();
+  checkHash(actual_hal_info, ignore_rel_for_aosp, std::nullopt);
 
-  if (is_aosp) {
-    if (!found_hash) {
-      if (is_release || (reliable_version && is_existing)) {
-        ADD_FAILURE() << "Interface " << name << " has an unrecognized hash: '"
-                      << hash << "'. The following hashes are known:\n"
-                      << base::Join(hashes, '\n')
-                      << "\nHAL interfaces must be released and unchanged.";
-      } else {
-        std::cout << "INFO: using unfrozen hash '" << hash << "' for " << type
-                  << ". This will become an error upon release." << std::endl;
-      }
-    }
-  } else {
-    // is partner-owned
-    //
-    // we only require that these are frozen, but we cannot check them for
-    // accuracy
-    if (hash.empty() || hash == "notfrozen") {
-      if (is_release) {
-        ADD_FAILURE() << "Interface " << name
-                      << " is used but not frozen (cannot find hash for it).";
-      } else {
-        std::cout << "INFO: missing hash for " << type
-                  << ". This will become an error upon release." << std::endl;
-      }
-    }
+  if (GetVendorApiLevel() >= kAndroidApi202504) {
+    checkVintfExtensionInterfaces(actual_hal_info);
   }
-  if (GetVendorApiLevel() >= kAndroidApi202404) {
-    checkVintfExtensionInterfaces(binder, is_release);
+
+  // TODO(b/388106311): always be able to determine where this code comes from
+  const bool ableToDeterminePartition = actual_partition != Partition::UNKNOWN;
+  if (GetVendorApiLevel() >= kAndroidApi202504 && ableToDeterminePartition) {
+    Partition expected_partition = PartitionOfType(manifest->type());
+    EXPECT_EQ(expected_partition, actual_partition);
   }
 
   if (updatable_via_apex.has_value()) {
-    checkVintfUpdatableViaApex(binder, updatable_via_apex.value());
+    checkVintfUpdatableViaApex(actual_hal_info.exe, updatable_via_apex.value());
   }
 }
 
diff --git a/treble/vintf/VtsTrebleVintfTestBase.cpp b/treble/vintf/VtsTrebleVintfTestBase.cpp
index a12db361..ba2497ae 100644
--- a/treble/vintf/VtsTrebleVintfTestBase.cpp
+++ b/treble/vintf/VtsTrebleVintfTestBase.cpp
@@ -94,6 +94,11 @@ sp<IServiceManager> VtsTrebleVintfTestBase::default_manager() {
 
 std::vector<HidlInstance> VtsTrebleVintfTestBase::GetHidlInstances(
     const HalManifestPtr &manifest) {
+  if (manifest == nullptr) {
+    ADD_FAILURE() << "Failed to parse the HAL Manifest files. Check logcat for "
+                     "more details";
+    return {};
+  }
   std::vector<HidlInstance> ret;
   manifest->forEachInstance([manifest, &ret](const auto &manifest_instance) {
     if (manifest_instance.format() == HalFormat::HIDL) {
@@ -106,6 +111,11 @@ std::vector<HidlInstance> VtsTrebleVintfTestBase::GetHidlInstances(
 
 std::vector<AidlInstance> VtsTrebleVintfTestBase::GetAidlInstances(
     const HalManifestPtr &manifest) {
+  if (manifest == nullptr) {
+    ADD_FAILURE() << "Failed to parse the HAL Manifest files. Check logcat for "
+                     "more details";
+    return {};
+  }
   std::vector<AidlInstance> ret;
   manifest->forEachInstance([manifest, &ret](const auto &manifest_instance) {
     if (manifest_instance.format() == HalFormat::AIDL) {
@@ -118,6 +128,11 @@ std::vector<AidlInstance> VtsTrebleVintfTestBase::GetAidlInstances(
 
 std::vector<NativeInstance> VtsTrebleVintfTestBase::GetNativeInstances(
     const HalManifestPtr &manifest) {
+  if (manifest == nullptr) {
+    ADD_FAILURE() << "Failed to parse the HAL Manifest files. Check logcat for "
+                     "more details";
+    return {};
+  }
   std::vector<NativeInstance> ret;
   manifest->forEachInstance([manifest, &ret](const auto &manifest_instance) {
     if (manifest_instance.format() == HalFormat::NATIVE) {
@@ -219,6 +234,11 @@ Partition VtsTrebleVintfTestBase::GetPartition(sp<IBase> hal_service) {
 
 set<string> VtsTrebleVintfTestBase::GetDeclaredHidlHalsOfTransport(
     HalManifestPtr manifest, Transport transport) {
+  if (manifest == nullptr) {
+    ADD_FAILURE() << "Failed to parse the HAL Manifest files. Check logcat for "
+                     "more details";
+    return {};
+  }
   EXPECT_THAT(transport,
               AnyOf(Eq(Transport::HWBINDER), Eq(Transport::PASSTHROUGH)))
       << "Unrecognized transport of HIDL: " << transport;
diff --git a/treble/vintf/aidl/android/vintf/IServiceInfoFetcher.aidl b/treble/vintf/aidl/android/vintf/IServiceInfoFetcher.aidl
new file mode 100644
index 00000000..59f8c74c
--- /dev/null
+++ b/treble/vintf/aidl/android/vintf/IServiceInfoFetcher.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package android.vintf;
+
+import android.vintf.ServiceInfo;
+
+/**
+ * Interface for retrieving information about services.
+ */
+interface IServiceInfoFetcher {
+
+    /**
+     * Lists all available services.
+     *
+     * @return A vector of strings, where each string represents the name of a
+     *   service.
+     */
+    @utf8InCpp List<String> listAllServices();
+
+    /**
+     * Retrieves information about a specific service.
+     *
+     * @param name The name of the service.
+     * @return A ServiceInfo object containing the service's information or
+     * null if the service is not found.
+     */
+    ServiceInfo getServiceInfo(@utf8InCpp String name);
+}
diff --git a/treble/vintf/aidl/android/vintf/ServiceInfo.aidl b/treble/vintf/aidl/android/vintf/ServiceInfo.aidl
new file mode 100644
index 00000000..024829b6
--- /dev/null
+++ b/treble/vintf/aidl/android/vintf/ServiceInfo.aidl
@@ -0,0 +1,57 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package android.vintf;
+
+/**
+ * Represents information about a service.
+ */
+parcelable ServiceInfo {
+    /**
+     * Type of the service.
+     */
+    @utf8InCpp String type;
+
+    /**
+     * Instance of the service.
+     */
+    @utf8InCpp String instance;
+
+    /**
+     * Version of the service.
+     */
+    int version;
+
+    /**
+     * Whether the service requires VINTF declaration.
+     */
+    boolean requireVintfDeclaration;
+
+    /**
+     * Interface hash of the service.
+     */
+    @utf8InCpp String hash;
+
+    /**
+     * Path to the executable that starts the service.
+     */
+    @utf8InCpp String exe;
+
+    /**
+     * Extension interfaces of the service.
+     */
+    List<ServiceInfo> extensions;
+}
diff --git a/treble/vintf/libvts_vintf_test_common/common.cpp b/treble/vintf/libvts_vintf_test_common/common.cpp
index a09522fc..87012197 100644
--- a/treble/vintf/libvts_vintf_test_common/common.cpp
+++ b/treble/vintf/libvts_vintf_test_common/common.cpp
@@ -51,7 +51,8 @@ static const std::map<uint64_t /* Vendor API Level */, Level /* FCM Version */>
         {34, Level::U},
         // Starting from 2024Q2, vendor api level has YYYYMM format.
         {202404, Level::V},
-        {202504, Level::W},  // TODO(b/346861728) placeholder level
+        {202504, Level::B},
+        {202604, Level::C},
     }};
 
 android::base::Result<Level> GetFcmVersionFromApiLevel(uint64_t api_level) {
diff --git a/treble/vintf/utils.cpp b/treble/vintf/utils.cpp
index c64828b8..0f1712cf 100644
--- a/treble/vintf/utils.cpp
+++ b/treble/vintf/utils.cpp
@@ -149,9 +149,14 @@ set<string> ReleasedHashes(const FQName &fq_iface_name) {
 Partition PartitionOfProcess(int32_t pid) {
   auto partition = android::procpartition::getPartition(pid);
 
-  // TODO(b/70033981): remove once ODM and Vendor manifests are distinguished
+  // we should have a library dedicated to Treble containers.
+
   if (partition == Partition::ODM) {
     partition = Partition::VENDOR;
+  } else if (partition == Partition::SYSTEM_EXT) {
+    partition = Partition::SYSTEM;
+  } else if (partition == Partition::PRODUCT) {
+    partition = Partition::SYSTEM;
   }
 
   return partition;
diff --git a/treble/vintf/utils.h b/treble/vintf/utils.h
index 8b1c842d..94ca3d80 100644
--- a/treble/vintf/utils.h
+++ b/treble/vintf/utils.h
@@ -98,6 +98,7 @@ struct AidlInstance : private ManifestInstance {
   bool updatable_via_system() const {
     return ManifestInstance::updatableViaSystem();
   }
+  ExclusiveTo exclusiveTo() const { return ManifestInstance::exclusiveTo(); }
 
   string test_case_name() const;
 };
diff --git a/treble/vintf/vts_treble_vintf_trusted_hal_test.xml b/treble/vintf/vts_treble_vintf_trusted_hal_test.xml
new file mode 100644
index 00000000..f4f47b2e
--- /dev/null
+++ b/treble/vintf/vts_treble_vintf_trusted_hal_test.xml
@@ -0,0 +1,51 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Config for vts_treble_vintf_trusted_hal_test">
+    <object type="module_controller" class="com.android.tradefed.testtype.suite.module.CommandSuccessModuleController">
+        <!--Skip the test when trusty VM is not enabled. -->
+        <option name="run-command"
+           value="(getprop trusty.security_vm.enabled | grep 1) || (getprop trusty.widevine_vm.enabled | grep 1)" />
+    </object>
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
+    <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
+        <option name="cleanup" value="true" />
+        <option name="push-file" key="trusty-ut-ctrl.system" value="/data/local/tmp/trusty_test_vm/trusty-ut-ctrl" />
+        <option name="push-file" key="trusty-vm-launcher.sh" value="/data/local/tmp/trusty_test_vm/trusty-vm-launcher.sh" />
+        <option name="push-file" key="trusty-wait-ready.sh" value="/data/local/tmp/trusty_test_vm/trusty-wait-ready.sh" />
+        <option name="push-file" key="trusty-test_vm-config.json" value="/data/local/tmp/trusty_test_vm/trusty-test_vm-config.json" />
+        <option name="push-file" key="trusty_test_vm.elf" value="/data/local/tmp/trusty_test_vm/trusty_test_vm.elf" />
+        <option name="push" value="vts_treble_vintf_trusted_hal_test->/data/local/tmp/vts_treble_vintf_trusted_hal_test" />
+    </target_preparer>
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.FilePusher">
+        <option name="push" value="android.frameworks.txt->/data/local/tmp/frameworks/hardware/interfaces/current.txt"/>
+        <option name="push" value="android.hardware.txt->/data/local/tmp/hardware/interfaces/current.txt"/>
+        <option name="push" value="android.system.txt->/data/local/tmp/system/hardware/interfaces/current.txt"/>
+    </target_preparer>
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="throw-if-cmd-fail" value="true" />
+        <!--Note: the first run-command shall not expect the background command to have started -->
+        <option name="run-bg-command" value="sh /data/local/tmp/trusty_test_vm/trusty-vm-launcher.sh" />
+        <option name="run-command" value="sh /data/local/tmp/trusty_test_vm/trusty-wait-ready.sh" />
+        <option name="run-command" value="start storageproxyd_test_vm_os" />
+        <option name="teardown-command" value="stop storageproxyd_test_vm_os" />
+        <option name="teardown-command" value="killall storageproxyd_test_vm_os || true" />
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.GTest" >
+        <option name="native-test-device-path" value="/data/local/tmp" />
+        <option name="module-name" value="vts_treble_vintf_trusted_hal_test" />
+    </test>
+</configuration>
diff --git a/usb/OWNERS b/usb/OWNERS
index 0aa06c44..82a48918 100644
--- a/usb/OWNERS
+++ b/usb/OWNERS
@@ -1,10 +1,10 @@
 # Bug component: 175220
 
-anothermark@google.com
+vmartensson@google.com
+nkapron@google.com
 febinthattil@google.com
-aprasath@google.com
+shubhankarm@google.com
 badhri@google.com
 albertccwang@google.com
 rickyniu@google.com
-khoahong@google.com
-kumarashishg@google.com
\ No newline at end of file
+khoahong@google.com
\ No newline at end of file
diff --git a/usb/usb/aidl/host/src/com/android/usb/vts/VtsAidlUsbHostTest.java b/usb/usb/aidl/host/src/com/android/usb/vts/VtsAidlUsbHostTest.java
index e5d1d905..0cd9f739 100644
--- a/usb/usb/aidl/host/src/com/android/usb/vts/VtsAidlUsbHostTest.java
+++ b/usb/usb/aidl/host/src/com/android/usb/vts/VtsAidlUsbHostTest.java
@@ -16,6 +16,7 @@
 
 package com.android.tests.usbport;
 
+import com.android.compatibility.common.util.VsrTest;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.log.LogUtil.CLog;
@@ -29,6 +30,9 @@ import com.google.common.base.Strings;
 
 import java.util.Arrays;
 import java.util.HashSet;
+import java.util.Set;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
 import java.util.concurrent.atomic.AtomicBoolean;
 
 import org.junit.Assert;
@@ -45,6 +49,11 @@ public final class VtsAidlUsbHostTest extends BaseHostJUnit4Test {
     private static final long CONN_TIMEOUT = 5000;
     // Extra time to wait for device to be available after being NOT_AVAILABLE state.
     private static final long EXTRA_RECOVERY_TIMEOUT = 1000;
+    private static final String PRODUCT_FIRST_API_LEVEL_PROP = "ro.product.first_api_level";
+    private static final String BOARD_API_LEVEL_PROP = "ro.board.api_level";
+    private static final String BOARD_FIRST_API_LEVEL_PROP = "ro.board.first_api_level";
+    // TODO Remove unknown once b/383164760 is fixed.
+    private static final Set<String> VSR_54_REQUIRED_HAL_VERSIONS = Set.of("V2_0", "V1_3", "unknown");
 
     private static boolean mHasService;
 
@@ -113,4 +122,142 @@ public final class VtsAidlUsbHostTest extends BaseHostJUnit4Test {
 
         Assert.assertTrue("USB port did not reconnect within 6000ms timeout.", mReconnected.get());
     }
+
+    @Test
+    @VsrTest(requirements = {"VSR-5.4-009"})
+    public void testVerifyUsbHalVersion() throws Exception {
+        Assume.assumeTrue(
+            String.format("The device doesn't have service %s", HAL_SERVICE),
+            mHasService);
+        Assert.assertNotNull("Target device does not exist", mDevice);
+        long roBoardApiLevel = mDevice.getIntProperty(BOARD_API_LEVEL_PROP, -1);
+        long roBoardFirstApiLevel = mDevice.getIntProperty(BOARD_FIRST_API_LEVEL_PROP, -1);
+        if(roBoardApiLevel != -1) {
+            Assume.assumeTrue("Skip on devices with ro.board.api_level "
+                                  + roBoardApiLevel + " less than 202504",
+                roBoardApiLevel >= 202504);
+        } else {
+            Assume.assumeTrue("Skip on devices with ro.board.first_api_level "
+                                  + roBoardFirstApiLevel + " less than 202504",
+                roBoardFirstApiLevel >= 202504);
+        }
+
+        RunUtil.getDefault().sleep(100);
+        String cmd = "svc usb getUsbHalVersion";
+        CLog.i("Invoke shell command [" + cmd + "]");
+        String result = mDevice.executeShellCommand(cmd).trim();
+
+        Assert.assertTrue("Expected HAL version to be one of "
+                              + VSR_54_REQUIRED_HAL_VERSIONS.toString()
+                              + " but got: " + result,
+            VSR_54_REQUIRED_HAL_VERSIONS.contains(result));
+    }
+
+    @Test
+    @VsrTest(requirements = {"VSR-5.4-006", "VSR-5.4-007"})
+    public void testAoaDirectoryExists() throws Exception {
+        Assume.assumeTrue(
+                String.format("The device doesn't have service %s", HAL_SERVICE), mHasService);
+        Assert.assertNotNull("Target device does not exist", mDevice);
+        checkAoaRequirements();
+
+        RunUtil.getDefault().sleep(100);
+        String cmd = "ls -l /dev/usb-ffs/aoa";
+        CLog.i("Invoke shell command [" + cmd + "]");
+        String result = mDevice.executeShellCommand(cmd).trim();
+
+        Assert.assertTrue(
+                "Expected AOA directory to exist but got: " + result, result.contains("ep0"));
+    }
+
+    @Test
+    @VsrTest(requirements = {"VSR-5.4-006", "VSR-5.4-007"})
+    public void testAoaControlDirectoryExists() throws Exception {
+        Assume.assumeTrue(
+                String.format("The device doesn't have service %s", HAL_SERVICE), mHasService);
+        Assert.assertNotNull("Target device does not exist", mDevice);
+        checkAoaRequirements();
+
+        RunUtil.getDefault().sleep(100);
+        String cmd = "ls -l /dev/usb-ffs/ctrl";
+        CLog.i("Invoke shell command [" + cmd + "]");
+        String result = mDevice.executeShellCommand(cmd).trim();
+
+        Assert.assertTrue("Expected AOA control directory to exist but got: " + result,
+                result.contains("ep0"));
+    }
+
+    @Test
+    @VsrTest(requirements = {"VSR-5.4-005"})
+    public void testAoaDirectoryMountedAsFfs() throws Exception {
+        Assume.assumeTrue(
+                String.format("The device doesn't have service %s", HAL_SERVICE), mHasService);
+        Assert.assertNotNull("Target device does not exist", mDevice);
+        checkAoaRequirements();
+
+        RunUtil.getDefault().sleep(100);
+        String cmd = "mount | grep \"/dev/usb-ffs/aoa\"";
+        CLog.i("Invoke shell command [" + cmd + "]");
+        String result = mDevice.executeShellCommand(cmd).trim();
+
+        Assert.assertTrue("Expected AOA directory to be mounted as FunctionFS but got: " + result,
+                result.contains("functionfs"));
+    }
+
+    @Test
+    @VsrTest(requirements = {"VSR-5.4-008"})
+    public void testAoaEndpointsNotMountedAtBoot() throws Exception {
+        Assume.assumeTrue(
+                String.format("The device doesn't have service %s", HAL_SERVICE), mHasService);
+        Assert.assertNotNull("Target device does not exist", mDevice);
+        checkAoaRequirements();
+
+        RunUtil.getDefault().sleep(100);
+        String cmd = "ls -l /dev/usb-ffs/aoa";
+        CLog.i("Invoke shell command [" + cmd + "]");
+        String result = mDevice.executeShellCommand(cmd).trim();
+
+        Assert.assertFalse("Expected AOA endpoints to not be mounted but got: " + result,
+                result.contains("ep1") || result.contains("ep2"));
+    }
+
+    private void checkAoaRequirements() throws Exception {
+        long roProductFirstApiLevel = mDevice.getIntProperty(PRODUCT_FIRST_API_LEVEL_PROP, -1);
+        long roBoardApiLevel = mDevice.getIntProperty(BOARD_API_LEVEL_PROP, -1);
+        long roBoardFirstApiLevel = mDevice.getIntProperty(BOARD_FIRST_API_LEVEL_PROP, -1);
+
+        RunUtil.getDefault().sleep(100);
+        String cmd = "uname -r";
+        CLog.i("Invoke shell command [" + cmd + "]");
+        String osVersion = mDevice.executeShellCommand(cmd).trim();
+
+        Assume.assumeTrue("Skip on devices with ro.product.first_api_level "
+                        + roProductFirstApiLevel + " less than 36 (Android 16)",
+                roProductFirstApiLevel >= 36);
+        if (roBoardApiLevel != -1) {
+            Assume.assumeTrue(
+                    "Skip on devices with ro.board.api_level " + roBoardApiLevel
+                        + " less than 202504",
+                    roBoardApiLevel >= 202504);
+        } else {
+            Assume.assumeTrue("Skip on devices with ro.board.first_api_level "
+                            + roBoardFirstApiLevel + " less than 202504",
+                    roBoardFirstApiLevel >= 202504);
+        }
+
+        Assume.assumeTrue("Skip on devices with kernel version "
+                        + osVersion + " less than 6.12 ",
+                isKernelVersionAtLeast(osVersion, 6,12));
+    }
+
+    private boolean isKernelVersionAtLeast(String osVersion,
+            int major, int minor) {
+        Pattern p = Pattern.compile("^(\\d+)\\.(\\d+)");
+        Matcher m1 = p.matcher(osVersion);
+        Assert.assertTrue("Unable to parse kernel release version: %s"
+                              .format(osVersion), m1.find());
+        return Integer.parseInt(m1.group(1)) > major
+                || (Integer.parseInt(m1.group(1)) == major
+                && Integer.parseInt(m1.group(2)) > minor);
+    }
 }
```

