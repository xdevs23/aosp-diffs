```diff
diff --git a/Android.bp b/Android.bp
index a13e290..6bebea4 100644
--- a/Android.bp
+++ b/Android.bp
@@ -128,6 +128,9 @@ cc_library {
             srcs: [
                 "RuntimeInfo-target.cpp",
             ],
+            static_libs: [
+                "libapexd_flags",
+            ],
         },
         recovery: {
             srcs: [
diff --git a/Apex.cpp b/Apex.cpp
index 78dd26b..117e776 100644
--- a/Apex.cpp
+++ b/Apex.cpp
@@ -19,7 +19,9 @@
 
 #include <android-base/logging.h>
 #include <android-base/strings.h>
-
+#ifdef LIBVINTF_TARGET
+#include "com_android_apex_flags.h"
+#endif
 #include "com_android_apex.h"
 #include "constants-private.h"
 
@@ -38,6 +40,15 @@ constexpr const char* ODM = "ODM";
 
 static bool isApexReady(PropertyFetcher* propertyFetcher) {
 #ifdef LIBVINTF_TARGET
+    if constexpr (com::android::apex::flags::mount_before_data()) {
+        // "APEX ready" here means that the APEXes in the default mount
+        // namespace are ready to use. If init started with a single mount
+        // namespace, no need to wait for "APEX ready" because all APEXes are
+        // activated early.
+        if (propertyFetcher->getUintProperty("ro.init.mnt_ns.count", 2) == 1) {
+            return true;
+        }
+    }
     return propertyFetcher->getBoolProperty("apex.all.ready", false);
 #else
     // When running on host, it assumes that /apex is ready.
diff --git a/CompatibilityMatrix.cpp b/CompatibilityMatrix.cpp
index 799647a..c53f227 100644
--- a/CompatibilityMatrix.cpp
+++ b/CompatibilityMatrix.cpp
@@ -16,6 +16,7 @@
 
 #include "CompatibilityMatrix.h"
 
+#include <algorithm>
 #include <iostream>
 #include <utility>
 
@@ -449,6 +450,19 @@ bool CompatibilityMatrix::forEachInstanceOfVersion(
     return true;
 }
 
+bool CompatibilityMatrix::matchInterface(HalFormat format, ExclusiveTo exclusiveTo,
+                                        const std::string& halName, const Version& version,
+                                        const std::string& interfaceName) const {
+    bool found = false;
+    (void)forEachInstanceOfInterface(format, exclusiveTo, halName, version, interfaceName,
+                                     [&found](const auto&) {
+                                         found = true;
+                                         return false;  // no need to keep looking
+                                     });
+    return found;
+}
+
+
 bool CompatibilityMatrix::matchInstance(HalFormat format, ExclusiveTo exclusiveTo,
                                         const std::string& halName, const Version& version,
                                         const std::string& interfaceName,
diff --git a/HalManifest.cpp b/HalManifest.cpp
index e625efa..e99df2b 100644
--- a/HalManifest.cpp
+++ b/HalManifest.cpp
@@ -347,7 +347,9 @@ void multilineIndent(std::ostream& os, size_t indent, const Container& lines) {
 }
 
 std::set<std::string> HalManifest::checkUnusedHals(
-    const CompatibilityMatrix& mat, const std::vector<HidlInterfaceMetadata>& hidlMetadata) const {
+    const CompatibilityMatrix& mat, const std::vector<HidlInterfaceMetadata>& hidlMetadata,
+    const std::function<bool(const std::string&)>& shouldCheckPackage,
+    bool shouldCheckInstanceName) const {
     std::multimap<std::string, std::string> childrenMap;
     for (const auto& child : hidlMetadata) {
         for (const auto& parent : child.inherited) {
@@ -357,13 +359,26 @@ std::set<std::string> HalManifest::checkUnusedHals(
 
     std::set<std::string> ret;
 
-    forEachInstance([&ret, &mat, &childrenMap](const auto& manifestInstance) {
-        if (mat.matchInstance(manifestInstance.format(), manifestInstance.exclusiveTo(),
-                              manifestInstance.package(), manifestInstance.version(),
-                              manifestInstance.interface(), manifestInstance.instance())) {
+    forEachInstance([&ret, &mat, &childrenMap, &shouldCheckPackage,
+                     shouldCheckInstanceName](const auto& manifestInstance) {
+        // Don't report this instance as unused if the caller doesn't want it
+        // checked.
+        if (!shouldCheckPackage(manifestInstance.package())) return true;
+
+        if (shouldCheckInstanceName &&
+            mat.matchInstance(manifestInstance.format(), manifestInstance.exclusiveTo(),
+                               manifestInstance.package(), manifestInstance.version(),
+                               manifestInstance.interface(), manifestInstance.instance())) {
             // manifestInstance exactly matches an instance in |mat|.
             return true;
         }
+        if (!shouldCheckInstanceName &&
+            mat.matchInterface(manifestInstance.format(), manifestInstance.exclusiveTo(),
+                               manifestInstance.package(), manifestInstance.version(),
+                               manifestInstance.interface())) {
+            // manifestInstance exactly matches an interface in |mat|.
+            return true;
+        }
         // For HIDL instances, If foo@2.0 inherits from foo@1.0, manifest may contain both, but
         // matrix may contain only 2.0 if 1.0 is considered deprecated. Hence, if manifestInstance
         // is 1.0, check all its children in the matrix too.
@@ -374,9 +389,15 @@ std::set<std::string> HalManifest::checkUnusedHals(
             for (auto it = range.first; it != range.second; ++it) {
                 details::FQName fqName;
                 CHECK(fqName.setTo(it->second));
-                if (mat.matchInstance(manifestInstance.format(), manifestInstance.exclusiveTo(),
-                                      fqName.package(), fqName.getVersion(), fqName.name(),
-                                      manifestInstance.instance())) {
+                if (shouldCheckInstanceName &&
+                    mat.matchInstance(manifestInstance.format(), manifestInstance.exclusiveTo(),
+                                       fqName.package(), fqName.getVersion(), fqName.name(),
+                                       manifestInstance.instance())) {
+                    return true;
+                }
+                if (!shouldCheckInstanceName &&
+                    mat.matchInterface(manifestInstance.format(), manifestInstance.exclusiveTo(),
+                                       fqName.package(), fqName.getVersion(), fqName.name())) {
                     return true;
                 }
             }
diff --git a/OWNERS b/OWNERS
index 3518238..0967a91 100644
--- a/OWNERS
+++ b/OWNERS
@@ -5,5 +5,5 @@ elsk@google.com
 malchev@google.com
 sspatil@google.com
 
-per-file Apex* = rseymour@google.com
-per-file include/vintf/Apex* = rseymour@google.com
+per-file Apex* = file:platform/system/apex:/OWNERS
+per-file include/vintf/Apex* = file:platform/system/apex:/OWNERS
diff --git a/VintfObject.cpp b/VintfObject.cpp
index 708e58c..3ccaffa 100644
--- a/VintfObject.cpp
+++ b/VintfObject.cpp
@@ -941,8 +941,7 @@ android::base::Result<void> VintfObject::IsFqInstanceDeprecated(
     targetMatrix.forEachInstanceOfPackage(
         format, exclusiveTo, fqInstance.getPackage(), [&](const auto& targetMatrixInstance) {
             if (targetMatrixInstance.versionRange().majorVer == fqInstance.getMajorVersion() &&
-                targetMatrixInstance.interface() == fqInstance.getInterface() &&
-                targetMatrixInstance.matchInstance(fqInstance.getInstance())) {
+                targetMatrixInstance.interface() == fqInstance.getInterface()) {
                 targetMatrixMinVer =
                     std::min(targetMatrixMinVer, targetMatrixInstance.versionRange().minVer());
                 foundInstance = true;
@@ -1110,7 +1109,9 @@ android::base::Result<bool> VintfObject::hasFrameworkCompatibilityMatrixExtensio
 }
 
 android::base::Result<void> VintfObject::checkUnusedHals(
-    const std::vector<HidlInterfaceMetadata>& hidlMetadata) {
+    const std::vector<HidlInterfaceMetadata>& hidlMetadata,
+    const std::function<bool(const std::string&)>& shouldCheckPackage,
+    bool shouldCheckInstanceName) {
     auto matrix = getFrameworkCompatibilityMatrix();
     if (matrix == nullptr) {
         return android::base::Error(-NAME_NOT_FOUND) << "Missing framework matrix.";
@@ -1119,10 +1120,13 @@ android::base::Result<void> VintfObject::checkUnusedHals(
     if (manifest == nullptr) {
         return android::base::Error(-NAME_NOT_FOUND) << "Missing device manifest.";
     }
-    auto unused = manifest->checkUnusedHals(*matrix, hidlMetadata);
+    auto unused = manifest->checkUnusedHals(*matrix, hidlMetadata, shouldCheckPackage,
+                                            shouldCheckInstanceName);
     if (!unused.empty()) {
         return android::base::Error()
-               << "The following instances are in the device manifest but "
+               << "The following "
+               << (shouldCheckInstanceName ? "instances" : "interfaces")
+               << " are in the device manifest but "
                << "not specified in framework compatibility matrix: \n"
                << "    " << android::base::Join(unused, "\n    ") << "\n"
                << "Suggested fix:\n"
@@ -1132,7 +1136,10 @@ android::base::Result<void> VintfObject::checkUnusedHals(
                << "3. For new platform HALs, add them to any framework compatibility matrix "
                << "with FCM version >= " << matrix->level() << " where applicable.\n"
                << "4. For device-specific HALs, add to DEVICE_FRAMEWORK_COMPATIBILITY_MATRIX_FILE "
-               << "or DEVICE_PRODUCT_COMPATIBILITY_MATRIX_FILE.";
+               << "or DEVICE_PRODUCT_COMPATIBILITY_MATRIX_FILE.\n"
+               << "5. For `android.*` HALs that are using unexpected instance names, the instance "
+               << "names need to be added to the AOSP framework compatibility matrices. A regex "
+               << "wildcard can be used if the instance names are proprietary.\n";
     }
     return {};
 }
diff --git a/analyze_matrix/hals_for_release.py b/analyze_matrix/hals_for_release.py
index e0dbd66..593b2c8 100755
--- a/analyze_matrix/hals_for_release.py
+++ b/analyze_matrix/hals_for_release.py
@@ -17,6 +17,7 @@
 
 """
 Dump new HALs that are introduced in each FCM version in a human-readable format.
+Before using this script,'m analyze_matrix' must be run.
 
 Example:
 hals_for_release.py
diff --git a/check_vintf.cpp b/check_vintf.cpp
index 3e4e105..43f7616 100644
--- a/check_vintf.cpp
+++ b/check_vintf.cpp
@@ -437,7 +437,9 @@ android::base::Result<void> checkAllFiles(const Dirmap& dirmap, const Properties
     }
 
     if (hasFcmExt.value_or(false) || (targetFcm != Level::UNSPECIFIED && targetFcm >= Level::R)) {
-        AddResult(&retError, vintfObject->checkUnusedHals(hidlMetadata));
+        AddResult(&retError, vintfObject->checkUnusedHals(hidlMetadata,
+                                                          [](const std::string&) { return true; },
+                                                          true /* shouldCheckInstanceName */));
     } else {
         LOG(INFO) << "Skip checking unused HALs.";
     }
diff --git a/include/vintf/CompatibilityMatrix.h b/include/vintf/CompatibilityMatrix.h
index 4fa3fd7..cb2e260 100644
--- a/include/vintf/CompatibilityMatrix.h
+++ b/include/vintf/CompatibilityMatrix.h
@@ -149,6 +149,9 @@ struct CompatibilityMatrix : public HalGroup<MatrixHal>,
     bool matchInstance(HalFormat format, ExclusiveTo exclusiveTo, const std::string& halName,
                        const Version& version, const std::string& interfaceName,
                        const std::string& instance) const;
+    // Return whether the interface is in "this".
+    bool matchInterface(HalFormat format, ExclusiveTo exclusiveTo, const std::string& halName,
+                        const Version& version, const std::string& interfaceName) const;
 
     // Return the minlts of the latest <kernel>, or empty value if any error (e.g. this is not an
     // FCM, or there are no <kernel> tags).
@@ -188,7 +191,7 @@ struct CompatibilityMatrix : public HalGroup<MatrixHal>,
     } device;
 };
 
-} // namespace vintf
-} // namespace android
+}  // namespace vintf
+}  // namespace android
 
-#endif // ANDROID_VINTF_COMPATIBILITY_MATRIX_H
+#endif  // ANDROID_VINTF_COMPATIBILITY_MATRIX_H
diff --git a/include/vintf/HalManifest.h b/include/vintf/HalManifest.h
index a55523d..7ca6198 100644
--- a/include/vintf/HalManifest.h
+++ b/include/vintf/HalManifest.h
@@ -197,9 +197,12 @@ struct HalManifest : public HalGroup<ManifestHal>,
     // required HAL.
     // That is, return empty list iff
     // (instance in manifest) => (instance in matrix).
+    // `shouldCheckPackage` allows the caller to pick and choose which HALs to
+    // check based on their package name.
     std::set<std::string> checkUnusedHals(
-        const CompatibilityMatrix& mat,
-        const std::vector<HidlInterfaceMetadata>& hidlMetadata) const;
+        const CompatibilityMatrix& mat, const std::vector<HidlInterfaceMetadata>& hidlMetadata,
+        const std::function<bool(const std::string&)>& shouldCheckPackage,
+        bool shouldCheckInstanceName) const;
 
     // Check that manifest has no entries.
     bool empty() const;
diff --git a/include/vintf/VintfObject.h b/include/vintf/VintfObject.h
index 8476a41..d3b5840 100644
--- a/include/vintf/VintfObject.h
+++ b/include/vintf/VintfObject.h
@@ -188,6 +188,18 @@ class VintfObject {
      * Check that there are no unused HALs in HAL manifests. Currently, only
      * device manifest is checked against framework compatibility matrix.
      *
+     * Use the `shouldCheckPackage` function to filter out or ignore HALs based on
+     * the package name `ManifestInstance::package()`. Return true if we want
+     * to check that particular manifest instance.
+     *
+     * If shouldCheckInstanceName, a HAL android.foo.Ifoo/vendor is considered
+     * unused even if android.foo.Ifoo/default is in the framework compatibility
+     * matrix (i.e. it is used). If shouldCheckInstanceName is false, a HAL
+     * android.foo.Ifoo/vendor is considered used if android.foo.Ifoo/default
+     * is in the framework compatibility matrix. Setting it to false is useful
+     * when android.foo.Ifoo/vendor is in the product/system_ext FCM, but they
+     * are not visible during VTS tests.
+     *
      * Return result:
      * - result.ok() if no unused HALs
      * - !result.ok() && result.error().code() == 0 if with unused HALs. Check
@@ -196,7 +208,9 @@ class VintfObject {
      *     result.error() for detailed message.
      */
     android::base::Result<void> checkUnusedHals(
-        const std::vector<HidlInterfaceMetadata>& hidlMetadata);
+        const std::vector<HidlInterfaceMetadata>& hidlMetadata,
+        const std::function<bool(const std::string&)>& shouldCheckPackage,
+        bool shouldCheckInstanceName);
 
     // Check that all HALs are added to any framework compatibility matrix.
     // If shouldCheck is set, only check if:
diff --git a/test/LibVintfTest.cpp b/test/LibVintfTest.cpp
index 7b414da..a85a39d 100644
--- a/test/LibVintfTest.cpp
+++ b/test/LibVintfTest.cpp
@@ -126,8 +126,10 @@ public:
                                   std::string* e) {
         return cm1->addAllXmlFilesAsOptional(cm2, e);
     }
-    std::set<std::string> checkUnusedHals(const HalManifest& m, const CompatibilityMatrix& cm) {
-        return m.checkUnusedHals(cm, {});
+    std::set<std::string> checkUnusedHals(const HalManifest& m, const CompatibilityMatrix& cm,
+                                          bool shouldCheckInstanceName = true) {
+        return m.checkUnusedHals(cm, {}, [](const std::string&) { return true; },
+                                 shouldCheckInstanceName);
     }
     Level getLevel(const KernelInfo& ki) { return ki.level(); }
     static status_t parseGkiKernelRelease(RuntimeInfo::FetchFlags flags,
@@ -4057,6 +4059,10 @@ TEST_F(LibVintfTest, RegexInstanceCompat) {
                                          "android.hardware.foo@1.0::IFoo/legacy/0/nonmatch",
                                          "android.hardware.foo@1.0::IFoo/legacy0"}),
                   unused);
+
+        unused = checkUnusedHals(manifest, matrix, false /* shouldCheckInstanceName */);
+        // No unused HALs if checking at the interface level.
+        EXPECT_TRUE(unused.empty()) << android::base::Join(unused, "\n");
     }
 }
 
@@ -4562,6 +4568,38 @@ TEST_F(LibVintfTest, AidlAndHidlCheckUnused) {
     EXPECT_TRUE(unused.empty()) << android::base::Join(unused, "\n");
 }
 
+TEST_F(LibVintfTest, AidlCheckUnusedForUnrelatedInstance) {
+    std::string manifestXml =
+        "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
+        "    <hal format=\"aidl\">\n"
+        "        <name>android.system.foo</name>\n"
+        "        <fqname>IFoo/vendor</fqname>\n"
+        "    </hal>\n"
+        "</manifest>\n";
+        std::string matrixXml =
+            "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"
+            "    <hal format=\"aidl\">\n"
+            "        <name>android.system.foo</name>\n"
+            "        <interface>\n"
+            "            <name>IFoo</name>\n"
+            "            <instance>default</instance>\n"
+            "        </interface>\n"
+            "    </hal>\n"
+        "</compatibility-matrix>\n";
+    std::string error;
+    HalManifest manifest;
+    CompatibilityMatrix matrix;
+    EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
+    EXPECT_TRUE(fromXml(&matrix, matrixXml, &error)) << error;
+
+    auto unused = checkUnusedHals(manifest, matrix);
+    EXPECT_EQ((std::set<std::string>{"android.system.foo.IFoo/vendor (@1)"}),
+              unused);
+
+    unused = checkUnusedHals(manifest, matrix, false /* shouldCheckInstanceName */);
+    EXPECT_TRUE(unused.empty()) << android::base::Join(unused, "\n");
+}
+
 TEST_F(LibVintfTest, AidlVersion) {
     std::string xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"
diff --git a/test/vintf_object_tests.cpp b/test/vintf_object_tests.cpp
index ac4a595..4a72b0f 100644
--- a/test/vintf_object_tests.cpp
+++ b/test/vintf_object_tests.cpp
@@ -1459,8 +1459,8 @@ TEST_F(DeprecateTest, CheckMinorDeprecatedInstance2) {
         "android.hardware.major@2.0::IMajor/default",
     });
     std::string error;
-    EXPECT_EQ(DEPRECATED, vintfObject->checkDeprecation({}, &error))
-        << "minor@1.1::IMinor/legacy should be deprecated. " << error;
+    EXPECT_EQ(NO_DEPRECATED_HALS, vintfObject->checkDeprecation({}, &error))
+        << "None of these HALs are deprecated. " << error;
 }
 
 TEST_F(DeprecateTest, CheckMajor1) {
@@ -1513,7 +1513,7 @@ TEST_F(DeprecateTest, HidlMetadataDeprecate) {
         << "major@1.0 should be deprecated. " << error;
 }
 
-TEST_F(DeprecateTest, UnknownInstancesDoNotRespectDeprecation) {
+TEST_F(DeprecateTest, UnknownInstancesDoNotRespectDeprecationMajor) {
     expectVendorManifest(Level{2}, {
         "android.hardware.major@1.0::IMajor/unknown",
     });
@@ -1522,7 +1522,26 @@ TEST_F(DeprecateTest, UnknownInstancesDoNotRespectDeprecation) {
         << "major@1.0 should not be deprecated when targeting FCM level < 202504. " << error;
 }
 
-TEST_F(DeprecateTest, UnknownInstancesMustRespectDeprecation) {
+TEST_F(DeprecateTest, UnknownInstancesDoNotRespectDeprecationMinor) {
+    expectVendorManifest(Level{2}, {
+        "android.hardware.minor@1.0::IMinor/unknown",
+    });
+    std::string error;
+    EXPECT_EQ(NO_DEPRECATED_HALS, vintfObject->checkDeprecation({}, &error))
+        << "minor@1.0 should not be deprecated when targeting FCM level < 202504. " << error;
+}
+
+TEST_F(DeprecateTest, UnknownInstancesDoNotRespectDeprecationAidl) {
+    expectVendorManifest(Level{2}, {}, {
+        aidlFqInstance("android.hardware.minor", 101, "IMinor", "unknown"),
+    });
+    std::string error;
+    EXPECT_EQ(NO_DEPRECATED_HALS, vintfObject->checkDeprecation({}, &error))
+        << "minor@101 should not be deprecated when targeting FCM level < 202504. " << error;
+}
+
+
+TEST_F(DeprecateTest, UnknownInstancesMustRespectDeprecationMajor) {
     expectVendorManifest(Level{202504}, {
         "android.hardware.major@1.0::IMajor/unknown",
     });
@@ -1531,6 +1550,51 @@ TEST_F(DeprecateTest, UnknownInstancesMustRespectDeprecation) {
         << "major@1.0 should be deprecated. " << error;
 }
 
+TEST_F(DeprecateTest, UnknownInstancesMustRespectDeprecationMinor) {
+    expectVendorManifest(Level{202504}, {
+        "android.hardware.minor@1.0::IMinor/unknown",
+    });
+    std::string error;
+    EXPECT_EQ(DEPRECATED, vintfObject->checkDeprecation({}, &error))
+        << "minor@1.0 should be deprecated. " << error;
+}
+
+TEST_F(DeprecateTest, UnknownInstancesMustRespectDeprecationAidl) {
+    expectVendorManifest(Level{202504}, {}, {
+        aidlFqInstance("android.hardware.minor", 101, "IMinor", "unknown"),
+    });
+    std::string error;
+    EXPECT_EQ(DEPRECATED, vintfObject->checkDeprecation({}, &error))
+        << "major@101 should be deprecated. " << error;
+}
+
+TEST_F(DeprecateTest, UnknownInstancesAtHighVersionDoNotDeprecateMajor) {
+    expectVendorManifest(Level{202504}, {
+        "android.hardware.major@2.0::IMajor/unknown",
+    });
+    std::string error;
+    EXPECT_EQ(NO_DEPRECATED_HALS, vintfObject->checkDeprecation({}, &error))
+        << "major@2.0 should not be deprecated. " << error;
+}
+
+TEST_F(DeprecateTest, UnknownInstancesAtHighVersionDoNotDeprecateMinor) {
+    expectVendorManifest(Level{202504}, {
+        "android.hardware.minor@1.1::IMinor/unknown",
+    });
+    std::string error;
+    EXPECT_EQ(NO_DEPRECATED_HALS, vintfObject->checkDeprecation({}, &error))
+        << "major@1.1 should not be deprecated. " << error;
+}
+
+TEST_F(DeprecateTest, UnknownInstancesAtHighVersionDoNotDeprecateAidl) {
+    expectVendorManifest(Level{202504}, {}, {
+        aidlFqInstance("android.hardware.minor", 102, "IMinor", "unknown"),
+    });
+    std::string error;
+    EXPECT_EQ(NO_DEPRECATED_HALS, vintfObject->checkDeprecation({}, &error))
+        << "minor@102 should not be deprecated. " << error;
+}
+
 class RegexInstanceDeprecateTest : public VintfObjectTestBase {
    protected:
     virtual void SetUp() override {
@@ -1776,6 +1840,7 @@ TEST_F(RegexTest, DeprecateLevel2) {
 }
 
 class RegexTestDeprecateLevel2P : public RegexTest, public WithParamInterface<const char*> {};
+// We find deprecated HALs based on the interface, not the instance name
 TEST_P(RegexTestDeprecateLevel2P, Test) {
     auto deprecated = GetParam();
     std::string error;
@@ -1792,9 +1857,29 @@ INSTANTIATE_TEST_SUITE_P(RegexTest, RegexTestDeprecateLevel2P,
                          ::testing::Values("android.hardware.regex@1.0::IRegex/default",
                                            "android.hardware.regex@1.0::IRegex/special/1.0",
                                            "android.hardware.regex@1.0::IRegex/regex/1.0/1",
-                                           "android.hardware.regex@1.0::IRegex/regex_common/0",
-                                           "android.hardware.regex@1.1::IRegex/special/1.0",
-                                           "android.hardware.regex@1.1::IRegex/regex/1.0/1"));
+                                           "android.hardware.regex@1.0::IRegex/regex_common/0"));
+
+class RegexTestNonDeprecatedUnknownInstances : public RegexTest,
+                                               public WithParamInterface<const char*> {};
+// We find deprecated HALs based on the interface, not the instance name
+TEST_P(RegexTestNonDeprecatedUnknownInstances, Test) {
+    auto deprecated = GetParam();
+    std::string error;
+    // 2.0/default ensures compatibility.
+    expectVendorManifest(Level{2}, {
+                                       deprecated,
+                                       "android.hardware.regex@2.0::IRegex/default",
+                                   });
+    EXPECT_EQ(NO_DEPRECATED_HALS, vintfObject->checkDeprecation({}, &error))
+        << deprecated << " should not be deprecated. " << error;
+}
+
+INSTANTIATE_TEST_SUITE_P(RegexTest, RegexTestNonDeprecatedUnknownInstances,
+                         ::testing::Values("android.hardware.regex@1.1::IRegex/special/1.0",
+                                           "android.hardware.regex@1.1::IRegex/regex/1.0/1",
+                                           "android.hardware.regex@1.1::IRegex/unknown_name",
+                                           "android.hardware.regex@1.2::IRegex/special/1.0",
+                                           "android.hardware.regex@1.2::IRegex/unknown_name"));
 
 TEST_F(RegexTest, DeprecateLevel3) {
     std::string error;
```

