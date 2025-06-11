```diff
diff --git a/Apex.cpp b/Apex.cpp
index e8e2439..78dd26b 100644
--- a/Apex.cpp
+++ b/Apex.cpp
@@ -15,7 +15,8 @@
  */
 #include "Apex.h"
 
-#include <android-base/format.h>
+#include <format>
+
 #include <android-base/logging.h>
 #include <android-base/strings.h>
 
@@ -26,6 +27,15 @@ using android::base::StartsWith;
 
 namespace android::vintf::apex {
 
+namespace {
+// Partition tags used in apex-info-list.xml
+constexpr const char* SYSTEM = "SYSTEM";
+constexpr const char* SYSTEM_EXT = "SYSTEM_EXT";
+constexpr const char* PRODUCT = "PRODUCT";
+constexpr const char* VENDOR = "VENDOR";
+constexpr const char* ODM = "ODM";
+}  // namespace
+
 static bool isApexReady(PropertyFetcher* propertyFetcher) {
 #ifdef LIBVINTF_TARGET
     return propertyFetcher->getBoolProperty("apex.all.ready", false);
@@ -71,7 +81,7 @@ static status_t GetVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFe
         if (!apexInfo.getIsActive()) continue;
 
         if (filter(apexInfo.getPartition())) {
-            dirs->push_back(fmt::format("{}/{}/" VINTF_SUB_DIR, apexDir, apexInfo.getModuleName()));
+            dirs->push_back(std::format("{}/{}/" VINTF_SUB_DIR, apexDir, apexInfo.getModuleName()));
         }
     }
     LOG(INFO) << "Loaded APEX Infos from " << apexInfoFile;
@@ -97,18 +107,24 @@ std::optional<timespec> GetModifiedTime(FileSystem* fileSystem, PropertyFetcher*
     return mtime;
 }
 
-status_t GetDeviceVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
+status_t GetVendorVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
                             std::vector<std::string>* dirs, std::string* error) {
     return GetVintfDirs(fileSystem, propertyFetcher, dirs, error, [](const std::string& partition) {
-        return partition.compare("VENDOR") == 0 || partition.compare("ODM") == 0;
+        return partition.compare(VENDOR) == 0;
     });
 }
 
+status_t GetOdmVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
+                         std::vector<std::string>* dirs, std::string* error) {
+    return GetVintfDirs(fileSystem, propertyFetcher, dirs, error,
+                        [](const std::string& partition) { return partition.compare(ODM) == 0; });
+}
+
 status_t GetFrameworkVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
                                std::vector<std::string>* dirs, std::string* error) {
     return GetVintfDirs(fileSystem, propertyFetcher, dirs, error, [](const std::string& partition) {
-        return partition.compare("SYSTEM") == 0 || partition.compare("SYSTEM_EXT") == 0 ||
-               partition.compare("PRODUCT") == 0;
+        return partition.compare(SYSTEM) == 0 || partition.compare(SYSTEM_EXT) == 0 ||
+               partition.compare(PRODUCT) == 0;
     });
 }
 
diff --git a/AssembleVintf.cpp b/AssembleVintf.cpp
index 9a35ca7..ddb513d 100644
--- a/AssembleVintf.cpp
+++ b/AssembleVintf.cpp
@@ -545,8 +545,10 @@ class AssembleVintfImpl : public AssembleVintf {
             // Use manifest.kernel()->level() directly because inferredKernelLevel()
             // reads manifest.level().
             manifest.kernel().has_value() && manifest.kernel()->level() != Level::UNSPECIFIED) {
-            err() << "Error: Device manifest with level " << manifest.level()
-                  << " must not set kernel level " << manifest.kernel()->level() << std::endl;
+            err() << "Error: Device manifest with target-level " << manifest.level()
+                  << " must not explicitly set kernel level in the manifest file. "
+                  << "The kernel level is currently explicitly set to "
+                  << manifest.kernel()->level() << std::endl;
             return false;
         }
         return true;
diff --git a/CompatibilityMatrix.cpp b/CompatibilityMatrix.cpp
index 4707221..799647a 100644
--- a/CompatibilityMatrix.cpp
+++ b/CompatibilityMatrix.cpp
@@ -236,7 +236,6 @@ bool CompatibilityMatrix::addAllHalsAsOptional(CompatibilityMatrix* other, std::
         }
 
         if (halToAdd.instancesCount() > 0) {
-            halToAdd.setOptional(true);
             if (!add(std::move(halToAdd))) {
                 if (error) {
                     *error = "Cannot add HAL " + name + " for unknown reason.";
@@ -256,7 +255,6 @@ bool CompatibilityMatrix::addAllXmlFilesAsOptional(CompatibilityMatrix* other, s
         const std::string& name = pair.first;
         MatrixXmlFile& xmlFileToAdd = pair.second;
 
-        xmlFileToAdd.mOptional = true;
         if (!addXmlFile(std::move(xmlFileToAdd))) {
             if (error) {
                 *error = "Cannot add XML File " + name + " for unknown reason.";
diff --git a/FQName.cpp b/FQName.cpp
index 5285a48..2a73fe6 100644
--- a/FQName.cpp
+++ b/FQName.cpp
@@ -19,6 +19,7 @@
 #include <android-base/logging.h>
 #include <android-base/parseint.h>
 #include <android-base/strings.h>
+#include <constants-private.h>
 #include <iostream>
 #include <sstream>
 
@@ -44,7 +45,7 @@ bool FQName::setTo(const std::string& package, size_t majorVer, size_t minorVer,
     mName = name;
 
     FQName other;
-    if (!parse(string(), &other)) return false;
+    if (!parse(parsedString(), &other)) return false;
     if ((*this) != other) return false;
     mIsIdentifier = other.isIdentifier();
     return true;
@@ -186,6 +187,17 @@ std::string FQName::version() const {
     if (!hasVersion()) {
         return "";
     }
+    if (mMajor == details::kFakeAidlMajorVersion) {
+        return std::to_string(mMinor);
+    }
+    return std::to_string(mMajor) + "." + std::to_string(mMinor);
+}
+
+std::string FQName::parsedVersion() const {
+    if (!hasVersion()) {
+        return "";
+    }
+
     return std::to_string(mMajor) + "." + std::to_string(mMinor);
 }
 
@@ -194,6 +206,11 @@ std::string FQName::atVersion() const {
     return v.empty() ? "" : ("@" + v);
 }
 
+std::string FQName::parsedAtVersion() const {
+    std::string v = parsedVersion();
+    return v.empty() ? "" : ("@" + v);
+}
+
 void FQName::clear() {
     mIsIdentifier = false;
     mPackage.clear();
@@ -242,6 +259,20 @@ const std::string& FQName::name() const {
     return mName;
 }
 
+std::string FQName::parsedString() const {
+    std::string out;
+    out.append(mPackage);
+    out.append(parsedAtVersion());
+    if (!mName.empty()) {
+        if (!mPackage.empty() || !parsedVersion().empty()) {
+            out.append("::");
+        }
+        out.append(mName);
+    }
+
+    return out;
+}
+
 std::string FQName::string() const {
     std::string out;
     out.append(mPackage);
@@ -261,7 +292,7 @@ bool FQName::operator<(const FQName& other) const {
 }
 
 bool FQName::operator==(const FQName& other) const {
-    return string() == other.string();
+    return parsedString() == other.parsedString();
 }
 
 bool FQName::operator!=(const FQName& other) const {
diff --git a/HalManifest.cpp b/HalManifest.cpp
index 5f371d4..e625efa 100644
--- a/HalManifest.cpp
+++ b/HalManifest.cpp
@@ -21,6 +21,7 @@
 
 #include <dirent.h>
 
+#include <algorithm>
 #include <mutex>
 #include <set>
 
@@ -345,43 +346,6 @@ void multilineIndent(std::ostream& os, size_t indent, const Container& lines) {
     }
 }
 
-// For each hal in mat, there must be a hal in manifest that supports this.
-std::vector<std::string> HalManifest::checkIncompatibleHals(const CompatibilityMatrix& mat) const {
-    std::vector<std::string> ret;
-    for (const MatrixHal &matrixHal : mat.getHals()) {
-        if (matrixHal.optional) {
-            continue;
-        }
-
-        std::set<FqInstance> manifestInstances;
-        std::set<std::string> manifestInstanceDesc;
-        std::set<Version> versions;
-        for (const ManifestHal* manifestHal : getHals(matrixHal.name)) {
-            manifestHal->forEachInstance([&](const auto& manifestInstance) {
-                manifestInstances.insert(manifestInstance.getFqInstance());
-                manifestInstanceDesc.insert(manifestInstance.descriptionWithoutPackage());
-                return true;
-            });
-            manifestHal->appendAllVersions(&versions);
-        }
-
-        if (!matrixHal.isCompatible(manifestInstances, versions)) {
-            std::ostringstream oss;
-            oss << matrixHal.name << ":\n    required: ";
-            multilineIndent(oss, 8, android::vintf::expandInstances(matrixHal));
-            oss << "\n    provided: ";
-            if (manifestInstances.empty()) {
-                multilineIndent(oss, 8, versions);
-            } else {
-                multilineIndent(oss, 8, manifestInstanceDesc);
-            }
-
-            ret.insert(ret.end(), oss.str());
-        }
-    }
-    return ret;
-}
-
 std::set<std::string> HalManifest::checkUnusedHals(
     const CompatibilityMatrix& mat, const std::vector<HidlInterfaceMetadata>& hidlMetadata) const {
     std::multimap<std::string, std::string> childrenMap;
@@ -495,21 +459,6 @@ bool HalManifest::checkCompatibility(const CompatibilityMatrix& mat, std::string
         }
         return false;
     }
-    auto incompatibleHals = checkIncompatibleHals(mat);
-    if (!incompatibleHals.empty()) {
-        if (error != nullptr) {
-            *error = "HALs incompatible.";
-            if (mat.level() != Level::UNSPECIFIED)
-                *error += " Matrix level = " + to_string(mat.level()) + ".";
-            if (level() != Level::UNSPECIFIED)
-                *error += " Manifest level = " + to_string(level()) + ".";
-            *error += " The following requirements are not met:\n";
-            for (const auto& e : incompatibleHals) {
-                *error += e + "\n";
-            }
-        }
-        return false;
-    }
     if (mType == SchemaType::FRAMEWORK) {
         if (!checkVendorNdkCompatibility(mat.device.mVendorNdk, framework.mVendorNdks, error)) {
             return false;
@@ -555,12 +504,12 @@ bool HalManifest::shouldCheckKernelCompatibility() const {
     return kernel().has_value() && kernel()->version() != KernelVersion{};
 }
 
-CompatibilityMatrix HalManifest::generateCompatibleMatrix(bool optional) const {
+CompatibilityMatrix HalManifest::generateCompatibleMatrix() const {
     CompatibilityMatrix matrix;
 
     std::set<std::tuple<HalFormat, std::string, Version, std::string, std::string>> instances;
 
-    forEachInstance([&matrix, &instances, optional](const ManifestInstance& e) {
+    forEachInstance([&matrix, &instances](const ManifestInstance& e) {
         auto&& [it, added] =
             instances.emplace(e.format(), e.package(), e.version(), e.interface(), e.instance());
         if (!added) {
@@ -571,7 +520,6 @@ CompatibilityMatrix HalManifest::generateCompatibleMatrix(bool optional) const {
             .format = e.format(),
             .name = e.package(),
             .versionRanges = {VersionRange{e.version().majorVer, e.version().minorVer}},
-            .optional = optional,
             .interfaces = {{e.interface(), HalInterface{e.interface(), {e.instance()}}}}});
         return true;
     });
diff --git a/MatrixHal.cpp b/MatrixHal.cpp
index d18c42c..cae780b 100644
--- a/MatrixHal.cpp
+++ b/MatrixHal.cpp
@@ -59,9 +59,7 @@ bool MatrixHal::operator==(const MatrixHal &other) const {
         return false;
     if (versionRanges != other.versionRanges)
         return false;
-    if (interfaces != other.interfaces)
-        return false;
-    // do not compare optional
+    if (interfaces != other.interfaces) return false;
     return true;
 }
 
@@ -90,7 +88,7 @@ bool MatrixHal::forEachInstance(const VersionRange& vr,
                 FqInstance fqInstance;
                 if (fqInstance.setTo(getName(), vr.majorVer, vr.minMinor, interface, instance)) {
                     if (!func(MatrixInstance(format, exclusiveTo, std::move(fqInstance),
-                                             VersionRange(vr), optional, isRegex))) {
+                                             VersionRange(vr), isRegex))) {
                         return false;
                     }
                 }
@@ -118,47 +116,6 @@ bool MatrixHal::forEachInstance(
     return true;
 }
 
-bool MatrixHal::isCompatible(const std::set<FqInstance>& providedInstances,
-                             const std::set<Version>& providedVersions) const {
-    // <version>'s are related by OR.
-    return std::any_of(versionRanges.begin(), versionRanges.end(), [&](const VersionRange& vr) {
-        return isCompatible(vr, providedInstances, providedVersions);
-    });
-}
-
-bool MatrixHal::isCompatible(const VersionRange& vr, const std::set<FqInstance>& providedInstances,
-                             const std::set<Version>& providedVersions) const {
-    bool hasAnyInstance = false;
-    bool versionUnsatisfied = false;
-
-    // Look at each interface/instance, and ensure that they are in providedInstances.
-    forEachInstance(vr, [&](const MatrixInstance& matrixInstance) {
-        hasAnyInstance = true;
-
-        versionUnsatisfied |=
-            !std::any_of(providedInstances.begin(), providedInstances.end(),
-                         [&](const FqInstance& providedInstance) {
-                             return matrixInstance.isSatisfiedBy(providedInstance);
-                         });
-
-        return !versionUnsatisfied;  // if any interface/instance is unsatisfied, break
-    });
-
-    if (hasAnyInstance) {
-        return !versionUnsatisfied;
-    }
-
-    // In some cases (e.g. tests and native HALs), compatibility matrix doesn't specify
-    // any instances. Check versions only.
-    return std::any_of(
-        providedVersions.begin(), providedVersions.end(),
-        [&](const auto& providedVersion) { return vr.supportedBy(providedVersion); });
-}
-
-void MatrixHal::setOptional(bool o) {
-    this->optional = o;
-}
-
 void MatrixHal::insertVersionRanges(const std::vector<VersionRange>& other) {
     for (const VersionRange& otherVr : other) {
         auto existingVr = std::find_if(this->versionRanges.begin(), this->versionRanges.end(),
diff --git a/MatrixInstance.cpp b/MatrixInstance.cpp
index 2ba1612..c9f0a5e 100644
--- a/MatrixInstance.cpp
+++ b/MatrixInstance.cpp
@@ -35,22 +35,19 @@ MatrixInstance& MatrixInstance::operator=(const MatrixInstance&) = default;
 MatrixInstance& MatrixInstance::operator=(MatrixInstance&&) noexcept = default;
 
 MatrixInstance::MatrixInstance(HalFormat format, ExclusiveTo exclusiveTo, FqInstance&& fqInstance,
-                               VersionRange&& range, bool optional, bool isRegex)
+                               VersionRange&& range, bool isRegex)
     : mFormat(format),
       mExclusiveTo(exclusiveTo),
       mFqInstance(std::move(fqInstance)),
       mRange(std::move(range)),
-      mOptional(optional),
       mIsRegex(isRegex) {}
 
 MatrixInstance::MatrixInstance(HalFormat format, ExclusiveTo exclusiveTo,
-                               const FqInstance fqInstance, const VersionRange& range,
-                               bool optional, bool isRegex)
+                               const FqInstance fqInstance, const VersionRange& range, bool isRegex)
     : mFormat(format),
       mExclusiveTo(exclusiveTo),
       mFqInstance(fqInstance),
       mRange(range),
-      mOptional(optional),
       mIsRegex(isRegex) {}
 
 const std::string& MatrixInstance::package() const {
@@ -73,10 +70,6 @@ ExclusiveTo MatrixInstance::exclusiveTo() const {
     return mExclusiveTo;
 }
 
-bool MatrixInstance::optional() const {
-    return mOptional;
-}
-
 bool MatrixInstance::isSatisfiedBy(const FqInstance& provided) const {
     return package() == provided.getPackage() &&
            versionRange().supportedBy(provided.getVersion()) &&
diff --git a/Regex.cpp b/Regex.cpp
index c343398..c001e7d 100644
--- a/Regex.cpp
+++ b/Regex.cpp
@@ -16,6 +16,8 @@
 
 #include "Regex.h"
 
+#include <memory>
+
 namespace android {
 namespace vintf {
 namespace details {
diff --git a/RuntimeInfo.cpp b/RuntimeInfo.cpp
index 9dc4ad5..515f5e2 100644
--- a/RuntimeInfo.cpp
+++ b/RuntimeInfo.cpp
@@ -200,7 +200,10 @@ Level RuntimeInfo::gkiAndroidReleaseToLevel(uint64_t androidRelease) {
                 ret = Level::V;
             } break;
             case 16: {
-                ret = Level::W;
+                ret = Level::B;
+            } break;
+            case 17: {
+                ret = Level::C;
             } break;
             // Add more levels above this line.
             default: {
diff --git a/SystemSdk.cpp b/SystemSdk.cpp
index 1dfd463..5c347c1 100644
--- a/SystemSdk.cpp
+++ b/SystemSdk.cpp
@@ -17,6 +17,7 @@
 #include "SystemSdk.h"
 
 #include <algorithm>
+#include <iterator>
 
 namespace android {
 namespace vintf {
diff --git a/VintfFm.cpp b/VintfFm.cpp
index 290ad3d..4a75e4a 100644
--- a/VintfFm.cpp
+++ b/VintfFm.cpp
@@ -230,6 +230,14 @@ int VintfFm::update(const FsFactory& vintfFsFactory, const std::string& dir, Lev
 }
 
 int VintfFm::check(const FsFactory& vintfFsFactory, const std::string& dir) {
+    // Treat all HALs in these frozen matrices as mandatory to have installed.
+    // This is a list of HALs that are not installed on all GSIs (like TVs, Wear
+    // devices, automotive).
+    const std::set<std::string> kOptionalInterfaces = {
+        "android.frameworks.cameraservice.service",
+        "android.frameworks.vibrator",
+        "android.hardware.security.keymint",
+    };
     auto frozenMatrices = loadMatrices(dir);
     if (!frozenMatrices.has_value()) {
         return EX_SOFTWARE;
@@ -246,6 +254,31 @@ int VintfFm::check(const FsFactory& vintfFsFactory, const std::string& dir) {
                        << ": " << error;
             return EX_SOFTWARE;
         }
+        bool mandatoryError = false;
+        matrix.forEachInstance([&](const MatrixInstance& hal) {
+            if (!kOptionalInterfaces.contains(hal.package())) {
+                bool found = false;
+                manifest->forEachInstance([&](const ManifestInstance& manifestHal) {
+                    if (hal.package() == manifestHal.package()) {
+                        found = true;
+                    }
+                    return true;
+                });
+                if (found == false) {
+                    LOG(ERROR) << "ERROR: " << hal.package()
+                               << " is not declared in the VINTF manifest but is mandatory";
+                    mandatoryError = true;
+                }
+            }
+            return true;
+        });
+        if (mandatoryError) {
+            LOG(ERROR) << "ERROR: Framework manifest at level "
+                       << std::to_string(static_cast<size_t>(level))
+                       << " is not compatible with the frozen device matrix:\n    "
+                       << matrix.fileName();
+            return EX_SOFTWARE;
+        }
     }
     return OK;
 }
@@ -262,7 +295,7 @@ std::shared_ptr<const HalManifest> VintfFm::getManifestForLevel(const FsFactory&
 
 bool VintfFm::dumpMatrix(const HalManifest& frameworkManifest, const std::string& dir,
                          Level level) {
-    auto matrix = frameworkManifest.generateCompatibleMatrix(false /*optional*/);
+    auto matrix = frameworkManifest.generateCompatibleMatrix();
     std::string path = dir + "/" + to_string(level) + ".xml";
     std::string error;
     if (OK != mFs->write(path, toXml(matrix), &error)) {
@@ -296,6 +329,7 @@ std::optional<VintfFm::FrozenMatrices> VintfFm::loadMatrices(const std::string&
             LOG(ERROR) << "Unable to parse " << path << ": " << error;
             return std::nullopt;
         }
+        matrix.setFileName(dir + filename);
         std::string_view filenameSv{filename};
         (void)android::base::ConsumeSuffix(&filenameSv, ".xml");
         std::string levelString{filenameSv};
diff --git a/VintfObject.cpp b/VintfObject.cpp
index f391679..708e58c 100644
--- a/VintfObject.cpp
+++ b/VintfObject.cpp
@@ -279,12 +279,26 @@ status_t VintfObject::addDirectoriesManifests(const std::vector<std::string>& di
     return OK;
 }
 
-// Fetch fragments from apexes originated from /vendor.
-// For now, we don't have /odm apexes.
-status_t VintfObject::fetchDeviceHalManifestApex(HalManifest* out, std::string* error) {
-    std::vector<std::string> dirs;
+// Fetch fragments originated from /vendor including apexes:
+// - /vendor/etc/vintf/manifest/
+// - /apex/{vendor apex}/etc/vintf/
+status_t VintfObject::fetchVendorHalFragments(HalManifest* out, std::string* error) {
+    std::vector<std::string> dirs = {kVendorManifestFragmentDir};
+    status_t status =
+        apex::GetVendorVintfDirs(getFileSystem().get(), getPropertyFetcher().get(), &dirs, error);
+    if (status != OK) {
+        return status;
+    }
+    return addDirectoriesManifests(dirs, out, /*forceSchemaType=*/false, error);
+}
+
+// Fetch fragments originated from /odm including apexes:
+// - /odm/etc/vintf/manifest/
+// - /apex/{odm apex}/etc/vintf/
+status_t VintfObject::fetchOdmHalFragments(HalManifest* out, std::string* error) {
+    std::vector<std::string> dirs = {kOdmManifestFragmentDir};
     status_t status =
-        apex::GetDeviceVintfDirs(getFileSystem().get(), getPropertyFetcher().get(), &dirs, error);
+        apex::GetOdmVintfDirs(getFileSystem().get(), getPropertyFetcher().get(), &dirs, error);
     if (status != OK) {
         return status;
     }
@@ -292,8 +306,8 @@ status_t VintfObject::fetchDeviceHalManifestApex(HalManifest* out, std::string*
 }
 
 // Priority for loading vendor manifest:
-// 1. Vendor manifest + device fragments (including vapex) + ODM manifest (optional) + odm fragments
-// 2. Vendor manifest + device fragments (including vapex)
+// 1. Vendor manifest + vendor fragments + ODM manifest (optional) + odm fragments
+// 2. Vendor manifest + vendor fragments
 // 3. ODM manifest (optional) + odm fragments
 // 4. /vendor/manifest.xml (legacy, no fragments)
 // where:
@@ -308,16 +322,10 @@ status_t VintfObject::fetchDeviceHalManifest(HalManifest* out, std::string* erro
 
     if (vendorStatus == OK) {
         *out = std::move(vendorManifest);
-        status_t fragmentStatus = addDirectoryManifests(kVendorManifestFragmentDir, out,
-                                                        false /* forceSchemaType*/, error);
+        status_t fragmentStatus = fetchVendorHalFragments(out, error);
         if (fragmentStatus != OK) {
             return fragmentStatus;
         }
-
-        status_t apexStatus = fetchDeviceHalManifestApex(out, error);
-        if (apexStatus != OK) {
-            return apexStatus;
-        }
     }
 
     HalManifest odmManifest;
@@ -335,15 +343,13 @@ status_t VintfObject::fetchDeviceHalManifest(HalManifest* out, std::string* erro
                 return UNKNOWN_ERROR;
             }
         }
-        return addDirectoryManifests(kOdmManifestFragmentDir, out, false /* forceSchemaType */,
-                                     error);
+        return fetchOdmHalFragments(out, error);
     }
 
     // vendorStatus != OK, "out" is not changed.
     if (odmStatus == OK) {
         *out = std::move(odmManifest);
-        return addDirectoryManifests(kOdmManifestFragmentDir, out, false /* forceSchemaType */,
-                                     error);
+        return fetchOdmHalFragments(out, error);
     }
 
     // Use legacy /vendor/manifest.xml
@@ -804,8 +810,10 @@ bool VintfObject::IsInstanceDeprecated(const MatrixInstance& oldMatrixInstance,
     auto addErrorForInstance = [&](const ManifestInstance& manifestInstance) {
         const std::string& servedInstance = manifestInstance.instance();
         Version servedVersion = manifestInstance.version();
-        if (!oldMatrixInstance.matchInstance(servedInstance)) {
-            // ignore unrelated instance
+
+        // ignore unrelated instance on old devices only
+        if (!oldMatrixInstance.matchInstance(servedInstance) &&
+            deviceManifest->level() < Level::B) {
             return true;  // continue
         }
 
@@ -1005,8 +1013,14 @@ int32_t VintfObject::checkDeprecation(const std::vector<HidlInterfaceMetadata>&
     // Move these matrices into the targetMatrices vector...
     std::move(targetMatricesPartition, matrixFragments.end(), std::back_inserter(targetMatrices));
     if (targetMatrices.empty()) {
-        if (error)
-            *error = "Cannot find framework matrix at FCM version " + to_string(deviceLevel) + ".";
+        if (error) {
+            std::vector<std::string> files;
+            for (const auto& matrix : matrixFragments) {
+                files.push_back(matrix.fileName());
+            }
+            *error = "Cannot find framework matrix at FCM version " + to_string(deviceLevel) +
+                     ". Looked in:\n    " + android::base::Join(files, "\n    ");
+        }
         return NAME_NOT_FOUND;
     }
     // so that they can be combined into one matrix for deprecation checking.
diff --git a/XmlFile.cpp b/XmlFile.cpp
index 695b3d4..6884b7c 100644
--- a/XmlFile.cpp
+++ b/XmlFile.cpp
@@ -21,8 +21,7 @@ namespace vintf {
 
 bool MatrixXmlFile::operator==(const MatrixXmlFile& other) const {
     return name() == other.name() && overriddenPath() == other.overriddenPath() &&
-           optional() == other.optional() && format() == other.format() &&
-           versionRange() == other.versionRange();
+           format() == other.format() && versionRange() == other.versionRange();
 }
 
 bool ManifestXmlFile::operator==(const ManifestXmlFile& other) const {
diff --git a/analyze_matrix/analyze_matrix.cpp b/analyze_matrix/analyze_matrix.cpp
index c5eee23..0666880 100644
--- a/analyze_matrix/analyze_matrix.cpp
+++ b/analyze_matrix/analyze_matrix.cpp
@@ -46,19 +46,15 @@ std::optional<T> readObject(const std::string& path) {
 }
 
 template <typename F>
-std::set<std::string> getDescription(const CompatibilityMatrix& mat, F descriptionFn,
-                                     bool emitReq) {
+std::set<std::string> getDescription(const CompatibilityMatrix& mat, F descriptionFn) {
     std::set<std::string> set;
-    mat.forEachInstance([&set, descriptionFn, emitReq](const auto& matrixInstance) {
+    mat.forEachInstance([&set, descriptionFn](const auto& matrixInstance) {
         for (auto minorVer = matrixInstance.versionRange().minMinor;
              minorVer >= matrixInstance.versionRange().minMinor &&
              minorVer <= matrixInstance.versionRange().maxMinor;
              ++minorVer) {
             Version version{matrixInstance.versionRange().majorVer, minorVer};
             std::string s = std::invoke(descriptionFn, matrixInstance, version);
-            if (emitReq) {
-                s += (matrixInstance.optional() ? " optional" : " required");
-            }
             set.insert(s);
         }
         return true;  // continue
@@ -90,9 +86,10 @@ std::string GetDescription(Level level) {
             return "Android 14 (U)";
         case Level::V:
             return "Android 15 (V)";
-        case Level::W:
-            // TODO(b/346861728) verify name/number once decided
-            return "Android 16 (W)";
+        case Level::B:
+            return "Android 16 (B)";
+        case Level::C:
+            return "Android 17 (C)";
         case Level::UNSPECIFIED:
             return "Level unspecified";
         default:
@@ -113,7 +110,6 @@ DEFINE_bool(level, false, "Write level (FCM version) of the compatibility matrix
 DEFINE_bool(level_name, false, "Write level name (FCM version) of the compatibility matrix.");
 DEFINE_bool(interfaces, false, "Write strings like \"android.hardware.foo@1.0::IFoo\".");
 DEFINE_bool(instances, false, "Write strings like \"android.hardware.foo@1.0::IFoo/default\".");
-DEFINE_bool(requirement, false, "Append optional/required after each interface / instance.");
 
 int main(int argc, char** argv) {
     using namespace android::vintf;
@@ -146,8 +142,7 @@ int main(int argc, char** argv) {
     }
 
     if (FLAGS_interfaces) {
-        auto interfaces =
-            getDescription(*mat, &MatrixInstance::interfaceDescription, FLAGS_requirement);
+        auto interfaces = getDescription(*mat, &MatrixInstance::interfaceDescription);
         if (interfaces.empty()) {
             LOG(WARNING) << "No interfaces are found.";
         }
@@ -160,7 +155,7 @@ int main(int argc, char** argv) {
     }
 
     if (FLAGS_instances) {
-        auto instances = getDescription(*mat, &MatrixInstance::description, FLAGS_requirement);
+        auto instances = getDescription(*mat, &MatrixInstance::description);
         if (instances.empty()) {
             LOG(WARNING) << "No instances are found.";
         }
diff --git a/analyze_matrix/hals_for_release.py b/analyze_matrix/hals_for_release.py
index 14c214b..e0dbd66 100755
--- a/analyze_matrix/hals_for_release.py
+++ b/analyze_matrix/hals_for_release.py
@@ -184,7 +184,7 @@ def ReadMatrices(args: argparse.Namespace) -> dict[int, MatrixData]:
       logger.debug("Ignoring file %s", file)
       continue
     action = "--instances" if args.instances else "--interfaces"
-    instances = Analyze(args.analyze_matrix, file, [action, "--requirement"]).split("\n")
+    instances = Analyze(args.analyze_matrix, file, [action,]).split("\n")
     instances = set(map(str.strip, instances)) - {""}
     if level in matrices:
       logger.warning("Found duplicated matrix for level %s, ignoring: %s", level, file)
@@ -390,13 +390,13 @@ class HumanReadableReport(Report):
     desc = lambda fmt, instance: fmt.format(GetHalFormat(instance).name,
                                             *SplitInstance(instance))
     if self.args.deprecated:
-      package_report += [desc("- {0} {2} can no longer be used", instance)
+      package_report += [desc("- {0} {2} {3} can no longer be used", instance)
                          for instance in deprecated]
     if self.args.unchanged:
-      package_report += [desc("  {0} {2}", instance) for instance in
+      package_report += [desc("  {0} {2} {3}", instance) for instance in
                          unchanged]
     if self.args.introduced:
-      package_report += [desc("+ {0} {2}", instance) for instance in
+      package_report += [desc("+ {0} {2} {3}", instance) for instance in
                          introduced]
 
     return package_report
diff --git a/check_vintf.cpp b/check_vintf.cpp
index 2f513ed..3e4e105 100644
--- a/check_vintf.cpp
+++ b/check_vintf.cpp
@@ -360,56 +360,6 @@ int usage(const char* me) {
     return EX_USAGE;
 }
 
-class CheckVintfUtils {
-   public:
-    // Print HALs in the device manifest that are not declared in FCMs <= target FCM version.
-    static void logHalsFromNewFcms(VintfObject* vintfObject,
-                                   const std::vector<HidlInterfaceMetadata>& hidlMetadata) {
-        auto deviceManifest = vintfObject->getDeviceHalManifest();
-        if (deviceManifest == nullptr) {
-            LOG(WARNING) << "Unable to print HALs from new FCMs: no device HAL manifest.";
-            return;
-        }
-        std::string kernelLevelError;
-        auto kernelLevel = vintfObject->getKernelLevel(&kernelLevelError);
-        if (kernelLevel == Level::UNSPECIFIED) {
-            LOG(WARNING) << "getKernelLevel: " << kernelLevel;
-        }
-        std::vector<CompatibilityMatrix> matrixFragments;
-        std::string error;
-        auto status = vintfObject->getAllFrameworkMatrixLevels(&matrixFragments, &error);
-        if (status != OK || matrixFragments.empty()) {
-            LOG(WARNING) << "Unable to print HALs from new FCMs: " << statusToString(status) << ": "
-                         << error;
-            return;
-        }
-        auto it = std::remove_if(matrixFragments.begin(), matrixFragments.end(),
-                                 [&](const CompatibilityMatrix& matrix) {
-                                     return matrix.level() != Level::UNSPECIFIED &&
-                                            matrix.level() > deviceManifest->level();
-                                 });
-        matrixFragments.erase(it, matrixFragments.end());
-        auto combined = CompatibilityMatrix::combine(deviceManifest->level(), kernelLevel,
-                                                     &matrixFragments, &error);
-        if (combined == nullptr) {
-            LOG(WARNING) << "Unable to print HALs from new FCMs: unable to combine matrix "
-                            "fragments <= level "
-                         << deviceManifest->level() << ": " << error;
-        }
-        auto unused = deviceManifest->checkUnusedHals(*combined, hidlMetadata);
-        if (unused.empty()) {
-            LOG(INFO) << "All HALs in device manifest are declared in FCM <= level "
-                      << deviceManifest->level();
-            return;
-        }
-        LOG(INFO) << "The following HALs in device manifest are not declared in FCM <= level "
-                  << deviceManifest->level() << ": ";
-        for (const auto& hal : unused) {
-            LOG(INFO) << "  " << hal;
-        }
-    }
-};
-
 // If |result| is already an error, don't do anything. Otherwise, set it to
 // an error with |errorCode|. Return reference to Error object for appending
 // additional error messages.
@@ -492,8 +442,6 @@ android::base::Result<void> checkAllFiles(const Dirmap& dirmap, const Properties
         LOG(INFO) << "Skip checking unused HALs.";
     }
 
-    CheckVintfUtils::logHalsFromNewFcms(vintfObject.get(), hidlMetadata);
-
     if (retError.has_value()) {
         return *retError;
     } else {
@@ -571,11 +519,15 @@ int checkOne(const Dirmap& dirmap, const Properties& props) {
 
 void Logger(android::base::LogId, android::base::LogSeverity severity, const char* /*tag*/,
             const char* /*file*/, unsigned int /*line*/, const char* message) {
-    if (severity >= android::base::WARNING) {
+    if (severity >= android::base::ERROR) {
+        fflush(stdout);
+        fprintf(stderr, "\033[31m%s\033[0m\n", message);
+    } else if (severity >= android::base::WARNING) {
         fflush(stdout);
-        fprintf(stderr, "%s\n", message);
+        fprintf(stderr, "\033[33m[WARN] %s\033[0m\n", message);
     } else {
-        fprintf(stdout, "%s\n", message);
+        fflush(stderr);
+        fprintf(stdout, "[INFO] %s\n", message);
     }
 }
 
diff --git a/include/vintf/Apex.h b/include/vintf/Apex.h
index 175ae96..e0317f5 100644
--- a/include/vintf/Apex.h
+++ b/include/vintf/Apex.h
@@ -26,8 +26,10 @@
 namespace android::vintf::apex {
 
 std::optional<timespec> GetModifiedTime(FileSystem* fileSystem, PropertyFetcher* propertyFetcher);
-status_t GetDeviceVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
+status_t GetVendorVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
                             std::vector<std::string>* out, std::string* error);
+status_t GetOdmVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
+                         std::vector<std::string>* out, std::string* error);
 status_t GetFrameworkVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
                                std::vector<std::string>* out, std::string* error);
 
diff --git a/include/vintf/FQName.h b/include/vintf/FQName.h
index b933d59..4d4d4cc 100644
--- a/include/vintf/FQName.h
+++ b/include/vintf/FQName.h
@@ -34,8 +34,14 @@ struct FQName {
                                                    size_t minorVer, const std::string& name = "");
 
     const std::string& package() const;
-    // Return version in the form "1.0" if it is present, otherwise empty string.
+    // Return version in the form "1.0" for HIDL interfaces with major.minor versions,
+    // "1" for AIDL versions that have minor version set with `kFakeAidlMajorVersion` as
+    // the major version, and an empty string if there is no version set.
     std::string version() const;
+    // Same as version, but keeps the kFakeAidlMajorVersion in the string.
+    // This is still required for all of the parsing/assembling but not desired
+    // for logging and errors.
+    std::string parsedVersion() const;
     // Return true only if version is present.
     bool hasVersion() const;
     // Return pair of (major, minor) version. Defaults to 0, 0.
@@ -69,6 +75,10 @@ struct FQName {
     bool isInterfaceName() const;
 
     std::string string() const;
+    // Same as string, but keeps the kFakeAidlMajorVersion in the string.
+    // This is still required for all of the parsing/assembling but not desired
+    // for logging and errors.
+    std::string parsedString() const;
 
     bool operator<(const FQName& other) const;
     bool operator==(const FQName& other) const;
@@ -121,6 +131,10 @@ struct FQName {
     bool isIdentifier() const;
     // Return version in the form "@1.0" if it is present, otherwise empty string.
     std::string atVersion() const;
+    // Same as atVersion, but keeps the kFakeAidlMajorVersion in the string.
+    // This is still required for all of the parsing/assembling but not desired
+    // for logging and errors.
+    std::string parsedAtVersion() const;
 
     std::vector<std::string> getPackageComponents() const;
 };
diff --git a/include/vintf/HalGroup.h b/include/vintf/HalGroup.h
index cdc1cec..39e5eff 100644
--- a/include/vintf/HalGroup.h
+++ b/include/vintf/HalGroup.h
@@ -17,6 +17,7 @@
 #ifndef ANDROID_VINTF_HAL_GROUP_H
 #define ANDROID_VINTF_HAL_GROUP_H
 
+#include <functional>
 #include <map>
 #include <set>
 
diff --git a/include/vintf/HalManifest.h b/include/vintf/HalManifest.h
index 34dec69..a55523d 100644
--- a/include/vintf/HalManifest.h
+++ b/include/vintf/HalManifest.h
@@ -91,7 +91,7 @@ struct HalManifest : public HalGroup<ManifestHal>,
                             CheckFlags::Type flags = CheckFlags::DEFAULT) const;
 
     // Generate a compatibility matrix such that checkCompatibility will return true.
-    CompatibilityMatrix generateCompatibleMatrix(bool optional = true) const;
+    CompatibilityMatrix generateCompatibleMatrix() const;
 
     // Returns all component names.
     std::set<std::string> getHalNames() const;
@@ -183,8 +183,6 @@ struct HalManifest : public HalGroup<ManifestHal>,
                                  std::string* error = nullptr);
 
     details::Instances expandInstances(const std::string& name) const;
-    // Check if all instances in matrixHal is supported in this manifest.
-    bool isCompatible(const details::Instances& instances, const MatrixHal& matrixHal) const;
 
     // Return a list of error messages (for each <hal> name) that does NOT conform to
     // the given compatibility matrix. It does not contain components that are optional.
diff --git a/include/vintf/Level.h b/include/vintf/Level.h
index 37dbbe7..c7f37ed 100644
--- a/include/vintf/Level.h
+++ b/include/vintf/Level.h
@@ -43,7 +43,8 @@ enum class Level : size_t {
     T = 7,
     U = 8,
     V = 202404,
-    W = 202504,  // TODO(346861728) placeholder letter/number.
+    B = 202504,
+    C = 202604,
     // To add new values:
     // (1) add above this line.
     // (2) edit array below
@@ -69,7 +70,8 @@ inline bool IsValid(Level level) {
         Level::T,
         Level::U,
         Level::V,
-        Level::W,
+        Level::B,
+        Level::C,
         Level::UNSPECIFIED,
         // clang-format on
     };
diff --git a/include/vintf/MatrixHal.h b/include/vintf/MatrixHal.h
index af964cf..15c0a8a 100644
--- a/include/vintf/MatrixHal.h
+++ b/include/vintf/MatrixHal.h
@@ -42,7 +42,6 @@ struct MatrixHal {
     HalFormat format = HalFormat::HIDL;
     std::string name;
     std::vector<VersionRange> versionRanges;
-    bool optional = false;
     ExclusiveTo exclusiveTo = ExclusiveTo::EMPTY;
     bool updatableViaApex = false;
     std::map<std::string, HalInterface> interfaces;
@@ -74,12 +73,6 @@ struct MatrixHal {
         const std::function<bool(const std::vector<VersionRange>&, const std::string&,
                                  const std::string& instanceOrPattern, bool isRegex)>& func) const;
 
-    bool isCompatible(const std::set<FqInstance>& providedInstances,
-                      const std::set<Version>& providedVersions) const;
-    bool isCompatible(const VersionRange& vr, const std::set<FqInstance>& providedInstances,
-                      const std::set<Version>& providedVersions) const;
-
-    void setOptional(bool o);
     void insertVersionRanges(const std::vector<VersionRange>& other);
     // Return size of all interface/instance pairs.
     size_t instancesCount() const;
diff --git a/include/vintf/MatrixInstance.h b/include/vintf/MatrixInstance.h
index 73b9a92..1966220 100644
--- a/include/vintf/MatrixInstance.h
+++ b/include/vintf/MatrixInstance.h
@@ -38,13 +38,12 @@ class MatrixInstance {
     using VersionType = VersionRange;
     // fqInstance.version is ignored. Version range is provided separately.
     MatrixInstance(HalFormat format, ExclusiveTo exclusiveTo, FqInstance&& fqInstance,
-                   VersionRange&& range, bool optional, bool isRegex);
+                   VersionRange&& range, bool isRegex);
     MatrixInstance(HalFormat format, ExclusiveTo exclusiveTo, const FqInstance fqInstance,
-                   const VersionRange& range, bool optional, bool isRegex);
+                   const VersionRange& range, bool isRegex);
     const std::string& package() const;
     const VersionRange& versionRange() const;
     std::string interface() const;
-    bool optional() const;
     HalFormat format() const;
     ExclusiveTo exclusiveTo() const;
 
@@ -80,7 +79,6 @@ class MatrixInstance {
     ExclusiveTo mExclusiveTo = ExclusiveTo::EMPTY;
     FqInstance mFqInstance;
     VersionRange mRange;
-    bool mOptional = false;
     bool mIsRegex = false;
 };
 
diff --git a/include/vintf/Regex.h b/include/vintf/Regex.h
index 86c66f2..3c2682f 100644
--- a/include/vintf/Regex.h
+++ b/include/vintf/Regex.h
@@ -18,6 +18,7 @@
 #define ANDROID_VINTF_REGEX_H_
 
 #include <regex.h>
+#include <memory>
 #include <string>
 
 namespace android {
diff --git a/include/vintf/VintfObject.h b/include/vintf/VintfObject.h
index a7ba2ba..8476a41 100644
--- a/include/vintf/VintfObject.h
+++ b/include/vintf/VintfObject.h
@@ -309,12 +309,13 @@ class VintfObject {
                                      HalManifest* manifests, bool ignoreSchemaType,
                                      std::string* error);
     status_t fetchDeviceHalManifest(HalManifest* out, std::string* error = nullptr);
-    status_t fetchDeviceHalManifestApex(HalManifest* out, std::string* error = nullptr);
     status_t fetchDeviceMatrix(CompatibilityMatrix* out, std::string* error = nullptr);
     status_t fetchOdmHalManifest(HalManifest* out, std::string* error = nullptr);
+    status_t fetchOdmHalFragments(HalManifest* out, std::string* error = nullptr);
     status_t fetchOneHalManifest(const std::string& path, HalManifest* out,
                                  std::string* error = nullptr);
     status_t fetchVendorHalManifest(HalManifest* out, std::string* error = nullptr);
+    status_t fetchVendorHalFragments(HalManifest* out, std::string* error = nullptr);
     status_t fetchFrameworkHalManifest(HalManifest* out, std::string* error = nullptr);
     status_t fetchFrameworkHalManifestApex(HalManifest* out, std::string* error = nullptr);
 
diff --git a/include/vintf/XmlFile.h b/include/vintf/XmlFile.h
index 1ad57bb..7e6819f 100644
--- a/include/vintf/XmlFile.h
+++ b/include/vintf/XmlFile.h
@@ -38,7 +38,6 @@ struct XmlFile {
 
 // An <xmlfile> entry in matrix
 struct MatrixXmlFile : public XmlFile {
-    inline bool optional() const { return mOptional; }
     inline XmlSchemaFormat format() const { return mFormat; }
     inline const VersionRange& versionRange() const { return mVersionRange; }
     bool operator==(const MatrixXmlFile& other) const;
@@ -47,7 +46,6 @@ struct MatrixXmlFile : public XmlFile {
     friend struct CompatibilityMatrix;
     friend struct MatrixXmlFileConverter;
     friend struct LibVintfTest;
-    bool mOptional;
     XmlSchemaFormat mFormat;
     VersionRange mVersionRange;
 };
diff --git a/main.cpp b/main.cpp
index 8c3dfa2..15ff524 100644
--- a/main.cpp
+++ b/main.cpp
@@ -29,7 +29,7 @@
 
 using namespace ::android::vintf;
 
-static const std::string kColumnSeperator = "   ";
+static const std::string kColumnSeparator = "   ";
 
 std::string existString(bool value) {
     return value ? "GOOD" : "DOES NOT EXIST";
@@ -205,27 +205,12 @@ struct TableRow {
     bool fm = false;
     bool dcm = false;
     bool fcm = false;
-    // If the HAL version is in device / framework compatibility matrix, whether it is required
-    // or not.
-    bool required = false;
-
-    // Return true if:
-    // - not a required HAL version; OR
-    // - required in device matrix and framework manifest;
-    // - required in framework matrix and device manifest.
-    bool meetsReqeuirement() const {
-        if (!required) return true;
-        if (dcm && !fm) return false;
-        if (fcm && !dm) return false;
-        return true;
-    }
 };
 
 std::ostream& operator<<(std::ostream& out, const TableRow& row) {
-    return out << (row.required ? "R" : " ") << (row.meetsReqeuirement() ? " " : "!")
-               << kColumnSeperator << (row.dm ? "DM" : "  ") << kColumnSeperator
-               << (row.fm ? "FM" : "  ") << kColumnSeperator << (row.fcm ? "FCM" : "   ")
-               << kColumnSeperator << (row.dcm ? "DCM" : "   ");
+    return out << kColumnSeparator << (row.dm ? "DM" : "  ") << kColumnSeparator
+               << (row.fm ? "FM" : "  ") << kColumnSeparator << (row.fcm ? "FCM" : "   ")
+               << kColumnSeparator << (row.dcm ? "DCM" : "   ");
 }
 
 using RowMutator = std::function<void(TableRow*)>;
@@ -256,9 +241,6 @@ void insert(const CompatibilityMatrix* matrix, Table* table, const RowMutator& m
                 mutate(&(*table)[key]);
             } else {
                 mutate(&it->second);
-                if (minorVer == matrixInstance.versionRange().minMinor) {
-                    it->second.required = !matrixInstance.optional();
-                }
             }
         }
         return true;
@@ -301,8 +283,6 @@ void dumpLegacy(const ParsedOptions& options) {
 
     if (!options.verbose) {
         std::cout << "======== HALs =========" << std::endl
-                  << "R: required. (empty): optional or missing from matrices. "
-                  << "!: required and not in manifest." << std::endl
                   << "DM: device manifest. FM: framework manifest." << std::endl
                   << "FCM: framework compatibility matrix. DCM: device compatibility matrix."
                   << std::endl
@@ -310,7 +290,7 @@ void dumpLegacy(const ParsedOptions& options) {
         auto table = generateHalSummary(vm.get(), fm.get(), vcm.get(), fcm.get());
 
         for (const auto& pair : table)
-            std::cout << pair.second << kColumnSeperator << pair.first << std::endl;
+            std::cout << pair.second << kColumnSeparator << pair.first << std::endl;
 
         std::cout << std::endl;
     }
diff --git a/parse_string.cpp b/parse_string.cpp
index c95fe10..40221de 100644
--- a/parse_string.cpp
+++ b/parse_string.cpp
@@ -248,7 +248,11 @@ bool parse(const std::string& s, SepolicyVersion* sepolicyVer) {
 }
 
 std::ostream &operator<<(std::ostream &os, const Version &ver) {
-    return os << ver.majorVer << "." << ver.minorVer;
+    if (ver.majorVer == details::kFakeAidlMajorVersion) {
+        return os << ver.minorVer;
+    } else {
+        return os << ver.majorVer << "." << ver.minorVer;
+    }
 }
 
 std::ostream& operator<<(std::ostream& os, const SepolicyVersion& ver) {
diff --git a/parse_xml.cpp b/parse_xml.cpp
index 37483f5..7c67314 100644
--- a/parse_xml.cpp
+++ b/parse_xml.cpp
@@ -644,7 +644,6 @@ struct MatrixHalConverter : public XmlNodeConverter<MatrixHal> {
     void mutateNode(const MatrixHal& object, NodeType* root,
                     const MutateNodeParam& param) const override {
         appendAttr(root, "format", object.format);
-        appendAttr(root, "optional", object.optional);
         // Only include if it is not the default empty value
         if (object.exclusiveTo != ExclusiveTo::EMPTY) {
             appendAttr(root, "exclusive-to", object.exclusiveTo);
@@ -671,8 +670,6 @@ struct MatrixHalConverter : public XmlNodeConverter<MatrixHal> {
                      const BuildObjectParam& param) const override {
         std::vector<HalInterface> interfaces;
         if (!parseOptionalAttr(root, "format", HalFormat::HIDL, &object->format, param) ||
-            !parseOptionalAttr(root, "optional", true /* defaultValue */, &object->optional,
-                               param) ||
             !parseOptionalAttr(root, "exclusive-to", ExclusiveTo::EMPTY, &object->exclusiveTo,
                                param) ||
             !parseOptionalAttr(root, "updatable-via-apex", false /* defaultValue */,
@@ -1441,7 +1438,6 @@ struct MatrixXmlFileConverter : public XmlNodeConverter<MatrixXmlFile> {
                     const MutateNodeParam& param) const override {
         appendTextElement(root, "name", object.name(), param.d);
         appendAttr(root, "format", object.format());
-        appendAttr(root, "optional", object.optional());
         appendChild(root, VersionRangeConverter{}(object.versionRange(), param));
         if (!object.overriddenPath().empty()) {
             appendTextElement(root, "path", object.overriddenPath(), param.d);
@@ -1451,7 +1447,6 @@ struct MatrixXmlFileConverter : public XmlNodeConverter<MatrixXmlFile> {
                      const BuildObjectParam& param) const override {
         if (!parseTextElement(root, "name", &object->mName, param.error) ||
             !parseAttr(root, "format", &object->mFormat, param.error) ||
-            !parseOptionalAttr(root, "optional", false, &object->mOptional, param) ||
             !parseChild(root, VersionRangeConverter{}, &object->mVersionRange, param) ||
             !parseOptionalTextElement(root, "path", {}, &object->mOverriddenPath, param.error)) {
             return false;
@@ -1595,11 +1590,6 @@ struct CompatibilityMatrixConverter : public XmlNodeConverter<CompatibilityMatri
             return false;
         }
         for (auto&& xmlFile : xmlFiles) {
-            if (!xmlFile.optional()) {
-                *param.error = "compatibility-matrix.xmlfile entry " + xmlFile.name() +
-                               " has to be optional for compatibility matrix version 1.0";
-                return false;
-            }
             std::string description{xmlFile.name()};
             if (!object->addXmlFile(std::move(xmlFile))) {
                 *param.error = "Duplicated compatibility-matrix.xmlfile entry " + description;
diff --git a/test/AssembleVintfTest.cpp b/test/AssembleVintfTest.cpp
index f243cf9..f4e33ce 100644
--- a/test/AssembleVintfTest.cpp
+++ b/test/AssembleVintfTest.cpp
@@ -181,7 +181,7 @@ TEST_F(AssembleVintfTest, FrameworkMatrix) {
 
     std::string xml1 =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -193,7 +193,7 @@ TEST_F(AssembleVintfTest, FrameworkMatrix) {
 
     std::string xml2 =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0-1</version>\n"
         "        <interface>\n"
@@ -205,7 +205,7 @@ TEST_F(AssembleVintfTest, FrameworkMatrix) {
 
     std::string xml3 =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"3\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>2.0</version>\n"
         "        <interface>\n"
@@ -255,7 +255,7 @@ TEST_F(AssembleVintfTest, FrameworkMatrix) {
     EXPECT_TRUE(getInstance()->assemble());
     EXPECT_IN(
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0-1</version>\n"
         "        <version>2.0</version>\n"
@@ -273,7 +273,7 @@ TEST_F(AssembleVintfTest, FrameworkMatrix) {
     EXPECT_TRUE(getInstance()->assemble());
     EXPECT_IN(
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0-1</version>\n"
         "        <version>2.0</version>\n"
@@ -291,7 +291,7 @@ TEST_F(AssembleVintfTest, FrameworkMatrix) {
     EXPECT_TRUE(getInstance()->assemble());
     EXPECT_IN(
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"3\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>2.0</version>\n"
         "        <interface>\n"
@@ -428,7 +428,7 @@ TEST_F(AssembleVintfTest, DeviceFrameworkMatrixOptional) {
 
     addInput("compatibility_matrix.empty.xml",
              "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-             "    <hal format=\"hidl\" optional=\"true\">\n"
+             "    <hal format=\"hidl\">\n"
              "        <name>vendor.foo.bar</name>\n"
              "        <version>1.0</version>\n"
              "        <interface>\n"
@@ -441,7 +441,7 @@ TEST_F(AssembleVintfTest, DeviceFrameworkMatrixOptional) {
     EXPECT_TRUE(getInstance()->assemble());
     EXPECT_IN(
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>vendor.foo.bar</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -462,29 +462,6 @@ TEST_F(AssembleVintfTest, DeviceFrameworkMatrixOptional) {
         getOutput());
 }
 
-TEST_F(AssembleVintfTest, DeviceFrameworkMatrixRequired) {
-    setFakeEnvs({{"POLICYVERS", "30"},
-                 {"PLATFORM_SEPOLICY_VERSION", "202404"},
-                 {"PLATFORM_SEPOLICY_COMPAT_VERSIONS", "26.0 27.0"},
-                 {"FRAMEWORK_VBMETA_VERSION", "1.0"},
-                 {"PRODUCT_ENFORCE_VINTF_MANIFEST", "true"}});
-    getInstance()->setCheckInputStream("check.xml", makeStream(gEmptyOutManifest));
-
-    addInput("compatibility_matrix.empty.xml",
-             "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-             "    <hal format=\"hidl\" optional=\"false\">\n"
-             "        <name>vendor.foo.bar</name>\n"
-             "        <version>1.0</version>\n"
-             "        <interface>\n"
-             "            <name>IFoo</name>\n"
-             "            <instance>default</instance>\n"
-             "        </interface>\n"
-             "    </hal>\n"
-             "</compatibility-matrix>");
-
-    EXPECT_FALSE(getInstance()->assemble());
-}
-
 TEST_F(AssembleVintfTest, DeviceFrameworkMatrixMultiple) {
     setFakeEnvs({{"POLICYVERS", "30"},
                  {"PLATFORM_SEPOLICY_VERSION", "202404"},
@@ -495,7 +472,7 @@ TEST_F(AssembleVintfTest, DeviceFrameworkMatrixMultiple) {
 
     addInput("compatibility_matrix.foobar.xml",
              "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-             "    <hal format=\"hidl\" optional=\"true\">\n"
+             "    <hal format=\"hidl\">\n"
              "        <name>vendor.foo.bar</name>\n"
              "        <version>1.0</version>\n"
              "        <interface>\n"
@@ -507,7 +484,7 @@ TEST_F(AssembleVintfTest, DeviceFrameworkMatrixMultiple) {
 
     addInput("compatibility_matrix.bazquux.xml",
              "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-             "    <hal format=\"hidl\" optional=\"true\">\n"
+             "    <hal format=\"hidl\">\n"
              "        <name>vendor.baz.quux</name>\n"
              "        <version>1.0</version>\n"
              "        <interface>\n"
@@ -520,7 +497,7 @@ TEST_F(AssembleVintfTest, DeviceFrameworkMatrixMultiple) {
     EXPECT_TRUE(getInstance()->assemble());
     EXPECT_IN(
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>vendor.baz.quux</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -528,7 +505,7 @@ TEST_F(AssembleVintfTest, DeviceFrameworkMatrixMultiple) {
         "            <instance>default</instance>\n"
         "        </interface>\n"
         "    </hal>\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>vendor.foo.bar</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
diff --git a/test/LibVintfTest.cpp b/test/LibVintfTest.cpp
index 2bc3c0a..7b414da 100644
--- a/test/LibVintfTest.cpp
+++ b/test/LibVintfTest.cpp
@@ -78,7 +78,6 @@ public:
         f.mName = name;
         f.mVersionRange = range;
         f.mFormat = XmlSchemaFormat::DTD;
-        f.mOptional = true;
         cm.addXmlFile(std::move(f));
     }
     void set(CompatibilityMatrix &cm, Sepolicy &&sepolicy) {
@@ -736,12 +735,12 @@ static bool insert(std::map<std::string, HalInterface>* map, HalInterface&& intf
 TEST_F(LibVintfTest, MatrixHalConverter) {
     MatrixHal mh{HalFormat::NATIVE, "android.hardware.camera",
             {{VersionRange(1,2,3), VersionRange(4,5,6)}},
-            false /* optional */, ExclusiveTo::EMPTY, false /* updatableViaApex */, {}};
+            ExclusiveTo::EMPTY, false /* updatableViaApex */, {}};
     EXPECT_TRUE(insert(&mh.interfaces, {"IBetterCamera", {"default", "great"}}));
     EXPECT_TRUE(insert(&mh.interfaces, {"ICamera", {"default"}}));
     std::string xml = toXml(mh);
     EXPECT_EQ(xml,
-        "<hal format=\"native\" optional=\"false\">\n"
+        "<hal format=\"native\">\n"
         "    <name>android.hardware.camera</name>\n"
         "    <version>1.2-3</version>\n"
         "    <version>4.5-6</version>\n"
@@ -848,11 +847,11 @@ TEST_F(LibVintfTest, CompatibilityMatrixConverter) {
     CompatibilityMatrix cm;
     EXPECT_TRUE(add(cm, MatrixHal{HalFormat::NATIVE, "android.hardware.camera",
             {{VersionRange(1,2,3), VersionRange(4,5,6)}},
-            false /* optional */, ExclusiveTo::EMPTY,  false /* updatableViaApex */,
+            ExclusiveTo::EMPTY,  false /* updatableViaApex */,
             testHalInterfaces()}));
     EXPECT_TRUE(add(cm, MatrixHal{HalFormat::NATIVE, "android.hardware.nfc",
             {{VersionRange(4,5,6), VersionRange(10,11,12)}},
-            true /* optional */, ExclusiveTo::EMPTY, false /* updatableViaApex */,
+            ExclusiveTo::EMPTY, false /* updatableViaApex */,
             testHalInterfaces()}));
     EXPECT_TRUE(add(cm, MatrixKernel{KernelVersion(3, 18, 22),
             {KernelConfig{"CONFIG_FOO", Tristate::YES},
@@ -865,7 +864,7 @@ TEST_F(LibVintfTest, CompatibilityMatrixConverter) {
     std::string xml = toXml(cm);
     EXPECT_EQ(xml,
             "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"native\" optional=\"false\">\n"
+            "    <hal format=\"native\">\n"
             "        <name>android.hardware.camera</name>\n"
             "        <version>1.2-3</version>\n"
             "        <version>4.5-6</version>\n"
@@ -874,7 +873,7 @@ TEST_F(LibVintfTest, CompatibilityMatrixConverter) {
             "            <instance>default</instance>\n"
             "        </interface>\n"
             "    </hal>\n"
-            "    <hal format=\"native\" optional=\"true\">\n"
+            "    <hal format=\"native\">\n"
             "        <name>android.hardware.nfc</name>\n"
             "        <version>4.5-6</version>\n"
             "        <version>10.11-12</version>\n"
@@ -922,14 +921,14 @@ TEST_F(LibVintfTest, DeviceCompatibilityMatrixCoverter) {
     CompatibilityMatrix cm;
     EXPECT_TRUE(add(cm, MatrixHal{HalFormat::NATIVE, "android.hidl.manager",
             {{VersionRange(1,0)}},
-            false /* optional */, ExclusiveTo::EMPTY, false /* updatableViaApex */,
+            ExclusiveTo::EMPTY, false /* updatableViaApex */,
             testHalInterfaces()}));
     set(cm, SchemaType::DEVICE);
     set(cm, VndkVersionRange{25,0,1,5}, {"libjpeg.so", "libbase.so"});
     std::string xml = toXml(cm);
     EXPECT_EQ(xml,
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"
-        "    <hal format=\"native\" optional=\"false\">\n"
+        "    <hal format=\"native\">\n"
         "        <name>android.hidl.manager</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -965,7 +964,6 @@ TEST_F(LibVintfTest, CompatibilityMatrixDefaultOptionalTrue) {
     EXPECT_TRUE(fromXml(&cm, xml));
     auto hal = getAnyHal(cm, "android.foo.bar");
     ASSERT_NE(nullptr, hal);
-    EXPECT_TRUE(hal->optional) << "If optional is not specified, it should be true by default";
 }
 
 TEST_F(LibVintfTest, IsValid) {
@@ -1063,14 +1061,12 @@ TEST_F(LibVintfTest, CompatibilityMatrixGetHals) {
     EXPECT_TRUE(add(cm, MatrixHal{HalFormat::NATIVE,
                                   "android.hardware.camera",
                                   {{VersionRange(1, 2, 3), VersionRange(4, 5, 6)}},
-                                  false /* optional */,
                                   ExclusiveTo::EMPTY,
                                   false /* updatableViaApex */,
                                   testHalInterfaces()}));
     EXPECT_TRUE(add(cm, MatrixHal{HalFormat::NATIVE,
                                   "android.hardware.nfc",
                                   {{VersionRange(4, 5, 6), VersionRange(10, 11, 12)}},
-                                  true /* optional */,
                                   ExclusiveTo::EMPTY,
                                   false /* updatableViaApex */,
                                   testHalInterfaces()}));
@@ -1079,7 +1075,6 @@ TEST_F(LibVintfTest, CompatibilityMatrixGetHals) {
         HalFormat::NATIVE,
         "android.hardware.camera",
         {{VersionRange(1, 2, 3), VersionRange(4, 5, 6)}},
-        false /* optional */,
         ExclusiveTo::EMPTY,
         false /* updatableViaApex */,
         testHalInterfaces(),
@@ -1087,7 +1082,6 @@ TEST_F(LibVintfTest, CompatibilityMatrixGetHals) {
     MatrixHal expectedNfcHal = MatrixHal{HalFormat::NATIVE,
                                          "android.hardware.nfc",
                                          {{VersionRange(4, 5, 6), VersionRange(10, 11, 12)}},
-                                         true /* optional */,
                                          ExclusiveTo::EMPTY,
                                          false /* updatableViaApex */,
                                          testHalInterfaces()};
@@ -1246,228 +1240,6 @@ TEST_F(LibVintfTest, DisableAvb) {
     EXPECT_TRUE(ki.checkCompatibility(cm, &error, CheckFlags::DISABLE_AVB_CHECK)) << error;
 }
 
-// This is the test extracted from VINTF Object doc
-TEST_F(LibVintfTest, HalCompat) {
-    CompatibilityMatrix matrix;
-    std::string error;
-
-    std::string matrixXml =
-            "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"hidl\" optional=\"false\">\n"
-            "        <name>android.hardware.foo</name>\n"
-            "        <version>1.0</version>\n"
-            "        <version>3.1-2</version>\n"
-            "        <interface>\n"
-            "            <name>IFoo</name>\n"
-            "            <instance>default</instance>\n"
-            "            <instance>specific</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "    <hal format=\"hidl\" optional=\"false\">\n"
-            "        <name>android.hardware.foo</name>\n"
-            "        <version>2.0</version>\n"
-            "        <interface>\n"
-            "            <name>IBar</name>\n"
-            "            <instance>default</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "    <sepolicy>\n"
-            "        <kernel-sepolicy-version>30</kernel-sepolicy-version>\n"
-            "        <sepolicy-version>25.5</sepolicy-version>\n"
-            "    </sepolicy>\n"
-            "</compatibility-matrix>\n";
-    EXPECT_TRUE(fromXml(&matrix, matrixXml, &error)) << error;
-
-    {
-        std::string manifestXml =
-                "<manifest " + kMetaVersionStr + " type=\"device\">\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>1.0</version>\n"
-                "        <interface>\n"
-                "            <name>IFoo</name>\n"
-                "            <instance>default</instance>\n"
-                "            <instance>specific</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>2.0</version>\n"
-                "        <interface>\n"
-                "            <name>IBar</name>\n"
-                "            <instance>default</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <sepolicy>\n"
-                "        <version>25.5</version>\n"
-                "    </sepolicy>\n"
-                "</manifest>\n";
-
-        HalManifest manifest;
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_TRUE(manifest.checkCompatibility(matrix, &error)) << error;
-    }
-
-    {
-        std::string manifestXml =
-                "<manifest " + kMetaVersionStr + " type=\"device\">\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>1.0</version>\n"
-                "        <interface>\n"
-                "            <name>IFoo</name>\n"
-                "            <instance>default</instance>\n"
-                "            <instance>specific</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <sepolicy>\n"
-                "        <version>25.5</version>\n"
-                "    </sepolicy>\n"
-                "</manifest>\n";
-        HalManifest manifest;
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-                << "should not be compatible because IBar is missing";
-    }
-
-    {
-        std::string manifestXml =
-                "<manifest " + kMetaVersionStr + " type=\"device\">\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>1.0</version>\n"
-                "        <interface>\n"
-                "            <name>IFoo</name>\n"
-                "            <instance>default</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>2.0</version>\n"
-                "        <interface>\n"
-                "            <name>IBar</name>\n"
-                "            <instance>default</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <sepolicy>\n"
-                "        <version>25.5</version>\n"
-                "    </sepolicy>\n"
-                "</manifest>\n";
-        HalManifest manifest;
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "should not be compatible because IFoo/specific is missing";
-    }
-
-    {
-        std::string manifestXml =
-                "<manifest " + kMetaVersionStr + " type=\"device\">\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>3.3</version>\n"
-                "        <interface>\n"
-                "            <name>IFoo</name>\n"
-                "            <instance>default</instance>\n"
-                "            <instance>specific</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>2.0</version>\n"
-                "        <interface>\n"
-                "            <name>IBar</name>\n"
-                "            <instance>default</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <sepolicy>\n"
-                "        <version>25.5</version>\n"
-                "    </sepolicy>\n"
-                "</manifest>\n";
-        HalManifest manifest;
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_TRUE(manifest.checkCompatibility(matrix, &error)) << error;
-    }
-
-    {
-        std::string manifestXml =
-                "<manifest " + kMetaVersionStr + " type=\"device\">\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>1.0</version>\n"
-                "        <interface>\n"
-                "            <name>IFoo</name>\n"
-                "            <instance>default</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>3.2</version>\n"
-                "        <interface>\n"
-                "            <name>IFoo</name>\n"
-                "            <instance>specific</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>2.0</version>\n"
-                "        <interface>\n"
-                "            <name>IBar</name>\n"
-                "            <instance>default</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <sepolicy>\n"
-                "        <version>25.5</version>\n"
-                "    </sepolicy>\n"
-                "</manifest>\n";
-        HalManifest manifest;
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-                << "should not be compatible even though @1.0::IFoo/default "
-                << "and @3.2::IFoo/specific present";
-    }
-
-    {
-        std::string manifestXml =
-                "<manifest " + kMetaVersionStr + " type=\"device\">\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>1.0</version>\n"
-                "        <interface>\n"
-                "            <name>IFoo</name>\n"
-                "            <instance>default</instance>\n"
-                "            <instance>specific</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <hal format=\"hidl\">\n"
-                "        <name>android.hardware.foo</name>\n"
-                "        <transport>hwbinder</transport>\n"
-                "        <version>2.0</version>\n"
-                "        <interface>\n"
-                "            <name>IBar</name>\n"
-                "            <instance>default</instance>\n"
-                "        </interface>\n"
-                "    </hal>\n"
-                "    <sepolicy>\n"
-                "        <version>25.5</version>\n"
-                "    </sepolicy>\n"
-                "</manifest>\n";
-        HalManifest manifest;
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_TRUE(manifest.checkCompatibility(matrix, &error)) << error;
-    }
-}
-
 TEST_F(LibVintfTest, FullCompat) {
     std::string manifestXml =
         "<manifest " + kMetaVersionStr + " type=\"device\">\n"
@@ -1511,7 +1283,7 @@ TEST_F(LibVintfTest, FullCompat) {
 
     std::string matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.camera</name>\n"
         "        <version>2.0-5</version>\n"
         "        <version>3.4-16</version>\n"
@@ -1525,7 +1297,7 @@ TEST_F(LibVintfTest, FullCompat) {
         "            <instance>legacy/0</instance>\n"
         "        </interface>\n"
         "    </hal>\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.nfc</name>\n"
         "        <version>1.0</version>\n"
         "        <version>2.0</version>\n"
@@ -1534,7 +1306,7 @@ TEST_F(LibVintfTest, FullCompat) {
         "            <instance>nfc_nci</instance>\n"
         "        </interface>\n"
         "    </hal>\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "    </hal>\n"
@@ -1556,32 +1328,6 @@ TEST_F(LibVintfTest, FullCompat) {
     EXPECT_TRUE(fromXml(&matrix, matrixXml));
     EXPECT_TRUE(manifest.checkCompatibility(matrix, &error)) << error;
 
-    // some smaller test cases
-    matrixXml =
-        "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
-        "        <name>android.hardware.camera</name>\n"
-        "        <version>3.4</version>\n"
-        "    </hal>\n"
-        "    <sepolicy>\n"
-        "        <kernel-sepolicy-version>30</kernel-sepolicy-version>\n"
-        "        <sepolicy-version>25.5</sepolicy-version>\n"
-        "    </sepolicy>\n"
-        "    <avb><vbmeta-version>2.1</vbmeta-version></avb>\n"
-        "</compatibility-matrix>\n";
-    matrix = {};
-    EXPECT_TRUE(fromXml(&matrix, matrixXml));
-    EXPECT_TRUE(manifest.checkCompatibility(matrix, &error)) << error;
-    MatrixHal *camera = getAnyHal(matrix, "android.hardware.camera");
-    EXPECT_NE(camera, nullptr);
-    camera->versionRanges[0] = {3, 5};
-    EXPECT_TRUE(manifest.checkCompatibility(matrix, &error)) << error;
-    camera->versionRanges[0] = {3, 6};
-    EXPECT_FALSE(manifest.checkCompatibility(matrix));
-
-    // reset it
-    matrix = {};
-    EXPECT_TRUE(fromXml(&matrix, matrixXml));
     set(matrix, Sepolicy{30, {{26, 0}}});
     EXPECT_FALSE(manifest.checkCompatibility(matrix));
     set(matrix, Sepolicy{30, {{25, 6}}});
@@ -1614,7 +1360,7 @@ TEST_F(LibVintfTest, ApexInterfaceShouldBeOkayWithoutApexInfoList) {
     details::PropertyFetcherNoOp pf;
     EXPECT_THAT(apex::GetModifiedTime(&fs, &pf), std::nullopt);
     std::vector<std::string> dirs;
-    ASSERT_EQ(OK, apex::GetDeviceVintfDirs(&fs, &pf, &dirs, nullptr));
+    ASSERT_EQ(OK, apex::GetVendorVintfDirs(&fs, &pf, &dirs, nullptr));
     ASSERT_EQ(dirs, std::vector<std::string>{});
 }
 
@@ -1630,7 +1376,7 @@ class NativeHalCompatTest : public LibVintfTest,
    public:
     static std::vector<NativeHalCompatTestParam> createParams() {
         std::string matrixIntf = "<compatibility-matrix " + kMetaVersionStr + R"( type="device">
-                <hal format="native" optional="false">
+                <hal format="native">
                     <name>foo</name>
                     <version>1.0</version>
                     <interface>
@@ -1641,7 +1387,7 @@ class NativeHalCompatTest : public LibVintfTest,
             </compatibility-matrix>
         )";
         std::string matrixNoIntf = "<compatibility-matrix " + kMetaVersionStr + R"( type="device">
-                <hal format="native" optional="false">
+                <hal format="native">
                     <name>foo</name>
                     <version>1.0</version>
                     <interface>
@@ -1651,7 +1397,7 @@ class NativeHalCompatTest : public LibVintfTest,
             </compatibility-matrix>
         )";
         std::string matrixNoInst = "<compatibility-matrix " + kMetaVersionStr + R"( type="device">
-                <hal format="native" optional="false">
+                <hal format="native">
                     <name>foo</name>
                     <version>1.0</version>
                </hal>
@@ -1702,25 +1448,21 @@ class NativeHalCompatTest : public LibVintfTest,
 
         std::vector<NativeHalCompatTestParam> ret;
 
-        // If the matrix specifies interface name, the manifest must also do.
+        // If the matrix specifies interface name, the manifest can specify or
+        // not.
         ret.emplace_back(NativeHalCompatTestParam{matrixIntf, manifestFqnameIntf, true, ""});
         ret.emplace_back(NativeHalCompatTestParam{matrixIntf, manifestLegacyIntf, true, ""});
-        ret.emplace_back(NativeHalCompatTestParam{matrixIntf, manifestFqnameNoIntf, false,
-                                                  "required: @1.0::IFoo/default"});
-        ret.emplace_back(NativeHalCompatTestParam{matrixIntf, manifestLegacyNoIntf, false,
-                                                  "required: @1.0::IFoo/default"});
-        ret.emplace_back(NativeHalCompatTestParam{matrixIntf, manifestNoInst, false,
-                                                  "required: @1.0::IFoo/default"});
-
-        // If the matrix does not specify an interface name, the manifest must not do that either.
-        ret.emplace_back(NativeHalCompatTestParam{matrixNoIntf, manifestFqnameIntf, false,
-                                                  "required: @1.0/default"});
-        ret.emplace_back(NativeHalCompatTestParam{matrixNoIntf, manifestLegacyIntf, false,
-                                                  "required: @1.0/default"});
+        ret.emplace_back(NativeHalCompatTestParam{matrixIntf, manifestFqnameNoIntf, true, ""});
+        ret.emplace_back(NativeHalCompatTestParam{matrixIntf, manifestLegacyNoIntf, true, ""});
+        ret.emplace_back(NativeHalCompatTestParam{matrixIntf, manifestNoInst, true, ""});
+
+        // If the matrix does not specify an interface name, the manifest can
+        // specify it or not.
+        ret.emplace_back(NativeHalCompatTestParam{matrixNoIntf, manifestFqnameIntf, true, ""});
+        ret.emplace_back(NativeHalCompatTestParam{matrixNoIntf, manifestLegacyIntf, true, ""});
         ret.emplace_back(NativeHalCompatTestParam{matrixNoIntf, manifestFqnameNoIntf, true, ""});
         ret.emplace_back(NativeHalCompatTestParam{matrixNoIntf, manifestLegacyNoIntf, true, ""});
-        ret.emplace_back(NativeHalCompatTestParam{matrixNoIntf, manifestNoInst, false,
-                                                  "required: @1.0/default"});
+        ret.emplace_back(NativeHalCompatTestParam{matrixNoIntf, manifestNoInst, true, ""});
 
         // If the matrix does not specify interface name nor instances, the manifest may either
         // provide instances of that version, or just a version number with no instances.
@@ -1833,7 +1575,7 @@ TEST_F(LibVintfTest, CompatibilityMatrixConverterXmlFile) {
     std::string xml = toXml(cm, SerializeFlags::XMLFILES_ONLY);
     EXPECT_EQ(xml,
               "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-              "    <xmlfile format=\"dtd\" optional=\"true\">\n"
+              "    <xmlfile format=\"dtd\">\n"
               "        <name>media_profile</name>\n"
               "        <version>1.0</version>\n"
               "    </xmlfile>\n"
@@ -1843,21 +1585,6 @@ TEST_F(LibVintfTest, CompatibilityMatrixConverterXmlFile) {
     EXPECT_EQ(cm, cm2);
 }
 
-TEST_F(LibVintfTest, CompatibilityMatrixConverterXmlFile2) {
-    std::string error;
-    std::string xml =
-        "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-        "    <xmlfile format=\"dtd\" optional=\"false\">\n"
-        "        <name>media_profile</name>\n"
-        "        <version>1.0</version>\n"
-        "    </xmlfile>\n"
-        "</compatibility-matrix>\n";
-    CompatibilityMatrix cm;
-    EXPECT_FALSE(fromXml(&cm, xml, &error));
-    EXPECT_EQ("compatibility-matrix.xmlfile entry media_profile has to be optional for "
-              "compatibility matrix version 1.0", error);
-}
-
 TEST_F(LibVintfTest, ManifestXmlFilePathDevice) {
     std::string manifestXml =
         "<manifest " + kMetaVersionStr + " type=\"device\">"
@@ -1916,7 +1643,7 @@ TEST_F(LibVintfTest, ManifestXmlFilePathMissing) {
 TEST_F(LibVintfTest, MatrixXmlFilePathFramework) {
     std::string matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">"
-        "    <xmlfile format=\"dtd\" optional=\"true\">"
+        "    <xmlfile format=\"dtd\">"
         "        <name>media_profile</name>"
         "        <version>2.0-1</version>"
         "    </xmlfile>"
@@ -1930,7 +1657,7 @@ TEST_F(LibVintfTest, MatrixXmlFilePathFramework) {
 TEST_F(LibVintfTest, MatrixXmlFilePathDevice) {
     std::string matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">"
-        "    <xmlfile format=\"xsd\" optional=\"true\">"
+        "    <xmlfile format=\"xsd\">"
         "        <name>media_profile</name>"
         "        <version>2.0-1</version>"
         "    </xmlfile>"
@@ -1944,7 +1671,7 @@ TEST_F(LibVintfTest, MatrixXmlFilePathDevice) {
 TEST_F(LibVintfTest, MatrixXmlFilePathOverride) {
     std::string matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">"
-        "    <xmlfile format=\"xsd\" optional=\"true\">"
+        "    <xmlfile format=\"xsd\">"
         "        <name>media_profile</name>"
         "        <version>2.0-1</version>"
         "        <path>/system/etc/foo.xsd</path>"
@@ -1958,7 +1685,7 @@ TEST_F(LibVintfTest, MatrixXmlFilePathOverride) {
 TEST_F(LibVintfTest, MatrixXmlFilePathMissing) {
     std::string matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">"
-        "    <xmlfile format=\"dtd\" optional=\"true\">"
+        "    <xmlfile format=\"dtd\">"
         "        <name>media_profile</name>"
         "        <version>2.1</version>"
         "    </xmlfile>"
@@ -2064,7 +1791,7 @@ TEST_F(LibVintfTest, NetutilsWrapperMatrix) {
 
     matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">"
-        "    <hal format=\"native\" optional=\"false\">"
+        "    <hal format=\"native\">"
         "        <name>netutils-wrapper</name>"
         "        <version>1.0</version>"
         "    </hal>"
@@ -2076,7 +1803,7 @@ TEST_F(LibVintfTest, NetutilsWrapperMatrix) {
 
     matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">"
-        "    <hal format=\"native\" optional=\"false\">"
+        "    <hal format=\"native\">"
         "        <name>netutils-wrapper</name>"
         "        <version>1.0-1</version>"
         "    </hal>"
@@ -2088,7 +1815,7 @@ TEST_F(LibVintfTest, NetutilsWrapperMatrix) {
 
     matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">"
-        "    <hal format=\"native\" optional=\"false\">"
+        "    <hal format=\"native\">"
         "        <name>netutils-wrapper</name>"
         "        <version>1.1</version>"
         "    </hal>"
@@ -2100,7 +1827,7 @@ TEST_F(LibVintfTest, NetutilsWrapperMatrix) {
 
     matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">"
-        "    <hal format=\"native\" optional=\"false\">"
+        "    <hal format=\"native\">"
         "        <name>netutils-wrapper</name>"
         "        <version>1.0</version>"
         "        <version>2.0</version>"
@@ -2582,7 +2309,7 @@ TEST_F(LibVintfTest, AddOptionalHal) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0-1</version>\n"
         "        <interface>\n"
@@ -2597,7 +2324,7 @@ TEST_F(LibVintfTest, AddOptionalHal) {
     xml = toXml(cm1, SerializeFlags::HALS_ONLY);
     EXPECT_EQ(xml,
               "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-              "    <hal format=\"hidl\" optional=\"true\">\n"
+              "    <hal format=\"hidl\">\n"
               "        <name>android.hardware.foo</name>\n"
               "        <version>1.0-1</version>\n"
               "        <interface>\n"
@@ -2616,7 +2343,7 @@ TEST_F(LibVintfTest, AddOptionalHalMinorVersion) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.2-3</version>\n"
         "        <interface>\n"
@@ -2629,7 +2356,7 @@ TEST_F(LibVintfTest, AddOptionalHalMinorVersion) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0-4</version>\n"
         "        <interface>\n"
@@ -2644,7 +2371,7 @@ TEST_F(LibVintfTest, AddOptionalHalMinorVersion) {
     xml = toXml(cm1, SerializeFlags::HALS_ONLY);
     EXPECT_EQ(xml,
               "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-              "    <hal format=\"hidl\" optional=\"false\">\n"
+              "    <hal format=\"hidl\">\n"
               "        <name>android.hardware.foo</name>\n"
               "        <version>1.0-4</version>\n"
               "        <interface>\n"
@@ -2663,7 +2390,7 @@ TEST_F(LibVintfTest, AddOptionalHalMajorVersion) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.2-3</version>\n"
         "        <interface>\n"
@@ -2676,7 +2403,7 @@ TEST_F(LibVintfTest, AddOptionalHalMajorVersion) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.2-3</version>\n"
         "        <version>2.0-4</version>\n"
@@ -2692,7 +2419,7 @@ TEST_F(LibVintfTest, AddOptionalHalMajorVersion) {
     xml = toXml(cm1, SerializeFlags::HALS_ONLY);
     EXPECT_EQ(xml,
               "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-              "    <hal format=\"hidl\" optional=\"false\">\n"
+              "    <hal format=\"hidl\">\n"
               "        <name>android.hardware.foo</name>\n"
               "        <version>1.2-3</version>\n"
               "        <version>2.0-4</version>\n"
@@ -2712,7 +2439,7 @@ TEST_F(LibVintfTest, AddOptionalHalMinorVersionDiffInstance) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0-1</version>\n"
         "        <interface>\n"
@@ -2725,7 +2452,7 @@ TEST_F(LibVintfTest, AddOptionalHalMinorVersionDiffInstance) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.1-2</version>\n"
         "        <interface>\n"
@@ -2740,7 +2467,7 @@ TEST_F(LibVintfTest, AddOptionalHalMinorVersionDiffInstance) {
     xml = toXml(cm1, SerializeFlags::HALS_ONLY);
     EXPECT_EQ(xml,
               "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-              "    <hal format=\"hidl\" optional=\"false\">\n"
+              "    <hal format=\"hidl\">\n"
               "        <name>android.hardware.foo</name>\n"
               "        <version>1.0-1</version>\n"
               "        <interface>\n"
@@ -2748,7 +2475,7 @@ TEST_F(LibVintfTest, AddOptionalHalMinorVersionDiffInstance) {
               "            <instance>default</instance>\n"
               "        </interface>\n"
               "    </hal>\n"
-              "    <hal format=\"hidl\" optional=\"true\">\n"
+              "    <hal format=\"hidl\">\n"
               "        <name>android.hardware.foo</name>\n"
               "        <version>1.1-2</version>\n"
               "        <interface>\n"
@@ -2766,7 +2493,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstance) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -2784,7 +2511,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstance) {
         CompatibilityMatrix cm2;
         xml =
             "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-            "    <hal format=\"hidl\" optional=\"false\">\n"
+            "    <hal format=\"hidl\">\n"
             "        <name>android.hardware.foo</name>\n"
             "        <version>2.0</version>\n"
             "        <interface>\n"
@@ -2800,7 +2527,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstance) {
         xml = toXml(cm1, SerializeFlags::HALS_ONLY);
         EXPECT_EQ(xml,
                   "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-                  "    <hal format=\"hidl\" optional=\"false\">\n"
+                  "    <hal format=\"hidl\">\n"
                   "        <name>android.hardware.foo</name>\n"
                   "        <version>1.0</version>\n"
                   "        <interface>\n"
@@ -2808,7 +2535,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstance) {
                   "            <instance>custom</instance>\n"
                   "        </interface>\n"
                   "    </hal>\n"
-                  "    <hal format=\"hidl\" optional=\"false\">\n"
+                  "    <hal format=\"hidl\">\n"
                   "        <name>android.hardware.foo</name>\n"
                   "        <version>1.0</version>\n"
                   "        <version>2.0</version>\n"
@@ -2825,7 +2552,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstance) {
         CompatibilityMatrix cm2;
         xml =
             "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-            "    <hal format=\"hidl\" optional=\"false\">\n"
+            "    <hal format=\"hidl\">\n"
             "        <name>android.hardware.foo</name>\n"
             "        <version>2.0</version>\n"
             "        <interface>\n"
@@ -2842,7 +2569,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstance) {
         xml = toXml(cm1, SerializeFlags::HALS_ONLY);
         EXPECT_EQ(xml,
                   "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-                  "    <hal format=\"hidl\" optional=\"false\">\n"
+                  "    <hal format=\"hidl\">\n"
                   "        <name>android.hardware.foo</name>\n"
                   "        <version>1.0</version>\n"
                   "        <interface>\n"
@@ -2850,7 +2577,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstance) {
                   "            <instance>custom</instance>\n"
                   "        </interface>\n"
                   "    </hal>\n"
-                  "    <hal format=\"hidl\" optional=\"false\">\n"
+                  "    <hal format=\"hidl\">\n"
                   "        <name>android.hardware.foo</name>\n"
                   "        <version>1.0</version>\n"
                   "        <version>2.0</version>\n"
@@ -2859,7 +2586,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstance) {
                   "            <instance>default</instance>\n"
                   "        </interface>\n"
                   "    </hal>\n"
-                  "    <hal format=\"hidl\" optional=\"true\">\n"
+                  "    <hal format=\"hidl\">\n"
                   "        <name>android.hardware.foo</name>\n"
                   "        <version>2.0</version>\n"
                   "        <interface>\n"
@@ -2879,7 +2606,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstanceSplit) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -2887,7 +2614,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstanceSplit) {
         "            <instance>default</instance>\n"
         "        </interface>\n"
         "    </hal>\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -2900,7 +2627,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstanceSplit) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>2.0</version>\n"
         "        <interface>\n"
@@ -2908,7 +2635,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstanceSplit) {
         "            <instance>default</instance>\n"
         "        </interface>\n"
         "    </hal>\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>2.0</version>\n"
         "        <interface>\n"
@@ -2923,7 +2650,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstanceSplit) {
     xml = toXml(cm1, SerializeFlags::HALS_ONLY);
     EXPECT_EQ(
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <version>2.0</version>\n"
@@ -2932,7 +2659,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstanceSplit) {
         "            <instance>default</instance>\n"
         "        </interface>\n"
         "    </hal>\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -2940,7 +2667,7 @@ TEST_F(LibVintfTest, AddRequiredHalOverlapInstanceSplit) {
         "            <instance>custom</instance>\n"
         "        </interface>\n"
         "    </hal>\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>2.0</version>\n"
         "        <interface>\n"
@@ -2960,7 +2687,7 @@ TEST_F(LibVintfTest, AddOptionalHalUpdatableViaApex) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <hal format=\"aidl\" optional=\"false\">\n"
+        "    <hal format=\"aidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <interface>\n"
         "            <name>IFoo</name>\n"
@@ -2972,7 +2699,7 @@ TEST_F(LibVintfTest, AddOptionalHalUpdatableViaApex) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-        "    <hal format=\"aidl\" optional=\"false\" updatable-via-apex=\"true\">\n"
+        "    <hal format=\"aidl\" updatable-via-apex=\"true\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <interface>\n"
         "            <name>IFoo</name>\n"
@@ -2986,7 +2713,7 @@ TEST_F(LibVintfTest, AddOptionalHalUpdatableViaApex) {
     xml = toXml(cm1, SerializeFlags::HALS_ONLY);
     EXPECT_EQ(xml,
               "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-              "    <hal format=\"aidl\" optional=\"false\" updatable-via-apex=\"true\">\n"
+              "    <hal format=\"aidl\" updatable-via-apex=\"true\">\n"
               "        <name>android.hardware.foo</name>\n"
               "        <interface>\n"
               "            <name>IFoo</name>\n"
@@ -3004,7 +2731,7 @@ TEST_F(LibVintfTest, AddOptionalXmlFile) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <xmlfile format=\"xsd\" optional=\"true\">\n"
+        "    <xmlfile format=\"xsd\">\n"
         "        <name>foo</name>\n"
         "        <version>1.0-2</version>\n"
         "        <path>/foo/bar/baz.xsd</path>\n"
@@ -3014,7 +2741,7 @@ TEST_F(LibVintfTest, AddOptionalXmlFile) {
 
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-        "    <xmlfile format=\"xsd\" optional=\"true\">\n"
+        "    <xmlfile format=\"xsd\">\n"
         "        <name>foo</name>\n"
         "        <version>1.1-3</version>\n"
         "        <path>/foo/bar/quux.xsd</path>\n"
@@ -3026,12 +2753,12 @@ TEST_F(LibVintfTest, AddOptionalXmlFile) {
     xml = toXml(cm1, SerializeFlags::XMLFILES_ONLY);
     EXPECT_EQ(xml,
               "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-              "    <xmlfile format=\"xsd\" optional=\"true\">\n"
+              "    <xmlfile format=\"xsd\">\n"
               "        <name>foo</name>\n"
               "        <version>1.0-2</version>\n"
               "        <path>/foo/bar/baz.xsd</path>\n"
               "    </xmlfile>\n"
-              "    <xmlfile format=\"xsd\" optional=\"true\">\n"
+              "    <xmlfile format=\"xsd\">\n"
               "        <name>foo</name>\n"
               "        <version>1.1-3</version>\n"
               "        <path>/foo/bar/quux.xsd</path>\n"
@@ -4041,84 +3768,6 @@ TEST_F(LibVintfTest, MatrixDetailErrorMsg) {
         "    </hal>\n"
         "</manifest>\n";
     ASSERT_TRUE(fromXml(&manifest, xml, &error)) << error;
-
-    {
-        CompatibilityMatrix cm;
-        xml =
-            "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"7\">\n"
-            "    <hal format=\"hidl\" optional=\"false\">\n"
-            "        <name>android.hardware.foo</name>\n"
-            "        <version>1.2-3</version>\n"
-            "        <version>4.5</version>\n"
-            "        <interface>\n"
-            "            <name>IFoo</name>\n"
-            "            <instance>default</instance>\n"
-            "            <instance>slot1</instance>\n"
-            "        </interface>\n"
-            "        <interface>\n"
-            "            <name>IBar</name>\n"
-            "            <instance>default</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "</compatibility-matrix>\n";
-        EXPECT_TRUE(fromXml(&cm, xml, &error)) << error;
-        EXPECT_FALSE(manifest.checkCompatibility(cm, &error));
-        EXPECT_IN("Manifest level = 8", error);
-        EXPECT_IN("Matrix level = 7", error);
-        EXPECT_IN(
-            "android.hardware.foo:\n"
-            "    required: \n"
-            "        (@1.2-3::IBar/default AND @1.2-3::IFoo/default AND @1.2-3::IFoo/slot1) OR\n"
-            "        (@4.5::IBar/default AND @4.5::IFoo/default AND @4.5::IFoo/slot1)\n"
-            "    provided: @1.0::IFoo/default",
-            error);
-    }
-
-    {
-        CompatibilityMatrix cm;
-        xml =
-            "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"hidl\" optional=\"false\">\n"
-            "        <name>android.hardware.foo</name>\n"
-            "        <version>1.2-3</version>\n"
-            "        <interface>\n"
-            "            <name>IFoo</name>\n"
-            "            <instance>default</instance>\n"
-            "            <instance>slot1</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "</compatibility-matrix>\n";
-        EXPECT_TRUE(fromXml(&cm, xml, &error)) << error;
-        EXPECT_FALSE(manifest.checkCompatibility(cm, &error));
-        EXPECT_IN(
-            "android.hardware.foo:\n"
-            "    required: (@1.2-3::IFoo/default AND @1.2-3::IFoo/slot1)\n"
-            "    provided: @1.0::IFoo/default",
-            error);
-    }
-
-    // the most frequent use case.
-    {
-        CompatibilityMatrix cm;
-        xml =
-            "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"hidl\" optional=\"false\">\n"
-            "        <name>android.hardware.foo</name>\n"
-            "        <version>1.2-3</version>\n"
-            "        <interface>\n"
-            "            <name>IFoo</name>\n"
-            "            <instance>default</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "</compatibility-matrix>\n";
-        EXPECT_TRUE(fromXml(&cm, xml, &error)) << error;
-        EXPECT_FALSE(manifest.checkCompatibility(cm, &error));
-        EXPECT_IN(
-            "android.hardware.foo:\n"
-            "    required: @1.2-3::IFoo/default\n"
-            "    provided: @1.0::IFoo/default",
-            error);
-    }
 }
 
 TEST_F(LibVintfTest, DisabledHal) {
@@ -4162,7 +3811,7 @@ TEST_F(LibVintfTest, FqNameValid) {
     CompatibilityMatrix cm;
     xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -4170,7 +3819,7 @@ TEST_F(LibVintfTest, FqNameValid) {
         "            <instance>default</instance>\n"
         "        </interface>\n"
         "    </hal>\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.1</version>\n"
         "        <interface>\n"
@@ -4219,32 +3868,6 @@ TEST_F(LibVintfTest, FqNameValid) {
         EXPECT_TRUE(manifest.checkCompatibility(cm, &error)) << error;
     }
 
-    {
-        HalManifest manifest;
-        xml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"hidl\">\n"
-            "        <name>android.hardware.foo</name>\n"
-            "        <transport>hwbinder</transport>\n"
-            "        <version>1.0</version>\n"
-            "        <interface>\n"
-            "            <name>IFoo</name>\n"
-            "            <instance>default</instance>\n"
-            "            <instance>custom</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        ASSERT_TRUE(fromXml(&manifest, xml, &error)) << error;
-        EXPECT_FALSE(manifest.checkCompatibility(cm, &error));
-        EXPECT_IN(
-            "android.hardware.foo:\n"
-            "    required: @1.1::IFoo/custom\n"
-            "    provided: \n"
-            "        @1.0::IFoo/custom\n"
-            "        @1.0::IFoo/default",
-            error);
-    }
-
     {
         HalManifest manifest;
         xml =
@@ -4323,7 +3946,7 @@ TEST_F(LibVintfTest, RegexInstanceValid) {
 
     std::string xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -4342,7 +3965,7 @@ TEST_F(LibVintfTest, RegexInstanceInvalid) {
     std::string error;
     std::string xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -4368,7 +3991,7 @@ TEST_F(LibVintfTest, RegexInstanceCompat) {
 
     std::string matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <version>3.1-2</version>\n"
@@ -4429,9 +4052,6 @@ TEST_F(LibVintfTest, RegexInstanceCompat) {
 
         HalManifest manifest;
         EXPECT_TRUE(fromXml(&manifest, xml));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because no legacy/[0-9]+ is provided.";
-
         auto unused = checkUnusedHals(manifest, matrix);
         EXPECT_EQ((std::set<std::string>{"android.hardware.foo@1.0::IFoo/nonmatch/legacy/0",
                                          "android.hardware.foo@1.0::IFoo/legacy/0/nonmatch",
@@ -4783,7 +4403,7 @@ TEST_F(LibVintfTest, HalManifestWithMultipleFiles) {
 TEST_F(LibVintfTest, Aidl) {
     std::string xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"
-        "    <hal format=\"aidl\" optional=\"false\">\n"
+        "    <hal format=\"aidl\">\n"
         "        <name>android.system.foo</name>\n"
         "        <interface>\n"
         "            <name>IFoo</name>\n"
@@ -4855,125 +4475,19 @@ TEST_F(LibVintfTest, Aidl) {
         EXPECT_EQ(manifest.getAidlInstances("android.system.does_not_exist", "IFoo"),
                   std::set<std::string>({}));
     }
-
-    {
-        HalManifest manifest;
-        std::string manifestXml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <fqname>IFoo/incompat_instance</fqname>\n"
-            "        <fqname>IFoo/test0</fqname>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_EQ(manifestXml, toXml(manifest, SerializeFlags::HALS_ONLY));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because default instance is missing";
-        EXPECT_IN("required: (IFoo/default (@1) AND IFoo/test.* (@1))", error);
-        EXPECT_IN("provided: \n"
-                  "        IFoo/incompat_instance (@1)\n"
-                  "        IFoo/test0 (@1)",
-                  error);
-    }
-
-    {
-        HalManifest manifest;
-        std::string manifestXml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <interface>\n"
-            "            <name>IFoo</name>\n"
-            "            <instance>incompat_instance</instance>\n"
-            "            <instance>test0</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_EQ(
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <fqname>IFoo/incompat_instance</fqname>\n"
-            "        <fqname>IFoo/test0</fqname>\n"
-            "    </hal>\n"
-            "</manifest>\n",
-            toXml(manifest, SerializeFlags::HALS_ONLY));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because default instance is missing";
-        EXPECT_IN("required: (IFoo/default (@1) AND IFoo/test.* (@1))", error);
-        EXPECT_IN("provided: \n"
-                  "        IFoo/incompat_instance (@1)\n"
-                  "        IFoo/test0 (@1)",
-                  error);
-    }
-
-    {
-        HalManifest manifest;
-        std::string manifestXml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <fqname>IFoo/default</fqname>\n"
-            "        <fqname>IFoo/incompat_instance</fqname>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_EQ(manifestXml, toXml(manifest, SerializeFlags::HALS_ONLY));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because test.* instance is missing";
-        EXPECT_IN("required: (IFoo/default (@1) AND IFoo/test.* (@1))", error);
-        EXPECT_IN("provided: \n"
-                  "        IFoo/default (@1)\n"
-                  "        IFoo/incompat_instance (@1)\n",
-                  error);
-    }
-
-    {
-        HalManifest manifest;
-        std::string manifestXml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <interface>\n"
-            "            <name>IFoo</name>\n"
-            "            <instance>default</instance>\n"
-            "            <instance>incompat_instance</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_EQ(
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <fqname>IFoo/default</fqname>\n"
-            "        <fqname>IFoo/incompat_instance</fqname>\n"
-            "    </hal>\n"
-            "</manifest>\n",
-            toXml(manifest, SerializeFlags::HALS_ONLY));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because test.* instance is missing";
-        EXPECT_IN("required: (IFoo/default (@1) AND IFoo/test.* (@1))", error);
-        EXPECT_IN("provided: \n"
-                  "        IFoo/default (@1)\n"
-                  "        IFoo/incompat_instance (@1)\n",
-                  error);
-    }
 }
 
 TEST_F(LibVintfTest, AidlAndHidlNamesMatrix) {
     std::string xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"
-        "    <hal format=\"aidl\" optional=\"true\">\n"
+        "    <hal format=\"aidl\">\n"
         "        <name>android.system.foo</name>\n"
         "        <interface>\n"
         "            <name>IFoo</name>\n"
         "            <instance>default</instance>\n"
         "        </interface>\n"
         "    </hal>\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.system.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -5022,14 +4536,14 @@ TEST_F(LibVintfTest, AidlAndHidlCheckUnused) {
         "</manifest>\n";
     std::string matrixXml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"
-        "    <hal format=\"aidl\" optional=\"true\">\n"
+        "    <hal format=\"aidl\">\n"
         "        <name>android.system.foo</name>\n"
         "        <interface>\n"
         "            <name>IFoo</name>\n"
         "            <instance>default</instance>\n"
         "        </interface>\n"
         "    </hal>\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.system.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -5051,7 +4565,7 @@ TEST_F(LibVintfTest, AidlAndHidlCheckUnused) {
 TEST_F(LibVintfTest, AidlVersion) {
     std::string xml =
         "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"
-        "    <hal format=\"aidl\" optional=\"false\">\n"
+        "    <hal format=\"aidl\">\n"
         "        <name>android.system.foo</name>\n"
         "        <version>4-100</version>\n"
         "        <interface>\n"
@@ -5147,175 +4661,6 @@ TEST_F(LibVintfTest, AidlVersion) {
         EXPECT_EQ(manifest.getAidlInstances("android.system.does_not_exist", "IFoo"),
                   std::set<std::string>({}));
     }
-
-    {
-        HalManifest manifest;
-        std::string manifestXml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <version>5</version>\n"
-            "        <fqname>IFoo/incompat_instance</fqname>\n"
-            "        <fqname>IFoo/test0</fqname>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_EQ(manifestXml, toXml(manifest, SerializeFlags::HALS_ONLY));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because default instance is missing";
-        EXPECT_IN("required: (IFoo/default (@4-100) AND IFoo/test.* (@4-100))", error);
-        EXPECT_IN("provided: \n"
-                  "        IFoo/incompat_instance (@5)\n"
-                  "        IFoo/test0 (@5)",
-                  error);
-    }
-
-    {
-        HalManifest manifest;
-        std::string manifestXml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <version>5</version>\n"
-            "        <interface>\n"
-            "            <name>IFoo</name>\n"
-            "            <instance>incompat_instance</instance>\n"
-            "            <instance>test0</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_EQ(
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <version>5</version>\n"
-            "        <fqname>IFoo/incompat_instance</fqname>\n"
-            "        <fqname>IFoo/test0</fqname>\n"
-            "    </hal>\n"
-            "</manifest>\n",
-            toXml(manifest, SerializeFlags::HALS_ONLY));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because default instance is missing";
-        EXPECT_IN("required: (IFoo/default (@4-100) AND IFoo/test.* (@4-100))", error);
-        EXPECT_IN("provided: \n"
-                  "        IFoo/incompat_instance (@5)\n"
-                  "        IFoo/test0 (@5)",
-                  error);
-    }
-
-    {
-        HalManifest manifest;
-        std::string manifestXml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <version>5</version>\n"
-            "        <fqname>IFoo/default</fqname>\n"
-            "        <fqname>IFoo/incompat_instance</fqname>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_EQ(manifestXml, toXml(manifest, SerializeFlags::HALS_ONLY));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because test.* instance is missing";
-        EXPECT_IN("required: (IFoo/default (@4-100) AND IFoo/test.* (@4-100))", error);
-        EXPECT_IN("provided: \n"
-                  "        IFoo/default (@5)\n"
-                  "        IFoo/incompat_instance (@5)",
-                  error);
-    }
-
-    {
-        HalManifest manifest;
-        std::string manifestXml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <version>5</version>\n"
-            "        <interface>\n"
-            "            <name>IFoo</name>\n"
-            "            <instance>default</instance>\n"
-            "            <instance>incompat_instance</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_EQ(
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <version>5</version>\n"
-            "        <fqname>IFoo/default</fqname>\n"
-            "        <fqname>IFoo/incompat_instance</fqname>\n"
-            "    </hal>\n"
-            "</manifest>\n",
-            toXml(manifest, SerializeFlags::HALS_ONLY));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because test.* instance is missing";
-        EXPECT_IN("required: (IFoo/default (@4-100) AND IFoo/test.* (@4-100))", error);
-        EXPECT_IN("provided: \n"
-                  "        IFoo/default (@5)\n"
-                  "        IFoo/incompat_instance (@5)",
-                  error);
-    }
-
-    {
-        HalManifest manifest;
-        std::string manifestXml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <version>3</version>\n"
-            "        <fqname>IFoo/default</fqname>\n"
-            "        <fqname>IFoo/test0</fqname>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_EQ(manifestXml, toXml(manifest, SerializeFlags::HALS_ONLY));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because version 3 cannot satisfy version 4-100";
-        EXPECT_IN("required: (IFoo/default (@4-100) AND IFoo/test.* (@4-100))", error);
-        EXPECT_IN("provided: \n"
-                  "        IFoo/default (@3)\n"
-                  "        IFoo/test0 (@3)",
-                  error);
-
-    }
-
-    {
-        HalManifest manifest;
-        std::string manifestXml =
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <version>3</version>\n"
-            "        <interface>\n"
-            "            <name>IFoo</name>\n"
-            "            <instance>default</instance>\n"
-            "            <instance>test0</instance>\n"
-            "        </interface>\n"
-            "    </hal>\n"
-            "</manifest>\n";
-        EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
-        EXPECT_EQ(
-            "<manifest " + kMetaVersionStr + " type=\"framework\">\n"
-            "    <hal format=\"aidl\">\n"
-            "        <name>android.system.foo</name>\n"
-            "        <version>3</version>\n"
-            "        <fqname>IFoo/default</fqname>\n"
-            "        <fqname>IFoo/test0</fqname>\n"
-            "    </hal>\n"
-            "</manifest>\n",
-            toXml(manifest, SerializeFlags::HALS_ONLY));
-        EXPECT_FALSE(manifest.checkCompatibility(matrix, &error))
-            << "Should not be compatible because version 3 cannot satisfy version 4-100";
-        EXPECT_IN("required: (IFoo/default (@4-100) AND IFoo/test.* (@4-100))", error);
-        EXPECT_IN("provided: \n"
-                  "        IFoo/default (@3)\n"
-                  "        IFoo/test0 (@3)",
-                  error);
-    }
 }
 
 TEST_F(LibVintfTest, AidlFqnameNoVersion) {
@@ -5343,10 +4688,9 @@ TEST_F(LibVintfTest, GetTransportHidlHalWithFakeAidlVersion) {
         "</manifest>\n";
     std::string error;
     HalManifest manifest;
-    EXPECT_TRUE(fromXml(&manifest, xml, &error)) << error;
-    EXPECT_EQ(Transport::HWBINDER,
-              manifest.getHidlTransport("android.system.foo", details::kDefaultAidlVersion, "IFoo",
-                                        "default"));
+    EXPECT_FALSE(fromXml(&manifest, xml, &error))
+            << "This should fail to parse";
+    EXPECT_IN("Could not parse text \"@1::IFoo/default\"", error);
 }
 
 TEST_F(LibVintfTest, RejectAidlHalsWithUnsupportedTransport) {
@@ -5718,17 +5062,12 @@ TEST_F(LibVintfTest, UnknownAccessEntryInManifestIsEmpty) {
 }
 
 TEST_F(LibVintfTest, AccessEntryInMatrix) {
-    MatrixHal mh{HalFormat::AIDL,
-                 "android.hardware.foo",
-                 {{SIZE_MAX, 1}},
-                 false /* optional */,
-                 ExclusiveTo::VM,
-                 false /* updatableViaApex */,
-                 {}};
+    MatrixHal mh{HalFormat::AIDL, "android.hardware.foo",       {{SIZE_MAX, 1}},
+                 ExclusiveTo::VM, false /* updatableViaApex */, {}};
     EXPECT_TRUE(insert(&mh.interfaces, {"IFoo", {"default"}}));
     std::string xml = toXml(mh);
     EXPECT_EQ(xml,
-              "<hal format=\"aidl\" optional=\"false\" exclusive-to=\"virtual-machine\">\n"
+              "<hal format=\"aidl\" exclusive-to=\"virtual-machine\">\n"
               "    <name>android.hardware.foo</name>\n"
               "    <interface>\n"
               "        <name>IFoo</name>\n"
@@ -5741,17 +5080,12 @@ TEST_F(LibVintfTest, AccessEntryInMatrix) {
 }
 
 TEST_F(LibVintfTest, NoAccessEntryInMatrix) {
-    MatrixHal mh{HalFormat::AIDL,
-                 "android.hardware.foo",
-                 {{SIZE_MAX, 1}},
-                 false /* optional */,
-                 ExclusiveTo::EMPTY,
-                 false /* updatableViaApex */,
-                 {}};
+    MatrixHal mh{HalFormat::AIDL,    "android.hardware.foo",       {{SIZE_MAX, 1}},
+                 ExclusiveTo::EMPTY, false /* updatableViaApex */, {}};
     EXPECT_TRUE(insert(&mh.interfaces, {"IFoo", {"default"}}));
     std::string xml = toXml(mh);
     EXPECT_EQ(xml,
-              "<hal format=\"aidl\" optional=\"false\">\n"
+              "<hal format=\"aidl\">\n"
               "    <name>android.hardware.foo</name>\n"
               "    <interface>\n"
               "        <name>IFoo</name>\n"
@@ -5814,7 +5148,7 @@ TEST_F(LibVintfTest, AccessIncompatibleNoAccess) {
 
     xml = "<compatibility-matrix " + kMetaVersionStr +
           " type=\"framework\">\n"
-          "    <hal format=\"aidl\" optional=\"false\" exclusive-to=\"virtual-machine\">\n"
+          "    <hal format=\"aidl\" exclusive-to=\"virtual-machine\">\n"
           "        <name>android.hardware.foo</name>\n"
           "        <interface>\n"
           "            <name>IFoo</name>\n"
@@ -6684,7 +6018,7 @@ TEST_F(FrameworkCompatibilityMatrixCombineTest, AidlAndHidlNames) {
     std::string head2{"<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"};
     std::string tail{"</compatibility-matrix>\n"};
     std::string aidl =
-        "    <hal format=\"aidl\" optional=\"false\">\n"
+        "    <hal format=\"aidl\">\n"
         "        <name>android.system.foo</name>\n"
         "        <interface>\n"
         "            <name>IFoo</name>\n"
@@ -6692,7 +6026,7 @@ TEST_F(FrameworkCompatibilityMatrixCombineTest, AidlAndHidlNames) {
         "        </interface>\n"
         "    </hal>\n";
     std::string hidl =
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.system.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -6700,8 +6034,6 @@ TEST_F(FrameworkCompatibilityMatrixCombineTest, AidlAndHidlNames) {
         "            <instance>default</instance>\n"
         "        </interface>\n"
         "    </hal>\n";
-    std::string aidlOptional = std::string(aidl).replace(hidl.find("false"), 5, "true");
-    std::string hidlOptional = std::string(hidl).replace(hidl.find("false"), 5, "true");
     std::string error;
     {
         ASSERT_TRUE(fromXml(&matrices[0], head1 + aidl + tail, &error))
@@ -6727,7 +6059,7 @@ TEST_F(FrameworkCompatibilityMatrixCombineTest, AidlAndHidlNames) {
 
         auto combinedXml = toXml(*combined);
         EXPECT_IN(aidl, combinedXml);
-        EXPECT_IN(hidlOptional, combinedXml);
+        EXPECT_IN(hidl, combinedXml);
     }
     {
         ASSERT_TRUE(fromXml(&matrices[0], head2 + aidl + tail, &error))
@@ -6739,8 +6071,8 @@ TEST_F(FrameworkCompatibilityMatrixCombineTest, AidlAndHidlNames) {
         ASSERT_NE(nullptr, combined) << error;
 
         auto combinedXml = toXml(*combined);
-        EXPECT_IN(aidlOptional, combinedXml);
         EXPECT_IN(hidl, combinedXml);
+        EXPECT_IN(aidl, combinedXml);
     }
 }
 
@@ -6766,7 +6098,7 @@ TEST_P(FcmCombineKernelTest, OlderKernel) {
 
     constexpr auto fmt = R"(
         <compatibility-matrix %s type="framework" level="%s">
-            <hal format="hidl" optional="false">
+            <hal format="hidl">
                 <name>android.system.foo</name>
                 <version>%zu.0</version>
                 <interface>
@@ -6852,7 +6184,7 @@ TEST_F(DeviceCompatibilityMatrixCombineTest, Success) {
     std::string head{"<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"};
     std::string tail{"</compatibility-matrix>\n"};
     std::string halFoo{
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -6861,7 +6193,7 @@ TEST_F(DeviceCompatibilityMatrixCombineTest, Success) {
         "        </interface>\n"
         "    </hal>\n"};
     std::string halBar{
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.bar</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -6907,7 +6239,7 @@ TEST_F(DeviceCompatibilityMatrixCombineTest, AidlAndHidlNames) {
     std::string head{"<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"};
     std::string tail{"</compatibility-matrix>\n"};
     std::string aidl =
-        "    <hal format=\"aidl\" optional=\"true\">\n"
+        "    <hal format=\"aidl\">\n"
         "        <name>android.system.foo</name>\n"
         "        <interface>\n"
         "            <name>IFoo</name>\n"
@@ -6915,7 +6247,7 @@ TEST_F(DeviceCompatibilityMatrixCombineTest, AidlAndHidlNames) {
         "        </interface>\n"
         "    </hal>\n";
     std::string hidl =
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.system.foo</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
diff --git a/test/VintfFmTest.cpp b/test/VintfFmTest.cpp
index b25dc28..3ad1609 100644
--- a/test/VintfFmTest.cpp
+++ b/test/VintfFmTest.cpp
@@ -55,7 +55,10 @@ using std::string_literals::operator""s;
 
 static constexpr const char* gFakeRoot = "fake_root";
 static constexpr const char* gFakeSystemArg = "/system:fake_root/system";
+static constexpr const char* gBadFakeSystemArg = "/system:fake_root/bad_system";
 static constexpr const char* gFrameworkManifestPath = "fake_root/system/etc/vintf/manifest.xml";
+static constexpr const char* gBadFrameworkManifestPath =
+    "fake_root/bad_system/etc/vintf/bad_manifest.xml";
 static constexpr const char* gFrozenDir = "frozen";
 static constexpr const char* gFrameworkManifest = R"(
 <manifest version="2.0" type="framework">
@@ -87,6 +90,29 @@ static constexpr const char* gFrameworkManifest = R"(
     <fqname>IAidl/default</fqname>
   </hal>
 </manifest>)";
+// Missing the android.frameworks.no_level interface.
+// A missing interface is considered an error
+static constexpr const char* gBadFrameworkManifest = R"(
+<manifest version="2.0" type="framework">
+  <hal max-level="1">
+    <name>android.frameworks.level1</name>
+    <transport>hwbinder</transport>
+    <fqname>@1.0::IHidl/default</fqname>
+  </hal>
+  <hal max-level="2">
+    <name>android.frameworks.level2</name>
+    <transport>hwbinder</transport>
+    <fqname>@1.0::IHidl/default</fqname>
+  </hal>
+  <hal format="aidl" max-level="1">
+    <name>android.frameworks.level1</name>
+    <fqname>IAidl/default</fqname>
+  </hal>
+  <hal format="aidl" max-level="2">
+    <name>android.frameworks.level2</name>
+    <fqname>IAidl/default</fqname>
+  </hal>
+</manifest>)";
 
 // clang-format off
 static std::set<std::string> gInstances1 = {
@@ -241,7 +267,6 @@ std::string createMatrixHal(HalFormat format, const std::string& package) {
     MatrixHal matrixHal{.format = format,
                         .name = package,
                         .versionRanges = versionRanges,
-                        .optional = false,
                         .interfaces = {{interface, HalInterface{interface, {"default"}}}}};
     return toXml(matrixHal);
 }
@@ -268,6 +293,11 @@ class VintfFmCheckTest : public VintfFmTest, public WithParamInterface<Level> {
                 *fetched = it->second;
                 return OK;
             }));
+        ON_CALL(*fs, fetch(PathEq(gBadFrameworkManifestPath), _, _))
+            .WillByDefault(Invoke([](const auto&, auto* fetched, auto*) {
+                *fetched = gBadFrameworkManifest;
+                return OK;
+            }));
     }
 
     std::map<std::string, std::string> files;
@@ -312,6 +342,10 @@ TEST_P(VintfFmCheckTest, Check) {
     Args args({"vintffm", "--check", "--dirmap", gFakeSystemArg, gFrozenDir});
     EXPECT_EQ(EX_OK, vintffm->main(args.size(), args.get()));
 }
+TEST_P(VintfFmCheckTest, CheckMissingManifestHal) {
+    Args args({"vintffm", "--check", "--dirmap", gBadFakeSystemArg, gFrozenDir});
+    EXPECT_EQ(EX_SOFTWARE, vintffm->main(args.size(), args.get()));
+}
 
 INSTANTIATE_TEST_SUITE_P(VintfFmTest, VintfFmCheckTest,
                          ::testing::Values(static_cast<Level>(1), static_cast<Level>(2),
diff --git a/test/vintf_object_tests.cpp b/test/vintf_object_tests.cpp
index 9baeb59..ac4a595 100644
--- a/test/vintf_object_tests.cpp
+++ b/test/vintf_object_tests.cpp
@@ -62,17 +62,17 @@ using namespace ::android::vintf::details;
 
 const std::string systemMatrixXml1 =
     "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-    "    <hal format=\"hidl\" optional=\"false\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.camera</name>\n"
     "        <version>2.0-5</version>\n"
     "        <version>3.4-16</version>\n"
     "    </hal>\n"
-    "    <hal format=\"hidl\" optional=\"false\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.nfc</name>\n"
     "        <version>1.0</version>\n"
     "        <version>2.0</version>\n"
     "    </hal>\n"
-    "    <hal format=\"hidl\" optional=\"true\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.foo</name>\n"
     "        <version>1.0</version>\n"
     "    </hal>\n"
@@ -147,7 +147,7 @@ const std::string systemManifestXml1 =
 
 const std::string vendorMatrixXml1 =
     "<compatibility-matrix " + kMetaVersionStr + " type=\"device\">\n"
-    "    <hal format=\"hidl\" optional=\"false\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hidl.manager</name>\n"
     "        <version>1.0</version>\n"
     "    </hal>\n"
@@ -158,46 +158,13 @@ const std::string vendorMatrixXml1 =
     "    </vndk>\n"
     "</compatibility-matrix>\n";
 
-//
-// Set of Xml2 metadata compatible with each other.
-//
-
-const std::string systemMatrixXml2 =
-    "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-    "    <hal format=\"hidl\" optional=\"false\">\n"
-    "        <name>android.hardware.foo</name>\n"
-    "        <version>1.0</version>\n"
-    "    </hal>\n"
-    "    <kernel version=\"3.18.31\"></kernel>\n"
-    "    <sepolicy>\n"
-    "        <kernel-sepolicy-version>30</kernel-sepolicy-version>\n"
-    "        <sepolicy-version>25.5</sepolicy-version>\n"
-    "        <sepolicy-version>26.0-3</sepolicy-version>\n"
-    "    </sepolicy>\n"
-    "    <avb>\n"
-    "        <vbmeta-version>0.0</vbmeta-version>\n"
-    "    </avb>\n"
-    "</compatibility-matrix>\n";
-
-const std::string vendorManifestXml2 =
-    "<manifest " + kMetaVersionStr + " type=\"device\">"
-    "    <hal>"
-    "        <name>android.hardware.foo</name>"
-    "        <transport>hwbinder</transport>"
-    "        <version>1.0</version>"
-    "    </hal>"
-    "    <sepolicy>\n"
-    "        <version>25.5</version>\n"
-    "    </sepolicy>\n"
-    "</manifest>";
-
 //
 // Set of framework matrices of different FCM version.
 //
 
 const std::string systemMatrixLevel1 =
     "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-    "    <hal format=\"hidl\" optional=\"true\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.major</name>\n"
     "        <version>1.0</version>\n"
     "        <interface>\n"
@@ -205,7 +172,7 @@ const std::string systemMatrixLevel1 =
     "            <instance>default</instance>\n"
     "        </interface>\n"
     "    </hal>\n"
-    "    <hal format=\"hidl\" optional=\"true\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.removed</name>\n"
     "        <version>1.0</version>\n"
     "        <interface>\n"
@@ -213,7 +180,7 @@ const std::string systemMatrixLevel1 =
     "            <instance>default</instance>\n"
     "        </interface>\n"
     "    </hal>\n"
-    "    <hal format=\"hidl\" optional=\"true\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.minor</name>\n"
     "        <version>1.0</version>\n"
     "        <interface>\n"
@@ -222,7 +189,7 @@ const std::string systemMatrixLevel1 =
     "            <instance>legacy</instance>\n"
     "        </interface>\n"
     "    </hal>\n"
-    "    <hal format=\"aidl\" optional=\"true\">\n"
+    "    <hal format=\"aidl\">\n"
     "        <name>android.hardware.minor</name>\n"
     "        <version>101</version>\n"
     "        <interface>\n"
@@ -230,7 +197,7 @@ const std::string systemMatrixLevel1 =
     "            <instance>default</instance>\n"
     "        </interface>\n"
     "    </hal>\n"
-    "    <hal format=\"aidl\" optional=\"true\">\n"
+    "    <hal format=\"aidl\">\n"
     "        <name>android.hardware.removed</name>\n"
     "        <version>101</version>\n"
     "        <interface>\n"
@@ -250,7 +217,46 @@ const std::string systemMatrixLevel1 =
 
 const std::string systemMatrixLevel2 =
     "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-    "    <hal format=\"hidl\" optional=\"true\">\n"
+    "    <hal format=\"hidl\">\n"
+    "        <name>android.hardware.major</name>\n"
+    "        <version>2.0</version>\n"
+    "        <interface>\n"
+    "            <name>IMajor</name>\n"
+    "            <instance>default</instance>\n"
+    "        </interface>\n"
+    "    </hal>\n"
+    "    <hal format=\"hidl\">\n"
+    "        <name>android.hardware.minor</name>\n"
+    "        <version>1.1</version>\n"
+    "        <interface>\n"
+    "            <name>IMinor</name>\n"
+    "            <instance>default</instance>\n"
+    "        </interface>\n"
+    "    </hal>\n"
+    "    <hal format=\"aidl\">\n"
+    "        <name>android.hardware.minor</name>\n"
+    "        <version>102</version>\n"
+    "        <interface>\n"
+    "            <name>IMinor</name>\n"
+    "            <instance>default</instance>\n"
+    "        </interface>\n"
+    "    </hal>\n"
+    "    <hal format=\"aidl\" exclusive-to=\"virtual-machine\">\n"
+    "        <name>android.hardware.vm.removed</name>\n"
+    "        <version>3</version>\n"
+    "        <interface>\n"
+    "            <name>IRemoved</name>\n"
+    "            <instance>default</instance>\n"
+    "        </interface>\n"
+    "    </hal>\n"
+    "</compatibility-matrix>\n";
+
+// Same as systemMatrixLevel2 - used to test the different behavior of
+// deprecating no longer being instance-specific based on the
+// target-level of 202504 or greater
+const std::string systemMatrixLevel202504 =
+    "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"202504\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.major</name>\n"
     "        <version>2.0</version>\n"
     "        <interface>\n"
@@ -258,7 +264,7 @@ const std::string systemMatrixLevel2 =
     "            <instance>default</instance>\n"
     "        </interface>\n"
     "    </hal>\n"
-    "    <hal format=\"hidl\" optional=\"true\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.minor</name>\n"
     "        <version>1.1</version>\n"
     "        <interface>\n"
@@ -266,7 +272,7 @@ const std::string systemMatrixLevel2 =
     "            <instance>default</instance>\n"
     "        </interface>\n"
     "    </hal>\n"
-    "    <hal format=\"aidl\" optional=\"true\">\n"
+    "    <hal format=\"aidl\">\n"
     "        <name>android.hardware.minor</name>\n"
     "        <version>102</version>\n"
     "        <interface>\n"
@@ -291,7 +297,7 @@ const std::string systemMatrixLevel2 =
 
 const std::string productMatrixLevel1 =
     "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-    "    <hal format=\"hidl\" optional=\"true\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>product.removed</name>\n"
     "        <version>1.0</version>\n"
     "        <interface>\n"
@@ -299,7 +305,7 @@ const std::string productMatrixLevel1 =
     "            <instance>default</instance>\n"
     "        </interface>\n"
     "    </hal>\n"
-    "    <hal format=\"hidl\" optional=\"true\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>product.minor</name>\n"
     "        <version>1.0</version>\n"
     "        <interface>\n"
@@ -311,7 +317,7 @@ const std::string productMatrixLevel1 =
 
 const std::string productMatrixLevel2 =
     "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-    "    <hal format=\"hidl\" optional=\"true\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>product.minor</name>\n"
     "        <version>1.1</version>\n"
     "        <interface>\n"
@@ -328,7 +334,7 @@ const std::string productMatrixLevel2 =
 const static std::vector<std::string> systemMatrixRegexXmls = {
     // 1.xml
     "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-    "    <hal format=\"hidl\" optional=\"false\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.regex</name>\n"
     "        <version>1.0-1</version>\n"
     "        <interface>\n"
@@ -342,7 +348,7 @@ const static std::vector<std::string> systemMatrixRegexXmls = {
     "</compatibility-matrix>\n",
     // 2.xml
     "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-    "    <hal format=\"hidl\" optional=\"false\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.regex</name>\n"
     "        <version>1.1-2</version>\n"
     "        <interface>\n"
@@ -356,7 +362,7 @@ const static std::vector<std::string> systemMatrixRegexXmls = {
     "</compatibility-matrix>\n",
     // 3.xml
     "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"3\">\n"
-    "    <hal format=\"hidl\" optional=\"false\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.regex</name>\n"
     "        <version>2.0</version>\n"
     "        <interface>\n"
@@ -376,7 +382,7 @@ const static std::vector<std::string> systemMatrixRegexXmls = {
 const std::vector<std::string> systemMatrixRequire = {
     // 1.xml
     "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-    "    <hal format=\"hidl\" optional=\"false\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.foo</name>\n"
     "        <version>1.0</version>\n"
     "        <interface>\n"
@@ -387,7 +393,7 @@ const std::vector<std::string> systemMatrixRequire = {
     "</compatibility-matrix>\n",
     // 2.xml
     "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-    "    <hal format=\"hidl\" optional=\"false\">\n"
+    "    <hal format=\"hidl\">\n"
     "        <name>android.hardware.bar</name>\n"
     "        <version>1.0</version>\n"
     "        <interface>\n"
@@ -639,29 +645,6 @@ TEST_F(VintfObjectCompatibleTest, TestDeviceCompatibility) {
     ASSERT_STREQ(error.c_str(), "");
 }
 
-// Test fixture that provides incompatible metadata from the mock device.
-class VintfObjectIncompatibleTest : public VintfObjectTestBase {
-   protected:
-    virtual void SetUp() {
-        VintfObjectTestBase::SetUp();
-        setupMockFetcher(vendorManifestXml1, systemMatrixXml2, systemManifestXml1, vendorMatrixXml1);
-    }
-};
-
-// Fetch all metadata from device and ensure that it fails.
-TEST_F(VintfObjectIncompatibleTest, TestDeviceCompatibility) {
-    std::string error;
-
-    expectVendorManifest();
-    expectSystemManifest();
-    expectVendorMatrix();
-    expectSystemMatrix();
-
-    int result = vintfObject->checkCompatibility(&error);
-
-    ASSERT_EQ(result, 1) << "Should have failed:" << error.c_str();
-}
-
 const std::string vendorManifestKernelFcm =
         "<manifest " + kMetaVersionStr + " type=\"device\">\n"
         "    <kernel version=\"3.18.999\" target-level=\"8\"/>\n"
@@ -789,7 +772,7 @@ TEST_F(VintfObjectTest, ProductCompatibilityMatrix) {
                 "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\"/>");
     expectFetch(kProductMatrix,
                 "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\">\n"
-                "    <hal format=\"hidl\" optional=\"true\">\n"
+                "    <hal format=\"hidl\">\n"
                 "        <name>android.hardware.foo</name>\n"
                 "        <version>1.0</version>\n"
                 "        <interface>\n"
@@ -1082,7 +1065,7 @@ TEST_F(VendorApexTest, ReadBootstrapApexBeforeApexReady) {
         .WillByDefault(Return(false));
     // Should read bootstrap APEXes from /bootstrap-apex
     EXPECT_CALL(fetcher(), fetch(kBootstrapApexInfoFile, _))
-        .WillOnce(Invoke([](const auto&, auto& out) {
+        .WillRepeatedly(Invoke([](const auto&, auto& out) {
             out = R"(<?xml version="1.0" encoding="utf-8"?>
                 <apex-info-list>
                     <apex-info moduleName="com.vendor.foo"
@@ -1106,7 +1089,7 @@ TEST_F(VendorApexTest, OkayIfBootstrapApexDirDoesntExist) {
         .WillByDefault(Return(false));
     // Should try to read bootstrap APEXes from /bootstrap-apex
     EXPECT_CALL(fetcher(), fetch(kBootstrapApexInfoFile, _))
-        .WillOnce(Invoke([](const auto&, auto&) {
+        .WillRepeatedly(Invoke([](const auto&, auto&) {
             return NAME_NOT_FOUND;
         }));
     // Doesn't fallback to normal APEX if APEXes are not ready.
@@ -1324,11 +1307,13 @@ class DeprecateTest : public VintfObjectTestBase {
                 *out = {
                     "compatibility_matrix.1.xml",
                     "compatibility_matrix.2.xml",
+                    "compatibility_matrix.202504.xml",
                 };
                 return ::android::OK;
             }));
         expectFetchRepeatedly(kSystemVintfDir + "compatibility_matrix.1.xml"s, systemMatrixLevel1);
         expectFetchRepeatedly(kSystemVintfDir + "compatibility_matrix.2.xml"s, systemMatrixLevel2);
+        expectFetchRepeatedly(kSystemVintfDir + "compatibility_matrix.202504.xml"s, systemMatrixLevel202504);
         EXPECT_CALL(fetcher(), listFiles(StrEq(kProductVintfDir), _, _))
             .WillRepeatedly(Invoke([](const auto&, auto* out, auto*) {
                 *out = {
@@ -1528,6 +1513,24 @@ TEST_F(DeprecateTest, HidlMetadataDeprecate) {
         << "major@1.0 should be deprecated. " << error;
 }
 
+TEST_F(DeprecateTest, UnknownInstancesDoNotRespectDeprecation) {
+    expectVendorManifest(Level{2}, {
+        "android.hardware.major@1.0::IMajor/unknown",
+    });
+    std::string error;
+    EXPECT_EQ(NO_DEPRECATED_HALS, vintfObject->checkDeprecation({}, &error))
+        << "major@1.0 should not be deprecated when targeting FCM level < 202504. " << error;
+}
+
+TEST_F(DeprecateTest, UnknownInstancesMustRespectDeprecation) {
+    expectVendorManifest(Level{202504}, {
+        "android.hardware.major@1.0::IMajor/unknown",
+    });
+    std::string error;
+    EXPECT_EQ(DEPRECATED, vintfObject->checkDeprecation({}, &error))
+        << "major@1.0 should be deprecated. " << error;
+}
+
 class RegexInstanceDeprecateTest : public VintfObjectTestBase {
    protected:
     virtual void SetUp() override {
@@ -1543,7 +1546,7 @@ class RegexInstanceDeprecateTest : public VintfObjectTestBase {
             }));
         expectFetchRepeatedly(kSystemVintfDir + "compatibility_matrix.1.xml"s,
             "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-            "    <hal format=\"hidl\" optional=\"true\">\n"
+            "    <hal format=\"hidl\">\n"
             "        <name>android.hardware.minor</name>\n"
             "        <version>1.1</version>\n"
             "        <interface>\n"
@@ -1551,7 +1554,7 @@ class RegexInstanceDeprecateTest : public VintfObjectTestBase {
             "            <regex-instance>instance.*</regex-instance>\n"
             "        </interface>\n"
             "    </hal>\n"
-            "    <hal format=\"aidl\" optional=\"true\">\n"
+            "    <hal format=\"aidl\">\n"
             "        <name>android.hardware.minor</name>\n"
             "        <version>101</version>\n"
             "        <interface>\n"
@@ -1563,7 +1566,7 @@ class RegexInstanceDeprecateTest : public VintfObjectTestBase {
         );
         expectFetchRepeatedly(kSystemVintfDir + "compatibility_matrix.2.xml"s,
             "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-            "    <hal format=\"hidl\" optional=\"true\">\n"
+            "    <hal format=\"hidl\">\n"
             "        <name>android.hardware.minor</name>\n"
             "        <version>1.2</version>\n"
             "        <interface>\n"
@@ -1571,7 +1574,7 @@ class RegexInstanceDeprecateTest : public VintfObjectTestBase {
             "            <regex-instance>instance.*</regex-instance>\n"
             "        </interface>\n"
             "    </hal>\n"
-            "    <hal format=\"aidl\" optional=\"true\">\n"
+            "    <hal format=\"aidl\">\n"
             "        <name>android.hardware.minor</name>\n"
             "        <version>102</version>\n"
             "        <interface>\n"
@@ -1615,6 +1618,7 @@ TEST_F(RegexInstanceDeprecateTest, AidlDeprecate) {
     std::string error;
     EXPECT_EQ(DEPRECATED, vintfObject->checkDeprecation({}, &error))
         << "minor@101::IMinor/instance2 is deprecated";
+    EXPECT_IN("minor@101", error);
 }
 
 class MultiMatrixTest : public VintfObjectTestBase {
@@ -1666,7 +1670,7 @@ TEST_F(RegexTest, CombineLevel1) {
     std::string xml = toXml(*matrix);
 
     EXPECT_IN(
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.regex</name>\n"
         "        <version>1.0-2</version>\n"
         "        <version>2.0</version>\n"
@@ -1677,7 +1681,7 @@ TEST_F(RegexTest, CombineLevel1) {
         "    </hal>\n",
         xml);
     EXPECT_IN(
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.regex</name>\n"
         "        <version>1.0-1</version>\n"
         "        <interface>\n"
@@ -1689,7 +1693,7 @@ TEST_F(RegexTest, CombineLevel1) {
         "    </hal>\n",
         xml);
     EXPECT_IN(
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.regex</name>\n"
         "        <version>1.1-2</version>\n"
         "        <interface>\n"
@@ -1701,7 +1705,7 @@ TEST_F(RegexTest, CombineLevel1) {
         "    </hal>\n",
         xml);
     EXPECT_IN(
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.regex</name>\n"
         "        <version>2.0</version>\n"
         "        <interface>\n"
@@ -1721,7 +1725,7 @@ TEST_F(RegexTest, CombineLevel2) {
     std::string xml = toXml(*matrix);
 
     EXPECT_IN(
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.regex</name>\n"
         "        <version>1.1-2</version>\n"
         "        <version>2.0</version>\n"
@@ -1732,7 +1736,7 @@ TEST_F(RegexTest, CombineLevel2) {
         "    </hal>\n",
         xml);
     EXPECT_IN(
-        "    <hal format=\"hidl\" optional=\"false\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.regex</name>\n"
         "        <version>1.1-2</version>\n"
         "        <interface>\n"
@@ -1744,7 +1748,7 @@ TEST_F(RegexTest, CombineLevel2) {
         "    </hal>\n",
         xml);
     EXPECT_IN(
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>android.hardware.regex</name>\n"
         "        <version>2.0</version>\n"
         "        <interface>\n"
@@ -2448,7 +2452,7 @@ std::vector<std::string> GetOemFcmMatrixLevels(const std::string& name) {
     return {
         // 1.xml
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>vendor.foo." + name + "</name>\n"
         "        <version>1.0</version>\n"
         "        <interface>\n"
@@ -2459,7 +2463,7 @@ std::vector<std::string> GetOemFcmMatrixLevels(const std::string& name) {
         "</compatibility-matrix>\n",
         // 2.xml
         "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"2\">\n"
-        "    <hal format=\"hidl\" optional=\"true\">\n"
+        "    <hal format=\"hidl\">\n"
         "        <name>vendor.foo." + name + "</name>\n"
         "        <version>2.0</version>\n"
         "        <interface>\n"
@@ -2542,7 +2546,7 @@ class CheckMatricesWithHalDefTestBase : public MultiMatrixTest {
         // clang-format off
         std::vector<std::string> matrices{
             "<compatibility-matrix " + kMetaVersionStr + " type=\"framework\" level=\"1\">\n"
-            "    <hal format=\"hidl\" optional=\"false\">\n"
+            "    <hal format=\"hidl\">\n"
             "        <name>android.hardware.hidl</name>\n"
             "        <version>1.0</version>\n"
             "        <interface>\n"
@@ -2550,7 +2554,7 @@ class CheckMatricesWithHalDefTestBase : public MultiMatrixTest {
             "            <instance>default</instance>\n"
             "        </interface>\n"
             "    </hal>\n"
-            "    <hal format=\"aidl\" optional=\"false\">\n"
+            "    <hal format=\"aidl\">\n"
             "        <name>android.hardware.aidl</name>\n"
             "        <interface>\n"
             "            <name>IAidl</name>\n"
@@ -2727,7 +2731,7 @@ TEST_F(CheckMatrixHalsHasDefinitionTest, FailMissingBoth) {
 
 constexpr const char* systemMatrixHealthFormat = R"(
 <compatibility-matrix %s type="framework" level="%s">
-    <hal format="%s" optional="%s">
+    <hal format="%s">
         <name>android.hardware.health</name>
         <version>%s</version>
         <interface>
@@ -2795,19 +2799,19 @@ class VintfObjectHealthHalTest : public MultiMatrixTest,
         SetUpMockSystemMatrices({
             android::base::StringPrintf(
                 systemMatrixHealthFormat, kMetaVersionStr.c_str(), to_string(Level::P).c_str(),
-                to_string(HalFormat::HIDL).c_str(), "true", to_string(Version{2, 0}).c_str()),
+                to_string(HalFormat::HIDL).c_str(), to_string(Version{2, 0}).c_str()),
             android::base::StringPrintf(
                 systemMatrixHealthFormat, kMetaVersionStr.c_str(), to_string(Level::Q).c_str(),
-                to_string(HalFormat::HIDL).c_str(), "true", to_string(Version{2, 0}).c_str()),
+                to_string(HalFormat::HIDL).c_str(), to_string(Version{2, 0}).c_str()),
             android::base::StringPrintf(
                 systemMatrixHealthFormat, kMetaVersionStr.c_str(), to_string(Level::R).c_str(),
-                to_string(HalFormat::HIDL).c_str(), "true", to_string(Version{2, 1}).c_str()),
+                to_string(HalFormat::HIDL).c_str(), to_string(Version{2, 1}).c_str()),
             android::base::StringPrintf(
                 systemMatrixHealthFormat, kMetaVersionStr.c_str(), to_string(Level::S).c_str(),
-                to_string(HalFormat::HIDL).c_str(), "true", to_string(Version{2, 1}).c_str()),
-            android::base::StringPrintf(
-                systemMatrixHealthFormat, kMetaVersionStr.c_str(), to_string(Level::T).c_str(),
-                to_string(HalFormat::AIDL).c_str(), "false", to_string(1).c_str()),
+                to_string(HalFormat::HIDL).c_str(), to_string(Version{2, 1}).c_str()),
+            android::base::StringPrintf(systemMatrixHealthFormat, kMetaVersionStr.c_str(),
+                                        to_string(Level::T).c_str(),
+                                        to_string(HalFormat::AIDL).c_str(), to_string(1).c_str()),
         });
         switch (GetParam().getHalFormat()) {
             case HalFormat::HIDL:
@@ -2866,7 +2870,7 @@ constexpr const char* systemMatrixComposerFormat = R"(
 )";
 
 constexpr const char* systemMatrixComposerHalFragmentFormat = R"(
-    <hal format="%s" optional="%s">
+    <hal format="%s">
         <name>%s</name>
         <version>%s</version>
         <interface>
@@ -2951,19 +2955,19 @@ class VintfObjectComposerHalTest : public MultiMatrixTest,
         MultiMatrixTest::SetUp();
 
         const std::string requiresHidl2_1To2_2 = android::base::StringPrintf(
-            systemMatrixComposerHalFragmentFormat, to_string(HalFormat::HIDL).c_str(), "false",
+            systemMatrixComposerHalFragmentFormat, to_string(HalFormat::HIDL).c_str(),
             composerHidlHalName, to_string(VersionRange{2, 1, 2}).c_str());
         const std::string requiresHidl2_1To2_3 = android::base::StringPrintf(
-            systemMatrixComposerHalFragmentFormat, to_string(HalFormat::HIDL).c_str(), "false",
+            systemMatrixComposerHalFragmentFormat, to_string(HalFormat::HIDL).c_str(),
             composerHidlHalName, to_string(VersionRange{2, 1, 3}).c_str());
         const std::string requiresHidl2_1To2_4 = android::base::StringPrintf(
-            systemMatrixComposerHalFragmentFormat, to_string(HalFormat::HIDL).c_str(), "false",
+            systemMatrixComposerHalFragmentFormat, to_string(HalFormat::HIDL).c_str(),
             composerHidlHalName, to_string(VersionRange{2, 1, 4}).c_str());
         const std::string optionalHidl2_1To2_4 = android::base::StringPrintf(
-            systemMatrixComposerHalFragmentFormat, to_string(HalFormat::HIDL).c_str(), "true",
+            systemMatrixComposerHalFragmentFormat, to_string(HalFormat::HIDL).c_str(),
             composerHidlHalName, to_string(VersionRange{2, 1, 4}).c_str());
         const std::string optionalAidl1 = android::base::StringPrintf(
-            systemMatrixComposerHalFragmentFormat, to_string(HalFormat::AIDL).c_str(), "true",
+            systemMatrixComposerHalFragmentFormat, to_string(HalFormat::AIDL).c_str(),
             composerAidlHalName, "1");
         const std::string optionalHidl2_1To2_4OrAidl1 = optionalHidl2_1To2_4 + optionalAidl1;
 
```

